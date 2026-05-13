"""M22.b alert broker — fan out newly-inserted alerts to SSE subscribers.

A single asyncio task per manager instance polls the alerts table for
rows whose `created_at` is newer than the last value it observed and
pushes each new row out to subscribers.

Two fan-out modes:

* Single-instance (`VIGIL_REDIS_URL=""`): broadcast directly to local
  per-connection queues. This is the original M22.b implementation.

* Multi-instance (Redis configured): every manager instance still
  runs the pollster (so a single instance's failure doesn't stall
  fan-out for the whole fleet). Before fanning out a particular
  alert row, the pollster races for a short-lived Redis lock
  (`SET vigil:broker:lock:<alert-id> NX PX 1500`). Whichever instance
  wins publishes the event on the `vigil:alerts:broadcast` Pub/Sub
  channel; every instance subscribes and pipes incoming messages into
  its local subscriber queues. Without the lock dedup, an alert
  inserted just before a poll tick would be emitted N times (once per
  replica) and every connected SSE client would see N copies.

Per-connection RBAC scoping happens at the SSE handler level by
filtering on host visibility — that's unchanged.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.core.db import SessionLocal
from app.models import Alert, Host, Rule

log = structlog.get_logger()

# Queue depth per subscriber. If a slow client falls behind, we drop
# the oldest event rather than pile memory; 256 covers about ~8 min
# at 2 events/s.
_QUEUE_MAX = 256

# Redis pub/sub channel + dedup lock key prefix. Both share the
# `vigil:` namespace so an operator running multiple unrelated apps
# against the same Redis can grep their own keys.
REDIS_CHANNEL = "vigil:alerts:broadcast"
REDIS_LOCK_PREFIX = "vigil:broker:lock"
# Lock TTL: the lock only needs to survive the fan-out window between
# instances racing the same row. 1500 ms is long enough that the
# winner's publish completes; if the winner crashes mid-publish, the
# lock auto-expires and the next poll on any instance re-emits the
# row (alerts are immutable so a duplicate publish carries the same
# payload and the SSE clients dedupe on event.id at the React keying
# layer anyway).
REDIS_LOCK_TTL_MS = 1500


def _alert_to_event(alert: Alert, host: Host | None, rule: Rule | None) -> dict[str, Any]:
    """Shape the SSE payload to mirror the AlertOut response model so
    the frontend can reuse the same row renderer.
    """
    return {
        "id": str(alert.id),
        # Null for synthetic alerts (audit chain break, etc.). The SSE
        # handler treats null-host events as admin-only.
        "host_id": str(alert.host_id) if alert.host_id else None,
        "rule_id": str(alert.rule_id),
        "severity": alert.severity.value,
        "action_taken": alert.action_taken.value,
        "state": alert.state.value,
        "summary": alert.summary,
        "details": alert.details,
        "telemetry_index": alert.telemetry_index,
        "telemetry_doc_ids": alert.telemetry_doc_ids,
        "opened_at": alert.opened_at.isoformat(),
        "closed_at": alert.closed_at.isoformat() if alert.closed_at else None,
        "assignee_id": str(alert.assignee_id) if alert.assignee_id else None,
        "created_at": alert.created_at.isoformat(),
        "updated_at": alert.updated_at.isoformat(),
        # Phase 1 #1.10 dedup surface.
        "occurrence_count": alert.occurrence_count,
        "last_occurred_at": alert.last_occurred_at.isoformat(),
        "host_hostname": host.hostname if host else None,
        "rule_name": rule.name if rule else None,
    }


class AlertBroker:
    def __init__(self, poll_interval_s: float = 2.0) -> None:
        self.poll_interval_s = poll_interval_s
        # Subscribers keyed by id() so we can remove a specific queue
        # on unsubscribe without needing the queue itself to be hashable
        # in a stable way (asyncio.Queue is).
        self._subs: dict[int, asyncio.Queue[dict[str, Any]]] = {}
        self._last_seen: datetime | None = None
        self._task: asyncio.Task[None] | None = None
        self._subscriber_task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        # Lazy: populated on start() if a Redis client is configured.
        self._redis: Any = None
        self._pubsub: Any = None

    async def start(self) -> None:
        # Anchor the high-water mark a few seconds in the past so the
        # first poll picks up alerts created right before startup, but
        # not the entire historical backlog.
        self._last_seen = datetime.now(UTC) - timedelta(seconds=5)
        # Redis-backed mode is opt-in via lifespan; pull the client
        # off the singleton so callers don't have to thread it.
        from app.core.redis_client import redis_client

        self._redis = redis_client()
        if self._redis is not None:
            # One pub/sub connection per instance; the subscriber task
            # below pumps incoming messages into local subscriber
            # queues. `ignore_subscribe_messages=True` filters the
            # internal "subscribed" / "unsubscribed" control frames
            # so `get_message` only returns real publishes.
            self._pubsub = self._redis.pubsub(ignore_subscribe_messages=True)
            await self._pubsub.subscribe(REDIS_CHANNEL)
            self._subscriber_task = asyncio.create_task(
                self._run_subscriber(), name="alert-broker-sub"
            )
        self._task = asyncio.create_task(self._run(), name="alert-broker")

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
        if self._subscriber_task:
            self._subscriber_task.cancel()
            try:
                await self._subscriber_task
            except (asyncio.CancelledError, Exception):
                pass
        if self._pubsub is not None:
            try:
                await self._pubsub.unsubscribe(REDIS_CHANNEL)
                await self._pubsub.aclose()
            except Exception:  # noqa: BLE001
                pass
            self._pubsub = None
        self._redis = None

    async def _run(self) -> None:
        log.info("alert_broker.start", poll_s=self.poll_interval_s, redis=self._redis is not None)
        while not self._stop.is_set():
            try:
                await self._poll_once()
            except Exception:
                log.exception("alert_broker.poll_failed")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.poll_interval_s)
                break
            except TimeoutError:
                continue
        log.info("alert_broker.stop")

    async def _run_subscriber(self) -> None:
        """Read pub/sub messages and pipe them into local subscriber
        queues. Only runs in multi-instance mode."""
        assert self._pubsub is not None
        while not self._stop.is_set():
            try:
                # `get_message` returns None when there's nothing to
                # read; the timeout makes the wait async so this
                # doesn't busy-loop the event loop.
                msg = await self._pubsub.get_message(timeout=1.0)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("alert_broker.subscriber_recv_failed")
                # Back off a bit before retrying. The pub/sub
                # connection auto-reconnects, but a tight loop on
                # repeated errors would spam the log.
                await asyncio.sleep(0.5)
                continue
            if not msg:
                continue
            data = msg.get("data")
            if isinstance(data, bytes):
                try:
                    event = json.loads(data)
                except Exception:
                    log.exception("alert_broker.bad_message")
                    continue
                self._broadcast_local(event)

    async def _poll_once(self) -> None:
        if self._last_seen is None:
            # Lifespan didn't init yet; nothing to do.
            return
        # In single-instance mode with no subscribers, skip the query
        # entirely — keep advancing the watermark so we don't
        # backflood once a client connects mid-stream.
        #
        # In multi-instance mode we still poll even with no local
        # subscribers, because *this* instance's poll is what triggers
        # publishing to peers that DO have subscribers.
        if not self._subs and self._redis is None:
            self._last_seen = datetime.now(UTC)
            return
        cutoff = self._last_seen
        async with SessionLocal() as db:
            stmt = (
                select(Alert)
                .where(Alert.created_at > cutoff)
                .order_by(Alert.created_at.asc())
                .options(selectinload(Alert.history))
                .limit(100)
            )
            rows = (await db.execute(stmt)).scalars().all()
            if not rows:
                return
            # Single bulk fetch of hosts + rules so we don't N+1.
            # Synthetic alerts (host_id IS NULL) are filtered out of the
            # host lookup; `hosts.get(None)` returns None below, which
            # `_alert_to_event` renders as host_hostname=null.
            host_ids = {a.host_id for a in rows if a.host_id is not None}
            rule_ids = {a.rule_id for a in rows}
            hosts = {
                h.id: h
                for h in (await db.execute(select(Host).where(Host.id.in_(host_ids)))).scalars()
            }
            rules = {
                r.id: r
                for r in (await db.execute(select(Rule).where(Rule.id.in_(rule_ids)))).scalars()
            }
            for alert in rows:
                host = hosts.get(alert.host_id) if alert.host_id is not None else None
                event = _alert_to_event(alert, host, rules.get(alert.rule_id))
                await self._fanout(event, str(alert.id))
            self._last_seen = rows[-1].created_at

    async def _fanout(self, event: dict[str, Any], alert_id: str) -> None:
        """Decide between local-only and Redis-publish based on the
        configured mode, and dedup across replicas in the latter."""
        if self._redis is None:
            self._broadcast_local(event)
            return
        # Multi-instance: race for the dedup lock; whichever instance
        # wins publishes once. The losers skip; the pub/sub
        # subscription routes the winning publish back to every
        # instance's local subscribers (including the publisher's
        # own, via the subscriber task).
        lock_key = f"{REDIS_LOCK_PREFIX}:{alert_id}"
        try:
            # `SET key value NX PX ms` returns truthy on the first
            # writer; subsequent writers within the TTL window get
            # None.
            won = await self._redis.set(lock_key, b"1", nx=True, px=REDIS_LOCK_TTL_MS)
        except Exception:
            # If Redis hiccups, fall back to local broadcast so a
            # subscriber on this instance still sees the event. The
            # other instances will retry on the next poll cycle.
            log.exception("alert_broker.lock_failed")
            self._broadcast_local(event)
            return
        if not won:
            return
        try:
            await self._redis.publish(REDIS_CHANNEL, json.dumps(event).encode())
        except Exception:
            log.exception("alert_broker.publish_failed")
            self._broadcast_local(event)

    def _broadcast_local(self, event: dict[str, Any]) -> None:
        # Iterate over a copy — subscribers may remove themselves
        # concurrently when their SSE connection drops.
        for q in list(self._subs.values()):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                # Slow client. Drop the oldest event to keep memory
                # bounded; the client can refresh manually if it cares.
                try:
                    _ = q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                q.put_nowait(event)

    # Kept as the public broadcast hook so legacy callers (tests that
    # poked the broker directly) still work.
    def _broadcast(self, event: dict[str, Any]) -> None:  # pragma: no cover - thin wrapper
        self._broadcast_local(event)

    @asynccontextmanager
    async def subscribe(self):
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=_QUEUE_MAX)
        key = id(q)
        self._subs[key] = q
        try:
            yield q
        finally:
            self._subs.pop(key, None)


broker = AlertBroker()
