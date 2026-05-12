"""M22.b alert broker — fan out newly-inserted alerts to SSE subscribers.

A single asyncio task polls the alerts table for rows whose
`created_at` is newer than the last value it observed and pushes
each new row to every subscriber queue. Per-connection RBAC scoping
happens at the SSE handler level by filtering on host visibility.

This is intentionally simple — one DB query every `poll_interval_s`
seconds regardless of how many SSE clients are connected. For a
single-tenant manager with a low alert rate this is the cheapest
correct design; if alert volume climbs we'd switch to LISTEN/NOTIFY.
"""

from __future__ import annotations

import asyncio
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
        self._stop = asyncio.Event()

    async def start(self) -> None:
        # Anchor the high-water mark a few seconds in the past so the
        # first poll picks up alerts created right before startup, but
        # not the entire historical backlog.
        self._last_seen = datetime.now(UTC) - timedelta(seconds=5)
        self._task = asyncio.create_task(self._run(), name="alert-broker")

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass

    async def _run(self) -> None:
        log.info("alert_broker.start", poll_s=self.poll_interval_s)
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

    async def _poll_once(self) -> None:
        if self._last_seen is None or not self._subs:
            # No clients waiting — keep advancing the watermark without
            # building event payloads.
            if self._subs:
                pass  # keep going below
            else:
                # No-op poll: still bump the watermark so we don't
                # backflood once a client connects mid-stream.
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
                self._broadcast(event)
            self._last_seen = rows[-1].created_at

    def _broadcast(self, event: dict[str, Any]) -> None:
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
