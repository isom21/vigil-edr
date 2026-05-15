"""Sigma realtime worker.

Replaces sigma_scheduler for per-event Sigma rules. Architecture:

  telemetry.normalized (Kafka)
        |
        v
  sigma_realtime (this worker, group=sigma_realtime)
        |
        v
  POST /sigma-rules/_search  { percolate: { document: ECS event } }
        |
        v
  for each matched rule -> Alert row in PG + alerts-YYYYMMDD doc

Detection latency = Kafka commit + percolate round-trip + alert write,
typically 10-50ms vs ~60s for the scheduled correlator.

Aggregation / count-of / time-window Sigma rules don't fit the percolator
model (it matches one document at a time); those remain on
sigma_scheduler when we add count support back.

Run with:
    python -m app.workers.sigma_realtime
"""

from __future__ import annotations

import asyncio
import json
import signal
from datetime import UTC, datetime
from uuid import UUID, uuid4

import structlog
from aiokafka import AIOKafkaConsumer
from sqlalchemy import select

from app.core.config import settings
from app.core.db import SessionLocal
from app.core.metrics import sigma_realtime_index_failures_total
from app.models import Alert, AlertState, AlertStateHistory, Rule, RuleKind
from app.services import opensearch as os_svc
from app.services.alert_dedup import bump_occurrence, dedup_key_for, find_open_dupe
from app.services.host_cache import resolve_alert_tenant_id


class AlertIndexError(Exception):
    """Raised when one or more alert docs failed to index into
    OpenSearch. Propagated up so the run loop refuses to commit the
    Kafka offset and the message is re-processed on the next poll."""


log = structlog.get_logger()


class SigmaRealtime:
    def __init__(self) -> None:
        self.consumer: AIOKafkaConsumer | None = None
        self.os_client = os_svc._client()
        self._stop = asyncio.Event()
        # Cache rule metadata by rule_id so we don't hit PG on every match.
        self._rule_cache: dict[UUID, Rule] = {}

    async def start(self) -> None:
        await os_svc.ensure_template(self.os_client)
        await os_svc.ensure_sigma_index(self.os_client)
        await self._sync_rules_to_percolator()
        self.consumer = AIOKafkaConsumer(
            settings.topic_telemetry_normalized,
            bootstrap_servers=settings.kafka_brokers,
            group_id="sigma_realtime",
            enable_auto_commit=False,
            auto_offset_reset="latest",
            session_timeout_ms=15_000,
            max_poll_interval_ms=300_000,
        )
        await self.consumer.start()
        log.info(
            "sigma.realtime.start",
            topic=settings.topic_telemetry_normalized,
            cached_rules=len(self._rule_cache),
        )

    async def stop(self) -> None:
        self._stop.set()
        if self.consumer is not None:
            await self.consumer.stop()
        await self.os_client.close()
        log.info("sigma.realtime.stop")

    async def _sync_rules_to_percolator(self) -> None:
        """At startup, reconcile the percolator index with PG.

        - Every enabled Sigma rule with a compiled query gets registered.
        - Any percolator doc whose rule_id is no longer enabled in PG (or
          doesn't exist) gets removed.

        Also populates self._rule_cache for fast lookup on hits.
        """
        async with SessionLocal() as db:
            stmt = select(Rule).where(Rule.kind == RuleKind.SIGMA, Rule.enabled.is_(True))
            enabled = list((await db.execute(stmt)).scalars().all())

        # Read what's currently in the percolator index.
        try:
            existing = await self.os_client.search(
                index=os_svc.SIGMA_RULES_INDEX,
                body={"size": 10_000, "_source": ["rule_id"]},
                request_timeout=10,  # pyright: ignore[reportCallIssue]
            )
            existing_ids = {
                h["_source"]["rule_id"]
                for h in existing.get("hits", {}).get("hits", [])
                if h.get("_source", {}).get("rule_id")
            }
        except Exception:
            existing_ids = set()

        wanted_ids: set[str] = set()
        for rule in enabled:
            if not rule.sigma_compiled:
                continue
            self._rule_cache[rule.id] = rule
            wanted_ids.add(str(rule.id))
            # An individual rule registration can fail when its query
            # references a field that's not in the percolator index
            # mapping — that's a rule-quality issue (or a missing
            # template update), not a reason to crash the worker and
            # take down the rest of the manager. Log and continue.
            try:
                await os_svc.register_sigma_rule(
                    self.os_client,
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity.value,
                    lucene_query=rule.sigma_compiled,
                )
            except Exception:
                log.exception(
                    "sigma.realtime.register_failed", rule_id=str(rule.id), rule_name=rule.name
                )
                wanted_ids.discard(str(rule.id))

        # Remove stale entries (rule disabled or deleted in PG).
        for stale in existing_ids - wanted_ids:
            try:
                await os_svc.unregister_sigma_rule(self.os_client, UUID(stale))
            except Exception:
                log.exception("sigma.realtime.stale_remove_failed", rule_id=stale)

        log.info(
            "sigma.realtime.sync_done",
            registered=len(wanted_ids),
            removed=len(existing_ids - wanted_ids),
        )

    async def _refresh_rule_cache(self, rule_id: UUID) -> Rule | None:
        async with SessionLocal() as db:
            rule = await db.get(Rule, rule_id)
        if rule is not None:
            self._rule_cache[rule_id] = rule
        return rule

    async def _get_rule_fresh(self, rule_id: UUID) -> Rule | None:
        """Return the cached rule iff its revision still matches the DB,
        else fetch and re-cache. Review MEDIUM #16: pre-fix the cache
        served the snapshot taken at startup / first-percolate forever,
        so a rule edited from low→critical kept emitting low alerts
        until the worker restarted.

        Trade-off: one indexed PK-select per matched rule (Rule.id is
        the primary key, so the row revision is a one-page lookup).
        Cheaper than re-loading the rule on every hit, more correct
        than serving stale severity/action/name forever."""
        cached = self._rule_cache.get(rule_id)
        if cached is None:
            return await self._refresh_rule_cache(rule_id)
        async with SessionLocal() as db:
            current_rev = (
                await db.execute(select(Rule.revision).where(Rule.id == rule_id))
            ).scalar_one_or_none()
        if current_rev is None:
            # Rule deleted mid-flight — drop from cache and signal miss.
            self._rule_cache.pop(rule_id, None)
            return None
        if current_rev == cached.revision:
            return cached
        return await self._refresh_rule_cache(rule_id)

    async def run(self) -> None:
        assert self.consumer is not None
        while not self._stop.is_set():
            try:
                msg = await asyncio.wait_for(self.consumer.getone(), timeout=1.0)
            except TimeoutError:
                continue
            if msg.value is None:
                await self.consumer.commit()
                continue

            try:
                ecs = json.loads(msg.value)
            except Exception:
                log.exception("sigma.realtime.decode_failed", offset=msg.offset)
                await self.consumer.commit()
                continue

            try:
                hits = await os_svc.percolate(self.os_client, ecs)
            except Exception:
                log.exception("sigma.realtime.percolate_failed")
                # Don't commit — replay this offset on the next attempt.
                continue

            if hits:
                try:
                    await self._emit_alerts(ecs, hits)
                except AlertIndexError:
                    # PG was rolled back; Kafka offset stays where it
                    # is. The consumer will replay the same message
                    # on the next poll. Operators see the metric +
                    # the log line below.
                    sigma_realtime_index_failures_total.inc()
                    log.warning(
                        "sigma.realtime.kafka_offset_not_committed",
                        offset=msg.offset,
                        reason="alert-doc index failed; will retry",
                    )
                    continue

            await self.consumer.commit()

    async def _emit_alerts(self, ecs: dict, hits: list[dict]) -> None:
        host_id_str = ecs.get("host", {}).get("id")
        event_id = ecs.get("event", {}).get("id")
        if not host_id_str:
            return
        try:
            host_id = UUID(host_id_str)
        except ValueError:
            return

        ts = datetime.now(UTC)
        async with SessionLocal() as db:
            # CODE-24: resolve the host's tenant_id once per call so
            # every Alert built below lands on the right tenant.
            host_tenant_id = await resolve_alert_tenant_id(
                db,
                host_id=host_id,
                ecs_tenant_id=(ecs.get("tenant") or {}).get("id"),
            )
            if host_tenant_id is None:
                # The host has been deleted out from under us between event
                # arrival and alert emission. Skip rather than mis-tag.
                log.warning("sigma.realtime.tenant_lookup_miss", host_id=host_id_str)
                return
            new_alerts: list[tuple[Alert, dict]] = []
            for hit in hits:
                rule_id_str = hit.get("rule_id")
                if not rule_id_str:
                    continue
                try:
                    rule_id = UUID(rule_id_str)
                except ValueError:
                    continue

                rule = await self._get_rule_fresh(rule_id)
                if rule is None or not rule.enabled or rule.kind is not RuleKind.SIGMA:
                    # Rule was deleted/disabled mid-flight; drop the hit.
                    continue

                # Clamp the rule's action down to its group's ceiling
                # (M20.b). Ungrouped rules pass through unchanged.
                from app.models import RuleGroup, clamp_action

                ceiling = None
                if rule.group_id is not None:
                    g = await db.get(RuleGroup, rule.group_id)
                    if g is not None:
                        ceiling = g.max_action
                effective_action = clamp_action(rule.action, ceiling)

                # Phase 1 #1.10 dedup probe. An open alert sharing the
                # key inside the window bumps the occurrence counter
                # and refreshes last_occurred_at instead of inserting a
                # duplicate row. Closed alerts (FP/TP) don't coalesce,
                # so a fresh recurrence after triage still fires.
                dkey = dedup_key_for(rule.id, host_id, ecs)
                existing = await find_open_dupe(
                    db,
                    dedup_key=dkey,
                    window_seconds=settings.alert_dedup_window_s,
                    now=ts,
                )
                if existing is not None:
                    bump_occurrence(existing, now=ts)
                    await db.flush()
                    log.info(
                        "sigma.realtime.alert_deduped",
                        alert_id=str(existing.id),
                        rule_id=str(rule.id),
                        host_id=host_id_str,
                        occurrence_count=existing.occurrence_count,
                    )
                    continue

                alert = Alert(
                    tenant_id=host_tenant_id,
                    host_id=host_id,
                    rule_id=rule.id,
                    severity=rule.severity,
                    action_taken=effective_action,
                    state=AlertState.NEW,
                    summary=f"Sigma match: {rule.name}",
                    details={
                        "engine": "sigma",
                        "mode": "realtime",
                        "event_id": event_id,
                        "lucene": rule.sigma_compiled,
                    },
                    dedup_key=dkey,
                    last_occurred_at=ts,
                    # Phase 1 #1.8: snapshot the rule's ATT&CK tags onto
                    # the alert row so later edits to the rule don't
                    # rewrite history.
                    mitre_techniques=(
                        list(rule.mitre_techniques) if rule.mitre_techniques else None
                    ),
                )
                alert.history.append(
                    AlertStateHistory(
                        from_state=None,
                        to_state=AlertState.NEW,
                        comment="auto-generated by sigma realtime",
                    )
                )
                db.add(alert)
                await db.flush()
                # Auto-trigger response actions for non-alert effective
                # actions (M20).
                from app.services.response import queue_command_for_match

                await queue_command_for_match(
                    db,
                    host_id=host_id,
                    rule_id=rule.id,
                    rule_action=effective_action,
                    alert_id=alert.id,
                    ecs=ecs,
                )
                new_alerts.append((alert, hit))

            # Index alert docs into OpenSearch BEFORE committing PG.
            # If any indexing call fails we roll the session back and
            # raise — the run loop sees AlertIndexError, refuses to
            # commit the Kafka offset, and the message is replayed on
            # the next poll. Keeping PG and OS in lock-step here means
            # operators don't see "alert exists in the UI but never
            # made it to alert search" — a confusing failure mode
            # when OpenSearch is unhealthy.
            #
            # Cost: on retry we'll re-emit alerts with fresh ids
            # (Alerts don't dedupe by event_id today — separate
            # tracking item). Acceptable given OpenSearch outages are
            # rare; the alternative (silently dropping alert docs) is
            # worse for forensics.
            for alert, hit in new_alerts:
                rule = self._rule_cache.get(alert.rule_id)
                alert_doc = {
                    "@timestamp": ts.isoformat(),
                    "alert": {
                        "id": str(alert.id),
                        "summary": alert.summary,
                        "severity": alert.severity.value,
                        "action_taken": alert.action_taken.value,
                        "engine": "sigma",
                        "mode": "realtime",
                    },
                    "rule": {
                        "id": str(alert.rule_id),
                        "name": rule.name if rule else hit.get("rule_name"),
                    },
                    "host": ecs.get("host", {}),
                    "event": {"id": event_id},
                    "sigma": {"lucene": rule.sigma_compiled if rule else None},
                }
                try:
                    await self.os_client.index(
                        index=os_svc.alerts_index_for(ts),
                        id=str(uuid4()),
                        body=alert_doc,
                    )
                except Exception as exc:
                    log.exception("sigma.realtime.alert_index_failed", alert_id=str(alert.id))
                    await db.rollback()
                    raise AlertIndexError(f"OpenSearch index failed for alert {alert.id}") from exc

            await db.commit()

            if new_alerts:
                log.info(
                    "sigma.realtime.alerts_emitted",
                    n=len(new_alerts),
                    host_id=host_id_str,
                    event_id=event_id,
                    rules=[h.get("rule_name") for h in hits],
                )


async def amain() -> None:
    worker = SigmaRealtime()
    await worker.start()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(worker.stop()))
    try:
        await worker.run()
    finally:
        await worker.stop()


def main() -> None:
    from app.core.logging import configure as _configure_logging

    _configure_logging()
    asyncio.run(amain())


if __name__ == "__main__":
    main()
