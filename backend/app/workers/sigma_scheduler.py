"""Sigma scheduler.

Periodic worker that translates Sigma rules to OpenSearch Lucene queries
(via pySigma) and runs them in a sliding window over the live
`telemetry-*` indices.

Each iteration:
  1. Snapshot the enabled Sigma rules from PG.
  2. Compile any rule whose `revision` is unseen since last compile.
  3. For each rule, query telemetry-* for events in (last_run, now - LAG)
     matching the Lucene query.
  4. For each hit, write an Alert row + alerts-YYYYMMDD doc.
  5. Sleep until the next interval.

Run with:
    python -m app.workers.sigma_scheduler
"""

from __future__ import annotations

import asyncio
import logging
import signal
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import SessionLocal
from app.models import Alert, AlertState, AlertStateHistory, Rule, RuleAction, RuleKind
from app.services import opensearch as os_svc
from app.services.host_cache import resolve_alert_tenant_id
from app.services.sigma import CompiledSigma, SigmaCompileError, compile_yaml

log = structlog.get_logger()

# How often the scheduler runs.
INTERVAL_SECONDS = 30.0
# Indexing lag — wait this long before evaluating, so events can land in OS.
EVAL_LAG_SECONDS = 30.0
# Backfill on first run / cold start.
COLD_START_BACKFILL_SECONDS = 60.0
# Hard cap on hits per (rule, iteration) — defensive against runaway rules.
MAX_HITS_PER_RUN = 200


@dataclass
class CompileCacheEntry:
    revision: int
    compiled: CompiledSigma


class SigmaScheduler:
    def __init__(self) -> None:
        self.os_client = os_svc._client()
        self._stop = asyncio.Event()
        # rule_id -> CompileCacheEntry
        self._compiled: dict[UUID, CompileCacheEntry] = {}
        # rule_id -> last successful evaluation upper bound
        self._last_run: dict[UUID, datetime] = {}

    async def start(self) -> None:
        await os_svc.ensure_template(self.os_client)
        log.info("sigma.scheduler.start", interval_s=INTERVAL_SECONDS, lag_s=EVAL_LAG_SECONDS)

    async def stop(self) -> None:
        self._stop.set()
        await self.os_client.close()
        log.info("sigma.scheduler.stop")

    async def run(self) -> None:
        while not self._stop.is_set():
            try:
                await self._tick()
            except Exception:
                log.exception("sigma.scheduler.tick_failed")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=INTERVAL_SECONDS)
            except TimeoutError:
                pass

    async def _tick(self) -> None:
        async with SessionLocal() as db:
            rules = await self._load_rules(db)
        log.debug("sigma.scheduler.tick", rule_count=len(rules))

        now = datetime.now(UTC)
        upper = now - timedelta(seconds=EVAL_LAG_SECONDS)

        for rule in rules:
            try:
                await self._eval_rule(rule, upper)
            except Exception:
                log.exception("sigma.scheduler.rule_failed", rule_id=str(rule.id))

    async def _load_rules(self, db: AsyncSession) -> list[Rule]:
        stmt = (
            select(Rule)
            .where(Rule.kind == RuleKind.SIGMA, Rule.enabled.is_(True))
            .order_by(Rule.updated_at.asc())
        )
        return list((await db.execute(stmt)).scalars().all())

    def _compiled_for(self, rule: Rule) -> CompiledSigma | None:
        cached = self._compiled.get(rule.id)
        if cached is not None and cached.revision == rule.revision:
            return cached.compiled
        if not rule.body:
            return None
        try:
            compiled = compile_yaml(rule.body)
        except SigmaCompileError as exc:
            log.warning("sigma.compile_failed", rule_id=str(rule.id), error=str(exc))
            return None
        self._compiled[rule.id] = CompileCacheEntry(revision=rule.revision, compiled=compiled)
        log.info(
            "sigma.compile_ok",
            rule_id=str(rule.id),
            revision=rule.revision,
            query=compiled.query,
        )
        return compiled

    async def _eval_rule(self, rule: Rule, upper: datetime) -> None:
        compiled = self._compiled_for(rule)
        if compiled is None:
            return

        lower = self._last_run.get(rule.id) or (
            upper - timedelta(seconds=COLD_START_BACKFILL_SECONDS)
        )
        if lower >= upper:
            return

        body = {
            "size": MAX_HITS_PER_RUN,
            "_source": True,
            "sort": [{"@timestamp": {"order": "asc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gt": lower.isoformat(),
                                    "lte": upper.isoformat(),
                                }
                            }
                        },
                        {"query_string": {"query": compiled.query}},
                    ]
                }
            },
        }
        try:
            resp = await self.os_client.search(
                index="telemetry-*",
                body=body,
                request_timeout=15,  # pyright: ignore[reportCallIssue]
            )
        except Exception:
            log.exception("sigma.search_failed", rule_id=str(rule.id))
            return

        hits = resp.get("hits", {}).get("hits", [])
        if hits:
            log.info(
                "sigma.matched",
                rule_id=str(rule.id),
                rule_name=rule.name,
                n=len(hits),
                query=compiled.query,
            )
            await self._emit_alerts(rule, compiled, hits, upper)

        # Slide the window forward only on success — failure leaves _last_run
        # alone so we replay on the next tick.
        self._last_run[rule.id] = upper

    async def _emit_alerts(
        self,
        rule: Rule,
        compiled: CompiledSigma,
        hits: list,
        ts: datetime,
    ) -> None:
        async with SessionLocal() as db:
            for hit in hits:
                src = hit.get("_source", {}) or {}
                host_id_str = src.get("host", {}).get("id")
                event_id = src.get("event", {}).get("id")
                if not host_id_str:
                    continue
                try:
                    host_id = UUID(host_id_str)
                except ValueError:
                    continue
                # CODE-25: stamp tenant_id from the host. Falls back to
                # tenant.id on the OS hit doc when present.
                host_tenant_id = await resolve_alert_tenant_id(
                    db,
                    host_id=host_id,
                    ecs_tenant_id=(src.get("tenant") or {}).get("id"),
                )
                if host_tenant_id is None:
                    log.warning("sigma.scheduler.tenant_lookup_miss", host_id=host_id_str)
                    continue
                alert = Alert(
                    tenant_id=host_tenant_id,
                    host_id=host_id,
                    rule_id=rule.id,
                    severity=rule.severity,
                    action_taken=RuleAction.ALERT,
                    state=AlertState.NEW,
                    summary=f"Sigma match: {compiled.title or rule.name}",
                    details={
                        "engine": "sigma",
                        "query": compiled.query,
                        "event_id": event_id,
                        "hit_index": hit.get("_index"),
                        "hit_id": hit.get("_id"),
                    },
                )
                alert.history.append(
                    AlertStateHistory(
                        from_state=None,
                        to_state=AlertState.NEW,
                        comment="auto-generated by sigma scheduler",
                    )
                )
                db.add(alert)
                await db.flush()
                alert_doc = {
                    "@timestamp": ts.isoformat(),
                    "alert": {
                        "id": str(alert.id),
                        "summary": alert.summary,
                        "severity": rule.severity.value,
                        "action_taken": "alert",
                        "engine": "sigma",
                    },
                    "rule": {"id": str(rule.id), "name": rule.name},
                    "host": src.get("host", {}),
                    "event": {"id": event_id},
                    "sigma": {"query": compiled.query, "title": compiled.title},
                }
                try:
                    await self.os_client.index(
                        index=os_svc.alerts_index_for(ts),
                        id=str(uuid4()),
                        body=alert_doc,
                    )
                except Exception:
                    log.exception("sigma.alert_index_failed", alert_id=str(alert.id))
            await db.commit()


async def amain() -> None:
    scheduler = SigmaScheduler()
    await scheduler.start()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(scheduler.stop()))
    try:
        await scheduler.run()
    finally:
        await scheduler.stop()


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ]
    )
    asyncio.run(amain())


if __name__ == "__main__":
    main()
