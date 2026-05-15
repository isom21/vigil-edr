"""M12 self-protection tamper alert worker.

Consumes `telemetry.normalized` (ECS-shaped JSON), looks at
`agent.tamper.kind`, and fires a HIGH-severity alert. The agent
already sets `event.kind=alert` on these messages, but the manager
needs an Alert row in PG so the SOC sees it in the UI alerts list
and so it joins to the rule for ack/triage workflow.

Run with:
    python -m app.workers.tamper

Bootstraps a synthetic Rule with a fixed UUID so the alerts table
FK accepts the row. Idempotent.

Out of scope:
  * Auto-isolating the host on tamper detection (M12 follow-up;
    needs operator-configurable policy, not auto-applied).
  * Notifier integration (email/Slack) — the existing alert path
    already covers fan-out; this worker just needs to write the row.
"""

from __future__ import annotations

import asyncio
import json
import logging
import signal
from uuid import UUID

import structlog
from aiokafka import AIOKafkaConsumer

from app.core.config import settings
from app.core.db import SessionLocal
from app.models import (
    Alert,
    AlertState,
    Rule,
    RuleAction,
    RuleKind,
    Severity,
)
from app.services.host_cache import resolve_alert_tenant_id

log = structlog.get_logger()


# Stable pseudo-rule id — all M12 tamper alerts attach here.
TAMPER_RULE_ID = UUID("a0a0a0a0-0000-0000-0000-000000000003")


_KIND_SUMMARY = {
    "binary_mismatch": "Agent binary modified at runtime",
    "config_mismatch": "Agent config modified at runtime",
    "bpf_detached": "Agent BPF program detached",
    "bpf_map_missing": "Agent pinned BPF map removed",
}


class TamperWorker:
    def __init__(self) -> None:
        self.consumer: AIOKafkaConsumer | None = None
        self._stop = asyncio.Event()

    async def start(self) -> None:
        await self._ensure_pseudo_rule()
        self.consumer = AIOKafkaConsumer(
            settings.topic_telemetry_normalized,
            bootstrap_servers=settings.kafka_brokers,
            group_id="tamper-detector",
            enable_auto_commit=False,
            auto_offset_reset="latest",
        )
        await self.consumer.start()
        log.info("tamper.start", topic=settings.topic_telemetry_normalized)

    async def stop(self) -> None:
        self._stop.set()
        if self.consumer is not None:
            await self.consumer.stop()
        log.info("tamper.stop")

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
                doc = json.loads(msg.value)
            except Exception:
                log.exception("tamper.decode_failed", offset=msg.offset)
                await self.consumer.commit()
                continue

            try:
                await self._handle_doc(doc)
            except Exception:
                log.exception("tamper.handle_failed", offset=msg.offset)
            await self.consumer.commit()

    async def _handle_doc(self, doc: dict) -> None:
        agent = doc.get("agent") or {}
        tamper = agent.get("tamper")
        if not tamper:
            return
        host_id_str = (doc.get("host") or {}).get("id")
        if not host_id_str:
            return
        try:
            host_id = UUID(host_id_str)
        except ValueError:
            return
        kind = tamper.get("kind") or "unspecified"
        target = tamper.get("target_path") or ""
        expected = tamper.get("expected_hash") or ""
        actual = tamper.get("actual_hash") or ""
        detail = tamper.get("detail") or ""

        async with SessionLocal() as db:
            # CODE-25: resolve tenant_id inside the session so the
            # synthetic-tamper Alert carries the right tenant. Tamper
            # docs may not carry tenant.id (the agent emits them via
            # a side channel, not the normalizer); fall back to the
            # Host row lookup.
            host_tenant_id = await resolve_alert_tenant_id(
                db,
                host_id=host_id,
                ecs_tenant_id=(doc.get("tenant") or {}).get("id"),
            )
            if host_tenant_id is None:
                log.warning("tamper.tenant_lookup_miss", host_id=host_id_str)
                return
            alert = Alert(
                tenant_id=host_tenant_id,
                host_id=host_id,
                rule_id=TAMPER_RULE_ID,
                severity=Severity.HIGH,
                action_taken=RuleAction.ALERT,
                state=AlertState.NEW,
                summary=_KIND_SUMMARY.get(kind, f"Agent tamper: {kind}"),
                details={
                    "tamper_kind": kind,
                    "target_path": target,
                    "expected_sha256": expected,
                    "actual_sha256": actual,
                    "detail": detail,
                    "detector": "tamper_v1",
                },
            )
            db.add(alert)
            await db.commit()
            log.warning(
                "tamper.alert",
                host_id=str(host_id),
                kind=kind,
                target=target[:120],
            )

    async def _ensure_pseudo_rule(self) -> None:
        async with SessionLocal() as db:
            existing = await db.get(Rule, TAMPER_RULE_ID)
            if existing is not None:
                return
            rule = Rule(
                id=TAMPER_RULE_ID,
                name="M12 self-protection: agent tamper detected",
                kind=RuleKind.IOC,
                action=RuleAction.ALERT,
                severity=Severity.HIGH,
                enabled=True,
                description="Synthetic rule — fires on agent-emitted tamper "
                "events (binary/config drift, BPF detachment).",
            )
            db.add(rule)
            await db.commit()
            log.info("tamper.rule_bootstrapped", rule_id=str(TAMPER_RULE_ID))


async def main() -> None:
    logging.basicConfig(level=logging.INFO)
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ]
    )
    worker = TamperWorker()
    await worker.start()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(worker.stop()))
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
