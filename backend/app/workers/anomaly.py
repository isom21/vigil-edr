"""M11.b anomaly detection worker.

Consumes `telemetry.normalized` (ECS-shaped JSON), counts
`(host_id, exe, parent_exe)` triples per host, and fires an alert
the first time a triple is observed AND its parent isn't a known
launcher.

Run with:
    python -m app.workers.anomaly

Configurable via env:
    VIGIL_ANOMALY_KNOWN_LAUNCHERS  comma-separated list of executables
                                  treated as boring launch sources
                                  (default: systemd, init, cron,
                                  bash, sshd, sh, dbus-daemon, runc,
                                  containerd-shim, docker-shim,
                                  explorer.exe, services.exe,
                                  svchost.exe, taskhostw.exe)
    VIGIL_ANOMALY_MIN_FLEET_HOURS  refuse to alert until the fleet has
                                  been observed for this many hours;
                                  prevents bootstrap-time noise
                                  (default 1)

Bootstrapping: on first run, the worker creates a pseudo-rule with
`kind=anomaly` and a fixed UUID so anomaly alerts can attach to
something the alerts table FK accepts. Idempotent.

Out of scope:
  * Trimming `process_baseline` rows by `last_seen < now() - 7 days`
    (M11.b follow-up cron).
  * Per-tenant baselines (M15.e RLS work).
  * False-positive feedback that boosts a triple's count to suppress
    future alerts (M11.c).
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
from datetime import UTC, datetime
from uuid import UUID

import structlog
from aiokafka import AIOKafkaConsumer
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import SessionLocal
from app.models import (
    Alert,
    AlertState,
    ProcessBaseline,
    Rule,
    RuleAction,
    RuleKind,
    Severity,
)
from app.services.host_cache import resolve_alert_tenant_id

log = structlog.get_logger()


# Stable pseudo-rule id so all anomaly alerts attach to the same row.
ANOMALY_RULE_ID = UUID("a0a0a0a0-0000-0000-0000-000000000001")

DEFAULT_KNOWN_LAUNCHERS = (
    # Linux init/userspace
    "/usr/lib/systemd/systemd",
    "/sbin/init",
    "/usr/sbin/cron",
    "/usr/sbin/sshd",
    "/usr/bin/bash",
    "/bin/bash",
    "/bin/sh",
    "/usr/bin/dbus-daemon",
    "/usr/bin/runc",
    "/usr/bin/containerd-shim-runc-v2",
    # Windows
    "C:\\Windows\\explorer.exe",
    "C:\\Windows\\System32\\services.exe",
    "C:\\Windows\\System32\\svchost.exe",
    "C:\\Windows\\System32\\taskhostw.exe",
    "C:\\Windows\\System32\\smss.exe",
    "C:\\Windows\\System32\\wininit.exe",
    "C:\\Windows\\System32\\winlogon.exe",
)


def _known_launchers() -> set[str]:
    raw = os.environ.get("VIGIL_ANOMALY_KNOWN_LAUNCHERS")
    if raw:
        return {s.strip() for s in raw.split(",") if s.strip()}
    return set(DEFAULT_KNOWN_LAUNCHERS)


class AnomalyWorker:
    def __init__(self) -> None:
        self.consumer: AIOKafkaConsumer | None = None
        self._stop = asyncio.Event()
        self._known_launchers = _known_launchers()
        self._started_at = datetime.now(UTC)
        self._min_fleet_hours = int(os.environ.get("VIGIL_ANOMALY_MIN_FLEET_HOURS", 1))

    async def start(self) -> None:
        await self._ensure_pseudo_rule()
        self.consumer = AIOKafkaConsumer(
            settings.topic_telemetry_normalized,
            bootstrap_servers=settings.kafka_brokers,
            group_id="anomaly-detector",
            enable_auto_commit=False,
            auto_offset_reset="latest",
        )
        await self.consumer.start()
        log.info(
            "anomaly.start",
            topic=settings.topic_telemetry_normalized,
            known_launchers=len(self._known_launchers),
        )

    async def stop(self) -> None:
        self._stop.set()
        if self.consumer is not None:
            await self.consumer.stop()
        log.info("anomaly.stop")

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
                log.exception("anomaly.decode_failed", offset=msg.offset)
                await self.consumer.commit()
                continue

            try:
                await self._handle_doc(doc)
            except Exception:
                log.exception("anomaly.handle_failed", offset=msg.offset)
            await self.consumer.commit()

    async def _handle_doc(self, doc: dict) -> None:
        if doc.get("event", {}).get("kind") != "process_started":
            return
        host = doc.get("host", {})
        host_id_str = host.get("id")
        if not host_id_str:
            return
        proc = doc.get("process", {})
        exe = proc.get("executable") or ""
        parent_exe = (proc.get("parent") or {}).get("executable") or ""
        if not exe:
            return
        try:
            host_id = UUID(host_id_str)
        except ValueError:
            return

        async with SessionLocal() as db:
            is_new = await self._upsert_baseline(db, host_id, exe, parent_exe)
            await db.commit()
            if not is_new:
                return
            # Bootstrap grace: don't alert during the first hour after
            # the worker started — every triple looks "new" right after
            # boot.
            uptime = (datetime.now(UTC) - self._started_at).total_seconds() / 3600
            if uptime < self._min_fleet_hours:
                return
            if parent_exe in self._known_launchers:
                return
            event_id = (doc.get("event") or {}).get("id")
            pid_raw = proc.get("pid")
            pid = pid_raw if isinstance(pid_raw, int) else None
            await self._fire_alert(db, host_id, exe, parent_exe, event_id, pid)
            await db.commit()

    async def _upsert_baseline(
        self,
        db: AsyncSession,
        host_id: UUID,
        exe: str,
        parent_exe: str,
    ) -> bool:
        """Insert-or-bump the baseline row. Returns True iff this was
        the first time the (host, exe, parent) triple was seen."""
        # Postgres ON CONFLICT DO UPDATE — atomic and lets us detect
        # the first-insert vs already-exists case in one round trip
        # via the `xmax` system column.
        stmt = (
            pg_insert(ProcessBaseline)
            .values(host_id=host_id, exe=exe, parent_exe=parent_exe, count=1)
            .on_conflict_do_update(
                constraint="uq_process_baseline_triple",
                set_={
                    "count": ProcessBaseline.count + 1,
                    "last_seen": datetime.now(UTC),
                },
            )
            .returning(ProcessBaseline.id, ProcessBaseline.count)
        )
        row = (await db.execute(stmt)).first()
        return row is not None and row.count == 1

    async def _fire_alert(
        self,
        db: AsyncSession,
        host_id: UUID,
        exe: str,
        parent_exe: str,
        event_id: str | None,
        pid: int | None,
    ) -> None:
        details: dict = {
            "executable": exe,
            "parent_executable": parent_exe,
            "detector": "anomaly_baseline_v1",
            "reason": "exe+parent triple seen for the first time on this host",
        }
        # event_id + pid let the investigation page rebuild the process
        # chain (ancestors + the leaf's children) without us recording
        # telemetry_doc_ids separately.
        if event_id:
            details["event_id"] = event_id
        if pid is not None:
            details["pid"] = pid
        # CODE-25: stamp tenant_id from the host. The anomaly worker
        # commits its baseline upsert before reaching here, so the
        # session can see the Host row in the same DB.
        host_tenant_id = await resolve_alert_tenant_id(db, host_id=host_id, ecs_tenant_id=None)
        if host_tenant_id is None:
            log.warning("anomaly.tenant_lookup_miss", host_id=str(host_id))
            return
        alert = Alert(
            tenant_id=host_tenant_id,
            host_id=host_id,
            rule_id=ANOMALY_RULE_ID,
            severity=Severity.LOW,
            action_taken=RuleAction.ALERT,
            state=AlertState.NEW,
            summary=f"First-time process: {exe[:80]}",
            details=details,
        )
        db.add(alert)
        log.info(
            "anomaly.alert",
            host_id=str(host_id),
            exe=exe[:80],
            parent_exe=parent_exe[:80],
        )

    async def _ensure_pseudo_rule(self) -> None:
        async with SessionLocal() as db:
            existing = await db.get(Rule, ANOMALY_RULE_ID)
            if existing is not None:
                return
            rule = Rule(
                id=ANOMALY_RULE_ID,
                name="Anomaly: first-time process exec",
                # Closest existing kind; M11.c may add a dedicated `ANOMALY` kind.
                kind=RuleKind.IOC,
                action=RuleAction.ALERT,
                severity=Severity.LOW,
                enabled=True,
                description="M11.b synthetic rule — fires on first-time-seen "
                "(host, exe, parent_exe) triple where parent isn't a known "
                "launcher.",
            )
            db.add(rule)
            await db.commit()
            log.info("anomaly.rule_bootstrapped", rule_id=str(ANOMALY_RULE_ID))


async def amain() -> None:
    from app.core.logging import configure as _configure_logging

    _configure_logging()
    worker = AnomalyWorker()

    def _signal(_sig, _frame):
        worker._stop.set()

    signal.signal(signal.SIGINT, _signal)
    signal.signal(signal.SIGTERM, _signal)
    try:
        await worker.start()
        await worker.run()
    finally:
        await worker.stop()


if __name__ == "__main__":
    asyncio.run(amain())
