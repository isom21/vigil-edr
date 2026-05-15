"""M12.d agent silence alerting worker.

Periodic backend worker that scans the `hosts` table and fires a
HIGH-severity alert whenever a host's `last_seen_at` is older than
the configured silence threshold (default 10 min) AND the host is
currently marked ONLINE. The check is idempotent — a synthetic
"silence is over" alert is suppressed by writing one alert per
silence-window, then resetting on next observation of activity.

Distinct from "host offline" status:
  * status=OFFLINE means the gRPC stream got `EOF` — explicit
    disconnect or process exit.
  * silence means the stream might still be open, but no events or
    heartbeats arrived in the window.

Either pattern is an attack signal: an attacker who blocks the
agent's network path (without killing the process) generates
silence; an attacker who kills the agent generates OFFLINE. Silence
catches the subtler case.

Run with:
    python -m app.workers.silence

Configurable via env:
    VIGIL_SILENCE_THRESHOLD_SECONDS  silence trigger (default 600)
    VIGIL_SILENCE_TICK_SECONDS       scan cadence (default 60)
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
from datetime import UTC, datetime, timedelta
from uuid import UUID

import structlog
from sqlalchemy import select

from app.core.db import SessionLocal
from app.models import (
    Alert,
    AlertState,
    Host,
    HostStatus,
    Rule,
    RuleAction,
    RuleKind,
    Severity,
)

log = structlog.get_logger()


# Stable pseudo-rule id — all silence alerts attach here.
SILENCE_RULE_ID = UUID("a0a0a0a0-0000-0000-0000-000000000004")


class SilenceWorker:
    def __init__(self) -> None:
        self._stop = asyncio.Event()
        self._threshold = timedelta(
            seconds=int(os.environ.get("VIGIL_SILENCE_THRESHOLD_SECONDS", 600))
        )
        self._tick = float(os.environ.get("VIGIL_SILENCE_TICK_SECONDS", 60))
        # In-memory dedup: host_ids that already have an open silence
        # alert. Cleared when we see the host go non-silent again.
        self._open_alerts: set[UUID] = set()

    async def start(self) -> None:
        await self._ensure_pseudo_rule()
        log.info(
            "silence.start",
            threshold_s=int(self._threshold.total_seconds()),
            tick_s=self._tick,
        )

    async def stop(self) -> None:
        self._stop.set()
        log.info("silence.stop")

    async def run(self) -> None:
        while not self._stop.is_set():
            try:
                await self._tick_once()
            except Exception:
                log.exception("silence.tick_failed")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self._tick)
            except TimeoutError:
                continue

    async def _tick_once(self) -> None:
        cutoff = datetime.now(UTC) - self._threshold
        async with SessionLocal() as db:
            stmt = select(Host).where(
                Host.status == HostStatus.ONLINE,
                Host.last_seen_at.isnot(None),
            )
            hosts = (await db.execute(stmt)).scalars().all()
            for host in hosts:
                if host.last_seen_at is None:
                    continue
                # last_seen_at is timezone-aware; the cutoff is too,
                # but be defensive against legacy naive rows.
                last = host.last_seen_at
                if last.tzinfo is None:
                    last = last.replace(tzinfo=UTC)
                is_silent = last < cutoff
                if is_silent and host.id not in self._open_alerts:
                    silence_seconds = int((datetime.now(UTC) - last).total_seconds())
                    await self._fire_alert(db, host, silence_seconds)
                    self._open_alerts.add(host.id)
                elif not is_silent and host.id in self._open_alerts:
                    # Host recovered — drop the latch so the next
                    # silence event fires a fresh alert.
                    self._open_alerts.discard(host.id)
                    log.info("silence.recovered", host_id=str(host.id))
            await db.commit()

    async def _fire_alert(self, db, host: Host, silence_seconds: int) -> None:
        alert = Alert(
            # CODE-25: Host row is in scope, so its tenant_id is
            # authoritative — no host_cache lookup needed.
            tenant_id=host.tenant_id,
            host_id=host.id,
            rule_id=SILENCE_RULE_ID,
            severity=Severity.HIGH,
            action_taken=RuleAction.ALERT,
            state=AlertState.NEW,
            summary=f"Agent silent for {silence_seconds}s on {host.hostname}",
            details={
                "hostname": host.hostname,
                "last_seen_at": host.last_seen_at.isoformat() if host.last_seen_at else None,
                "silence_seconds": silence_seconds,
                "threshold_seconds": int(self._threshold.total_seconds()),
                "host_status_at_detect": host.status.value,
                "detector": "silence_v1",
            },
        )
        db.add(alert)
        log.warning(
            "silence.alert",
            host_id=str(host.id),
            hostname=host.hostname,
            silence_seconds=silence_seconds,
        )

    async def _ensure_pseudo_rule(self) -> None:
        async with SessionLocal() as db:
            existing = await db.get(Rule, SILENCE_RULE_ID)
            if existing is not None:
                return
            rule = Rule(
                id=SILENCE_RULE_ID,
                name="M12 self-protection: agent silence",
                kind=RuleKind.IOC,
                action=RuleAction.ALERT,
                severity=Severity.HIGH,
                enabled=True,
                description="Synthetic rule — fires when an ONLINE host "
                "stops sending events/heartbeats for longer than the "
                "configured silence threshold (default 10 min).",
            )
            db.add(rule)
            await db.commit()
            log.info("silence.rule_bootstrapped", rule_id=str(SILENCE_RULE_ID))


async def main() -> None:
    logging.basicConfig(level=logging.INFO)
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ]
    )
    worker = SilenceWorker()
    await worker.start()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(worker.stop()))
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
