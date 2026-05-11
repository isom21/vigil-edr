"""M23.h sweep scheduler.

Periodic backend worker that fans out HOST_SWEEP jobs to online hosts
on the cadence configured by their assigned Policy. The sweep job
gathers a bundle of survey artifacts (process snapshot, network state,
installed software, persistence audit, etc.) so analysts can pivot off
the same data the manager already has from the live event stream.

Selection (per tick):
  - Host is ONLINE and heartbeating recently.
  - Host.last_sweep_at is NULL, or `now - last_sweep_at >= interval`.
  - Host's policy has `sweep_interval_hours > 0` AND non-empty
    `sweep_categories`. Hosts without a policy fall back to global
    defaults so out-of-the-box deployments still get sweeps.

Idempotency: the manager stamps `Host.last_sweep_at = now` after
queueing the job (not on completion), so a single stuck job won't
re-queue every minute. The Jobs engine surfaces failures separately.

Run standalone with:
    python -m app.workers.sweep_scheduler

Configurable via env:
    VIGIL_SWEEP_TICK_SECONDS    scan cadence (default 60)
    VIGIL_SWEEP_DEFAULT_HOURS   fallback interval for policy-less hosts
                                (default 4)
"""

from __future__ import annotations

import asyncio
import os
import signal
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import structlog
from sqlalchemy import select

from app.core.db import SessionLocal
from app.models import (
    Command,
    CommandKind,
    CommandStatus,
    Host,
    HostStatus,
    Job,
    JobKind,
    JobRun,
    JobRunStatus,
    JobScopeKind,
    JobStatus,
    Policy,
)

log = structlog.get_logger()


_DEFAULT_TICK_SECONDS = int(os.environ.get("VIGIL_SWEEP_TICK_SECONDS", "60"))
_DEFAULT_INTERVAL_HOURS = int(os.environ.get("VIGIL_SWEEP_DEFAULT_HOURS", "4"))
_DEFAULT_CATEGORIES: list[str] = [
    "process_snapshot",
    "network_snapshot",
    "account_audit",
    "installed_software",
    "persistence_audit",
    "service_audit",
]
# An online host that hasn't heartbeated in this long is treated as
# silent — no point asking it to sweep, the job would sit pending.
_HEARTBEAT_GRACE = timedelta(minutes=5)


class SweepScheduler:
    def __init__(
        self,
        tick_seconds: int = _DEFAULT_TICK_SECONDS,
        default_interval_hours: int = _DEFAULT_INTERVAL_HOURS,
    ) -> None:
        self._tick = max(15, tick_seconds)
        self._default_interval = max(1, default_interval_hours)
        self._stop = asyncio.Event()

    def shutdown(self) -> None:
        self._stop.set()

    async def run(self) -> None:
        log.info(
            "sweep_scheduler.start",
            tick_seconds=self._tick,
            default_interval_hours=self._default_interval,
        )
        while not self._stop.is_set():
            try:
                await self._tick_once()
            except Exception as exc:  # pragma: no cover - defensive
                log.exception("sweep_scheduler.tick_failed", error=str(exc))
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self._tick)
            except TimeoutError:
                pass
        log.info("sweep_scheduler.stopped")

    async def _tick_once(self) -> None:
        async with SessionLocal() as db:
            now = datetime.now(UTC)
            heartbeat_floor = now - _HEARTBEAT_GRACE
            # Pull every ONLINE host with a recent heartbeat. Filtering
            # by "due for sweep" needs the policy interval, so do it in
            # Python — the host count is bounded by your fleet, not by
            # a query plan, and we want to log "skipped — policy
            # disabled" reasons.
            stmt = select(Host).where(
                Host.status == HostStatus.ONLINE,
                Host.last_seen_at.is_not(None),
                Host.last_seen_at >= heartbeat_floor,
            )
            hosts = (await db.execute(stmt)).scalars().all()
            if not hosts:
                return

            # Bulk-load every distinct policy in one query to avoid N+1.
            policy_ids = {h.policy_id for h in hosts if h.policy_id is not None}
            policies: dict[UUID, Policy] = {}
            if policy_ids:
                p_stmt = select(Policy).where(Policy.id.in_(policy_ids))
                for p in (await db.execute(p_stmt)).scalars().all():
                    policies[p.id] = p

            fired = 0
            for host in hosts:
                interval, categories = self._effective_config(host, policies)
                if interval <= 0 or not categories:
                    continue
                last = host.last_sweep_at
                if last is not None and (now - last) < timedelta(hours=interval):
                    continue
                await self._fire_sweep(db, host, categories, now)
                host.last_sweep_at = now
                fired += 1

            if fired:
                await db.commit()
                log.info("sweep_scheduler.fired", count=fired)

    def _effective_config(self, host: Host, policies: dict[UUID, Policy]) -> tuple[int, list[str]]:
        if host.policy_id is not None and host.policy_id in policies:
            p = policies[host.policy_id]
            interval = int(p.sweep_interval_hours)
            categories = list(p.sweep_categories or [])
            return interval, categories
        # No policy → fall back to the env default + the canonical
        # category set.
        return self._default_interval, list(_DEFAULT_CATEGORIES)

    async def _fire_sweep(
        self,
        db,
        host: Host,
        categories: list[str],
        now: datetime,
    ) -> None:
        """Create one Job(HOST_SWEEP) + one JobRun + one bridging Command
        for this host. We don't go through services.jobs.fanout() because
        the scheduler always targets a single host and the audit trail
        wants a 'sweep_scheduler' actor breadcrumb."""
        job = Job(
            kind=JobKind.HOST_SWEEP,
            parameters={"categories": categories},
            scope_kind=JobScopeKind.HOST_IDS,
            scope_host_ids=[str(host.id)],
            scope_group_id=None,
            status=JobStatus.QUEUED,
            summary=f"Scheduled sweep · {len(categories)} categories",
            created_by_user_id=None,
            triggered_by="sweep_scheduler",
        )
        db.add(job)
        await db.flush()

        run = JobRun(
            id=uuid4(),
            job_id=job.id,
            host_id=host.id,
            status=JobRunStatus.QUEUED,
        )
        db.add(run)
        await db.flush()

        cmd = Command(
            host_id=host.id,
            kind=CommandKind.RUN_JOB,
            status=CommandStatus.PENDING,
            payload={
                "job_id": str(job.id),
                "run_id": str(run.id),
                "job_kind": JobKind.HOST_SWEEP.value,
                "parameters": {"categories": categories},
            },
            issued_by_user_id=None,
        )
        db.add(cmd)
        await db.flush()
        run.command_id = cmd.id
        job.status = JobStatus.RUNNING

        log.info(
            "sweep_scheduler.queue",
            host_id=str(host.id),
            hostname=host.hostname,
            job_id=str(job.id),
            run_id=str(run.id),
            categories=categories,
        )
        # Suppress unused-arg warning while keeping signature stable.
        _ = now


async def _main() -> None:
    scheduler = SweepScheduler()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, scheduler.shutdown)
    await scheduler.run()


if __name__ == "__main__":  # pragma: no cover - module entry point
    asyncio.run(_main())
