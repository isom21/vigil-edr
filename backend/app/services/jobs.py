"""Jobs engine service: scope resolution, fan-out, run aggregation.

The router stays thin; this module encapsulates the logic of turning
a JobScope into a concrete list of target hosts, emitting one
Command(kind=run_job) per host as the dispatch bridge, and rolling up
JobRun state into the parent Job.status.
"""

from __future__ import annotations

from datetime import timedelta
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
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
    host_in_group,
)
from app.schemas.job import JobScope
from app.services.rollout import eligible_for_update

# Recent threshold for "all online" scope — a host is considered online
# if it's been heartbeating within this window. Mirrors the heartbeat
# silence detector's grace.
_ONLINE_WINDOW = timedelta(minutes=5)


async def resolve_scope(
    db: AsyncSession,
    scope: JobScope,
    *,
    visible_host_ids: list[UUID] | None = None,
) -> list[UUID]:
    """Resolve a job scope into a deduped list of host ids.

    `visible_host_ids` is the actor's host-group scope; when supplied
    the result is intersected with it so analysts can't accidentally
    fan a job out to hosts they cannot see.
    """
    target: list[UUID]
    if scope.kind == JobScopeKind.HOST_IDS:
        target = list(scope.host_ids or [])
    elif scope.kind == JobScopeKind.HOST_GROUP:
        stmt = select(host_in_group.c.host_id).where(
            host_in_group.c.host_group_id == scope.group_id
        )
        rows = (await db.execute(stmt)).scalars().all()
        target = [UUID(str(r)) for r in rows]
    else:  # ALL_ONLINE
        from datetime import UTC, datetime  # local: keep top-level import light

        cutoff = datetime.now(UTC) - _ONLINE_WINDOW
        stmt = select(Host.id).where(
            Host.status == HostStatus.ONLINE,
            Host.last_seen_at.is_not(None),
            Host.last_seen_at >= cutoff,
        )
        rows = (await db.execute(stmt)).scalars().all()
        target = [UUID(str(r)) for r in rows]

    if visible_host_ids is not None:
        visible_set = set(visible_host_ids)
        target = [h for h in target if h in visible_set]

    # Dedupe preserving order so the operator sees runs in the order
    # they listed hosts.
    seen: set[UUID] = set()
    out: list[UUID] = []
    for h in target:
        if h in seen:
            continue
        seen.add(h)
        out.append(h)
    return out


async def fanout(
    db: AsyncSession,
    *,
    job: Job,
    host_ids: list[UUID],
    issued_by_user_id: UUID | None,
) -> list[JobRun]:
    """Create one JobRun + bridging Command per host. Caller commits.

    For ``JobKind.UPDATE`` we additionally gate each host through
    :func:`app.services.rollout.eligible_for_update`: a host whose
    cohort bucket sits outside the policy's ``cohort_rolled_out_pct``
    is silently skipped (no JobRun, no Command). This keeps the job's
    UI status honest — the resulting JobRun set is exactly what the
    manager dispatched, not "everyone we considered". The auto-
    rollback path drops the percentage to 0 to halt further dispatch
    without retracting whatever's already in flight.
    """
    if job.kind == JobKind.UPDATE:
        host_ids = await _filter_rollout_eligible(db, host_ids)

    runs: list[JobRun] = []
    for hid in host_ids:
        run = JobRun(
            id=uuid4(),
            job_id=job.id,
            host_id=hid,
            status=JobRunStatus.QUEUED,
        )
        db.add(run)
        await db.flush()
        cmd = Command(
            host_id=hid,
            kind=CommandKind.RUN_JOB,
            status=CommandStatus.PENDING,
            payload={
                "job_id": str(job.id),
                "run_id": str(run.id),
                "job_kind": job.kind.value,
                "parameters": job.parameters,
            },
            issued_by_user_id=issued_by_user_id,
        )
        db.add(cmd)
        await db.flush()
        run.command_id = cmd.id
        runs.append(run)

    if runs:
        job.status = JobStatus.RUNNING

    return runs


async def _filter_rollout_eligible(db: AsyncSession, host_ids: list[UUID]) -> list[UUID]:
    """Drop hosts whose cohort bucket sits outside the policy's
    rolled-out percentage. Hosts without a policy or whose policy
    has no target version are also dropped — an UPDATE job for them
    is a no-op the operator should explicitly configure first.
    """
    if not host_ids:
        return []
    hosts = (await db.execute(select(Host).where(Host.id.in_(host_ids)))).scalars().all()
    by_id: dict[UUID, Host] = {h.id: h for h in hosts}
    policy_ids = {h.policy_id for h in hosts if h.policy_id is not None}
    policies: dict[UUID, Policy] = {}
    if policy_ids:
        rows = (await db.execute(select(Policy).where(Policy.id.in_(policy_ids)))).scalars().all()
        policies = {p.id: p for p in rows}

    out: list[UUID] = []
    for hid in host_ids:
        host = by_id.get(hid)
        if host is None or host.policy_id is None:
            continue
        policy = policies.get(host.policy_id)
        if policy is None:
            continue
        if eligible_for_update(host, policy):
            out.append(hid)
    return out


async def aggregate_status(db: AsyncSession, job_id: UUID) -> JobStatus:
    """Roll JobRun statuses up into a Job.status.

    Rules: any RUNNING/DISPATCHED/QUEUED → RUNNING. All COMPLETED →
    COMPLETED. Mix of COMPLETED and FAILED with no in-flight → FAILED
    (so the worst case wins). All CANCELED → CANCELED.
    """
    stmt = (
        select(JobRun.status, func.count(JobRun.id))
        .where(JobRun.job_id == job_id)
        .group_by(JobRun.status)
    )
    rows = (await db.execute(stmt)).all()
    counts: dict[JobRunStatus, int] = {s: int(c) for s, c in rows}
    if not counts:
        return JobStatus.QUEUED
    nonterminal = {
        JobRunStatus.QUEUED,
        JobRunStatus.DISPATCHED,
        JobRunStatus.RUNNING,
    }
    if any(counts.get(s, 0) > 0 for s in nonterminal):
        return JobStatus.RUNNING
    if counts.get(JobRunStatus.FAILED, 0) > 0 or counts.get(JobRunStatus.TIMEOUT, 0) > 0:
        return JobStatus.FAILED
    if counts.get(JobRunStatus.CANCELED, 0) > 0 and counts.get(JobRunStatus.COMPLETED, 0) == 0:
        return JobStatus.CANCELED
    return JobStatus.COMPLETED


def artifact_object_key(*, run_id: UUID, original_name: str) -> str:
    """Build the MinIO object key for an artifact upload.

    Layout: `runs/<yyyy>/<mm>/<run_id>/<filename>`. The date prefix
    keeps lifecycle rules simple; the run_id directory keeps related
    artifacts together for browsing in the MinIO console.
    """
    from datetime import UTC, datetime  # local: avoid top-level circular

    now = datetime.now(UTC)
    # Drop any path components from the supplied filename — the agent
    # is untrusted here.
    safe = original_name.replace("/", "_").replace("\\", "_").replace("..", "_")
    if not safe:
        safe = "artifact.bin"
    return f"runs/{now:%Y}/{now:%m}/{run_id}/{safe}"


def artifact_bucket_for(kind: JobKind) -> str:
    """Snapshot bulk dumps land in the snapshots bucket; everything
    else (analyst-facing artifacts) goes to the main artifacts bucket.
    """
    if kind == JobKind.HOST_SWEEP:
        return settings.minio_bucket_snapshots
    return settings.minio_bucket_artifacts
