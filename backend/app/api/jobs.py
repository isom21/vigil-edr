"""Jobs API (M23.b).

Endpoints:
  POST   /api/jobs                                — create + fan out
  GET    /api/jobs                                — paginated list
  GET    /api/jobs/{id}                           — detail incl. runs
  GET    /api/jobs/{id}/runs                      — runs (paginated)
  GET    /api/jobs/{id}/runs/{run_id}/artifacts   — artifact list
  POST   /api/jobs/{id}/cancel                    — cancel in-flight
  GET    /api/artifacts/{id}/download             — presigned GET URL

Authorization:
  Analysts can create jobs whose kind is NOT in JOB_KIND_ADMIN_ONLY.
  Admins can create any kind. All readers must already be analysts.
  Host-group scoping is enforced at fan-out time — runs are only
  created for hosts the creator can see.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, status
from sqlalchemy import desc, func, select
from sqlalchemy.orm import selectinload

from app.core.deps import DbSession, RequireAnalyst
from app.core.errors import bad_request, forbidden, not_found
from app.models import (
    JOB_KIND_ADMIN_ONLY,
    Command,
    CommandStatus,
    Host,
    Job,
    JobArtifact,
    JobKind,
    JobRun,
    JobRunStatus,
    JobStatus,
    UserRole,
)
from app.schemas.common import Page
from app.schemas.job import (
    ArtifactDownloadOut,
    JobArtifactOut,
    JobCreate,
    JobDetail,
    JobOut,
    JobRunOut,
)
from app.services import audit
from app.services.jobs import (
    aggregate_status,
    fanout,
    resolve_scope,
)
from app.services.scoping import apply_host_scope, visible_host_ids

router = APIRouter(prefix="/api/jobs", tags=["jobs"])
artifacts_router = APIRouter(prefix="/api/artifacts", tags=["jobs"])


def _hostname_map(db_rows: list[tuple[UUID, str]]) -> dict[UUID, str]:
    return dict(db_rows)


@router.post("", response_model=JobDetail, status_code=status.HTTP_201_CREATED)
async def create_job(
    body: JobCreate,
    db: DbSession,
    actor: RequireAnalyst,
) -> JobDetail:
    if body.kind in JOB_KIND_ADMIN_ONLY and not actor.has_role(UserRole.ADMIN):
        raise forbidden(f"job kind {body.kind.value} requires admin")

    scoped = await visible_host_ids(actor, db)
    target_hosts = await resolve_scope(db, body.scope, visible_host_ids=scoped)
    if not target_hosts:
        raise bad_request("scope did not resolve to any visible hosts")

    summary = body.summary or _default_summary(body.kind, len(target_hosts))
    job = Job(
        kind=body.kind,
        parameters=body.parameters,
        scope_kind=body.scope.kind,
        scope_host_ids=[str(h) for h in target_hosts] if body.scope.host_ids else None,
        scope_group_id=body.scope.group_id,
        status=JobStatus.QUEUED,
        summary=summary,
        created_by_user_id=actor.user.id,
        triggered_by="manual",
    )
    db.add(job)
    await db.flush()

    runs = await fanout(
        db,
        job=job,
        host_ids=target_hosts,
        issued_by_user_id=actor.user.id,
    )

    await audit.record(
        db,
        actor=actor,
        action="job.create",
        resource_type="job",
        resource_id=str(job.id),
        payload={
            "kind": body.kind.value,
            "scope_kind": body.scope.kind.value,
            "host_count": len(runs),
        },
    )
    await db.commit()
    await db.refresh(job)

    # Build response with hostname denormalisation
    host_rows = list(
        (await db.execute(select(Host.id, Host.hostname).where(Host.id.in_(target_hosts)))).all()
    )
    hostnames = _hostname_map([(h, n) for h, n in host_rows])
    detail = _job_to_detail(job, runs, hostnames, artifact_counts={})
    return detail


@router.get("", response_model=Page[JobOut])
async def list_jobs(
    db: DbSession,
    actor: RequireAnalyst,
    kind: JobKind | None = None,
    status_: JobStatus | None = None,
    triggered_by_alert_id: UUID | None = None,
    limit: int = 50,
    offset: int = 0,
) -> Page[JobOut]:
    # Phase 3 #3.1: tenant-scope jobs. Jobs carry their own
    # tenant_id so this filter is index-only — no JobRun -> Host
    # join needed for the cross-tenant gate.
    stmt = select(Job).where(Job.tenant_id == actor.tenant_id)
    count_stmt = select(func.count(Job.id)).where(Job.tenant_id == actor.tenant_id)
    if kind:
        stmt = stmt.where(Job.kind == kind)
        count_stmt = count_stmt.where(Job.kind == kind)
    if status_:
        stmt = stmt.where(Job.status == status_)
        count_stmt = count_stmt.where(Job.status == status_)
    if triggered_by_alert_id is not None:
        stmt = stmt.where(Job.triggered_by_alert_id == triggered_by_alert_id)
        count_stmt = count_stmt.where(Job.triggered_by_alert_id == triggered_by_alert_id)

    # Host-group scope. Restrict Job.id to those that have at least one
    # JobRun whose host is visible to the actor. `apply_host_scope` is a
    # no-op for admins (they see all jobs); for non-admins the inner
    # subquery walks user_host_group ∩ host_in_group via JobRun.host_id.
    # Jobs with zero runs are invisible to non-admins by design — only
    # the creator (and admins) see a still-fanning-out job.
    visible_run_subq = apply_host_scope(
        select(JobRun.job_id).distinct(),
        actor,
        host_column=JobRun.host_id,
    )
    if not actor.has_role(UserRole.ADMIN):
        stmt = stmt.where(Job.id.in_(visible_run_subq))
        count_stmt = count_stmt.where(Job.id.in_(visible_run_subq))

    stmt = stmt.order_by(desc(Job.created_at)).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).scalars().all()
    total = (await db.execute(count_stmt)).scalar_one()

    if not rows:
        return Page(items=[], total=int(total), limit=limit, offset=offset)

    # One bulk query for the run-status aggregates so the list endpoint
    # stays a single round-trip irrespective of page size.
    job_ids = [j.id for j in rows]
    agg_stmt = (
        select(JobRun.job_id, JobRun.status, func.count(JobRun.id))
        .where(JobRun.job_id.in_(job_ids))
        .group_by(JobRun.job_id, JobRun.status)
    )
    aggs: dict[UUID, dict[JobRunStatus, int]] = {}
    for jid, st, c in (await db.execute(agg_stmt)).all():
        aggs.setdefault(jid, {})[st] = int(c)

    items: list[JobOut] = []
    for j in rows:
        agg = aggs.get(j.id, {})
        items.append(
            JobOut.model_validate(
                {
                    **{c.name: getattr(j, c.name) for c in Job.__table__.columns},
                    "run_count": sum(agg.values()),
                    "run_completed": agg.get(JobRunStatus.COMPLETED, 0),
                    "run_failed": agg.get(JobRunStatus.FAILED, 0)
                    + agg.get(JobRunStatus.TIMEOUT, 0),
                }
            )
        )
    return Page(items=items, total=int(total), limit=limit, offset=offset)


@router.get("/{job_id}", response_model=JobDetail)
async def get_job(
    job_id: UUID,
    db: DbSession,
    actor: RequireAnalyst,
) -> JobDetail:
    job = (
        await db.execute(select(Job).options(selectinload(Job.runs)).where(Job.id == job_id))
    ).scalar_one_or_none()
    if job is None:
        raise not_found("job", str(job_id))

    # Host-group scope. Admins see every run; non-admins only see runs
    # whose host they're in a group with. Per the 403/404 unification:
    # if there's no intersection, return 404 (never confirm existence).
    visible = await visible_host_ids(actor, db)
    all_runs = list(job.runs)
    if visible is None:
        runs = all_runs
    else:
        visible_set = set(visible)
        runs = [r for r in all_runs if r.host_id in visible_set]
        if not runs:
            raise not_found("job", str(job_id))

    host_ids = [r.host_id for r in runs]
    hostnames: dict[UUID, str] = {}
    if host_ids:
        rows = (await db.execute(select(Host.id, Host.hostname).where(Host.id.in_(host_ids)))).all()
        hostnames = _hostname_map([(h, n) for h, n in rows])

    artifact_counts = await _artifact_counts(db, [r.id for r in runs])
    return _job_to_detail(job, runs, hostnames, artifact_counts)


@router.get("/{job_id}/runs", response_model=Page[JobRunOut])
async def list_job_runs(
    job_id: UUID,
    db: DbSession,
    actor: RequireAnalyst,
    status_: JobRunStatus | None = None,
    limit: int = 200,
    offset: int = 0,
) -> Page[JobRunOut]:
    job = (
        await db.execute(select(Job).options(selectinload(Job.runs)).where(Job.id == job_id))
    ).scalar_one_or_none()
    if job is None:
        raise not_found("job", str(job_id))

    # 403/404 unification: non-admins with no visible runs see 404 on the
    # parent job itself, not just an empty runs list. The per-run scope
    # below still filters the actual list — this check stops a non-admin
    # from confirming a job's existence via the list endpoint when their
    # group doesn't intersect any of its runs.
    visible = await visible_host_ids(actor, db)
    if visible is not None:
        visible_set = set(visible)
        if not any(r.host_id in visible_set for r in job.runs):
            raise not_found("job", str(job_id))

    stmt = (
        select(JobRun, Host.hostname)
        .join(Host, Host.id == JobRun.host_id, isouter=True)
        .where(JobRun.job_id == job_id)
    )
    count_stmt = select(func.count(JobRun.id)).where(JobRun.job_id == job_id)
    if status_:
        stmt = stmt.where(JobRun.status == status_)
        count_stmt = count_stmt.where(JobRun.status == status_)

    # Host-group scope still applies — non-admins should never see runs
    # for hosts they can't otherwise view.
    stmt = apply_host_scope(stmt, actor, host_column=JobRun.host_id)
    count_stmt = apply_host_scope(count_stmt, actor, host_column=JobRun.host_id)

    stmt = stmt.order_by(desc(JobRun.created_at)).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).all()
    total = (await db.execute(count_stmt)).scalar_one()

    run_ids = [r.id for r, _ in rows]
    counts = await _artifact_counts(db, run_ids)
    items = [_run_to_out(r, hostname, counts.get(r.id, 0)) for r, hostname in rows]
    return Page(items=items, total=int(total), limit=limit, offset=offset)


@router.get(
    "/{job_id}/runs/{run_id}/artifacts",
    response_model=list[JobArtifactOut],
)
async def list_run_artifacts(
    job_id: UUID,
    run_id: UUID,
    db: DbSession,
    actor: RequireAnalyst,
) -> list[JobArtifactOut]:
    run = await db.get(JobRun, run_id)
    if run is None or run.job_id != job_id:
        raise not_found("job_run", str(run_id))

    # Host-group scope. Non-admins can only enumerate artifacts for runs
    # against hosts they share a group with. 404 instead of 403 — see
    # M-audit-and-auth #7 unification.
    from app.services.scoping import host_visible_to

    if not await host_visible_to(actor, run.host_id, db):
        raise not_found("job_run", str(run_id))

    stmt = (
        select(JobArtifact).where(JobArtifact.job_run_id == run_id).order_by(JobArtifact.created_at)
    )
    rows = (await db.execute(stmt)).scalars().all()
    return [JobArtifactOut.model_validate(a) for a in rows]


@router.post("/{job_id}/cancel", response_model=JobDetail)
async def cancel_job(
    job_id: UUID,
    db: DbSession,
    actor: RequireAnalyst,
) -> JobDetail:
    job = (
        await db.execute(select(Job).options(selectinload(Job.runs)).where(Job.id == job_id))
    ).scalar_one_or_none()
    if job is None:
        raise not_found("job", str(job_id))

    # Host-group scope. Non-admins can only cancel jobs that have at
    # least one run targeting a host they share a group with. Without
    # this an analyst with one tiny group could cancel a fleet-wide
    # admin-issued incident response. 404 (not 403) to avoid leaking
    # existence (M-audit-and-auth #7).
    visible = await visible_host_ids(actor, db)
    if visible is not None:
        visible_set = set(visible)
        if not any(r.host_id in visible_set for r in job.runs):
            raise not_found("job", str(job_id))

    if job.status in {JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELED}:
        raise bad_request(f"job already {job.status.value}")

    job.canceled_at = datetime.now(UTC)
    job.status = JobStatus.CANCELED

    # Cancel any non-terminal runs + mark their bridging Commands
    # FAILED so the gRPC dispatch path doesn't keep them.
    for run in job.runs:
        if run.status in {
            JobRunStatus.COMPLETED,
            JobRunStatus.FAILED,
            JobRunStatus.CANCELED,
            JobRunStatus.TIMEOUT,
        }:
            continue
        run.status = JobRunStatus.CANCELED
        run.completed_at = datetime.now(UTC)
        if run.command_id is not None:
            cmd = await db.get(Command, run.command_id)
            if cmd is not None and cmd.status == CommandStatus.PENDING:
                cmd.status = CommandStatus.FAILED
                cmd.error = "canceled by operator"
                cmd.completed_at = datetime.now(UTC)

    await audit.record(
        db,
        actor=actor,
        action="job.cancel",
        resource_type="job",
        resource_id=str(job.id),
    )
    await db.commit()
    await db.refresh(job)

    host_ids = [r.host_id for r in job.runs]
    hostnames: dict[UUID, str] = {}
    if host_ids:
        rows = (await db.execute(select(Host.id, Host.hostname).where(Host.id.in_(host_ids)))).all()
        hostnames = _hostname_map([(h, n) for h, n in rows])
    artifact_counts = await _artifact_counts(db, [r.id for r in job.runs])
    return _job_to_detail(job, list(job.runs), hostnames, artifact_counts)


@artifacts_router.get("/{artifact_id}/download", response_model=ArtifactDownloadOut)
async def download_artifact(
    artifact_id: UUID,
    db: DbSession,
    actor: RequireAnalyst,
) -> ArtifactDownloadOut:
    art = await db.get(JobArtifact, artifact_id)
    if art is None:
        raise not_found("artifact", str(artifact_id))

    # Host-scope check: verify the actor can see the host that produced
    # this artifact. Admins skip the check inside host_visible_to.
    # 403 → 404 per M-audit-and-auth #7 (never confirm existence to a
    # caller who isn't allowed to see the resource).
    run = await db.get(JobRun, art.job_run_id)
    if run is None:
        raise not_found("job_run", str(art.job_run_id))
    from app.services.scoping import host_visible_to

    if not await host_visible_to(actor, run.host_id, db):
        raise not_found("artifact", str(artifact_id))

    # M23.k: hand back a manager-hosted URL. The manager's
    # `/api/downloads/{id}` route streams from MinIO server-side and
    # audit-logs the access there; the analyst's session JWT
    # authenticates the GET, so no token TTL applies.
    from datetime import timedelta

    from app.core.config import settings

    url = f"{settings.manager_public_url.rstrip('/')}/api/downloads/{art.id}"
    expires = datetime.now(UTC) + timedelta(seconds=300)
    return ArtifactDownloadOut(url=url, expires_at=expires)


# ---------- helpers ----------


async def _artifact_counts(db, run_ids: list[UUID]) -> dict[UUID, int]:
    if not run_ids:
        return {}
    stmt = (
        select(JobArtifact.job_run_id, func.count(JobArtifact.id))
        .where(JobArtifact.job_run_id.in_(run_ids))
        .group_by(JobArtifact.job_run_id)
    )
    return {rid: int(c) for rid, c in (await db.execute(stmt)).all()}


def _job_to_detail(
    job: Job,
    runs: list[JobRun],
    hostnames: dict[UUID, str],
    artifact_counts: dict[UUID, int],
) -> JobDetail:
    completed = sum(1 for r in runs if r.status == JobRunStatus.COMPLETED)
    failed = sum(1 for r in runs if r.status in {JobRunStatus.FAILED, JobRunStatus.TIMEOUT})
    return JobDetail.model_validate(
        {
            **{c.name: getattr(job, c.name) for c in Job.__table__.columns},
            "run_count": len(runs),
            "run_completed": completed,
            "run_failed": failed,
            "runs": [
                _run_to_out(r, hostnames.get(r.host_id), artifact_counts.get(r.id, 0)) for r in runs
            ],
        }
    )


def _run_to_out(run: JobRun, hostname: str | None, artifact_count: int) -> JobRunOut:
    return JobRunOut.model_validate(
        {
            **{c.name: getattr(run, c.name) for c in JobRun.__table__.columns},
            "host_hostname": hostname,
            "artifact_count": artifact_count,
        }
    )


def _default_summary(kind: JobKind, host_count: int) -> str:
    return f"{kind.value} × {host_count} host{'s' if host_count != 1 else ''}"


# Re-export aggregate_status so workers can import it without
# pulling in the whole jobs service surface.
__all__ = [
    "router",
    "artifacts_router",
    "aggregate_status",
]
