"""Phase 3 #3.2: archive job API.

Three operator-facing endpoints:

  * ``GET /api/archive`` — list **frozen** indices (admin / analyst /
    viewer can read; the cold-archive view doesn't expose sensitive
    data — just OpenSearch index names + sizes).
  * ``GET /api/archive/jobs`` — full job ledger including ``failed``
    rows so operators can debug a stuck freeze.
  * ``POST /api/archive/{job_id}/rehydrate`` — admin-only, audited.
    Kicks off the rehydrate in a background task because the bulk
    re-index can take tens of seconds for a fat index.
"""

from __future__ import annotations

from uuid import UUID

import structlog
from fastapi import APIRouter, BackgroundTasks
from sqlalchemy import select

from app.core.db import SessionLocal
from app.core.deps import DbSession, RequireAdmin, RequireViewer
from app.core.errors import bad_request, not_found
from app.models import ArchiveJob, ArchiveJobStatus
from app.schemas.archive import ArchiveJobOut
from app.services import archive, audit

log = structlog.get_logger()

router = APIRouter(prefix="/api/archive", tags=["archive"])


def _to_out(j: ArchiveJob) -> ArchiveJobOut:
    return ArchiveJobOut(
        id=j.id,
        index_name=j.index_name,
        status=j.status,
        started_at=j.started_at,
        finished_at=j.finished_at,
        doc_count=j.doc_count,
        s3_key=j.s3_key,
        error=j.error,
        created_at=j.created_at,
    )


@router.get("", response_model=list[ArchiveJobOut])
async def list_frozen(
    db: DbSession,
    actor: RequireViewer,
    limit: int = 200,
) -> list[ArchiveJobOut]:
    """List successfully-frozen indices, newest first. The UI's main
    table renders off this — failed/in-flight rows are visible via
    ``GET /jobs``."""
    rows = (
        (
            await db.execute(
                select(ArchiveJob)
                .where(ArchiveJob.status == ArchiveJobStatus.FROZEN.value)
                .order_by(ArchiveJob.created_at.desc())
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    return [_to_out(r) for r in rows]


@router.get("/jobs", response_model=list[ArchiveJobOut])
async def list_jobs(
    db: DbSession,
    actor: RequireViewer,
    limit: int = 200,
) -> list[ArchiveJobOut]:
    """All archive_job rows, newest first, regardless of status."""
    rows = (
        (await db.execute(select(ArchiveJob).order_by(ArchiveJob.created_at.desc()).limit(limit)))
        .scalars()
        .all()
    )
    return [_to_out(r) for r in rows]


async def _do_rehydrate(job_id: UUID) -> None:
    """Background-task entry point. Opens a fresh session so the
    rehydrate runs independently of the request's transaction."""
    async with SessionLocal() as db:
        job = await db.get(ArchiveJob, job_id)
        if job is None:
            return
        try:
            await archive.rehydrate(job, db)
        except Exception:  # pragma: no cover — already recorded on the row
            pass
        await db.commit()


@router.post("/{job_id}/rehydrate", response_model=ArchiveJobOut)
async def rehydrate_job(
    job_id: UUID,
    db: DbSession,
    actor: RequireAdmin,
    bg: BackgroundTasks,
) -> ArchiveJobOut:
    """Queue a rehydrate. The actual bulk re-index happens in a
    background task; the response surfaces the row already flipped to
    ``rehydrating`` so the UI can show progress immediately."""
    job = await db.get(ArchiveJob, job_id)
    if job is None:
        raise not_found("archive_job", str(job_id))
    if job.status != ArchiveJobStatus.FROZEN.value:
        raise bad_request(
            f"archive_job {job_id} is in status '{job.status}'; "
            "only 'frozen' jobs can be rehydrated"
        )
    await audit.record(
        db,
        actor=actor,
        action="archive.rehydrate",
        resource_type="archive_job",
        resource_id=str(job.id),
        payload={"s3_key": job.s3_key, "target_index": f"{job.index_name}-rehydrated"},
    )
    # Flip status pre-commit so the UI's next poll sees the
    # in-flight state before the background task even starts.
    job.status = ArchiveJobStatus.REHYDRATING.value
    await db.commit()
    await db.refresh(job)
    bg.add_task(_do_rehydrate, job.id)
    return _to_out(job)
