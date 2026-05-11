"""M20.c quarantine inventory + release.

Two routers in this module:
  * `/api/hosts/{host_id}/quarantined` — list rows for one host.
  * `/api/quarantined/{id}/release` — queue a RELEASE_QUARANTINE
    command back to the agent that holds the file. Quarantined_files
    row flips to released only after the agent confirms via its
    QuarantineCompletedEvent (handled by the quarantine worker).
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, status
from pydantic import BaseModel
from sqlalchemy import desc, func, select

from app.core.deps import DbSession, RequireAdmin, RequireAnalyst
from app.core.errors import bad_request, forbidden, not_found
from app.models import Command, CommandKind, CommandStatus, Host, QuarantinedFile, QuarantineStatus
from app.schemas.common import ORMModel, Page
from app.services import audit
from app.services.scoping import host_visible_to

per_host_router = APIRouter(prefix="/api/hosts", tags=["quarantine"])
flat_router = APIRouter(prefix="/api/quarantined", tags=["quarantine"])


class QuarantinedFileOut(ORMModel):
    id: UUID
    host_id: UUID
    # Joined denormalisation so the fleet table shows a hostname
    # instead of an opaque uuid; per-host view leaves it blank since
    # the hostname is already in the page header.
    host_hostname: str | None = None
    alert_id: UUID | None
    command_id: UUID | None
    original_path: str
    sha256: str
    size_bytes: int
    deleted_original: bool
    quarantined_at: datetime
    released_at: datetime | None
    status: QuarantineStatus


class QuarantineReleaseRequest(BaseModel):
    # Optional: where to restore. Defaults to the original_path the
    # row already remembers.
    target_path: str | None = None


@per_host_router.get("/{host_id}/quarantined", response_model=Page[QuarantinedFileOut])
async def list_quarantined_for_host(
    host_id: UUID,
    db: DbSession,
    actor: RequireAnalyst,
    status_: QuarantineStatus | None = None,
    limit: int = 50,
    offset: int = 0,
) -> Page[QuarantinedFileOut]:
    host = await db.get(Host, host_id)
    if host is None:
        raise not_found("host", str(host_id))
    if not await host_visible_to(actor, host_id, db):
        raise forbidden("host not in any of your groups")

    stmt = select(QuarantinedFile).where(QuarantinedFile.host_id == host_id)
    count_stmt = select(func.count(QuarantinedFile.id)).where(QuarantinedFile.host_id == host_id)
    if status_ is not None:
        stmt = stmt.where(QuarantinedFile.status == status_)
        count_stmt = count_stmt.where(QuarantinedFile.status == status_)
    stmt = stmt.order_by(desc(QuarantinedFile.quarantined_at)).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).scalars().all()
    total = (await db.execute(count_stmt)).scalar_one()
    return Page(
        items=[QuarantinedFileOut.model_validate(r) for r in rows],
        total=int(total),
        limit=limit,
        offset=offset,
    )


@flat_router.get("", response_model=Page[QuarantinedFileOut])
async def list_quarantined_fleet(
    db: DbSession,
    actor: RequireAnalyst,
    status_: QuarantineStatus | None = None,
    sha256: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> Page[QuarantinedFileOut]:
    """M22.d: fleet-wide quarantined files list (any host the actor can see)."""
    from app.services.scoping import apply_host_scope

    # Outer-join Host so deleted hosts still surface; hostname goes on
    # the response so the UI doesn't have to N+1 a hosts lookup.
    stmt = select(QuarantinedFile, Host.hostname).join(
        Host, Host.id == QuarantinedFile.host_id, isouter=True
    )
    count_stmt = select(func.count(QuarantinedFile.id))
    if status_ is not None:
        stmt = stmt.where(QuarantinedFile.status == status_)
        count_stmt = count_stmt.where(QuarantinedFile.status == status_)
    if sha256:
        stmt = stmt.where(QuarantinedFile.sha256 == sha256.lower())
        count_stmt = count_stmt.where(QuarantinedFile.sha256 == sha256.lower())
    stmt = apply_host_scope(stmt, actor, host_column=QuarantinedFile.host_id)
    count_stmt = apply_host_scope(count_stmt, actor, host_column=QuarantinedFile.host_id)
    stmt = stmt.order_by(desc(QuarantinedFile.quarantined_at)).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).all()
    total = (await db.execute(count_stmt)).scalar_one()
    items: list[QuarantinedFileOut] = []
    for row, hostname in rows:
        out = QuarantinedFileOut.model_validate(row)
        out.host_hostname = hostname
        items.append(out)
    return Page(
        items=items,
        total=int(total),
        limit=limit,
        offset=offset,
    )


@flat_router.post(
    "/{quarantine_id}/release",
    response_model=QuarantinedFileOut,
)
async def release_quarantined_file(
    quarantine_id: UUID,
    payload: QuarantineReleaseRequest,
    db: DbSession,
    actor: RequireAnalyst,
) -> QuarantinedFileOut:
    row = await db.get(QuarantinedFile, quarantine_id)
    if row is None:
        raise not_found("quarantined_file", str(quarantine_id))
    if row.status != QuarantineStatus.ACTIVE:
        raise bad_request(f"quarantined file already {row.status.value}")
    if not await host_visible_to(actor, row.host_id, db):
        raise forbidden("host not in any of your groups")

    cmd = Command(
        host_id=row.host_id,
        kind=CommandKind.RELEASE_QUARANTINE,
        status=CommandStatus.PENDING,
        payload={
            "sha256": row.sha256,
            "target_path": payload.target_path or row.original_path,
        },
        issued_by_user_id=actor.user.id,
    )
    db.add(cmd)
    await db.flush()
    row.command_id = cmd.id
    await audit.record(
        db,
        actor=actor,
        action="quarantine.release",
        resource_type="quarantined_file",
        resource_id=str(row.id),
        payload={
            "host_id": str(row.host_id),
            "sha256": row.sha256,
            "command_id": str(cmd.id),
        },
    )
    await db.commit()
    return QuarantinedFileOut.model_validate(row)


@flat_router.delete("/{quarantine_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_quarantined_record(
    quarantine_id: UUID,
    db: DbSession,
    actor: RequireAdmin,
) -> None:
    """Mark a quarantine record as permanently deleted. Does NOT touch
    the agent's on-disk copy — operator must run a separate sweep, or
    just leave the quarantine dir alone. This call only flips the PG
    row so the UI stops listing it."""
    row = await db.get(QuarantinedFile, quarantine_id)
    if row is None:
        raise not_found("quarantined_file", str(quarantine_id))
    row.status = QuarantineStatus.DELETED
    await audit.record(
        db,
        actor=actor,
        action="quarantine.delete",
        resource_type="quarantined_file",
        resource_id=str(row.id),
    )
    await db.commit()
