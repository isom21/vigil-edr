"""Host CRUD (read for analyst+, write for admin)."""
from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, status
from sqlalchemy import func, select

from app.core.deps import DbSession, RequireAdmin, RequireAnalyst
from app.core.errors import not_found
from app.models import Host, HostStatus, OsFamily
from app.schemas.common import Page
from app.schemas.host import HostOut, HostUpdate
from app.services import audit

router = APIRouter(prefix="/api/hosts", tags=["hosts"])


@router.get("", response_model=Page[HostOut])
async def list_hosts(
    db: DbSession,
    actor: RequireAnalyst,
    status_: HostStatus | None = None,
    os_family: OsFamily | None = None,
    q: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> Page[HostOut]:
    stmt = select(Host)
    count_stmt = select(func.count(Host.id))
    if status_:
        stmt = stmt.where(Host.status == status_)
        count_stmt = count_stmt.where(Host.status == status_)
    if os_family:
        stmt = stmt.where(Host.os_family == os_family)
        count_stmt = count_stmt.where(Host.os_family == os_family)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(Host.hostname.ilike(like))
        count_stmt = count_stmt.where(Host.hostname.ilike(like))
    stmt = stmt.order_by(Host.last_seen_at.desc().nulls_last()).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).scalars().all()
    total = (await db.execute(count_stmt)).scalar_one()
    return Page(
        items=[HostOut.model_validate(h) for h in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{host_id}", response_model=HostOut)
async def get_host(host_id: UUID, db: DbSession, actor: RequireAnalyst) -> HostOut:
    host = await db.get(Host, host_id)
    if host is None:
        raise not_found("host", str(host_id))
    return HostOut.model_validate(host)


@router.patch("/{host_id}", response_model=HostOut)
async def update_host(
    host_id: UUID, payload: HostUpdate, db: DbSession, actor: RequireAdmin
) -> HostOut:
    host = await db.get(Host, host_id)
    if host is None:
        raise not_found("host", str(host_id))
    if payload.policy_id is not None:
        host.policy_id = payload.policy_id
    if payload.status is not None:
        host.status = payload.status
    await audit.record(
        db,
        actor=actor,
        action="host.update",
        resource_type="host",
        resource_id=str(host.id),
        payload=payload.model_dump(exclude_none=True),
    )
    return HostOut.model_validate(host)


@router.delete("/{host_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_host(host_id: UUID, db: DbSession, actor: RequireAdmin) -> None:
    host = await db.get(Host, host_id)
    if host is None:
        raise not_found("host", str(host_id))
    await db.delete(host)
    await audit.record(
        db, actor=actor, action="host.delete", resource_type="host", resource_id=str(host_id)
    )
