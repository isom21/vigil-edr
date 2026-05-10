"""Host CRUD (read for analyst+, write for admin) + stats."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, status
from sqlalchemy import case, func, select

from app.core.deps import DbSession, RequireAdmin, RequireAnalyst
from app.core.errors import bad_request, forbidden, not_found
from app.models import Host, HostStatus, OsFamily
from app.schemas.common import Page
from app.schemas.host import HostOut, HostUpdate
from app.schemas.stats import StatBucket
from app.services import audit
from app.services.scoping import apply_host_scope, host_visible_to
from app.services.sorting import parse_sort

router = APIRouter(prefix="/api/hosts", tags=["hosts"])


_SORTABLE = {
    "hostname": Host.hostname,
    "last_seen_at": Host.last_seen_at,
    "status": Host.status,
    "agent_version": Host.agent_version,
    "enrolled_at": Host.enrolled_at,
    "os_family": Host.os_family,
}


@router.get("", response_model=Page[HostOut])
async def list_hosts(
    db: DbSession,
    actor: RequireAnalyst,
    status_: HostStatus | None = None,
    os_family: OsFamily | None = None,
    q: str | None = None,
    sort: str | None = None,
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
    stmt = apply_host_scope(stmt, actor)
    count_stmt = apply_host_scope(count_stmt, actor)
    order = parse_sort(sort, _SORTABLE, default=[Host.last_seen_at.desc().nulls_last()])
    stmt = stmt.order_by(*order).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).scalars().all()
    total = (await db.execute(count_stmt)).scalar_one()
    return Page(
        items=[HostOut.model_validate(h) for h in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/stats", response_model=list[StatBucket])
async def host_stats(
    db: DbSession,
    actor: RequireAnalyst,
    bucket: str,
) -> list[StatBucket]:
    """Aggregations for the fleet charts.

    bucket=status|os_family|agent_version|last_seen
    """
    if bucket == "status":
        stmt = select(Host.status, func.count(Host.id)).group_by(Host.status)
    elif bucket == "os_family":
        stmt = select(Host.os_family, func.count(Host.id)).group_by(Host.os_family)
    elif bucket == "agent_version":
        stmt = (
            select(Host.agent_version, func.count(Host.id))
            .group_by(Host.agent_version)
            .order_by(func.count(Host.id).desc())
            .limit(10)
        )
    elif bucket == "last_seen":
        cutoff_5m = datetime.now(UTC) - timedelta(minutes=5)
        cutoff_24h = datetime.now(UTC) - timedelta(hours=24)
        bucket_expr = case(
            (Host.last_seen_at.is_(None), "never"),
            (Host.last_seen_at >= cutoff_5m, "online"),
            (Host.last_seen_at >= cutoff_24h, "idle"),
            else_="stale",
        )
        stmt = select(bucket_expr.label("b"), func.count(Host.id)).group_by("b")
    else:
        raise bad_request("bucket must be one of: status, os_family, agent_version, last_seen")
    stmt = apply_host_scope(stmt, actor)
    rows = (await db.execute(stmt)).all()
    return [StatBucket(key=_key_str(k), count=int(c)) for k, c in rows]


def _key_str(v) -> str:
    if v is None:
        return "unknown"
    if hasattr(v, "value"):
        return v.value
    return str(v)


@router.get("/{host_id}", response_model=HostOut)
async def get_host(host_id: UUID, db: DbSession, actor: RequireAnalyst) -> HostOut:
    host = await db.get(Host, host_id)
    if host is None:
        raise not_found("host", str(host_id))
    if not await host_visible_to(actor, host_id, db):
        raise forbidden("host not in any of your groups")
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
