"""Host group CRUD + membership management (M7.5 RBAC).

All endpoints require ADMIN. Operators / viewers consume groups
implicitly via host scoping — they don't manage them.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, status
from sqlalchemy import delete, func, insert, select

from app.core.deps import DbSession, RequireAdmin
from app.core.errors import bad_request, not_found
from app.models import Host, HostGroup, User, host_in_group, user_host_group
from app.schemas.common import Page
from app.schemas.host_group import (
    HostGroupCreate,
    HostGroupMembership,
    HostGroupOut,
    HostGroupUpdate,
)
from app.services import audit

router = APIRouter(prefix="/api/host-groups", tags=["host-groups"])


async def _hydrate_counts(db, group: HostGroup) -> HostGroupOut:
    h = (
        await db.execute(
            select(func.count())
            .select_from(host_in_group)
            .where(host_in_group.c.host_group_id == group.id)
        )
    ).scalar_one()
    u = (
        await db.execute(
            select(func.count())
            .select_from(user_host_group)
            .where(user_host_group.c.host_group_id == group.id)
        )
    ).scalar_one()
    out = HostGroupOut.model_validate(group)
    out.host_count = h
    out.user_count = u
    return out


@router.get("", response_model=Page[HostGroupOut])
async def list_groups(
    db: DbSession,
    actor: RequireAdmin,
    q: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> Page[HostGroupOut]:
    stmt = select(HostGroup)
    count_stmt = select(func.count(HostGroup.id))
    if q:
        like = f"%{q}%"
        stmt = stmt.where(HostGroup.name.ilike(like))
        count_stmt = count_stmt.where(HostGroup.name.ilike(like))
    stmt = stmt.order_by(HostGroup.name).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).scalars().all()
    total = (await db.execute(count_stmt)).scalar_one()
    items = [await _hydrate_counts(db, g) for g in rows]
    return Page(items=items, total=total, limit=limit, offset=offset)


@router.post("", response_model=HostGroupOut, status_code=status.HTTP_201_CREATED)
async def create_group(
    payload: HostGroupCreate, db: DbSession, actor: RequireAdmin
) -> HostGroupOut:
    dup = (
        await db.execute(select(HostGroup).where(HostGroup.name == payload.name))
    ).scalar_one_or_none()
    if dup is not None:
        raise bad_request(f"host group '{payload.name}' already exists")
    g = HostGroup(name=payload.name, description=payload.description)
    db.add(g)
    await db.flush()
    await audit.record(
        db,
        actor=actor,
        action="host_group.create",
        resource_type="host_group",
        resource_id=str(g.id),
        payload=payload.model_dump(exclude_none=True),
    )
    await db.commit()
    return await _hydrate_counts(db, g)


@router.get("/{group_id}", response_model=HostGroupOut)
async def get_group(group_id: UUID, db: DbSession, actor: RequireAdmin) -> HostGroupOut:
    g = await db.get(HostGroup, group_id)
    if g is None:
        raise not_found("host_group", str(group_id))
    return await _hydrate_counts(db, g)


@router.patch("/{group_id}", response_model=HostGroupOut)
async def update_group(
    group_id: UUID, payload: HostGroupUpdate, db: DbSession, actor: RequireAdmin
) -> HostGroupOut:
    g = await db.get(HostGroup, group_id)
    if g is None:
        raise not_found("host_group", str(group_id))
    if payload.name is not None and payload.name != g.name:
        dup = (
            await db.execute(select(HostGroup).where(HostGroup.name == payload.name))
        ).scalar_one_or_none()
        if dup is not None:
            raise bad_request(f"host group '{payload.name}' already exists")
        g.name = payload.name
    if payload.description is not None:
        g.description = payload.description
    await audit.record(
        db,
        actor=actor,
        action="host_group.update",
        resource_type="host_group",
        resource_id=str(group_id),
        payload=payload.model_dump(exclude_none=True),
    )
    await db.commit()
    return await _hydrate_counts(db, g)


@router.delete("/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_group(group_id: UUID, db: DbSession, actor: RequireAdmin) -> None:
    g = await db.get(HostGroup, group_id)
    if g is None:
        raise not_found("host_group", str(group_id))
    await db.delete(g)
    await audit.record(
        db,
        actor=actor,
        action="host_group.delete",
        resource_type="host_group",
        resource_id=str(group_id),
    )
    await db.commit()


@router.post("/{group_id}/members", response_model=HostGroupMembership)
async def replace_membership(
    group_id: UUID,
    body: HostGroupMembership,
    db: DbSession,
    actor: RequireAdmin,
) -> HostGroupMembership:
    """Replace this group's host + user membership in one call.

    Idempotent: any host_id / user_id passed but unknown is silently
    ignored. Existing assignments outside the new lists are removed.
    """
    g = await db.get(HostGroup, group_id)
    if g is None:
        raise not_found("host_group", str(group_id))

    # Validate ids.
    if body.host_ids:
        valid_hosts = (
            (await db.execute(select(Host.id).where(Host.id.in_(body.host_ids)))).scalars().all()
        )
    else:
        valid_hosts = []
    if body.user_ids:
        valid_users = (
            (await db.execute(select(User.id).where(User.id.in_(body.user_ids)))).scalars().all()
        )
    else:
        valid_users = []

    # Replace in a single transaction.
    await db.execute(delete(host_in_group).where(host_in_group.c.host_group_id == group_id))
    await db.execute(delete(user_host_group).where(user_host_group.c.host_group_id == group_id))
    for hid in valid_hosts:
        await db.execute(insert(host_in_group).values(host_id=hid, host_group_id=group_id))
    for uid in valid_users:
        await db.execute(insert(user_host_group).values(user_id=uid, host_group_id=group_id))

    await audit.record(
        db,
        actor=actor,
        action="host_group.members.replace",
        resource_type="host_group",
        resource_id=str(group_id),
        payload={"hosts": [str(h) for h in valid_hosts], "users": [str(u) for u in valid_users]},
    )
    await db.commit()
    return HostGroupMembership(host_ids=list(valid_hosts), user_ids=list(valid_users))


@router.get("/{group_id}/members", response_model=HostGroupMembership)
async def get_membership(group_id: UUID, db: DbSession, actor: RequireAdmin) -> HostGroupMembership:
    g = await db.get(HostGroup, group_id)
    if g is None:
        raise not_found("host_group", str(group_id))
    hosts = (
        (
            await db.execute(
                select(host_in_group.c.host_id).where(host_in_group.c.host_group_id == group_id)
            )
        )
        .scalars()
        .all()
    )
    users = (
        (
            await db.execute(
                select(user_host_group.c.user_id).where(user_host_group.c.host_group_id == group_id)
            )
        )
        .scalars()
        .all()
    )
    return HostGroupMembership(host_ids=list(hosts), user_ids=list(users))
