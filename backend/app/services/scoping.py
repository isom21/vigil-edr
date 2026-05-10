"""M7.5 host-scope helpers.

Filters Host (and Host-derived) queries by the actor's host-group
membership. Admins see all hosts; non-admins see only hosts that
share at least one group with them.

Convention: every router that returns or operates on host-keyed
resources should call `apply_host_scope()` (for queries that already
join Host) or `host_visible_to(actor, host_id, db)` (for single-resource
checks like GET /hosts/{id} or POST /hosts/{id}/commands).
"""
from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import exists, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Select

from app.core.deps import Actor
from app.models import Host, UserRole, host_in_group, user_host_group


def _is_admin(actor: Actor) -> bool:
    return actor.has_role(UserRole.ADMIN)


def apply_host_scope(stmt: Select[Any], actor: Actor, host_column: Any = Host.id) -> Select[Any]:
    """Add a WHERE clause restricting `host_column` to hosts visible to
    `actor`. Admins are pass-through. Other users see only hosts in at
    least one of their groups."""
    if _is_admin(actor):
        return stmt
    visible = (
        select(host_in_group.c.host_id)
        .join(
            user_host_group,
            user_host_group.c.host_group_id == host_in_group.c.host_group_id,
        )
        .where(user_host_group.c.user_id == actor.user.id)
    )
    return stmt.where(host_column.in_(visible))


async def host_visible_to(actor: Actor, host_id: UUID, db: AsyncSession) -> bool:
    """True if `actor` can see `host_id`. Always true for admins."""
    if _is_admin(actor):
        # Just verify the host exists; don't apply scope.
        return (await db.execute(select(exists().where(Host.id == host_id)))).scalar_one()
    q = (
        select(exists()
            .where(host_in_group.c.host_id == host_id)
            .where(host_in_group.c.host_group_id == user_host_group.c.host_group_id)
            .where(user_host_group.c.user_id == actor.user.id)
        )
    )
    return (await db.execute(q)).scalar_one()
