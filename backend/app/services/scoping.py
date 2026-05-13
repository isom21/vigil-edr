"""M7.5 host-scope helpers + Phase 3 #3.1 tenant scope helpers.

Filters Host (and Host-derived) queries by the actor's host-group
membership and tenant. Admins see all hosts in their tenant;
non-admins see only hosts that share at least one host-group with
them, again restricted to their tenant. Super-admins are not a
special case here — they're tenant-scoped via the active tenant in
their Actor (set from the ``vigil_active_tenant_id`` cookie).

Convention: every router that returns or operates on host-keyed
resources should call ``apply_host_scope()`` (for queries that
already join Host) or ``host_visible_to(actor, host_id, db)`` (for
single-resource checks like GET /hosts/{id} or POST
/hosts/{id}/commands). For non-host-keyed tables, call
``apply_tenant_scope(stmt, actor, Model.tenant_id)``.
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
    """Add a WHERE clause restricting ``host_column`` to hosts visible
    to ``actor``. Admins see every host in their tenant; non-admins
    see only hosts in at least one of their groups, also restricted
    to the tenant. Synthetic / null-host rows (``host_column IS
    NULL`` — e.g. audit-chain-break alerts) are surfaced to admins
    only, matching the M-audit-and-auth #10 invariant.

    Both branches gate on ``Host.tenant_id`` so a tenant-A admin
    can't see tenant-B hosts even via a cross-tenant join."""
    in_tenant = select(Host.id).where(Host.tenant_id == actor.tenant_id)
    if _is_admin(actor):
        # Admins keep seeing rows where the host id is in-tenant OR
        # the host id is NULL (synthetic alerts). Non-admins never
        # see NULL-host rows — SQL's UNKNOWN-on-NULL semantics make
        # the IN clause filter them out automatically.
        return stmt.where(host_column.is_(None) | host_column.in_(in_tenant))
    visible = (
        select(host_in_group.c.host_id)
        .join(
            user_host_group,
            user_host_group.c.host_group_id == host_in_group.c.host_group_id,
        )
        .where(user_host_group.c.user_id == actor.user.id)
    )
    return stmt.where(host_column.in_(in_tenant)).where(host_column.in_(visible))


def apply_tenant_scope(stmt: Select[Any], actor: Actor, tenant_column: Any) -> Select[Any]:
    """Add a ``tenant_id == actor.tenant_id`` filter to a query against
    a non-host-keyed table.

    Use this on tables that carry their own ``tenant_id`` column
    (rules, intel_feeds, notification_channels, etc.) where the
    host-scope walk is not relevant. Super-admins still pass through
    here because their Actor's ``tenant_id`` is already set to the
    active tenant from the cookie."""
    return stmt.where(tenant_column == actor.tenant_id)


async def host_visible_to(actor: Actor, host_id: UUID | None, db: AsyncSession) -> bool:
    """True if ``actor`` can see ``host_id``. Always true for admins
    *inside the actor's tenant*.

    ``host_id=None`` is the synthetic-alert case (e.g. audit chain-
    break alerts that don't belong to any host). Admins see those;
    non-admins don't.

    Cross-tenant lookup returns False so the caller raises 404 via
    ``not_found(...)`` — never 403 — and we don't leak existence.
    """
    if host_id is None:
        return _is_admin(actor)
    # Cross-tenant check first: a tenant-A actor never sees a
    # tenant-B host id, even one belonging to a same-named tenant
    # admin elsewhere.
    host_tenant = (
        await db.execute(select(Host.tenant_id).where(Host.id == host_id))
    ).scalar_one_or_none()
    if host_tenant is None or host_tenant != actor.tenant_id:
        return False
    if _is_admin(actor):
        # Admin in the right tenant — we already proved the host
        # exists and is in-tenant via the SELECT above.
        return True
    q = select(
        exists()
        .where(host_in_group.c.host_id == host_id)
        .where(host_in_group.c.host_group_id == user_host_group.c.host_group_id)
        .where(user_host_group.c.user_id == actor.user.id)
    )
    return (await db.execute(q)).scalar_one()


async def visible_host_ids(actor: Actor, db: AsyncSession) -> list[UUID] | None:
    """Return the list of host ids visible to the actor, or None when
    the caller can safely treat the actor as "see every host in this
    tenant".

    Admins inside their tenant return None — the upstream tenant
    filter on the calling query (or the OpenSearch tenant facet, in
    the hunt code path) is expected to bound the result set. Non-
    admins return the explicit intersection of their host-group
    membership with the actor's active tenant, so the Jobs engine's
    fan-out can never cross tenants even when a stale group row
    references a host that moved tenants.

    Phase 3 #3.1: every caller that previously trusted None-means-
    "all-hosts-everywhere" must now apply a tenant filter
    (``apply_tenant_scope`` or an explicit ``WHERE tenant_id = ?``)
    on the underlying query before consuming the None return."""
    if _is_admin(actor):
        return None
    stmt = (
        select(host_in_group.c.host_id)
        .select_from(
            host_in_group.join(
                user_host_group,
                user_host_group.c.host_group_id == host_in_group.c.host_group_id,
            ).join(Host, Host.id == host_in_group.c.host_id)
        )
        .where(user_host_group.c.user_id == actor.user.id)
        .where(Host.tenant_id == actor.tenant_id)
        .distinct()
    )
    rows = (await db.execute(stmt)).scalars().all()
    return [UUID(str(r)) for r in rows]
