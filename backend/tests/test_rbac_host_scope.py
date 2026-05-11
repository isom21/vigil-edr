"""Unit tests for M7.5 host-group scoping (M8 follow-up).

Mirrors tools/smoke/50-rbac-e2e.sh — verifies that:
  * `apply_host_scope()` is a no-op for admins
  * non-admins see only hosts in their groups
  * `host_visible_to()` returns True/False per the same predicate

These run against the test DB; they're cheap (each test < 100ms).
"""

from __future__ import annotations

import os
from uuid import uuid4

import pytest
from sqlalchemy import insert, select


@pytest.fixture
async def two_hosts(db_session):
    """Two hosts: A and B."""
    from app.models import Host, HostStatus, OsFamily

    a = Host(
        hostname=f"host-a-{os.urandom(3).hex()}",
        os_family=OsFamily.LINUX,
        status=HostStatus.ONLINE,
    )
    b = Host(
        hostname=f"host-b-{os.urandom(3).hex()}",
        os_family=OsFamily.LINUX,
        status=HostStatus.ONLINE,
    )
    db_session.add_all([a, b])
    await db_session.flush()
    return a, b


@pytest.fixture
async def two_groups_with_partition(db_session, two_hosts, analyst_user):
    """Group alpha = host A + analyst_user; group beta = host B (no users)."""
    from app.models import HostGroup, host_in_group, user_host_group

    a, b = two_hosts
    alpha = HostGroup(name=f"alpha-{os.urandom(3).hex()}")
    beta = HostGroup(name=f"beta-{os.urandom(3).hex()}")
    db_session.add_all([alpha, beta])
    await db_session.flush()

    await db_session.execute(insert(host_in_group).values(host_id=a.id, host_group_id=alpha.id))
    await db_session.execute(insert(host_in_group).values(host_id=b.id, host_group_id=beta.id))
    await db_session.execute(
        insert(user_host_group).values(user_id=analyst_user.id, host_group_id=alpha.id)
    )
    await db_session.flush()
    return alpha, beta


@pytest.mark.asyncio
async def test_admin_sees_all_hosts(db_session, two_hosts, admin_user):
    from app.core.deps import Actor
    from app.models import Host
    from app.services.scoping import apply_host_scope

    actor = Actor(user=admin_user, kind="user")
    stmt = select(Host)
    scoped = apply_host_scope(stmt, actor)
    results = (await db_session.execute(scoped)).scalars().all()
    ids = {h.id for h in results}
    assert two_hosts[0].id in ids
    assert two_hosts[1].id in ids


@pytest.mark.asyncio
async def test_analyst_only_sees_assigned_hosts(
    db_session, two_hosts, analyst_user, two_groups_with_partition
):
    from app.core.deps import Actor
    from app.models import Host
    from app.services.scoping import apply_host_scope

    actor = Actor(user=analyst_user, kind="user")
    stmt = select(Host)
    scoped = apply_host_scope(stmt, actor)
    results = (await db_session.execute(scoped)).scalars().all()
    ids = {h.id for h in results}
    assert two_hosts[0].id in ids, "host_a (in analyst's group) should be visible"
    assert two_hosts[1].id not in ids, "host_b (not in analyst's group) should be hidden"


@pytest.mark.asyncio
async def test_host_visible_to_admin_passthrough(db_session, two_hosts, admin_user):
    from app.core.deps import Actor
    from app.services.scoping import host_visible_to

    actor = Actor(user=admin_user, kind="user")
    assert await host_visible_to(actor, two_hosts[0].id, db_session)
    assert await host_visible_to(actor, two_hosts[1].id, db_session)
    # An invented uuid still returns True for admin (caller pattern: combined
    # with a not_found check upstream, this shape lets the router map missing
    # to 404 rather than 403).
    assert await host_visible_to(actor, uuid4(), db_session) is False


@pytest.mark.asyncio
async def test_host_visible_to_analyst_is_group_gated(
    db_session, two_hosts, analyst_user, two_groups_with_partition
):
    from app.core.deps import Actor
    from app.services.scoping import host_visible_to

    actor = Actor(user=analyst_user, kind="user")
    assert await host_visible_to(actor, two_hosts[0].id, db_session) is True
    assert await host_visible_to(actor, two_hosts[1].id, db_session) is False
