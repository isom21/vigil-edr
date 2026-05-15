"""Regression test for CODE-1.

Admins in tenant A must not be able to list, get, mutate, delete, or
push membership into tenant B's host groups — the host_groups router
previously had no tenant scope, so cross-tenant enumeration + mutation
was possible.
"""

from __future__ import annotations

import os
from typing import Any

import pytest
import pytest_asyncio


@pytest_asyncio.fixture
async def _two_tenant_groups(db_session: Any, tenant_a: Any, tenant_b: Any) -> tuple[Any, Any]:
    from app.models import HostGroup

    a = HostGroup(
        tenant_id=tenant_a.id,
        name=f"linux-prod-a-{os.urandom(2).hex()}",
        description="tenant A group",
    )
    b = HostGroup(
        tenant_id=tenant_b.id,
        name=f"linux-prod-b-{os.urandom(2).hex()}",
        description="tenant B group",
    )
    db_session.add_all([a, b])
    await db_session.flush()
    return a, b


@pytest.mark.asyncio
async def test_admin_in_a_cannot_list_tenant_b_groups(
    http_client: Any,
    admin_in_a: Any,
    _two_tenant_groups: tuple[Any, Any],
) -> None:
    from tests.conftest import headers_for

    a, b = _two_tenant_groups
    resp = await http_client.get("/api/host-groups", headers=headers_for(admin_in_a))
    assert resp.status_code == 200
    ids = {item["id"] for item in resp.json()["items"]}
    assert str(a.id) in ids
    assert str(b.id) not in ids, "tenant A admin saw tenant B's host group"


@pytest.mark.asyncio
async def test_admin_in_a_cannot_get_tenant_b_group(
    http_client: Any,
    admin_in_a: Any,
    _two_tenant_groups: tuple[Any, Any],
) -> None:
    """Cross-tenant get returns 404 (not 403) — keeps existence opaque."""
    from tests.conftest import headers_for

    _, b = _two_tenant_groups
    resp = await http_client.get(f"/api/host-groups/{b.id}", headers=headers_for(admin_in_a))
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_admin_in_a_cannot_patch_tenant_b_group(
    http_client: Any,
    admin_in_a: Any,
    _two_tenant_groups: tuple[Any, Any],
) -> None:
    from tests.conftest import headers_for

    _, b = _two_tenant_groups
    resp = await http_client.patch(
        f"/api/host-groups/{b.id}",
        json={"description": "hijacked"},
        headers=headers_for(admin_in_a),
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_admin_in_a_cannot_delete_tenant_b_group(
    http_client: Any,
    admin_in_a: Any,
    _two_tenant_groups: tuple[Any, Any],
) -> None:
    from tests.conftest import headers_for

    _, b = _two_tenant_groups
    resp = await http_client.delete(f"/api/host-groups/{b.id}", headers=headers_for(admin_in_a))
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_admin_in_a_create_stamps_their_tenant_id(
    http_client: Any,
    admin_in_a: Any,
    tenant_a: Any,
    db_session: Any,
) -> None:
    """The Create handler must stamp the actor's tenant_id, not fall
    back to DEFAULT_TENANT_ID."""
    from uuid import UUID

    from sqlalchemy import select

    from app.models import HostGroup
    from tests.conftest import headers_for

    resp = await http_client.post(
        "/api/host-groups",
        json={"name": f"created-{os.urandom(3).hex()}", "description": "x"},
        headers=headers_for(admin_in_a),
    )
    assert resp.status_code == 201
    new_id = UUID(resp.json()["id"])
    row = (await db_session.execute(select(HostGroup).where(HostGroup.id == new_id))).scalar_one()
    assert row.tenant_id == tenant_a.id


@pytest.mark.asyncio
async def test_replace_membership_rejects_cross_tenant_host_and_user(
    http_client: Any,
    db_session: Any,
    admin_in_a: Any,
    tenant_a: Any,
    tenant_b: Any,
    _two_tenant_groups: tuple[Any, Any],
) -> None:
    """An admin can't sneak a tenant-B host or user into a tenant-A
    group by passing the foreign id in the membership body. The
    validation must silently drop cross-tenant ids (mirrors the
    existing behaviour of dropping unknown ids)."""
    from app.core.security import hash_password
    from app.models import Host, HostStatus, OsFamily, User, UserRole
    from tests.conftest import headers_for

    a, _ = _two_tenant_groups
    foreign_host = Host(
        tenant_id=tenant_b.id,
        hostname=f"b-host-{os.urandom(3).hex()}",
        os_family=OsFamily.LINUX,
        status=HostStatus.ONLINE,
    )
    foreign_user = User(
        email=f"b-user-{os.urandom(3).hex()}@test.local",
        password_hash=hash_password("p"),
        role=UserRole.ANALYST,
        tenant_id=tenant_b.id,
    )
    db_session.add_all([foreign_host, foreign_user])
    await db_session.flush()

    resp = await http_client.post(
        f"/api/host-groups/{a.id}/members",
        json={
            "host_ids": [str(foreign_host.id)],
            "user_ids": [str(foreign_user.id)],
        },
        headers=headers_for(admin_in_a),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["host_ids"] == []
    assert body["user_ids"] == []
