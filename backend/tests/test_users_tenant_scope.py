"""Regression tests for CODE-2, CODE-3.

The /api/users router previously had no tenant scope on any path. A
tenant-A admin could enumerate every tenant's roster, demote another
tenant's admins, reset passwords, force-disable 2FA, and cross-grant
host-group visibility via the per-user groups endpoint.
"""

from __future__ import annotations

import os
from typing import Any

import pytest
import pytest_asyncio


@pytest_asyncio.fixture
async def _two_tenant_users(
    db_session: Any, admin_in_a: Any, admin_in_b: Any, analyst_in_a: Any, analyst_in_b: Any
) -> dict[str, Any]:
    """Return both admins + analysts. Each fixture is bound to its tenant
    by the conftest helpers we reuse."""
    return {
        "admin_a": admin_in_a,
        "admin_b": admin_in_b,
        "analyst_a": analyst_in_a,
        "analyst_b": analyst_in_b,
    }


@pytest.mark.asyncio
async def test_admin_in_a_cannot_list_tenant_b_users(
    http_client: Any, admin_in_a: Any, _two_tenant_users: dict[str, Any]
) -> None:
    from tests.conftest import headers_for

    resp = await http_client.get("/api/users", headers=headers_for(admin_in_a))
    assert resp.status_code == 200
    ids = {item["id"] for item in resp.json()}
    assert str(_two_tenant_users["admin_a"].id) in ids
    assert str(_two_tenant_users["admin_b"].id) not in ids, (
        "tenant-A admin saw tenant-B admin in the roster"
    )
    assert str(_two_tenant_users["analyst_b"].id) not in ids


@pytest.mark.asyncio
async def test_admin_in_a_cannot_patch_tenant_b_user(
    http_client: Any, admin_in_a: Any, _two_tenant_users: dict[str, Any]
) -> None:
    from tests.conftest import headers_for

    target = _two_tenant_users["analyst_b"]
    resp = await http_client.patch(
        f"/api/users/{target.id}",
        json={"disabled": True},
        headers=headers_for(admin_in_a),
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_admin_in_a_cannot_force_disable_2fa_in_tenant_b(
    http_client: Any, admin_in_a: Any, _two_tenant_users: dict[str, Any]
) -> None:
    from tests.conftest import headers_for

    target = _two_tenant_users["analyst_b"]
    resp = await http_client.post(
        f"/api/users/{target.id}/2fa/disable",
        headers=headers_for(admin_in_a),
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_admin_in_a_cannot_delete_tenant_b_user(
    http_client: Any, admin_in_a: Any, _two_tenant_users: dict[str, Any]
) -> None:
    from tests.conftest import headers_for

    target = _two_tenant_users["analyst_b"]
    resp = await http_client.delete(
        f"/api/users/{target.id}",
        headers=headers_for(admin_in_a),
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_create_user_stamps_admin_tenant(
    http_client: Any, admin_in_a: Any, tenant_a: Any, db_session: Any
) -> None:
    from uuid import UUID

    from sqlalchemy import select

    from app.models import User
    from tests.conftest import headers_for

    email = f"new-{os.urandom(3).hex()}@test.local"
    resp = await http_client.post(
        "/api/users",
        json={"email": email, "password": "abcDEF12345!", "role": "analyst"},
        headers=headers_for(admin_in_a),
    )
    assert resp.status_code == 201, resp.text
    new_id = UUID(resp.json()["id"])
    row = (await db_session.execute(select(User).where(User.id == new_id))).scalar_one()
    assert row.tenant_id == tenant_a.id


@pytest.mark.asyncio
async def test_last_admin_lockout_is_per_tenant(
    http_client: Any, admin_in_a: Any, admin_in_b: Any, db_session: Any
) -> None:
    """With one admin per tenant, demoting tenant-A's admin must be
    rejected even though tenant-B's admin is still enabled — the
    last-admin check is per-tenant (CODE-2)."""
    from tests.conftest import headers_for

    resp = await http_client.patch(
        f"/api/users/{admin_in_a.id}",
        json={"role": "analyst"},
        headers=headers_for(admin_in_a),
    )
    assert resp.status_code == 400
    assert "last enabled admin" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_replace_user_groups_drops_cross_tenant_group(
    http_client: Any,
    db_session: Any,
    admin_in_a: Any,
    tenant_a: Any,
    tenant_b: Any,
) -> None:
    """An admin in tenant A can't grant a tenant-A user visibility into
    a tenant-B host group by passing the foreign id (CODE-3)."""
    from app.core.security import hash_password
    from app.models import HostGroup, User, UserRole
    from tests.conftest import headers_for

    target = User(
        email=f"target-{os.urandom(3).hex()}@test.local",
        password_hash=hash_password("p"),
        role=UserRole.ANALYST,
        tenant_id=tenant_a.id,
    )
    own_group = HostGroup(tenant_id=tenant_a.id, name=f"a-group-{os.urandom(2).hex()}")
    foreign_group = HostGroup(tenant_id=tenant_b.id, name=f"b-group-{os.urandom(2).hex()}")
    db_session.add_all([target, own_group, foreign_group])
    await db_session.flush()

    resp = await http_client.post(
        f"/api/users/{target.id}/groups",
        json={"host_group_ids": [str(own_group.id), str(foreign_group.id)]},
        headers=headers_for(admin_in_a),
    )
    assert resp.status_code == 200
    returned = set(resp.json()["host_group_ids"])
    assert returned == {str(own_group.id)}, (
        "foreign tenant's host_group_id leaked into the user's assignment"
    )


@pytest.mark.asyncio
async def test_admin_in_a_cannot_read_tenant_b_user_groups(
    http_client: Any, admin_in_a: Any, _two_tenant_users: dict[str, Any]
) -> None:
    from tests.conftest import headers_for

    target = _two_tenant_users["analyst_b"]
    resp = await http_client.get(
        f"/api/users/{target.id}/groups",
        headers=headers_for(admin_in_a),
    )
    assert resp.status_code == 404
