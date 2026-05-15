"""Regression test for CODE-20.

The Dashboard table predated Phase 3 multi-tenancy. Pre-PR, a
`shared=true` dashboard authored by a tenant-A admin showed up in
every other tenant's analysts' list views — the router checked
ownership but not tenant.

Migration 20260515_1100_dashboard_tenant_id adds the column.
"""

from __future__ import annotations

import os
from typing import Any

import pytest
import pytest_asyncio


@pytest_asyncio.fixture
async def _per_tenant_dashboards(
    db_session: Any,
    admin_in_a: Any,
    admin_in_b: Any,
) -> tuple[Any, Any]:
    from app.models import Dashboard

    a = Dashboard(
        tenant_id=admin_in_a.tenant_id,
        owner_user_id=admin_in_a.id,
        name=f"a-{os.urandom(2).hex()}",
        shared=True,  # explicitly shared so pre-PR behaviour would leak it
        widgets_json=[],
    )
    b = Dashboard(
        tenant_id=admin_in_b.tenant_id,
        owner_user_id=admin_in_b.id,
        name=f"b-{os.urandom(2).hex()}",
        shared=True,
        widgets_json=[],
    )
    db_session.add_all([a, b])
    await db_session.flush()
    return a, b


@pytest.mark.asyncio
async def test_shared_dashboard_does_not_leak_across_tenants(
    http_client: Any,
    admin_in_a: Any,
    _per_tenant_dashboards: tuple[Any, Any],
) -> None:
    """The headline CODE-20 regression: shared=true rows in tenant A
    must not appear in tenant B's list."""
    from tests.conftest import headers_for

    a, b = _per_tenant_dashboards
    resp = await http_client.get("/api/dashboards", headers=headers_for(admin_in_a))
    assert resp.status_code == 200
    ids = {item["id"] for item in resp.json()}
    assert str(a.id) in ids
    assert str(b.id) not in ids, (
        "shared dashboard from tenant B leaked into tenant A's list (CODE-20)"
    )


@pytest.mark.asyncio
async def test_get_dashboard_returns_404_cross_tenant(
    http_client: Any, admin_in_a: Any, _per_tenant_dashboards: tuple[Any, Any]
) -> None:
    from tests.conftest import headers_for

    _, b = _per_tenant_dashboards
    resp = await http_client.get(f"/api/dashboards/{b.id}", headers=headers_for(admin_in_a))
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_put_dashboard_returns_404_cross_tenant(
    http_client: Any, admin_in_a: Any, _per_tenant_dashboards: tuple[Any, Any]
) -> None:
    from tests.conftest import headers_for

    _, b = _per_tenant_dashboards
    resp = await http_client.put(
        f"/api/dashboards/{b.id}",
        json={"name": "hijacked"},
        headers=headers_for(admin_in_a),
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_dashboard_returns_404_cross_tenant(
    http_client: Any, admin_in_a: Any, _per_tenant_dashboards: tuple[Any, Any]
) -> None:
    from tests.conftest import headers_for

    _, b = _per_tenant_dashboards
    resp = await http_client.delete(f"/api/dashboards/{b.id}", headers=headers_for(admin_in_a))
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_duplicate_dashboard_returns_404_cross_tenant(
    http_client: Any, admin_in_a: Any, _per_tenant_dashboards: tuple[Any, Any]
) -> None:
    """Duplicating a tenant-B shared dashboard would clone its layout
    into tenant A. Must 404."""
    from tests.conftest import headers_for

    _, b = _per_tenant_dashboards
    resp = await http_client.post(
        f"/api/dashboards/{b.id}/duplicate", headers=headers_for(admin_in_a)
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_create_dashboard_stamps_actor_tenant_id(
    http_client: Any, admin_in_a: Any, tenant_a: Any, db_session: Any
) -> None:
    from uuid import UUID

    from sqlalchemy import select

    from app.models import Dashboard
    from tests.conftest import headers_for

    resp = await http_client.post(
        "/api/dashboards",
        json={
            "name": f"new-{os.urandom(2).hex()}",
            "shared": False,
            "widgets_json": [],
        },
        headers=headers_for(admin_in_a),
    )
    assert resp.status_code == 201, resp.text
    new_id = UUID(resp.json()["id"])
    row = (await db_session.execute(select(Dashboard).where(Dashboard.id == new_id))).scalar_one()
    assert row.tenant_id == tenant_a.id
