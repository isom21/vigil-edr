"""Regression tests for CODE-13 and CODE-14.

* /api/dns-blocks list / create / delete / import had no tenant
  filter — a tenant-A admin could enumerate and mutate tenant B's
  sinkhole rules.
* /api/host-groups/{id}/allowlist gated existence on `_require_group`
  but didn't check tenant — flipping another tenant's group into
  ENFORCE could brick every binary on tenant B's fleet.
"""

from __future__ import annotations

import os
from typing import Any

import pytest
import pytest_asyncio

# ---------- dns_block (CODE-13) -------------------------------------------


@pytest_asyncio.fixture
async def _per_tenant_dns_blocks(db_session: Any, tenant_a: Any, tenant_b: Any) -> tuple[Any, Any]:
    from app.models import DnsBlockEntry

    a = DnsBlockEntry(
        tenant_id=tenant_a.id,
        domain=f"a-{os.urandom(2).hex()}.example",
        action="block",
    )
    b = DnsBlockEntry(
        tenant_id=tenant_b.id,
        domain=f"b-{os.urandom(2).hex()}.example",
        action="block",
    )
    db_session.add_all([a, b])
    await db_session.flush()
    return a, b


@pytest.mark.asyncio
async def test_dns_list_invisibility(
    http_client: Any, admin_in_a: Any, _per_tenant_dns_blocks: tuple[Any, Any]
) -> None:
    from tests.conftest import headers_for

    a, b = _per_tenant_dns_blocks
    resp = await http_client.get("/api/dns-blocks", headers=headers_for(admin_in_a))
    assert resp.status_code == 200
    ids = {item["id"] for item in resp.json()}
    assert str(a.id) in ids
    assert str(b.id) not in ids


@pytest.mark.asyncio
async def test_dns_delete_404_cross_tenant(
    http_client: Any, admin_in_a: Any, _per_tenant_dns_blocks: tuple[Any, Any]
) -> None:
    from tests.conftest import headers_for

    _, b = _per_tenant_dns_blocks
    resp = await http_client.delete(f"/api/dns-blocks/{b.id}", headers=headers_for(admin_in_a))
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_dns_create_rejects_cross_tenant_host_group(
    http_client: Any,
    db_session: Any,
    admin_in_a: Any,
    tenant_b: Any,
) -> None:
    from app.models import HostGroup
    from tests.conftest import headers_for

    foreign = HostGroup(tenant_id=tenant_b.id, name=f"b-grp-{os.urandom(2).hex()}")
    db_session.add(foreign)
    await db_session.flush()

    resp = await http_client.post(
        "/api/dns-blocks",
        json={
            "domain": f"evil-{os.urandom(2).hex()}.example",
            "action": "block",
            "host_group_id": str(foreign.id),
        },
        headers=headers_for(admin_in_a),
    )
    assert resp.status_code == 400
    assert "unknown host_group_id" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_dns_create_stamps_actor_tenant(
    http_client: Any, admin_in_a: Any, tenant_a: Any, db_session: Any
) -> None:
    from uuid import UUID

    from sqlalchemy import select

    from app.models import DnsBlockEntry
    from tests.conftest import headers_for

    resp = await http_client.post(
        "/api/dns-blocks",
        json={
            "domain": f"new-{os.urandom(2).hex()}.example",
            "action": "block",
        },
        headers=headers_for(admin_in_a),
    )
    assert resp.status_code == 201, resp.text
    new_id = UUID(resp.json()["id"])
    row = (
        await db_session.execute(select(DnsBlockEntry).where(DnsBlockEntry.id == new_id))
    ).scalar_one()
    assert row.tenant_id == tenant_a.id


# ---------- allowlist (CODE-14) -------------------------------------------


@pytest.mark.asyncio
async def test_allowlist_mode_returns_404_cross_tenant_group(
    http_client: Any,
    db_session: Any,
    admin_in_a: Any,
    tenant_b: Any,
) -> None:
    """Reading a tenant-B group's allowlist mode must 404."""
    from app.models import HostGroup
    from tests.conftest import headers_for

    foreign = HostGroup(tenant_id=tenant_b.id, name=f"b-grp-{os.urandom(2).hex()}")
    db_session.add(foreign)
    await db_session.flush()

    resp = await http_client.get(
        f"/api/host-groups/{foreign.id}/allowlist",
        headers=headers_for(admin_in_a),
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_allowlist_update_mode_returns_404_cross_tenant_group(
    http_client: Any,
    db_session: Any,
    admin_in_a: Any,
    tenant_b: Any,
) -> None:
    """Flipping a tenant-B group into ENFORCE would brick that
    tenant's exec across every host in the group."""
    from app.models import HostGroup
    from tests.conftest import headers_for

    foreign = HostGroup(tenant_id=tenant_b.id, name=f"b-grp-{os.urandom(2).hex()}")
    db_session.add(foreign)
    await db_session.flush()

    resp = await http_client.put(
        f"/api/host-groups/{foreign.id}/allowlist/mode",
        json={"mode": "enforce"},
        headers=headers_for(admin_in_a),
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_allowlist_list_entries_returns_404_cross_tenant_group(
    http_client: Any,
    db_session: Any,
    admin_in_a: Any,
    tenant_b: Any,
) -> None:
    from app.models import HostGroup
    from tests.conftest import headers_for

    foreign = HostGroup(tenant_id=tenant_b.id, name=f"b-grp-{os.urandom(2).hex()}")
    db_session.add(foreign)
    await db_session.flush()

    resp = await http_client.get(
        f"/api/host-groups/{foreign.id}/allowlist/entries",
        headers=headers_for(admin_in_a),
    )
    assert resp.status_code == 404
