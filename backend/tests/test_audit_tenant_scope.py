"""Regression test for CODE-19, CODE-35.

/api/audit was admin-only but completely unfiltered — a tenant-A
admin's GET /api/audit returned cross-tenant rows.
"""

from __future__ import annotations

import os
from typing import Any

import pytest
import pytest_asyncio


@pytest_asyncio.fixture
async def _per_tenant_audit_rows(db_session: Any, tenant_a: Any, tenant_b: Any) -> tuple[Any, Any]:
    """Insert one AuditLog row per tenant directly (bypasses the audit
    service so we keep test cost low — the per-tenant filter check
    doesn't depend on the HMAC chain shape)."""
    from datetime import UTC, datetime

    from app.models import AuditLog

    # Use a unique action so the test can pick its rows out of any
    # bystander entries the http_client + fixtures generate.
    action_a = f"test.action.a-{os.urandom(2).hex()}"
    action_b = f"test.action.b-{os.urandom(2).hex()}"
    a = AuditLog(
        tenant_id=tenant_a.id,
        seq=10_000_001,
        ts=datetime.now(UTC),
        actor_kind="user",
        action=action_a,
        resource_type="test",
        resource_id="r1",
        payload={"x": "a"},
        ip=None,
        prev_hmac=None,
        row_hmac=None,
    )
    b = AuditLog(
        tenant_id=tenant_b.id,
        seq=20_000_001,
        ts=datetime.now(UTC),
        actor_kind="user",
        action=action_b,
        resource_type="test",
        resource_id="r2",
        payload={"x": "b"},
        ip=None,
        prev_hmac=None,
        row_hmac=None,
    )
    db_session.add_all([a, b])
    await db_session.flush()
    return a, b


@pytest.mark.asyncio
async def test_audit_list_invisibility(
    http_client: Any, admin_in_a: Any, _per_tenant_audit_rows: tuple[Any, Any]
) -> None:
    from tests.conftest import headers_for

    a, b = _per_tenant_audit_rows
    resp = await http_client.get(f"/api/audit?action={a.action}", headers=headers_for(admin_in_a))
    assert resp.status_code == 200
    seqs = {item["seq"] for item in resp.json()["items"]}
    assert a.seq in seqs

    resp = await http_client.get(f"/api/audit?action={b.action}", headers=headers_for(admin_in_a))
    assert resp.status_code == 200
    seqs_b_search = {item["seq"] for item in resp.json()["items"]}
    assert b.seq not in seqs_b_search, (
        "tenant-A admin saw tenant-B audit row when filtering by tenant-B's action"
    )


@pytest.mark.asyncio
async def test_audit_list_unfiltered_excludes_other_tenant(
    http_client: Any, admin_in_a: Any, _per_tenant_audit_rows: tuple[Any, Any]
) -> None:
    from tests.conftest import headers_for

    _, b = _per_tenant_audit_rows
    resp = await http_client.get("/api/audit?limit=500", headers=headers_for(admin_in_a))
    assert resp.status_code == 200
    seqs = {item["seq"] for item in resp.json()["items"]}
    assert b.seq not in seqs, "tenant-A admin saw tenant-B audit row in unfiltered list"
