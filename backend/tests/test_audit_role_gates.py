"""Audit log + chain verify are admin-only.

Review MEDIUM #20: pin the contract that non-admins can't read the
audit log or run the chain verifier. The endpoints already enforce
RequireAdmin (api/audit.py); this catches a future relaxation.
"""

from __future__ import annotations

import os

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import make_jwt


@pytest_asyncio.fixture
async def viewer_user(db_session: AsyncSession):
    from app.core.security import hash_password
    from app.models import User, UserRole

    u = User(
        email=f"viewer-{os.urandom(4).hex()}@test.local",
        password_hash=hash_password("test-password-123"),
        role=UserRole.VIEWER,
    )
    db_session.add(u)
    await db_session.flush()
    return u


@pytest.fixture
def viewer_headers(viewer_user) -> dict[str, str]:
    return {"Authorization": f"Bearer {make_jwt(str(viewer_user.id), 'viewer')}"}


@pytest.mark.asyncio
async def test_list_audit_analyst_403(http_client, analyst_headers):
    resp = await http_client.get("/api/audit", headers=analyst_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_list_audit_viewer_403(http_client, viewer_headers):
    resp = await http_client.get("/api/audit", headers=viewer_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_list_audit_admin_200(http_client, admin_headers):
    resp = await http_client.get("/api/audit", headers=admin_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert "items" in body and "total" in body


@pytest.mark.asyncio
async def test_verify_audit_analyst_403(http_client, analyst_headers):
    resp = await http_client.get("/api/audit/verify", headers=analyst_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_verify_audit_admin_200(http_client, admin_headers):
    resp = await http_client.get("/api/audit/verify", headers=admin_headers)
    assert resp.status_code == 200
    body = resp.json()
    # Shape contract — the audit-verify badge on the frontend reads
    # these keys; pin them so a renaming triggers a test, not a silent
    # UI break.
    assert "ok" in body
    assert "rows_examined" in body
    assert "chain_rows" in body
    assert "breaks" in body
