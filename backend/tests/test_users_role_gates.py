"""Users API is admin-only on every verb.

Review MEDIUM #20: backfill missing pos+neg integration tests for
admin-gated routes. `app/api/users.py` already enforces RequireAdmin
on list/get/create/update/delete and on the per-user host-group
assignment routes — this just pins the contract so a future relaxation
to RequireAnalyst trips a test, not production.
"""

from __future__ import annotations

import os
from uuid import uuid4

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


@pytest_asyncio.fixture
async def target_user(db_session: AsyncSession):
    """A second user the test can mutate (separate from admin/analyst/viewer)."""
    from app.core.security import hash_password
    from app.models import User, UserRole

    u = User(
        email=f"target-{os.urandom(4).hex()}@test.local",
        password_hash=hash_password("test-password-123"),
        role=UserRole.ANALYST,
    )
    db_session.add(u)
    await db_session.flush()
    return u


@pytest.mark.asyncio
async def test_list_users_admin_only_analyst_403(http_client, analyst_headers):
    resp = await http_client.get("/api/users", headers=analyst_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_list_users_admin_200(http_client, admin_user, admin_headers):
    resp = await http_client.get("/api/users", headers=admin_headers)
    assert resp.status_code == 200
    emails = {u["email"] for u in resp.json()}
    assert admin_user.email in emails


@pytest.mark.asyncio
async def test_create_user_admin_only_viewer_403(http_client, viewer_headers):
    resp = await http_client.post(
        "/api/users",
        json={"email": "noop@test.local", "password": "verylongpassword", "role": "analyst"},
        headers=viewer_headers,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_create_user_admin_201(http_client, admin_headers):
    email = f"new-{os.urandom(4).hex()}@test.local"
    resp = await http_client.post(
        "/api/users",
        json={"email": email, "password": "verylongpassword", "role": "viewer"},
        headers=admin_headers,
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["email"] == email
    assert resp.json()["role"] == "viewer"


@pytest.mark.asyncio
async def test_update_user_admin_only_analyst_403(http_client, target_user, analyst_headers):
    resp = await http_client.patch(
        f"/api/users/{target_user.id}", json={"role": "viewer"}, headers=analyst_headers
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_update_user_admin_200(http_client, target_user, admin_headers):
    resp = await http_client.patch(
        f"/api/users/{target_user.id}", json={"role": "viewer"}, headers=admin_headers
    )
    assert resp.status_code == 200
    assert resp.json()["role"] == "viewer"


@pytest.mark.asyncio
async def test_delete_user_admin_only_viewer_403(http_client, target_user, viewer_headers):
    resp = await http_client.delete(f"/api/users/{target_user.id}", headers=viewer_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_delete_user_admin_204(http_client, target_user, admin_headers):
    resp = await http_client.delete(f"/api/users/{target_user.id}", headers=admin_headers)
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_delete_nonexistent_user_admin_404(http_client, admin_headers):
    resp = await http_client.delete(f"/api/users/{uuid4()}", headers=admin_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_user_groups_admin_only_analyst_403(http_client, target_user, analyst_headers):
    resp = await http_client.get(f"/api/users/{target_user.id}/groups", headers=analyst_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_replace_user_groups_admin_only_viewer_403(http_client, target_user, viewer_headers):
    resp = await http_client.post(
        f"/api/users/{target_user.id}/groups",
        json={"host_group_ids": []},
        headers=viewer_headers,
    )
    assert resp.status_code == 403
