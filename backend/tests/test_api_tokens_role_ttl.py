"""POST /api/tokens — role gate + default TTL + no scopes field.

Review MEDIUM #14:
  * Pre-fix the endpoint gated on `CurrentActor`, so any authenticated
    user (including a viewer) could mint a token.
  * `ttl_days` was optional and fell through to `expires_at=None`, so
    a forgetful operator could leave a permanent credential behind.
  * The `scopes` field on the request body was never enforced (no code
    outside `deps.py` reads `Actor.scopes`) — exposing it was a
    footgun.

This pins the new contract.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

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
async def test_viewer_cannot_create_token(http_client, viewer_headers):
    resp = await http_client.post(
        "/api/tokens", json={"name": "viewer-tries"}, headers=viewer_headers
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_analyst_can_create_token(http_client, analyst_headers):
    resp = await http_client.post(
        "/api/tokens", json={"name": "analyst-token"}, headers=analyst_headers
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["token"].startswith("edr_")
    assert body["name"] == "analyst-token"


@pytest.mark.asyncio
async def test_create_without_ttl_applies_default_90_days(http_client, admin_headers):
    before = datetime.now(UTC)
    resp = await http_client.post(
        "/api/tokens", json={"name": "default-ttl"}, headers=admin_headers
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    expires = datetime.fromisoformat(body["expires_at"].replace("Z", "+00:00"))
    # Should be ~90 days out. Allow a small wall-clock fudge for the
    # request round-trip.
    diff = expires - before
    assert timedelta(days=89, hours=23) < diff < timedelta(days=90, hours=1), (
        f"expires_at not within 90d window: diff={diff}"
    )


@pytest.mark.asyncio
async def test_explicit_ttl_is_honoured(http_client, admin_headers):
    before = datetime.now(UTC)
    resp = await http_client.post(
        "/api/tokens", json={"name": "short-ttl", "ttl_days": 7}, headers=admin_headers
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    expires = datetime.fromisoformat(body["expires_at"].replace("Z", "+00:00"))
    diff = expires - before
    assert timedelta(days=6, hours=23) < diff < timedelta(days=7, hours=1), (
        f"expires_at not within 7d window: diff={diff}"
    )


@pytest.mark.asyncio
async def test_scopes_field_no_longer_on_request_or_response(http_client, admin_headers):
    # Sending `scopes` is now ignored by Pydantic (the field is gone
    # from the schema) — request still succeeds, but the response
    # doesn't echo a scopes key either.
    resp = await http_client.post(
        "/api/tokens",
        json={"name": "no-scopes", "scopes": ["should-be-ignored"]},
        headers=admin_headers,
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert "scopes" not in body, f"response still exposes scopes: {body}"
