"""Regression test for CODE-4.

The /api/tokens router had no tenant scope, so a tenant-A admin's
list call returned every tenant's tokens, and the same admin could
revoke a tenant-B token by id.
"""

from __future__ import annotations

import os
from typing import Any

import pytest
import pytest_asyncio


@pytest_asyncio.fixture
async def _two_tenant_tokens(db_session: Any, admin_in_a: Any, admin_in_b: Any) -> tuple[Any, Any]:
    """One ApiToken per tenant."""
    from datetime import UTC, datetime, timedelta

    from app.core.security import generate_api_token_secret, hash_api_token_secret
    from app.models import ApiToken

    expires_at = datetime.now(UTC) + timedelta(days=30)
    a = ApiToken(
        user_id=admin_in_a.id,
        tenant_id=admin_in_a.tenant_id,
        name=f"a-{os.urandom(2).hex()}",
        secret_hash=hash_api_token_secret(generate_api_token_secret()),
        scopes=[],
        expires_at=expires_at,
    )
    b = ApiToken(
        user_id=admin_in_b.id,
        tenant_id=admin_in_b.tenant_id,
        name=f"b-{os.urandom(2).hex()}",
        secret_hash=hash_api_token_secret(generate_api_token_secret()),
        scopes=[],
        expires_at=expires_at,
    )
    db_session.add_all([a, b])
    await db_session.flush()
    return a, b


@pytest.mark.asyncio
async def test_admin_in_a_does_not_see_tenant_b_tokens(
    http_client: Any, admin_in_a: Any, _two_tenant_tokens: tuple[Any, Any]
) -> None:
    from tests.conftest import headers_for

    a, b = _two_tenant_tokens
    resp = await http_client.get("/api/tokens", headers=headers_for(admin_in_a))
    assert resp.status_code == 200
    ids = {item["id"] for item in resp.json()}
    assert str(a.id) in ids
    assert str(b.id) not in ids, "tenant-A admin saw tenant-B API token"


@pytest.mark.asyncio
async def test_admin_in_a_cannot_revoke_tenant_b_token(
    http_client: Any, admin_in_a: Any, _two_tenant_tokens: tuple[Any, Any]
) -> None:
    from tests.conftest import headers_for

    _, b = _two_tenant_tokens
    resp = await http_client.delete(f"/api/tokens/{b.id}", headers=headers_for(admin_in_a))
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_create_token_stamps_actor_tenant_id(
    http_client: Any, admin_in_a: Any, tenant_a: Any, db_session: Any
) -> None:
    from uuid import UUID

    from sqlalchemy import select

    from app.models import ApiToken
    from tests.conftest import headers_for

    resp = await http_client.post(
        "/api/tokens",
        json={"name": f"new-{os.urandom(3).hex()}", "ttl_days": 30},
        headers=headers_for(admin_in_a),
    )
    assert resp.status_code == 201, resp.text
    new_id = UUID(resp.json()["id"])
    row = (await db_session.execute(select(ApiToken).where(ApiToken.id == new_id))).scalar_one()
    assert row.tenant_id == tenant_a.id
