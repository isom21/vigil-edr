"""Regression tests for CODE-21 and CODE-33.

  * /api/hunt/saved list / get / update / delete / run / runs had no
    SavedHunt.tenant_id filter — a tenant-A admin could enumerate
    and run (or schedule) tenant B's saved hunts.
  * /api/scim-tokens + /scim/v2/Users had no tenant binding — SCIM
    users always landed on DEFAULT_TENANT_ID regardless of which
    token authenticated the request.

Migration 20260515_1200_scim_token_tenant_id added the column.
"""

from __future__ import annotations

import os
from typing import Any

import pytest
import pytest_asyncio

# ---------- hunt (CODE-21) -----------------------------------------------


@pytest_asyncio.fixture
async def _per_tenant_hunts(db_session: Any, admin_in_a: Any, admin_in_b: Any) -> tuple[Any, Any]:
    from app.models import SavedHunt, Severity

    a = SavedHunt(
        tenant_id=admin_in_a.tenant_id,
        owner_user_id=admin_in_a.id,
        name=f"hunt-a-{os.urandom(2).hex()}",
        query_dsl='process.name:"powershell.exe"',
        query_language="lucene",
        severity=Severity.MEDIUM,
    )
    b = SavedHunt(
        tenant_id=admin_in_b.tenant_id,
        owner_user_id=admin_in_b.id,
        name=f"hunt-b-{os.urandom(2).hex()}",
        query_dsl='process.name:"powershell.exe"',
        query_language="lucene",
        severity=Severity.MEDIUM,
    )
    db_session.add_all([a, b])
    await db_session.flush()
    return a, b


@pytest.mark.asyncio
async def test_hunt_list_invisibility(
    http_client: Any, admin_in_a: Any, _per_tenant_hunts: tuple[Any, Any]
) -> None:
    from tests.conftest import headers_for

    a, b = _per_tenant_hunts
    resp = await http_client.get("/api/hunt/saved", headers=headers_for(admin_in_a))
    assert resp.status_code == 200
    ids = {item["id"] for item in resp.json()["items"]}
    assert str(a.id) in ids
    assert str(b.id) not in ids


@pytest.mark.asyncio
async def test_hunt_get_404_cross_tenant(
    http_client: Any, admin_in_a: Any, _per_tenant_hunts: tuple[Any, Any]
) -> None:
    from tests.conftest import headers_for

    _, b = _per_tenant_hunts
    resp = await http_client.get(f"/api/hunt/saved/{b.id}", headers=headers_for(admin_in_a))
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_hunt_delete_404_cross_tenant(
    http_client: Any, admin_in_a: Any, _per_tenant_hunts: tuple[Any, Any]
) -> None:
    from tests.conftest import headers_for

    _, b = _per_tenant_hunts
    resp = await http_client.delete(f"/api/hunt/saved/{b.id}", headers=headers_for(admin_in_a))
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_create_hunt_stamps_actor_tenant_id(
    http_client: Any, admin_in_a: Any, tenant_a: Any, db_session: Any
) -> None:
    from uuid import UUID

    from sqlalchemy import select

    from app.models import SavedHunt
    from tests.conftest import headers_for

    resp = await http_client.post(
        "/api/hunt/saved",
        json={
            "name": f"new-hunt-{os.urandom(2).hex()}",
            "query_dsl": 'process.name:"x"',
            "query_language": "lucene",
            "severity": "medium",
        },
        headers=headers_for(admin_in_a),
    )
    assert resp.status_code == 201, resp.text
    new_id = UUID(resp.json()["id"])
    row = (await db_session.execute(select(SavedHunt).where(SavedHunt.id == new_id))).scalar_one()
    assert row.tenant_id == tenant_a.id


# ---------- scim tokens admin endpoints (CODE-33) -------------------------


@pytest.mark.asyncio
async def test_scim_token_list_invisibility(
    http_client: Any,
    db_session: Any,
    admin_in_a: Any,
    admin_in_b: Any,
) -> None:
    """Admins must not see other tenants' SCIM tokens."""
    from app.models import ScimToken
    from tests.conftest import headers_for

    a = ScimToken(
        tenant_id=admin_in_a.tenant_id,
        label=f"a-{os.urandom(2).hex()}",
        token_hash="a" * 64,
    )
    b = ScimToken(
        tenant_id=admin_in_b.tenant_id,
        label=f"b-{os.urandom(2).hex()}",
        token_hash="b" * 64,
    )
    db_session.add_all([a, b])
    await db_session.flush()

    resp = await http_client.get("/api/scim-tokens", headers=headers_for(admin_in_a))
    assert resp.status_code == 200
    ids = {item["id"] for item in resp.json()}
    assert str(a.id) in ids
    assert str(b.id) not in ids


@pytest.mark.asyncio
async def test_scim_token_create_stamps_actor_tenant_id(
    http_client: Any, admin_in_a: Any, tenant_a: Any, db_session: Any
) -> None:
    from uuid import UUID

    from sqlalchemy import select

    from app.models import ScimToken
    from tests.conftest import headers_for

    resp = await http_client.post(
        "/api/scim-tokens",
        json={"label": f"new-{os.urandom(2).hex()}"},
        headers=headers_for(admin_in_a),
    )
    assert resp.status_code == 201, resp.text
    new_id = UUID(resp.json()["id"])
    row = (await db_session.execute(select(ScimToken).where(ScimToken.id == new_id))).scalar_one()
    assert row.tenant_id == tenant_a.id


@pytest.mark.asyncio
async def test_scim_user_created_in_token_tenant(
    http_client: Any,
    db_session: Any,
    tenant_b: Any,
) -> None:
    """A SCIM POST authenticated by a tenant-B token must create the
    user under tenant B, not DEFAULT_TENANT_ID."""
    from uuid import UUID

    from sqlalchemy import select

    from app.models import ScimToken, User
    from app.services.scim import generate_scim_token, hash_scim_token

    raw = generate_scim_token()
    token = ScimToken(
        tenant_id=tenant_b.id,
        label=f"tok-{os.urandom(2).hex()}",
        token_hash=hash_scim_token(raw),
    )
    db_session.add(token)
    await db_session.flush()

    email = f"scim-{os.urandom(3).hex()}@test.local"
    resp = await http_client.post(
        "/scim/v2/Users",
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": email,
            "emails": [{"value": email, "primary": True}],
            "active": True,
            "externalId": "ext-" + os.urandom(3).hex(),
        },
        headers={"Authorization": f"Bearer {raw}"},
    )
    assert resp.status_code == 201, resp.text
    new_id = UUID(resp.json()["id"])
    row = (await db_session.execute(select(User).where(User.id == new_id))).scalar_one()
    assert row.tenant_id == tenant_b.id, (
        "SCIM-created user landed on the wrong tenant — CODE-33 regression"
    )
