"""SCIM 2.0 user provisioning (Phase 3 #3.8).

The Okta / Azure AD / Google Workspace flows we promise to support:

  * POST /Users — IdP-driven user create → local users row, role=viewer.
  * PATCH /Users/{id} with `active=false` — deprovision (mark disabled).
  * DELETE /Users/{id} — remove the row, audit-logged.
  * Bearer token rotation — disabled token returns 401.
  * Filter `userName eq "x"` returns the matching user.

Groups are out of scope for v1 — IdP-side group sync isn't required
for the auto-create/auto-disable side of provisioning, and adding it
inflates the surface significantly. (Note for future contributors: the
PATCH path stub-ignores `groups` paths; wiring those up just needs a
`groups` table + the host_group plumbing.)
"""

from __future__ import annotations

import uuid

import pytest
import pytest_asyncio
from sqlalchemy import select

# ----------------------------------------------------------------------
# Fixtures.
# ----------------------------------------------------------------------


@pytest_asyncio.fixture
async def scim_token(db_session):
    """A fresh SCIM bearer token. Returns (raw_token, row)."""
    from app.models import ScimToken
    from app.services.scim import generate_scim_token, hash_scim_token

    raw = generate_scim_token()
    row = ScimToken(label=f"scim-{uuid.uuid4().hex[:8]}", token_hash=hash_scim_token(raw))
    db_session.add(row)
    await db_session.flush()
    return raw, row


@pytest.fixture
def scim_headers(scim_token):
    raw, _ = scim_token
    return {
        "Authorization": f"Bearer {raw}",
        "Content-Type": "application/scim+json",
    }


# ----------------------------------------------------------------------
# Discovery endpoints (smoke).
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_service_provider_config_returns_features(http_client, scim_headers):
    resp = await http_client.get("/scim/v2/ServiceProviderConfig", headers=scim_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["patch"]["supported"] is True
    assert body["filter"]["supported"] is True
    # Bulk advertised as unsupported — IdPs degrade gracefully.
    assert body["bulk"]["supported"] is False


@pytest.mark.asyncio
async def test_resource_types_lists_user(http_client, scim_headers):
    resp = await http_client.get("/scim/v2/ResourceTypes", headers=scim_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    ids = [r["id"] for r in body["Resources"]]
    assert "User" in ids


@pytest.mark.asyncio
async def test_schemas_lists_user_schema(http_client, scim_headers):
    resp = await http_client.get("/scim/v2/Schemas", headers=scim_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    ids = [r["id"] for r in body["Resources"]]
    assert "urn:ietf:params:scim:schemas:core:2.0:User" in ids


# ----------------------------------------------------------------------
# Auth.
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_users_requires_bearer(http_client):
    resp = await http_client.get("/scim/v2/Users")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_disabled_token_is_rejected(http_client, scim_token, db_session):
    raw, row = scim_token
    row.disabled = True
    await db_session.flush()
    resp = await http_client.get("/scim/v2/Users", headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_unknown_token_is_rejected(http_client):
    resp = await http_client.get(
        "/scim/v2/Users", headers={"Authorization": "Bearer not-a-real-token"}
    )
    assert resp.status_code == 401


# ----------------------------------------------------------------------
# Create / read.
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_post_create_materialises_user_with_viewer_role(
    http_client, scim_headers, db_session
):
    from app.models import User, UserRole

    body = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "externalId": "okta:00u123",
        "userName": "ada@example.com",
        "emails": [{"value": "ada@example.com", "primary": True, "type": "work"}],
        "displayName": "Ada Lovelace",
        "active": True,
    }
    resp = await http_client.post("/scim/v2/Users", json=body, headers=scim_headers)
    assert resp.status_code == 201, resp.text
    out = resp.json()
    assert out["userName"] == "ada@example.com"
    assert out["externalId"] == "okta:00u123"
    assert out["active"] is True
    user_id = out["id"]

    # Local row exists with role=viewer.
    user = (
        await db_session.execute(select(User).where(User.id == uuid.UUID(user_id)))
    ).scalar_one()
    assert user.role == UserRole.VIEWER
    assert user.scim_external_id == "okta:00u123"
    assert user.disabled is False


@pytest.mark.asyncio
async def test_post_create_idempotent_on_same_external_id(http_client, scim_headers):
    body = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "externalId": "okta:idem-1",
        "userName": "idem@example.com",
    }
    r1 = await http_client.post("/scim/v2/Users", json=body, headers=scim_headers)
    assert r1.status_code == 201, r1.text
    id1 = r1.json()["id"]
    # IdP retries — second POST returns the same id (treated as update).
    r2 = await http_client.post("/scim/v2/Users", json=body, headers=scim_headers)
    assert r2.status_code == 201
    assert r2.json()["id"] == id1


@pytest.mark.asyncio
async def test_get_single_user(http_client, scim_headers):
    body = {"userName": "get@example.com", "externalId": "g1"}
    create = await http_client.post("/scim/v2/Users", json=body, headers=scim_headers)
    user_id = create.json()["id"]
    resp = await http_client.get(f"/scim/v2/Users/{user_id}", headers=scim_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["userName"] == "get@example.com"


@pytest.mark.asyncio
async def test_get_unknown_user_returns_404(http_client, scim_headers):
    resp = await http_client.get(f"/scim/v2/Users/{uuid.uuid4()}", headers=scim_headers)
    assert resp.status_code == 404
    body = resp.json()
    assert "urn:ietf:params:scim:api:messages:2.0:Error" in body["schemas"]


# ----------------------------------------------------------------------
# Filter + pagination.
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_filter_username_eq(http_client, scim_headers):
    for u in ["alpha@example.com", "beta@example.com", "gamma@example.com"]:
        await http_client.post(
            "/scim/v2/Users",
            json={"userName": u, "externalId": f"x-{u}"},
            headers=scim_headers,
        )
    resp = await http_client.get(
        '/scim/v2/Users?filter=userName eq "beta@example.com"', headers=scim_headers
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["totalResults"] == 1
    assert body["Resources"][0]["userName"] == "beta@example.com"


@pytest.mark.asyncio
async def test_pagination_start_index_and_count(http_client, scim_headers):
    for i in range(5):
        await http_client.post(
            "/scim/v2/Users",
            json={"userName": f"page-{i}@example.com", "externalId": f"p{i}"},
            headers=scim_headers,
        )
    resp = await http_client.get("/scim/v2/Users?startIndex=1&count=2", headers=scim_headers)
    body = resp.json()
    assert body["startIndex"] == 1
    assert body["itemsPerPage"] == 2
    assert len(body["Resources"]) == 2


# ----------------------------------------------------------------------
# PATCH — deprovision.
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_patch_active_false_deprovisions(http_client, scim_headers, db_session):
    from app.models import User

    body = {"userName": "deprov@example.com", "externalId": "okta:deprov"}
    create = await http_client.post("/scim/v2/Users", json=body, headers=scim_headers)
    user_id = create.json()["id"]

    patch = {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "Replace", "path": "active", "value": False}],
    }
    resp = await http_client.patch(f"/scim/v2/Users/{user_id}", json=patch, headers=scim_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["active"] is False

    user = await db_session.get(User, uuid.UUID(user_id))
    assert user.disabled is True


@pytest.mark.asyncio
async def test_patch_object_form_no_path(http_client, scim_headers, db_session):
    """Azure AD sends `value` as the full attribute object with no `path`."""
    from app.models import User

    body = {"userName": "azure@example.com", "externalId": "az:01"}
    create = await http_client.post("/scim/v2/Users", json=body, headers=scim_headers)
    user_id = create.json()["id"]

    patch = {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "Replace", "value": {"active": False}}],
    }
    resp = await http_client.patch(f"/scim/v2/Users/{user_id}", json=patch, headers=scim_headers)
    assert resp.status_code == 200, resp.text
    user = await db_session.get(User, uuid.UUID(user_id))
    assert user.disabled is True


# ----------------------------------------------------------------------
# PUT — full replace.
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_put_replaces_fields(http_client, scim_headers, db_session):
    from app.models import User

    create = await http_client.post(
        "/scim/v2/Users",
        json={"userName": "put@example.com", "externalId": "p1", "active": True},
        headers=scim_headers,
    )
    user_id = create.json()["id"]

    resp = await http_client.put(
        f"/scim/v2/Users/{user_id}",
        json={
            "userName": "put-renamed@example.com",
            "externalId": "p1",
            "active": False,
        },
        headers=scim_headers,
    )
    assert resp.status_code == 200, resp.text
    user = await db_session.get(User, uuid.UUID(user_id))
    assert user.email == "put-renamed@example.com"
    assert user.disabled is True


# ----------------------------------------------------------------------
# DELETE — hard delete, audited.
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_removes_user_and_audits(http_client, scim_headers, db_session):
    from app.models import AuditLog, User

    body = {"userName": "delete-me@example.com", "externalId": "rip-1"}
    create = await http_client.post("/scim/v2/Users", json=body, headers=scim_headers)
    user_id = create.json()["id"]

    resp = await http_client.delete(f"/scim/v2/Users/{user_id}", headers=scim_headers)
    assert resp.status_code == 204, resp.text

    # Expire the session cache so we re-read from the DB rather than
    # returning the identity-map copy from the earlier create.
    db_session.expire_all()
    refetch = (
        await db_session.execute(select(User).where(User.id == uuid.UUID(user_id)))
    ).scalar_one_or_none()
    assert refetch is None

    rows = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.action == "scim.user.delete",
                    AuditLog.resource_id == user_id,
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].actor_kind == "scim_token"
    # SCIM rows MUST NOT pin user_id (no real user behind a SCIM
    # token).
    assert rows[0].user_id is None


# ----------------------------------------------------------------------
# Admin-side CRUD for SCIM tokens.
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_creates_scim_token_and_raw_only_shown_once(
    http_client, admin_headers, db_session
):
    from app.models import ScimToken

    resp = await http_client.post(
        "/api/scim-tokens", json={"label": "okta-prod"}, headers=admin_headers
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["label"] == "okta-prod"
    assert body["token"]  # raw token present on create
    raw = body["token"]
    token_id = body["id"]

    # List view doesn't return raw token.
    listing = await http_client.get("/api/scim-tokens", headers=admin_headers)
    assert listing.status_code == 200
    items = listing.json()
    match = next(t for t in items if t["id"] == token_id)
    assert "token" not in match

    # And the row stores only the hash.
    row = await db_session.get(ScimToken, uuid.UUID(token_id))
    assert row.token_hash and row.token_hash != raw


@pytest.mark.asyncio
async def test_disable_scim_token_blocks_subsequent_requests(
    http_client, admin_headers, scim_token
):
    raw, row = scim_token
    resp = await http_client.post(f"/api/scim-tokens/{row.id}/disable", headers=admin_headers)
    assert resp.status_code == 204, resp.text
    rejected = await http_client.get("/scim/v2/Users", headers={"Authorization": f"Bearer {raw}"})
    assert rejected.status_code == 401


@pytest.mark.asyncio
async def test_non_admin_cannot_create_scim_token(http_client, analyst_headers):
    resp = await http_client.post(
        "/api/scim-tokens", json={"label": "nope"}, headers=analyst_headers
    )
    assert resp.status_code == 403
