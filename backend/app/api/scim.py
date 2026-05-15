"""SCIM 2.0 endpoints — IdP-facing user provisioning.

Bearer-token authenticated against the `scim_token` table. The actor
for SCIM mutations is synthetic (kind="scim_token") so audit rows
attribute back to the integration label rather than to a real user.

Reference shapes per RFC 7643/7644. Out-of-scope for v1:

  * /Groups (commented in the test recipe).
  * Bulk operations (`/Bulk` — IdPs we care about all degrade to
    per-resource calls when the server doesn't advertise it).
  * Tenancy — this is the "no tenant_id" parallel batch.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Body, Depends, Header, Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.deps import Actor, DbSession
from app.core.errors import unauthorized
from app.core.security import constant_time_eq
from app.models import ScimToken, User, UserRole
from app.services import audit
from app.services.scim import (
    SCIM_ENTERPRISE_SCHEMA,
    SCIM_ERROR_SCHEMA,
    SCIM_LIST_SCHEMA,
    SCIM_USER_SCHEMA,
    apply_scim_patch,
    apply_scim_user_fields,
    hash_scim_token,
    parse_scim_user_create,
    scim_issuer,
    to_scim_user,
)

router = APIRouter(prefix=settings.scim_base_path, tags=["scim"])

# ----------------------------------------------------------------------
# Auth: SCIM bearer token.
# ----------------------------------------------------------------------


def _scim_error_body(detail: str, status_code: int) -> dict[str, Any]:
    """Build a SCIM error body. Returned via JSONResponse with the
    matching HTTP status so IdPs can render the human message."""
    return {
        "schemas": [SCIM_ERROR_SCHEMA],
        "status": str(status_code),
        "detail": detail,
    }


def _scim_error(detail: str, status_code: int) -> JSONResponse:
    return JSONResponse(
        content=_scim_error_body(detail, status_code),
        status_code=status_code,
        media_type="application/scim+json",
    )


async def _resolve_scim_token(
    db: AsyncSession,
    authorization: str | None,
) -> tuple[ScimToken, Actor]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise unauthorized("missing bearer token")
    raw = authorization.split(" ", 1)[1].strip()
    if not raw:
        raise unauthorized("missing bearer token")
    token_hash = hash_scim_token(raw)
    row = (
        await db.execute(select(ScimToken).where(ScimToken.token_hash == token_hash))
    ).scalar_one_or_none()
    if row is None or not constant_time_eq(token_hash, row.token_hash):
        raise unauthorized("invalid scim token")
    if row.disabled:
        raise unauthorized("scim token disabled")
    row.last_used_at = datetime.now(UTC)
    # Build a synthetic Actor. The placeholder `user` is a stub User
    # object that's NEVER persisted — it exists only so callers reading
    # `actor.user.role` for RBAC checks see something sensible. Audit
    # writes detect the scim_token kind and skip the user_id FK.
    #
    # CODE-33: thread the token's tenant_id into the Actor so SCIM
    # endpoints can scope by it and `create_user` can stamp it on
    # newly-provisioned User rows.
    stub = User(
        id=row.id,
        email=f"scim:{row.label}",
        password_hash="",
        role=UserRole.ADMIN,  # SCIM bearer = admin-equivalent for User mgmt
        tenant_id=row.tenant_id,
    )
    actor = Actor(
        user=stub,
        kind="scim_token",
        token_id=row.id,
        tenant_id=row.tenant_id,
    )
    return row, actor


async def scim_actor(
    db: DbSession,
    authorization: Annotated[str | None, Header()] = None,
) -> Actor:
    _, actor = await _resolve_scim_token(db, authorization)
    return actor


ScimActor = Annotated[Actor, Depends(scim_actor)]


# ----------------------------------------------------------------------
# /Users — list / get / create / put / patch / delete.
# ----------------------------------------------------------------------


_FILTER_RE = re.compile(r'^\s*(\w+)\s+eq\s+"([^"]+)"\s*$', re.IGNORECASE)


def _location_base(request: Request) -> str:
    """Absolute URL base to put in `meta.location`."""
    return f"{request.url.scheme}://{request.url.netloc}{settings.scim_base_path}"


def _list_response(resources: list[dict[str, Any]], total: int, start: int, count: int) -> dict:
    return {
        "schemas": [SCIM_LIST_SCHEMA],
        "totalResults": total,
        "startIndex": start,
        "itemsPerPage": len(resources),
        "Resources": resources,
    }


@router.get("/Users")
async def list_users(
    request: Request,
    db: DbSession,
    actor: ScimActor,
    filter: str | None = None,  # noqa: A002 — SCIM mandates this name
    startIndex: int = 1,  # noqa: N803 — SCIM wire name (RFC 7644 §3.4.2.4)
    count: int = 100,
) -> dict[str, Any]:
    # SCIM uses 1-based startIndex (RFC 7644 §3.4.2.4). Negative or
    # missing means start at 1.
    if startIndex < 1:
        startIndex = 1  # noqa: N806 — SCIM wire name
    if count < 0:
        count = 0
    count = min(count, 500)  # hard cap so an over-eager IdP can't ask for 1M

    # CODE-33: scope to the token's tenant so an IdP provisioned for
    # tenant A can't enumerate / mutate tenant B's roster via SCIM.
    stmt = select(User).where(User.tenant_id == actor.tenant_id).order_by(User.created_at.desc())
    total_stmt = select(func.count(User.id)).where(User.tenant_id == actor.tenant_id)

    if filter:
        m = _FILTER_RE.match(filter)
        if m is None:
            return _scim_error("unsupported filter", status.HTTP_400_BAD_REQUEST)  # type: ignore[return-value]
        attr = m.group(1).lower()
        value = m.group(2)
        if attr in ("username", "emails", "emails.value"):
            stmt = stmt.where(User.email == value.lower())
            total_stmt = total_stmt.where(User.email == value.lower())
        elif attr == "externalid":
            stmt = stmt.where(User.scim_external_id == value)
            total_stmt = total_stmt.where(User.scim_external_id == value)
        else:
            # Unknown attribute — return empty rather than 400 (Okta
            # probes with vendor-specific filters during connection
            # tests and a 400 makes the connection light up red).
            return _list_response([], 0, startIndex, count)

    total = int((await db.execute(total_stmt)).scalar_one())
    rows = (await db.execute(stmt.offset(startIndex - 1).limit(count))).scalars().all()
    base = _location_base(request)
    resources = [to_scim_user(u, location_base=base) for u in rows]
    return _list_response(resources, total, startIndex, count)


@router.get("/Users/{user_id}")
async def get_user(
    user_id: UUID,
    request: Request,
    db: DbSession,
    actor: ScimActor,
) -> Any:
    # CODE-33: 404 (SCIM uses "user not found" body) on cross-tenant id.
    user = await db.get(User, user_id)
    if user is None or user.tenant_id != actor.tenant_id:
        return _scim_error("user not found", 404)
    return to_scim_user(user, location_base=_location_base(request))


@router.post("/Users", status_code=status.HTTP_201_CREATED)
async def create_user(
    request: Request,
    db: DbSession,
    actor: ScimActor,
    payload: Annotated[dict[str, Any], Body()],
) -> Any:
    try:
        fields = parse_scim_user_create(payload)
    except ValueError as exc:
        return _scim_error(str(exc), 400)

    issuer = scim_issuer()
    external_id = fields.get("external_id")

    # Idempotency: a SCIM POST that matches an existing (issuer,
    # externalId) returns the existing resource per Okta / Azure
    # expectations (they retry on transient errors). CODE-33: scope
    # the idempotency lookup to the actor's tenant so a tenant-B
    # external_id can't accidentally match a tenant-A user.
    existing: User | None = None
    if external_id:
        existing = (
            await db.execute(
                select(User).where(
                    User.oidc_issuer == issuer,
                    User.scim_external_id == external_id,
                    User.tenant_id == actor.tenant_id,
                )
            )
        ).scalar_one_or_none()
    if existing is None:
        # Email is globally unique on User; if a row with this email
        # exists in any tenant, the SCIM provider must clean it up
        # before claiming it.
        existing = (
            await db.execute(select(User).where(User.email == fields["email"]))
        ).scalar_one_or_none()
        if existing is not None and (
            existing.scim_external_id is None or existing.tenant_id != actor.tenant_id
        ):
            return _scim_error("email already exists for non-SCIM user", 409)

    if existing is None:
        user = User(
            tenant_id=actor.tenant_id,
            email=fields["email"],
            password_hash="",  # SCIM users don't carry passwords
            role=fields.get("role") or UserRole.VIEWER,
            disabled=bool(fields.get("disabled", False)),
            scim_external_id=str(external_id) if external_id else None,
            oidc_issuer=issuer,
        )
        db.add(user)
        await db.flush()
        action = "scim.user.create"
    else:
        apply_scim_user_fields(existing, fields)
        existing.oidc_issuer = issuer
        user = existing
        action = "scim.user.update"

    await audit.record(
        db,
        actor=actor,
        action=action,
        resource_type="user",
        resource_id=str(user.id),
        payload={
            "scim_external_id": user.scim_external_id,
            "actor_token_id": str(actor.token_id) if actor.token_id else None,
            "email": user.email,
        },
    )
    await db.flush()
    return to_scim_user(user, location_base=_location_base(request))


@router.put("/Users/{user_id}")
async def replace_user(
    user_id: UUID,
    request: Request,
    db: DbSession,
    actor: ScimActor,
    payload: Annotated[dict[str, Any], Body()],
) -> Any:
    # CODE-33: 404 on cross-tenant id.
    user = await db.get(User, user_id)
    if user is None or user.tenant_id != actor.tenant_id:
        return _scim_error("user not found", 404)
    try:
        fields = parse_scim_user_create(payload)
    except ValueError as exc:
        return _scim_error(str(exc), 400)
    apply_scim_user_fields(user, fields)
    await audit.record(
        db,
        actor=actor,
        action="scim.user.update",
        resource_type="user",
        resource_id=str(user.id),
        payload={
            "scim_external_id": user.scim_external_id,
            "actor_token_id": str(actor.token_id) if actor.token_id else None,
        },
    )
    await db.flush()
    return to_scim_user(user, location_base=_location_base(request))


@router.patch("/Users/{user_id}")
async def patch_user(
    user_id: UUID,
    request: Request,
    db: DbSession,
    actor: ScimActor,
    payload: Annotated[dict[str, Any], Body()],
) -> Any:
    # CODE-33: 404 on cross-tenant id.
    user = await db.get(User, user_id)
    if user is None or user.tenant_id != actor.tenant_id:
        return _scim_error("user not found", 404)
    ops = payload.get("Operations") or []
    if not isinstance(ops, list):
        return _scim_error("Operations must be a list", 400)
    apply_scim_patch(user, ops)
    await audit.record(
        db,
        actor=actor,
        action="scim.user.update",
        resource_type="user",
        resource_id=str(user.id),
        payload={
            "scim_external_id": user.scim_external_id,
            "actor_token_id": str(actor.token_id) if actor.token_id else None,
            "operations": [{"op": o.get("op"), "path": o.get("path")} for o in ops],
        },
    )
    await db.flush()
    return to_scim_user(user, location_base=_location_base(request))


@router.delete("/Users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(user_id: UUID, db: DbSession, actor: ScimActor) -> Response:
    # CODE-33: 404 on cross-tenant id.
    user = await db.get(User, user_id)
    if user is None or user.tenant_id != actor.tenant_id:
        return _scim_error("user not found", 404)
    external_id = user.scim_external_id
    await db.delete(user)
    await audit.record(
        db,
        actor=actor,
        action="scim.user.delete",
        resource_type="user",
        resource_id=str(user_id),
        payload={
            "scim_external_id": external_id,
            "actor_token_id": str(actor.token_id) if actor.token_id else None,
        },
    )
    await db.flush()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ----------------------------------------------------------------------
# Discovery endpoints. Authenticated like /Users so IdPs hit them with
# the same bearer they use for /Users; per RFC 7644 §4 these MAY be
# open, but keeping them auth'd avoids leaking schema details.
# ----------------------------------------------------------------------


@router.get("/ServiceProviderConfig")
async def service_provider_config(request: Request, actor: ScimActor) -> dict[str, Any]:
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "documentationUri": "https://www.rfc-editor.org/rfc/rfc7644",
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": 500},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "OAuth Bearer Token",
                "description": "Authentication scheme using the OAuth Bearer Token Standard",
                "specUri": "https://www.rfc-editor.org/rfc/rfc6750",
                "documentationUri": "https://www.rfc-editor.org/rfc/rfc7644",
            }
        ],
        "meta": {
            "resourceType": "ServiceProviderConfig",
            "location": f"{_location_base(request)}/ServiceProviderConfig",
        },
    }


@router.get("/ResourceTypes")
async def resource_types(request: Request, actor: ScimActor) -> dict[str, Any]:
    base = _location_base(request)
    resources = [
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "User",
            "name": "User",
            "endpoint": "/Users",
            "description": "User Account",
            "schema": SCIM_USER_SCHEMA,
            "schemaExtensions": [
                {"schema": SCIM_ENTERPRISE_SCHEMA, "required": False},
            ],
            "meta": {
                "resourceType": "ResourceType",
                "location": f"{base}/ResourceTypes/User",
            },
        }
    ]
    return _list_response(resources, len(resources), 1, len(resources))


@router.get("/Schemas")
async def schemas(request: Request, actor: ScimActor) -> dict[str, Any]:
    # Minimal advertised schema — IdPs that fetch this only care that
    # the core User schema is present with the attributes they map.
    base = _location_base(request)
    user_schema = {
        "id": SCIM_USER_SCHEMA,
        "name": "User",
        "description": "SCIM core resource for representing users",
        "attributes": [
            {
                "name": "userName",
                "type": "string",
                "multiValued": False,
                "required": True,
                "caseExact": False,
                "uniqueness": "server",
            },
            {
                "name": "active",
                "type": "boolean",
                "multiValued": False,
                "required": False,
            },
            {
                "name": "emails",
                "type": "complex",
                "multiValued": True,
                "required": False,
                "subAttributes": [
                    {"name": "value", "type": "string"},
                    {"name": "primary", "type": "boolean"},
                    {"name": "type", "type": "string"},
                ],
            },
            {
                "name": "externalId",
                "type": "string",
                "multiValued": False,
                "required": False,
            },
            {
                "name": "displayName",
                "type": "string",
                "multiValued": False,
                "required": False,
            },
        ],
        "meta": {"resourceType": "Schema", "location": f"{base}/Schemas/{SCIM_USER_SCHEMA}"},
    }
    return _list_response([user_schema], 1, 1, 1)
