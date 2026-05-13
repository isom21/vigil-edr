"""FastAPI dependencies: current actor (user via JWT or API token), DB session, role guards."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID

import jwt
from fastapi import Depends, Header, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_session
from app.core.errors import forbidden, unauthorized
from app.core.security import (
    constant_time_eq,
    decode_jwt,
    hash_api_token_secret,
    parse_api_token,
)
from app.models import ApiToken, User, UserRole
from app.models.tenant import DEFAULT_TENANT_ID

DbSession = Annotated[AsyncSession, Depends(get_session)]

# Cookie name carrying the super-admin's currently-selected tenant.
# Non-super users ignore the cookie; their tenant stays pinned to
# the JWT claim regardless. Centralised here so the frontend
# switcher and the backend resolver can't drift on the name.
ACTIVE_TENANT_COOKIE: str = "vigil_active_tenant_id"


@dataclass(frozen=True)
class Actor:
    """Authenticated identity for a request.

    Three kinds today: a user (JWT), an API token (machine — owned by a
    user), and a SCIM token (machine — Phase 3 #3.8, owned by no user
    because the IdP is the actor). For SCIM the synthetic `user` is a
    placeholder so anything that reads `actor.user.role` keeps working;
    `token_id` references the `scim_token` row and `actor.user.id` is
    NOT a real user_id (it's the token id reused as a placeholder).
    Audit rows for SCIM stamp `actor_kind="scim_token"` and put the
    label / token_id in the payload.
    """

    user: User
    kind: Literal["user", "api_token", "scim_token"]
    token_id: UUID | None = None  # set when kind in {"api_token", "scim_token"}
    scopes: tuple[str, ...] = ()
    # Phase 3 #3.1: the tenant this request operates inside. For
    # non-super-admins this always equals ``user.tenant_id`` —
    # the JWT claim is cross-checked against the user row and the
    # ``vigil_active_tenant_id`` cookie is ignored. Super-admins can
    # flip the active tenant via the cookie; falls back to the
    # home tenant when the cookie is missing or malformed.
    tenant_id: UUID = DEFAULT_TENANT_ID
    is_super_admin: bool = False

    def has_role(self, *roles: UserRole) -> bool:
        return self.user.role in roles


async def _resolve_jwt(token: str, db: AsyncSession) -> tuple[User, UUID, bool]:
    """Return ``(user, claimed_tenant_id, claimed_super_admin)``.

    The claimed tenant + super-admin bit come from the JWT and are
    cross-checked by the caller against the user row. A claim that
    doesn't match the user (e.g. token replay after a tenant move
    or a privilege flip) returns 401 — we don't silently fall back
    to the user's current state, because that would let a stolen
    pre-demotion token keep working past the demotion."""
    try:
        payload = decode_jwt(token)
    except jwt.ExpiredSignatureError as exc:
        raise unauthorized("token expired") from exc
    except jwt.PyJWTError as exc:
        raise unauthorized("invalid token") from exc
    if payload.get("type") != "access":
        raise unauthorized("wrong token type")
    user = await db.get(User, UUID(payload["sub"]))
    if user is None or user.disabled:
        raise unauthorized("user inactive")
    claimed_tenant_raw = payload.get("tenant_id")
    claimed_tenant = UUID(claimed_tenant_raw) if claimed_tenant_raw else user.tenant_id
    claimed_super = bool(payload.get("is_super_admin", False))
    return user, claimed_tenant, claimed_super


async def _resolve_api_token(token: str, db: AsyncSession) -> Actor:
    parsed = parse_api_token(token)
    if parsed is None:
        raise unauthorized("malformed api token")
    token_id, secret = parsed
    api_token = await db.get(ApiToken, token_id)
    if api_token is None or api_token.revoked_at is not None:
        raise unauthorized("revoked or unknown api token")
    if api_token.expires_at and api_token.expires_at < datetime.now(UTC):
        raise unauthorized("api token expired")
    if not constant_time_eq(hash_api_token_secret(secret), api_token.secret_hash):
        raise unauthorized("invalid api token")
    user = await db.get(User, api_token.user_id)
    if user is None or user.disabled:
        raise unauthorized("token owner inactive")
    api_token.last_used_at = datetime.now(UTC)
    # API tokens are pinned to their owner's tenant — no cookie-driven
    # tenant switch for machine identities. The token row's own
    # tenant_id mirrors the user's home tenant.
    return Actor(
        user=user,
        kind="api_token",
        token_id=api_token.id,
        scopes=tuple(api_token.scopes or ()),
        tenant_id=user.tenant_id,
        is_super_admin=user.is_super_admin,
    )


def _resolve_active_tenant(request: Request, user: User, is_super_admin: bool) -> UUID:
    """Pick the effective tenant for this request.

    Non-super-admins are pinned to their home tenant regardless of
    cookie state. Super-admins may flip the active tenant via the
    ``vigil_active_tenant_id`` cookie; if the cookie is missing or
    invalid we fall back to their home tenant so a cleared cookie
    doesn't leave the UI stuck."""
    if not is_super_admin:
        return user.tenant_id
    raw = request.cookies.get(ACTIVE_TENANT_COOKIE)
    if not raw:
        return user.tenant_id
    try:
        return UUID(raw)
    except ValueError:
        return user.tenant_id


async def current_actor(
    request: Request,
    db: DbSession,
    authorization: Annotated[str | None, Header()] = None,
) -> Actor:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise unauthorized("missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    if token.startswith("edr_"):
        return await _resolve_api_token(token, db)
    user, claimed_tenant, claimed_super = await _resolve_jwt(token, db)
    if claimed_tenant != user.tenant_id:
        raise unauthorized("tenant claim mismatch")
    if claimed_super != user.is_super_admin:
        raise unauthorized("privilege claim mismatch")
    active_tenant = _resolve_active_tenant(request, user, user.is_super_admin)
    return Actor(
        user=user,
        kind="user",
        tenant_id=active_tenant,
        is_super_admin=user.is_super_admin,
    )


async def current_actor_stream(
    request: Request,
    db: DbSession,
    authorization: Annotated[str | None, Header()] = None,
) -> Actor:
    """SSE-friendly variant of current_actor.

    EventSource can't set Authorization headers, so we also accept the
    bearer token via `?access_token=...`. Header still takes precedence
    when both are present.
    """
    token: str | None = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
    if not token:
        token = request.query_params.get("access_token")
    if not token:
        raise unauthorized("missing bearer token")
    if token.startswith("edr_"):
        return await _resolve_api_token(token, db)
    user, claimed_tenant, claimed_super = await _resolve_jwt(token, db)
    if claimed_tenant != user.tenant_id:
        raise unauthorized("tenant claim mismatch")
    if claimed_super != user.is_super_admin:
        raise unauthorized("privilege claim mismatch")
    active_tenant = _resolve_active_tenant(request, user, user.is_super_admin)
    return Actor(
        user=user,
        kind="user",
        tenant_id=active_tenant,
        is_super_admin=user.is_super_admin,
    )


CurrentActor = Annotated[Actor, Depends(current_actor)]
CurrentActorStream = Annotated[Actor, Depends(current_actor_stream)]


def require_role(*roles: UserRole):
    async def _dep(actor: CurrentActor) -> Actor:
        if not actor.has_role(*roles):
            raise forbidden("insufficient role")
        return actor

    return _dep


def require_super_admin(actor: CurrentActor) -> Actor:
    """Gate endpoint behind the super-admin bit.

    Returns 403 ("super-admin required") for everyone else, including
    tenant-level admins. Used for tenant CRUD and other cross-tenant
    operations."""
    if not actor.is_super_admin:
        raise forbidden("super-admin required")
    return actor


RequireAdmin = Annotated[Actor, Depends(require_role(UserRole.ADMIN))]
RequireAnalyst = Annotated[Actor, Depends(require_role(UserRole.ADMIN, UserRole.ANALYST))]
# M-rbac-viewer #9: viewer was previously a role with nothing it could
# actually do — every read endpoint gated on `RequireAnalyst`, so a
# viewer login returned 403 on every page. `docs/rbac.md` documented
# the role as "read-only on alerts, hosts, rules", so the docs and
# code disagreed. Pick the docs: add a Require* that admits all three
# roles for the read endpoints. Write endpoints keep RequireAnalyst.
RequireViewer = Annotated[
    Actor, Depends(require_role(UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER))
]
# Phase 3 #3.1: tenant CRUD + cross-tenant tooling.
RequireSuperAdmin = Annotated[Actor, Depends(require_super_admin)]
