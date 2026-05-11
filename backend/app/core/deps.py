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

DbSession = Annotated[AsyncSession, Depends(get_session)]


@dataclass(frozen=True)
class Actor:
    """Authenticated identity for a request. Either a user (JWT) or API token (machine)."""

    user: User
    kind: Literal["user", "api_token"]
    token_id: UUID | None = None  # set when kind == "api_token"
    scopes: tuple[str, ...] = ()

    def has_role(self, *roles: UserRole) -> bool:
        return self.user.role in roles


async def _resolve_jwt(token: str, db: AsyncSession) -> User:
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
    return user


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
    return Actor(
        user=user,
        kind="api_token",
        token_id=api_token.id,
        scopes=tuple(api_token.scopes or ()),
    )


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
    user = await _resolve_jwt(token, db)
    return Actor(user=user, kind="user")


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
    user = await _resolve_jwt(token, db)
    return Actor(user=user, kind="user")


CurrentActor = Annotated[Actor, Depends(current_actor)]
CurrentActorStream = Annotated[Actor, Depends(current_actor_stream)]


def require_role(*roles: UserRole):
    async def _dep(actor: CurrentActor) -> Actor:
        if not actor.has_role(*roles):
            raise forbidden("insufficient role")
        return actor

    return _dep


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
