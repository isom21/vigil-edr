"""Programmatic API tokens. Each user manages their own; admins see all."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, status
from sqlalchemy import select

from app.core.deps import CurrentActor, DbSession, RequireAnalyst
from app.core.errors import forbidden, not_found
from app.core.security import (
    format_api_token,
    generate_api_token_secret,
    hash_api_token_secret,
)
from app.models import ApiToken, UserRole
from app.schemas.api_token import (
    DEFAULT_TTL_DAYS,
    ApiTokenCreate,
    ApiTokenCreated,
    ApiTokenOut,
)
from app.services import audit

router = APIRouter(prefix="/api/tokens", tags=["api-tokens"])


@router.get("", response_model=list[ApiTokenOut])
async def list_tokens(db: DbSession, actor: CurrentActor) -> list[ApiTokenOut]:
    # CODE-4: admins see every token IN THEIR TENANT, not every token
    # everywhere. Pre-PR, an admin in tenant A could enumerate (and
    # via DELETE below revoke) every tenant's API tokens.
    stmt = (
        select(ApiToken)
        .where(ApiToken.tenant_id == actor.tenant_id)
        .order_by(ApiToken.created_at.desc())
    )
    if actor.user.role is not UserRole.ADMIN:
        stmt = stmt.where(ApiToken.user_id == actor.user.id)
    rows = (await db.execute(stmt)).scalars().all()
    return [ApiTokenOut.model_validate(t) for t in rows]


@router.post("", response_model=ApiTokenCreated, status_code=status.HTTP_201_CREATED)
async def create_token(
    payload: ApiTokenCreate, db: DbSession, actor: RequireAnalyst
) -> ApiTokenCreated:
    # Review MEDIUM #14: token creation is now analyst+ (was any
    # authenticated user), and a non-expiring token is no longer the
    # default — when ttl_days is omitted we apply DEFAULT_TTL_DAYS (90)
    # so operator forgetfulness can't leave a permanent credential
    # behind. The on-the-wire schema is unchanged; only the implicit
    # default moved.
    ttl = payload.ttl_days if payload.ttl_days is not None else DEFAULT_TTL_DAYS
    expires_at = datetime.now(UTC) + timedelta(days=ttl)
    secret = generate_api_token_secret()
    token = ApiToken(
        user_id=actor.user.id,
        # CODE-4: stamp the actor's tenant so revoke/list paths can
        # gate on it. Tokens belong to a user, who belongs to a tenant.
        tenant_id=actor.tenant_id,
        name=payload.name,
        secret_hash=hash_api_token_secret(secret),
        # `scopes` column stays in the DB for now (no migration), but
        # the API surface no longer exposes it — nothing on the
        # backend reads `Actor.scopes` outside deps.py, and exposing a
        # field that doesn't gate anything was just a footgun.
        scopes=[],
        expires_at=expires_at,
    )
    db.add(token)
    await db.flush()
    await audit.record(
        db,
        actor=actor,
        action="api_token.create",
        resource_type="api_token",
        resource_id=str(token.id),
        payload={"name": payload.name, "ttl_days": ttl},
    )
    out = ApiTokenOut.model_validate(token)
    return ApiTokenCreated(**out.model_dump(), token=format_api_token(token.id, secret))


@router.delete("/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_token(token_id: UUID, db: DbSession, actor: CurrentActor) -> None:
    token = await db.get(ApiToken, token_id)
    # CODE-4: 404 (not 403) on cross-tenant id — convention is to not
    # leak existence. Pre-PR, an admin in tenant A who happened to know
    # a tenant B token id could revoke it.
    if token is None or token.tenant_id != actor.tenant_id:
        raise not_found("api_token", str(token_id))
    if token.user_id != actor.user.id and actor.user.role is not UserRole.ADMIN:
        raise forbidden()
    token.revoked_at = datetime.now(UTC)
    await audit.record(
        db,
        actor=actor,
        action="api_token.revoke",
        resource_type="api_token",
        resource_id=str(token.id),
    )
