"""Programmatic API tokens. Each user manages their own; admins see all."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import APIRouter, status
from sqlalchemy import select

from app.core.deps import CurrentActor, DbSession
from app.core.errors import forbidden, not_found
from app.core.security import (
    format_api_token,
    generate_api_token_secret,
    hash_api_token_secret,
)
from app.models import ApiToken, UserRole
from app.schemas.api_token import ApiTokenCreate, ApiTokenCreated, ApiTokenOut
from app.services import audit

router = APIRouter(prefix="/api/tokens", tags=["api-tokens"])


@router.get("", response_model=list[ApiTokenOut])
async def list_tokens(db: DbSession, actor: CurrentActor) -> list[ApiTokenOut]:
    stmt = select(ApiToken).order_by(ApiToken.created_at.desc())
    if actor.user.role is not UserRole.ADMIN:
        stmt = stmt.where(ApiToken.user_id == actor.user.id)
    rows = (await db.execute(stmt)).scalars().all()
    return [ApiTokenOut.model_validate(t) for t in rows]


@router.post("", response_model=ApiTokenCreated, status_code=status.HTTP_201_CREATED)
async def create_token(
    payload: ApiTokenCreate, db: DbSession, actor: CurrentActor
) -> ApiTokenCreated:
    secret = generate_api_token_secret()
    expires_at = (
        datetime.now(timezone.utc) + timedelta(days=payload.ttl_days)
        if payload.ttl_days
        else None
    )
    token = ApiToken(
        user_id=actor.user.id,
        name=payload.name,
        secret_hash=hash_api_token_secret(secret),
        scopes=payload.scopes,
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
        payload={"name": payload.name, "scopes": payload.scopes},
    )
    out = ApiTokenOut.model_validate(token)
    return ApiTokenCreated(**out.model_dump(), token=format_api_token(token.id, secret))


@router.delete("/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_token(token_id: UUID, db: DbSession, actor: CurrentActor) -> None:
    token = await db.get(ApiToken, token_id)
    if token is None:
        raise not_found("api_token", str(token_id))
    if token.user_id != actor.user.id and actor.user.role is not UserRole.ADMIN:
        raise forbidden()
    token.revoked_at = datetime.now(timezone.utc)
    await audit.record(
        db,
        actor=actor,
        action="api_token.revoke",
        resource_type="api_token",
        resource_id=str(token.id),
    )
