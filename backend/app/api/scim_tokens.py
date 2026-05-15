"""Admin CRUD for SCIM bearer tokens. Lives on the regular `/api`
surface (not under `/scim/v2`) so it's gated by the normal admin JWT
flow rather than by a SCIM token authenticating itself."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, status
from sqlalchemy import select

from app.core.deps import DbSession, RequireAdmin
from app.core.errors import bad_request, not_found
from app.models import ScimToken
from app.schemas.scim import ScimTokenCreate, ScimTokenCreated, ScimTokenOut
from app.services import audit
from app.services.scim import generate_scim_token, hash_scim_token

router = APIRouter(prefix="/api/scim-tokens", tags=["scim-tokens"])


@router.get("", response_model=list[ScimTokenOut])
async def list_tokens(db: DbSession, actor: RequireAdmin) -> list[ScimTokenOut]:
    # CODE-33: scope to actor's tenant. Pre-PR, a tenant-A admin saw
    # every tenant's SCIM token labels + last-used timestamps and
    # could disable / delete them.
    rows = (
        (
            await db.execute(
                select(ScimToken)
                .where(ScimToken.tenant_id == actor.tenant_id)
                .order_by(ScimToken.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return [ScimTokenOut.model_validate(t) for t in rows]


@router.post("", response_model=ScimTokenCreated, status_code=status.HTTP_201_CREATED)
async def create_token(
    payload: ScimTokenCreate, db: DbSession, actor: RequireAdmin
) -> ScimTokenCreated:
    raw = generate_scim_token()
    token = ScimToken(
        tenant_id=actor.tenant_id,
        label=payload.label,
        token_hash=hash_scim_token(raw),
    )
    db.add(token)
    await db.flush()
    await audit.record(
        db,
        actor=actor,
        action="scim_token.create",
        resource_type="scim_token",
        resource_id=str(token.id),
        payload={"label": payload.label},
    )
    out = ScimTokenOut.model_validate(token)
    return ScimTokenCreated(**out.model_dump(), token=raw)


@router.post("/{token_id}/disable", status_code=status.HTTP_204_NO_CONTENT)
async def disable_token(token_id: UUID, db: DbSession, actor: RequireAdmin) -> None:
    token = await db.get(ScimToken, token_id)
    # CODE-33: 404 on cross-tenant id.
    if token is None or token.tenant_id != actor.tenant_id:
        raise not_found("scim_token", str(token_id))
    if token.disabled:
        raise bad_request("token already disabled")
    token.disabled = True
    await audit.record(
        db,
        actor=actor,
        action="scim_token.disable",
        resource_type="scim_token",
        resource_id=str(token.id),
        payload={"label": token.label},
    )


@router.delete("/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_token(token_id: UUID, db: DbSession, actor: RequireAdmin) -> None:
    token = await db.get(ScimToken, token_id)
    if token is None or token.tenant_id != actor.tenant_id:
        raise not_found("scim_token", str(token_id))
    label = token.label
    await db.delete(token)
    await audit.record(
        db,
        actor=actor,
        action="scim_token.delete",
        resource_type="scim_token",
        resource_id=str(token_id),
        payload={"label": label},
    )
