"""Honeytoken CRUD + hit listing (Phase 4 #4.5).

Admin-only writes; analyst+ can read. Each mutation is audited and
fans out a `DEPLOY_HONEYTOKEN` command per affected host so the
agent's deployed-token set converges within seconds.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, status
from sqlalchemy import select

from app.core.deps import DbSession, RequireAdmin, RequireAnalyst
from app.core.errors import conflict, not_found
from app.models import Honeytoken, HoneytokenHit
from app.schemas.honeytoken import (
    HoneytokenCreate,
    HoneytokenHitOut,
    HoneytokenOut,
    HoneytokenUpdate,
)
from app.services import audit
from app.services.honeytoken import push_to_group

router = APIRouter(prefix="/api/honeytokens", tags=["deception"])


@router.get("", response_model=list[HoneytokenOut])
async def list_honeytokens(
    db: DbSession,
    actor: RequireAnalyst,
    host_group_id: UUID | None = None,
) -> list[HoneytokenOut]:
    stmt = (
        select(Honeytoken).where(Honeytoken.tenant_id == actor.tenant_id).order_by(Honeytoken.name)
    )
    if host_group_id is not None:
        stmt = stmt.where(Honeytoken.host_group_id == host_group_id)
    rows = (await db.execute(stmt)).scalars().all()
    return [HoneytokenOut.model_validate(r) for r in rows]


@router.post("", response_model=HoneytokenOut, status_code=status.HTTP_201_CREATED)
async def create_honeytoken(
    payload: HoneytokenCreate, db: DbSession, actor: RequireAdmin
) -> HoneytokenOut:
    dup_stmt = select(Honeytoken).where(
        Honeytoken.tenant_id == actor.tenant_id,
        Honeytoken.name == payload.name,
    )
    if (await db.execute(dup_stmt)).scalar_one_or_none() is not None:
        raise conflict(f"honeytoken {payload.name!r} already exists in this tenant")

    token = Honeytoken(
        tenant_id=actor.tenant_id,
        host_group_id=payload.host_group_id,
        kind=payload.kind.value,
        name=payload.name,
        payload_json=payload.payload_json,
        target_path=payload.target_path,
        enabled=payload.enabled,
    )
    db.add(token)
    await db.flush()

    await audit.record(
        db,
        actor=actor,
        action="honeytoken.create",
        resource_type="honeytoken",
        resource_id=str(token.id),
        payload={
            "name": token.name,
            "kind": token.kind,
            "host_group_id": str(token.host_group_id) if token.host_group_id else None,
            "target_path": token.target_path,
            "enabled": token.enabled,
        },
    )

    await push_to_group(
        db,
        actor.tenant_id,
        token.host_group_id,
        issued_by_user_id=actor.user.id,
    )
    return HoneytokenOut.model_validate(token)


@router.patch("/{honeytoken_id}", response_model=HoneytokenOut)
async def update_honeytoken(
    honeytoken_id: UUID,
    payload: HoneytokenUpdate,
    db: DbSession,
    actor: RequireAdmin,
) -> HoneytokenOut:
    token = await db.get(Honeytoken, honeytoken_id)
    if token is None or token.tenant_id != actor.tenant_id:
        raise not_found("honeytoken", str(honeytoken_id))

    if payload.name is not None and payload.name != token.name:
        dup_stmt = select(Honeytoken).where(
            Honeytoken.tenant_id == actor.tenant_id,
            Honeytoken.name == payload.name,
            Honeytoken.id != token.id,
        )
        if (await db.execute(dup_stmt)).scalar_one_or_none() is not None:
            raise conflict(f"honeytoken {payload.name!r} already exists in this tenant")

    changes: dict[str, object] = {}
    if payload.kind is not None:
        token.kind = payload.kind.value
        changes["kind"] = token.kind
    if payload.name is not None:
        token.name = payload.name
        changes["name"] = token.name
    if payload.payload_json is not None:
        token.payload_json = payload.payload_json
        changes["payload_json"] = "<updated>"
    if payload.target_path is not None:
        token.target_path = payload.target_path
        changes["target_path"] = token.target_path
    if payload.enabled is not None:
        token.enabled = payload.enabled
        changes["enabled"] = token.enabled

    await db.flush()

    await audit.record(
        db,
        actor=actor,
        action="honeytoken.update",
        resource_type="honeytoken",
        resource_id=str(token.id),
        payload={"changes": changes},
    )

    await push_to_group(
        db,
        actor.tenant_id,
        token.host_group_id,
        issued_by_user_id=actor.user.id,
    )
    return HoneytokenOut.model_validate(token)


@router.delete("/{honeytoken_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_honeytoken(honeytoken_id: UUID, db: DbSession, actor: RequireAdmin) -> None:
    token = await db.get(Honeytoken, honeytoken_id)
    if token is None or token.tenant_id != actor.tenant_id:
        raise not_found("honeytoken", str(honeytoken_id))
    snapshot = {
        "name": token.name,
        "kind": token.kind,
        "host_group_id": str(token.host_group_id) if token.host_group_id else None,
    }
    affected_group = token.host_group_id
    await db.delete(token)
    await db.flush()

    await audit.record(
        db,
        actor=actor,
        action="honeytoken.delete",
        resource_type="honeytoken",
        resource_id=str(honeytoken_id),
        payload=snapshot,
    )

    await push_to_group(
        db,
        actor.tenant_id,
        affected_group,
        issued_by_user_id=actor.user.id,
    )


@router.get("/{honeytoken_id}/hits", response_model=list[HoneytokenHitOut])
async def list_hits(
    honeytoken_id: UUID,
    db: DbSession,
    actor: RequireAnalyst,
    limit: int = 100,
) -> list[HoneytokenHitOut]:
    token = await db.get(Honeytoken, honeytoken_id)
    if token is None or token.tenant_id != actor.tenant_id:
        raise not_found("honeytoken", str(honeytoken_id))
    capped = max(1, min(limit, 500))
    stmt = (
        select(HoneytokenHit)
        .where(HoneytokenHit.honeytoken_id == honeytoken_id)
        .order_by(HoneytokenHit.hit_at.desc())
        .limit(capped)
    )
    rows = (await db.execute(stmt)).scalars().all()
    return [HoneytokenHitOut.model_validate(r) for r in rows]
