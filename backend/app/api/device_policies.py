"""Device control policy CRUD (Phase 3 #3.10).

Admin-only writes; analyst+ can read. Every mutation is audited and
fans out a `DEVICE_CONTROL_SYNC` command per affected host so the
agent's per-host effective policy converges within seconds (commands
ride the existing notify pipeline, no extra polling).
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, status
from sqlalchemy import select

from app.core.deps import DbSession, RequireAdmin, RequireAnalyst
from app.core.errors import conflict, not_found
from app.models import DevicePolicy
from app.schemas.device_policy import (
    DevicePolicyCreate,
    DevicePolicyOut,
    DevicePolicyUpdate,
)
from app.services import audit
from app.services.device_control import push_to_group

router = APIRouter(prefix="/api/device-policies", tags=["device-control"])


@router.get("", response_model=list[DevicePolicyOut])
async def list_policies(
    db: DbSession,
    _actor: RequireAnalyst,
    host_group_id: UUID | None = None,
) -> list[DevicePolicyOut]:
    stmt = select(DevicePolicy).order_by(DevicePolicy.name)
    if host_group_id is not None:
        stmt = stmt.where(DevicePolicy.host_group_id == host_group_id)
    rows = (await db.execute(stmt)).scalars().all()
    return [DevicePolicyOut.model_validate(r) for r in rows]


@router.post("", response_model=DevicePolicyOut, status_code=status.HTTP_201_CREATED)
async def create_policy(
    payload: DevicePolicyCreate, db: DbSession, actor: RequireAdmin
) -> DevicePolicyOut:
    # Pre-check uniqueness in-tx so we can return a clean 409 rather
    # than relying on IntegrityError catch-and-rollback (which would
    # dissolve the test-suite SAVEPOINT).
    dup_stmt = select(DevicePolicy).where(DevicePolicy.name == payload.name)
    if payload.host_group_id is None:
        dup_stmt = dup_stmt.where(DevicePolicy.host_group_id.is_(None))
    else:
        dup_stmt = dup_stmt.where(DevicePolicy.host_group_id == payload.host_group_id)
    if (await db.execute(dup_stmt)).scalar_one_or_none() is not None:
        raise conflict(
            f"device policy {payload.name!r} already exists "
            f"(scope={payload.host_group_id or 'global'})"
        )

    policy = DevicePolicy(
        host_group_id=payload.host_group_id,
        kind=payload.kind.value,
        name=payload.name,
        description=payload.description,
        allowed_vendor_ids=payload.allowed_vendor_ids,
        allowed_product_ids=payload.allowed_product_ids,
        enabled=payload.enabled,
    )
    db.add(policy)
    await db.flush()

    await audit.record(
        db,
        actor=actor,
        action="device_policy.create",
        resource_type="device_policy",
        resource_id=str(policy.id),
        payload={
            "name": policy.name,
            "kind": policy.kind,
            "host_group_id": str(policy.host_group_id) if policy.host_group_id else None,
            "enabled": policy.enabled,
            "allowed_vendor_ids": policy.allowed_vendor_ids,
            "allowed_product_ids": policy.allowed_product_ids,
        },
    )

    await push_to_group(
        db,
        policy.host_group_id,
        issued_by_user_id=actor.user.id,
    )
    return DevicePolicyOut.model_validate(policy)


@router.patch("/{policy_id}", response_model=DevicePolicyOut)
async def update_policy(
    policy_id: UUID,
    payload: DevicePolicyUpdate,
    db: DbSession,
    actor: RequireAdmin,
) -> DevicePolicyOut:
    policy = await db.get(DevicePolicy, policy_id)
    if policy is None:
        raise not_found("device_policy", str(policy_id))

    # Pre-check name uniqueness if the operator renamed it. Same scope
    # rule as create.
    if payload.name is not None and payload.name != policy.name:
        dup_stmt = select(DevicePolicy).where(
            DevicePolicy.name == payload.name,
            DevicePolicy.id != policy.id,
        )
        if policy.host_group_id is None:
            dup_stmt = dup_stmt.where(DevicePolicy.host_group_id.is_(None))
        else:
            dup_stmt = dup_stmt.where(DevicePolicy.host_group_id == policy.host_group_id)
        if (await db.execute(dup_stmt)).scalar_one_or_none() is not None:
            raise conflict(
                f"device policy {payload.name!r} already exists "
                f"(scope={policy.host_group_id or 'global'})"
            )

    changes: dict[str, object] = {}
    if payload.kind is not None:
        policy.kind = payload.kind.value
        changes["kind"] = policy.kind
    if payload.name is not None:
        policy.name = payload.name
        changes["name"] = policy.name
    if payload.description is not None:
        policy.description = payload.description
        changes["description"] = policy.description
    if payload.allowed_vendor_ids is not None:
        policy.allowed_vendor_ids = payload.allowed_vendor_ids
        changes["allowed_vendor_ids"] = policy.allowed_vendor_ids
    if payload.allowed_product_ids is not None:
        policy.allowed_product_ids = payload.allowed_product_ids
        changes["allowed_product_ids"] = policy.allowed_product_ids
    if payload.enabled is not None:
        policy.enabled = payload.enabled
        changes["enabled"] = policy.enabled

    await db.flush()

    await audit.record(
        db,
        actor=actor,
        action="device_policy.update",
        resource_type="device_policy",
        resource_id=str(policy.id),
        payload={"changes": changes},
    )

    await push_to_group(
        db,
        policy.host_group_id,
        issued_by_user_id=actor.user.id,
    )
    return DevicePolicyOut.model_validate(policy)


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(policy_id: UUID, db: DbSession, actor: RequireAdmin) -> None:
    policy = await db.get(DevicePolicy, policy_id)
    if policy is None:
        raise not_found("device_policy", str(policy_id))
    snapshot = {
        "name": policy.name,
        "kind": policy.kind,
        "host_group_id": str(policy.host_group_id) if policy.host_group_id else None,
    }
    affected_group = policy.host_group_id
    await db.delete(policy)
    await db.flush()

    await audit.record(
        db,
        actor=actor,
        action="device_policy.delete",
        resource_type="device_policy",
        resource_id=str(policy_id),
        payload=snapshot,
    )

    await push_to_group(
        db,
        affected_group,
        issued_by_user_id=actor.user.id,
    )
