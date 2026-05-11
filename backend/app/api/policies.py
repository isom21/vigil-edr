"""Policy CRUD."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, status
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.core.deps import DbSession, RequireAdmin, RequireAnalyst
from app.core.errors import conflict, not_found
from app.models import Policy, PolicyRule
from app.schemas.policy import (
    PolicyCreate,
    PolicyOut,
    PolicyRuleEntryIn,
    PolicyRuleEntryOut,
    PolicyUpdate,
)
from app.services import audit

router = APIRouter(prefix="/api/policies", tags=["policies"])


def _to_out(policy: Policy) -> PolicyOut:
    return PolicyOut(
        id=policy.id,
        name=policy.name,
        description=policy.description,
        version=policy.version,
        sweep_interval_hours=policy.sweep_interval_hours,
        sweep_categories=list(policy.sweep_categories or []),
        created_at=policy.created_at,
        updated_at=policy.updated_at,
        rules=[
            PolicyRuleEntryOut(
                rule_id=link.rule_id,
                action_override=link.action_override,
                enabled_override=link.enabled_override,
            )
            for link in policy.rule_links
        ],
    )


def _replace_rule_links(policy: Policy, entries: list[PolicyRuleEntryIn]) -> None:
    policy.rule_links = [
        PolicyRule(
            rule_id=e.rule_id,
            action_override=e.action_override,
            enabled_override=e.enabled_override,
        )
        for e in entries
    ]


@router.get("", response_model=list[PolicyOut])
async def list_policies(db: DbSession, actor: RequireAnalyst) -> list[PolicyOut]:
    stmt = select(Policy).options(selectinload(Policy.rule_links)).order_by(Policy.name)
    rows = (await db.execute(stmt)).scalars().all()
    return [_to_out(p) for p in rows]


@router.get("/{policy_id}", response_model=PolicyOut)
async def get_policy(policy_id: UUID, db: DbSession, actor: RequireAnalyst) -> PolicyOut:
    stmt = select(Policy).where(Policy.id == policy_id).options(selectinload(Policy.rule_links))
    policy = (await db.execute(stmt)).scalar_one_or_none()
    if policy is None:
        raise not_found("policy", str(policy_id))
    return _to_out(policy)


@router.post("", response_model=PolicyOut, status_code=status.HTTP_201_CREATED)
async def create_policy(payload: PolicyCreate, db: DbSession, actor: RequireAdmin) -> PolicyOut:
    existing = (
        await db.execute(select(Policy).where(Policy.name == payload.name))
    ).scalar_one_or_none()
    if existing:
        raise conflict("policy name already in use")
    policy = Policy(name=payload.name, description=payload.description)
    if payload.sweep_interval_hours is not None:
        policy.sweep_interval_hours = payload.sweep_interval_hours
    if payload.sweep_categories is not None:
        policy.sweep_categories = list(payload.sweep_categories)
    _replace_rule_links(policy, payload.rules)
    db.add(policy)
    await db.flush()
    await db.refresh(policy, attribute_names=["rule_links"])
    await audit.record(
        db,
        actor=actor,
        action="policy.create",
        resource_type="policy",
        resource_id=str(policy.id),
        payload={"name": policy.name, "rule_count": len(policy.rule_links)},
    )
    return _to_out(policy)


@router.patch("/{policy_id}", response_model=PolicyOut)
async def update_policy(
    policy_id: UUID, payload: PolicyUpdate, db: DbSession, actor: RequireAdmin
) -> PolicyOut:
    stmt = select(Policy).where(Policy.id == policy_id).options(selectinload(Policy.rule_links))
    policy = (await db.execute(stmt)).scalar_one_or_none()
    if policy is None:
        raise not_found("policy", str(policy_id))
    if payload.name is not None:
        policy.name = payload.name
    if payload.description is not None:
        policy.description = payload.description
    if payload.sweep_interval_hours is not None:
        policy.sweep_interval_hours = payload.sweep_interval_hours
    if payload.sweep_categories is not None:
        policy.sweep_categories = list(payload.sweep_categories)
    if payload.rules is not None:
        _replace_rule_links(policy, payload.rules)
        policy.version += 1
    await audit.record(
        db,
        actor=actor,
        action="policy.update",
        resource_type="policy",
        resource_id=str(policy.id),
        payload=payload.model_dump(exclude_none=True, exclude={"rules"}),
    )
    await db.flush()
    await db.refresh(policy, attribute_names=["rule_links"])
    return _to_out(policy)


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(policy_id: UUID, db: DbSession, actor: RequireAdmin) -> None:
    policy = await db.get(Policy, policy_id)
    if policy is None:
        raise not_found("policy", str(policy_id))
    await db.delete(policy)
    await audit.record(
        db,
        actor=actor,
        action="policy.delete",
        resource_type="policy",
        resource_id=str(policy_id),
    )
