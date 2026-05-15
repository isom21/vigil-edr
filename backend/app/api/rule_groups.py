"""Rule groups (M20.b).

A rule group is a named bucket of rules of one kind (YARA / Sigma /
IOC) with a `max_action` ceiling. When a rule in the group fires, the
agent-facing effective action is clamped down to the group ceiling.
Lets an operator dial down a whole class of rules to alert-only during
tuning, then promote the whole group later.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, status
from sqlalchemy import func, select

from app.core.deps import DbSession, RequireAdmin, RequireAnalyst
from app.core.errors import bad_request, not_found
from app.models import Rule, RuleGroup
from app.schemas.common import Page
from app.schemas.rule import RuleGroupCreate, RuleGroupOut, RuleGroupUpdate
from app.services import audit
from app.services.scoping import apply_tenant_scope

router = APIRouter(prefix="/api/rule-groups", tags=["rule-groups"])


async def _hydrate(db, g: RuleGroup) -> RuleGroupOut:
    count = (
        await db.execute(select(func.count(Rule.id)).where(Rule.group_id == g.id))
    ).scalar_one()
    return RuleGroupOut(
        id=g.id,
        kind=g.kind,
        name=g.name,
        description=g.description,
        max_action=g.max_action,
        created_at=g.created_at,
        updated_at=g.updated_at,
        rule_count=int(count),
    )


async def _load_in_tenant(db, group_id: UUID, actor) -> RuleGroup:
    """Fetch a RuleGroup, enforcing tenant scope. 404 (not 403) on
    cross-tenant id, per the project convention (CODE-7)."""
    g = await db.get(RuleGroup, group_id)
    if g is None or g.tenant_id != actor.tenant_id:
        raise not_found("rule_group", str(group_id))
    return g


@router.get("", response_model=Page[RuleGroupOut])
async def list_groups(
    db: DbSession,
    actor: RequireAnalyst,
    kind: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> Page[RuleGroupOut]:
    # CODE-7: scope to the actor's tenant. Pre-PR, RuleGroup CRUD
    # operated globally, so tenant A's admin could rebind tenant B's
    # rules to a different group / max_action ceiling.
    stmt = apply_tenant_scope(select(RuleGroup), actor, RuleGroup.tenant_id)
    count_stmt = apply_tenant_scope(select(func.count(RuleGroup.id)), actor, RuleGroup.tenant_id)
    if kind:
        stmt = stmt.where(RuleGroup.kind == kind)
        count_stmt = count_stmt.where(RuleGroup.kind == kind)
    stmt = stmt.order_by(RuleGroup.kind, RuleGroup.name).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).scalars().all()
    total = (await db.execute(count_stmt)).scalar_one()
    items = [await _hydrate(db, g) for g in rows]
    return Page(items=items, total=int(total), limit=limit, offset=offset)


@router.post("", response_model=RuleGroupOut, status_code=status.HTTP_201_CREATED)
async def create_group(
    payload: RuleGroupCreate,
    db: DbSession,
    actor: RequireAdmin,
) -> RuleGroupOut:
    # Name uniqueness is per-(tenant, kind): tenant A and tenant B can
    # both have a "yara-tuning" group.
    dup = (
        await db.execute(
            select(RuleGroup).where(
                RuleGroup.kind == payload.kind,
                RuleGroup.name == payload.name,
                RuleGroup.tenant_id == actor.tenant_id,
            )
        )
    ).scalar_one_or_none()
    if dup is not None:
        raise bad_request(
            f"rule group named '{payload.name}' already exists for kind={payload.kind.value}"
        )
    g = RuleGroup(
        kind=payload.kind,
        tenant_id=actor.tenant_id,
        name=payload.name,
        description=payload.description,
        max_action=payload.max_action,
    )
    db.add(g)
    await db.flush()
    await audit.record(
        db,
        actor=actor,
        action="rule_group.create",
        resource_type="rule_group",
        resource_id=str(g.id),
        payload={"name": g.name, "kind": g.kind.value, "max_action": g.max_action.value},
    )
    await db.commit()
    return await _hydrate(db, g)


@router.get("/{group_id}", response_model=RuleGroupOut)
async def get_group(group_id: UUID, db: DbSession, actor: RequireAnalyst) -> RuleGroupOut:
    g = await _load_in_tenant(db, group_id, actor)
    return await _hydrate(db, g)


@router.patch("/{group_id}", response_model=RuleGroupOut)
async def update_group(
    group_id: UUID,
    payload: RuleGroupUpdate,
    db: DbSession,
    actor: RequireAdmin,
) -> RuleGroupOut:
    g = await _load_in_tenant(db, group_id, actor)
    if payload.name is not None and payload.name != g.name:
        dup = (
            await db.execute(
                select(RuleGroup).where(
                    RuleGroup.kind == g.kind,
                    RuleGroup.name == payload.name,
                    RuleGroup.tenant_id == actor.tenant_id,
                )
            )
        ).scalar_one_or_none()
        if dup is not None and dup.id != g.id:
            raise bad_request(f"rule group '{payload.name}' already exists")
        g.name = payload.name
    if payload.description is not None:
        g.description = payload.description
    if payload.max_action is not None:
        g.max_action = payload.max_action
    await audit.record(
        db,
        actor=actor,
        action="rule_group.update",
        resource_type="rule_group",
        resource_id=str(g.id),
        payload=payload.model_dump(exclude_none=True),
    )
    await db.commit()
    return await _hydrate(db, g)


@router.delete("/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_group(
    group_id: UUID,
    db: DbSession,
    actor: RequireAdmin,
) -> None:
    g = await _load_in_tenant(db, group_id, actor)
    # Rules with a group_id FK get nulled out via ON DELETE SET NULL.
    await db.delete(g)
    await audit.record(
        db,
        actor=actor,
        action="rule_group.delete",
        resource_type="rule_group",
        resource_id=str(group_id),
    )
    await db.commit()
