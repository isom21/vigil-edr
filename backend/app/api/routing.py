"""Routing rules CRUD (Phase 1 #1.7 — alert routing).

Routing rules are admin-managed; analyst+ may list / get. The rule is
how operators connect alert filters to the credentialed channels they
created via /api/notifications/channels.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, status
from sqlalchemy import select

from app.core.deps import DbSession, RequireAdmin, RequireAnalyst
from app.core.errors import bad_request, not_found
from app.models import HostGroup, NotificationChannel, RoutingRule
from app.schemas.routing import RoutingRuleCreate, RoutingRuleOut, RoutingRuleUpdate
from app.services import audit

router = APIRouter(prefix="/api/notifications/rules", tags=["notifications"])


async def _validate_refs(
    db,
    *,
    channel_ids: list[UUID] | None,
    host_group_id: UUID | None,
) -> None:
    """Make sure the referenced channels / host group all exist. We
    validate at write-time so the worker can assume well-formed rule
    rows at fire-time (a missing FK on channel_ids would manifest as
    a silent drop)."""
    if channel_ids:
        found = (
            (
                await db.execute(
                    select(NotificationChannel.id).where(
                        NotificationChannel.id.in_(channel_ids)
                    )
                )
            )
            .scalars()
            .all()
        )
        missing = set(channel_ids) - set(found)
        if missing:
            raise bad_request(
                f"unknown notification channel(s): {sorted(str(m) for m in missing)}"
            )
    if host_group_id is not None:
        g = await db.get(HostGroup, host_group_id)
        if g is None:
            raise bad_request(f"unknown host_group_id: {host_group_id}")


@router.get("", response_model=list[RoutingRuleOut])
async def list_rules(db: DbSession, actor: RequireAnalyst) -> list[RoutingRuleOut]:
    rows = (
        (await db.execute(select(RoutingRule).order_by(RoutingRule.name)))
        .scalars()
        .all()
    )
    return [RoutingRuleOut.model_validate(r) for r in rows]


@router.post(
    "",
    response_model=RoutingRuleOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_rule(
    payload: RoutingRuleCreate,
    db: DbSession,
    actor: RequireAdmin,
) -> RoutingRuleOut:
    dup = (
        await db.execute(select(RoutingRule).where(RoutingRule.name == payload.name))
    ).scalar_one_or_none()
    if dup is not None:
        raise bad_request(f"routing rule '{payload.name}' already exists")
    await _validate_refs(
        db,
        channel_ids=payload.channel_ids,
        host_group_id=payload.host_group_id,
    )
    rule = RoutingRule(
        name=payload.name,
        min_severity=payload.min_severity,
        rule_kind=payload.rule_kind,
        host_group_id=payload.host_group_id,
        channel_ids=list(payload.channel_ids),
        enabled=payload.enabled,
    )
    db.add(rule)
    await db.flush()
    await audit.record(
        db,
        actor=actor,
        action="routing_rule.create",
        resource_type="routing_rule",
        resource_id=str(rule.id),
        payload={
            "name": rule.name,
            "min_severity": rule.min_severity.value,
            "rule_kind": rule.rule_kind.value if rule.rule_kind else None,
            "host_group_id": str(rule.host_group_id) if rule.host_group_id else None,
            "channel_ids": [str(c) for c in rule.channel_ids],
            "enabled": rule.enabled,
        },
    )
    await db.commit()
    return RoutingRuleOut.model_validate(rule)


@router.get("/{rule_id}", response_model=RoutingRuleOut)
async def get_rule(
    rule_id: UUID, db: DbSession, actor: RequireAnalyst
) -> RoutingRuleOut:
    r = await db.get(RoutingRule, rule_id)
    if r is None:
        raise not_found("routing_rule", str(rule_id))
    return RoutingRuleOut.model_validate(r)


@router.patch("/{rule_id}", response_model=RoutingRuleOut)
async def update_rule(
    rule_id: UUID,
    payload: RoutingRuleUpdate,
    db: DbSession,
    actor: RequireAdmin,
) -> RoutingRuleOut:
    r = await db.get(RoutingRule, rule_id)
    if r is None:
        raise not_found("routing_rule", str(rule_id))
    if payload.name is not None and payload.name != r.name:
        dup = (
            await db.execute(
                select(RoutingRule).where(
                    RoutingRule.name == payload.name, RoutingRule.id != rule_id
                )
            )
        ).scalar_one_or_none()
        if dup is not None:
            raise bad_request(f"routing rule '{payload.name}' already exists")
        r.name = payload.name
    if payload.min_severity is not None:
        r.min_severity = payload.min_severity
    if payload.rule_kind is not None:
        r.rule_kind = payload.rule_kind
    if payload.host_group_id is not None:
        await _validate_refs(db, channel_ids=None, host_group_id=payload.host_group_id)
        r.host_group_id = payload.host_group_id
    if payload.channel_ids is not None:
        await _validate_refs(db, channel_ids=payload.channel_ids, host_group_id=None)
        r.channel_ids = list(payload.channel_ids)
    if payload.enabled is not None:
        r.enabled = payload.enabled
    await audit.record(
        db,
        actor=actor,
        action="routing_rule.update",
        resource_type="routing_rule",
        resource_id=str(rule_id),
        payload={
            "name": r.name,
            "min_severity": r.min_severity.value,
            "rule_kind": r.rule_kind.value if r.rule_kind else None,
            "host_group_id": str(r.host_group_id) if r.host_group_id else None,
            "channel_ids": [str(c) for c in r.channel_ids],
            "enabled": r.enabled,
        },
    )
    await db.commit()
    return RoutingRuleOut.model_validate(r)


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(rule_id: UUID, db: DbSession, actor: RequireAdmin) -> None:
    r = await db.get(RoutingRule, rule_id)
    if r is None:
        raise not_found("routing_rule", str(rule_id))
    await db.delete(r)
    await audit.record(
        db,
        actor=actor,
        action="routing_rule.delete",
        resource_type="routing_rule",
        resource_id=str(rule_id),
        payload={"name": r.name},
    )
    await db.commit()
