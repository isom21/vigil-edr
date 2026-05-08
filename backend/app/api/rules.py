"""Rule CRUD: YARA, Sigma, IOC."""
from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, status
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from app.core.deps import DbSession, RequireAdmin, RequireAnalyst
from app.core.errors import bad_request, not_found
from app.models import IocEntry, IocKind, Rule, RuleKind
from app.schemas.common import Page
from app.schemas.rule import IocEntryIn, RuleCreate, RuleOut, RuleUpdate
from app.services import audit

router = APIRouter(prefix="/api/rules", tags=["rules"])


def _normalize_ioc(kind: IocKind, value: str) -> str:
    v = value.strip()
    if kind in (IocKind.HASH_SHA256, IocKind.HASH_MD5, IocKind.HASH_SHA1):
        return v.lower()
    if kind is IocKind.FILENAME:
        return v.lower()
    if kind is IocKind.FILEPATH:
        # Cross-platform normalization: lowercase + use forward slashes for matching keys.
        return v.replace("\\", "/").lower()
    return v


def _set_iocs(rule: Rule, entries: list[IocEntryIn]) -> None:
    rule.iocs = [
        IocEntry(kind=e.kind, value=e.value, value_normalized=_normalize_ioc(e.kind, e.value))
        for e in entries
    ]


@router.get("", response_model=Page[RuleOut])
async def list_rules(
    db: DbSession,
    actor: RequireAnalyst,
    kind: RuleKind | None = None,
    enabled: bool | None = None,
    q: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> Page[RuleOut]:
    stmt = select(Rule).options(selectinload(Rule.iocs))
    count_stmt = select(func.count(Rule.id))
    if kind:
        stmt = stmt.where(Rule.kind == kind)
        count_stmt = count_stmt.where(Rule.kind == kind)
    if enabled is not None:
        stmt = stmt.where(Rule.enabled == enabled)
        count_stmt = count_stmt.where(Rule.enabled == enabled)
    if q:
        stmt = stmt.where(Rule.name.ilike(f"%{q}%"))
        count_stmt = count_stmt.where(Rule.name.ilike(f"%{q}%"))
    stmt = stmt.order_by(Rule.updated_at.desc()).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).scalars().all()
    total = (await db.execute(count_stmt)).scalar_one()
    return Page(
        items=[RuleOut.model_validate(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{rule_id}", response_model=RuleOut)
async def get_rule(rule_id: UUID, db: DbSession, actor: RequireAnalyst) -> RuleOut:
    stmt = select(Rule).where(Rule.id == rule_id).options(selectinload(Rule.iocs))
    rule = (await db.execute(stmt)).scalar_one_or_none()
    if rule is None:
        raise not_found("rule", str(rule_id))
    return RuleOut.model_validate(rule)


@router.post("", response_model=RuleOut, status_code=status.HTTP_201_CREATED)
async def create_rule(payload: RuleCreate, db: DbSession, actor: RequireAdmin) -> RuleOut:
    rule = Rule(
        kind=payload.kind,
        name=payload.name,
        description=payload.description,
        severity=payload.severity,
        action=payload.action,
        enabled=payload.enabled,
        body=payload.body,
    )
    if payload.iocs:
        _set_iocs(rule, payload.iocs)
    db.add(rule)
    await db.flush()
    await db.refresh(rule, attribute_names=["iocs"])
    await audit.record(
        db,
        actor=actor,
        action="rule.create",
        resource_type="rule",
        resource_id=str(rule.id),
        payload={"kind": rule.kind.value, "name": rule.name},
    )
    return RuleOut.model_validate(rule)


@router.patch("/{rule_id}", response_model=RuleOut)
async def update_rule(
    rule_id: UUID, payload: RuleUpdate, db: DbSession, actor: RequireAdmin
) -> RuleOut:
    stmt = select(Rule).where(Rule.id == rule_id).options(selectinload(Rule.iocs))
    rule = (await db.execute(stmt)).scalar_one_or_none()
    if rule is None:
        raise not_found("rule", str(rule_id))

    body_changed = False
    for field in ("name", "description", "severity", "action", "enabled"):
        v = getattr(payload, field)
        if v is not None:
            setattr(rule, field, v)
    if payload.body is not None:
        if rule.kind is RuleKind.IOC:
            raise bad_request("ioc rules do not have a body")
        rule.body = payload.body
        body_changed = True
    if payload.iocs is not None:
        if rule.kind is not RuleKind.IOC:
            raise bad_request("only ioc rules may set iocs")
        _set_iocs(rule, payload.iocs)
        body_changed = True

    if body_changed:
        rule.revision += 1
        rule.sigma_compiled = None  # invalidate cached compile output

    await audit.record(
        db,
        actor=actor,
        action="rule.update",
        resource_type="rule",
        resource_id=str(rule.id),
        payload=payload.model_dump(exclude_none=True),
    )
    await db.flush()
    await db.refresh(rule, attribute_names=["iocs"])
    return RuleOut.model_validate(rule)


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(rule_id: UUID, db: DbSession, actor: RequireAdmin) -> None:
    rule = await db.get(Rule, rule_id)
    if rule is None:
        raise not_found("rule", str(rule_id))
    await db.delete(rule)
    await audit.record(
        db, actor=actor, action="rule.delete", resource_type="rule", resource_id=str(rule_id)
    )
