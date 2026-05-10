"""Rule CRUD: YARA, Sigma, IOC."""

from __future__ import annotations

from uuid import UUID

import structlog
from fastapi import APIRouter, status
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from app.core.deps import DbSession, RequireAdmin, RequireAnalyst
from app.core.errors import bad_request, not_found
from app.models import IocEntry, IocKind, Rule, RuleKind
from app.schemas.common import Page
from app.schemas.rule import IocEntryIn, RuleCreate, RuleOut, RuleUpdate
from app.schemas.stats import StatBucket
from app.services import audit
from app.services import opensearch as os_svc
from app.services.sigma import SigmaCompileError, compile_yaml
from app.services.sorting import parse_sort

log = structlog.get_logger()

router = APIRouter(prefix="/api/rules", tags=["rules"])


_SORTABLE = {
    "name": Rule.name,
    "kind": Rule.kind,
    "severity": Rule.severity,
    "updated_at": Rule.updated_at,
    "enabled": Rule.enabled,
}


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
    sort: str | None = None,
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
    order = parse_sort(sort, _SORTABLE, default=[Rule.updated_at.desc()])
    stmt = stmt.order_by(*order).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).scalars().all()
    total = (await db.execute(count_stmt)).scalar_one()
    return Page(
        items=[RuleOut.model_validate(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/stats", response_model=list[StatBucket])
async def rule_stats(
    db: DbSession,
    actor: RequireAnalyst,
    bucket: str,
) -> list[StatBucket]:
    """bucket=kind|severity|enabled."""
    if bucket == "kind":
        stmt = select(Rule.kind, func.count(Rule.id)).group_by(Rule.kind)
    elif bucket == "severity":
        stmt = select(Rule.severity, func.count(Rule.id)).group_by(Rule.severity)
    elif bucket == "enabled":
        stmt = select(Rule.enabled, func.count(Rule.id)).group_by(Rule.enabled)
    else:
        raise bad_request("bucket must be one of: kind, severity, enabled")
    rows = (await db.execute(stmt)).all()
    return [StatBucket(key=_key_str(k), count=int(c)) for k, c in rows]


def _key_str(v) -> str:
    if v is None:
        return "unknown"
    if isinstance(v, bool):
        return "enabled" if v else "disabled"
    if hasattr(v, "value"):
        return v.value
    return str(v)


@router.get("/{rule_id}", response_model=RuleOut)
async def get_rule(rule_id: UUID, db: DbSession, actor: RequireAnalyst) -> RuleOut:
    stmt = select(Rule).where(Rule.id == rule_id).options(selectinload(Rule.iocs))
    rule = (await db.execute(stmt)).scalar_one_or_none()
    if rule is None:
        raise not_found("rule", str(rule_id))
    return RuleOut.model_validate(rule)


def _validate_sigma_or_400(body: str | None) -> str | None:
    """Compile a Sigma rule body and return its Lucene query, or 400."""
    if not body:
        return None
    try:
        compiled = compile_yaml(body)
    except SigmaCompileError as exc:
        raise bad_request(f"sigma compile failed: {exc}") from exc
    return compiled.query


async def _sync_sigma_rule_to_percolator(rule: Rule) -> None:
    """Reflect the rule's current state into the OpenSearch percolator index.

    Best-effort: failures here log but don't fail the API call. The
    sigma_realtime worker re-syncs from PG on startup, so eventual
    consistency is fine.

    A rule is *registered* iff: kind=sigma AND enabled AND has a compiled
    query. In every other case (deleted, disabled, kind changed away,
    compile failed) we *unregister*.
    """
    client = os_svc._client()
    try:
        await os_svc.ensure_sigma_index(client)
        if rule.kind is RuleKind.SIGMA and rule.enabled and rule.sigma_compiled:
            await os_svc.register_sigma_rule(
                client,
                rule_id=rule.id,
                rule_name=rule.name,
                severity=rule.severity.value,
                lucene_query=rule.sigma_compiled,
            )
        else:
            await os_svc.unregister_sigma_rule(client, rule.id)
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "sigma.percolator_sync_failed",
            rule_id=str(rule.id),
            error=str(exc),
        )
    finally:
        await client.close()


async def _unregister_sigma_rule(rule_id: UUID) -> None:
    """Remove a rule from the percolator index. Best-effort."""
    client = os_svc._client()
    try:
        await os_svc.ensure_sigma_index(client)
        await os_svc.unregister_sigma_rule(client, rule_id)
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "sigma.percolator_unregister_failed",
            rule_id=str(rule_id),
            error=str(exc),
        )
    finally:
        await client.close()


@router.post("", response_model=RuleOut, status_code=status.HTTP_201_CREATED)
async def create_rule(payload: RuleCreate, db: DbSession, actor: RequireAdmin) -> RuleOut:
    sigma_compiled = (
        _validate_sigma_or_400(payload.body) if payload.kind is RuleKind.SIGMA else None
    )
    rule = Rule(
        kind=payload.kind,
        name=payload.name,
        description=payload.description,
        severity=payload.severity,
        action=payload.action,
        enabled=payload.enabled,
        body=payload.body,
        sigma_compiled=sigma_compiled,
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
    if rule.kind is RuleKind.SIGMA:
        await _sync_sigma_rule_to_percolator(rule)
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
        if rule.kind is RuleKind.SIGMA:
            rule.sigma_compiled = _validate_sigma_or_400(rule.body)
        else:
            rule.sigma_compiled = None

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
    if rule.kind is RuleKind.SIGMA:
        await _sync_sigma_rule_to_percolator(rule)
    return RuleOut.model_validate(rule)


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(rule_id: UUID, db: DbSession, actor: RequireAdmin) -> None:
    rule = await db.get(Rule, rule_id)
    if rule is None:
        raise not_found("rule", str(rule_id))
    was_sigma = rule.kind is RuleKind.SIGMA
    await db.delete(rule)
    await audit.record(
        db, actor=actor, action="rule.delete", resource_type="rule", resource_id=str(rule_id)
    )
    if was_sigma:
        await _unregister_sigma_rule(rule_id)
