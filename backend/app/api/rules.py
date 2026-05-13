"""Rule CRUD: YARA, Sigma, IOC."""

from __future__ import annotations

from uuid import UUID

import structlog
from fastapi import APIRouter, status
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from app.core.deps import DbSession, RequireAdmin, RequireViewer
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


def _normalize_techniques(value: list[str] | None) -> list[str] | None:
    """Trim/uppercase MITRE ATT&CK technique IDs, drop blanks + dupes.

    The UI typically passes comma-separated input ("T1059.001, t1547.001")
    which the form splits client-side. The backend normalises to a
    deduped, upper-case list so the JSONB column stays consistent
    regardless of caller. Returns None when the resulting list is empty
    so we don't persist `[]` distinct from "unset".
    """
    if value is None:
        return None
    seen: set[str] = set()
    out: list[str] = []
    for raw in value:
        if not isinstance(raw, str):
            continue
        v = raw.strip().upper()
        if not v or v in seen:
            continue
        seen.add(v)
        out.append(v)
    return out or None


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
    actor: RequireViewer,
    kind: RuleKind | None = None,
    enabled: bool | None = None,
    group_id: str | None = None,
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
    if group_id is not None:
        # Special-case "null" string for the kind-section "Ungrouped"
        # row so the UI can fetch unassigned rules without inventing a
        # sentinel UUID.
        if group_id == "null":
            stmt = stmt.where(Rule.group_id.is_(None))
            count_stmt = count_stmt.where(Rule.group_id.is_(None))
        else:
            try:
                gid = UUID(group_id)
            except ValueError as exc:
                raise bad_request("group_id must be a UUID or 'null'") from exc
            stmt = stmt.where(Rule.group_id == gid)
            count_stmt = count_stmt.where(Rule.group_id == gid)
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
    actor: RequireViewer,
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
async def get_rule(rule_id: UUID, db: DbSession, actor: RequireViewer) -> RuleOut:
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
    if payload.group_id is not None:
        from app.models import RuleGroup

        g = await db.get(RuleGroup, payload.group_id)
        if g is None:
            raise not_found("rule_group", str(payload.group_id))
        if g.kind != payload.kind:
            raise bad_request(
                f"rule group kind ({g.kind.value}) doesn't match rule kind ({payload.kind.value})"
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
        group_id=payload.group_id,
        mitre_techniques=_normalize_techniques(payload.mitre_techniques),
        auto_memory_scan=payload.auto_memory_scan,
    )
    if payload.iocs:
        _set_iocs(rule, payload.iocs)
    db.add(rule)
    await db.flush()
    await db.refresh(rule, attribute_names=["iocs"])
    create_payload: dict[str, object] = {"kind": rule.kind.value, "name": rule.name}
    if rule.mitre_techniques:
        create_payload["mitre_techniques"] = list(rule.mitre_techniques)
    await audit.record(
        db,
        actor=actor,
        action="rule.create",
        resource_type="rule",
        resource_id=str(rule.id),
        payload=create_payload,
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
    if payload.group_id is not None:
        # Sentinel: an explicit None in JSON sets group_id=NULL.
        if str(payload.group_id) == "00000000-0000-0000-0000-000000000000":
            rule.group_id = None
        else:
            from app.models import RuleGroup

            g = await db.get(RuleGroup, payload.group_id)
            if g is None:
                raise not_found("rule_group", str(payload.group_id))
            if g.kind != rule.kind:
                raise bad_request(
                    f"rule group kind ({g.kind.value}) doesn't match rule kind ({rule.kind.value})"
                )
            rule.group_id = payload.group_id
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
    if payload.mitre_techniques is not None:
        rule.mitre_techniques = _normalize_techniques(payload.mitre_techniques)
    if payload.auto_memory_scan is not None:
        rule.auto_memory_scan = payload.auto_memory_scan

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
        # mode="json" coerces UUID/datetime into JSON-native types so the
        # audit_log JSON column accepts the row (UUID() is not serializable
        # by stdlib json otherwise).
        payload=payload.model_dump(exclude_none=True, mode="json"),
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
