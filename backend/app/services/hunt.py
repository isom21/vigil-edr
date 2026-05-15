"""Threat-hunting workbench services (Phase 2 #2.11).

Three jobs:

  * `translate_to_dsl(query, language)` — turn an operator-authored
    query into the OpenSearch `query_string` body the runner uses.
    Lucene + KQL pass through (KQL is treated as Lucene-superset for
    v1; the rule editor's KQL→Lucene migration happens upstream of
    here). Sigma YAML compiles via `app.services.sigma.compile_yaml`.

  * `run_hunt(db, hunt_id, dry_run=False)` — execute a saved hunt
    against the telemetry-* indices. Returns the persisted `HuntRun`
    row. When `alert_on_hit=True` and the run has hits, the function
    creates (or reuses) a managed `Rule` per hunt and inserts `Alert`
    rows pointing at it — mirroring `intel_ingest._ensure_managed_rule`.

  * `cron_matches(cron, now)` — five-field cron matcher used by the
    scheduler. Bare-minimum implementation: comma lists, ranges,
    `*/step` patterns, `*`. Day-of-month vs day-of-week match
    independently (OR-semantics), matching Vixie cron when either side
    is `*`.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models import (
    Alert,
    AlertState,
    AlertStateHistory,
    HuntRun,
    Rule,
    RuleAction,
    RuleKind,
    SavedHunt,
    Severity,
)
from app.services import opensearch as os_svc
from app.services.sigma import SigmaCompileError, compile_yaml

log = structlog.get_logger()

# Cap on hits returned from OpenSearch per run. The DSL `size` is the
# OS-level cap; total counts are returned separately via track_total_hits.
DEFAULT_RESULT_LIMIT = 10_000


class HuntCompileError(ValueError):
    """Raised when a hunt's query body fails to translate to a DSL."""


def translate_to_dsl(query: str, language: str) -> dict[str, Any]:
    """Translate an authored query into the OpenSearch query clause.

    Returns the inner clause (wrapped under `query_string` for lucene /
    kql / sigma). The caller composes the surrounding bool + range +
    host-scope filters.

    Raises HuntCompileError on bad input.
    """
    body = query.strip()
    if not body:
        raise HuntCompileError("query is empty")
    if language in ("lucene", "kql"):
        # KQL is a subset of Lucene for the field-equality queries
        # that make up 99% of hunt workloads (`process.name: foo AND
        # event.category: process`). Treating them identically here
        # keeps the worker simple; a proper KQL parser ships later
        # if operators ever hit a syntax gap.
        return {"query_string": {"query": body}}
    if language == "sigma":
        try:
            compiled = compile_yaml(body)
        except SigmaCompileError as exc:
            raise HuntCompileError(f"sigma compile failed: {exc}") from exc
        return {"query_string": {"query": compiled.query}}
    raise HuntCompileError(f"unknown query language: {language}")


def _result_limit() -> int:
    return int(settings.hunt_result_limit or DEFAULT_RESULT_LIMIT)


def build_search_body(
    query_clause: dict[str, Any],
    *,
    lower: datetime,
    upper: datetime,
    visible_host_ids: list[UUID] | None,
    host_scope: dict[str, Any] | None,
    size: int,
    tenant_id: UUID | None = None,
) -> dict[str, Any]:
    """Compose the OpenSearch request body for a hunt run.

    Wraps the translated query clause with a `@timestamp` range filter
    + the RBAC `host.id` terms clause (see `app.api.sigma._build_search_body`
    for the reference implementation). When the actor scopes themselves
    down further via `host_scope_json={"host_ids": [...]}`, that
    intersects with the visible list.

    CODE-22 / Phase 3 #3.1: when ``tenant_id`` is set, a `term: tenant.id`
    filter is appended so a non-super-admin can never see cross-tenant
    hits even if the host-id filter was ever bypassed. The normalizer
    stamps `tenant.id` on every ECS doc; pre-tenancy docs lacking the
    field will silently miss this filter — that's intentional, those
    pre-tenancy docs predate multi-tenancy.
    """
    filters: list[dict[str, Any]] = [
        {"range": {"@timestamp": {"gte": lower.isoformat(), "lte": upper.isoformat()}}},
        query_clause,
    ]
    if tenant_id is not None:
        filters.append({"term": {"tenant.id": str(tenant_id)}})
    # Resolve the effective host filter from RBAC ∩ saved scope.
    rbac_ids: list[str] | None = (
        [str(h) for h in visible_host_ids] if visible_host_ids is not None else None
    )
    scope_ids: list[str] | None = None
    if host_scope and isinstance(host_scope.get("host_ids"), list):
        scope_ids = [str(h) for h in host_scope["host_ids"]]
    effective: list[str] | None
    if rbac_ids is None and scope_ids is None:
        effective = None
    elif rbac_ids is None:
        effective = scope_ids
    elif scope_ids is None:
        effective = rbac_ids
    else:
        rbac_set = set(rbac_ids)
        effective = [h for h in scope_ids if h in rbac_set]
    if effective is not None:
        filters.append({"terms": {"host.id": effective}})
    return {
        "size": size,
        "track_total_hits": True,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": filters}},
    }


def effective_host_filter_empty(
    visible_host_ids: list[UUID] | None,
    host_scope: dict[str, Any] | None,
) -> bool:
    """True when the effective host filter resolves to zero ids — the
    runner should short-circuit (matches the sigma test path)."""
    rbac_ids: list[str] | None = (
        [str(h) for h in visible_host_ids] if visible_host_ids is not None else None
    )
    scope_ids: list[str] | None = None
    if host_scope and isinstance(host_scope.get("host_ids"), list):
        scope_ids = [str(h) for h in host_scope["host_ids"]]
    if rbac_ids is None and scope_ids is None:
        return False
    if rbac_ids is None:
        return len(scope_ids or []) == 0
    if scope_ids is None:
        return len(rbac_ids) == 0
    rbac_set = set(rbac_ids)
    return not any(h in rbac_set for h in scope_ids)


_SEVERITY_MAP: dict[str, Severity] = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


async def _ensure_managed_rule(db: AsyncSession, hunt: SavedHunt) -> Rule:
    """Create (or refetch) the managed Rule that backs alerts emitted
    by an `alert_on_hit` hunt. Mirrors `intel_ingest._ensure_managed_rule`.

    The Rule is kind=SIGMA because that's the only kind whose `name`
    label is operator-facing and whose `revision` field the alert
    pipeline checks. The body is left empty — the rule never feeds the
    realtime percolator; the hunt scheduler emits Alert rows directly.
    """
    if hunt.managed_rule_id is not None:
        rule = await db.get(Rule, hunt.managed_rule_id)
        if rule is not None:
            return rule
    severity = _SEVERITY_MAP.get((hunt.severity or "medium").lower(), Severity.MEDIUM)
    rule = Rule(
        kind=RuleKind.SIGMA,
        name=f"hunt:{hunt.name}",
        description=(
            f"Auto-managed: alerts emitted by scheduled hunt '{hunt.name}'. "
            "Edit the hunt in /hunt/saved; this rule itself is a stub used "
            "only for FK + alert dedup attribution."
        ),
        severity=severity,
        action=RuleAction.ALERT,
        enabled=True,
        body=None,
    )
    db.add(rule)
    await db.flush()
    hunt.managed_rule_id = rule.id
    return rule


async def _emit_alerts_for_hits(
    db: AsyncSession,
    hunt: SavedHunt,
    rule: Rule,
    hits: list[dict[str, Any]],
) -> int:
    """Insert Alert rows for each hit with a resolvable host. Returns
    the count actually inserted (hits without a `host.id` are skipped
    — we can't attach them to a host scope check otherwise)."""
    inserted = 0
    severity = _SEVERITY_MAP.get((hunt.severity or "medium").lower(), Severity.MEDIUM)
    techniques = list(hunt.mitre_techniques) if hunt.mitre_techniques else None
    for hit in hits:
        src = hit.get("_source") or {}
        host_id_str = (src.get("host") or {}).get("id")
        if not host_id_str:
            continue
        try:
            host_id = UUID(host_id_str)
        except (ValueError, TypeError):
            continue
        event_id = (src.get("event") or {}).get("id")
        alert = Alert(
            host_id=host_id,
            rule_id=rule.id,
            severity=severity,
            action_taken=RuleAction.ALERT,
            state=AlertState.NEW,
            summary=f"Hunt match: {hunt.name}",
            details={
                "engine": "hunt",
                "hunt_id": str(hunt.id),
                "hunt_name": hunt.name,
                "event_id": event_id,
                "query_language": hunt.query_language,
            },
            mitre_techniques=techniques,
        )
        alert.history.append(
            AlertStateHistory(
                from_state=None,
                to_state=AlertState.NEW,
                comment=f"auto-generated by hunt '{hunt.name}'",
            )
        )
        db.add(alert)
        inserted += 1
    if inserted:
        await db.flush()
    return inserted


async def execute_search(
    *,
    query_dsl: str,
    body: dict[str, Any],
) -> tuple[int, list[dict[str, Any]]]:
    """Run a search against telemetry-* and return (total, hits).

    `query_dsl` is logged for traceability; the actual wire query lives
    in `body`. Kept separate from `run_hunt` so the ad-hoc API path can
    invoke it without first persisting a HuntRun row.
    """
    client = os_svc._client()
    try:
        resp = await client.search(
            index="telemetry-*",
            body=body,
            request_timeout=30,  # pyright: ignore[reportCallIssue]
        )
    finally:
        await client.close()
    total_obj = resp.get("hits", {}).get("total", 0)
    total = total_obj.get("value", 0) if isinstance(total_obj, dict) else int(total_obj)
    hits = resp.get("hits", {}).get("hits", [])
    log.info("hunt.search", total=total, returned=len(hits), query_dsl=query_dsl[:200])
    return total, hits


async def run_hunt(
    db: AsyncSession,
    hunt_id: UUID,
    *,
    dry_run: bool = False,
    now: datetime | None = None,
    lookback_hours: int = 24,
) -> HuntRun:
    """Execute a saved hunt and persist the run history row.

    `dry_run=True` skips alert emission AND the saved-hunt row updates
    (last_run_at / last_run_hit_count). The HuntRun row is still
    inserted so the operator sees the run in history.
    """
    now = now or datetime.now(UTC)
    hunt = await db.get(SavedHunt, hunt_id)
    if hunt is None:
        raise ValueError(f"saved_hunt {hunt_id} not found")

    run = HuntRun(hunt_id=hunt.id, started_at=now)
    db.add(run)
    await db.flush()

    try:
        query_clause = translate_to_dsl(hunt.query_dsl, hunt.query_language)
    except HuntCompileError as exc:
        run.error = str(exc)
        run.finished_at = datetime.now(UTC)
        run.hit_count = 0
        run.alert_count = 0
        await db.flush()
        return run

    upper = now
    lower = upper - timedelta(hours=lookback_hours)
    body = build_search_body(
        query_clause,
        lower=lower,
        upper=upper,
        # Schedule path: no actor → admin-equivalent (the scheduler is
        # a system component, not a user). The saved scope still applies.
        visible_host_ids=None,
        host_scope=hunt.host_scope_json,
        size=min(_result_limit(), 10_000),
        # CODE-22: scheduler runs are still tenant-scoped — the hunt
        # belongs to a tenant, and we must not cross that boundary.
        tenant_id=hunt.tenant_id,
    )

    try:
        total, hits = await execute_search(query_dsl=hunt.query_dsl, body=body)
    except Exception as exc:  # noqa: BLE001
        run.error = f"search failed: {exc}"
        run.finished_at = datetime.now(UTC)
        run.hit_count = 0
        run.alert_count = 0
        await db.flush()
        log.warning("hunt.run.search_failed", hunt_id=str(hunt.id), error=str(exc))
        return run

    run.hit_count = total
    alert_count = 0
    if hunt.alert_on_hit and not dry_run and hits:
        rule = await _ensure_managed_rule(db, hunt)
        alert_count = await _emit_alerts_for_hits(db, hunt, rule, hits)
    run.alert_count = alert_count

    if not dry_run:
        hunt.last_run_at = now
        hunt.last_run_hit_count = total

    run.finished_at = datetime.now(UTC)
    await db.flush()
    return run


# --- cron matching ----------------------------------------------------


def _parse_field(spec: str, lo: int, hi: int) -> set[int]:
    """Parse one cron field into the matching minute/hour/etc. set."""
    out: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        step = 1
        if "/" in chunk:
            base, step_s = chunk.split("/", 1)
            step = int(step_s)
            if step < 1:
                raise ValueError(f"invalid step in cron field: {spec}")
        else:
            base = chunk
        if base == "*":
            start, end = lo, hi
        elif "-" in base:
            a, b = base.split("-", 1)
            start, end = int(a), int(b)
        else:
            v = int(base)
            start = end = v
        if start < lo or end > hi or start > end:
            raise ValueError(f"cron field out of range: {chunk}")
        for v in range(start, end + 1, step):
            out.add(v)
    return out


def cron_matches(cron: str, when: datetime) -> bool:
    """Return True when `when` (minute resolution) falls on `cron`.

    Five-field cron: minute hour day-of-month month day-of-week.
    Vixie OR-semantics for day-of-month vs day-of-week: when both are
    restricted, either match counts; when one is `*`, only the other
    has to match.
    """
    parts = cron.split()
    if len(parts) != 5:
        raise ValueError(f"cron string must have 5 fields, got {len(parts)}: {cron}")
    minute_set = _parse_field(parts[0], 0, 59)
    hour_set = _parse_field(parts[1], 0, 23)
    dom_set = _parse_field(parts[2], 1, 31)
    mon_set = _parse_field(parts[3], 1, 12)
    # Cron weekdays: 0 = Sunday … 6 = Saturday. Python: Monday=0, Sunday=6.
    dow_set = _parse_field(parts[4], 0, 6)
    if when.minute not in minute_set:
        return False
    if when.hour not in hour_set:
        return False
    if when.month not in mon_set:
        return False
    py_dow = when.weekday()  # Mon=0…Sun=6
    cron_dow = (py_dow + 1) % 7  # → Sun=0…Sat=6
    dom_restricted = parts[2] != "*"
    dow_restricted = parts[4] != "*"
    dom_match = when.day in dom_set
    dow_match = cron_dow in dow_set
    if dom_restricted and dow_restricted:
        return dom_match or dow_match
    return dom_match and dow_match


def validate_cron(cron: str) -> None:
    """Raise ValueError if the cron string is malformed. Cheap pre-flight
    check used by the API on create/update so bad strings don't slip
    through and get caught only on the first tick."""
    cron_matches(cron, datetime.now(UTC))
