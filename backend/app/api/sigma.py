"""Sigma compile + test endpoints.

Used by the rule editor to validate Sigma YAML and to dry-run a rule
against historical telemetry before saving.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from fastapi import APIRouter
from sqlalchemy import select

from app.core.deps import DbSession, RequireAnalyst
from app.core.errors import bad_request, not_found
from app.models import Rule, RuleKind
from app.schemas.sigma import (
    SigmaCompileRequest,
    SigmaCompileResponse,
    SigmaTestRequest,
    SigmaTestResponse,
    SigmaTestSampleHit,
)
from app.services import opensearch as os_svc
from app.services.scoping import visible_host_ids
from app.services.sigma import SigmaCompileError, compile_yaml

router = APIRouter(prefix="/api/sigma", tags=["sigma"])


@router.post("/compile", response_model=SigmaCompileResponse)
async def compile_endpoint(
    payload: SigmaCompileRequest, _actor: RequireAnalyst
) -> SigmaCompileResponse:
    try:
        compiled = compile_yaml(payload.body)
    except SigmaCompileError as exc:
        return SigmaCompileResponse(ok=False, error=str(exc))
    return SigmaCompileResponse(
        ok=True,
        query=compiled.query,
        title=compiled.title or None,
        description=compiled.description,
    )


def _effective_tenant_filter(actor, tenant_override: UUID | None) -> UUID | None:
    """Resolve the tenant.id filter for an OpenSearch search.

    Non-super-admins always filter by their own tenant; the override
    (only honoured for super-admins) lets the global view drill into
    a specific tenant. Super-admins with no override see across tenants.
    """
    if actor.is_super_admin:
        return tenant_override
    return actor.tenant_id


@router.post("/test", response_model=SigmaTestResponse)
async def test_adhoc(
    payload: SigmaTestRequest,
    actor: RequireAnalyst,
    db: DbSession,
    tenant_id: UUID | None = None,
) -> SigmaTestResponse:
    if not payload.body:
        raise bad_request("body required for ad-hoc test (or use /api/rules/{id}/test)")
    visible = await visible_host_ids(actor, db)
    return await _run_test(
        payload.body,
        payload.lookback_hours,
        visible,
        _effective_tenant_filter(actor, tenant_id),
    )


@router.post("/rules/{rule_id}/test", response_model=SigmaTestResponse)
async def test_saved_rule(
    rule_id: UUID,
    payload: SigmaTestRequest,
    db: DbSession,
    actor: RequireAnalyst,
    tenant_id: UUID | None = None,
) -> SigmaTestResponse:
    rule = (await db.execute(select(Rule).where(Rule.id == rule_id))).scalar_one_or_none()
    if rule is None:
        raise not_found("rule", str(rule_id))
    if rule.kind is not RuleKind.SIGMA:
        raise bad_request("rule is not a sigma rule")
    body = payload.body or rule.body or ""
    if not body:
        raise bad_request("rule has no body")
    visible = await visible_host_ids(actor, db)
    # Non-super-admins are pinned to their tenant; for super-admins
    # the rule's own tenant_id is the most natural scope (the rule
    # belongs to that tenant), with ?tenant_id= as the override.
    eff_tenant = (
        tenant_id
        if actor.is_super_admin and tenant_id is not None
        else (None if actor.is_super_admin else actor.tenant_id)
    )
    if not actor.is_super_admin and rule.tenant_id != actor.tenant_id:
        raise not_found("rule", str(rule_id))
    return await _run_test(body, payload.lookback_hours, visible, eff_tenant)


def _build_search_body(
    compiled_query: str,
    lower: datetime,
    upper: datetime,
    visible_ids: list[UUID] | None,
    tenant_id: UUID | None = None,
) -> dict[str, Any]:
    """Compose the OpenSearch request body for a sigma test run.

    `visible_ids` semantics match `visible_host_ids`: None means admin
    pass-through (no extra filter), a list means restrict to those
    host ids. The empty-list case is handled at the caller — that
    actor sees no hosts, so we return zero results without hitting
    OpenSearch at all.

    CODE-22: when ``tenant_id`` is set, a `term: tenant.id` filter is
    added so cross-tenant docs are never returned even if the host-id
    filter was ever bypassed. Pre-tenancy docs (no `tenant.id` field)
    silently miss this filter — intentional, they predate multi-tenancy.
    """
    filters: list[dict[str, Any]] = [
        {"range": {"@timestamp": {"gte": lower.isoformat(), "lte": upper.isoformat()}}},
        {"query_string": {"query": compiled_query}},
    ]
    if visible_ids is not None:
        filters.append({"terms": {"host.id": [str(h) for h in visible_ids]}})
    if tenant_id is not None:
        filters.append({"term": {"tenant.id": str(tenant_id)}})
    return {
        "size": 25,
        "track_total_hits": True,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": filters}},
    }


async def _run_test(
    body: str,
    lookback_hours: int,
    visible_ids: list[UUID] | None,
    tenant_id: UUID | None = None,
) -> SigmaTestResponse:
    try:
        compiled = compile_yaml(body)
    except SigmaCompileError as exc:
        raise bad_request(f"compile failed: {exc}") from exc

    upper = datetime.now(UTC)
    lower = upper - timedelta(hours=lookback_hours)

    # Non-admin actor with zero visible hosts → no hits are reachable.
    # Short-circuit so we don't issue a search with an empty `terms`
    # filter (which OpenSearch rejects as malformed).
    if visible_ids is not None and not visible_ids:
        return SigmaTestResponse(query=compiled.query, total=0, samples=[])

    client = os_svc._client()
    try:
        resp = await client.search(
            index="telemetry-*",
            body=_build_search_body(compiled.query, lower, upper, visible_ids, tenant_id),
            request_timeout=20,  # pyright: ignore[reportCallIssue]
        )
    finally:
        await client.close()

    total_obj = resp.get("hits", {}).get("total", 0)
    total = total_obj.get("value", 0) if isinstance(total_obj, dict) else int(total_obj)
    hits = resp.get("hits", {}).get("hits", [])
    samples = [
        SigmaTestSampleHit(
            timestamp=h.get("_source", {}).get("@timestamp"),
            host_id=h.get("_source", {}).get("host", {}).get("id"),
            event_id=h.get("_source", {}).get("event", {}).get("id"),
            process=h.get("_source", {}).get("process"),
            file=h.get("_source", {}).get("file"),
        )
        for h in hits
    ]
    return SigmaTestResponse(query=compiled.query, total=total, samples=samples)
