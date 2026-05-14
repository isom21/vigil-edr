"""AI-assisted analyst endpoints (Phase 4 #4.1).

Two endpoints:

  * ``GET /api/alerts/{id}/summary`` — projects the persisted
    ``alert_summary`` row for the given alert. RBAC + host-visibility
    scoping mirror the alerts router: analysts + viewers in-tenant
    see summaries for hosts they can see; admins see everything
    in-tenant; cross-tenant lookups 404.
  * ``POST /api/ai/nl-to-query`` — translates English to a KQL or
    Lucene query. Admin or analyst only, with a per-route token
    bucket capped at ``_NL_RATE_LIMIT`` calls per minute keyed off
    ``actor.user.id`` so a single account can't hammer Anthropic
    from the UI.

The endpoint-level limiter rides on top of the global
``RateLimitMiddleware`` — the middleware enforces the per-role role
budget (e.g. 300/min for analyst), and this endpoint's per-user 30
/min cap stacks under it as a safety net specifically for the
LLM-cost-bearing surface. Both share ``request.app.state.
rate_limit_store`` so a Redis-backed deployment serializes the cap
across replicas exactly the same way.
"""

from __future__ import annotations

import time
from uuid import UUID

import structlog
from fastapi import APIRouter, Request
from sqlalchemy import select

from app.core.deps import DbSession, RequireAnalyst, RequireViewer
from app.core.errors import not_found
from app.models import Alert, AlertSummary
from app.schemas.ai_summary import AlertSummaryOut, NlQueryRequest, NlQueryResponse
from app.services.ai_client import AnthropicClient
from app.services.scoping import apply_tenant_scope, host_visible_to

log = structlog.get_logger()

router = APIRouter(prefix="/api", tags=["ai"])


# Per-route, per-user cap for the NL-to-query endpoint. The model
# call is the only externally-billed leg in the request path, so the
# limit is well below the per-role middleware budget (admin 600,
# analyst 300) but still leaves an analyst-grade headroom for
# iterative prompt refinement.
_NL_RATE_LIMIT: int = 30


async def _check_nl_rate_limit(request: Request, user_id: UUID) -> None:
    """Raise 429 via FastAPI's HTTPException if the per-user budget is
    spent. The middleware's bucket store is reused so Redis-backed
    deployments serialize the cap across replicas; in-memory store
    is fine for single-instance dev."""
    from fastapi import HTTPException

    store = getattr(request.app.state, "rate_limit_store", None)
    if store is None:
        # Fall back to the middleware's default in-memory store so the
        # cap still applies on a fresh process. Cheap: one bucket per
        # active analyst.
        from app.core.rate_limit import InMemoryStore

        store = InMemoryStore()
        request.app.state.rate_limit_store = store

    key = f"ai:nl:{user_id}"
    now = time.time()
    allowed, _remaining, reset = await store.admit(key, now, _NL_RATE_LIMIT)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="ai nl-to-query rate limit exceeded",
            headers={
                "Retry-After": str(max(1, int(reset - now))),
                "X-RateLimit-Limit": str(_NL_RATE_LIMIT),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(int(reset)),
            },
        )


@router.get("/alerts/{alert_id}/summary", response_model=AlertSummaryOut)
async def get_alert_summary(
    alert_id: UUID,
    db: DbSession,
    actor: RequireViewer,
) -> AlertSummaryOut:
    """Return the persisted AI summary for an alert.

    Two 404 cases:
      * the alert doesn't exist / isn't visible to the actor;
      * the alert exists but the summariser hasn't produced a row yet.
    Both surface as 404 so the UI can render the "AI analysis pending"
    spinner uniformly without leaking which axis failed.
    """
    # Apply tenant scope first — a cross-tenant alert id returns 404
    # without leaking existence.
    alert = (
        await db.execute(
            apply_tenant_scope(select(Alert).where(Alert.id == alert_id), actor, Alert.tenant_id)
        )
    ).scalar_one_or_none()
    if alert is None:
        raise not_found("alert", str(alert_id))
    if not await host_visible_to(actor, alert.host_id, db):
        raise not_found("alert", str(alert_id))

    row = (
        await db.execute(select(AlertSummary).where(AlertSummary.alert_id == alert_id))
    ).scalar_one_or_none()
    if row is None:
        raise not_found("alert_summary", str(alert_id))
    return AlertSummaryOut.model_validate(row)


@router.post("/ai/nl-to-query", response_model=NlQueryResponse)
async def nl_to_query(
    payload: NlQueryRequest,
    request: Request,
    actor: RequireAnalyst,
) -> NlQueryResponse:
    """Translate natural language to a KQL/Lucene query.

    Admin + analyst only — viewers can already read alerts but the
    hunt workbench is gated to analyst+, so the translator follows
    the same gate. Per-user 30/min rate limit on top of the role
    budget; the cap is well below the role budget because the
    Anthropic call is the externally-billed leg.
    """
    await _check_nl_rate_limit(request, actor.user.id)

    client = AnthropicClient()
    result = await client.nl_to_query(payload.prompt, payload.language)
    return NlQueryResponse(
        query=result.payload.get("query", ""),
        language=payload.language,
        cached_input_tokens=result.cached_input_tokens,
        output_tokens=result.output_tokens,
        model_id=result.model_id,
    )


__all__ = ["router"]
