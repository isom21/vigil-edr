"""Process-chain lineage endpoints (Phase 2 #2.6).

Two surfaces:

  * `GET /api/hosts/{host_id}/process_chain?pid=<>` — ancestors +
    descendants of a pid on one host. Used by the agent details page
    and by the alert investigation drawer when a pid is known.
  * `GET /api/alerts/{alert_id}/process_chain` — same lineage view
    keyed off the triggering pid of an alert. Falls through to a
    404 when the alert's host is not visible to the actor.

Both endpoints route through `host_visible_to` for the 403/404
unification baked into the rest of the host-scoped surface.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query

from app.core.deps import DbSession, RequireViewer
from app.core.errors import bad_request, not_found
from app.models import Alert
from app.schemas.process_chain import ProcessChainNodePG, ProcessChainResponse
from app.services import process_graph
from app.services.scoping import host_visible_to

router = APIRouter(tags=["process-chain"])


def _to_response(host_id: UUID, pid: int, ancestors, descendants) -> ProcessChainResponse:
    return ProcessChainResponse(
        host_id=host_id,
        pid=pid,
        ancestors=[ProcessChainNodePG.model_validate(r) for r in ancestors],
        descendants=[ProcessChainNodePG.model_validate(r) for r in descendants],
    )


@router.get(
    "/api/hosts/{host_id}/process_chain",
    response_model=ProcessChainResponse,
)
async def host_process_chain(
    host_id: UUID,
    db: DbSession,
    actor: RequireViewer,
    pid: Annotated[int, Query(gt=0)],
) -> ProcessChainResponse:
    if not await host_visible_to(actor, host_id, db):
        # M-audit-and-auth #7: 404 not 403 so a viewer can't probe for
        # the existence of hosts they can't see.
        raise not_found("host", str(host_id))
    ancestors = await process_graph.ancestors(db, host_id=host_id, pid=pid)
    descendants = await process_graph.descendants(db, host_id=host_id, pid=pid)
    return _to_response(host_id, pid, ancestors, descendants)


@router.get(
    "/api/alerts/{alert_id}/process_chain",
    response_model=ProcessChainResponse,
)
async def alert_process_chain(
    alert_id: UUID,
    db: DbSession,
    actor: RequireViewer,
) -> ProcessChainResponse:
    alert = await db.get(Alert, alert_id)
    if alert is None:
        raise not_found("alert", str(alert_id))
    if not await host_visible_to(actor, alert.host_id, db):
        raise not_found("alert", str(alert_id))
    if alert.host_id is None:
        raise not_found("alert", str(alert_id))
    pid = _alert_trigger_pid(alert)
    if pid is None:
        raise bad_request("alert has no triggering pid in details")
    ancestors = await process_graph.ancestors(db, host_id=alert.host_id, pid=pid)
    descendants = await process_graph.descendants(db, host_id=alert.host_id, pid=pid)
    return _to_response(alert.host_id, pid, ancestors, descendants)


def _alert_trigger_pid(alert: Alert) -> int | None:
    """Pull the triggering pid out of an alert's details payload. Same
    convention the rest of the alert surface uses — detectors stuff
    `pid` into `alert.details` so the investigation view doesn't have
    to round-trip OpenSearch for the seed."""
    details = alert.details if isinstance(alert.details, dict) else None
    if details is None:
        return None
    raw = details.get("pid")
    if isinstance(raw, int) and raw > 0:
        return raw
    if isinstance(raw, str):
        try:
            value = int(raw)
        except ValueError:
            return None
        return value if value > 0 else None
    return None
