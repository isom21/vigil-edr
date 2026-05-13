"""MITRE ATT&CK Navigator JSON aggregation.

Phase 1 #1.8: emit an ATT&CK Navigator layer (v4.5) listing recent
alerts aggregated by technique ID. The layer JSON can be loaded
directly at https://mitre-attack.github.io/attack-navigator/ to colour
the matrix by alert volume.

Aggregation strategy: count(*) GROUP BY each technique in the alert's
`mitre_techniques` JSON array. Postgres' `jsonb_array_elements_text`
unrolls the array so multi-technique alerts contribute to every
matching cell. Host scoping reuses `apply_host_scope` so non-admin
actors only see counts from hosts they can reach.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Query
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import JSONB

from app.core.deps import DbSession, RequireViewer
from app.models import Alert
from app.services.scoping import apply_host_scope

router = APIRouter(prefix="/api/mitre", tags=["mitre"])


# Pin a known-good ATT&CK / Navigator combo; bumping these is a docs
# change for operators who load the JSON locally.
ATTACK_VERSION = "14"
NAVIGATOR_VERSION = "4.9.1"
LAYER_VERSION = "4.5"
DOMAIN = "enterprise-attack"


@router.get("/navigator.json")
async def navigator_layer(
    db: DbSession,
    actor: RequireViewer,
    window_hours: int = Query(default=168, ge=1, le=720),
) -> dict[str, Any]:
    """Return an ATT&CK Navigator layer aggregating alerts by technique.

    `window_hours` defaults to 7 days; max 30 days to keep the GROUP BY
    bounded. Admins get fleet-wide counts; analysts get only their
    hosts' alerts (scoped via `apply_host_scope`).
    """
    cutoff = datetime.now(UTC) - timedelta(hours=window_hours)
    # Postgres-only: unroll the JSON array so each technique becomes a
    # row, then count by id. `jsonb_array_elements_text` is a
    # set-returning function — used in the SELECT list it expands one
    # alert row into N rows (one per technique). `Alert.mitre_techniques
    # IS NOT NULL` keeps the planner from feeding nulls to the SRF.
    technique_expr = func.jsonb_array_elements_text(Alert.mitre_techniques.cast(JSONB)).label(
        "technique_id"
    )
    stmt = (
        select(technique_expr, func.count().label("n"))
        .where(Alert.opened_at >= cutoff)
        .where(Alert.mitre_techniques.is_not(None))
        .group_by(technique_expr)
        .order_by(func.count().desc())
    )
    stmt = apply_host_scope(stmt, actor, host_column=Alert.host_id)
    rows = (await db.execute(stmt)).all()

    techniques = [
        {
            "techniqueID": str(tid),
            "score": int(count),
            "comment": f"{int(count)} alert{'s' if int(count) != 1 else ''}",
        }
        for tid, count in rows
    ]
    # `count(*)` after GROUP BY is always >= 1, so default=1 covers the
    # empty-result case (no alerts in window) without an `or 1` guard.
    max_score = max((t["score"] for t in techniques), default=1)
    return {
        "name": f"Vigil alerts — last {window_hours}h",
        "versions": {
            "attack": ATTACK_VERSION,
            "navigator": NAVIGATOR_VERSION,
            "layer": LAYER_VERSION,
        },
        "domain": DOMAIN,
        "description": "Auto-generated from alerts in the configured window.",
        "techniques": techniques,
        "gradient": {
            "colors": ["#fff5f5", "#7a0000"],
            "minValue": 1,
            "maxValue": max_score,
        },
        "legendItems": [],
    }
