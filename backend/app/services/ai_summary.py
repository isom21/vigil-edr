"""AI summariser service (Phase 4 #4.1).

One public entry point — ``summarise_and_persist`` — that the Kafka
consumer worker calls when an ``alert.opened`` envelope arrives.

The flow:

  1. Load the alert (the envelope only carries the id) plus the
     parent rule for context. If the alert vanished between publish
     and consume, log + return — no row, no event.
  2. Hand the trio (alert, ecs, rule) to ``AnthropicClient``. The
     client short-circuits to a dev stub when no API key is
     configured; tests rely on this path.
  3. Replace any prior ``alert_summary`` row for this alert (delete
     then insert — UNIQUE(alert_id) makes overwrites a one-line
     conflict). Stamp the model id + token counts.
  4. Publish ``alert.summary_ready`` so webhook subscribers (and a
     future UI listener) get notified without polling.

Re-summarisation is intentionally allowed: the call site is free to
re-invoke with the same alert_id when the model id rotates or when
the operator clicks a "regenerate" button. The unique constraint
keeps storage cost bounded — one row per alert.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Alert, AlertSummary, Rule
from app.services.ai_client import AiCallResult, AnthropicClient
from app.services.event_bus import publish_event

log = structlog.get_logger()


def alert_envelope_for_model(alert: Alert) -> dict[str, Any]:
    """Project the columns the model needs onto a flat dict. We avoid
    handing the SQLAlchemy row to the JSON encoder so a future column
    addition doesn't leak into the prompt unintentionally. Exported so
    the `ai_suggest` playbook step builds the same envelope shape
    without re-defining the projection."""
    return {
        "id": str(alert.id),
        "severity": alert.severity.value,
        "state": alert.state.value,
        "summary": alert.summary,
        "opened_at": alert.opened_at.isoformat(),
        "mitre_techniques": list(alert.mitre_techniques or []),
        "host_id": str(alert.host_id) if alert.host_id else None,
        "details": alert.details or {},
    }


def _rule_envelope(rule: Rule | None) -> dict[str, Any]:
    if rule is None:
        return {}
    return {
        "id": str(rule.id),
        "name": rule.name,
        "kind": rule.kind.value if rule.kind else None,
        "description": rule.description,
        "severity": rule.severity.value if rule.severity else None,
    }


async def summarise_and_persist(
    db: AsyncSession,
    alert_id: UUID,
    *,
    client: AnthropicClient | None = None,
) -> AlertSummary | None:
    """Summarise one alert and persist the row. Returns the row, or
    None when the alert can't be loaded (already deleted, etc.).

    The caller commits — we only flush here so the row is visible to
    the surrounding transaction for tests and for publishing the
    `alert.summary_ready` envelope after the flush succeeds.
    """
    alert = await db.get(Alert, alert_id)
    if alert is None:
        log.warning("ai_summary.alert_missing", alert_id=str(alert_id))
        return None

    rule = await db.get(Rule, alert.rule_id) if alert.rule_id else None
    cli = client or AnthropicClient()

    ecs: dict[str, Any] = {}
    if alert.details and isinstance(alert.details, dict):
        # The ECS-shaped envelope the detectors stash under `details.ecs`
        # is what we want to surface to the model. Fall back to the raw
        # `details` blob otherwise so older alerts still get useful
        # output.
        ecs = alert.details.get("ecs") or alert.details

    result: AiCallResult = await cli.summarise_alert(
        alert=alert_envelope_for_model(alert),
        ecs=ecs,
        rule=_rule_envelope(rule),
    )

    # Drop any prior row so the UNIQUE(alert_id) constraint doesn't
    # bounce the insert. Cheap: at most one row deleted.
    await db.execute(delete(AlertSummary).where(AlertSummary.alert_id == alert_id))

    row = AlertSummary(
        alert_id=alert_id,
        tenant_id=alert.tenant_id,
        summary=result.payload.get("summary", ""),
        suggested_response_json=result.payload.get("suggested_response") or [],
        model_id=result.model_id,
        cached_input_tokens=result.cached_input_tokens,
        output_tokens=result.output_tokens,
    )
    db.add(row)
    await db.flush()

    # Best-effort notify. publish_event swallows broker errors so a
    # downed Kafka can't take the summariser worker with it.
    await publish_event(
        "alert.summary_ready",
        {
            "alert_id": str(alert_id),
            "tenant_id": str(alert.tenant_id),
            "model_id": result.model_id,
        },
    )

    log.info(
        "ai_summary.persisted",
        alert_id=str(alert_id),
        model_id=result.model_id,
        cached_input_tokens=result.cached_input_tokens,
        output_tokens=result.output_tokens,
    )
    return row


__all__ = ["alert_envelope_for_model", "summarise_and_persist"]
