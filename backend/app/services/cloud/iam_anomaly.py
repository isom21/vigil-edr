"""IAM-role anomaly detection over CloudTrail events (Phase 4 #4.2).

Four detectors fire synthetic Vigil alerts:

  * :func:`detect_new_principal` — first time a principal ARN is seen
    for this source. Seeds the baseline row but does NOT fire on the
    first observation (avoids alert-on-bootstrap noise).
  * :func:`detect_new_action` — the principal performed an action
    (``event_source`` + ``event_name``) it hasn't performed before.
  * :func:`detect_new_region` — the principal called from a region it
    hasn't called from before.
  * :func:`detect_root_console_login` — the root account signed into
    the AWS console at all (a real CIS / SOC2 finding regardless of
    history).

Every hit bootstraps the synthetic ``Rule`` row (idempotent) so the
alerts FK is satisfied, then inserts an ``Alert`` directly with
``rule_id=CLOUD_IAM_ANOMALY_RULE_ID``, severity ``HIGH``, MITRE
T1078.004 (Cloud Accounts). ``host_id`` is ``None`` because cloud
events don't belong to a host.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    Alert,
    AlertState,
    CloudBaseline,
    Rule,
    RuleAction,
    RuleKind,
    Severity,
)
from app.models.synthetic_rules import CLOUD_IAM_ANOMALY_RULE_ID

log = structlog.get_logger()


# Reasons we tag onto alerts. Operators read these in the alert details
# blob; keep them stable across releases so saved searches keep working.
REASON_NEW_PRINCIPAL = "new_principal"
REASON_NEW_ACTION = "new_action_for_principal"
REASON_NEW_REGION = "new_region_for_principal"
REASON_ROOT_CONSOLE_LOGIN = "root_console_login"


def _action_key(event: dict[str, Any]) -> str:
    """``s3.amazonaws.com:GetObject`` — service:operation canonical form."""
    return f"{event.get('event_source', '')}:{event.get('event_name', '')}"


async def _ensure_synthetic_rule(db: AsyncSession) -> None:
    """Idempotently create the rule cloud-anomaly alerts attach to.
    Called lazily on first detection so a source that never fires
    doesn't pollute the rules list."""
    existing = await db.get(Rule, CLOUD_IAM_ANOMALY_RULE_ID)
    if existing is not None:
        return
    rule = Rule(
        id=CLOUD_IAM_ANOMALY_RULE_ID,
        name="Cloud: AWS IAM-role anomaly",
        kind=RuleKind.IOC,
        action=RuleAction.ALERT,
        severity=Severity.HIGH,
        enabled=True,
        description=(
            "Phase 4 #4.2 synthetic rule — fires when a CloudTrail event "
            "introduces a never-before-seen principal/action/region for a "
            "configured source, or whenever the AWS root user signs in."
        ),
    )
    db.add(rule)
    await db.flush()


async def _fire_alert(
    db: AsyncSession,
    *,
    tenant_id: UUID,
    source_id: UUID,
    event: dict[str, Any],
    reason: str,
    summary: str,
    extra: dict[str, Any] | None = None,
) -> None:
    await _ensure_synthetic_rule(db)
    details: dict[str, Any] = {
        "detector": "cloud_iam_anomaly_v1",
        "reason": reason,
        "source_id": str(source_id),
        "principal_arn": event.get("principal_arn"),
        "region": event.get("region"),
        "event_source": event.get("event_source"),
        "event_name": event.get("event_name"),
        "source_ip": event.get("source_ip"),
        "error_code": event.get("error_code"),
        "user_type": event.get("user_type"),
    }
    if extra:
        details.update(extra)
    alert = Alert(
        tenant_id=tenant_id,
        host_id=None,
        rule_id=CLOUD_IAM_ANOMALY_RULE_ID,
        severity=Severity.HIGH,
        action_taken=RuleAction.ALERT,
        state=AlertState.NEW,
        summary=summary[:512],
        details=details,
        mitre_techniques=["T1078.004"],
    )
    db.add(alert)
    log.info(
        "cloud_iam_anomaly.alert",
        reason=reason,
        source_id=str(source_id),
        principal=event.get("principal_arn"),
    )


async def _get_or_create_baseline(
    db: AsyncSession,
    *,
    tenant_id: UUID,
    source_id: UUID,
    principal_arn: str,
    ts: datetime | None,
) -> tuple[CloudBaseline, bool]:
    """Insert-on-conflict the baseline row. Returns ``(row, created)``
    where ``created`` is True iff this was the first observation."""
    stmt = (
        pg_insert(CloudBaseline)
        .values(
            tenant_id=tenant_id,
            source_id=source_id,
            principal_arn=principal_arn,
            observed_actions=[],
            observed_regions=[],
            first_seen=ts,
            last_seen=ts,
        )
        .on_conflict_do_nothing(
            constraint="uq_cloud_baseline_source_id_principal_arn",
        )
        .returning(CloudBaseline.id)
    )
    row = (await db.execute(stmt)).first()
    created = row is not None
    baseline = (
        await db.execute(
            select(CloudBaseline).where(
                CloudBaseline.source_id == source_id,
                CloudBaseline.principal_arn == principal_arn,
            )
        )
    ).scalar_one()
    return baseline, created


async def detect_new_principal(
    db: AsyncSession,
    *,
    tenant_id: UUID,
    source_id: UUID,
    event: dict[str, Any],
) -> bool:
    """Seed-or-bump the baseline for this principal.

    Returns True when the row was just created (first observation). The
    seed-only semantics here mean the action / region the principal
    arrived with is recorded as the founding entry, so the action /
    region detectors below don't double-fire on the same observation.
    A freshly-configured bucket would otherwise blow up the alert
    queue on the first poll with "everything is new".
    """
    arn = event.get("principal_arn") or ""
    if not arn:
        return False
    baseline, created = await _get_or_create_baseline(
        db,
        tenant_id=tenant_id,
        source_id=source_id,
        principal_arn=arn,
        ts=event.get("ts"),
    )
    if created:
        action = _action_key(event)
        region = event.get("region") or ""
        if action:
            baseline.observed_actions = [action]
        if region:
            baseline.observed_regions = [region]
        if event.get("ts") is not None:
            baseline.last_seen = event["ts"]
    return created


async def detect_new_action(
    db: AsyncSession,
    *,
    tenant_id: UUID,
    source_id: UUID,
    event: dict[str, Any],
) -> bool:
    """Fire if (principal, action) hasn't been observed before. Skips
    seeding entirely when the principal has no prior baseline — that's
    :func:`detect_new_principal`'s job — so this detector is safe to
    call after the principal seeder. Returns True iff an alert fired."""
    arn = event.get("principal_arn") or ""
    if not arn:
        return False
    action = _action_key(event)
    if not action:
        return False
    baseline = (
        await db.execute(
            select(CloudBaseline).where(
                CloudBaseline.source_id == source_id,
                CloudBaseline.principal_arn == arn,
            )
        )
    ).scalar_one_or_none()
    if baseline is None:
        return False
    actions = list(baseline.observed_actions or [])
    if action in actions:
        return False
    await _fire_alert(
        db,
        tenant_id=tenant_id,
        source_id=source_id,
        event=event,
        reason=REASON_NEW_ACTION,
        summary=f"IAM principal {arn} performed new action {action}",
        extra={"action": action, "prior_action_count": len(actions)},
    )
    actions.append(action)
    baseline.observed_actions = actions
    if event.get("ts") is not None:
        baseline.last_seen = event["ts"]
    return True


async def detect_new_region(
    db: AsyncSession,
    *,
    tenant_id: UUID,
    source_id: UUID,
    event: dict[str, Any],
) -> bool:
    """Fire if (principal, region) hasn't been observed before. Same
    "principal must already be baselined" semantics as
    :func:`detect_new_action`."""
    arn = event.get("principal_arn") or ""
    region = event.get("region") or ""
    if not arn or not region:
        return False
    baseline = (
        await db.execute(
            select(CloudBaseline).where(
                CloudBaseline.source_id == source_id,
                CloudBaseline.principal_arn == arn,
            )
        )
    ).scalar_one_or_none()
    if baseline is None:
        return False
    regions = list(baseline.observed_regions or [])
    if region in regions:
        return False
    await _fire_alert(
        db,
        tenant_id=tenant_id,
        source_id=source_id,
        event=event,
        reason=REASON_NEW_REGION,
        summary=f"IAM principal {arn} called from new region {region}",
        extra={"region": region, "prior_region_count": len(regions)},
    )
    regions.append(region)
    baseline.observed_regions = regions
    if event.get("ts") is not None:
        baseline.last_seen = event["ts"]
    return True


async def detect_root_console_login(
    db: AsyncSession,
    *,
    tenant_id: UUID,
    source_id: UUID,
    event: dict[str, Any],
) -> bool:
    """Fire whenever the AWS root user signs into the console. No
    baseline check — root console activity is a finding regardless of
    history."""
    if event.get("user_type") != "Root":
        return False
    if event.get("event_name") != "ConsoleLogin":
        return False
    await _fire_alert(
        db,
        tenant_id=tenant_id,
        source_id=source_id,
        event=event,
        reason=REASON_ROOT_CONSOLE_LOGIN,
        summary="AWS root user console login",
    )
    return True


__all__ = (
    "CLOUD_IAM_ANOMALY_RULE_ID",
    "REASON_NEW_ACTION",
    "REASON_NEW_PRINCIPAL",
    "REASON_NEW_REGION",
    "REASON_ROOT_CONSOLE_LOGIN",
    "detect_new_action",
    "detect_new_principal",
    "detect_new_region",
    "detect_root_console_login",
)
