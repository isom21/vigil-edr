"""Rollout cohort dashboard + advance action (Phase 3 #3.3).

  * ``GET  /api/rollouts`` — one summary row per policy: target
    version, rolled-out percentage, per-cohort counts, the last few
    events.
  * ``POST /api/rollouts/{policy_id}/advance`` — admin only. Body
    ``{"to_pct": <int>}``. Recorded in the audit log.

Reads are analyst-OK; the only mutation is the advance, which is
admin-gated and audited.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter
from sqlalchemy import select

from app.core.deps import DbSession, RequireAdmin, RequireAnalyst
from app.core.errors import not_found
from app.models import Policy, RolloutEvent, RolloutStatus
from app.schemas.rollout import (
    CohortCounts,
    PolicyRolloutOut,
    RolloutAdvanceIn,
    RolloutEventOut,
)
from app.services import audit
from app.services.rollout import CANARY, EARLY, MAINLINE

router = APIRouter(prefix="/api/rollouts", tags=["rollouts"])


# Cohort labels we always surface in the response, even when there
# are no events for that label yet — the UI renders three columns
# regardless of whether anything has landed yet.
_COHORT_LABELS = (CANARY, EARLY, MAINLINE)
_RECENT_LIMIT = 25


async def _summarize_policy(db, policy: Policy) -> PolicyRolloutOut:
    # Pre-seed the three canonical labels so an empty rollout still
    # renders the standard three-column layout in the dashboard.
    counts: dict[str, CohortCounts] = {
        label: CohortCounts(cohort=label) for label in _COHORT_LABELS
    }
    rows = (
        (
            await db.execute(
                select(RolloutEvent)
                .where(RolloutEvent.policy_id == policy.id)
                .order_by(RolloutEvent.started_at.desc())
            )
        )
        .scalars()
        .all()
    )
    for event in rows:
        bucket = counts.setdefault(event.cohort, CohortCounts(cohort=event.cohort))
        if event.status == RolloutStatus.SUCCESS.value:
            bucket.success += 1
        elif event.status == RolloutStatus.FAILED.value:
            bucket.failed += 1
        elif event.status in (
            RolloutStatus.PENDING.value,
            RolloutStatus.IN_FLIGHT.value,
        ):
            bucket.in_flight += 1

    return PolicyRolloutOut(
        policy_id=policy.id,
        policy_name=policy.name,
        rollout_cohort=policy.rollout_cohort,
        cohort_target_version=policy.cohort_target_version,
        cohort_rolled_out_pct=int(policy.cohort_rolled_out_pct or 0),
        cohorts=list(counts.values()),
        recent=[RolloutEventOut.model_validate(e) for e in rows[:_RECENT_LIMIT]],
    )


@router.get("", response_model=list[PolicyRolloutOut])
async def list_rollouts(db: DbSession, actor: RequireAnalyst) -> list[PolicyRolloutOut]:
    """Per-policy rollout summary. One row per Policy regardless of
    whether the policy has anything outstanding — the UI can grey
    out the inactive ones without a second round trip."""
    policies = (await db.execute(select(Policy).order_by(Policy.name))).scalars().all()
    out: list[PolicyRolloutOut] = []
    for p in policies:
        out.append(await _summarize_policy(db, p))
    return out


@router.post("/{policy_id}/advance", response_model=PolicyRolloutOut)
async def advance_rollout(
    policy_id: UUID,
    payload: RolloutAdvanceIn,
    db: DbSession,
    actor: RequireAdmin,
) -> PolicyRolloutOut:
    policy = await db.get(Policy, policy_id)
    if policy is None:
        raise not_found("policy", str(policy_id))
    from_pct = int(policy.cohort_rolled_out_pct or 0)
    policy.cohort_rolled_out_pct = int(payload.to_pct)
    await db.flush()
    await audit.record(
        db,
        actor=actor,
        action="rollout.advance",
        resource_type="policy",
        resource_id=str(policy.id),
        payload={"to_pct": int(payload.to_pct), "from_pct": from_pct},
    )
    await db.commit()
    return await _summarize_policy(db, policy)
