"""Rollout monitor worker (Phase 3 #3.3).

Watches ``rollout_event`` rows for failure spikes. When a single
cohort within a policy accumulates ``VIGIL_ROLLOUT_FAILURE_THRESHOLD``
failures within ``VIGIL_ROLLOUT_FAILURE_WINDOW_S``, the worker:

  1. Sets ``policy.cohort_rolled_out_pct = 0`` to halt further
     dispatch of ``JobKind.UPDATE`` to the policy's hosts.
  2. Emits a critical Alert via the existing synthetic-alert path
     (NULL host_id; visible to admins on the dashboard / SSE
     stream).

Step (1) doesn't retract any in-flight updates — the breaker only
prevents new ones. Operators investigate via the rollout dashboard
and either advance back to a non-zero percentage or fix the
underlying issue and retry.

Lifecycle template copied from ``app.workers.intel_ingest``.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from datetime import UTC, datetime, timedelta
from uuid import UUID

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import SessionLocal
from app.models import (
    Alert,
    AlertState,
    Policy,
    RolloutEvent,
    RolloutStatus,
    Rule,
    RuleAction,
    RuleKind,
    Severity,
)

SessionMaker = Callable[[], AbstractAsyncContextManager[AsyncSession]]

log = structlog.get_logger()

# Stable synthetic Rule id for "rollout breaker tripped" alerts. The
# row is materialised on first trip the same way the audit verifier
# manages its rule; analysts can rename it but should not delete it.
ROLLOUT_BREAKER_RULE_ID = UUID("e3c4d5e6-f7a8-0000-0000-000000000001")

__all__ = (
    "run_forever",
    "_run_once",
    "_trip_if_failing",
    "_interval_seconds",
    "ROLLOUT_BREAKER_RULE_ID",
)


def _interval_seconds() -> int:
    raw = os.environ.get(
        "VIGIL_ROLLOUT_MONITOR_INTERVAL_S",
        str(settings.rollout_monitor_interval_s),
    )
    try:
        return max(5, int(raw))
    except ValueError:
        return settings.rollout_monitor_interval_s


def _failure_threshold() -> int:
    raw = os.environ.get(
        "VIGIL_ROLLOUT_FAILURE_THRESHOLD",
        str(settings.rollout_failure_threshold),
    )
    try:
        return max(1, int(raw))
    except ValueError:
        return settings.rollout_failure_threshold


def _failure_window_s() -> int:
    raw = os.environ.get(
        "VIGIL_ROLLOUT_FAILURE_WINDOW_S",
        str(settings.rollout_failure_window_s),
    )
    try:
        return max(10, int(raw))
    except ValueError:
        return settings.rollout_failure_window_s


async def _ensure_breaker_rule(db: AsyncSession) -> Rule:
    """Lazy-create the synthetic Rule the breaker alert points at.

    Same shape as the audit-verifier rule: an admin-visible IOC rule
    whose only purpose is to be the rule_id on the synthetic alert.
    """
    rule = await db.get(Rule, ROLLOUT_BREAKER_RULE_ID)
    if rule is not None:
        return rule
    rule = Rule(
        id=ROLLOUT_BREAKER_RULE_ID,
        kind=RuleKind.IOC,
        name="Phase 3 #3.3: rollout breaker tripped",
        action=RuleAction.ALERT,
        severity=Severity.CRITICAL,
        enabled=True,
        description=(
            "Synthetic rule — fires when the rollout monitor sees the "
            "failure threshold exceeded within the configured window "
            "for a cohort. The policy's `cohort_rolled_out_pct` is "
            "reset to 0 at the same time. Investigate via the rollout "
            "dashboard before advancing again."
        ),
    )
    db.add(rule)
    await db.flush()
    return rule


async def _emit_alert(
    db: AsyncSession,
    *,
    policy: Policy,
    cohort: str,
    failure_count: int,
    window_s: int,
) -> None:
    await _ensure_breaker_rule(db)
    db.add(
        Alert(
            host_id=None,
            rule_id=ROLLOUT_BREAKER_RULE_ID,
            severity=Severity.CRITICAL,
            action_taken=RuleAction.ALERT,
            state=AlertState.NEW,
            summary=(
                f"Rollout halted for policy '{policy.name}' "
                f"(cohort {cohort}, {failure_count} failures in {window_s}s)"
            ),
            details={
                "policy_id": str(policy.id),
                "policy_name": policy.name,
                "cohort": cohort,
                "failure_count": failure_count,
                "window_s": window_s,
                "target_version": policy.cohort_target_version,
                "detector": "rollout_monitor_v1",
            },
        )
    )


async def _trip_if_failing(
    db: AsyncSession,
    policy: Policy,
    *,
    threshold: int,
    window_s: int,
    now: datetime,
) -> bool:
    """If any cohort under ``policy`` exceeds the failure threshold in
    the trailing window, slam the policy's percentage to 0 and emit a
    critical alert. Returns True when the breaker was tripped.

    Already-zero policies are skipped — there's nothing left to halt
    and re-emitting the alert each tick would spam the inbox.
    """
    if int(policy.cohort_rolled_out_pct or 0) == 0:
        return False
    cutoff = now - timedelta(seconds=window_s)
    rows = (
        await db.execute(
            select(RolloutEvent.cohort, func.count(RolloutEvent.id))
            .where(
                RolloutEvent.policy_id == policy.id,
                RolloutEvent.status == RolloutStatus.FAILED.value,
                RolloutEvent.started_at >= cutoff,
            )
            .group_by(RolloutEvent.cohort)
        )
    ).all()
    tripping_cohort: str | None = None
    tripping_count = 0
    for cohort, count in rows:
        if count >= threshold and count > tripping_count:
            tripping_cohort = cohort
            tripping_count = int(count)
    if tripping_cohort is None:
        return False
    log.warning(
        "rollout_monitor.breaker.trip",
        policy_id=str(policy.id),
        policy_name=policy.name,
        cohort=tripping_cohort,
        failure_count=tripping_count,
        window_s=window_s,
    )
    policy.cohort_rolled_out_pct = 0
    await _emit_alert(
        db,
        policy=policy,
        cohort=tripping_cohort,
        failure_count=tripping_count,
        window_s=window_s,
    )
    return True


async def _run_once(session_maker: SessionMaker | None = None) -> int:
    """One pass. Returns the number of policies tripped this pass."""
    sm: SessionMaker = session_maker if session_maker is not None else SessionLocal
    threshold = _failure_threshold()
    window_s = _failure_window_s()
    tripped = 0
    async with sm() as db:
        policies = (
            (await db.execute(select(Policy).where(Policy.cohort_rolled_out_pct > 0)))
            .scalars()
            .all()
        )
        now = datetime.now(UTC)
        for policy in policies:
            if await _trip_if_failing(db, policy, threshold=threshold, window_s=window_s, now=now):
                tripped += 1
        if tripped:
            await db.commit()
    return tripped


async def run_forever() -> None:
    """Main loop. Wrapped in lifespan as a background task."""
    interval = _interval_seconds()
    log.info("rollout_monitor.loop.starting", interval_s=interval)
    while True:
        try:
            await _run_once()
        except asyncio.CancelledError:
            log.info("rollout_monitor.loop.cancelled")
            raise
        except Exception:  # pragma: no cover — never let the loop die
            log.exception("rollout_monitor.loop.iteration_failed")
        try:
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            log.info("rollout_monitor.loop.cancelled")
            raise
