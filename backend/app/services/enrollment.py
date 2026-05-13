"""Shared enrollment helpers — REST and gRPC paths both call these so
they can't drift on token semantics or on which side runs the M12.e
re-enrollment anomaly detector.

`consume_token` collapses the check-then-write into a single
`UPDATE ... WHERE used_at IS NULL AND expires_at > now() RETURNING ...`
under READ COMMITTED. PG resolves concurrent writers row-by-row; the
loser's WHERE filters out the row already written and RETURNING comes
back empty.

`detect_reenrollment` flags hosts enrolling under an existing hostname
within `VIGIL_REENROLLMENT_WINDOW_SECONDS`. Originally REST-only — the
gRPC enroll path had to skip the detector entirely because the helper
lived in `api/enrollment.py`. That was the M12 self-protection blind
spot the reviewer flagged.

The caller is responsible for setting `used_by_host_id` once the host
row exists (it doesn't at consume time).
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_enrollment_token
from app.models import (
    Alert,
    AlertState,
    EnrollmentToken,
    Host,
    HostStatus,
    Rule,
    RuleAction,
    RuleKind,
    Severity,
)
from app.models.synthetic_rules import REENROLLMENT_RULE_ID

# Re-export for callers that imported the constant from this module
# (REST enrollment + the existing race tests). LOW #8 moved the
# canonical value to `app.models.synthetic_rules`; the alias here
# keeps the call sites unchanged.
__all__ = (
    "EnrollmentTokenInvalid",
    "REENROLLMENT_RULE_ID",
    "bind_token_to_host",
    "consume_token",
    "detect_reenrollment",
)


class EnrollmentTokenInvalid(Exception):  # noqa: N818 — read aloud as "token-invalid", not "error"
    """Token unknown, already used, or expired.

    REST and gRPC translate this to their transport's invalid-token
    status. The single exception type keeps the two callers symmetric.
    """


async def consume_token(db: AsyncSession, raw_token: str) -> tuple[UUID, UUID]:
    """Atomically mark the token as used. Returns ``(token_id, tenant_id)``.

    Raises ``EnrollmentTokenInvalid`` if the token is unknown,
    already consumed, or past its expiry. Idempotent under retry —
    a second call with the same plaintext after a successful
    consume will raise just like a stolen-then-reused token would.

    Phase 3 #3.1: the consumed token's ``tenant_id`` comes back in
    the returning tuple so the caller can stamp it onto the new
    ``Host`` row without an extra round-trip.
    """
    th = hash_enrollment_token(raw_token)
    now = datetime.now(UTC)
    stmt = (
        update(EnrollmentToken)
        .where(
            EnrollmentToken.token_hash == th,
            EnrollmentToken.used_at.is_(None),
            EnrollmentToken.expires_at > now,
        )
        .values(used_at=now)
        .returning(EnrollmentToken.id, EnrollmentToken.tenant_id)
    )
    row = (await db.execute(stmt)).first()
    if row is None:
        raise EnrollmentTokenInvalid
    return row.id, row.tenant_id


async def bind_token_to_host(db: AsyncSession, token_id: UUID, host_id: UUID) -> None:
    """Stamp the consumed token with the host it enrolled.

    Separated from `consume_token` because the host row doesn't exist
    yet at consume time. Called once the host insert has flushed.
    """
    await db.execute(
        update(EnrollmentToken)
        .where(EnrollmentToken.id == token_id)
        .values(used_by_host_id=host_id)
    )


async def _ensure_reenrollment_rule(db: AsyncSession) -> None:
    """Idempotently create the synthetic Rule that re-enrollment alerts
    attach to. Both REST and gRPC enroll paths call this so they end
    up writing alerts under the same rule_id."""
    existing = await db.get(Rule, REENROLLMENT_RULE_ID)
    if existing is not None:
        return
    rule = Rule(
        id=REENROLLMENT_RULE_ID,
        name="M12 self-protection: agent re-enrollment anomaly",
        kind=RuleKind.IOC,
        action=RuleAction.ALERT,
        severity=Severity.HIGH,
        enabled=True,
        description=(
            "Synthetic rule — fires when a host with the same hostname "
            "re-enrolls within a short window. Detects compromise-then-"
            "reset workflows where an attacker wipes the agent's "
            "identity dir to re-issue itself a fresh certificate."
        ),
    )
    db.add(rule)
    await db.flush()


async def detect_reenrollment(
    db: AsyncSession,
    *,
    hostname: str,
    os_family: str | object,
    new_host_id: UUID,
    now: datetime,
    source: str,
    source_ip: str | None,
) -> None:
    """Attach an M12.e re-enrollment alert if a non-decommissioned host
    with the same hostname enrolled inside the configured window.

    ``source`` is the enrollment path ("rest" or "grpc") and lands in
    the alert payload so SOC analysts can tell which RPC fired the
    detector. The detector itself doesn't reject the enrollment —
    legitimate reimages need to succeed — it just attaches a HIGH
    alert for triage.

    Caller already has the new ``Host`` row flushed (so ``new_host_id``
    is real) and is mid-transaction; this writes the Alert row to the
    same session.
    """
    window_seconds = int(os.environ.get("VIGIL_REENROLLMENT_WINDOW_SECONDS", 3600))
    cutoff = now - timedelta(seconds=window_seconds)
    prior = (
        await db.execute(
            select(Host)
            .where(
                Host.hostname == hostname,
                Host.id != new_host_id,
                Host.enrolled_at.isnot(None),
                Host.enrolled_at >= cutoff,
                Host.status != HostStatus.DECOMMISSIONED,
            )
            .order_by(Host.enrolled_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if prior is None or prior.enrolled_at is None:
        return

    await _ensure_reenrollment_rule(db)
    prior_age_seconds = int((now - prior.enrolled_at).total_seconds())
    same_os = prior.os_family == os_family
    alert = Alert(
        host_id=new_host_id,
        rule_id=REENROLLMENT_RULE_ID,
        severity=Severity.HIGH,
        action_taken=RuleAction.ALERT,
        state=AlertState.NEW,
        summary=(f"Re-enrollment of '{hostname}' ({prior_age_seconds}s after prior enrollment)"),
        details={
            "hostname": hostname,
            "new_host_id": str(new_host_id),
            "prior_host_id": str(prior.id),
            "prior_enrolled_at": prior.enrolled_at.isoformat(),
            "prior_age_seconds": prior_age_seconds,
            "same_os_family": same_os,
            "window_seconds": window_seconds,
            "source": source,
            "ip": source_ip,
            "detector": "reenrollment_v1",
        },
    )
    db.add(alert)
