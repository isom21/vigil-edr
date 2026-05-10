"""Enrollment: admin issues one-time tokens; agents POST CSR with token to receive a cert.

Per ADR 0002 the agent's full lifecycle is gRPC over mTLS; the Enroll RPC will live on
the same gRPC service in M2. The REST endpoint here is the dev-friendly equivalent and
is the path the agent will use during M1/M2 thin-slice work.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Request, status
from sqlalchemy import select

from app.core.deps import DbSession, RequireAdmin
from app.core.errors import bad_request, not_found
from app.core.security import (
    generate_enrollment_token,
    hash_enrollment_token,
)
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
from app.schemas.enrollment import (
    EnrollmentTokenCreate,
    EnrollmentTokenCreated,
    EnrollmentTokenOut,
    EnrollRequest,
    EnrollResponse,
)
from app.services import audit
from app.services.ca import CaService

router = APIRouter(prefix="/api/enrollment", tags=["enrollment"])


# M12.e: synthetic rule id for re-enrollment anomaly alerts. Stable
# across restarts so all such alerts attach to one row in the alerts
# UI.
REENROLLMENT_RULE_ID = UUID("a0a0a0a0-0000-0000-0000-000000000005")


async def _ensure_reenrollment_rule(db) -> None:
    existing = await db.get(Rule, REENROLLMENT_RULE_ID)
    if existing is not None:
        return
    rule = Rule(
        id=REENROLLMENT_RULE_ID,
        name="M12 self-protection: agent re-enrollment anomaly",
        kind=RuleKind.IOC,
        action=RuleAction.DETECT,
        severity=Severity.HIGH,
        enabled=True,
        description="Synthetic rule — fires when a host with the same "
        "hostname re-enrolls within a short window. Detects "
        "compromise-then-reset workflows where an attacker wipes the "
        "agent's identity dir to re-issue itself a fresh certificate.",
    )
    db.add(rule)
    await db.flush()


@router.get("/tokens", response_model=list[EnrollmentTokenOut])
async def list_tokens(db: DbSession, actor: RequireAdmin) -> list[EnrollmentTokenOut]:
    rows = (
        (
            await db.execute(
                select(EnrollmentToken).order_by(EnrollmentToken.created_at.desc()).limit(200)
            )
        )
        .scalars()
        .all()
    )
    return [EnrollmentTokenOut.model_validate(t) for t in rows]


@router.post("/tokens", response_model=EnrollmentTokenCreated, status_code=status.HTTP_201_CREATED)
async def create_token(
    payload: EnrollmentTokenCreate, db: DbSession, actor: RequireAdmin
) -> EnrollmentTokenCreated:
    plaintext = generate_enrollment_token()
    token = EnrollmentToken(
        token_hash=hash_enrollment_token(plaintext),
        label=payload.label,
        expires_at=datetime.now(UTC) + timedelta(hours=payload.ttl_hours),
        created_by=actor.user.id,
    )
    db.add(token)
    await db.flush()
    await audit.record(
        db,
        actor=actor,
        action="enrollment_token.create",
        resource_type="enrollment_token",
        resource_id=str(token.id),
        payload={"label": payload.label, "ttl_hours": payload.ttl_hours},
    )
    out = EnrollmentTokenOut.model_validate(token)
    return EnrollmentTokenCreated(**out.model_dump(), token=plaintext)


@router.delete("/tokens/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_token(token_id: UUID, db: DbSession, actor: RequireAdmin) -> None:
    token = await db.get(EnrollmentToken, token_id)
    if token is None:
        raise not_found("enrollment_token", str(token_id))
    await db.delete(token)
    await audit.record(
        db,
        actor=actor,
        action="enrollment_token.revoke",
        resource_type="enrollment_token",
        resource_id=str(token_id),
    )


@router.post("/enroll", response_model=EnrollResponse)
async def enroll(payload: EnrollRequest, request: Request, db: DbSession) -> EnrollResponse:
    """Public endpoint: agent presents one-time token + CSR, gets back a signed client cert.

    Anonymous TLS — no client cert required (the agent doesn't have one yet).
    """
    th = hash_enrollment_token(payload.enrollment_token)
    token = (
        await db.execute(select(EnrollmentToken).where(EnrollmentToken.token_hash == th))
    ).scalar_one_or_none()
    if token is None:
        raise bad_request("invalid enrollment token")
    now = datetime.now(UTC)
    if token.used_at is not None:
        raise bad_request("token already used")
    if token.expires_at < now:
        raise bad_request("token expired")

    # M12.e: detect re-enrollment under an existing hostname within
    # a short window — that's the signature of an attacker who wiped
    # the agent's identity dir to coax a fresh enrollment, or a
    # legitimate-but-noisy reimage that the SOC may want to triage.
    # We never reject the enrollment (legitimate workflows need it
    # to succeed), but we attach an Alert so the recent-enrollment
    # gets flagged for human review.
    reenrollment_window_seconds = int(
        os.environ.get("EDR_REENROLLMENT_WINDOW_SECONDS", 3600)
    )
    reenrollment_cutoff = now - timedelta(seconds=reenrollment_window_seconds)
    prior_host = (
        await db.execute(
            select(Host)
            .where(
                Host.hostname == payload.hostname,
                Host.enrolled_at.isnot(None),
                Host.enrolled_at >= reenrollment_cutoff,
                Host.status != HostStatus.DECOMMISSIONED,
            )
            .order_by(Host.enrolled_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    host = Host(
        hostname=payload.hostname,
        os_family=payload.os_family,
        os_version=payload.os_version,
        os_platform=payload.os_platform,
        os_arch=payload.os_arch,
        agent_version=payload.agent_version,
        status=HostStatus.PENDING,
        enrolled_at=now,
    )
    db.add(host)
    await db.flush()  # need host.id for the CSR subject CN

    if prior_host is not None and prior_host.id != host.id:
        await _ensure_reenrollment_rule(db)
        prior_age_seconds = int((now - prior_host.enrolled_at).total_seconds())
        same_os = prior_host.os_family == payload.os_family
        alert = Alert(
            host_id=host.id,
            rule_id=REENROLLMENT_RULE_ID,
            severity=Severity.HIGH,
            action_taken=RuleAction.DETECT,
            state=AlertState.NEW,
            summary=(
                f"Re-enrollment of '{payload.hostname}' "
                f"({prior_age_seconds}s after prior enrollment)"
            ),
            details={
                "hostname": payload.hostname,
                "new_host_id": str(host.id),
                "prior_host_id": str(prior_host.id),
                "prior_enrolled_at": prior_host.enrolled_at.isoformat(),
                "prior_age_seconds": prior_age_seconds,
                "same_os_family": same_os,
                "window_seconds": reenrollment_window_seconds,
                "ip": request.client.host if request.client else None,
                "detector": "reenrollment_v1",
            },
        )
        db.add(alert)

    ca = CaService(db)
    issued = await ca.sign_csr(
        payload.csr_pem.encode("utf-8"),
        host_id=str(host.id),
        hostname=payload.hostname,
    )
    host.cert_fingerprint = issued.fingerprint_sha256

    token.used_at = now
    token.used_by_host_id = host.id

    await audit.record(
        db,
        actor=None,
        action="host.enroll",
        resource_type="host",
        resource_id=str(host.id),
        payload={"hostname": payload.hostname, "os_family": payload.os_family.value},
        ip=request.client.host if request.client else None,
    )

    return EnrollResponse(
        host_id=host.id,
        client_cert_pem=issued.cert_pem,
        ca_chain_pem=issued.ca_chain_pem,
        cert_not_after=issued.not_after,
    )
