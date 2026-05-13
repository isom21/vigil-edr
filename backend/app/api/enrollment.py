"""Enrollment: admin issues one-time tokens; agents POST CSR with token to receive a cert.

Per ADR 0002 the agent's full lifecycle is gRPC over mTLS; the Enroll RPC will live on
the same gRPC service in M2. The REST endpoint here is the dev-friendly equivalent and
is the path the agent will use during M1/M2 thin-slice work.
"""

from __future__ import annotations

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
    EnrollmentToken,
    Host,
    HostStatus,
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
from app.services.enrollment import (
    EnrollmentTokenInvalid,
    bind_token_to_host,
    consume_token,
    detect_reenrollment,
)

router = APIRouter(prefix="/api/enrollment", tags=["enrollment"])


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
    # Phase 3 #3.1: resolve the target tenant. Non-super-admins are
    # locked to their own tenant; super-admins may target any.
    target_tenant = payload.tenant_id or actor.tenant_id
    if target_tenant != actor.tenant_id and not actor.is_super_admin:
        raise bad_request("only super-admins can mint enrollment tokens for other tenants")
    plaintext = generate_enrollment_token()
    token = EnrollmentToken(
        tenant_id=target_tenant,
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
        payload={
            "label": payload.label,
            "ttl_hours": payload.ttl_hours,
            "tenant_id": str(target_tenant),
        },
        tenant_id=target_tenant,
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
    # Atomic UPDATE ... WHERE used_at IS NULL RETURNING — see
    # services/enrollment.py. Two concurrent enroll calls with the same
    # token cannot both pass this gate.
    try:
        token_id, token_tenant_id = await consume_token(db, payload.enrollment_token)
    except EnrollmentTokenInvalid as exc:
        raise bad_request("invalid or expired token") from exc
    now = datetime.now(UTC)

    host = Host(
        # Phase 3 #3.1: stamp the host with the tenant the
        # enrollment token came from. Agents themselves are
        # tenant-blind — the token is what binds them.
        tenant_id=token_tenant_id,
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

    # M12.e re-enrollment anomaly. Shared with the gRPC enroll path
    # so the signal fires regardless of which RPC the (attacker or
    # legitimate reimage) used.
    await detect_reenrollment(
        db,
        hostname=payload.hostname,
        os_family=payload.os_family,
        new_host_id=host.id,
        now=now,
        source="rest",
        source_ip=request.client.host if request.client else None,
    )

    ca = CaService(db)
    issued = await ca.sign_csr(
        payload.csr_pem.encode("utf-8"),
        host_id=str(host.id),
        hostname=payload.hostname,
    )
    host.cert_fingerprint = issued.fingerprint_sha256

    await bind_token_to_host(db, token_id, host.id)

    await audit.record(
        db,
        actor=None,
        action="host.enroll",
        resource_type="host",
        resource_id=str(host.id),
        payload={"hostname": payload.hostname, "os_family": payload.os_family.value},
        ip=request.client.host if request.client else None,
        tenant_id=token_tenant_id,
    )

    return EnrollResponse(
        host_id=host.id,
        client_cert_pem=issued.cert_pem,
        ca_chain_pem=issued.ca_chain_pem,
        cert_not_after=issued.not_after,
    )
