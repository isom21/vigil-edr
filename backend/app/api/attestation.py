"""TPM attestation endpoints (Phase 4 #4.10).

Three flows expose the underlying tables:

  * ``POST /api/hosts/:id/attestation/request`` — admin queues a fresh
    ``REQUEST_ATTESTATION`` command. Generates a random nonce that the
    agent must echo inside its TPM Quote so a replayed PCR set can't
    masquerade as fresh.
  * ``POST /api/hosts/:id/attestation/promote`` — admin records the
    host's latest event as the golden baseline. Re-promoting
    overwrites.
  * ``GET /api/hosts/:id/attestation/events`` — paginated history.

Reads (events + golden) are analyst+; mutations are admin-only. Every
mutation is audited.
"""

from __future__ import annotations

import secrets
from uuid import UUID

from fastapi import APIRouter, status
from sqlalchemy import func, select

from app.core.deps import DbSession, RequireAdmin, RequireAnalyst
from app.core.errors import bad_request, not_found
from app.models import (
    AttestationEvent,
    AttestationGolden,
    Command,
    CommandKind,
    CommandStatus,
    Host,
)
from app.schemas.attestation import (
    AttestationEventOut,
    AttestationGoldenOut,
    RequestAttestationResponse,
)
from app.schemas.common import Page
from app.services import audit
from app.services.scoping import host_visible_to

router = APIRouter(prefix="/api/hosts", tags=["attestation"])


def _new_nonce() -> str:
    """32 bytes of randomness, hex-encoded. The agent echoes this inside
    the TPM Quote so a replayed PCR set can't pass for a fresh quote."""
    return secrets.token_hex(32)


@router.post(
    "/{host_id}/attestation/request",
    response_model=RequestAttestationResponse,
    status_code=status.HTTP_201_CREATED,
)
async def request_attestation(
    host_id: UUID, db: DbSession, actor: RequireAdmin
) -> RequestAttestationResponse:
    host = await db.get(Host, host_id)
    if host is None or not await host_visible_to(actor, host_id, db):
        raise not_found("host", str(host_id))

    nonce = _new_nonce()
    cmd = Command(
        tenant_id=host.tenant_id,
        host_id=host.id,
        kind=CommandKind.REQUEST_ATTESTATION,
        status=CommandStatus.PENDING,
        payload={"nonce": nonce},
        issued_by_user_id=actor.user.id,
    )
    db.add(cmd)
    await db.flush()

    await audit.record(
        db,
        actor=actor,
        action="attestation.request",
        resource_type="host",
        resource_id=str(host.id),
        payload={"command_id": str(cmd.id), "nonce_prefix": nonce[:16]},
        tenant_id=host.tenant_id,
    )
    return RequestAttestationResponse(command_id=cmd.id, nonce=nonce)


@router.post(
    "/{host_id}/attestation/promote",
    response_model=AttestationGoldenOut,
    status_code=status.HTTP_201_CREATED,
)
async def promote_attestation(
    host_id: UUID, db: DbSession, actor: RequireAdmin
) -> AttestationGoldenOut:
    host = await db.get(Host, host_id)
    if host is None or not await host_visible_to(actor, host_id, db):
        raise not_found("host", str(host_id))

    latest_stmt = (
        select(AttestationEvent)
        .where(AttestationEvent.host_id == host.id)
        .order_by(AttestationEvent.recorded_at.desc())
        .limit(1)
    )
    latest = (await db.execute(latest_stmt)).scalar_one_or_none()
    if latest is None:
        raise bad_request("no attestation events recorded for host yet")

    golden = await db.get(AttestationGolden, host.id)
    if golden is None:
        golden = AttestationGolden(
            host_id=host.id,
            tenant_id=host.tenant_id,
            pcr_values_json=list(latest.pcr_values_json or []),
            recorded_by_user_id=actor.user.id,
        )
        db.add(golden)
    else:
        golden.pcr_values_json = list(latest.pcr_values_json or [])
        golden.tenant_id = host.tenant_id
        golden.recorded_by_user_id = actor.user.id
    await db.flush()

    await audit.record(
        db,
        actor=actor,
        action="attestation.promote",
        resource_type="host",
        resource_id=str(host.id),
        payload={"pcr_count": len(golden.pcr_values_json or [])},
        tenant_id=host.tenant_id,
    )
    return AttestationGoldenOut.model_validate(golden)


@router.get(
    "/{host_id}/attestation/events",
    response_model=Page[AttestationEventOut],
)
async def list_events(
    host_id: UUID,
    db: DbSession,
    actor: RequireAnalyst,
    limit: int = 50,
    offset: int = 0,
) -> Page[AttestationEventOut]:
    if limit <= 0 or limit > 200:
        raise bad_request("limit must be in (0, 200]")
    host = await db.get(Host, host_id)
    if host is None or not await host_visible_to(actor, host_id, db):
        raise not_found("host", str(host_id))

    count_stmt = select(func.count(AttestationEvent.id)).where(AttestationEvent.host_id == host_id)
    rows_stmt = (
        select(AttestationEvent)
        .where(AttestationEvent.host_id == host_id)
        .order_by(AttestationEvent.recorded_at.desc())
        .limit(limit)
        .offset(offset)
    )
    total = (await db.execute(count_stmt)).scalar_one()
    rows = (await db.execute(rows_stmt)).scalars().all()
    return Page(
        items=[AttestationEventOut.model_validate(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )
