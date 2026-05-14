"""Detonation provider CRUD + manual submission + job listing (Phase 4 #4.4).

Two surfaces:

  * ``/api/detonation/providers`` — admin CRUD. Same shape as
    case_destinations: TEXT + CHECK on the kind column, Fernet-
    encrypted config blob that never round-trips through the API.
  * ``/api/detonation/jobs`` — analyst-readable list of recent jobs.
  * ``POST /api/detonation/submit`` — admin-only manual submission;
    body ``{sha256, provider_id?}``. The hash drives the submitter,
    which materialises a ``DetonationJob`` row in ``queued`` state.

Every mutation is audited; the audit payload elides the plaintext
config the same way case_destinations does.
"""

from __future__ import annotations

import base64
import binascii
from uuid import UUID

from fastapi import APIRouter, status
from sqlalchemy import desc, func, select

from app.core.deps import DbSession, RequireAdmin, RequireAnalyst
from app.core.errors import bad_request, conflict, not_found
from app.models import DetonationJob, DetonationProvider, DetonationProviderKind
from app.schemas.common import Page
from app.schemas.detonation import (
    DetonationJobOut,
    DetonationProviderCreate,
    DetonationProviderOut,
    DetonationProviderUpdate,
    DetonationSubmitRequest,
)
from app.services import audit
from app.services.detonation.submitter import submit_for_analysis
from app.services.encryption import encrypt_config

router = APIRouter(prefix="/api/detonation", tags=["detonation"])


def _kind_required_fields(kind: DetonationProviderKind) -> tuple[str, ...]:
    """Per-kind required-config keys. Mirrors the per-client expectation
    so the operator gets a 400 at registration instead of a 500 on the
    first submit."""
    if kind is DetonationProviderKind.CUCKOO:
        return ("base_url",)
    # VMRay + ANY.RUN are stubbed; the operator can pre-stage their
    # config but submits will still raise NotImplementedError. No
    # required fields enforced.
    return ()


def _check_required(kind: DetonationProviderKind, config: dict) -> None:
    missing = [k for k in _kind_required_fields(kind) if not config.get(k)]
    if missing:
        raise bad_request(f"missing required config fields for {kind.value}: {','.join(missing)}")


def _to_provider_out(provider: DetonationProvider) -> DetonationProviderOut:
    return DetonationProviderOut(
        id=provider.id,
        kind=DetonationProviderKind.coerce(provider.kind),
        name=provider.name,
        enabled=provider.enabled,
        created_at=provider.created_at,
        updated_at=provider.updated_at,
    )


# ---------- providers ----------


@router.get("/providers", response_model=list[DetonationProviderOut])
async def list_providers(db: DbSession, actor: RequireAdmin) -> list[DetonationProviderOut]:
    rows = (
        (
            await db.execute(
                select(DetonationProvider)
                .where(DetonationProvider.tenant_id == actor.tenant_id)
                .order_by(DetonationProvider.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return [_to_provider_out(p) for p in rows]


@router.post(
    "/providers",
    response_model=DetonationProviderOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_provider(
    payload: DetonationProviderCreate, db: DbSession, actor: RequireAdmin
) -> DetonationProviderOut:
    clash = (
        await db.execute(
            select(DetonationProvider.id).where(
                DetonationProvider.tenant_id == actor.tenant_id,
                DetonationProvider.name == payload.name,
            )
        )
    ).scalar_one_or_none()
    if clash is not None:
        raise conflict("detonation provider name already in use")

    _check_required(payload.kind, payload.config)

    provider = DetonationProvider(
        tenant_id=actor.tenant_id,
        kind=payload.kind.value,
        name=payload.name,
        config_encrypted=encrypt_config(payload.config),
        enabled=payload.enabled,
    )
    db.add(provider)
    await db.flush()

    await audit.record(
        db,
        actor=actor,
        action="detonation_provider.create",
        resource_type="detonation_provider",
        resource_id=str(provider.id),
        payload={
            "name": payload.name,
            "kind": payload.kind.value,
            "enabled": payload.enabled,
        },
    )
    return _to_provider_out(provider)


@router.patch("/providers/{provider_id}", response_model=DetonationProviderOut)
async def update_provider(
    provider_id: UUID,
    payload: DetonationProviderUpdate,
    db: DbSession,
    actor: RequireAdmin,
) -> DetonationProviderOut:
    provider = await db.get(DetonationProvider, provider_id)
    if provider is None or provider.tenant_id != actor.tenant_id:
        raise not_found("detonation_provider", str(provider_id))

    audit_payload: dict = {}
    if payload.name is not None and payload.name != provider.name:
        clash = (
            await db.execute(
                select(DetonationProvider.id).where(
                    DetonationProvider.tenant_id == actor.tenant_id,
                    DetonationProvider.name == payload.name,
                    DetonationProvider.id != provider_id,
                )
            )
        ).scalar_one_or_none()
        if clash is not None:
            raise conflict("detonation provider name already in use")
        provider.name = payload.name
        audit_payload["name"] = payload.name
    if payload.enabled is not None:
        provider.enabled = payload.enabled
        audit_payload["enabled"] = payload.enabled
    if payload.config is not None:
        _check_required(DetonationProviderKind.coerce(provider.kind), payload.config)
        provider.config_encrypted = encrypt_config(payload.config)
        audit_payload["config_rotated"] = True

    await audit.record(
        db,
        actor=actor,
        action="detonation_provider.update",
        resource_type="detonation_provider",
        resource_id=str(provider.id),
        payload=audit_payload,
    )
    return _to_provider_out(provider)


@router.delete("/providers/{provider_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_provider(provider_id: UUID, db: DbSession, actor: RequireAdmin) -> None:
    provider = await db.get(DetonationProvider, provider_id)
    if provider is None or provider.tenant_id != actor.tenant_id:
        raise not_found("detonation_provider", str(provider_id))
    name = provider.name
    kind_val = DetonationProviderKind.coerce(provider.kind).value
    await db.delete(provider)
    await audit.record(
        db,
        actor=actor,
        action="detonation_provider.delete",
        resource_type="detonation_provider",
        resource_id=str(provider_id),
        payload={"name": name, "kind": kind_val},
    )


# ---------- jobs ----------


@router.get("/jobs", response_model=Page[DetonationJobOut])
async def list_jobs(
    db: DbSession,
    actor: RequireAnalyst,
    sha256: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> Page[DetonationJobOut]:
    stmt = select(DetonationJob).where(DetonationJob.tenant_id == actor.tenant_id)
    count_stmt = select(func.count(DetonationJob.id)).where(
        DetonationJob.tenant_id == actor.tenant_id
    )
    if sha256:
        normalised = sha256.lower().strip()
        stmt = stmt.where(DetonationJob.sha256 == normalised)
        count_stmt = count_stmt.where(DetonationJob.sha256 == normalised)
    stmt = stmt.order_by(desc(DetonationJob.submitted_at)).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).scalars().all()
    total = (await db.execute(count_stmt)).scalar_one()
    return Page(
        items=[DetonationJobOut.model_validate(r) for r in rows],
        total=int(total),
        limit=limit,
        offset=offset,
    )


@router.post("/submit", response_model=DetonationJobOut, status_code=status.HTTP_201_CREATED)
async def submit_for_detonation(
    payload: DetonationSubmitRequest,
    db: DbSession,
    actor: RequireAdmin,
) -> DetonationJobOut:
    sample_bytes: bytes | None = None
    if payload.sample_b64:
        try:
            sample_bytes = base64.b64decode(payload.sample_b64, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise bad_request(f"sample_b64 is not valid base64: {exc}") from exc

    try:
        job = await submit_for_analysis(
            db,
            sha256=payload.sha256,
            tenant_id=actor.tenant_id,
            provider_id=payload.provider_id,
            sample_bytes=sample_bytes,
        )
    except RuntimeError as exc:
        # "no detonation provider available" → 400 so the operator
        # sees the missing-provider state explicitly.
        raise bad_request(str(exc)) from exc

    await audit.record(
        db,
        actor=actor,
        action="detonation.submit",
        resource_type="detonation_job",
        resource_id=str(job.id),
        payload={
            "sha256": payload.sha256,
            "provider_id": str(job.provider_id),
            "status": job.status.value if hasattr(job.status, "value") else str(job.status),
        },
    )
    return DetonationJobOut.model_validate(job)
