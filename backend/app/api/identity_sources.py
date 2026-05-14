"""Identity threat detection sources CRUD (Phase 4 #4.3).

Admin-only. Every mutation is audited; the audit payload elides the
`config` blob entirely — the credential never round-trips through
the audit log (same shape as `app.api.case_destinations`).

Reads are scoped to the actor's active tenant (Phase 3 #3.1
convention). The monitor worker keys off `IdentitySource.tenant_id`
when it inserts Alert rows, so the per-tenant scoping is consistent
end-to-end.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, status
from sqlalchemy import select

from app.core.deps import DbSession, RequireAdmin
from app.core.errors import bad_request, conflict, not_found
from app.models import IdentitySource, IdentitySourceKind
from app.schemas.identity_source import (
    IdentitySourceCreate,
    IdentitySourceOut,
    IdentitySourceUpdate,
)
from app.services import audit
from app.services.encryption import encrypt_config

router = APIRouter(prefix="/api/identity-sources", tags=["identity-sources"])


def _kind_required_fields(kind: IdentitySourceKind) -> tuple[str, ...]:
    """Per-kind required-keys gate. Mirrors the validation each
    fetcher does at call time so the operator gets a 400 at
    registration instead of a 500 on the first poll."""
    if kind is IdentitySourceKind.OKTA:
        return ("domain", "api_token")
    if kind is IdentitySourceKind.AZURE_AD:
        return ("tenant_id", "client_id", "client_secret")
    return ()


def _check_required(kind: IdentitySourceKind, config: dict) -> None:
    missing = [k for k in _kind_required_fields(kind) if not config.get(k)]
    if missing:
        raise bad_request(f"missing required config fields for {kind.value}: {','.join(missing)}")


def _to_out(source: IdentitySource) -> IdentitySourceOut:
    return IdentitySourceOut(
        id=source.id,
        kind=IdentitySourceKind.coerce(source.kind),
        name=source.name,
        enabled=source.enabled,
        last_polled_at=source.last_polled_at,
        last_event_ts=source.last_event_ts,
        created_at=source.created_at,
        updated_at=source.updated_at,
    )


@router.get("", response_model=list[IdentitySourceOut])
async def list_sources(
    db: DbSession,
    actor: RequireAdmin,
) -> list[IdentitySourceOut]:
    rows = (
        (
            await db.execute(
                select(IdentitySource)
                .where(IdentitySource.tenant_id == actor.tenant_id)
                .order_by(IdentitySource.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return [_to_out(s) for s in rows]


@router.post("", response_model=IdentitySourceOut, status_code=status.HTTP_201_CREATED)
async def create_source(
    payload: IdentitySourceCreate,
    db: DbSession,
    actor: RequireAdmin,
) -> IdentitySourceOut:
    existing = (
        await db.execute(
            select(IdentitySource).where(
                IdentitySource.tenant_id == actor.tenant_id,
                IdentitySource.name == payload.name,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise conflict("identity source name already in use")

    _check_required(payload.kind, payload.config)

    source = IdentitySource(
        tenant_id=actor.tenant_id,
        kind=payload.kind.value,
        name=payload.name,
        config_encrypted=encrypt_config(payload.config),
        enabled=payload.enabled,
    )
    db.add(source)
    await db.flush()

    await audit.record(
        db,
        actor=actor,
        action="identity_source.create",
        resource_type="identity_source",
        resource_id=str(source.id),
        payload={
            "name": payload.name,
            "kind": payload.kind.value,
            "enabled": payload.enabled,
        },
    )
    await db.commit()
    return _to_out(source)


@router.get("/{source_id}", response_model=IdentitySourceOut)
async def get_source(
    source_id: UUID,
    db: DbSession,
    actor: RequireAdmin,
) -> IdentitySourceOut:
    source = await db.get(IdentitySource, source_id)
    if source is None or source.tenant_id != actor.tenant_id:
        raise not_found("identity_source", str(source_id))
    return _to_out(source)


@router.patch("/{source_id}", response_model=IdentitySourceOut)
async def update_source(
    source_id: UUID,
    payload: IdentitySourceUpdate,
    db: DbSession,
    actor: RequireAdmin,
) -> IdentitySourceOut:
    source = await db.get(IdentitySource, source_id)
    if source is None or source.tenant_id != actor.tenant_id:
        raise not_found("identity_source", str(source_id))

    audit_payload: dict = {}
    if payload.name is not None and payload.name != source.name:
        clash = (
            await db.execute(
                select(IdentitySource.id).where(
                    IdentitySource.tenant_id == actor.tenant_id,
                    IdentitySource.name == payload.name,
                    IdentitySource.id != source_id,
                )
            )
        ).scalar_one_or_none()
        if clash is not None:
            raise conflict("identity source name already in use")
        source.name = payload.name
        audit_payload["name"] = payload.name
    if payload.enabled is not None:
        source.enabled = payload.enabled
        audit_payload["enabled"] = payload.enabled
    if payload.config is not None:
        _check_required(IdentitySourceKind.coerce(source.kind), payload.config)
        source.config_encrypted = encrypt_config(payload.config)
        # Don't audit the plaintext config — record only the fact of
        # rotation, which is what an operator reviewing the log needs.
        audit_payload["config_rotated"] = True

    await audit.record(
        db,
        actor=actor,
        action="identity_source.update",
        resource_type="identity_source",
        resource_id=str(source.id),
        payload=audit_payload,
    )
    await db.commit()
    await db.refresh(source)
    return _to_out(source)


@router.delete("/{source_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_source(
    source_id: UUID,
    db: DbSession,
    actor: RequireAdmin,
) -> None:
    source = await db.get(IdentitySource, source_id)
    if source is None or source.tenant_id != actor.tenant_id:
        raise not_found("identity_source", str(source_id))
    name = source.name
    kind_val = IdentitySourceKind.coerce(source.kind).value
    await db.delete(source)
    await audit.record(
        db,
        actor=actor,
        action="identity_source.delete",
        resource_type="identity_source",
        resource_id=str(source_id),
        payload={"name": name, "kind": kind_val},
    )
    await db.commit()
