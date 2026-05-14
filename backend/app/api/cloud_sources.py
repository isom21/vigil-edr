"""Cloud telemetry sources CRUD (Phase 4 #4.2).

Operator-registered AWS CloudTrail S3 buckets. Admin-only writes;
viewers + analysts read. Every mutation is audited; the audit payload
records the bucket / prefix / region but never the credential bytes.

The credential pair is Fernet-encrypted at rest. Reads surface
``aws_access_key_id`` (the public half — useful for "which AWS account
am I looking at?" without inviting a full credential rotation) and a
``has_credentials`` boolean so the UI knows whether the row already
has a working pair.
"""

from __future__ import annotations

from uuid import UUID

import structlog
from fastapi import APIRouter, status
from sqlalchemy import select

from app.core.deps import DbSession, RequireAdmin, RequireViewer
from app.core.errors import bad_request, conflict, not_found
from app.models import CloudSource, CloudSourceKind
from app.schemas.cloud_source import CloudSourceCreate, CloudSourceOut, CloudSourceUpdate
from app.services import audit
from app.services.encryption import decrypt_config, encrypt_config

log = structlog.get_logger()

router = APIRouter(prefix="/api/cloud-sources", tags=["cloud-sources"])


def _to_out(source: CloudSource) -> CloudSourceOut:
    """Decrypt + project the config blob into the API shape, masking
    the secret. Decrypt failure surfaces only if the key rotated since
    write; in normal operation the manager's in-process Fernet key is
    the same one that wrote the row."""
    try:
        config = decrypt_config(source.config_encrypted)
    except RuntimeError:
        config = {}
    access_key = config.get("aws_access_key_id", "")
    secret = config.get("aws_secret_access_key", "")
    return CloudSourceOut(
        id=source.id,
        name=source.name,
        kind=CloudSourceKind(source.kind),
        enabled=source.enabled,
        bucket=config.get("bucket", ""),
        prefix=config.get("prefix", ""),
        region=config.get("region", ""),
        aws_access_key_id=access_key,
        has_credentials=bool(access_key and secret),
        last_polled_at=source.last_polled_at,
        last_event_ts=source.last_event_ts,
        created_at=source.created_at,
        updated_at=source.updated_at,
    )


def _config_from_payload(payload: CloudSourceCreate) -> dict:
    return {
        "bucket": payload.bucket,
        "prefix": payload.prefix,
        "region": payload.region,
        "aws_access_key_id": payload.aws_access_key_id,
        "aws_secret_access_key": payload.aws_secret_access_key,
    }


@router.get("", response_model=list[CloudSourceOut])
async def list_sources(db: DbSession, actor: RequireViewer) -> list[CloudSourceOut]:
    rows = (
        (
            await db.execute(
                select(CloudSource)
                .where(CloudSource.tenant_id == actor.tenant_id)
                .order_by(CloudSource.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return [_to_out(r) for r in rows]


@router.post("", response_model=CloudSourceOut, status_code=status.HTTP_201_CREATED)
async def create_source(
    payload: CloudSourceCreate, db: DbSession, actor: RequireAdmin
) -> CloudSourceOut:
    if payload.kind is not CloudSourceKind.AWS_CLOUDTRAIL:
        raise bad_request("only aws_cloudtrail is supported")
    existing = (
        await db.execute(
            select(CloudSource).where(
                CloudSource.tenant_id == actor.tenant_id,
                CloudSource.name == payload.name,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise conflict(f"cloud source '{payload.name}' already exists")

    source = CloudSource(
        tenant_id=actor.tenant_id,
        kind=payload.kind.value,
        name=payload.name,
        config_encrypted=encrypt_config(_config_from_payload(payload)),
        enabled=payload.enabled,
    )
    db.add(source)
    await db.flush()
    await audit.record(
        db,
        actor=actor,
        action="cloud_source.create",
        resource_type="cloud_source",
        resource_id=str(source.id),
        payload={
            "name": payload.name,
            "kind": payload.kind.value,
            "bucket": payload.bucket,
            "prefix": payload.prefix,
            "region": payload.region,
            "credentials_set": True,
        },
    )
    return _to_out(source)


@router.get("/{source_id}", response_model=CloudSourceOut)
async def get_source(source_id: UUID, db: DbSession, actor: RequireViewer) -> CloudSourceOut:
    source = await db.get(CloudSource, source_id)
    if source is None or source.tenant_id != actor.tenant_id:
        raise not_found("cloud_source", str(source_id))
    return _to_out(source)


@router.patch("/{source_id}", response_model=CloudSourceOut)
async def update_source(
    source_id: UUID,
    payload: CloudSourceUpdate,
    db: DbSession,
    actor: RequireAdmin,
) -> CloudSourceOut:
    source = await db.get(CloudSource, source_id)
    if source is None or source.tenant_id != actor.tenant_id:
        raise not_found("cloud_source", str(source_id))
    audit_payload: dict = {}
    if payload.name is not None and payload.name != source.name:
        clash = (
            await db.execute(
                select(CloudSource.id).where(
                    CloudSource.tenant_id == actor.tenant_id,
                    CloudSource.name == payload.name,
                    CloudSource.id != source_id,
                )
            )
        ).scalar_one_or_none()
        if clash is not None:
            raise conflict(f"cloud source '{payload.name}' already exists")
        source.name = payload.name
        audit_payload["name"] = payload.name
    if payload.enabled is not None:
        source.enabled = payload.enabled
        audit_payload["enabled"] = payload.enabled

    # Any config-shape change requires a re-encrypt of the whole blob;
    # decrypt once, mutate, re-encrypt.
    config_dirty = any(
        v is not None
        for v in (
            payload.bucket,
            payload.prefix,
            payload.region,
            payload.aws_access_key_id,
            payload.aws_secret_access_key,
        )
    )
    if config_dirty:
        try:
            config = decrypt_config(source.config_encrypted)
        except RuntimeError:
            config = {}
        if payload.bucket is not None:
            config["bucket"] = payload.bucket
            audit_payload["bucket"] = payload.bucket
        if payload.prefix is not None:
            config["prefix"] = payload.prefix
            audit_payload["prefix"] = payload.prefix
        if payload.region is not None:
            config["region"] = payload.region
            audit_payload["region"] = payload.region
        if payload.aws_access_key_id is not None:
            config["aws_access_key_id"] = payload.aws_access_key_id
            audit_payload["aws_access_key_id"] = payload.aws_access_key_id
        if payload.aws_secret_access_key is not None:
            config["aws_secret_access_key"] = payload.aws_secret_access_key
            audit_payload["credentials_rotated"] = True
        source.config_encrypted = encrypt_config(config)

    await audit.record(
        db,
        actor=actor,
        action="cloud_source.update",
        resource_type="cloud_source",
        resource_id=str(source.id),
        payload=audit_payload,
    )
    await db.flush()
    return _to_out(source)


@router.delete("/{source_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_source(source_id: UUID, db: DbSession, actor: RequireAdmin) -> None:
    source = await db.get(CloudSource, source_id)
    if source is None or source.tenant_id != actor.tenant_id:
        raise not_found("cloud_source", str(source_id))
    name = source.name
    await db.delete(source)
    await audit.record(
        db,
        actor=actor,
        action="cloud_source.delete",
        resource_type="cloud_source",
        resource_id=str(source_id),
        payload={"name": name},
    )
