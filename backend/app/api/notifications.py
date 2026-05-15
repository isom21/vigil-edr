"""Notification channels CRUD (Phase 1 #1.7 — alert routing).

Channel mutations require admin; analyst+ may list / get (so non-admin
analysts can see WHICH channels are wired up without learning the
credentials themselves — secrets never leave the manager regardless).
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, status
from sqlalchemy import select

from app.core.deps import DbSession, RequireAdmin, RequireAnalyst
from app.core.errors import bad_request, not_found
from app.models import NotificationChannel
from app.schemas.notification import (
    NotificationChannelCreate,
    NotificationChannelOut,
    NotificationChannelUpdate,
)
from app.services import audit
from app.services.routing import (
    ChannelConfigError,
    audit_payload,
    decrypt_config,
    encrypt_config,
    secret_fingerprint,
    validate_config,
)
from app.services.scoping import apply_tenant_scope

router = APIRouter(prefix="/api/notifications/channels", tags=["notifications"])


def _hydrate(ch: NotificationChannel) -> NotificationChannelOut:
    out = NotificationChannelOut.model_validate(ch)
    try:
        cfg = decrypt_config(ch.encrypted_config)
        out.secret_fingerprint = secret_fingerprint(ch.kind, cfg)
    except Exception:
        # Decryption can fail if the operator rotated
        # VIGIL_NOTIFICATION_ENCRYPTION_KEY without rotating the
        # channels. Surface NULL fingerprint and let the operator
        # re-create the channel; the worker will log the same error
        # on its first attempt to fire.
        out.secret_fingerprint = None
    return out


async def _load_in_tenant(db, channel_id: UUID, actor) -> NotificationChannel:
    """404 (not 403) on cross-tenant id (CODE-11)."""
    ch = await db.get(NotificationChannel, channel_id)
    if ch is None or ch.tenant_id != actor.tenant_id:
        raise not_found("notification_channel", str(channel_id))
    return ch


@router.get("", response_model=list[NotificationChannelOut])
async def list_channels(db: DbSession, actor: RequireAnalyst) -> list[NotificationChannelOut]:
    # CODE-11: scope to actor's tenant. Pre-PR, tenant A's analysts
    # could enumerate every tenant's Slack / PagerDuty / SMTP channel
    # names (and admins could rotate their config).
    stmt = apply_tenant_scope(
        select(NotificationChannel), actor, NotificationChannel.tenant_id
    ).order_by(NotificationChannel.name)
    rows = (await db.execute(stmt)).scalars().all()
    return [_hydrate(r) for r in rows]


@router.post(
    "",
    response_model=NotificationChannelOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_channel(
    payload: NotificationChannelCreate,
    db: DbSession,
    actor: RequireAdmin,
) -> NotificationChannelOut:
    try:
        validate_config(payload.kind, payload.config)
    except ChannelConfigError as exc:
        raise bad_request(str(exc)) from exc
    # Name uniqueness is per-tenant.
    dup = (
        await db.execute(
            select(NotificationChannel)
            .where(NotificationChannel.name == payload.name)
            .where(NotificationChannel.tenant_id == actor.tenant_id)
        )
    ).scalar_one_or_none()
    if dup is not None:
        raise bad_request(f"notification channel '{payload.name}' already exists")
    ch = NotificationChannel(
        tenant_id=actor.tenant_id,
        name=payload.name,
        kind=payload.kind,
        encrypted_config=encrypt_config(payload.config),
        enabled=payload.enabled,
    )
    db.add(ch)
    await db.flush()
    await audit.record(
        db,
        actor=actor,
        action="notification_channel.create",
        resource_type="notification_channel",
        resource_id=str(ch.id),
        payload=audit_payload(
            name=ch.name, kind=ch.kind, config=payload.config, enabled=ch.enabled
        ),
    )
    await db.commit()
    return _hydrate(ch)


@router.get("/{channel_id}", response_model=NotificationChannelOut)
async def get_channel(
    channel_id: UUID, db: DbSession, actor: RequireAnalyst
) -> NotificationChannelOut:
    ch = await _load_in_tenant(db, channel_id, actor)
    return _hydrate(ch)


@router.patch("/{channel_id}", response_model=NotificationChannelOut)
async def update_channel(
    channel_id: UUID,
    payload: NotificationChannelUpdate,
    db: DbSession,
    actor: RequireAdmin,
) -> NotificationChannelOut:
    ch = await _load_in_tenant(db, channel_id, actor)
    if payload.name is not None and payload.name != ch.name:
        dup = (
            await db.execute(
                select(NotificationChannel).where(
                    NotificationChannel.name == payload.name,
                    NotificationChannel.tenant_id == actor.tenant_id,
                    NotificationChannel.id != channel_id,
                )
            )
        ).scalar_one_or_none()
        if dup is not None:
            raise bad_request(f"notification channel '{payload.name}' already exists")
        ch.name = payload.name
    audit_config_view: dict | None = None
    if payload.config is not None:
        try:
            validate_config(ch.kind, payload.config)
        except ChannelConfigError as exc:
            raise bad_request(str(exc)) from exc
        ch.encrypted_config = encrypt_config(payload.config)
        audit_config_view = payload.config
    if payload.enabled is not None:
        ch.enabled = payload.enabled
    # If the operator only rotated `enabled` we still log a fingerprint
    # of the current secret so audit trail is meaningful.
    if audit_config_view is None:
        try:
            audit_config_view = decrypt_config(ch.encrypted_config)
        except Exception:
            audit_config_view = {}
    await audit.record(
        db,
        actor=actor,
        action="notification_channel.update",
        resource_type="notification_channel",
        resource_id=str(channel_id),
        payload=audit_payload(
            name=ch.name, kind=ch.kind, config=audit_config_view, enabled=ch.enabled
        ),
    )
    await db.commit()
    return _hydrate(ch)


@router.delete("/{channel_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_channel(channel_id: UUID, db: DbSession, actor: RequireAdmin) -> None:
    ch = await _load_in_tenant(db, channel_id, actor)
    await db.delete(ch)
    await audit.record(
        db,
        actor=actor,
        action="notification_channel.delete",
        resource_type="notification_channel",
        resource_id=str(channel_id),
        payload={"name": ch.name, "kind": ch.kind.value, "redacted": True},
    )
    await db.commit()
