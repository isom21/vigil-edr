"""Webhook subscription CRUD + test-fire + delivery history API.

Admin-only writes; viewer+analyst can list / inspect.

Audit-log discipline mirrors the SIEM / notification-channel APIs:
the audit payload never carries the raw signing secret — only a
short fingerprint that lets an operator confirm a rotation took
effect without leaking enough of the secret to forge a signature.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from uuid import UUID

import httpx
from fastapi import APIRouter, Query, status
from sqlalchemy import func, select

from app.core.deps import DbSession, RequireAdmin, RequireViewer
from app.core.errors import bad_request, conflict, not_found
from app.models import WebhookDelivery, WebhookSubscription
from app.schemas.common import Page
from app.schemas.webhook import (
    WebhookDeliveryOut,
    WebhookSubscriptionCreate,
    WebhookSubscriptionCreateResponse,
    WebhookSubscriptionOut,
    WebhookSubscriptionUpdate,
    WebhookTestRequest,
)
from app.services import audit
from app.services.webhook_dispatcher import (
    deliver,
    encrypt_secret,
    generate_secret,
)

router = APIRouter(prefix="/api/webhooks", tags=["webhooks"])


def _fingerprint(secret_plain: str) -> str:
    """Short stable id for the signing secret (sha256, first 8 hex).
    Identical to the convention in `services/routing.secret_fingerprint`
    so audit-log readers see a consistent shape across the
    notification + webhook paths."""
    return hashlib.sha256(secret_plain.encode("utf-8")).hexdigest()[:8]


def _to_out(sub: WebhookSubscription) -> WebhookSubscriptionOut:
    return WebhookSubscriptionOut.model_validate(sub)


@router.get("", response_model=list[WebhookSubscriptionOut])
async def list_subscriptions(db: DbSession, _actor: RequireViewer) -> list[WebhookSubscriptionOut]:
    rows = (
        (
            await db.execute(
                select(WebhookSubscription).order_by(WebhookSubscription.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return [_to_out(s) for s in rows]


@router.get("/{sub_id}", response_model=WebhookSubscriptionOut)
async def get_subscription(
    sub_id: UUID, db: DbSession, _actor: RequireViewer
) -> WebhookSubscriptionOut:
    sub = await db.get(WebhookSubscription, sub_id)
    if sub is None:
        raise not_found("webhook_subscription", str(sub_id))
    return _to_out(sub)


@router.post(
    "",
    response_model=WebhookSubscriptionCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_subscription(
    payload: WebhookSubscriptionCreate, db: DbSession, actor: RequireAdmin
) -> WebhookSubscriptionCreateResponse:
    existing = (
        await db.execute(
            select(WebhookSubscription).where(WebhookSubscription.name == payload.name)
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise conflict("webhook subscription name already in use")

    secret = generate_secret()
    sub = WebhookSubscription(
        name=payload.name,
        url=str(payload.url),
        secret_encrypted=encrypt_secret(secret),
        event_types=list(payload.event_types),
        enabled=payload.enabled,
    )
    db.add(sub)
    await db.flush()

    await audit.record(
        db,
        actor=actor,
        action="webhook.create",
        resource_type="webhook_subscription",
        resource_id=str(sub.id),
        payload={
            "name": payload.name,
            "url": str(payload.url),
            "event_types": list(payload.event_types),
            "enabled": payload.enabled,
            "secret_fingerprint": _fingerprint(secret),
            "redacted": True,
        },
    )

    out_base = _to_out(sub).model_dump()
    return WebhookSubscriptionCreateResponse(**out_base, secret=secret)


@router.patch("/{sub_id}", response_model=WebhookSubscriptionOut)
async def update_subscription(
    sub_id: UUID,
    payload: WebhookSubscriptionUpdate,
    db: DbSession,
    actor: RequireAdmin,
) -> WebhookSubscriptionOut:
    sub = await db.get(WebhookSubscription, sub_id)
    if sub is None:
        raise not_found("webhook_subscription", str(sub_id))

    audit_payload: dict = {}
    if payload.name is not None and payload.name != sub.name:
        clash = (
            await db.execute(
                select(WebhookSubscription.id).where(
                    WebhookSubscription.name == payload.name,
                    WebhookSubscription.id != sub_id,
                )
            )
        ).scalar_one_or_none()
        if clash is not None:
            raise conflict("webhook subscription name already in use")
        sub.name = payload.name
        audit_payload["name"] = payload.name
    if payload.url is not None:
        sub.url = str(payload.url)
        audit_payload["url"] = str(payload.url)
    if payload.event_types is not None:
        sub.event_types = list(payload.event_types)
        audit_payload["event_types"] = list(payload.event_types)
    if payload.enabled is not None:
        was_enabled = sub.enabled
        sub.enabled = payload.enabled
        audit_payload["enabled"] = payload.enabled
        # Re-enabling clears the consecutive-failure counter so the
        # next delivery has a clean slate. Operators don't expect a
        # subscription they just re-enabled to instantly auto-disable
        # again because the old counter was already at threshold.
        if payload.enabled and not was_enabled:
            sub.failure_count = 0
            audit_payload["failure_count_reset"] = True

    await audit.record(
        db,
        actor=actor,
        action="webhook.update",
        resource_type="webhook_subscription",
        resource_id=str(sub.id),
        payload=audit_payload,
    )
    return _to_out(sub)


@router.delete("/{sub_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_subscription(sub_id: UUID, db: DbSession, actor: RequireAdmin) -> None:
    sub = await db.get(WebhookSubscription, sub_id)
    if sub is None:
        raise not_found("webhook_subscription", str(sub_id))
    name = sub.name
    await db.delete(sub)
    await audit.record(
        db,
        actor=actor,
        action="webhook.delete",
        resource_type="webhook_subscription",
        resource_id=str(sub_id),
        payload={"name": name},
    )


@router.post("/{sub_id}/test", response_model=WebhookDeliveryOut)
async def test_subscription(
    sub_id: UUID,
    payload: WebhookTestRequest,
    db: DbSession,
    actor: RequireAdmin,
) -> WebhookDeliveryOut:
    """Fire a synthetic delivery synchronously so the operator can see
    the response right after subscribing. Goes through the same
    dispatcher path as live events — including HMAC, retries, and
    failure-counter updates — so a green test gives high confidence
    the receiver will accept real fires."""
    sub = await db.get(WebhookSubscription, sub_id)
    if sub is None:
        raise not_found("webhook_subscription", str(sub_id))
    if payload.event_type not in sub.event_types:
        # Tested types must be one the subscription accepts — otherwise
        # a green test would mean nothing operationally.
        raise bad_request(
            f"event_type '{payload.event_type}' is not in this subscription's event_types"
        )

    sample = {
        "test": True,
        "subscription_id": str(sub.id),
        "subscription_name": sub.name,
        "fired_at": datetime.now(UTC).isoformat(),
        "fired_by_user_id": str(actor.user.id) if actor.user is not None else None,
    }
    async with httpx.AsyncClient() as client:
        delivery = await deliver(sub, payload.event_type, sample, client=client)
    db.add(delivery)
    await db.flush()

    await audit.record(
        db,
        actor=actor,
        action="webhook.test",
        resource_type="webhook_subscription",
        resource_id=str(sub.id),
        payload={
            "event_type": payload.event_type,
            "delivery_id": str(delivery.id),
            "status": delivery.status,
            "response_status": delivery.response_status,
        },
    )
    return WebhookDeliveryOut.model_validate(delivery)


@router.post(
    "/{sub_id}/rotate",
    response_model=WebhookSubscriptionCreateResponse,
    status_code=status.HTTP_200_OK,
)
async def rotate_secret(
    sub_id: UUID, db: DbSession, actor: RequireAdmin
) -> WebhookSubscriptionCreateResponse:
    """Rotate the signing secret. The new value is returned exactly
    once — the operator must update the receiver's verifier before
    the next event fires, otherwise the receiver will reject every
    delivery for a bad signature."""
    sub = await db.get(WebhookSubscription, sub_id)
    if sub is None:
        raise not_found("webhook_subscription", str(sub_id))
    new_secret = generate_secret()
    sub.secret_encrypted = encrypt_secret(new_secret)
    await audit.record(
        db,
        actor=actor,
        action="webhook.rotate",
        resource_type="webhook_subscription",
        resource_id=str(sub.id),
        payload={"secret_fingerprint": _fingerprint(new_secret), "redacted": True},
    )
    out_base = _to_out(sub).model_dump()
    return WebhookSubscriptionCreateResponse(**out_base, secret=new_secret)


@router.get("/{sub_id}/deliveries", response_model=Page[WebhookDeliveryOut])
async def list_deliveries(
    sub_id: UUID,
    db: DbSession,
    _actor: RequireViewer,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> Page[WebhookDeliveryOut]:
    sub = await db.get(WebhookSubscription, sub_id)
    if sub is None:
        raise not_found("webhook_subscription", str(sub_id))
    stmt = (
        select(WebhookDelivery)
        .where(WebhookDelivery.subscription_id == sub.id)
        .order_by(WebhookDelivery.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    rows = (await db.execute(stmt)).scalars().all()
    total = (
        await db.execute(
            select(func.count(WebhookDelivery.id)).where(WebhookDelivery.subscription_id == sub.id)
        )
    ).scalar_one()
    return Page[WebhookDeliveryOut](
        items=[WebhookDeliveryOut.model_validate(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


__all__ = ["router"]
