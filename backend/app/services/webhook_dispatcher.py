"""Webhook dispatcher service (Phase 3 #3.7).

Three responsibilities split across pure-function helpers:

  * ``sign_payload(secret, body)`` — HMAC-SHA256 hex over the bytes
    we're about to POST. Receivers compute the same digest with the
    shared secret and compare; mismatch = drop.
  * ``encrypt_secret`` / ``decrypt_secret`` — Fernet round-trip,
    keyed off ``VIGIL_NOTIFICATION_ENCRYPTION_KEY`` (same key the
    SIEM forwarders + alert-routing channels use).
  * ``deliver(...)`` — single-shot delivery with bounded retries and
    consecutive-failure tracking. Writes a ``WebhookDelivery`` row on
    each call so an operator can trace exactly what was sent and what
    came back.

The worker in ``app/workers/webhook_dispatcher.py`` is the production
caller; tests call ``deliver`` directly with an injected httpx client
to exercise the HTTP path.

The docstring of `app/services/notifications`-equivalent is in
``app/services/routing.py``; this module deliberately mirrors that
shape for symmetry so an operator who's read one knows where to look
in the other.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import secrets
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
import structlog
from cryptography.fernet import Fernet, InvalidToken

from app.core.config import NOTIFICATION_KEY_DEV_DEFAULT, settings
from app.models import WebhookDelivery, WebhookSubscription

log = structlog.get_logger()


# Retry budget — caller can override per-call. Same shape as
# routing.RETRY_BACKOFF_BASE_S so tests can tune it down to zero.
RETRY_BACKOFF_BASE_S = 0.5

# Response body snippet we persist for debugging. Capped so a chatty
# receiver can't blow the row size.
RESPONSE_TRUNCATE_BYTES = 512


# ---------- Secret crypto ---------------------------------------------------


def _fernet() -> Fernet:
    """Build a Fernet from the shared notification key. Lazy so the
    module can import in environments where the key hasn't been
    provisioned yet (lint, mypy, etc.)."""
    key = settings.notification_encryption_key or NOTIFICATION_KEY_DEV_DEFAULT
    return Fernet(key.encode("ascii"))


def encrypt_secret(plaintext: str) -> bytes:
    return _fernet().encrypt(plaintext.encode("utf-8"))


def decrypt_secret(blob: bytes) -> str:
    try:
        return _fernet().decrypt(blob).decode("utf-8")
    except InvalidToken as exc:
        raise RuntimeError(
            "stored webhook secret could not be decrypted; "
            "VIGIL_NOTIFICATION_ENCRYPTION_KEY may have been rotated"
        ) from exc


def generate_secret() -> str:
    """48-char URL-safe token. 256 bits of entropy is overkill for
    HMAC-SHA256 keying but cheap and trivially copy-paste-able."""
    return secrets.token_urlsafe(32)


# ---------- HMAC ------------------------------------------------------------


def sign_payload(secret: str, body: bytes) -> str:
    """HMAC-SHA256(body, secret) hex-digest. Receivers verify by
    re-computing the same digest with the secret they recorded at
    subscribe time."""
    return hmac.new(secret.encode("utf-8"), body, digestmod=hashlib.sha256).hexdigest()


# ---------- Envelope --------------------------------------------------------


def build_envelope(event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Wrap the publisher's raw payload in a stable envelope. The
    envelope is what gets signed + delivered — receivers parse this,
    not the inner ``data`` dict directly. Stable shape:

        {
          "event_type": "alert.opened",
          "occurred_at": "2026-05-13T18:00:00+00:00",
          "data": {... publisher-provided ...}
        }
    """
    return {
        "event_type": event_type,
        "occurred_at": datetime.now(UTC).isoformat(),
        "data": payload,
    }


def serialize_body(envelope: dict[str, Any]) -> bytes:
    """Canonical JSON encoding of the envelope. sort_keys=True so the
    signature is byte-stable across Python dict iteration orderings."""
    return json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------- Delivery --------------------------------------------------------


class WebhookDeliveryError(RuntimeError):
    """Retry-exhausted or permanent failure. The caller persists the
    delivery row in `failed` state and bumps the subscription's
    consecutive-failure counter."""


async def _attempt_post(
    client: httpx.AsyncClient,
    *,
    url: str,
    body: bytes,
    headers: dict[str, str],
    request_timeout: float,
) -> httpx.Response:
    return await client.post(url, content=body, headers=headers, timeout=request_timeout)


async def _post_with_retries(
    client: httpx.AsyncClient,
    *,
    url: str,
    body: bytes,
    headers: dict[str, str],
    retry_max: int,
    request_timeout: float = 10.0,
) -> tuple[httpx.Response | None, int, str | None]:
    """Try once, then retry on 5xx / network exceptions up to
    ``retry_max`` extra attempts. Returns ``(response, attempts,
    error)``. 4xx is permanent — no retry, just record the response.

    ``error`` is set to a short string on the final transient failure
    case so the delivery row can record what went wrong even when no
    response object is available.
    """
    attempts = 0
    last_response: httpx.Response | None = None
    last_error: str | None = None
    total = max(1, retry_max + 1)

    for i in range(total):
        attempts += 1
        try:
            resp = await _attempt_post(
                client, url=url, body=body, headers=headers, request_timeout=request_timeout
            )
        except (TimeoutError, httpx.HTTPError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            last_response = None
            log.warning(
                "webhook.delivery.transport_error",
                url=url,
                attempt=attempts,
                error=last_error,
            )
        else:
            last_response = resp
            last_error = None
            if resp.status_code < 400:
                return resp, attempts, None
            if 400 <= resp.status_code < 500:
                # Permanent — no retry.
                return resp, attempts, f"permanent {resp.status_code}"
            # 5xx falls through to retry path.
            last_error = f"5xx {resp.status_code}"
            log.warning(
                "webhook.delivery.server_error",
                url=url,
                attempt=attempts,
                status=resp.status_code,
            )

        if i < total - 1:
            # Exponential backoff with a tiny jitter cap. Tests set
            # RETRY_BACKOFF_BASE_S to 0 to drive this to instant.
            backoff = RETRY_BACKOFF_BASE_S * (2**i)
            if backoff:
                await asyncio.sleep(backoff)

    return last_response, attempts, last_error


def _truncate_body(text: str | None) -> str | None:
    if text is None:
        return None
    if len(text) <= RESPONSE_TRUNCATE_BYTES:
        return text
    return text[:RESPONSE_TRUNCATE_BYTES] + "…"


async def deliver(
    subscription: WebhookSubscription,
    event_type: str,
    payload: dict[str, Any],
    *,
    client: httpx.AsyncClient | None = None,
    retry_max: int | None = None,
    failure_threshold: int | None = None,
) -> WebhookDelivery:
    """Send one payload to one subscription. Returns the delivery row
    populated with the final state — the caller is responsible for
    `add`-ing it to the session and mutating the subscription if the
    delivery succeeded / failed.

    The delivery row + the subscription mutations are intentionally
    kept off the SQLAlchemy session here: the worker / API caller
    decides when to persist and commits in its own transaction.
    """
    rmax = retry_max if retry_max is not None else settings.webhook_retry_max
    threshold = (
        failure_threshold if failure_threshold is not None else settings.webhook_failure_threshold
    )

    envelope = build_envelope(event_type, payload)
    body = serialize_body(envelope)
    secret = decrypt_secret(subscription.secret_encrypted)
    signature = sign_payload(secret, body)
    delivery_id = uuid.uuid4()

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "vigil-webhook/1.0",
        "X-Vigil-Event-Type": event_type,
        "X-Vigil-Delivery-Id": str(delivery_id),
        "X-Vigil-Signature": f"sha256={signature}",
    }

    delivery = WebhookDelivery(
        id=delivery_id,
        subscription_id=subscription.id,
        event_type=event_type,
        payload_json=envelope,
        status="pending",
        attempts=0,
    )

    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient()
    try:
        response, attempts, transport_error = await _post_with_retries(
            client,
            url=subscription.url,
            body=body,
            headers=headers,
            retry_max=rmax,
        )
    finally:
        if owns_client:
            await client.aclose()

    delivery.attempts = attempts
    if response is not None:
        delivery.response_status = response.status_code
        delivery.response_body_truncated = _truncate_body(response.text)

    now = datetime.now(UTC)
    if response is not None and response.status_code < 400:
        delivery.status = "delivered"
        delivery.delivered_at = now
        subscription.last_delivery_at = now
        # A single successful delivery clears the consecutive-failure
        # counter, even if the previous N attempts had failed. The
        # threshold is *consecutive*, not cumulative.
        subscription.failure_count = 0
    else:
        delivery.status = "failed"
        if transport_error is not None and delivery.response_body_truncated is None:
            delivery.response_body_truncated = _truncate_body(transport_error)
        subscription.last_failure_at = now
        subscription.failure_count = (subscription.failure_count or 0) + 1
        if subscription.failure_count >= threshold:
            # Trip the kill-switch on this subscription. The next event
            # for this subscriber gets skipped by the worker until an
            # operator re-enables it via the API.
            subscription.enabled = False
            log.warning(
                "webhook.subscription.auto_disabled",
                subscription_id=str(subscription.id),
                consecutive_failures=subscription.failure_count,
            )

    log.info(
        "webhook.delivery.recorded",
        subscription_id=str(subscription.id),
        event_type=event_type,
        status=delivery.status,
        attempts=delivery.attempts,
        response_status=delivery.response_status,
    )
    return delivery


__all__ = [
    "RETRY_BACKOFF_BASE_S",
    "WebhookDeliveryError",
    "build_envelope",
    "decrypt_secret",
    "deliver",
    "encrypt_secret",
    "generate_secret",
    "serialize_body",
    "sign_payload",
]
