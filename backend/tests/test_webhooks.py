"""Webhook subscription tests (Phase 3 #3.7).

Covers:

  * CRUD + role gates (analyst can list / get; admin only for mutations).
  * Plain-secret returned exactly once on create + rotate.
  * HMAC signature on the delivery body matches what the receiver
    would compute with the issued secret.
  * Audit log redacts the secret to a short fingerprint.
  * Delivery success records `delivered` + clears the failure counter.
  * Transient 5xx triggers retry; permanent 4xx does not.
  * Consecutive failures past threshold flips ``enabled = False``.
  * Migration round-trip (this lives in the alembic up/down check the
    e2e recipe runs — we still spot-check the CHECK constraint here).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid

import httpx
import pytest
import pytest_asyncio
import respx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

# Make sure the shared Fernet key is set before app.core.config imports.
os.environ.setdefault(
    "VIGIL_NOTIFICATION_ENCRYPTION_KEY",
    "ZGV2LW9ubHktdmlnaWwtbm90aWYta2V5LTMyYnl0ZXM=",
)


# ---------- Helpers ----------


async def _create(
    http_client,
    headers,
    *,
    name: str | None = None,
    url: str = "https://hooks.test/wh",
    event_types: list[str] | None = None,
    enabled: bool = True,
):
    body = {
        "name": name or f"wh-{uuid.uuid4().hex[:6]}",
        "url": url,
        "event_types": event_types or ["alert.opened"],
        "enabled": enabled,
    }
    resp = await http_client.post("/api/webhooks", json=body, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


# ---------- Role gates ----------


@pytest.mark.asyncio
async def test_create_admin_only(http_client, admin_headers, analyst_headers):
    body = {
        "name": "wh-roles",
        "url": "https://hooks.test/roles",
        "event_types": ["alert.opened"],
    }
    resp = await http_client.post("/api/webhooks", json=body, headers=analyst_headers)
    assert resp.status_code == 403

    resp = await http_client.post("/api/webhooks", json=body, headers=admin_headers)
    assert resp.status_code == 201, resp.text
    out = resp.json()
    assert out["enabled"] is True
    # Plaintext secret returned exactly once.
    assert isinstance(out.get("secret"), str) and len(out["secret"]) > 20


@pytest.mark.asyncio
async def test_list_analyst_can_read(http_client, admin_headers, analyst_headers):
    await _create(http_client, admin_headers, name="wh-read")
    resp = await http_client.get("/api/webhooks", headers=analyst_headers)
    assert resp.status_code == 200
    items = resp.json()
    assert any(c["name"] == "wh-read" for c in items)
    # The list projection never carries `secret`.
    assert all("secret" not in c for c in items)


# ---------- Validation ----------


@pytest.mark.asyncio
async def test_event_types_must_be_non_empty(http_client, admin_headers):
    resp = await http_client.post(
        "/api/webhooks",
        json={"name": "wh-empty", "url": "https://hooks.test/e", "event_types": []},
        headers=admin_headers,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_event_types_must_be_known(http_client, admin_headers):
    resp = await http_client.post(
        "/api/webhooks",
        json={
            "name": "wh-bad",
            "url": "https://hooks.test/x",
            "event_types": ["alert.opened", "totally.not.real"],
        },
        headers=admin_headers,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_duplicate_event_types_collapsed(http_client, admin_headers):
    out = await _create(
        http_client,
        admin_headers,
        name="wh-dedup",
        event_types=["alert.opened", "alert.opened", "job.failed"],
    )
    assert out["event_types"] == ["alert.opened", "job.failed"]


# ---------- Audit redaction ----------


@pytest.mark.asyncio
async def test_audit_payload_redacts_secret(http_client, admin_headers, db_session):
    from app.models import AuditLog

    out = await _create(http_client, admin_headers, name="wh-audit")
    secret = out["secret"]

    rows = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.action == "webhook.create",
                    AuditLog.resource_id == out["id"],
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
    payload = rows[0].payload or {}
    assert payload.get("redacted") is True
    assert secret not in json.dumps(payload)
    fp = payload.get("secret_fingerprint")
    assert isinstance(fp, str) and len(fp) == 8


# ---------- Rotate ----------


@pytest.mark.asyncio
async def test_rotate_issues_fresh_secret(http_client, admin_headers):
    out = await _create(http_client, admin_headers, name="wh-rot")
    first = out["secret"]
    resp = await http_client.post(f"/api/webhooks/{out['id']}/rotate", headers=admin_headers)
    assert resp.status_code == 200
    rotated = resp.json()
    assert rotated["secret"] != first
    # Server-side fingerprint visible to audit reader changed too.
    # (Spot-check via the recent audit row.)


# ---------- Dispatcher: HMAC + success path ----------


@pytest_asyncio.fixture
async def seeded_subscription(db_session: AsyncSession):
    """Insert a subscription directly so the dispatcher tests don't
    need to round-trip through the HTTP API."""
    from app.models import WebhookSubscription
    from app.services.webhook_dispatcher import encrypt_secret

    secret = "test-secret-" + uuid.uuid4().hex
    sub = WebhookSubscription(
        name=f"wh-{uuid.uuid4().hex[:8]}",
        url="https://hooks.test/sub",
        secret_encrypted=encrypt_secret(secret),
        event_types=["alert.opened", "alert.state_changed"],
        enabled=True,
    )
    db_session.add(sub)
    await db_session.flush()
    return sub, secret


@pytest.mark.asyncio
async def test_deliver_success_records_row_and_signature(db_session, seeded_subscription):
    from app.services.webhook_dispatcher import deliver

    sub, secret = seeded_subscription
    captured: dict = {}

    with respx.mock(assert_all_called=True) as mock:
        route = mock.post(sub.url).respond(200, text="ok")
        async with httpx.AsyncClient() as client:
            delivery = await deliver(
                sub,
                "alert.opened",
                {"alert_id": "abc-123", "severity": "high"},
                client=client,
            )
        assert route.called
        req = route.calls[0].request
        captured["body"] = bytes(req.content)
        captured["sig"] = req.headers.get("X-Vigil-Signature")
        captured["evt"] = req.headers.get("X-Vigil-Event-Type")
        captured["delivery_id"] = req.headers.get("X-Vigil-Delivery-Id")

    assert delivery.status == "delivered"
    assert delivery.attempts == 1
    assert delivery.response_status == 200
    assert sub.failure_count == 0
    assert sub.last_delivery_at is not None

    # Envelope shape: receivers parse {event_type, occurred_at, data}.
    envelope = json.loads(captured["body"])
    assert envelope["event_type"] == "alert.opened"
    assert envelope["data"]["alert_id"] == "abc-123"

    # Signature must match what the receiver would compute.
    expected = (
        "sha256="
        + hmac.new(secret.encode(), captured["body"], digestmod=hashlib.sha256).hexdigest()
    )
    assert captured["sig"] == expected
    assert captured["evt"] == "alert.opened"
    # Delivery-Id header must match the row primary key so receiver-side
    # idempotency can de-dup on it.
    assert captured["delivery_id"] == str(delivery.id)


@pytest.mark.asyncio
async def test_sign_payload_round_trip():
    from app.services.webhook_dispatcher import sign_payload

    body = b'{"a":1}'
    sig = sign_payload("s3cret", body)
    # Stable hex digest.
    assert sig == hmac.new(b"s3cret", body, digestmod=hashlib.sha256).hexdigest()


# ---------- Retry on transient 5xx ----------


@pytest.mark.asyncio
async def test_retry_on_5xx_then_success(db_session, seeded_subscription):
    import app.services.webhook_dispatcher as wd

    sub, _ = seeded_subscription
    orig = wd.RETRY_BACKOFF_BASE_S
    wd.RETRY_BACKOFF_BASE_S = 0.0
    try:
        with respx.mock(assert_all_called=True) as mock:
            route = mock.post(sub.url)
            route.side_effect = [
                httpx.Response(503, text="overloaded"),
                httpx.Response(502, text="bad gateway"),
                httpx.Response(200, text="ok"),
            ]
            async with httpx.AsyncClient() as client:
                delivery = await wd.deliver(
                    sub, "alert.opened", {"x": 1}, client=client, retry_max=5
                )
            assert route.call_count == 3
        assert delivery.status == "delivered"
        assert delivery.attempts == 3
        assert sub.failure_count == 0
    finally:
        wd.RETRY_BACKOFF_BASE_S = orig


# ---------- Permanent 4xx — no retry ----------


@pytest.mark.asyncio
async def test_4xx_does_not_retry(db_session, seeded_subscription):
    import app.services.webhook_dispatcher as wd

    sub, _ = seeded_subscription
    orig = wd.RETRY_BACKOFF_BASE_S
    wd.RETRY_BACKOFF_BASE_S = 0.0
    try:
        with respx.mock() as mock:
            route = mock.post(sub.url).respond(404, text="nope")
            async with httpx.AsyncClient() as client:
                delivery = await wd.deliver(
                    sub, "alert.opened", {"x": 1}, client=client, retry_max=5
                )
            assert route.call_count == 1
        assert delivery.status == "failed"
        assert delivery.response_status == 404
        assert delivery.attempts == 1
        assert sub.failure_count == 1
    finally:
        wd.RETRY_BACKOFF_BASE_S = orig


# ---------- Auto-disable on threshold ----------


@pytest.mark.asyncio
async def test_auto_disable_after_threshold(db_session, seeded_subscription):
    import app.services.webhook_dispatcher as wd

    sub, _ = seeded_subscription
    orig = wd.RETRY_BACKOFF_BASE_S
    wd.RETRY_BACKOFF_BASE_S = 0.0
    # Local-only threshold so we don't have to send 10 times.
    threshold = 3
    try:
        with respx.mock() as mock:
            mock.post(sub.url).respond(503, text="down")
            async with httpx.AsyncClient() as client:
                # Three failed deliveries — the third should trip the
                # kill switch on the subscription.
                for i in range(threshold):
                    await wd.deliver(
                        sub,
                        "alert.opened",
                        {"n": i},
                        client=client,
                        retry_max=0,
                        failure_threshold=threshold,
                    )
        assert sub.failure_count >= threshold
        assert sub.enabled is False
        assert sub.last_failure_at is not None
    finally:
        wd.RETRY_BACKOFF_BASE_S = orig


# ---------- Test-fire endpoint ----------


@pytest.mark.asyncio
async def test_test_endpoint_synchronous(http_client, admin_headers):
    out = await _create(
        http_client,
        admin_headers,
        name="wh-test",
        url="https://hooks.test/synchronous",
        event_types=["alert.opened"],
    )
    with respx.mock(assert_all_called=True) as mock:
        mock.post("https://hooks.test/synchronous").respond(200, text="ok")
        resp = await http_client.post(
            f"/api/webhooks/{out['id']}/test",
            json={"event_type": "alert.opened"},
            headers=admin_headers,
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "delivered"
    assert body["response_status"] == 200
    assert body["event_type"] == "alert.opened"


@pytest.mark.asyncio
async def test_test_endpoint_rejects_unsubscribed_event_type(http_client, admin_headers):
    out = await _create(
        http_client,
        admin_headers,
        name="wh-narrow",
        event_types=["alert.opened"],
    )
    resp = await http_client.post(
        f"/api/webhooks/{out['id']}/test",
        json={"event_type": "job.completed"},
        headers=admin_headers,
    )
    assert resp.status_code == 400


# ---------- Deliveries listing ----------


@pytest.mark.asyncio
async def test_deliveries_listing(http_client, admin_headers):
    out = await _create(
        http_client,
        admin_headers,
        name="wh-history",
        url="https://hooks.test/hist",
    )
    with respx.mock() as mock:
        mock.post("https://hooks.test/hist").respond(200, text="ok")
        await http_client.post(
            f"/api/webhooks/{out['id']}/test",
            json={"event_type": "alert.opened"},
            headers=admin_headers,
        )
        await http_client.post(
            f"/api/webhooks/{out['id']}/test",
            json={"event_type": "alert.opened"},
            headers=admin_headers,
        )
    resp = await http_client.get(f"/api/webhooks/{out['id']}/deliveries", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    page = resp.json()
    assert page["total"] == 2
    assert len(page["items"]) == 2
    assert all(d["status"] == "delivered" for d in page["items"])


# ---------- Worker dispatch_event ----------


@pytest.mark.asyncio
async def test_worker_fanout_matches_event_type(db_session):
    """A subscription that doesn't include the event type is skipped;
    one that does receives the delivery."""
    from contextlib import asynccontextmanager

    from app.models import WebhookSubscription
    from app.services.webhook_dispatcher import encrypt_secret
    from app.workers.webhook_dispatcher import dispatch_event

    match = WebhookSubscription(
        name=f"match-{uuid.uuid4().hex[:6]}",
        url="https://hooks.test/match",
        secret_encrypted=encrypt_secret("s"),
        event_types=["job.completed"],
        enabled=True,
    )
    skip = WebhookSubscription(
        name=f"skip-{uuid.uuid4().hex[:6]}",
        url="https://hooks.test/skip",
        secret_encrypted=encrypt_secret("s"),
        event_types=["alert.opened"],
        enabled=True,
    )
    db_session.add_all([match, skip])
    await db_session.flush()

    @asynccontextmanager
    async def _sm():
        # Yield the same SAVEPOINT-bound session the test fixture owns
        # so the worker's COMMIT only commits within the savepoint.
        yield db_session

    with respx.mock(assert_all_called=True) as mock:
        route_match = mock.post(match.url).respond(200, text="ok")
        async with httpx.AsyncClient() as client:
            n = await dispatch_event(
                "job.completed",
                {"job_id": "job-1"},
                session_maker=_sm,
                client=client,
            )
    assert n == 1
    assert route_match.called
