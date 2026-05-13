"""Alert routing tests (Phase 1 #1.7).

Covers:

  * Notification-channel + routing-rule CRUD with role gates
    (analyst can list/get; only admin can mutate).
  * Audit-log fingerprint redaction: the audit payload for a Slack /
    PagerDuty / email channel must NEVER contain the raw secret —
    only a short sha256 fingerprint + a redaction marker.
  * Severity / kind / host-group matching semantics.
  * End-to-end dispatch with `respx` for HTTP channels and
    `aiosmtpd` for SMTP. Verifies retry-on-5xx and failure path.
  * Fernet round-trip of the encrypted_config blob.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import uuid
from collections.abc import AsyncIterator
from typing import Any
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
import respx
from aiosmtpd.controller import Controller
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

# Ensure a working Fernet key is in scope before anything imports
# app.core.config — the dev default is fine for tests.
os.environ.setdefault(
    "VIGIL_NOTIFICATION_ENCRYPTION_KEY",
    "ZGV2LW9ubHktdmlnaWwtbm90aWYta2V5LTMyYnl0ZXM=",
)


# ---------- Helpers ----------


async def _make_channel(http_client, headers, *, name, kind, config, enabled=True):
    resp = await http_client.post(
        "/api/notifications/channels",
        json={"name": name, "kind": kind, "config": config, "enabled": enabled},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _make_rule(http_client, headers, **body) -> dict[str, Any]:
    resp = await http_client.post(
        "/api/notifications/rules", json=body, headers=headers
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


# ---------- Channel CRUD + role gates ----------


@pytest.mark.asyncio
async def test_create_channel_admin_only(http_client, analyst_headers, admin_headers):
    # Analyst can't mutate.
    resp = await http_client.post(
        "/api/notifications/channels",
        json={
            "name": "no-perm",
            "kind": "slack",
            "config": {"webhook_url": "https://hooks.example/abc"},
        },
        headers=analyst_headers,
    )
    assert resp.status_code == 403

    # Admin can.
    body = await _make_channel(
        http_client,
        admin_headers,
        name="ops-slack",
        kind="slack",
        config={"webhook_url": "https://hooks.slack.example/T000/B000/XXX"},
    )
    assert body["kind"] == "slack"
    assert body["enabled"] is True
    # Public projection never carries the raw config.
    assert "webhook_url" not in body
    assert body["secret_fingerprint"] and len(body["secret_fingerprint"]) == 8


@pytest.mark.asyncio
async def test_list_channel_analyst_can_read(http_client, admin_headers, analyst_headers):
    await _make_channel(
        http_client,
        admin_headers,
        name="pd-prod",
        kind="pagerduty",
        config={"integration_key": "abcdef0123"},
    )
    resp = await http_client.get(
        "/api/notifications/channels", headers=analyst_headers
    )
    assert resp.status_code == 200
    items = resp.json()
    assert any(c["name"] == "pd-prod" for c in items)


@pytest.mark.asyncio
async def test_channel_config_validation_rejects_bad_shape(http_client, admin_headers):
    # missing webhook_url
    resp = await http_client.post(
        "/api/notifications/channels",
        json={"name": "bad-slack", "kind": "slack", "config": {}},
        headers=admin_headers,
    )
    assert resp.status_code == 400
    assert "webhook_url" in resp.json()["detail"]

    # PagerDuty: empty key
    resp = await http_client.post(
        "/api/notifications/channels",
        json={"name": "bad-pd", "kind": "pagerduty", "config": {"integration_key": ""}},
        headers=admin_headers,
    )
    assert resp.status_code == 400

    # Email: missing port
    resp = await http_client.post(
        "/api/notifications/channels",
        json={
            "name": "bad-mail",
            "kind": "email",
            "config": {
                "smtp_host": "mail.example",
                "from_addr": "vigil@example",
                "to_addr": "soc@example",
            },
        },
        headers=admin_headers,
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_channel_update_rotate_secret_and_disable(http_client, admin_headers):
    ch = await _make_channel(
        http_client,
        admin_headers,
        name="rot-1",
        kind="slack",
        config={"webhook_url": "https://hooks.example/v1"},
    )
    fp_before = ch["secret_fingerprint"]

    # Rotate secret only.
    resp = await http_client.patch(
        f"/api/notifications/channels/{ch['id']}",
        json={"config": {"webhook_url": "https://hooks.example/v2"}},
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["secret_fingerprint"] != fp_before
    assert body["enabled"] is True

    # Toggle enabled.
    resp = await http_client.patch(
        f"/api/notifications/channels/{ch['id']}",
        json={"enabled": False},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False


@pytest.mark.asyncio
async def test_channel_delete(http_client, admin_headers):
    ch = await _make_channel(
        http_client,
        admin_headers,
        name="del-1",
        kind="slack",
        config={"webhook_url": "https://hooks.example/del"},
    )
    resp = await http_client.delete(
        f"/api/notifications/channels/{ch['id']}", headers=admin_headers
    )
    assert resp.status_code == 204
    # Now gone.
    resp = await http_client.get(
        f"/api/notifications/channels/{ch['id']}", headers=admin_headers
    )
    assert resp.status_code == 404


# ---------- Audit redaction ----------


@pytest.mark.asyncio
async def test_audit_payload_redacts_secret(http_client, admin_headers, db_session):
    """The audit row for a Slack-channel create MUST NOT contain the
    webhook URL — only the fingerprint + a redaction marker."""
    from app.models import AuditLog

    secret = "https://hooks.example/SUPER-SECRET-XYZ123"
    ch = await _make_channel(
        http_client,
        admin_headers,
        name="audit-redact",
        kind="slack",
        config={"webhook_url": secret},
    )
    rows = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.action == "notification_channel.create",
                    AuditLog.resource_id == ch["id"],
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
    payload = rows[0].payload or {}
    assert payload.get("redacted") is True
    assert payload.get("kind") == "slack"
    # Secret material absent.
    assert "webhook_url" not in payload
    assert secret not in json.dumps(payload)
    fp = payload.get("secret_fingerprint")
    assert isinstance(fp, str) and len(fp) == 8


# ---------- Routing-rule CRUD + matching ----------


@pytest.mark.asyncio
async def test_routing_rule_admin_only(http_client, admin_headers, analyst_headers):
    ch = await _make_channel(
        http_client,
        admin_headers,
        name="route-slack",
        kind="slack",
        config={"webhook_url": "https://hooks.example/rule"},
    )
    body = {
        "name": "high-only",
        "min_severity": "high",
        "channel_ids": [ch["id"]],
    }
    # Analyst can list but not create.
    resp = await http_client.post(
        "/api/notifications/rules", json=body, headers=analyst_headers
    )
    assert resp.status_code == 403
    resp = await http_client.get(
        "/api/notifications/rules", headers=analyst_headers
    )
    assert resp.status_code == 200

    rule = await _make_rule(http_client, admin_headers, **body)
    assert rule["min_severity"] == "high"
    assert rule["channel_ids"] == [ch["id"]]


@pytest.mark.asyncio
async def test_routing_rule_unknown_channel_rejected(http_client, admin_headers):
    resp = await http_client.post(
        "/api/notifications/rules",
        json={
            "name": "bad-ref",
            "min_severity": "low",
            "channel_ids": [str(uuid4())],
        },
        headers=admin_headers,
    )
    assert resp.status_code == 400


# ---------- Match logic (pure service-layer) ----------


@pytest_asyncio.fixture
async def seeded_alert(db_session: AsyncSession):
    """Insert a rule + alert directly so the service can score them."""
    from app.models import (
        Alert,
        AlertState,
        Host,
        OsFamily,
        Rule,
        RuleAction,
        RuleKind,
        Severity,
    )

    host = Host(
        hostname=f"host-{uuid.uuid4().hex[:8]}",
        os_family=OsFamily.LINUX,
    )
    db_session.add(host)
    await db_session.flush()
    rule = Rule(
        kind=RuleKind.SIGMA,
        name="route-test-rule",
        severity=Severity.HIGH,
        action=RuleAction.ALERT,
    )
    db_session.add(rule)
    await db_session.flush()
    alert = Alert(
        host_id=host.id,
        rule_id=rule.id,
        severity=Severity.HIGH,
        action_taken=RuleAction.ALERT,
        state=AlertState.NEW,
        summary="route-test summary",
        details={"x": 1},
    )
    db_session.add(alert)
    await db_session.flush()
    return alert


@pytest.mark.asyncio
async def test_match_severity_floor(db_session, seeded_alert):
    from app.models import NotificationChannel, NotificationChannelKind, RoutingRule, Severity
    from app.services.routing import encrypt_config, envelope_from_alert, matching_rules

    ch = NotificationChannel(
        name=f"sev-{uuid.uuid4().hex[:6]}",
        kind=NotificationChannelKind.SLACK,
        encrypted_config=encrypt_config({"webhook_url": "https://hooks.example/sev"}),
    )
    db_session.add(ch)
    await db_session.flush()

    # Rule that should match: floor=medium, alert is high.
    r_match = RoutingRule(
        name=f"r-match-{uuid.uuid4().hex[:6]}",
        min_severity=Severity.MEDIUM,
        channel_ids=[ch.id],
    )
    # Rule that should NOT match: floor=critical, alert is high.
    r_skip = RoutingRule(
        name=f"r-skip-{uuid.uuid4().hex[:6]}",
        min_severity=Severity.CRITICAL,
        channel_ids=[ch.id],
    )
    db_session.add_all([r_match, r_skip])
    await db_session.flush()

    env = await envelope_from_alert(db_session, seeded_alert)
    out = await matching_rules(db_session, env)
    names = {r.name for r in out}
    assert r_match.name in names
    assert r_skip.name not in names


@pytest.mark.asyncio
async def test_match_rule_kind_and_host_group(db_session, seeded_alert):
    from app.models import (
        HostGroup,
        NotificationChannel,
        NotificationChannelKind,
        RoutingRule,
        RuleKind,
        Severity,
        host_in_group,
    )
    from app.services.routing import encrypt_config, envelope_from_alert, matching_rules

    ch = NotificationChannel(
        name=f"hg-{uuid.uuid4().hex[:6]}",
        kind=NotificationChannelKind.SLACK,
        encrypted_config=encrypt_config({"webhook_url": "https://hooks.example/hg"}),
    )
    db_session.add(ch)
    await db_session.flush()

    group = HostGroup(name=f"grp-{uuid.uuid4().hex[:6]}")
    db_session.add(group)
    await db_session.flush()

    # Rule keyed on sigma + this group — alert is sigma + host not yet in group.
    r = RoutingRule(
        name=f"hgrule-{uuid.uuid4().hex[:6]}",
        min_severity=Severity.LOW,
        rule_kind=RuleKind.SIGMA,
        host_group_id=group.id,
        channel_ids=[ch.id],
    )
    db_session.add(r)
    await db_session.flush()

    env = await envelope_from_alert(db_session, seeded_alert)
    assert env.rule_kind == "sigma"

    # Before host membership: rule shouldn't match.
    out = await matching_rules(db_session, env)
    assert r.name not in {x.name for x in out}

    # Add host to group → rule should now match.
    await db_session.execute(
        host_in_group.insert().values(host_id=env.host_id, host_group_id=group.id)
    )
    await db_session.flush()
    out2 = await matching_rules(db_session, env)
    assert r.name in {x.name for x in out2}

    # Wrong rule_kind filter doesn't match.
    r.rule_kind = RuleKind.YARA
    await db_session.flush()
    out3 = await matching_rules(db_session, env)
    assert r.name not in {x.name for x in out3}


# ---------- Dispatcher integration ----------


@pytest.mark.asyncio
async def test_dispatch_slack_success(db_session, seeded_alert):
    from app.models import NotificationChannel, NotificationChannelKind, RoutingRule, Severity
    from app.services.routing import dispatch_for_alert, encrypt_config

    webhook = "https://hooks.slack.test/T000/B000/secret"
    ch = NotificationChannel(
        name=f"dsp-slack-{uuid.uuid4().hex[:6]}",
        kind=NotificationChannelKind.SLACK,
        encrypted_config=encrypt_config({"webhook_url": webhook}),
    )
    db_session.add(ch)
    await db_session.flush()
    rule = RoutingRule(
        name=f"dsp-r-{uuid.uuid4().hex[:6]}",
        min_severity=Severity.LOW,
        channel_ids=[ch.id],
    )
    db_session.add(rule)
    await db_session.flush()

    with respx.mock(assert_all_called=True) as mock:
        route = mock.post(webhook).respond(200, text="ok")
        async with httpx.AsyncClient() as client:
            succ, fail = await dispatch_for_alert(db_session, seeded_alert, client=client)
        assert succ == 1 and fail == 0
        assert route.called
        body = json.loads(route.calls[0].request.content)
        assert "Vigil alert" in body["text"]
        assert body["attachments"][0]["fields"]
        # Sanity: rendered payload references the alert.
        flat = json.dumps(body)
        assert str(seeded_alert.id) in flat


@pytest.mark.asyncio
async def test_dispatch_pagerduty_retry_on_5xx_then_success(db_session, seeded_alert):
    import app.services.routing as routing_mod
    from app.models import NotificationChannel, NotificationChannelKind, RoutingRule, Severity
    from app.services.routing import dispatch_for_alert, encrypt_config

    ch = NotificationChannel(
        name=f"pd-{uuid.uuid4().hex[:6]}",
        kind=NotificationChannelKind.PAGERDUTY,
        encrypted_config=encrypt_config({"integration_key": "pd-routing-key-xyz"}),
    )
    db_session.add(ch)
    await db_session.flush()
    rule = RoutingRule(
        name=f"pd-r-{uuid.uuid4().hex[:6]}",
        min_severity=Severity.LOW,
        channel_ids=[ch.id],
    )
    db_session.add(rule)
    await db_session.flush()

    # Tighten retry sleep so the test runs fast.
    orig = routing_mod.RETRY_BACKOFF_BASE_S
    routing_mod.RETRY_BACKOFF_BASE_S = 0.0
    try:
        with respx.mock(assert_all_called=True) as mock:
            route = mock.post("https://events.pagerduty.com/v2/enqueue")
            route.side_effect = [
                httpx.Response(503, text="overloaded"),
                httpx.Response(202, json={"status": "success"}),
            ]
            async with httpx.AsyncClient() as client:
                succ, fail = await dispatch_for_alert(
                    db_session, seeded_alert, client=client
                )
            assert succ == 1, f"expected success after retry, got fail={fail}"
            assert fail == 0
            # Two calls — one 5xx + one success.
            assert route.call_count == 2
            body = json.loads(route.calls[-1].request.content)
            assert body["routing_key"] == "pd-routing-key-xyz"
            assert body["payload"]["severity"] in ("error", "warning", "critical")
            assert body["dedup_key"] == f"vigil:{seeded_alert.id}"
    finally:
        routing_mod.RETRY_BACKOFF_BASE_S = orig


@pytest.mark.asyncio
async def test_dispatch_4xx_does_not_retry(db_session, seeded_alert):
    """Permanent 4xx should NOT consume the retry budget — log + give up."""
    import app.services.routing as routing_mod
    from app.models import NotificationChannel, NotificationChannelKind, RoutingRule, Severity
    from app.services.routing import dispatch_for_alert, encrypt_config

    webhook = "https://hooks.slack.test/bad/url"
    ch = NotificationChannel(
        name=f"4xx-{uuid.uuid4().hex[:6]}",
        kind=NotificationChannelKind.SLACK,
        encrypted_config=encrypt_config({"webhook_url": webhook}),
    )
    db_session.add(ch)
    await db_session.flush()
    rule = RoutingRule(
        name=f"4xx-r-{uuid.uuid4().hex[:6]}",
        min_severity=Severity.LOW,
        channel_ids=[ch.id],
    )
    db_session.add(rule)
    await db_session.flush()

    orig = routing_mod.RETRY_BACKOFF_BASE_S
    routing_mod.RETRY_BACKOFF_BASE_S = 0.0
    try:
        with respx.mock() as mock:
            route = mock.post(webhook).respond(404, text="bad webhook")
            async with httpx.AsyncClient() as client:
                succ, fail = await dispatch_for_alert(
                    db_session, seeded_alert, client=client
                )
            assert succ == 0 and fail == 1
            # Exactly one call — no retry on permanent 4xx.
            assert route.call_count == 1
    finally:
        routing_mod.RETRY_BACKOFF_BASE_S = orig


@pytest.mark.asyncio
async def test_dispatch_skips_disabled_channel(db_session, seeded_alert):
    from app.models import NotificationChannel, NotificationChannelKind, RoutingRule, Severity
    from app.services.routing import dispatch_for_alert, encrypt_config

    ch = NotificationChannel(
        name=f"off-{uuid.uuid4().hex[:6]}",
        kind=NotificationChannelKind.SLACK,
        encrypted_config=encrypt_config({"webhook_url": "https://hooks.example/off"}),
        enabled=False,
    )
    db_session.add(ch)
    await db_session.flush()
    rule = RoutingRule(
        name=f"off-r-{uuid.uuid4().hex[:6]}",
        min_severity=Severity.LOW,
        channel_ids=[ch.id],
    )
    db_session.add(rule)
    await db_session.flush()

    async with httpx.AsyncClient() as client:
        succ, fail = await dispatch_for_alert(db_session, seeded_alert, client=client)
    # Channel is disabled → no fires, no failures.
    assert succ == 0 and fail == 0


# ---------- Fernet round-trip ----------


def test_encrypt_decrypt_round_trip():
    from app.services.routing import decrypt_config, encrypt_config

    cfg = {"webhook_url": "https://hooks.example/r", "extra": "ok"}
    blob = encrypt_config(cfg)
    assert isinstance(blob, bytes)
    # Ciphertext doesn't contain the plaintext.
    assert b"hooks.example" not in blob
    out = decrypt_config(blob)
    assert out == cfg


def test_secret_fingerprint_stable_and_bounded():
    from app.models import NotificationChannelKind
    from app.services.routing import secret_fingerprint

    a = secret_fingerprint(
        NotificationChannelKind.SLACK, {"webhook_url": "https://hooks.example/x"}
    )
    b = secret_fingerprint(
        NotificationChannelKind.SLACK, {"webhook_url": "https://hooks.example/x"}
    )
    c = secret_fingerprint(
        NotificationChannelKind.SLACK, {"webhook_url": "https://hooks.example/y"}
    )
    assert a == b
    assert a != c
    assert len(a) == 8


# ---------- SMTP end-to-end ----------


class _Capture:
    """Minimal aiosmtpd handler that stores RCPT + message contents in
    a list the test can inspect after the send."""

    def __init__(self) -> None:
        self.messages: list[dict[str, Any]] = []

    async def handle_DATA(self, server, session, envelope):  # noqa: N802 - aiosmtpd API
        self.messages.append(
            {
                "from": envelope.mail_from,
                "rcpts": list(envelope.rcpt_tos),
                "data": envelope.content.decode("utf-8", errors="replace"),
            }
        )
        return "250 OK"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest_asyncio.fixture
async def smtp_server() -> AsyncIterator[tuple[str, int, _Capture]]:
    capture = _Capture()
    port = _free_port()
    controller = Controller(capture, hostname="127.0.0.1", port=port)
    controller.start()
    try:
        # Give the controller a tick to bind.
        await asyncio.sleep(0.05)
        yield "127.0.0.1", port, capture
    finally:
        controller.stop()


@pytest.mark.asyncio
async def test_dispatch_email_through_aiosmtpd(db_session, seeded_alert, smtp_server):
    from app.models import NotificationChannel, NotificationChannelKind, RoutingRule, Severity
    from app.services.routing import dispatch_for_alert, encrypt_config

    host, port, capture = smtp_server
    ch = NotificationChannel(
        name=f"mail-{uuid.uuid4().hex[:6]}",
        kind=NotificationChannelKind.EMAIL,
        encrypted_config=encrypt_config(
            {
                "smtp_host": host,
                "smtp_port": port,
                "from_addr": "vigil@example.test",
                "to_addr": "soc@example.test",
                "use_tls": False,
                "use_starttls": False,
            }
        ),
    )
    db_session.add(ch)
    await db_session.flush()
    rule = RoutingRule(
        name=f"mail-r-{uuid.uuid4().hex[:6]}",
        min_severity=Severity.LOW,
        channel_ids=[ch.id],
    )
    db_session.add(rule)
    await db_session.flush()

    async with httpx.AsyncClient() as client:
        succ, fail = await dispatch_for_alert(db_session, seeded_alert, client=client)
    assert succ == 1 and fail == 0, f"fail={fail}"
    assert capture.messages, "aiosmtpd received no message"
    msg = capture.messages[0]
    assert msg["from"] == "vigil@example.test"
    assert "soc@example.test" in msg["rcpts"]
    assert "route-test summary" in msg["data"]


# ---------- Routing-rule update + delete + audit -----------


@pytest.mark.asyncio
async def test_routing_rule_update_and_delete(http_client, admin_headers):
    ch = await _make_channel(
        http_client,
        admin_headers,
        name=f"rru-{uuid.uuid4().hex[:6]}",
        kind="slack",
        config={"webhook_url": "https://hooks.example/rru"},
    )
    rule = await _make_rule(
        http_client,
        admin_headers,
        name=f"rru-r-{uuid.uuid4().hex[:6]}",
        min_severity="medium",
        channel_ids=[ch["id"]],
    )
    # Patch min_severity + name.
    new_name = f"renamed-{uuid.uuid4().hex[:6]}"
    resp = await http_client.patch(
        f"/api/notifications/rules/{rule['id']}",
        json={"min_severity": "critical", "name": new_name},
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["min_severity"] == "critical"
    assert body["name"] == new_name

    # Delete.
    resp = await http_client.delete(
        f"/api/notifications/rules/{rule['id']}", headers=admin_headers
    )
    assert resp.status_code == 204
    resp = await http_client.get(
        f"/api/notifications/rules/{rule['id']}", headers=admin_headers
    )
    assert resp.status_code == 404
