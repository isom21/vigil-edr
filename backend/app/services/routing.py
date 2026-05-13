"""Alert routing service (Phase 1 #1.7).

Three responsibilities:

  1. Validate + encrypt notification-channel config blobs.
  2. Match an alert against the enabled `RoutingRule` set and return
     the channels to fire.
  3. Per-channel HTTP / SMTP dispatchers with a retry policy.

The worker that drives this (`app.workers.alert_router`) reads alerts
from Postgres (poll on `created_at`) and calls `dispatch_for_alert`.
We keep the worker thin so the matching + sending logic lives here
and is unit-testable without Kafka or PG fixtures."""

from __future__ import annotations

import asyncio
import hashlib
import json
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Any
from uuid import UUID

import httpx
import structlog
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import NOTIFICATION_KEY_DEV_DEFAULT, settings
from app.models import (
    Alert,
    Host,
    NotificationChannel,
    NotificationChannelKind,
    RoutingRule,
    Rule,
    Severity,
    host_in_group,
)

log = structlog.get_logger()


# Severity ranking — must match `Severity` enum value ordering. Lower
# index = less severe.
SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class ChannelConfigError(ValueError):
    """Raised when a channel's config blob is missing required fields
    or has the wrong shape for its kind. Bubbled up to the API as
    400."""


class ChannelDispatchError(RuntimeError):
    """A retry-exhausted failure. Logged + metric'd; the worker still
    commits the alert offset so head-of-line stalls don't block the
    rest of the queue."""


# ---------- Encryption / config validation ----------


def _fernet() -> Fernet:
    """Build a Fernet from settings.notification_encryption_key.
    Validates the key shape lazily so a missing key only fails when
    routing is actually exercised, not at import time."""
    key = settings.notification_encryption_key or NOTIFICATION_KEY_DEV_DEFAULT
    return Fernet(key.encode("ascii"))


def encrypt_config(config: dict[str, Any]) -> bytes:
    payload = json.dumps(config, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return _fernet().encrypt(payload)


def decrypt_config(blob: bytes) -> dict[str, Any]:
    try:
        plaintext = _fernet().decrypt(blob)
    except InvalidToken as exc:
        raise RuntimeError(
            "notification-channel config could not be decrypted; "
            "VIGIL_NOTIFICATION_ENCRYPTION_KEY may have been rotated"
        ) from exc
    return json.loads(plaintext)


# Fields per kind that we treat as the secret material — used to
# compute the fingerprint surfaced in the API response and the audit
# log payload.
_SECRET_FIELDS: dict[NotificationChannelKind, tuple[str, ...]] = {
    NotificationChannelKind.SLACK: ("webhook_url",),
    NotificationChannelKind.PAGERDUTY: ("integration_key",),
    NotificationChannelKind.EMAIL: ("smtp_password", "smtp_host", "to_addr"),
}


def secret_fingerprint(kind: NotificationChannelKind, config: dict[str, Any]) -> str:
    """sha256(first-8 hex) over the secret fields, stable across
    re-encrypts of the same secret. Truncating to 8 hex chars gives
    enough entropy to spot rotation without leaking enough of the
    secret to be useful to an attacker."""
    fields = _SECRET_FIELDS.get(kind, ())
    h = hashlib.sha256()
    for f in fields:
        # Use repr so str("") and missing are distinguishable; missing
        # field shows as "None" in the digest input.
        h.update(repr(config.get(f)).encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()[:8]


def audit_payload(
    *, name: str, kind: NotificationChannelKind, config: dict[str, Any], enabled: bool
) -> dict[str, Any]:
    """Audit-log-safe payload — secrets replaced with their fingerprint.

    Never include plaintext webhook URLs / integration keys / SMTP
    passwords in the audit row. The fingerprint is enough for "did
    operator X rotate channel Y on date Z?" without leaking the
    rotated value itself."""
    return {
        "name": name,
        "kind": kind.value,
        "enabled": enabled,
        "secret_fingerprint": secret_fingerprint(kind, config),
        "redacted": True,
    }


def validate_config(kind: NotificationChannelKind, config: dict[str, Any]) -> None:
    """Reject malformed config blobs at the API boundary.

    Loose-shape OK: extra keys are tolerated (forward-compat with new
    optional fields). Required keys per kind:
      slack:     webhook_url (https://…)
      pagerduty: integration_key (string)
      email:     smtp_host, smtp_port (int), from_addr, to_addr
                 (smtp_user, smtp_password, use_tls, subject_template
                  are optional)
    """
    if kind is NotificationChannelKind.SLACK:
        url = config.get("webhook_url")
        if not isinstance(url, str) or not url.startswith(("https://", "http://")):
            raise ChannelConfigError(
                "slack channel: 'webhook_url' must be an http(s) URL"
            )
    elif kind is NotificationChannelKind.PAGERDUTY:
        key = config.get("integration_key")
        if not isinstance(key, str) or not key.strip():
            raise ChannelConfigError(
                "pagerduty channel: 'integration_key' must be a non-empty string"
            )
    elif kind is NotificationChannelKind.EMAIL:
        host = config.get("smtp_host")
        port = config.get("smtp_port")
        from_addr = config.get("from_addr")
        to_addr = config.get("to_addr")
        if not isinstance(host, str) or not host.strip():
            raise ChannelConfigError("email channel: 'smtp_host' is required")
        if not isinstance(port, int) or not (0 < port < 65536):
            raise ChannelConfigError(
                "email channel: 'smtp_port' must be an integer 1..65535"
            )
        if not isinstance(from_addr, str) or "@" not in from_addr:
            raise ChannelConfigError(
                "email channel: 'from_addr' must be a valid email address"
            )
        if not isinstance(to_addr, str) or "@" not in to_addr:
            raise ChannelConfigError(
                "email channel: 'to_addr' must be a valid email address"
            )
    else:  # pragma: no cover - exhaustive
        raise ChannelConfigError(f"unknown channel kind: {kind!r}")


# ---------- Matching ----------


@dataclass(frozen=True)
class AlertEnvelope:
    """The slice of an alert the matcher / dispatcher needs. Built
    from an `Alert` ORM row (+ optional host + rule) once per fire."""

    alert_id: UUID
    severity: Severity
    rule_id: UUID
    rule_kind: str | None  # str so callers don't need to import RuleKind
    rule_name: str | None
    host_id: UUID | None
    host_hostname: str | None
    summary: str
    details: dict[str, Any] | None


def _severity_at_least(actual: Severity, minimum: Severity) -> bool:
    return SEVERITY_ORDER[actual] >= SEVERITY_ORDER[minimum]


async def matching_rules(
    db: AsyncSession, envelope: AlertEnvelope
) -> list[RoutingRule]:
    """Return enabled routing rules that match this envelope. Pure
    SQLAlchemy + a single membership probe per rule with a
    host_group_id filter."""
    stmt = select(RoutingRule).where(RoutingRule.enabled.is_(True))
    rules = list((await db.execute(stmt)).scalars().all())

    matched: list[RoutingRule] = []
    for r in rules:
        # severity floor
        if not _severity_at_least(envelope.severity, r.min_severity):
            continue
        # rule_kind filter
        if r.rule_kind is not None and envelope.rule_kind != r.rule_kind.value:
            continue
        # host group scoping
        if r.host_group_id is not None:
            if envelope.host_id is None:
                continue
            in_group = (
                await db.execute(
                    select(host_in_group.c.host_id).where(
                        host_in_group.c.host_group_id == r.host_group_id,
                        host_in_group.c.host_id == envelope.host_id,
                    )
                )
            ).first()
            if in_group is None:
                continue
        if not r.channel_ids:
            continue
        matched.append(r)
    return matched


async def envelope_from_alert(db: AsyncSession, alert: Alert) -> AlertEnvelope:
    host_hostname: str | None = None
    if alert.host_id is not None:
        host = await db.get(Host, alert.host_id)
        host_hostname = host.hostname if host is not None else None
    rule = await db.get(Rule, alert.rule_id)
    return AlertEnvelope(
        alert_id=alert.id,
        severity=alert.severity,
        rule_id=alert.rule_id,
        rule_kind=rule.kind.value if rule is not None else None,
        rule_name=rule.name if rule is not None else None,
        host_id=alert.host_id,
        host_hostname=host_hostname,
        summary=alert.summary,
        details=alert.details,
    )


# ---------- Per-channel senders ----------


# Retry policy. Worker logs + commits past this — we trade a missed
# alert for a stalled queue.
RETRY_ATTEMPTS = 3
RETRY_BACKOFF_BASE_S = 0.5


def _slack_body(envelope: AlertEnvelope) -> dict[str, Any]:
    color_by_sev = {
        Severity.INFO: "#9aa0a6",
        Severity.LOW: "#3b82f6",
        Severity.MEDIUM: "#facc15",
        Severity.HIGH: "#fb923c",
        Severity.CRITICAL: "#ef4444",
    }
    host = envelope.host_hostname or "system"
    rule = envelope.rule_name or str(envelope.rule_id)
    return {
        "text": f"Vigil alert: {envelope.summary}",
        "attachments": [
            {
                "color": color_by_sev.get(envelope.severity, "#9aa0a6"),
                "title": envelope.summary,
                "fields": [
                    {"title": "Severity", "value": envelope.severity.value, "short": True},
                    {"title": "Host", "value": host, "short": True},
                    {"title": "Rule", "value": rule, "short": False},
                    {"title": "Alert ID", "value": str(envelope.alert_id), "short": False},
                ],
            }
        ],
    }


async def _slack_post(
    client: httpx.AsyncClient,
    webhook_url: str,
    envelope: AlertEnvelope,
) -> None:
    resp = await client.post(webhook_url, json=_slack_body(envelope), timeout=10.0)
    # Slack returns 200 with body "ok" on success. Any 4xx is permanent
    # (bad URL, revoked webhook); 5xx is transient and worth retrying.
    if 500 <= resp.status_code < 600:
        raise ChannelDispatchError(f"slack 5xx: status={resp.status_code}")
    if resp.status_code >= 400:
        # Permanent — log + give up immediately (no retry).
        raise ChannelDispatchError(
            f"slack permanent failure status={resp.status_code} body={resp.text[:200]}"
        )


def _pagerduty_body(envelope: AlertEnvelope, integration_key: str) -> dict[str, Any]:
    sev_map = {
        Severity.INFO: "info",
        Severity.LOW: "info",
        Severity.MEDIUM: "warning",
        Severity.HIGH: "error",
        Severity.CRITICAL: "critical",
    }
    return {
        "routing_key": integration_key,
        "event_action": "trigger",
        # dedup_key keeps repeated fires for the same alert collapsing
        # into one PagerDuty incident — exactly what an operator wants
        # if our retry path ever double-posts.
        "dedup_key": f"vigil:{envelope.alert_id}",
        "payload": {
            "summary": envelope.summary,
            "severity": sev_map.get(envelope.severity, "warning"),
            "source": envelope.host_hostname or "vigil-edr",
            "component": "alert-router",
            "class": envelope.rule_kind or "alert",
            "custom_details": {
                "rule_id": str(envelope.rule_id),
                "rule_name": envelope.rule_name,
                "alert_id": str(envelope.alert_id),
                "host_id": str(envelope.host_id) if envelope.host_id else None,
                "details": envelope.details,
            },
        },
    }


async def _pagerduty_post(
    client: httpx.AsyncClient,
    integration_key: str,
    envelope: AlertEnvelope,
) -> None:
    # PagerDuty Events v2 endpoint.
    resp = await client.post(
        "https://events.pagerduty.com/v2/enqueue",
        json=_pagerduty_body(envelope, integration_key),
        timeout=10.0,
    )
    if 500 <= resp.status_code < 600:
        raise ChannelDispatchError(f"pagerduty 5xx: status={resp.status_code}")
    if resp.status_code >= 400:
        raise ChannelDispatchError(
            f"pagerduty permanent failure status={resp.status_code} body={resp.text[:200]}"
        )


def _format_email(envelope: AlertEnvelope, config: dict[str, Any]) -> EmailMessage:
    subject_tpl = config.get("subject_template") or "[Vigil][{severity}] {summary}"
    fields = {
        "severity": envelope.severity.value,
        "summary": envelope.summary,
        "rule_name": envelope.rule_name or "",
        "host": envelope.host_hostname or "system",
        "alert_id": str(envelope.alert_id),
    }
    try:
        subject = subject_tpl.format(**fields)
    except Exception:
        # Bad operator template — fall back to a safe default so we
        # still fire instead of dropping the alert.
        subject = f"[Vigil][{envelope.severity.value}] {envelope.summary}"

    body_lines = [
        f"Alert: {envelope.summary}",
        f"Severity: {envelope.severity.value}",
        f"Rule: {envelope.rule_name or envelope.rule_id}",
        f"Host: {envelope.host_hostname or '(system)'}",
        f"Alert ID: {envelope.alert_id}",
    ]
    if envelope.details:
        body_lines.append("")
        body_lines.append("Details:")
        try:
            body_lines.append(json.dumps(envelope.details, indent=2, sort_keys=True))
        except Exception:
            body_lines.append(repr(envelope.details))

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = config["from_addr"]
    msg["To"] = config["to_addr"]
    msg.set_content("\n".join(body_lines))
    return msg


def _smtp_send_sync(config: dict[str, Any], msg: EmailMessage) -> None:
    """Synchronous SMTP send — invoked from a thread by `_email_send`.

    Uses stdlib smtplib (sync). aiosmtplib is available for future
    refactor; sync send in a worker thread is correct for the volume
    Phase 1 expects (one fire per alert × number of email channels)
    and avoids a third async TLS stack in the deps."""
    host = config["smtp_host"]
    port = int(config["smtp_port"])
    use_tls = bool(config.get("use_tls", port == 465))
    use_starttls = bool(config.get("use_starttls", port == 587))
    user = config.get("smtp_user")
    password = config.get("smtp_password")
    timeout = float(config.get("timeout_s", 10.0))

    context = ssl.create_default_context()
    if use_tls:
        with smtplib.SMTP_SSL(host, port, timeout=timeout, context=context) as srv:
            if user and password:
                srv.login(user, password)
            srv.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=timeout) as srv:
            if use_starttls:
                srv.starttls(context=context)
            if user and password:
                srv.login(user, password)
            srv.send_message(msg)


async def _email_send(config: dict[str, Any], envelope: AlertEnvelope) -> None:
    msg = _format_email(envelope, config)
    try:
        await asyncio.to_thread(_smtp_send_sync, config, msg)
    except Exception as exc:
        raise ChannelDispatchError(f"smtp send failed: {exc}") from exc


async def _send_with_retry(
    channel: NotificationChannel,
    config: dict[str, Any],
    envelope: AlertEnvelope,
    *,
    client: httpx.AsyncClient,
) -> bool:
    """Run the per-kind dispatcher up to RETRY_ATTEMPTS times with
    exponential backoff. Returns True on success, False after all
    retries are exhausted. The caller decides whether to keep the
    Kafka / poll offset paused on False."""
    last_err: Exception | None = None
    for attempt in range(1, RETRY_ATTEMPTS + 1):
        try:
            if channel.kind is NotificationChannelKind.SLACK:
                await _slack_post(client, config["webhook_url"], envelope)
            elif channel.kind is NotificationChannelKind.PAGERDUTY:
                await _pagerduty_post(client, config["integration_key"], envelope)
            elif channel.kind is NotificationChannelKind.EMAIL:
                await _email_send(config, envelope)
            else:
                raise ChannelDispatchError(f"unknown channel kind {channel.kind}")
            return True
        except ChannelDispatchError as exc:
            last_err = exc
            # Permanent? Stop retrying. "permanent failure" substring
            # is how _slack_post / _pagerduty_post mark non-5xx errors.
            if "permanent failure" in str(exc):
                break
        except Exception as exc:  # network errors, timeouts, etc.
            last_err = exc
        if attempt < RETRY_ATTEMPTS:
            backoff = RETRY_BACKOFF_BASE_S * (2 ** (attempt - 1))
            log.warning(
                "alert_router.retry",
                channel_id=str(channel.id),
                channel_name=channel.name,
                kind=channel.kind.value,
                attempt=attempt,
                backoff_s=backoff,
                err=str(last_err),
            )
            await asyncio.sleep(backoff)
    log.error(
        "alert_router.dispatch_failed",
        channel_id=str(channel.id),
        channel_name=channel.name,
        kind=channel.kind.value,
        attempts=RETRY_ATTEMPTS,
        err=str(last_err),
    )
    return False


# ---------- Top-level dispatch ----------


async def dispatch_for_alert(
    db: AsyncSession,
    alert: Alert,
    *,
    client: httpx.AsyncClient | None = None,
) -> tuple[int, int]:
    """Match `alert` against routing rules and fire every selected
    channel. Returns `(succeeded, failed)` counts. Designed to be
    called once per alert by `app.workers.alert_router`; safe to call
    from tests with an injected httpx client.

    Channel-level failures are independent — a transient PagerDuty 5xx
    doesn't stop the Slack fire on the same rule. After the retry
    budget is exhausted we log + count the failure and move on."""
    envelope = await envelope_from_alert(db, alert)
    rules = await matching_rules(db, envelope)
    if not rules:
        return (0, 0)

    # Deduplicate the channel set across multiple matching rules so
    # the same Slack workspace doesn't get five copies of the same
    # alert if the operator stacks broad + narrow rules on top of
    # each other.
    channel_ids: list[UUID] = []
    seen: set[UUID] = set()
    for r in rules:
        for cid in r.channel_ids:
            if cid not in seen:
                seen.add(cid)
                channel_ids.append(cid)
    if not channel_ids:
        return (0, 0)

    channels = (
        (
            await db.execute(
                select(NotificationChannel).where(
                    NotificationChannel.id.in_(channel_ids),
                    NotificationChannel.enabled.is_(True),
                )
            )
        )
        .scalars()
        .all()
    )

    owns_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=10.0)
        owns_client = True

    # Fire channels concurrently — each channel's retry policy is
    # independent, so a transient PagerDuty 5xx shouldn't add its
    # retry-backoff time to Slack's wall-clock latency.
    async def _fire_one(ch: NotificationChannel) -> bool:
        try:
            config = decrypt_config(ch.encrypted_config)
        except Exception:
            log.exception(
                "alert_router.config_decrypt_failed",
                channel_id=str(ch.id),
                channel_name=ch.name,
            )
            return False
        ok = await _send_with_retry(ch, config, envelope, client=client)
        if ok:
            log.info(
                "alert_router.fired",
                alert_id=str(envelope.alert_id),
                channel_id=str(ch.id),
                channel_name=ch.name,
                kind=ch.kind.value,
            )
        return ok

    try:
        results = await asyncio.gather(*(_fire_one(ch) for ch in channels))
    finally:
        if owns_client:
            await client.aclose()
    succeeded = sum(1 for r in results if r)
    failed = len(results) - succeeded
    return (succeeded, failed)
