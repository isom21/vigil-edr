"""Phase 4 #4.2: AWS CloudTrail IAM-anomaly detection.

Covers:
  * CloudTrail parser normalises Records into the detector shape and
    drops missing fields rather than crashing.
  * First sighting of a principal seeds the baseline row WITHOUT firing
    (avoids alert-on-bootstrap noise).
  * Same principal calling from a never-seen region fires a HIGH alert.
  * AWS root user ConsoleLogin fires unconditionally.
  * The config blob round-trips through Fernet (no plaintext on disk).
  * The CRUD API is admin-only for writes (analyst gets 403).
"""

from __future__ import annotations

import gzip
import io
import json
import os
import re
from contextlib import asynccontextmanager
from datetime import UTC, datetime

import httpx
import pytest
import pytest_asyncio
import respx

from app.services.encryption import decrypt_config, encrypt_config


def _test_session_maker(db_session):
    @asynccontextmanager
    async def _maker():
        yield db_session

    return _maker


@pytest_asyncio.fixture
async def cloud_source(db_session, tenant_a):
    """A registered AWS CloudTrail source bound to tenant_a, pointing at
    the synthetic ``vigil-test-trail`` bucket the respx mocks below
    answer for."""
    from app.models import CloudSource

    src = CloudSource(
        tenant_id=tenant_a.id,
        kind="aws_cloudtrail",
        name=f"trail-{os.urandom(3).hex()}",
        config_encrypted=encrypt_config(
            {
                "bucket": "vigil-test-trail",
                "prefix": "AWSLogs/",
                "region": "us-east-1",
                "aws_access_key_id": "AKIATEST",
                "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG",
            }
        ),
        enabled=True,
    )
    db_session.add(src)
    await db_session.flush()
    return src


def _list_xml(keys: list[tuple[str, str]]) -> str:
    """Build a minimal ListObjectsV2 XML response. ``keys`` is a list of
    (key, last-modified-iso) tuples."""
    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">',
        "<IsTruncated>false</IsTruncated>",
    ]
    for k, lm in keys:
        parts.append(f"<Contents><Key>{k}</Key><LastModified>{lm}</LastModified></Contents>")
    parts.append("</ListBucketResult>")
    return "".join(parts)


def _gzip_json(obj: dict) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(json.dumps(obj).encode("utf-8"))
    return buf.getvalue()


def _cloudtrail_record(
    *,
    principal_arn: str,
    region: str = "us-east-1",
    event_source: str = "s3.amazonaws.com",
    event_name: str = "GetObject",
    ts: str = "2026-05-14T12:00:00Z",
    user_type: str = "IAMUser",
    source_ip: str = "1.2.3.4",
) -> dict:
    return {
        "eventTime": ts,
        "eventSource": event_source,
        "eventName": event_name,
        "awsRegion": region,
        "sourceIPAddress": source_ip,
        "userIdentity": {"type": user_type, "arn": principal_arn},
    }


# ---------- parser ----------


def test_parse_events_shape() -> None:
    from app.services.cloud.cloudtrail import parse_events

    out = parse_events(
        {
            "Records": [
                _cloudtrail_record(principal_arn="arn:aws:iam::1:user/alice"),
                {"eventTime": "garbage"},
            ]
        }
    )
    assert len(out) == 2
    assert out[0]["principal_arn"] == "arn:aws:iam::1:user/alice"
    assert out[0]["region"] == "us-east-1"
    assert out[0]["event_source"] == "s3.amazonaws.com"
    assert out[0]["event_name"] == "GetObject"
    assert out[0]["user_type"] == "IAMUser"
    assert isinstance(out[0]["ts"], datetime)
    # Missing-field record still produces a row.
    assert out[1]["principal_arn"] == ""
    assert out[1]["ts"] is None


def test_parse_events_empty() -> None:
    from app.services.cloud.cloudtrail import parse_events

    assert parse_events({}) == []
    assert parse_events({"Records": []}) == []


# ---------- encrypted config round-trip ----------


def test_cloud_source_config_round_trip() -> None:
    """The credential pair is Fernet-encrypted on disk and decrypted only
    in-process. A malformed/rotated key surfaces as a clean exception
    rather than leaking plaintext."""
    blob = encrypt_config(
        {
            "bucket": "b",
            "prefix": "p",
            "region": "us-west-2",
            "aws_access_key_id": "AKIA",
            "aws_secret_access_key": "SECRET",
        }
    )
    assert b"SECRET" not in blob
    assert decrypt_config(blob)["aws_secret_access_key"] == "SECRET"


# ---------- detector unit tests ----------


@pytest.mark.asyncio
async def test_first_sighting_seeds_baseline_without_alerting(db_session, cloud_source) -> None:
    """First time we see a principal, the baseline row is created but no
    alert fires — every freshly-configured bucket would otherwise blow
    up the queue on the first poll."""
    from sqlalchemy import select

    from app.models import Alert, CloudBaseline
    from app.services.cloud import iam_anomaly

    event = {
        "ts": datetime(2026, 5, 14, 12, 0, tzinfo=UTC),
        "principal_arn": "arn:aws:iam::1:user/alice",
        "region": "us-east-1",
        "event_source": "s3.amazonaws.com",
        "event_name": "GetObject",
        "source_ip": "1.2.3.4",
        "error_code": None,
        "user_type": "IAMUser",
    }
    created = await iam_anomaly.detect_new_principal(
        db_session,
        tenant_id=cloud_source.tenant_id,
        source_id=cloud_source.id,
        event=event,
    )
    assert created is True
    fired_action = await iam_anomaly.detect_new_action(
        db_session,
        tenant_id=cloud_source.tenant_id,
        source_id=cloud_source.id,
        event=event,
    )
    assert fired_action is False
    fired_region = await iam_anomaly.detect_new_region(
        db_session,
        tenant_id=cloud_source.tenant_id,
        source_id=cloud_source.id,
        event=event,
    )
    assert fired_region is False
    await db_session.flush()

    baseline = (
        await db_session.execute(
            select(CloudBaseline).where(CloudBaseline.source_id == cloud_source.id)
        )
    ).scalar_one()
    assert baseline.principal_arn == "arn:aws:iam::1:user/alice"
    alerts = (await db_session.execute(select(Alert))).scalars().all()
    assert alerts == []


@pytest.mark.asyncio
async def test_same_principal_new_region_fires_alert(db_session, cloud_source) -> None:
    """Once the baseline is seeded, the same principal calling from a
    different region fires."""
    from sqlalchemy import select

    from app.models import Alert
    from app.models.synthetic_rules import CLOUD_IAM_ANOMALY_RULE_ID
    from app.services.cloud import iam_anomaly

    first = {
        "ts": datetime(2026, 5, 14, 12, 0, tzinfo=UTC),
        "principal_arn": "arn:aws:iam::1:user/alice",
        "region": "us-east-1",
        "event_source": "s3.amazonaws.com",
        "event_name": "GetObject",
        "source_ip": "1.2.3.4",
        "error_code": None,
        "user_type": "IAMUser",
    }
    await iam_anomaly.detect_new_principal(
        db_session,
        tenant_id=cloud_source.tenant_id,
        source_id=cloud_source.id,
        event=first,
    )
    await iam_anomaly.detect_new_region(
        db_session,
        tenant_id=cloud_source.tenant_id,
        source_id=cloud_source.id,
        event=first,
    )
    await db_session.flush()

    second = dict(first, region="eu-west-1")
    fired = await iam_anomaly.detect_new_region(
        db_session,
        tenant_id=cloud_source.tenant_id,
        source_id=cloud_source.id,
        event=second,
    )
    assert fired is True
    await db_session.flush()

    alerts = (await db_session.execute(select(Alert))).scalars().all()
    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule_id == CLOUD_IAM_ANOMALY_RULE_ID
    assert a.severity.value == "high"
    assert a.host_id is None
    assert a.details["reason"] == iam_anomaly.REASON_NEW_REGION
    assert a.details["region"] == "eu-west-1"
    assert a.mitre_techniques == ["T1078.004"]


@pytest.mark.asyncio
async def test_root_console_login_fires(db_session, cloud_source) -> None:
    """Root console login fires regardless of baseline state."""
    from sqlalchemy import select

    from app.models import Alert
    from app.services.cloud import iam_anomaly

    event = {
        "ts": datetime(2026, 5, 14, 12, 0, tzinfo=UTC),
        "principal_arn": "arn:aws:iam::1:root",
        "region": "us-east-1",
        "event_source": "signin.amazonaws.com",
        "event_name": "ConsoleLogin",
        "source_ip": "1.2.3.4",
        "error_code": None,
        "user_type": "Root",
    }
    fired = await iam_anomaly.detect_root_console_login(
        db_session,
        tenant_id=cloud_source.tenant_id,
        source_id=cloud_source.id,
        event=event,
    )
    assert fired is True
    await db_session.flush()

    alerts = (await db_session.execute(select(Alert))).scalars().all()
    assert len(alerts) == 1
    assert alerts[0].details["reason"] == iam_anomaly.REASON_ROOT_CONSOLE_LOGIN
    assert alerts[0].severity.value == "high"


# ---------- end-to-end worker over respx-mocked S3 ----------


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_worker_e2e_lists_fetches_and_alerts(respx_mock, db_session, cloud_source) -> None:
    """Run the worker once. The bucket lists two objects: one with a
    new principal (seed-only, no alert), one with the same principal
    from a new region (alert)."""
    from sqlalchemy import select

    from app.models import Alert
    from app.workers.cloud_iam_monitor import _run_once

    listing = _list_xml(
        [
            ("AWSLogs/seed.json.gz", "2026-05-14T12:00:00.000Z"),
            ("AWSLogs/move.json.gz", "2026-05-14T13:00:00.000Z"),
        ]
    )
    bucket_root = re.compile(r"^https://vigil-test-trail\.s3\.amazonaws\.com/(\?|$)")
    respx_mock.get(url__regex=bucket_root).mock(
        return_value=httpx.Response(200, content=listing.encode("utf-8"))
    )

    seed = {
        "Records": [
            _cloudtrail_record(
                principal_arn="arn:aws:iam::1:user/alice",
                region="us-east-1",
                ts="2026-05-14T12:00:00Z",
            )
        ]
    }
    move = {
        "Records": [
            _cloudtrail_record(
                principal_arn="arn:aws:iam::1:user/alice",
                region="eu-west-1",
                ts="2026-05-14T13:00:00Z",
            )
        ]
    }
    respx_mock.get("https://vigil-test-trail.s3.amazonaws.com/AWSLogs/seed.json.gz").mock(
        return_value=httpx.Response(200, content=_gzip_json(seed))
    )
    respx_mock.get("https://vigil-test-trail.s3.amazonaws.com/AWSLogs/move.json.gz").mock(
        return_value=httpx.Response(200, content=_gzip_json(move))
    )

    processed = await _run_once(session_maker=_test_session_maker(db_session))
    assert processed == 1

    await db_session.refresh(cloud_source)
    assert cloud_source.last_polled_at is not None
    assert cloud_source.last_event_ts is not None

    alerts = (await db_session.execute(select(Alert))).scalars().all()
    # One alert: new region. The seed event introduces the principal
    # but doesn't fire.
    assert len(alerts) == 1
    assert alerts[0].details["reason"] == "new_region_for_principal"
    assert alerts[0].details["region"] == "eu-west-1"


@pytest.mark.asyncio
@respx.mock(assert_all_called=False)
async def test_worker_isolates_failures_per_source(respx_mock, db_session, tenant_a) -> None:
    """A misconfigured bucket (S3 returns 500) records the failure on
    last_polled_at but doesn't bubble up — the worker keeps going."""
    from app.models import CloudSource
    from app.workers.cloud_iam_monitor import _run_once

    flaky = CloudSource(
        tenant_id=tenant_a.id,
        kind="aws_cloudtrail",
        name=f"flaky-{os.urandom(3).hex()}",
        config_encrypted=encrypt_config(
            {
                "bucket": "vigil-test-flaky",
                "prefix": "",
                "region": "us-east-1",
                "aws_access_key_id": "AKIA",
                "aws_secret_access_key": "S",
            }
        ),
        enabled=True,
    )
    db_session.add(flaky)
    await db_session.flush()

    respx_mock.get(url__regex=r"^https://vigil-test-flaky\.s3\.amazonaws\.com/.*").mock(
        return_value=httpx.Response(500, content=b"oops")
    )

    processed = await _run_once(session_maker=_test_session_maker(db_session))
    assert processed == 1

    await db_session.refresh(flaky)
    assert flaky.last_polled_at is not None


# ---------- API smoke ----------


@pytest.mark.asyncio
async def test_api_non_admin_cannot_create(http_client, analyst_in_a) -> None:
    """Analyst can read the list but not register a source."""
    from tests.conftest import headers_for

    body = {
        "name": "trail-x",
        "kind": "aws_cloudtrail",
        "bucket": "x-bucket",
        "prefix": "",
        "region": "us-east-1",
        "aws_access_key_id": "AKIA",
        "aws_secret_access_key": "S",
        "enabled": True,
    }
    resp = await http_client.post(
        "/api/cloud-sources", headers=headers_for(analyst_in_a), json=body
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_api_admin_create_redacts_secret(http_client, admin_in_a, db_session) -> None:
    """Create round-trips: ciphertext stored, ``has_credentials`` echoes
    True, secret never appears in the response or audit row."""
    from sqlalchemy import select

    from app.models import AuditLog, CloudSource
    from tests.conftest import headers_for

    body = {
        "name": f"trail-{os.urandom(3).hex()}",
        "kind": "aws_cloudtrail",
        "bucket": "my-bucket",
        "prefix": "AWSLogs/",
        "region": "us-east-1",
        "aws_access_key_id": "AKIAEXAMPLE",
        "aws_secret_access_key": "super-secret-aws-key-value",
        "enabled": True,
    }
    resp = await http_client.post("/api/cloud-sources", headers=headers_for(admin_in_a), json=body)
    assert resp.status_code == 201, resp.text
    payload = resp.json()
    assert payload["has_credentials"] is True
    assert "aws_secret_access_key" not in payload
    assert "super-secret-aws-key-value" not in resp.text

    src = (
        await db_session.execute(select(CloudSource).where(CloudSource.id == payload["id"]))
    ).scalar_one()
    assert b"super-secret-aws-key-value" not in src.config_encrypted

    audit_rows = (
        (await db_session.execute(select(AuditLog).where(AuditLog.resource_id == payload["id"])))
        .scalars()
        .all()
    )
    assert audit_rows, "audit row not written"
    for row in audit_rows:
        assert row.payload is None or "super-secret-aws-key-value" not in json.dumps(row.payload)
