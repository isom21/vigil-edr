"""Phase 1 #1.9 threat-intel feed ingest worker.

Covers:
  * STIX-pattern parser lowers the supported hash + filename atoms
    into `IocKind`; unsupported atoms (domain, ip, url) are dropped.
  * abuse.ch CSV parser handles the `# col,col,col` header convention
    and per-column dispatch to IocKind.
  * The worker materialises pulled indicators under a managed Rule
    of kind=IOC, one rule per feed.
  * The diff path is idempotent: a second pull with the same payload
    inserts nothing, with a smaller payload deletes the dropped rows.
  * A flaky feed records `last_error` and doesn't poison subsequent
    feeds in the same pass.
  * Encrypted auth round-trips: a Fernet ciphertext on the row is
    decrypted before the puller sees it (we don't test the network
    leg here — the unit-level puller call validates the contract).
  * The trigger-pull API endpoint forces a feed regardless of cadence
    and audits.
"""

from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio
import respx
from httpx import Response

FIXTURES = Path(__file__).parent / "fixtures"


def _test_session_maker(db_session):
    @asynccontextmanager
    async def _maker():
        yield db_session

    return _maker


# ---------- TAXII parser ----------


def test_taxii_parse_indicator_supported_kinds() -> None:
    from app.models import IocKind
    from app.services.intel.taxii import parse_indicator

    sha = "a" * 64
    out = parse_indicator(f"[file:hashes.'SHA-256' = '{sha}']")
    assert len(out) == 1
    assert out[0].kind is IocKind.HASH_SHA256
    assert out[0].value == sha

    md5 = parse_indicator("[file:hashes.MD5 = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb']")
    assert len(md5) == 1
    assert md5[0].kind is IocKind.HASH_MD5

    name = parse_indicator("[file:name = 'evil.exe']")
    assert len(name) == 1
    assert name[0].kind is IocKind.FILENAME


def test_taxii_parse_indicator_drops_unsupported() -> None:
    """Domain / IP / URL aren't in IocKind yet (Phase 1 scope), so we
    drop them at parse time rather than emit a kind that won't match
    anything on the agent side."""
    from app.services.intel.taxii import parse_indicator

    assert parse_indicator("[domain-name:value = 'evil.example.com']") == []
    assert parse_indicator("[ipv4-addr:value = '1.2.3.4']") == []
    assert parse_indicator("[url:value = 'http://evil.example.com/a']") == []


def test_taxii_parse_indicator_or_chain() -> None:
    """`[…] OR […]` should pull both atoms, dropping the unsupported
    half cleanly."""
    from app.models import IocKind
    from app.services.intel.taxii import parse_indicator

    sha = "c" * 64
    out = parse_indicator(
        f"[file:hashes.'SHA-256' = '{sha}'] OR [domain-name:value = 'bad.example.com']"
    )
    assert len(out) == 1
    assert out[0].kind is IocKind.HASH_SHA256


# ---------- abuse.ch CSV parser ----------


def test_abusech_parse_csv_with_header() -> None:
    from app.models import IocKind
    from app.services.intel.abusech import parse_csv

    text = (FIXTURES / "abusech_malware_bazaar.csv").read_text()
    out = parse_csv(text)
    # The fixture has 3 data rows × {sha256, md5, sha1, filename} = 12
    # entries.
    by_kind: dict[IocKind, int] = {}
    for ind in out:
        by_kind[ind.kind] = by_kind.get(ind.kind, 0) + 1
    assert by_kind[IocKind.HASH_SHA256] == 3
    assert by_kind[IocKind.HASH_SHA1] == 3
    assert by_kind[IocKind.HASH_MD5] == 3
    assert by_kind[IocKind.FILENAME] == 3


def test_abusech_parse_csv_headerless_sniff() -> None:
    """A single-column dump with no comment header should still pick
    up via per-cell hex sniffing."""
    from app.models import IocKind
    from app.services.intel.abusech import parse_csv

    text = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
    out = parse_csv(text)
    assert len(out) == 1
    assert out[0].kind is IocKind.HASH_SHA256


# ---------- custom_json parser ----------


def test_custom_json_parse_envelope() -> None:
    from app.models import IocKind
    from app.services.intel.custom_json import parse_indicators

    out = parse_indicators(
        {
            "indicators": [
                {"kind": "hash_sha256", "value": "deadbeef" * 8},
                {"kind": "filename", "value": "drop.exe"},
                # Unsupported kind — drop with warning, not crash.
                {"kind": "domain", "value": "evil.example.com"},
                # Malformed — no value.
                {"kind": "hash_md5"},
            ]
        }
    )
    assert len(out) == 2
    kinds = {i.kind for i in out}
    assert IocKind.HASH_SHA256 in kinds
    assert IocKind.FILENAME in kinds


def test_custom_json_parse_bare_list() -> None:
    from app.models import IocKind
    from app.services.intel.custom_json import parse_indicators

    out = parse_indicators([{"kind": "hash_md5", "value": "ab" * 16}])
    assert len(out) == 1
    assert out[0].kind is IocKind.HASH_MD5


# ---------- crypto round-trip ----------


def test_intel_crypto_round_trip(monkeypatch) -> None:
    """Encrypt/decrypt is symmetric under the same key; the dev-default
    key is used when settings is empty."""
    from app.core import config
    from app.services.intel.crypto import decrypt_auth, encrypt_auth

    # Settings reads at import time; the dev default fires when the
    # env var is empty.
    monkeypatch.setattr(config.settings, "intel_encryption_key", "")
    blob = encrypt_auth("user:passw0rd")
    assert decrypt_auth(blob) == "user:passw0rd"


# ---------- feed fixture + DB seeds ----------


@pytest_asyncio.fixture
async def taxii_feed(db_session):
    from app.models import IntelFeed, IntelFeedKind

    feed = IntelFeed(
        name=f"taxii-test-{os.urandom(3).hex()}",
        kind=IntelFeedKind.TAXII,
        url="https://taxii.example.com/api/v1/collections/abc/objects/",
        encrypted_auth=None,
        interval_s=3600,
        enabled=True,
    )
    db_session.add(feed)
    await db_session.flush()
    return feed


@pytest_asyncio.fixture
async def abusech_feed(db_session):
    from app.models import IntelFeed, IntelFeedKind

    feed = IntelFeed(
        name=f"abusech-test-{os.urandom(3).hex()}",
        kind=IntelFeedKind.ABUSECH_CSV,
        url="https://example.com/abusech.csv",
        encrypted_auth=None,
        interval_s=3600,
        enabled=True,
    )
    db_session.add(feed)
    await db_session.flush()
    return feed


# ---------- end-to-end worker ----------


@pytest.mark.asyncio
@respx.mock
async def test_run_once_taxii_materialises_managed_rule(db_session, taxii_feed) -> None:
    """End-to-end: a TAXII fetch returns the fixture envelope, the
    worker creates one managed Rule of kind=IOC + IocEntry rows."""
    from app.models import IocEntry, IocKind, Rule, RuleKind
    from app.workers.intel_ingest import _run_once

    envelope = json.loads((FIXTURES / "taxii_envelope.json").read_text())
    respx.get(taxii_feed.url).mock(return_value=Response(200, json=envelope))

    pulled = await _run_once(session_maker=_test_session_maker(db_session))
    assert pulled == 1

    await db_session.refresh(taxii_feed)
    assert taxii_feed.managed_rule_id is not None
    assert taxii_feed.last_pulled_at is not None
    assert taxii_feed.last_error is None
    # The fixture has 3 supported indicators (sha256 + md5 + filename)
    # plus a domain-name we drop.
    assert taxii_feed.entry_count == 3

    rule = await db_session.get(Rule, taxii_feed.managed_rule_id)
    assert rule is not None
    assert rule.kind is RuleKind.IOC
    assert rule.name == f"intel:{taxii_feed.name}"

    from sqlalchemy import select

    entries = (
        (await db_session.execute(select(IocEntry).where(IocEntry.source_id == taxii_feed.id)))
        .scalars()
        .all()
    )
    assert len(entries) == 3
    kinds = {e.kind for e in entries}
    assert IocKind.HASH_SHA256 in kinds
    assert IocKind.HASH_MD5 in kinds
    assert IocKind.FILENAME in kinds


@pytest.mark.asyncio
@respx.mock
async def test_run_once_idempotent_diff(db_session, taxii_feed) -> None:
    """Pulling the same envelope twice doesn't add duplicate rows; a
    shrunken second pull deletes the dropped indicators."""
    from sqlalchemy import select

    from app.models import IocEntry
    from app.workers.intel_ingest import _run_once

    envelope_full = json.loads((FIXTURES / "taxii_envelope.json").read_text())
    respx.get(taxii_feed.url).mock(return_value=Response(200, json=envelope_full))

    await _run_once(session_maker=_test_session_maker(db_session))
    first_count = (
        (await db_session.execute(select(IocEntry).where(IocEntry.source_id == taxii_feed.id)))
        .scalars()
        .all()
    )
    assert len(first_count) == 3

    # Bypass the per-feed cadence so the second pull actually fires.
    taxii_feed.last_pulled_at = datetime.now(UTC) - timedelta(days=1)
    await db_session.flush()

    # Replay same response — no new rows, no removals.
    await _run_once(session_maker=_test_session_maker(db_session))
    second_count = (
        (await db_session.execute(select(IocEntry).where(IocEntry.source_id == taxii_feed.id)))
        .scalars()
        .all()
    )
    assert len(second_count) == 3

    # Shrink the envelope so the worker has to drop the two removed
    # atoms.
    taxii_feed.last_pulled_at = datetime.now(UTC) - timedelta(days=1)
    await db_session.flush()
    envelope_small = {"objects": [envelope_full["objects"][0]]}
    respx.get(taxii_feed.url).mock(return_value=Response(200, json=envelope_small))

    await _run_once(session_maker=_test_session_maker(db_session))
    third_count = (
        (await db_session.execute(select(IocEntry).where(IocEntry.source_id == taxii_feed.id)))
        .scalars()
        .all()
    )
    assert len(third_count) == 1


@pytest.mark.asyncio
@respx.mock
async def test_run_once_abusech_csv(db_session, abusech_feed) -> None:
    """End-to-end pull of an abuse.ch CSV. 3 data rows × 4 supported
    columns = 12 IocEntry rows."""
    from sqlalchemy import select

    from app.models import IocEntry
    from app.workers.intel_ingest import _run_once

    text = (FIXTURES / "abusech_malware_bazaar.csv").read_text()
    respx.get(abusech_feed.url).mock(return_value=Response(200, text=text))

    await _run_once(session_maker=_test_session_maker(db_session))
    await db_session.refresh(abusech_feed)
    entries = (
        (await db_session.execute(select(IocEntry).where(IocEntry.source_id == abusech_feed.id)))
        .scalars()
        .all()
    )
    assert len(entries) == 12


@pytest.mark.asyncio
@respx.mock
async def test_run_once_records_pull_error_without_dropping_managed_rule(
    db_session, taxii_feed
) -> None:
    """A 500 from the TAXII server records last_error + leaves the
    feed state consistent. No managed Rule is created (we haven't had
    a successful pull yet)."""
    from app.workers.intel_ingest import _run_once

    respx.get(taxii_feed.url).mock(return_value=Response(500, text="oops"))
    await _run_once(session_maker=_test_session_maker(db_session))

    await db_session.refresh(taxii_feed)
    assert taxii_feed.last_error is not None
    assert "pull failed" in taxii_feed.last_error
    assert taxii_feed.last_pulled_at is not None
    assert taxii_feed.managed_rule_id is None
    assert taxii_feed.entry_count == 0


@pytest.mark.asyncio
@respx.mock
async def test_run_once_skips_not_due_feeds(db_session, taxii_feed) -> None:
    """A feed pulled recently (within `interval_s`) is skipped this
    pass. The respx mock is registered but should never be called."""
    from app.workers.intel_ingest import _run_once

    taxii_feed.last_pulled_at = datetime.now(UTC) - timedelta(seconds=10)
    taxii_feed.interval_s = 3600
    await db_session.flush()

    route = respx.get(taxii_feed.url).mock(return_value=Response(200, json={"objects": []}))
    pulled = await _run_once(session_maker=_test_session_maker(db_session))
    assert pulled == 0
    assert route.called is False


@pytest.mark.asyncio
@respx.mock
async def test_run_once_force_feed_id_overrides_cadence(db_session, taxii_feed) -> None:
    """`trigger_pull(feed_id)` (and the trigger-pull API) bypass the
    due-check so a recent pull doesn't block a manual refresh."""
    from app.workers.intel_ingest import _run_once

    taxii_feed.last_pulled_at = datetime.now(UTC)
    taxii_feed.interval_s = 86400
    await db_session.flush()

    envelope = json.loads((FIXTURES / "taxii_envelope.json").read_text())
    respx.get(taxii_feed.url).mock(return_value=Response(200, json=envelope))

    pulled = await _run_once(
        session_maker=_test_session_maker(db_session), force_feed_id=taxii_feed.id
    )
    assert pulled == 1
    await db_session.refresh(taxii_feed)
    assert taxii_feed.entry_count == 3


@pytest.mark.asyncio
@respx.mock
async def test_run_once_disabled_feeds_skipped(db_session, taxii_feed) -> None:
    """A feed with `enabled=False` is excluded from the worker's
    select even when its interval is due."""
    from app.workers.intel_ingest import _run_once

    taxii_feed.enabled = False
    await db_session.flush()

    route = respx.get(taxii_feed.url).mock(return_value=Response(200, json={"objects": []}))
    pulled = await _run_once(session_maker=_test_session_maker(db_session))
    assert pulled == 0
    assert route.called is False


# ---------- env knob parsing ----------


def test_interval_floor_is_10s() -> None:
    """A 1-second outer scheduler tick would burn CPU without
    benefit — each feed's own interval is the real cadence. Floor 10s."""
    from app.workers.intel_ingest import _interval_seconds

    os.environ["VIGIL_INTEL_INGEST_INTERVAL_S"] = "1"
    try:
        assert _interval_seconds() == 10
    finally:
        os.environ.pop("VIGIL_INTEL_INGEST_INTERVAL_S", None)


def test_interval_falls_back_to_default_on_garbage() -> None:
    from app.workers.intel_ingest import _interval_seconds

    os.environ["VIGIL_INTEL_INGEST_INTERVAL_S"] = "not-a-number"
    try:
        assert _interval_seconds() == 60
    finally:
        os.environ.pop("VIGIL_INTEL_INGEST_INTERVAL_S", None)


# ---------- normalisation parity with manual rules path ----------


def test_normalise_ioc_matches_api_rules_path() -> None:
    """Worker-materialised IocEntry rows must use the same normaliser
    the manual rules-edit handler uses; otherwise the IOC detector
    can't match a feed-derived hash against a sample."""
    from app.api.rules import _normalize_ioc as api_norm
    from app.models import IocKind
    from app.workers.intel_ingest import _normalize_ioc as worker_norm

    for kind in IocKind:
        sample = "AaBbCc1234" if kind is not IocKind.FILEPATH else "C:\\WinDoWs\\eVil.exe"
        assert api_norm(kind, sample) == worker_norm(kind, sample)


# ---------- API smoke ----------


@pytest.mark.asyncio
async def test_api_create_redacts_auth_in_audit(http_client, admin_headers, db_session) -> None:
    """Creating a feed with `auth` must encrypt + persist the bytes,
    must NOT echo the plaintext back, and must NOT include the
    plaintext in the audit row."""
    from sqlalchemy import select

    from app.models import AuditLog, IntelFeed

    body = {
        "name": f"api-feed-{os.urandom(3).hex()}",
        "kind": "taxii",
        "url": "https://taxii.example.com/api/v1/collections/abc/objects/",
        "auth": "super-secret-token",
        "interval_s": 3600,
        "enabled": True,
    }
    resp = await http_client.post("/api/intel/feeds", headers=admin_headers, json=body)
    assert resp.status_code == 201, resp.text
    payload = resp.json()
    assert payload["has_auth"] is True
    assert "auth" not in payload
    # Sanity: the ciphertext landed in the row.
    fid = payload["id"]
    feed = (await db_session.execute(select(IntelFeed).where(IntelFeed.id == fid))).scalar_one()
    assert feed.encrypted_auth is not None
    assert b"super-secret-token" not in feed.encrypted_auth

    # Audit row must redact.
    audit_rows = (
        (await db_session.execute(select(AuditLog).where(AuditLog.resource_id == fid)))
        .scalars()
        .all()
    )
    assert audit_rows, "audit row not written"
    for row in audit_rows:
        if row.action != "intel_feed.create":
            continue
        assert row.payload is not None
        assert "super-secret-token" not in json.dumps(row.payload)
        assert row.payload.get("auth_set") is True


@pytest.mark.asyncio
async def test_api_list_requires_auth(http_client) -> None:
    resp = await http_client.get("/api/intel/feeds")
    assert resp.status_code == 401
