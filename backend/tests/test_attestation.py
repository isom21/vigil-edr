"""TPM-backed boot-state attestation tests (Phase 4 #4.10).

Covers the full happy + sad path through the service layer (no proto
plumbing required for the unit tests; the gRPC handler is a thin
wrapper around `record_event`).

  * First report under no golden → ``unverified``, no alert.
  * Promote → ``AttestationGolden`` row written, recorded_by stamped.
  * Subsequent matching report → ``ok``, ``matches_golden=True``.
  * One-PCR divergence → ``diverged`` event + HIGH alert under the
    synthetic ``ATTESTATION_FAILED_RULE_ID``.
  * Bad-signature quote path (no AK cert) → ``verify_quote`` returns
    False, event still records under the unsigned-report semantics.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select


def _pcrs(index: int, bank: str = "sha256", digest_byte: int = 0x00) -> list[dict]:
    return [
        {
            "index": index,
            "bank": bank,
            "digest_hex": format(digest_byte, "02x") * 32,
        }
    ]


def _baseline_pcrs() -> list[dict]:
    return [
        {"index": 0, "bank": "sha256", "digest_hex": "00" * 32},
        {"index": 1, "bank": "sha256", "digest_hex": "11" * 32},
        {"index": 7, "bank": "sha256", "digest_hex": "77" * 32},
    ]


# ---------- Pure helpers ----------


def test_pcrs_from_pb_skips_empty_digests() -> None:
    from app.proto_gen.edr.v1 import control_pb2
    from app.services.attestation import pcrs_from_pb

    ta = control_pb2.TpmAttestation()
    p = ta.pcrs.add()
    p.index = 5
    p.bank = "sha256"
    p.digest = b"\x42" * 32
    skipped = ta.pcrs.add()
    skipped.index = 9
    skipped.bank = "sha256"
    skipped.digest = b""
    out = pcrs_from_pb(ta.pcrs)
    assert len(out) == 1
    assert out[0]["index"] == 5
    assert out[0]["digest_hex"] == "42" * 32


def test_compare_to_golden_matches() -> None:
    from app.models import AttestationGolden
    from app.services.attestation import compare_to_golden

    pcrs = _baseline_pcrs()
    golden = AttestationGolden(host_id=uuid.uuid4(), pcr_values_json=list(pcrs))
    matches, diverged = compare_to_golden(golden, pcrs)
    assert matches is True
    assert diverged == []


def test_compare_to_golden_flags_one_pcr_drift() -> None:
    from app.models import AttestationGolden
    from app.services.attestation import compare_to_golden

    pcrs = _baseline_pcrs()
    golden = AttestationGolden(host_id=uuid.uuid4(), pcr_values_json=list(pcrs))
    drifted = list(pcrs)
    drifted[2] = {"index": 7, "bank": "sha256", "digest_hex": "ff" * 32}
    matches, diverged = compare_to_golden(golden, drifted)
    assert matches is False
    assert diverged == [7]


def test_compare_to_golden_no_golden_is_unverified() -> None:
    from app.services.attestation import compare_to_golden

    matches, diverged = compare_to_golden(None, _baseline_pcrs())
    assert matches is False
    assert sorted(diverged) == [0, 1, 7]


def test_verify_quote_missing_signature_returns_false() -> None:
    from app.services.attestation import verify_quote

    assert verify_quote(b"", b"", "nonce", _baseline_pcrs()) is False
    assert verify_quote(b"\x01\x02", b"", "nonce", _baseline_pcrs()) is False


def test_verify_quote_accepts_self_signed_in_dev() -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    from app.services.attestation import verify_quote

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ak")])
    import datetime as _dt

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_dt.datetime.now(_dt.UTC))
        .not_valid_after(_dt.datetime.now(_dt.UTC) + _dt.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)
    assert verify_quote(b"sig-bytes", pem, "nonce", _baseline_pcrs()) is True


# ---------- record_event integration ----------


async def _seed_host(db_session, *, tenant_id=None):
    from app.models import Host, OsFamily

    host = Host(
        hostname=f"a-{uuid.uuid4().hex[:8]}",
        os_family=OsFamily.LINUX,
    )
    if tenant_id is not None:
        host.tenant_id = tenant_id
    db_session.add(host)
    await db_session.flush()
    return host


@pytest.mark.asyncio
async def test_record_event_unverified_when_no_golden(db_session) -> None:
    from app.models import Alert, AttestationEvent
    from app.services.attestation import record_event

    host = await _seed_host(db_session)
    pcrs = _baseline_pcrs()
    event = await record_event(db_session, host=host, current_pcrs=pcrs, golden=None)
    await db_session.flush()
    assert event.matches_golden is False
    assert sorted(event.diverged_pcrs) == [0, 1, 7]
    # No alert because no golden was promoted yet.
    alerts = (
        (await db_session.execute(select(Alert).where(Alert.host_id == host.id))).scalars().all()
    )
    assert alerts == []
    assert event.id is not None
    persisted = (
        (
            await db_session.execute(
                select(AttestationEvent).where(AttestationEvent.host_id == host.id)
            )
        )
        .scalars()
        .one()
    )
    assert persisted.id == event.id


@pytest.mark.asyncio
async def test_promote_then_match_then_diverge(db_session) -> None:
    from app.models import Alert, AttestationGolden
    from app.models.synthetic_rules import ATTESTATION_FAILED_RULE_ID
    from app.services.attestation import record_event

    host = await _seed_host(db_session)
    baseline = _baseline_pcrs()
    # Manually promote (mirrors the API path).
    golden = AttestationGolden(
        host_id=host.id, tenant_id=host.tenant_id, pcr_values_json=list(baseline)
    )
    db_session.add(golden)
    await db_session.flush()

    # Matching report — no alert, matches_golden=True.
    ok_event = await record_event(db_session, host=host, current_pcrs=list(baseline), golden=golden)
    assert ok_event.matches_golden is True
    assert ok_event.diverged_pcrs == []

    # Divergent report — HIGH alert via the synthetic rule.
    drifted = list(baseline)
    drifted[2] = {"index": 7, "bank": "sha256", "digest_hex": "ff" * 32}
    diverged_event = await record_event(db_session, host=host, current_pcrs=drifted, golden=golden)
    assert diverged_event.matches_golden is False
    assert diverged_event.diverged_pcrs == [7]

    alerts = (
        (
            await db_session.execute(
                select(Alert).where(
                    Alert.host_id == host.id,
                    Alert.rule_id == ATTESTATION_FAILED_RULE_ID,
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(alerts) == 1
    assert alerts[0].severity.value == "high"
    assert alerts[0].mitre_techniques == ["T1542"]


# ---------- API smoke ----------


@pytest.mark.asyncio
async def test_request_endpoint_queues_command(http_client, admin_headers, db_session) -> None:
    from app.models import Command, CommandKind

    host = await _seed_host(db_session)
    resp = await http_client.post(
        f"/api/hosts/{host.id}/attestation/request",
        headers=admin_headers,
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert "nonce" in body and len(body["nonce"]) == 64
    cmd = (
        (
            await db_session.execute(
                select(Command).where(
                    Command.host_id == host.id,
                    Command.kind == CommandKind.REQUEST_ATTESTATION,
                )
            )
        )
        .scalars()
        .one()
    )
    assert cmd.payload["nonce"] == body["nonce"]


@pytest.mark.asyncio
async def test_promote_400_without_events(http_client, admin_headers, db_session) -> None:
    host = await _seed_host(db_session)
    resp = await http_client.post(
        f"/api/hosts/{host.id}/attestation/promote",
        headers=admin_headers,
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_promote_then_host_detail_status_ok(http_client, admin_headers, db_session) -> None:
    from app.services.attestation import record_event

    host = await _seed_host(db_session)
    pcrs = _baseline_pcrs()
    # Pre-promote event must exist so the promote endpoint can pull it.
    await record_event(db_session, host=host, current_pcrs=pcrs, golden=None)
    await db_session.commit()

    promote = await http_client.post(
        f"/api/hosts/{host.id}/attestation/promote",
        headers=admin_headers,
    )
    assert promote.status_code == 201, promote.text
    assert len(promote.json()["pcr_values_json"]) == 3

    # Fresh matching report → status="ok"
    from app.models import AttestationGolden

    golden = await db_session.get(AttestationGolden, host.id)
    await record_event(db_session, host=host, current_pcrs=pcrs, golden=golden)
    await db_session.commit()

    detail = await http_client.get(f"/api/hosts/{host.id}", headers=admin_headers)
    assert detail.status_code == 200, detail.text
    block = detail.json()["attestation"]
    assert block["status"] == "ok"
    assert block["golden"] is not None
    assert block["latest"]["matches_golden"] is True


@pytest.mark.asyncio
async def test_events_endpoint_paginates(http_client, admin_headers, db_session) -> None:
    from app.services.attestation import record_event

    host = await _seed_host(db_session)
    for i in range(3):
        await record_event(db_session, host=host, current_pcrs=_pcrs(i, digest_byte=i), golden=None)
    await db_session.commit()
    resp = await http_client.get(
        f"/api/hosts/{host.id}/attestation/events",
        headers=admin_headers,
        params={"limit": 2},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == 3
    assert len(body["items"]) == 2
