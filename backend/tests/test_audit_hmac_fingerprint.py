"""HMAC key fingerprint helper + endpoint surface.

Review findings.md Top-20 #9: the audit verifier silently reports
chain breaks at every existing row when `VIGIL_AUDIT_HMAC_KEY` is
rotated, which looks identical to real tampering until the operator
realises what's happening. Surface a stable, non-revealing
fingerprint of the active key in both the verifier log line and
the `/api/audit/verify` response so a rotation is visually
distinguishable from a tamper event.

The fingerprint is the first 8 hex chars of sha256(key) — enough
entropy to distinguish rotations, far too little to attack the
secret itself.
"""

from __future__ import annotations

import hashlib

import pytest


def test_fingerprint_with_key_returns_first_8_hex(monkeypatch) -> None:
    import app.services.audit as audit_mod

    fake_key = b"dev-only-known-key-for-fingerprint-test"
    monkeypatch.setattr(audit_mod, "_HMAC_KEY", fake_key)

    expected = hashlib.sha256(fake_key).hexdigest()[:8]
    assert audit_mod.hmac_key_fingerprint() == expected
    assert len(audit_mod.hmac_key_fingerprint() or "") == 8


def test_fingerprint_returns_none_when_chain_dormant(monkeypatch) -> None:
    import app.services.audit as audit_mod

    monkeypatch.setattr(audit_mod, "_HMAC_KEY", None)
    assert audit_mod.hmac_key_fingerprint() is None


def test_fingerprint_changes_with_key_rotation(monkeypatch) -> None:
    """The whole point — operator rotates the key, the fingerprint
    moves, the difference is the trip-wire for 'this is a rotation,
    not tampering'."""
    import app.services.audit as audit_mod

    monkeypatch.setattr(audit_mod, "_HMAC_KEY", b"k1")
    fp1 = audit_mod.hmac_key_fingerprint()
    monkeypatch.setattr(audit_mod, "_HMAC_KEY", b"k2")
    fp2 = audit_mod.hmac_key_fingerprint()
    assert fp1 != fp2


@pytest.mark.asyncio
async def test_verify_endpoint_includes_key_fingerprint(
    http_client, admin_headers, monkeypatch
) -> None:
    import app.services.audit as audit_mod

    monkeypatch.setattr(audit_mod, "_HMAC_KEY", b"endpoint-test-key")

    resp = await http_client.get("/api/audit/verify", headers=admin_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert "key_fingerprint" in body
    expected = hashlib.sha256(b"endpoint-test-key").hexdigest()[:8]
    assert body["key_fingerprint"] == expected


@pytest.mark.asyncio
async def test_verify_endpoint_reports_null_fingerprint_when_dormant(
    http_client, admin_headers, monkeypatch
) -> None:
    import app.services.audit as audit_mod

    monkeypatch.setattr(audit_mod, "_HMAC_KEY", None)
    resp = await http_client.get("/api/audit/verify", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["key_fingerprint"] is None
