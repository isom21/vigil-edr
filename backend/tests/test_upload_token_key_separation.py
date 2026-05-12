"""VIGIL_UPLOAD_TOKEN_KEY signs upload-grant HMACs, not VIGIL_JWT_SECRET.

Review MEDIUM #18: `services/uploads.py:_key()` returned
`settings.jwt_secret`, so the upload-grant HMAC and JWT signing shared
a secret. A leak of either compromised both surfaces.

`_key()` now returns `settings.upload_token_key` when set and falls
back to `settings.jwt_secret` only when unset (dev / pre-install.sh
environments).
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from app.core.config import settings
from app.services.uploads import _key, issue_upload_token, verify_upload_token


def test_key_returns_upload_token_key_when_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "upload_token_key", "upload-only-secret-32-bytes-or-more")
    monkeypatch.setattr(settings, "jwt_secret", "jwt-only-secret-different-value!")
    assert _key() == b"upload-only-secret-32-bytes-or-more"


def test_key_falls_back_to_jwt_secret_when_upload_key_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "upload_token_key", "")
    monkeypatch.setattr(settings, "jwt_secret", "fallback-jwt-secret-32-bytes-long")
    assert _key() == b"fallback-jwt-secret-32-bytes-long"


def test_round_trip_with_separate_key_works(monkeypatch: pytest.MonkeyPatch) -> None:
    # Issue + verify a token under upload_token_key alone — confirms the
    # full flow uses the new secret consistently for both sides.
    monkeypatch.setattr(settings, "upload_token_key", "upload-secret-for-round-trip-test!")
    monkeypatch.setattr(settings, "jwt_secret", "completely-different-jwt-secret-here")
    run_id = uuid4()
    token, _ = issue_upload_token(run_id=run_id, bucket="vigil-artifacts", object_key="some/path")
    claim = verify_upload_token(token)
    assert claim is not None
    assert claim.run_id == run_id
    assert claim.bucket == "vigil-artifacts"
    assert claim.object_key == "some/path"


def test_token_signed_with_jwt_secret_invalid_under_upload_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A token issued under jwt_secret (legacy mode) should NOT verify
    # once upload_token_key is set — pin that the keys are actually
    # distinct, not silently aliased.
    monkeypatch.setattr(settings, "upload_token_key", "")
    monkeypatch.setattr(settings, "jwt_secret", "issuer-secret-only")
    run_id = uuid4()
    token, _ = issue_upload_token(run_id=run_id, bucket="b", object_key="k")
    # Switch keys.
    monkeypatch.setattr(settings, "upload_token_key", "verifier-secret-different")
    monkeypatch.setattr(settings, "jwt_secret", "issuer-secret-only")
    assert verify_upload_token(token) is None
