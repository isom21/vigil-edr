"""Refuse-to-boot guard for dev-default crypto secrets.

Review MEDIUM #17: with `debug=False`, the manager must not start while
`jwt_secret` / `ca_master_key` are still at their dev defaults or
`VIGIL_AUDIT_HMAC_KEY` is unset. Without this, a production deploy that
forgets the overrides advertises tamper-evidence + JWT signing + CA
encryption that don't actually exist.

These tests build a `Settings` instance directly (no env-file parsing)
and call `assert_production_secrets()` so we don't have to round-trip
through `os.environ`.
"""

from __future__ import annotations

import pytest

from app.core.config import (
    CA_MASTER_KEY_DEV_PREFIX,
    JWT_SECRET_DEV_DEFAULT,
    TOTP_KEY_DEV_DEFAULT,
    DevSecretsInProductionError,
    Settings,
    assert_production_secrets,
)


def _good_settings(**overrides: object) -> Settings:
    base: dict[str, object] = {
        "debug": False,
        "jwt_secret": "prod-secret-rotated-from-install-sh",
        "ca_master_key": "prod-ca-master-key-rotated-32-bytes-long",
        "totp_encryption_key": "prod-totp-key-44-chars-url-safe-base64-padded==",
        "upload_token_key": "prod-upload-token-key-32-bytes-hex-not-jwt-secret",
    }
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


def test_debug_true_bypasses_check(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VIGIL_AUDIT_HMAC_KEY", raising=False)
    s = Settings(debug=True, jwt_secret=JWT_SECRET_DEV_DEFAULT)
    # No raise even though everything is at its dev default.
    assert_production_secrets(s)


def test_all_secrets_rotated_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VIGIL_AUDIT_HMAC_KEY", "0123456789abcdef" * 4)
    assert_production_secrets(_good_settings())


def test_dev_jwt_secret_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VIGIL_AUDIT_HMAC_KEY", "0123456789abcdef" * 4)
    s = _good_settings(jwt_secret=JWT_SECRET_DEV_DEFAULT)
    with pytest.raises(DevSecretsInProductionError) as exc:
        assert_production_secrets(s)
    assert "VIGIL_JWT_SECRET" in str(exc.value)


def test_dev_ca_master_key_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VIGIL_AUDIT_HMAC_KEY", "0123456789abcdef" * 4)
    s = _good_settings(ca_master_key=CA_MASTER_KEY_DEV_PREFIX + "change-me-32-bytes-long!!")
    with pytest.raises(DevSecretsInProductionError) as exc:
        assert_production_secrets(s)
    assert "VIGIL_CA_MASTER_KEY" in str(exc.value)


def test_missing_audit_hmac_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VIGIL_AUDIT_HMAC_KEY", raising=False)
    with pytest.raises(DevSecretsInProductionError) as exc:
        assert_production_secrets(_good_settings())
    assert "VIGIL_AUDIT_HMAC_KEY" in str(exc.value)


def test_empty_audit_hmac_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VIGIL_AUDIT_HMAC_KEY", "")
    with pytest.raises(DevSecretsInProductionError):
        assert_production_secrets(_good_settings())


def test_dev_totp_key_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VIGIL_AUDIT_HMAC_KEY", "0123456789abcdef" * 4)
    s = _good_settings(totp_encryption_key=TOTP_KEY_DEV_DEFAULT)
    with pytest.raises(DevSecretsInProductionError) as exc:
        assert_production_secrets(s)
    assert "VIGIL_TOTP_ENCRYPTION_KEY" in str(exc.value)


def test_missing_totp_key_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VIGIL_AUDIT_HMAC_KEY", "0123456789abcdef" * 4)
    s = _good_settings(totp_encryption_key="")
    with pytest.raises(DevSecretsInProductionError) as exc:
        assert_production_secrets(s)
    assert "VIGIL_TOTP_ENCRYPTION_KEY" in str(exc.value)


def test_missing_upload_token_key_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    # Empty VIGIL_UPLOAD_TOKEN_KEY silently falls back to jwt_secret —
    # M18's whole point was decoupling them. The refuse-boot guard
    # now catches the regression.
    monkeypatch.setenv("VIGIL_AUDIT_HMAC_KEY", "0123456789abcdef" * 4)
    s = _good_settings(upload_token_key="")
    with pytest.raises(DevSecretsInProductionError) as exc:
        assert_production_secrets(s)
    assert "VIGIL_UPLOAD_TOKEN_KEY" in str(exc.value)
    assert "M18" in str(exc.value)


def test_all_three_problems_report_together(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VIGIL_AUDIT_HMAC_KEY", raising=False)
    s = _good_settings(
        jwt_secret=JWT_SECRET_DEV_DEFAULT,
        ca_master_key=CA_MASTER_KEY_DEV_PREFIX + "change-me-32-bytes-long!!",
    )
    with pytest.raises(DevSecretsInProductionError) as exc:
        assert_production_secrets(s)
    msg = str(exc.value)
    assert "VIGIL_JWT_SECRET" in msg
    assert "VIGIL_CA_MASTER_KEY" in msg
    assert "VIGIL_AUDIT_HMAC_KEY" in msg
    # Operators should know where to look for the right values.
    assert "install.md" in msg
