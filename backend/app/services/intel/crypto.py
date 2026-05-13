"""Fernet encrypt/decrypt for intel-feed auth tokens (Phase 1 #1.9).

Operators paste a TAXII basic-auth string or custom_json Authorization
header value into the /intel UI; the API encrypts it with the
configured Fernet key before persisting. The worker decrypts at pull
time. We never log the plaintext and the audit log only ever sees the
"present / absent" boolean.

Key handling mirrors `app/services/totp.py` — pulled from
`settings.intel_encryption_key`, falls back to a deterministic dev
default so local environments stay usable, and `assert_production_secrets`
blocks boot if the dev default is still in place in non-debug mode.
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import INTEL_KEY_DEV_DEFAULT, settings


def _fernet() -> Fernet:
    key = settings.intel_encryption_key or INTEL_KEY_DEV_DEFAULT
    return Fernet(key.encode("ascii"))


def encrypt_auth(plaintext: str) -> bytes:
    """Encrypt a TAXII basic-auth string / bearer token. Empty string
    is treated as "no auth" by the caller — don't call this with one."""
    return _fernet().encrypt(plaintext.encode("utf-8"))


def decrypt_auth(blob: bytes) -> str:
    """Decrypt the persisted bytes back to the original string. Raises
    RuntimeError if the key rotated since the row was written."""
    try:
        return _fernet().decrypt(blob).decode("utf-8")
    except InvalidToken as exc:
        raise RuntimeError(
            "stored intel-feed auth could not be decrypted; "
            "VIGIL_INTEL_ENCRYPTION_KEY may have been rotated without re-entry"
        ) from exc


__all__ = ["decrypt_auth", "encrypt_auth"]
