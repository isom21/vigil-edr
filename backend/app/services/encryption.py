"""Shared Fernet helpers for at-rest config secrets (Phase 3 #3.6).

Most subsystems that store an operator-provided secret (notification
channels, SIEM destinations, intel-feed auth, case-tracker tokens)
need the same shape: serialise a dict to JSON, encrypt with the
shared Fernet key, and round-trip back through a redaction step on
the way out. The case-management service is the first caller that
piggy-backs on this module specifically; older subsystems kept their
helpers inline. New subsystems should prefer the helpers here so the
Fernet wiring lives in exactly one place.

The encryption key is `notification_encryption_key` — the operator
already provisions it for SIEM destinations + alert routing, and
re-using it means we don't add another secret to the install.sh
rotation list. The dev-default key is the same one
`services/siem/__init__.py` falls back to.
"""

from __future__ import annotations

import json
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import NOTIFICATION_KEY_DEV_DEFAULT, settings


def _fernet() -> Fernet:
    """Build the Fernet from settings.notification_encryption_key.

    Lazy so a missing key fails on first encrypt/decrypt instead of
    at import time — matters because the tests import this module
    indirectly via the API surface even without a real key set.
    """
    key = settings.notification_encryption_key or NOTIFICATION_KEY_DEV_DEFAULT
    return Fernet(key.encode("ascii"))


def encrypt_config(plaintext: dict[str, Any]) -> bytes:
    """Serialise `plaintext` to canonical JSON and Fernet-encrypt.

    `sort_keys=True` so the same logical config always produces the
    same ciphertext shape — convenient for no-op-update detection
    without decrypting first.
    """
    payload = json.dumps(plaintext, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _fernet().encrypt(payload)


def decrypt_config(blob: bytes) -> dict[str, Any]:
    """Reverse `encrypt_config`. Raises RuntimeError when the key
    rotated since the row was written — the operator must re-enter
    the destination's secrets in that case."""
    try:
        plain = _fernet().decrypt(blob)
    except InvalidToken as exc:
        raise RuntimeError(
            "stored config could not be decrypted; "
            "VIGIL_NOTIFICATION_ENCRYPTION_KEY may have been rotated"
        ) from exc
    return json.loads(plain.decode("utf-8"))


__all__ = ["decrypt_config", "encrypt_config"]
