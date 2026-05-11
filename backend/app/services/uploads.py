"""HMAC-signed upload tokens for the agent → manager artifact proxy.

The manager hands an agent a short-lived token bound to a specific
(run_id, bucket, object_key, expires_at) tuple. The agent PUTs the
artifact body to the manager's REST surface with this token in a
header; the manager validates and then writes to MinIO using its own
credentials. Avoids exposing MinIO directly to the agent network.

Tokens are stateless: a single HMAC-SHA256 over the canonical fields
keyed off settings.jwt_secret. That key is already required to be
strong (>=16 chars) and rotates the same way every other token does.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from app.core.config import settings

_TOKEN_PREFIX = "vau1"  # vigil-artifact-upload v1


@dataclass(frozen=True)
class UploadClaim:
    run_id: UUID
    bucket: str
    object_key: str
    expires_at: datetime


def issue_upload_token(
    *, run_id: UUID, bucket: str, object_key: str, ttl_seconds: int | None = None
) -> tuple[str, datetime]:
    """Return (token, expires_at).

    Token format: `vau1.<b64(payload)>.<b64(hmac)>` where payload is
    the run_id|bucket|object_key|expires_unix tuple separated by `|`.
    """
    ttl = ttl_seconds or settings.upload_token_ttl_seconds
    expires_at = datetime.now(UTC) + timedelta(seconds=ttl)
    payload = _canonical(run_id, bucket, object_key, expires_at)
    sig = hmac.new(_key(), payload.encode("utf-8"), hashlib.sha256).digest()
    token = ".".join(
        [
            _TOKEN_PREFIX,
            _b64(payload.encode("utf-8")),
            _b64(sig),
        ]
    )
    return token, expires_at


def verify_upload_token(token: str) -> UploadClaim | None:
    """Validate `token` and return the claim, or None on any failure."""
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != _TOKEN_PREFIX:
        return None
    try:
        payload_bytes = _b64_decode(parts[1])
        sig_bytes = _b64_decode(parts[2])
    except (ValueError, TypeError):
        return None
    expected = hmac.new(_key(), payload_bytes, hashlib.sha256).digest()
    if not hmac.compare_digest(sig_bytes, expected):
        return None
    try:
        payload = payload_bytes.decode("utf-8")
        run_id_s, bucket, object_key, expires_unix_s = payload.split("|", 3)
        expires_at = datetime.fromtimestamp(int(expires_unix_s), tz=UTC)
    except (ValueError, OverflowError):
        return None
    if expires_at < datetime.now(UTC):
        return None
    try:
        run_id = UUID(run_id_s)
    except ValueError:
        return None
    return UploadClaim(
        run_id=run_id,
        bucket=bucket,
        object_key=object_key,
        expires_at=expires_at,
    )


def _canonical(run_id: UUID, bucket: str, object_key: str, expires_at: datetime) -> str:
    return f"{run_id}|{bucket}|{object_key}|{int(expires_at.timestamp())}"


def _key() -> bytes:
    # Re-use the JWT secret — both are about manager-internal
    # signatures and rotate together.
    return settings.jwt_secret.encode("utf-8")


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)
