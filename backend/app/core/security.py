"""Password hashing, JWT issuance, API token hashing."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from app.core.config import settings

# Argon2id with default OWASP parameters (the lib's defaults are reasonable for 2025+).
_hasher = PasswordHasher()


def hash_password(plaintext: str) -> str:
    return _hasher.hash(plaintext)


def verify_password(plaintext: str, hashed: str) -> bool:
    try:
        _hasher.verify(hashed, plaintext)
        return True
    except VerifyMismatchError:
        return False


def password_needs_rehash(hashed: str) -> bool:
    return _hasher.check_needs_rehash(hashed)


# ---------- JWT ----------

TokenType = Literal["access", "refresh"]

# How long an mfa_pending token is valid for between /login and
# /login/2fa. Short enough that a stolen pending token expires before
# anyone could exploit it; long enough that a human typing a code
# from their phone doesn't time out.
MFA_PENDING_TTL_SECONDS = 300


def issue_jwt(
    *,
    sub: UUID,
    role: str,
    token_type: TokenType,
    tenant_id: UUID | None = None,
    is_super_admin: bool = False,
) -> str:
    """Issue an access or refresh JWT.

    Phase 3 #3.1: ``tenant_id`` + ``is_super_admin`` ride in the
    claims so the auth resolver can cross-check them against the
    user row. ``tenant_id`` is optional so legacy callers (and the
    test suite's bare ``make_jwt`` helper) keep compiling; the
    resolver falls back to the user's home tenant when the claim is
    absent. New code paths should pass it explicitly.
    """
    now = datetime.now(UTC)
    if token_type == "access":
        exp = now + timedelta(minutes=settings.jwt_access_ttl_minutes)
    else:
        exp = now + timedelta(days=settings.jwt_refresh_ttl_days)
    payload: dict[str, str | int | bool] = {
        "sub": str(sub),
        "role": role,
        "type": token_type,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "is_super_admin": is_super_admin,
    }
    if tenant_id is not None:
        payload["tenant_id"] = str(tenant_id)
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def issue_mfa_pending_jwt(*, sub: UUID) -> str:
    """Short-lived token issued after /login when the account has TOTP
    enabled. The caller exchanges it at /login/2fa for the real
    access+refresh pair after presenting a valid code. Distinct
    `type` so it can't be used as an access token by accident."""
    now = datetime.now(UTC)
    exp = now + timedelta(seconds=MFA_PENDING_TTL_SECONDS)
    payload = {
        "sub": str(sub),
        "type": "mfa_pending",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_jwt(token: str) -> dict:
    return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])


# ---------- API tokens ----------

API_TOKEN_PREFIX = "edr_"


def generate_api_token_secret() -> str:
    return secrets.token_hex(32)


def hash_api_token_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def format_api_token(token_id: UUID, secret: str) -> str:
    """Wire format: edr_<token_id_hex>_<secret_hex>"""
    return f"{API_TOKEN_PREFIX}{token_id.hex}_{secret}"


def parse_api_token(token: str) -> tuple[UUID, str] | None:
    if not token.startswith(API_TOKEN_PREFIX):
        return None
    body = token[len(API_TOKEN_PREFIX) :]
    parts = body.split("_", 1)
    if len(parts) != 2:
        return None
    try:
        return UUID(hex=parts[0]), parts[1]
    except ValueError:
        return None


# ---------- Enrollment tokens ----------


def generate_enrollment_token() -> str:
    return f"enr_{secrets.token_urlsafe(32)}"


def hash_enrollment_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
