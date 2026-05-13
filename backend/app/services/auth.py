"""Login flow: validate credentials, issue JWTs, update last_login_at."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import unauthorized
from app.core.security import (
    hash_password,
    issue_jwt,
    password_needs_rehash,
    verify_password,
)
from app.models import User


class InvalidCredentials(Exception):  # noqa: N818 — read aloud, not "error"
    """Login failed. ``reason`` is one of ``"unknown_user"``,
    ``"disabled_user"``, or ``"bad_password"`` — useful for the
    failed-login audit row (M-audit-and-auth #1) and the per-user
    throttle (M-audit-and-auth #8). Mapped to a generic 401
    ``invalid credentials`` at the HTTP boundary so the caller
    can't tell the cases apart by HTTP status."""

    def __init__(self, reason: str, *, user_id: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.user_id = user_id


async def authenticate(db: AsyncSession, *, email: str, password: str) -> User:
    user = (await db.execute(select(User).where(User.email == email.lower()))).scalar_one_or_none()
    if user is None:
        raise InvalidCredentials("unknown_user")
    if user.disabled:
        raise InvalidCredentials("disabled_user", user_id=str(user.id))
    if not verify_password(password, user.password_hash):
        raise InvalidCredentials("bad_password", user_id=str(user.id))
    if password_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    user.last_login_at = datetime.now(UTC)
    return user


def raise_invalid_credentials() -> None:
    """HTTP-side translator. Callers map InvalidCredentials → this so
    the wire response stays generic."""
    raise unauthorized("invalid credentials")


def issue_token_pair(user: User) -> dict[str, str]:
    # Phase 3 #3.1: bake the user's tenant + super-admin claims into
    # both legs of the token pair. The auth resolver cross-checks them
    # against the user row on every request — a stolen pre-demotion
    # token can't ride past the demotion because the user.is_super_admin
    # flip invalidates the claim.
    common = {
        "sub": user.id,
        "role": user.role.value,
        "tenant_id": user.tenant_id,
        "is_super_admin": user.is_super_admin,
    }
    return {
        "access_token": issue_jwt(**common, token_type="access"),
        "refresh_token": issue_jwt(**common, token_type="refresh"),
        "token_type": "bearer",
    }
