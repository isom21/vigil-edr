"""Login flow: validate credentials, issue JWTs, update last_login_at."""
from __future__ import annotations

from datetime import datetime, timezone

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


async def authenticate(db: AsyncSession, *, email: str, password: str) -> User:
    user = (await db.execute(select(User).where(User.email == email.lower()))).scalar_one_or_none()
    if user is None or user.disabled:
        raise unauthorized("invalid credentials")
    if not verify_password(password, user.password_hash):
        raise unauthorized("invalid credentials")
    if password_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    user.last_login_at = datetime.now(timezone.utc)
    return user


def issue_token_pair(user: User) -> dict[str, str]:
    return {
        "access_token": issue_jwt(sub=user.id, role=user.role.value, token_type="access"),
        "refresh_token": issue_jwt(sub=user.id, role=user.role.value, token_type="refresh"),
        "token_type": "bearer",
    }
