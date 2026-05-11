"""M-audit-and-auth #1: failed logins are audited.

Reviewer's MEDIUM finding: the manager had `user.login` audit rows on
success but silence on wrong-password / unknown-user. With the
anon-rate-limit at 10/min/IP, a distributed credential-stuffing attack
(commodity botnet, residential proxies) sits under the limiter, and
the audit log gives the SOC nothing to alert on.

Tests:
  - `authenticate` raises InvalidCredentials with a specific reason
    for each of the three failure modes.
  - The HTTP /login wrapper writes a user.login.failed audit row
    independent of the rolled-back request session, then surfaces a
    generic 401 so the wire can't distinguish the failure modes.
"""

from __future__ import annotations

import os
from typing import Any

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine


def _pg_dsn() -> str | None:
    if v := os.environ.get("VIGIL_TEST_PG_DSN"):
        return v
    if v := os.environ.get("VIGIL_PG_DSN"):
        return v
    return None


@pytest_asyncio.fixture
async def engine() -> Any:
    dsn = _pg_dsn()
    if dsn is None:
        pytest.skip("No PG DSN configured.")
    e = create_async_engine(dsn, pool_pre_ping=True, echo=False)
    try:
        yield e
    finally:
        await e.dispose()


@pytest.mark.asyncio
async def test_authenticate_raises_unknown_user(engine: Any) -> None:
    from app.services.auth import InvalidCredentials, authenticate

    async with AsyncSession(engine) as db:
        with pytest.raises(InvalidCredentials) as exc_info:
            await authenticate(db, email="nobody-here-%@example.com", password="x")
        assert exc_info.value.reason == "unknown_user"
        assert exc_info.value.user_id is None


@pytest.mark.asyncio
async def test_authenticate_raises_bad_password(engine: Any) -> None:
    from app.core.security import hash_password
    from app.models import User, UserRole
    from app.services.auth import InvalidCredentials, authenticate

    email = f"audit-test-bp-{os.urandom(4).hex()}@local"
    async with AsyncSession(engine) as db:
        u = User(email=email, password_hash=hash_password("correct-pw-1234"), role=UserRole.ADMIN)
        db.add(u)
        await db.commit()
        await db.refresh(u)
        uid = u.id
    try:
        async with AsyncSession(engine) as db:
            with pytest.raises(InvalidCredentials) as exc_info:
                await authenticate(db, email=email, password="wrong-pw")
            assert exc_info.value.reason == "bad_password"
            assert exc_info.value.user_id == str(uid)
    finally:
        async with AsyncSession(engine) as db:
            await db.execute(delete(User).where(User.id == uid))
            await db.commit()


@pytest.mark.asyncio
async def test_authenticate_raises_disabled_user(engine: Any) -> None:
    from app.core.security import hash_password
    from app.models import User, UserRole
    from app.services.auth import InvalidCredentials, authenticate

    email = f"audit-test-dis-{os.urandom(4).hex()}@local"
    async with AsyncSession(engine) as db:
        u = User(
            email=email,
            password_hash=hash_password("correct-pw-1234"),
            role=UserRole.ADMIN,
            disabled=True,
        )
        db.add(u)
        await db.commit()
        await db.refresh(u)
        uid = u.id
    try:
        async with AsyncSession(engine) as db:
            with pytest.raises(InvalidCredentials) as exc_info:
                await authenticate(db, email=email, password="correct-pw-1234")
            assert exc_info.value.reason == "disabled_user"
            assert exc_info.value.user_id == str(uid)
    finally:
        async with AsyncSession(engine) as db:
            await db.execute(delete(User).where(User.id == uid))
            await db.commit()


@pytest.mark.asyncio
async def test_failed_login_writes_audit_row(engine: Any) -> None:
    """Full HTTP path: POST /api/auth/login with wrong creds returns
    401 and leaves a `user.login.failed` audit row that survived the
    request rollback. Pin both legs."""
    from app.main import app
    from app.models import AuditLog

    email = f"audit-test-http-{os.urandom(4).hex()}@local"
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/auth/login",
            json={"email": email, "password": "definitely-not-right"},
        )
        assert resp.status_code == 401
        # Generic detail — the wire can't tell unknown_user from bad_password.
        assert resp.json()["detail"] == "invalid credentials"

    async with AsyncSession(engine) as db:
        # `payload` is JSON not JSONB so we can't index with .astext;
        # filter by action and scan in Python — there's at most a
        # handful of matching rows even on a heavily-used dev DB.
        rows = (
            (await db.execute(select(AuditLog).where(AuditLog.action == "user.login.failed")))
            .scalars()
            .all()
        )
        matching = [r for r in rows if (r.payload or {}).get("email") == email]
        assert len(matching) == 1, f"expected 1 failed-login audit row, got {len(matching)}"
        payload = matching[0].payload or {}
        assert payload["reason"] == "unknown_user"
        # Audit_log is INSERT-only from vigil_manager (M16.a fixed) —
        # row cleanup happens via the writer-owner role. We don't
        # connect as that role here; instead each run picks a unique
        # email so subsequent runs don't double-up.
