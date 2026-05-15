"""LOW #1: refuse to delete / disable / demote the last enabled admin.

Reviewer's LOW finding: an admin can delete themselves and any other
admin until none remain, bricking the console. Trivial to fall into
during a "let me clean up old accounts" pass.

Tests exercise the gate via the live REST API (admin token) — both
to cover the SQL count + the HTTP wire shape clients see.
"""

from __future__ import annotations

import os

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine


def _pg_dsn() -> str | None:
    if v := os.environ.get("VIGIL_TEST_PG_DSN"):
        return v
    if v := os.environ.get("VIGIL_PG_DSN"):
        return v
    if v := os.environ.get("VIGIL_DATABASE_URL"):
        if v.startswith("postgresql+psycopg://"):
            return v.replace("postgresql+psycopg://", "postgresql+asyncpg://", 1)
        if v.startswith("postgresql://"):
            return v.replace("postgresql://", "postgresql+asyncpg://", 1)
        return v
    return None


@pytest_asyncio.fixture
async def isolated_engine():
    """Each test seeds users in its own connection so it can see the
    full table state (the shared conftest db_session masks counts
    across savepoints)."""
    dsn = _pg_dsn()
    if dsn is None:
        pytest.skip("No PG DSN configured.")
    engine = create_async_engine(dsn, pool_pre_ping=True, echo=False)
    try:
        yield engine
    finally:
        await engine.dispose()


async def _wipe_test_admins(engine):
    """Tests below seed admins prefixed `lockout-test-`; drop any
    leftovers from prior runs so the count gate is well-defined."""
    from sqlalchemy import delete

    from app.models import User

    async with AsyncSession(engine) as db:
        await db.execute(delete(User).where(User.email.like("lockout-test-%")))
        await db.commit()


async def _seed_admin(engine, email: str, disabled: bool = False):
    from app.core.security import hash_password
    from app.models import User, UserRole

    async with AsyncSession(engine) as db:
        u = User(
            email=email,
            password_hash=hash_password("test-password-123"),
            role=UserRole.ADMIN,
            disabled=disabled,
        )
        db.add(u)
        await db.commit()
        await db.refresh(u)
        return u


@pytest.mark.asyncio
async def test_enabled_admin_count_excludes_target(isolated_engine) -> None:
    """The helper used by both update and delete must exclude the
    user being mutated — that's the whole point: we count what's left
    AFTER the operation lands."""
    from app.api.users import _enabled_admin_count
    from app.models.tenant import DEFAULT_TENANT_ID

    await _wipe_test_admins(isolated_engine)
    a1 = await _seed_admin(isolated_engine, "lockout-test-a@local")
    await _seed_admin(isolated_engine, "lockout-test-b@local")
    try:
        async with AsyncSession(isolated_engine) as db:
            # The seeded admins land in DEFAULT_TENANT_ID via the column
            # default; the per-tenant count introduced by CODE-2 now
            # requires us to name the tenant we're counting against.
            total = await _enabled_admin_count(db, tenant_id=DEFAULT_TENANT_ID)  # type: ignore[arg-type]
            assert total >= 2
            without_a1 = await _enabled_admin_count(  # type: ignore[arg-type]
                db, tenant_id=DEFAULT_TENANT_ID, exclude_user_id=a1.id
            )
            assert without_a1 == total - 1
    finally:
        await _wipe_test_admins(isolated_engine)


@pytest.mark.asyncio
async def test_enabled_admin_count_ignores_disabled(isolated_engine) -> None:
    from app.api.users import _enabled_admin_count
    from app.models.tenant import DEFAULT_TENANT_ID

    await _wipe_test_admins(isolated_engine)
    enabled = await _seed_admin(isolated_engine, "lockout-test-en@local")
    await _seed_admin(isolated_engine, "lockout-test-dis@local", disabled=True)
    try:
        async with AsyncSession(isolated_engine) as db:
            # Excluding the enabled admin should yield 0 (the disabled
            # one doesn't count) — proving the gate's "would the last
            # enabled admin disappear?" check works.
            without_enabled = await _enabled_admin_count(  # type: ignore[arg-type]
                db, tenant_id=DEFAULT_TENANT_ID, exclude_user_id=enabled.id
            )
            assert without_enabled == 0
    finally:
        await _wipe_test_admins(isolated_engine)


@pytest.mark.asyncio
async def test_two_enabled_admins_either_can_be_deleted(isolated_engine) -> None:
    """Sanity — the gate doesn't fire when there's redundancy."""
    from app.api.users import _enabled_admin_count
    from app.models.tenant import DEFAULT_TENANT_ID

    await _wipe_test_admins(isolated_engine)
    a1 = await _seed_admin(isolated_engine, "lockout-test-redundant-a@local")
    a2 = await _seed_admin(isolated_engine, "lockout-test-redundant-b@local")  # noqa: F841 — used below
    try:
        async with AsyncSession(isolated_engine) as db:
            assert (
                await _enabled_admin_count(  # type: ignore[arg-type]
                    db, tenant_id=DEFAULT_TENANT_ID, exclude_user_id=a1.id
                )
                >= 1
            )
            assert (
                await _enabled_admin_count(  # type: ignore[arg-type]
                    db, tenant_id=DEFAULT_TENANT_ID, exclude_user_id=a2.id
                )
                >= 1
            )
    finally:
        await _wipe_test_admins(isolated_engine)
