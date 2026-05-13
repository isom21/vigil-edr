"""Pytest fixtures for the backend test suite.

The default fixture wires the FastAPI app to an isolated test database
created per session. We rely on a real Postgres (the CI service container
or a local instance) rather than SQLite-mocking because the schema uses
PG-specific types (uuid, jsonb, enum, citext-like patterns).

Test isolation uses a SAVEPOINT-per-test pattern — each test runs inside
a nested transaction that rolls back at teardown, so tests can share the
session-scoped schema without bleeding state.

Environment expected (CI sets these via the service container env block):
    VIGIL_DATABASE_URL  postgresql+psycopg://...        (sync url for alembic)
    VIGIL_PG_DSN        postgresql+asyncpg://...        (async url for the app)
    VIGIL_KAFKA_BROKERS localhost:9092                  (only if kafka tests run)
    VIGIL_OPENSEARCH_URL http://localhost:9200          (only if OS tests run)

When run locally without those, tests are skipped with a clear message.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from typing import Any

import pytest
import pytest_asyncio


def _pg_dsn() -> str | None:
    """Return the async PG DSN for tests, or None if not configured."""
    # Prefer VIGIL_TEST_PG_DSN, then VIGIL_PG_DSN, then derive from VIGIL_DATABASE_URL.
    if v := os.environ.get("VIGIL_TEST_PG_DSN"):
        return v
    if v := os.environ.get("VIGIL_PG_DSN"):
        return v
    if v := os.environ.get("VIGIL_DATABASE_URL"):
        # Convert sync to async driver if the user gave us a sync URL.
        if v.startswith("postgresql+psycopg://"):
            return v.replace("postgresql+psycopg://", "postgresql+asyncpg://", 1)
        if v.startswith("postgresql://"):
            return v.replace("postgresql://", "postgresql+asyncpg://", 1)
        return v
    return None


@pytest_asyncio.fixture
async def db_engine() -> AsyncIterator[Any]:
    """Per-test async engine. Connection pool overhead is small for the
    suite we run; session-scoping the engine clashes with pytest-asyncio's
    default function-scoped event loop."""
    dsn = _pg_dsn()
    if dsn is None:
        pytest.skip(
            "No PG DSN configured. Set VIGIL_TEST_PG_DSN or VIGIL_DATABASE_URL "
            "to run integration tests."
        )

    # Importing app.core.db here so Settings can pick up the env vars set
    # by the test harness rather than the dev defaults.
    os.environ.setdefault("VIGIL_PG_DSN", dsn)
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(dsn, pool_pre_ping=True, echo=False)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(db_engine: Any) -> AsyncIterator[Any]:
    """Per-test session inside a SAVEPOINT that rolls back at teardown."""
    from sqlalchemy.ext.asyncio import AsyncSession

    async with db_engine.connect() as conn:
        trans = await conn.begin()
        session = AsyncSession(bind=conn, expire_on_commit=False)
        try:
            yield session
        finally:
            await session.close()
            await trans.rollback()


@pytest_asyncio.fixture
async def http_client(db_session: Any) -> AsyncIterator[Any]:
    """ASGI client bound to the FastAPI app, sharing the test engine.

    Reuses the SAME `db_session` the test fixtures seed against, so
    rows added by helpers like `admin_user` are visible to handlers.
    Without that, the user lookup inside the JWT-bearer dependency
    runs in a fresh tx that hasn't seen the seeded admin and every
    request 401s.
    """
    from httpx import ASGITransport, AsyncClient

    from app.core.deps import get_session
    from app.main import app

    async def _override_session() -> AsyncIterator[Any]:
        # Important: yield the existing fixture session unchanged.
        # Don't open a new tx; don't close the session here. The
        # db_session fixture owns lifecycle.
        yield db_session

    app.dependency_overrides[get_session] = _override_session
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    app.dependency_overrides.pop(get_session, None)


@pytest_asyncio.fixture
async def admin_user(db_session: Any) -> Any:
    """A fresh admin user, scoped to the test transaction."""
    from app.core.security import hash_password
    from app.models import User, UserRole

    user = User(
        email=f"admin-{os.urandom(4).hex()}@test.local",
        password_hash=hash_password("test-password-123"),
        role=UserRole.ADMIN,
    )
    db_session.add(user)
    await db_session.flush()
    return user


@pytest_asyncio.fixture
async def analyst_user(db_session: Any) -> Any:
    """A fresh analyst user."""
    from app.core.security import hash_password
    from app.models import User, UserRole

    user = User(
        email=f"analyst-{os.urandom(4).hex()}@test.local",
        password_hash=hash_password("test-password-123"),
        role=UserRole.ANALYST,
    )
    db_session.add(user)
    await db_session.flush()
    return user


def make_jwt(
    user_id: str,
    role: str = "admin",
    *,
    tenant_id: Any = None,
    is_super_admin: bool = False,
) -> str:
    """Mint an access JWT for the given user, mirroring app.core.security.

    Phase 3 #3.1: ``tenant_id`` + ``is_super_admin`` ride in the
    claims. Callers that don't care can leave them at the defaults —
    the resolver falls back to the user's home tenant when the
    tenant claim is absent.
    """
    from uuid import UUID

    from app.core.security import issue_jwt

    if tenant_id is None:
        tenant_uuid: UUID | None = None
    elif isinstance(tenant_id, UUID):
        tenant_uuid = tenant_id
    else:
        tenant_uuid = UUID(str(tenant_id))
    return issue_jwt(
        sub=UUID(user_id),
        role=role,
        token_type="access",
        tenant_id=tenant_uuid,
        is_super_admin=is_super_admin,
    )


@pytest.fixture
def admin_headers(admin_user: Any) -> dict[str, str]:
    return {
        "Authorization": "Bearer "
        + make_jwt(
            str(admin_user.id),
            "admin",
            tenant_id=admin_user.tenant_id,
            is_super_admin=admin_user.is_super_admin,
        )
    }


@pytest.fixture
def analyst_headers(analyst_user: Any) -> dict[str, str]:
    return {
        "Authorization": "Bearer "
        + make_jwt(
            str(analyst_user.id),
            "analyst",
            tenant_id=analyst_user.tenant_id,
            is_super_admin=analyst_user.is_super_admin,
        )
    }


# ---- Phase 3 #3.1 multi-tenancy fixtures ----------------------------------


@pytest_asyncio.fixture
async def tenant_a(db_session: Any) -> Any:
    """A fresh tenant A scoped to the test transaction."""
    from app.models import Tenant

    slug = f"tenant-a-{os.urandom(3).hex()}"
    t = Tenant(slug=slug, name="Tenant A")
    db_session.add(t)
    await db_session.flush()
    return t


@pytest_asyncio.fixture
async def tenant_b(db_session: Any) -> Any:
    """A fresh tenant B scoped to the test transaction."""
    from app.models import Tenant

    slug = f"tenant-b-{os.urandom(3).hex()}"
    t = Tenant(slug=slug, name="Tenant B")
    db_session.add(t)
    await db_session.flush()
    return t


async def _make_user(
    db_session: Any, role: Any, tenant_id: Any, *, is_super_admin: bool = False
) -> Any:
    from app.core.security import hash_password
    from app.models import User

    user = User(
        email=f"u-{os.urandom(4).hex()}@test.local",
        password_hash=hash_password("test-password-123"),
        role=role,
        tenant_id=tenant_id,
        is_super_admin=is_super_admin,
    )
    db_session.add(user)
    await db_session.flush()
    return user


@pytest_asyncio.fixture
async def admin_in_a(db_session: Any, tenant_a: Any) -> Any:
    from app.models import UserRole

    return await _make_user(db_session, UserRole.ADMIN, tenant_a.id)


@pytest_asyncio.fixture
async def analyst_in_a(db_session: Any, tenant_a: Any) -> Any:
    from app.models import UserRole

    return await _make_user(db_session, UserRole.ANALYST, tenant_a.id)


@pytest_asyncio.fixture
async def viewer_in_a(db_session: Any, tenant_a: Any) -> Any:
    from app.models import UserRole

    return await _make_user(db_session, UserRole.VIEWER, tenant_a.id)


@pytest_asyncio.fixture
async def admin_in_b(db_session: Any, tenant_b: Any) -> Any:
    from app.models import UserRole

    return await _make_user(db_session, UserRole.ADMIN, tenant_b.id)


@pytest_asyncio.fixture
async def analyst_in_b(db_session: Any, tenant_b: Any) -> Any:
    from app.models import UserRole

    return await _make_user(db_session, UserRole.ANALYST, tenant_b.id)


@pytest_asyncio.fixture
async def viewer_in_b(db_session: Any, tenant_b: Any) -> Any:
    from app.models import UserRole

    return await _make_user(db_session, UserRole.VIEWER, tenant_b.id)


@pytest_asyncio.fixture
async def super_admin(db_session: Any, tenant_a: Any) -> Any:
    """A super-admin user. Their home tenant is tenant_a but the
    is_super_admin bit lets them flip the active tenant via the
    `vigil_active_tenant_id` cookie on the test client."""
    from app.models import UserRole

    return await _make_user(db_session, UserRole.ADMIN, tenant_a.id, is_super_admin=True)


def headers_for(user: Any) -> dict[str, str]:
    """Build a JWT bearer header for any test user fixture."""
    return {
        "Authorization": "Bearer "
        + make_jwt(
            str(user.id),
            user.role.value,
            tenant_id=user.tenant_id,
            is_super_admin=user.is_super_admin,
        )
    }
