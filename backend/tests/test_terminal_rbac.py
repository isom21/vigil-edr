"""Phase 1 #1.4 — live-response remote shell.

RBAC + host-scope checks on ``POST /api/hosts/{id}/terminal``:

  * Analyst with the host in one of their groups: 201.
  * Analyst with the host outside their groups: 404 (403/404
    unification — every other host-scoped endpoint behaves this way).
  * Viewer: 403, independent of host scope (viewers are read-only).

The gRPC TerminalStream handler is *not* exercised here — these
tests are about who can mint a session token. Coverage of the
WebSocket relay + agent path is deferred to e2e (needs a real agent
+ browser).
"""

from __future__ import annotations

import os

import pytest
import pytest_asyncio
from sqlalchemy import insert


@pytest_asyncio.fixture
async def viewer_user(db_session):
    from app.core.security import hash_password
    from app.models import User, UserRole

    user = User(
        email=f"viewer-{os.urandom(4).hex()}@test.local",
        password_hash=hash_password("test-password-123"),
        role=UserRole.VIEWER,
    )
    db_session.add(user)
    await db_session.flush()
    return user


@pytest.fixture
def viewer_headers(viewer_user):
    from tests.conftest import make_jwt

    return {"Authorization": f"Bearer {make_jwt(str(viewer_user.id), 'viewer')}"}


@pytest_asyncio.fixture
async def _terminal_seed(db_session, analyst_user):
    """Two hosts (A, B) each in its own group. Analyst is assigned to
    group-alpha (host A only). Mirrors test_alerts_rbac.py's shape."""
    from app.models import (
        Host,
        HostGroup,
        HostStatus,
        OsFamily,
        host_in_group,
        user_host_group,
    )

    a = Host(
        hostname=f"host-a-{os.urandom(3).hex()}",
        os_family=OsFamily.LINUX,
        status=HostStatus.ONLINE,
    )
    b = Host(
        hostname=f"host-b-{os.urandom(3).hex()}",
        os_family=OsFamily.LINUX,
        status=HostStatus.ONLINE,
    )
    db_session.add_all([a, b])
    await db_session.flush()

    alpha = HostGroup(name=f"alpha-{os.urandom(3).hex()}")
    beta = HostGroup(name=f"beta-{os.urandom(3).hex()}")
    db_session.add_all([alpha, beta])
    await db_session.flush()

    await db_session.execute(insert(host_in_group).values(host_id=a.id, host_group_id=alpha.id))
    await db_session.execute(insert(host_in_group).values(host_id=b.id, host_group_id=beta.id))
    await db_session.execute(
        insert(user_host_group).values(user_id=analyst_user.id, host_group_id=alpha.id)
    )
    await db_session.flush()
    return {"host_a": a, "host_b": b}


# ---------- POST /api/hosts/{id}/terminal ----------


@pytest.mark.asyncio
async def test_analyst_opens_terminal_for_visible_host(
    http_client, _terminal_seed, analyst_headers
):
    """Analyst with the host in one of their groups: 201."""
    host_id = str(_terminal_seed["host_a"].id)
    resp = await http_client.post(f"/api/hosts/{host_id}/terminal", headers=analyst_headers)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["session_id"]
    assert body["token"].startswith("vts1.")
    assert body["ws_url"].startswith(f"/api/hosts/{host_id}/terminal/ws?token=")
    assert body["expires_at"]


@pytest.mark.asyncio
async def test_analyst_out_of_scope_returns_404(http_client, _terminal_seed, analyst_headers):
    """Analyst opening a host outside their groups: 404 (not 403, to
    avoid leaking the host's existence)."""
    host_id = str(_terminal_seed["host_b"].id)
    resp = await http_client.post(f"/api/hosts/{host_id}/terminal", headers=analyst_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_viewer_cannot_open_terminal(http_client, _terminal_seed, viewer_headers):
    """Viewers are read-only — they can't open response-action sessions."""
    host_id = str(_terminal_seed["host_a"].id)
    resp = await http_client.post(f"/api/hosts/{host_id}/terminal", headers=viewer_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_admin_opens_terminal_for_any_host(http_client, _terminal_seed, admin_headers):
    """Admins bypass host-group scope and can open against any host."""
    host_id = str(_terminal_seed["host_b"].id)
    resp = await http_client.post(f"/api/hosts/{host_id}/terminal", headers=admin_headers)
    assert resp.status_code == 201


@pytest.mark.asyncio
async def test_unknown_host_returns_404(http_client, analyst_headers):
    """A made-up uuid is just a not-found, same as every other path."""
    fake = "00000000-0000-0000-0000-000000000000"
    resp = await http_client.post(f"/api/hosts/{fake}/terminal", headers=analyst_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_open_terminal_audits(
    http_client, _terminal_seed, analyst_headers, db_session, analyst_user
):
    """A successful POST writes a `host.terminal.open` audit row tied
    to the analyst and the host."""
    from sqlalchemy import select

    from app.models import AuditLog

    host_id = str(_terminal_seed["host_a"].id)
    resp = await http_client.post(f"/api/hosts/{host_id}/terminal", headers=analyst_headers)
    assert resp.status_code == 201
    session_id = resp.json()["session_id"]

    # The ASGI client + db_session share a transaction; the row is
    # readable here without an explicit refresh.
    stmt = (
        select(AuditLog)
        .where(AuditLog.action == "host.terminal.open")
        .where(AuditLog.resource_id == host_id)
        .order_by(AuditLog.id.desc())
        .limit(1)
    )
    row = (await db_session.execute(stmt)).scalar_one_or_none()
    assert row is not None, "expected a host.terminal.open audit row"
    assert row.user_id == analyst_user.id
    assert row.payload is not None
    assert row.payload.get("session_id") == session_id


# ---------- token verification (no WebSocket needed) ----------


def test_session_token_roundtrip():
    """Smoke check on the HMAC token shape so the WS handler can rely
    on `verify_session_token` returning the same fields the POST
    handler put in."""
    from uuid import uuid4

    from app.services.terminal import issue_session_token, verify_session_token

    host_id = uuid4()
    user_id = uuid4()
    session_id = uuid4()
    token, sid, _ = issue_session_token(host_id=host_id, user_id=user_id, session_id=session_id)
    claim = verify_session_token(token)
    assert claim is not None
    assert claim.session_id == sid
    assert claim.host_id == host_id
    assert claim.user_id == user_id


def test_session_token_rejects_tampered_signature():
    from uuid import uuid4

    from app.services.terminal import issue_session_token, verify_session_token

    token, _, _ = issue_session_token(host_id=uuid4(), user_id=uuid4())
    # Replace the whole signature with a different valid-base64
    # value so we don't accidentally land on an equivalent-decode
    # neighbour (a single-char flip on a 43-char b64-no-pad string
    # can decode to the same bytes when the padding-bit position
    # happens to be zero).
    head, _, _sig = token.rpartition(".")
    tampered = f"{head}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    assert verify_session_token(tampered) is None


def test_session_token_rejects_wrong_prefix():
    from app.services.terminal import verify_session_token

    # Upload tokens share a key but use a different prefix; they
    # must not validate as terminal session tokens.
    assert verify_session_token("vau1.aGVsbG8.aGVsbG8") is None
