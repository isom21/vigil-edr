"""OIDC SSO (Phase 1 #1.6) — authorization-code flow with PKCE.

Covers the bits that don't need a real IdP. We mock the discovery doc,
JWKS endpoint, and token endpoint via respx and feed the callback a
signed ID token built from our own RSA keypair so the verifier path
runs end-to-end.

Cases:
  * `/oidc/discovery` reports `enabled` honestly.
  * `/oidc/authorize` redirects to the IdP authorize endpoint with the
    canonical params (response_type, scope, state, nonce, PKCE) and
    sets the state cookie.
  * `/oidc/callback` provisions a new user on first login, with
    audit rows for `user.provision` + `user.login` (method=oidc).
  * `/oidc/callback` matches an existing OIDC user by `sub` on the
    second login (no second provision).
  * `/oidc/callback` rejects a state mismatch (cookie ≠ query param).
  * `/oidc/callback` rejects an ID token with a nonce mismatch.
"""

from __future__ import annotations

import base64
import json
import os
import time
import uuid
from typing import Any

import httpx
import jwt
import pytest
import pytest_asyncio
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

_TEST_ISSUER = "https://idp.example.test/realms/vigil-dev"
_TEST_CLIENT_ID = "vigil-manager"
_TEST_CLIENT_SECRET = "dev-test-client-secret-not-real"
_TEST_REDIRECT_URI = "http://test/api/auth/oidc/callback"


def _pg_dsn() -> str | None:
    if v := os.environ.get("VIGIL_TEST_PG_DSN"):
        return v
    if v := os.environ.get("VIGIL_PG_DSN"):
        return v
    return None


@pytest.fixture(autouse=True)
def _configure_oidc(monkeypatch: Any) -> None:
    """Force the OIDC settings to the test values for every case and
    reset the discovery/JWKS caches between tests so the mock URLs are
    re-fetched fresh. We also pin `debug=True` so the auth cookies get
    written without the secure flag — the ASGI client connects to
    ``http://test`` which httpx (rightly) refuses to send Secure-flag
    cookies over."""
    from app.core.config import settings
    from app.services import oidc as oidc_service

    monkeypatch.setattr(settings, "debug", True)
    monkeypatch.setattr(settings, "oidc_enabled", True)
    monkeypatch.setattr(settings, "oidc_issuer_url", _TEST_ISSUER)
    monkeypatch.setattr(settings, "oidc_client_id", _TEST_CLIENT_ID)
    monkeypatch.setattr(settings, "oidc_client_secret", _TEST_CLIENT_SECRET)
    monkeypatch.setattr(settings, "oidc_redirect_uri", _TEST_REDIRECT_URI)
    monkeypatch.setattr(settings, "oidc_default_role", "viewer")
    oidc_service._reset_caches_for_tests()


@pytest.fixture(scope="session")
def _rsa_keypair() -> tuple[rsa.RSAPrivateKey, dict[str, Any]]:
    """Generate one RSA keypair per test session; expose the public
    half as a JWKS document so the test IdP can advertise it."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_numbers = private.public_key().public_numbers()

    def _int_to_base64url(value: int) -> str:
        byte_len = (value.bit_length() + 7) // 8
        raw = value.to_bytes(byte_len, byteorder="big")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": "test-rsa-key",
                "n": _int_to_base64url(public_numbers.n),
                "e": _int_to_base64url(public_numbers.e),
            }
        ]
    }
    return private, jwks


def _sign_id_token(private: rsa.RSAPrivateKey, claims: dict[str, Any]) -> str:
    """Sign an ID token with the test keypair. PyJWT expects PEM bytes
    for RS256."""
    pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return jwt.encode(claims, pem, algorithm="RS256", headers={"kid": "test-rsa-key"})


def _mock_idp(
    respx_mock: respx.MockRouter,
    jwks: dict[str, Any],
    *,
    id_token: str,
) -> None:
    """Stand up the three IdP endpoints we hit: discovery, JWKS, and
    the token endpoint. ``id_token`` is the signed JWT we hand back on
    code exchange."""
    discovery_url = f"{_TEST_ISSUER}/.well-known/openid-configuration"
    jwks_uri = f"{_TEST_ISSUER}/protocol/openid-connect/certs"
    token_endpoint = f"{_TEST_ISSUER}/protocol/openid-connect/token"
    authz_endpoint = f"{_TEST_ISSUER}/protocol/openid-connect/auth"

    respx_mock.get(discovery_url).mock(
        return_value=httpx.Response(
            200,
            json={
                "issuer": _TEST_ISSUER,
                "authorization_endpoint": authz_endpoint,
                "token_endpoint": token_endpoint,
                "jwks_uri": jwks_uri,
                "userinfo_endpoint": f"{_TEST_ISSUER}/protocol/openid-connect/userinfo",
            },
        )
    )
    respx_mock.get(jwks_uri).mock(return_value=httpx.Response(200, json=jwks))
    respx_mock.post(token_endpoint).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "idp-access-token",
                "token_type": "Bearer",
                "id_token": id_token,
                "expires_in": 300,
            },
        )
    )


def _id_token_claims(*, sub: str, email: str, nonce: str) -> dict[str, Any]:
    now = int(time.time())
    return {
        "iss": _TEST_ISSUER,
        "sub": sub,
        "aud": _TEST_CLIENT_ID,
        "iat": now,
        "exp": now + 300,
        "email": email,
        "name": email.split("@")[0],
        "nonce": nonce,
    }


@pytest_asyncio.fixture
async def engine() -> Any:
    dsn = _pg_dsn()
    if dsn is None:
        pytest.skip("No PG DSN configured")
    e = create_async_engine(dsn, pool_pre_ping=True, echo=False)
    try:
        yield e
    finally:
        await e.dispose()


@pytest_asyncio.fixture
async def client() -> Any:
    """Plain ASGITransport client — the OIDC tests need cookies to
    persist across requests, which the conftest http_client fixture
    doesn't natively give us, and they don't need the savepoint
    rollback."""
    from app.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


# ---------- discovery ----------------------------------------------


@pytest.mark.asyncio
async def test_oidc_discovery_reports_enabled(client: AsyncClient) -> None:
    resp = await client.get("/api/auth/oidc/discovery")
    assert resp.status_code == 200
    assert resp.json() == {"enabled": True}


@pytest.mark.asyncio
async def test_oidc_discovery_reports_disabled_when_flag_off(
    client: AsyncClient, monkeypatch: Any
) -> None:
    from app.core.config import settings

    monkeypatch.setattr(settings, "oidc_enabled", False)
    resp = await client.get("/api/auth/oidc/discovery")
    assert resp.status_code == 200
    assert resp.json() == {"enabled": False}


# ---------- authorize redirect -------------------------------------


@pytest.mark.asyncio
async def test_oidc_authorize_redirects_to_idp_with_state_and_pkce(
    client: AsyncClient, _rsa_keypair: tuple[rsa.RSAPrivateKey, dict[str, Any]]
) -> None:
    _, jwks = _rsa_keypair
    with respx.mock(assert_all_called=False) as respx_mock:
        _mock_idp(
            respx_mock,
            jwks,
            id_token=_sign_id_token(
                _rsa_keypair[0],
                _id_token_claims(sub="unused", email="unused@x.test", nonce="unused"),
            ),
        )
        resp = await client.get("/api/auth/oidc/authorize", follow_redirects=False)
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert location.startswith(f"{_TEST_ISSUER}/protocol/openid-connect/auth?")
    # The mandatory OIDC params + PKCE.
    for needle in (
        "response_type=code",
        f"client_id={_TEST_CLIENT_ID}",
        "scope=openid+email+profile",
        "state=",
        "nonce=",
        "code_challenge=",
        "code_challenge_method=S256",
    ):
        assert needle in location, f"missing {needle} in {location}"

    # The state cookie should be set so the callback can recover state
    # + nonce + code_verifier.
    cookie = resp.cookies.get("vigil_oidc_state")
    assert cookie is not None
    assert cookie.count(".") == 2  # state.nonce.code_verifier


# ---------- callback: provisions a fresh user ----------------------


@pytest.mark.asyncio
async def test_oidc_callback_provisions_new_user(
    client: AsyncClient,
    engine: Any,
    _rsa_keypair: tuple[rsa.RSAPrivateKey, dict[str, Any]],
) -> None:
    """Full round-trip: the SPA hits /oidc/authorize, we follow the
    redirect manually so the IdP can return a stub ?code= and ?state=,
    then /oidc/callback exchanges and provisions."""
    private, jwks = _rsa_keypair
    email = f"newuser-{uuid.uuid4().hex[:8]}@idp.test"
    sub = f"idp-sub-{uuid.uuid4().hex}"

    with respx.mock(assert_all_called=False) as respx_mock:
        # /authorize first to get the state cookie.
        _mock_idp(
            respx_mock,
            jwks,
            id_token=_sign_id_token(
                private, _id_token_claims(sub="placeholder", email=email, nonce="placeholder")
            ),
        )
        authz = await client.get("/api/auth/oidc/authorize", follow_redirects=False)
        assert authz.status_code == 302
        cookie = authz.cookies.get("vigil_oidc_state")
        assert cookie is not None
        state, nonce, _code_verifier = cookie.split(".")

        # Rebuild the IdP mock with the real nonce baked into the ID
        # token. Respx routes are FIFO so we need to drop the prior
        # token-endpoint stub.
        respx_mock.reset()
        _mock_idp(
            respx_mock,
            jwks,
            id_token=_sign_id_token(private, _id_token_claims(sub=sub, email=email, nonce=nonce)),
        )

        resp = await client.get(
            "/api/auth/oidc/callback",
            params={"code": "test-auth-code", "state": state},
            follow_redirects=False,
        )

    assert resp.status_code == 302, resp.text
    assert resp.headers["location"] == "/dashboard"
    assert resp.cookies.get("vigil_refresh") is not None
    # State cookie should be cleared (Set-Cookie with max_age=0 / empty).
    assert resp.cookies.get("vigil_oidc_state", "") in ("", None)

    # The user landed in the DB with the default role.
    async with AsyncSession(engine) as db:
        from app.models import AuditLog, User, UserRole

        user = (await db.execute(select(User).where(User.oidc_subject == sub))).scalar_one_or_none()
        assert user is not None
        assert user.email == email
        assert user.oidc_issuer == _TEST_ISSUER
        assert user.oidc_email == email
        assert user.role == UserRole.VIEWER

        # Audit: user.provision then user.login(method=oidc) — order
        # doesn't matter, but both rows must exist for this user.
        rows = (
            (await db.execute(select(AuditLog).where(AuditLog.resource_id == str(user.id))))
            .scalars()
            .all()
        )
        actions = {(r.action, json.dumps(r.payload, sort_keys=True)) for r in rows}
        assert any(action == "user.provision" for action, _ in actions)
        assert any(
            action == "user.login" and '"method": "oidc"' in payload for action, payload in actions
        )

        # Cleanup so the row doesn't pollute later test runs.
        await db.delete(user)
        for r in rows:
            await db.delete(r)
        await db.commit()


# ---------- callback: existing user matched by `sub` ---------------


@pytest.mark.asyncio
async def test_oidc_callback_existing_user_matched_by_sub(
    client: AsyncClient,
    engine: Any,
    _rsa_keypair: tuple[rsa.RSAPrivateKey, dict[str, Any]],
) -> None:
    private, jwks = _rsa_keypair
    sub = f"idp-sub-{uuid.uuid4().hex}"
    email = f"existing-{uuid.uuid4().hex[:8]}@idp.test"

    # Seed a user with that OIDC subject already.
    from app.core.security import hash_password
    from app.models import AuditLog, User, UserRole

    async with AsyncSession(engine) as db:
        user = User(
            email=email,
            password_hash=hash_password("unused-oidc-only"),
            role=UserRole.ANALYST,  # not the default — proves we didn't re-provision
            oidc_subject=sub,
            oidc_issuer=_TEST_ISSUER,
            oidc_email=email,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
        seeded_id = user.id

    try:
        with respx.mock(assert_all_called=False) as respx_mock:
            _mock_idp(
                respx_mock,
                jwks,
                id_token=_sign_id_token(
                    private, _id_token_claims(sub=sub, email=email, nonce="placeholder")
                ),
            )
            authz = await client.get("/api/auth/oidc/authorize", follow_redirects=False)
            cookie = authz.cookies.get("vigil_oidc_state")
            assert cookie is not None
            state, nonce, _ = cookie.split(".")

            respx_mock.reset()
            _mock_idp(
                respx_mock,
                jwks,
                id_token=_sign_id_token(
                    private, _id_token_claims(sub=sub, email=email, nonce=nonce)
                ),
            )

            resp = await client.get(
                "/api/auth/oidc/callback",
                params={"code": "test-auth-code", "state": state},
                follow_redirects=False,
            )
        assert resp.status_code == 302

        # Role should still be ANALYST — no provision happened.
        async with AsyncSession(engine) as db:
            same = (await db.execute(select(User).where(User.id == seeded_id))).scalar_one()
            assert same.role == UserRole.ANALYST
            # And no `user.provision` audit row for this user id.
            rows = (
                (
                    await db.execute(
                        select(AuditLog)
                        .where(AuditLog.resource_id == str(seeded_id))
                        .where(AuditLog.action == "user.provision")
                    )
                )
                .scalars()
                .all()
            )
            assert rows == []
    finally:
        async with AsyncSession(engine) as db:
            await db.execute(select(AuditLog).where(AuditLog.resource_id == str(seeded_id)))
            for row in (
                (await db.execute(select(AuditLog).where(AuditLog.resource_id == str(seeded_id))))
                .scalars()
                .all()
            ):
                await db.delete(row)
            # Re-fetch the user — earlier session may have closed.
            u = await db.get(User, seeded_id)
            if u is not None:
                await db.delete(u)
            await db.commit()


# ---------- callback: state mismatch -------------------------------


@pytest.mark.asyncio
async def test_oidc_callback_rejects_state_mismatch(
    client: AsyncClient, _rsa_keypair: tuple[rsa.RSAPrivateKey, dict[str, Any]]
) -> None:
    private, jwks = _rsa_keypair
    with respx.mock(assert_all_called=False) as respx_mock:
        _mock_idp(
            respx_mock,
            jwks,
            id_token=_sign_id_token(
                private,
                _id_token_claims(sub="x", email="x@x.test", nonce="placeholder"),
            ),
        )
        authz = await client.get("/api/auth/oidc/authorize", follow_redirects=False)
        assert authz.status_code == 302

        # Hand the callback a state value that doesn't match the cookie.
        resp = await client.get(
            "/api/auth/oidc/callback",
            params={"code": "test-auth-code", "state": "tampered-state-value"},
            follow_redirects=False,
        )
    assert resp.status_code == 401
    assert "oidc state mismatch" in resp.text


# ---------- callback: nonce mismatch -------------------------------


@pytest.mark.asyncio
async def test_oidc_callback_rejects_nonce_mismatch(
    client: AsyncClient,
    engine: Any,
    _rsa_keypair: tuple[rsa.RSAPrivateKey, dict[str, Any]],
) -> None:
    private, jwks = _rsa_keypair
    email = f"nonce-fail-{uuid.uuid4().hex[:8]}@idp.test"
    sub = f"idp-sub-{uuid.uuid4().hex}"

    with respx.mock(assert_all_called=False) as respx_mock:
        _mock_idp(
            respx_mock,
            jwks,
            id_token=_sign_id_token(
                private, _id_token_claims(sub=sub, email=email, nonce="placeholder")
            ),
        )
        authz = await client.get("/api/auth/oidc/authorize", follow_redirects=False)
        cookie = authz.cookies.get("vigil_oidc_state")
        assert cookie is not None
        state, _real_nonce, _ = cookie.split(".")

        # Sign a token with a deliberately wrong nonce — the callback
        # must catch it even though signature + issuer + audience all
        # check out.
        respx_mock.reset()
        _mock_idp(
            respx_mock,
            jwks,
            id_token=_sign_id_token(
                private,
                _id_token_claims(sub=sub, email=email, nonce="wrong-nonce-attacker"),
            ),
        )

        resp = await client.get(
            "/api/auth/oidc/callback",
            params={"code": "test-auth-code", "state": state},
            follow_redirects=False,
        )
    assert resp.status_code == 401
    assert "id_token invalid" in resp.text

    # And no user got created on a rejected callback.
    async with AsyncSession(engine) as db:
        from app.models import User

        user = (await db.execute(select(User).where(User.oidc_subject == sub))).scalar_one_or_none()
        assert user is None
