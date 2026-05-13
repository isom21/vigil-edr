"""Login, refresh, logout."""

from __future__ import annotations

import os
import time
import urllib.parse
from collections import deque
from threading import Lock
from uuid import UUID

import jwt
from fastapi import APIRouter, Cookie, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy import select

from app.core.config import settings
from app.core.db import SessionLocal
from app.core.deps import CurrentActor, DbSession
from app.core.errors import bad_request, unauthorized
from app.core.security import (
    decode_jwt,
    generate_api_token_secret,
    hash_password,
    issue_mfa_pending_jwt,
)
from app.models import User, UserRole
from app.schemas.auth import (
    Login2FARequest,
    LoginRequest,
    LoginResponse,
    OidcDiscoveryResponse,
    RefreshRequest,
    TokenPair,
    TotpDisableRequest,
    TotpSetupResponse,
    TotpStatus,
    TotpVerifySetupRequest,
    TotpVerifySetupResponse,
)
from app.services import audit
from app.services import auth as auth_service
from app.services import oidc as oidc_service
from app.services import totp as totp_service

router = APIRouter(prefix="/api/auth", tags=["auth"])


# M-frontend-auth #10: the refresh token rides on a server-set
# HttpOnly cookie so XSS in the SPA can't read it. We also keep
# returning the refresh in the body so existing scripted clients
# (smoke tests, ops tooling) don't break — the cookie is additive.
# Frontend uses `credentials: "include"` on POST /refresh and never
# reads the body's refresh_token.
_REFRESH_COOKIE_NAME = "vigil_refresh"


def _refresh_cookie_max_age() -> int:
    return int(settings.jwt_refresh_ttl_days) * 24 * 3600


def _set_refresh_cookie(response: Response, refresh_token: str) -> None:
    """HttpOnly + SameSite=Strict; secure flag follows `settings.debug`
    so dev (HTTP localhost) doesn't drop the cookie."""
    response.set_cookie(
        key=_REFRESH_COOKIE_NAME,
        value=refresh_token,
        max_age=_refresh_cookie_max_age(),
        httponly=True,
        secure=not settings.debug,
        samesite="strict",
        path="/api/auth",
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(key=_REFRESH_COOKIE_NAME, path="/api/auth")


# M-audit-and-auth #8: per-email failed-login throttle.
#
# The per-IP anon limiter (rate_limit.py, default 10/min) catches a
# single attacker IP; a distributed credential-stuffing run across
# residential proxies sits comfortably under that cap and the audit
# log records every miss but nothing pushes back. Add a sliding
# window keyed by the lowercase email so the same target account can
# absorb at most N failures inside T seconds before /login rejects
# with 429 regardless of source IP.
#
# Two backends: in-memory deque (single-instance default) and a
# Redis-backed sliding-window via ZSET (multi-instance). The Redis
# path is opt-in via VIGIL_REDIS_URL — when unset, the original
# threadsafe in-memory implementation is unchanged.

_LOGIN_FAIL_LIMIT = int(os.environ.get("VIGIL_LOGIN_FAIL_LIMIT", 10))
_LOGIN_FAIL_WINDOW_S = int(os.environ.get("VIGIL_LOGIN_FAIL_WINDOW_S", 300))
_login_fails: dict[str, deque[float]] = {}
_login_fails_lock = Lock()
_REDIS_LOGIN_KEY_PREFIX = "vigil:login_fail"


def _redis_login_key(email_key: str) -> str:
    return f"{_REDIS_LOGIN_KEY_PREFIX}:{email_key}"


async def _record_login_failure(email_key: str) -> tuple[bool, int]:
    """Append a failure timestamp for ``email_key`` (lowercase email).

    Returns ``(blocked, retry_after_s)``: if the sliding window has
    `_LOGIN_FAIL_LIMIT` or more failures inside `_LOGIN_FAIL_WINDOW_S`,
    we tell the caller to back off.

    When Redis is configured, the window is a per-email ZSET with
    score=timestamp; we prune the prefix older than the cutoff,
    record the new attempt, and check the cluster-wide cardinality.
    All three steps run inside one pipeline so a concurrent failure
    from another replica can't slip through between prune and check.
    """
    from app.core.redis_client import redis_client

    client = redis_client()
    if client is not None:
        return await _record_login_failure_redis(client, email_key)
    return _record_login_failure_inmem(email_key)


def _record_login_failure_inmem(email_key: str) -> tuple[bool, int]:
    """Threadsafe in-memory sliding window. The lock serialises the
    trim + append so two concurrent failing logins can't both slip
    through the gate."""
    now = time.monotonic()
    cutoff = now - _LOGIN_FAIL_WINDOW_S
    with _login_fails_lock:
        bucket = _login_fails.setdefault(email_key, deque())
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        bucket.append(now)
        if len(bucket) > _LOGIN_FAIL_LIMIT:
            retry_after = max(1, int(bucket[0] + _LOGIN_FAIL_WINDOW_S - now))
            return True, retry_after
        return False, 0


async def _record_login_failure_redis(client, email_key: str) -> tuple[bool, int]:
    """Sliding-window counter in Redis using a per-email ZSET.

    Score = wall-clock timestamp; member = a unique nonce per
    attempt so two attempts in the same microsecond don't collide on
    the score (ZSETs only dedupe by member). After the prune we read
    `ZCARD`; if it exceeds the limit, the caller is blocked.
    """
    key = _redis_login_key(email_key)
    now = time.time()
    cutoff = now - _LOGIN_FAIL_WINDOW_S
    # 8 bytes of randomness in the member name keep two attempts in
    # the same microsecond from colliding on the score (ZSETs dedupe
    # by member, not by score).
    member = f"{now}:{os.urandom(8).hex()}".encode()
    pipe = client.pipeline()
    pipe.zremrangebyscore(key, "-inf", cutoff)
    pipe.zadd(key, {member: now})
    pipe.zcard(key)
    # Keep one TTL longer than the window so the key auto-evicts
    # if the email goes quiet — no GC sweep needed.
    pipe.expire(key, _LOGIN_FAIL_WINDOW_S + 60)
    # `zrange withscores` of the oldest member so we can compute
    # retry-after without an extra round-trip on the blocked path.
    pipe.zrange(key, 0, 0, withscores=True)
    _, _, count, _, oldest = await pipe.execute()
    count = int(count)
    if count > _LOGIN_FAIL_LIMIT:
        # `oldest` is a list of (member, score) tuples; the score is
        # the first failure still inside the window.
        if oldest:
            _, oldest_score = oldest[0]
            retry_after = max(1, int(oldest_score + _LOGIN_FAIL_WINDOW_S - now))
        else:
            retry_after = _LOGIN_FAIL_WINDOW_S
        return True, retry_after
    return False, 0


async def _clear_login_failures(email_key: str) -> None:
    """A successful login clears the failure counter for that email so
    a legitimate user whose typo'd password tripped the gate isn't
    left with a stale strike count."""
    from app.core.redis_client import redis_client

    client = redis_client()
    if client is not None:
        await client.delete(_redis_login_key(email_key))
        return
    with _login_fails_lock:
        _login_fails.pop(email_key, None)


async def _is_login_blocked(email_key: str) -> bool:
    """Check whether ``email_key`` is currently over the failure
    threshold without recording a new attempt. Used to short-circuit
    `/login` before the password hash so a slow argon2 verify doesn't
    leak which accounts are under active attack."""
    from app.core.redis_client import redis_client

    client = redis_client()
    if client is not None:
        key = _redis_login_key(email_key)
        now = time.time()
        cutoff = now - _LOGIN_FAIL_WINDOW_S
        pipe = client.pipeline()
        pipe.zremrangebyscore(key, "-inf", cutoff)
        pipe.zcard(key)
        _, count = await pipe.execute()
        return int(count) >= _LOGIN_FAIL_LIMIT
    with _login_fails_lock:
        bucket = _login_fails.get(email_key)
        if not bucket or len(bucket) < _LOGIN_FAIL_LIMIT:
            return False
        cutoff = time.monotonic() - _LOGIN_FAIL_WINDOW_S
        live = sum(1 for t in bucket if t >= cutoff)
        return live >= _LOGIN_FAIL_LIMIT


@router.post("/login", response_model=LoginResponse)
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: DbSession,
) -> LoginResponse:
    ip = request.client.host if request.client else None
    email_key = payload.email.lower()

    # Pre-check the throttle. If the email is already over the
    # threshold, fail before we even hit the password verifier — that
    # closes the timing channel where a slow argon2 hash leaked which
    # accounts were under attack.
    if await _is_login_blocked(email_key):
        async with SessionLocal() as audit_db:
            await audit.record(
                audit_db,
                actor=None,
                action="user.login.throttled",
                resource_type="user",
                resource_id=None,
                payload={"email": email_key, "window_s": _LOGIN_FAIL_WINDOW_S},
                ip=ip,
            )
            await audit_db.commit()
        from fastapi import HTTPException

        raise HTTPException(
            status_code=429,
            detail="too many failed login attempts; try again later",
            headers={"Retry-After": str(_LOGIN_FAIL_WINDOW_S)},
        )

    try:
        user = await auth_service.authenticate(db, email=payload.email, password=payload.password)
    except auth_service.InvalidCredentials as exc:
        # M-audit-and-auth #1: record failed logins so brute-force /
        # credential-stuffing has a trip-wire. We can't write through
        # `db` because the request session will rollback on the raised
        # 401 — open a fresh session that commits independently.
        async with SessionLocal() as audit_db:
            await audit.record(
                audit_db,
                actor=None,
                action="user.login.failed",
                resource_type="user",
                resource_id=exc.user_id,
                payload={"email": email_key, "reason": exc.reason},
                ip=ip,
            )
            await audit_db.commit()
        await _record_login_failure(email_key)
        raise unauthorized("invalid credentials") from exc

    await _clear_login_failures(email_key)
    if user.totp_enabled:
        # Defer the token issuance to /login/2fa. Don't audit
        # `user.login` yet — the login isn't complete until the
        # second factor lands. Record the password-stage success so
        # there's a trail if 2FA never finishes.
        await audit.record(
            db,
            actor=None,
            action="user.login.password_ok_mfa_required",
            resource_type="user",
            resource_id=str(user.id),
            ip=ip,
        )
        return LoginResponse(mfa_required=True, mfa_token=issue_mfa_pending_jwt(sub=user.id))

    await audit.record(
        db,
        actor=None,
        action="user.login",
        resource_type="user",
        resource_id=str(user.id),
        ip=ip,
    )
    pair = auth_service.issue_token_pair(user)
    _set_refresh_cookie(response, pair["refresh_token"])
    return LoginResponse(**pair, mfa_required=False)


@router.post("/refresh", response_model=TokenPair)
async def refresh(
    payload: RefreshRequest,
    response: Response,
    db: DbSession,
    vigil_refresh: str | None = Cookie(default=None),
) -> TokenPair:
    # M-frontend-auth #10: prefer the HttpOnly cookie. Body-shape stays
    # for scripted callers (smoke tests, ops tooling). If neither is
    # present, that's a malformed request — 401 with a clear message.
    token = payload.refresh_token or vigil_refresh
    if not token:
        raise unauthorized("missing refresh token")
    try:
        decoded = decode_jwt(token)
    except jwt.ExpiredSignatureError as exc:
        raise unauthorized("refresh token expired") from exc
    except jwt.PyJWTError as exc:
        raise unauthorized("invalid refresh token") from exc
    if decoded.get("type") != "refresh":
        raise unauthorized("not a refresh token")
    user = await db.get(User, UUID(decoded["sub"]))
    if user is None or user.disabled:
        raise unauthorized("user inactive")
    pair = auth_service.issue_token_pair(user)
    _set_refresh_cookie(response, pair["refresh_token"])
    return TokenPair(**pair)


@router.post("/logout", status_code=204)
async def logout(response: Response) -> Response:
    """Clear the refresh cookie. The access token is in-memory only
    in the SPA so the client drops it by reload. Logout doesn't
    invalidate the JWTs themselves (we don't operate a denylist) —
    they just stop being reachable. Operators who need true
    revocation should disable the user via /api/users."""
    _clear_refresh_cookie(response)
    response.status_code = 204
    return response


# ---------- Two-step login (TOTP) -----------------------------------


async def _consume_2fa_code(user: User, code: str, db: DbSession) -> bool:
    """Try `code` first as a current TOTP, then as a recovery code.
    On a recovery-code hit, persist the shortened list. Returns True
    iff one path accepted the code."""
    if user.totp_secret_encrypted is None:
        return False
    secret = totp_service.decrypt_secret(user.totp_secret_encrypted)
    if totp_service.verify_code(secret, code):
        return True
    remaining = totp_service.consume_recovery_code(user.totp_recovery_codes_hashed or [], code)
    if remaining is None:
        return False
    user.totp_recovery_codes_hashed = remaining
    await audit.record(
        db,
        actor=None,
        action="user.2fa.recovery_used",
        resource_type="user",
        resource_id=str(user.id),
        payload={"remaining": len(remaining)},
    )
    return True


@router.post("/login/2fa", response_model=TokenPair)
async def login_2fa(
    payload: Login2FARequest,
    request: Request,
    response: Response,
    db: DbSession,
) -> TokenPair:
    ip = request.client.host if request.client else None
    try:
        decoded = decode_jwt(payload.mfa_token)
    except jwt.ExpiredSignatureError as exc:
        raise unauthorized("mfa token expired") from exc
    except jwt.PyJWTError as exc:
        raise unauthorized("invalid mfa token") from exc
    if decoded.get("type") != "mfa_pending":
        raise unauthorized("not an mfa token")

    user = await db.get(User, UUID(decoded["sub"]))
    if user is None or user.disabled or not user.totp_enabled:
        raise unauthorized("user inactive or 2fa not enabled")

    accepted = await _consume_2fa_code(user, payload.code, db)
    if not accepted:
        await audit.record(
            db,
            actor=None,
            action="user.login.2fa_failed",
            resource_type="user",
            resource_id=str(user.id),
            ip=ip,
        )
        await _record_login_failure(user.email.lower())
        raise unauthorized("invalid 2fa code")

    await audit.record(
        db,
        actor=None,
        action="user.login",
        resource_type="user",
        resource_id=str(user.id),
        payload={"via": "totp"},
        ip=ip,
    )
    pair = auth_service.issue_token_pair(user)
    _set_refresh_cookie(response, pair["refresh_token"])
    return TokenPair(**pair)


# ---------- Self-service enrollment / disable -----------------------


def _require_interactive_user(actor: CurrentActor) -> User:
    """2FA management is intentionally restricted to interactive users
    (JWT bearer). API tokens are opaque machine credentials and live
    on a different threat model."""
    if actor.kind != "user":
        raise unauthorized("2fa endpoints require an interactive user session")
    return actor.user


@router.get("/2fa/status", response_model=TotpStatus)
async def totp_status(actor: CurrentActor) -> TotpStatus:
    user = _require_interactive_user(actor)
    return TotpStatus(
        enabled=user.totp_enabled,
        pending=user.totp_pending_secret_encrypted is not None and not user.totp_enabled,
    )


@router.post("/2fa/setup", response_model=TotpSetupResponse)
async def totp_setup(actor: CurrentActor, db: DbSession) -> TotpSetupResponse:
    user = _require_interactive_user(actor)
    if user.totp_enabled:
        raise bad_request("2fa already enabled; disable first to re-enroll")
    secret = totp_service.generate_secret()
    user.totp_pending_secret_encrypted = totp_service.encrypt_secret(secret)
    await audit.record(
        db,
        actor=actor,
        action="user.2fa.setup_started",
        resource_type="user",
        resource_id=str(user.id),
    )
    return TotpSetupResponse(
        secret_base32=secret,
        provisioning_uri=totp_service.provisioning_uri(secret, account_name=user.email),
    )


@router.post("/2fa/verify-setup", response_model=TotpVerifySetupResponse)
async def totp_verify_setup(
    payload: TotpVerifySetupRequest, actor: CurrentActor, db: DbSession
) -> TotpVerifySetupResponse:
    user = _require_interactive_user(actor)
    if user.totp_enabled:
        raise bad_request("2fa already enabled")
    if user.totp_pending_secret_encrypted is None:
        raise bad_request("no pending 2fa enrollment; call /2fa/setup first")
    pending = totp_service.decrypt_secret(user.totp_pending_secret_encrypted)
    if not totp_service.verify_code(pending, payload.code):
        raise bad_request("code did not match — try again")

    plaintext_codes, hashed_codes = totp_service.generate_recovery_codes()
    user.totp_secret_encrypted = user.totp_pending_secret_encrypted
    user.totp_pending_secret_encrypted = None
    user.totp_enabled = True
    user.totp_recovery_codes_hashed = hashed_codes
    await audit.record(
        db,
        actor=actor,
        action="user.2fa.enabled",
        resource_type="user",
        resource_id=str(user.id),
    )
    return TotpVerifySetupResponse(recovery_codes=plaintext_codes)


@router.post("/2fa/disable", status_code=204)
async def totp_disable(
    payload: TotpDisableRequest, actor: CurrentActor, db: DbSession, response: Response
) -> Response:
    user = _require_interactive_user(actor)
    if not user.totp_enabled:
        raise bad_request("2fa is not enabled on this account")
    if not await _consume_2fa_code(user, payload.code, db):
        raise unauthorized("invalid 2fa code")
    user.totp_enabled = False
    user.totp_secret_encrypted = None
    user.totp_pending_secret_encrypted = None
    user.totp_recovery_codes_hashed = None
    await audit.record(
        db,
        actor=actor,
        action="user.2fa.disabled",
        resource_type="user",
        resource_id=str(user.id),
    )
    response.status_code = 204
    return response


# ---------- OIDC SSO (Phase 1 #1.6) --------------------------------
#
# Authorization-code flow with PKCE. The frontend just GETs
# /oidc/authorize and follows the redirect to the IdP; on success the
# IdP redirects back to /oidc/callback which provisions / matches the
# local user, issues a token pair, sets the refresh cookie, and
# redirects to /dashboard. The access token is NOT in the redirect URL
# — instead the SPA loads /dashboard, finds no in-memory access token,
# and POSTs /refresh which the HttpOnly cookie satisfies.


# Cookie that holds the (state, nonce, code_verifier) tuple between
# /oidc/authorize and /oidc/callback. Short-lived; only valid during a
# single SSO handshake.
_OIDC_STATE_COOKIE = "vigil_oidc_state"
_OIDC_STATE_TTL_SECONDS = 300


def _set_oidc_state_cookie(response: Response, value: str) -> None:
    """Stash the state-bundle for the duration of the IdP round-trip.
    HttpOnly + SameSite=Lax so the cookie does come back through the
    cross-site redirect — Strict would drop it on the IdP→callback
    leg even though that's the leg that needs it."""
    response.set_cookie(
        key=_OIDC_STATE_COOKIE,
        value=value,
        max_age=_OIDC_STATE_TTL_SECONDS,
        httponly=True,
        secure=not settings.debug,
        samesite="lax",
        path="/api/auth",
    )


def _clear_oidc_state_cookie(response: Response) -> None:
    response.delete_cookie(key=_OIDC_STATE_COOKIE, path="/api/auth")


def _resolve_default_role() -> UserRole:
    """Map the configured default-role string to the enum. Anything
    unrecognised falls back to VIEWER — least privilege is the safer
    default if an operator mistypes the env var."""
    name = (settings.oidc_default_role or "viewer").lower()
    for role in UserRole:
        if role.value == name:
            return role
    return UserRole.VIEWER


@router.get("/oidc/discovery", response_model=OidcDiscoveryResponse)
async def oidc_discovery() -> OidcDiscoveryResponse:
    """Tiny gate the SPA hits on /login to decide whether to render the
    'Sign in with SSO' button. Doesn't expose any of the IdP-side
    secrets — just the boolean."""
    return OidcDiscoveryResponse(enabled=settings.oidc_enabled)


@router.get("/oidc/authorize")
async def oidc_authorize() -> RedirectResponse:
    """Mint state + nonce + code_verifier, set as a single HttpOnly
    cookie, and 302 to the IdP's authorization endpoint."""
    if not settings.oidc_enabled:
        raise bad_request("oidc is not enabled")

    discovery = await oidc_service.get_discovery()
    state = oidc_service.generate_state()
    nonce = oidc_service.generate_nonce()
    code_verifier = oidc_service.generate_code_verifier()
    code_challenge = oidc_service.code_challenge_for(code_verifier)

    # Pack the three values into the cookie. The cookie is HttpOnly so
    # the SPA can't read it; we just need to recover them on callback.
    cookie_value = f"{state}.{nonce}.{code_verifier}"

    params = {
        "response_type": "code",
        "client_id": settings.oidc_client_id,
        "redirect_uri": settings.oidc_redirect_uri,
        "scope": "openid email profile",
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    redirect_url = f"{discovery.authorization_endpoint}?{urllib.parse.urlencode(params)}"

    # FastAPI's RedirectResponse needs the Set-Cookie header attached
    # to itself, not the dependency-injected `response` — they're
    # different objects on a redirect.
    redirect = RedirectResponse(url=redirect_url, status_code=302)
    _set_oidc_state_cookie(redirect, cookie_value)
    return redirect


async def _provision_or_match_oidc_user(
    db: DbSession,
    *,
    claims: dict,
    actor_ip: str | None,
) -> User:
    """Find-or-provision logic. Three branches:

    1. ``oidc_subject`` already maps to a row — that's the user.
    2. Email matches an existing password user but no subject yet —
       link the row to the OIDC sub (audit-recorded as
       ``user.oidc_link``).
    3. Neither — provision a fresh row with the default role
       (audit-recorded as ``user.provision``).
    """
    sub = claims["sub"]
    issuer = claims.get("iss") or settings.oidc_issuer_url
    email = (claims.get("email") or "").lower()

    user = (await db.execute(select(User).where(User.oidc_subject == sub))).scalar_one_or_none()
    if user is not None:
        # Stale email in claims is informational; keep the canonical
        # column in sync so admin views show what the IdP last sent.
        if email and user.oidc_email != email:
            user.oidc_email = email
        return user

    if email:
        existing = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
        if existing is not None:
            existing.oidc_subject = sub
            existing.oidc_issuer = issuer
            existing.oidc_email = email
            await audit.record(
                db,
                actor=None,
                action="user.oidc_link",
                resource_type="user",
                resource_id=str(existing.id),
                payload={"issuer": issuer, "email": email},
                ip=actor_ip,
            )
            return existing

    # Password is a fresh random hash the user can't log in with —
    # they're an OIDC user. Filling something in keeps the NOT NULL
    # column constraint satisfied without a schema change.
    new_user = User(
        email=email or f"oidc-{sub[:12]}@unknown.local",
        password_hash=hash_password(generate_api_token_secret()),
        role=_resolve_default_role(),
        oidc_subject=sub,
        oidc_issuer=issuer,
        oidc_email=email or None,
    )
    db.add(new_user)
    await db.flush()
    await audit.record(
        db,
        actor=None,
        action="user.provision",
        resource_type="user",
        resource_id=str(new_user.id),
        payload={"issuer": issuer, "email": email, "role": new_user.role.value},
        ip=actor_ip,
    )
    return new_user


@router.get("/oidc/callback")
async def oidc_callback(
    request: Request,
    db: DbSession,
    code: str | None = None,
    state: str | None = None,
    vigil_oidc_state: str | None = Cookie(default=None),
) -> RedirectResponse:
    """The IdP redirects here with ``?code=&state=``. We verify state,
    exchange the code, validate the ID token (including nonce), find
    or provision the local user, issue a token pair, set the refresh
    cookie, and 302 to /dashboard."""
    if not settings.oidc_enabled:
        raise bad_request("oidc is not enabled")
    if not code or not state:
        raise bad_request("missing code or state on oidc callback")
    if not vigil_oidc_state:
        raise unauthorized("oidc state cookie missing")

    parts = vigil_oidc_state.split(".")
    if len(parts) != 3:
        raise unauthorized("oidc state cookie malformed")
    cookie_state, cookie_nonce, code_verifier = parts
    if state != cookie_state:
        raise unauthorized("oidc state mismatch")

    try:
        token_resp = await oidc_service.exchange_code(code=code, code_verifier=code_verifier)
    except oidc_service.OidcError as exc:
        raise unauthorized("oidc code exchange failed") from exc

    id_token = token_resp.get("id_token")
    if not id_token:
        raise unauthorized("oidc response missing id_token")

    try:
        claims = await oidc_service.validate_id_token(id_token, expected_nonce=cookie_nonce)
    except oidc_service.OidcError as exc:
        raise unauthorized("oidc id_token invalid") from exc

    ip = request.client.host if request.client else None
    user = await _provision_or_match_oidc_user(db, claims=claims, actor_ip=ip)
    if user.disabled:
        raise unauthorized("user inactive")

    await audit.record(
        db,
        actor=None,
        action="user.login",
        resource_type="user",
        resource_id=str(user.id),
        payload={"method": "oidc"},
        ip=ip,
    )

    pair = auth_service.issue_token_pair(user)
    redirect = RedirectResponse(url="/dashboard", status_code=302)
    _set_refresh_cookie(redirect, pair["refresh_token"])
    _clear_oidc_state_cookie(redirect)
    return redirect
