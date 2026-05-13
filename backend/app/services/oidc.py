"""OIDC authorization-code flow helpers (Phase 1 #1.6).

The HTTP-layer wiring is in ``app.api.auth``; this module owns the
side effects that talk to the IdP:

  * Discovery — pulls ``/.well-known/openid-configuration`` once per
    process and caches the result. Discovery is cheap but blocking;
    we don't want every callback to re-fetch.
  * JWKS — fetched on demand via ``httpx`` (NOT PyJWT's
    ``PyJWKClient`` — that uses synchronous ``urllib`` internally,
    which means tests can't intercept it via respx + makes the
    callback handler block the event loop). We cache the parsed JWKS
    in-process and fall back to a refetch on a ``kid`` cache miss so
    IdP key rollover doesn't need a manager restart.
  * Code exchange — POST to the token endpoint with client credentials
    (HTTP Basic + Confidential client) and the ``code`` returned by
    the IdP redirect. Returns the parsed JSON body.
  * ID-token validation — verifies signature, issuer, audience, expiry,
    and the ``nonce`` claim against the one we set as a cookie. Reject
    on any mismatch — the OIDC spec is unforgiving here for good reason.

PKCE is recommended (``S256``); we always emit ``code_challenge`` so a
public-client misconfiguration on the IdP side still buys us protection.

The module never logs the ``client_secret``. The token-endpoint POST
uses HTTP Basic auth which keeps the secret out of any structlog/uvicorn
access log that records bodies; if you swap the transport, audit that
contract.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import secrets
from dataclasses import dataclass
from typing import Any

import httpx
import jwt
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

from app.core.config import settings


class OidcError(RuntimeError):
    """Anything that prevents a successful OIDC login. Mapped to a
    generic 401 at the HTTP boundary — we never surface IdP error
    bodies to the client because they're a server-side concern."""


@dataclass(frozen=True)
class DiscoveryDoc:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    userinfo_endpoint: str | None = None


# Process-wide cache. Discovery rarely changes; the JWKS cache is
# keyed by ``kid`` so an IdP key rollover refetches automatically on
# first miss without a manager restart.
_discovery_cache: dict[str, DiscoveryDoc] = {}
_discovery_lock = asyncio.Lock()
# JWKS cache: jwks_uri → kid → loaded signing key.
_jwks_cache: dict[str, dict[str, Any]] = {}
_jwks_lock = asyncio.Lock()


def _discovery_url(issuer_url: str) -> str:
    """Build the discovery URL. OIDC spec: the well-known path is
    appended verbatim to the issuer URL after stripping the trailing
    slash. Don't try to be clever about query strings — the issuer
    URL shouldn't have them."""
    base = issuer_url.rstrip("/")
    return f"{base}/.well-known/openid-configuration"


async def get_discovery(issuer_url: str | None = None) -> DiscoveryDoc:
    """Fetch and cache the IdP discovery document. Subsequent calls
    return the cached copy; rotation requires a manager restart."""
    issuer_url = issuer_url or settings.oidc_issuer_url
    if not issuer_url:
        raise OidcError("oidc issuer URL is not configured")
    cached = _discovery_cache.get(issuer_url)
    if cached is not None:
        return cached
    async with _discovery_lock:
        cached = _discovery_cache.get(issuer_url)
        if cached is not None:
            return cached
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(_discovery_url(issuer_url))
                resp.raise_for_status()
                body = resp.json()
        except httpx.HTTPError as exc:
            raise OidcError(f"oidc discovery failed: {exc}") from exc
        try:
            doc = DiscoveryDoc(
                issuer=body["issuer"],
                authorization_endpoint=body["authorization_endpoint"],
                token_endpoint=body["token_endpoint"],
                jwks_uri=body["jwks_uri"],
                userinfo_endpoint=body.get("userinfo_endpoint"),
            )
        except KeyError as exc:
            raise OidcError(f"oidc discovery doc missing required field: {exc}") from exc
        _discovery_cache[issuer_url] = doc
        return doc


def _key_from_jwk(jwk: dict[str, Any]) -> Any:
    """Materialise a signing key from a JWK entry. PyJWT exposes
    algorithm-specific ``from_jwk`` builders that handle RSA + EC
    cleanly; HS* keys aren't legal in the OIDC ID-token context
    (symmetric secret would have to be shared with the IdP) and we
    refuse them explicitly."""
    kty = jwk.get("kty")
    if kty == "RSA":
        return RSAAlgorithm.from_jwk(jwk)
    if kty == "EC":
        return ECAlgorithm.from_jwk(jwk)
    raise OidcError(f"unsupported JWK kty: {kty}")


async def _fetch_jwks(jwks_uri: str) -> dict[str, Any]:
    """Pull the JWKS doc and index by kid. Cached per process; a
    cache miss on ``kid`` (e.g. IdP rotated keys) triggers a refetch
    via ``_signing_key_for``."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(jwks_uri)
            resp.raise_for_status()
            doc = resp.json()
    except httpx.HTTPError as exc:
        raise OidcError(f"jwks fetch failed: {exc}") from exc
    keys: dict[str, Any] = {}
    for jwk in doc.get("keys", []):
        kid = jwk.get("kid")
        if not kid:
            continue
        try:
            keys[kid] = _key_from_jwk(jwk)
        except (OidcError, Exception):  # noqa: BLE001 — skip unparseable entries
            continue
    return keys


async def get_signing_key(jwks_uri: str, kid: str) -> Any:
    """Return the signing key for ``kid`` from the JWKS at ``jwks_uri``.

    On a cache miss the JWKS doc is refetched once — that covers the
    IdP-rotated-keys path without a manager restart. A second miss
    raises ``OidcError`` rather than retrying forever.
    """
    cached = _jwks_cache.get(jwks_uri, {})
    key = cached.get(kid)
    if key is not None:
        return key
    async with _jwks_lock:
        cached = _jwks_cache.get(jwks_uri, {})
        key = cached.get(kid)
        if key is not None:
            return key
        fresh = await _fetch_jwks(jwks_uri)
        _jwks_cache[jwks_uri] = fresh
        key = fresh.get(kid)
        if key is None:
            raise OidcError(f"jwks has no key for kid={kid}")
        return key


# ---------- PKCE + state/nonce helpers -----------------------------


def generate_state() -> str:
    """URL-safe state token, 32 bytes of entropy. Set as a cookie
    before the redirect and compared on callback to defeat CSRF on the
    authorization-code flow."""
    return secrets.token_urlsafe(32)


def generate_nonce() -> str:
    """ID-token nonce. Embedded in the auth-request and checked on the
    returned ID token to defeat token-replay between sessions."""
    return secrets.token_urlsafe(32)


def generate_code_verifier() -> str:
    """RFC 7636 PKCE code_verifier: 43..128 chars from the unreserved
    set. token_urlsafe gives us 43+ chars at 32 bytes, which is well
    above the spec minimum."""
    return secrets.token_urlsafe(32)


def code_challenge_for(code_verifier: str) -> str:
    """RFC 7636 S256 challenge: base64url(SHA256(verifier)) with no
    padding."""
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


# ---------- Code exchange + token validation -----------------------


async def exchange_code(
    *,
    code: str,
    code_verifier: str,
    redirect_uri: str | None = None,
) -> dict[str, Any]:
    """POST to the IdP's token endpoint and return the JSON body.

    Uses HTTP Basic auth for the confidential-client credentials so the
    secret doesn't end up in a form-encoded body that a misconfigured
    proxy might log. PKCE ``code_verifier`` is mandatory: we always
    emit a ``code_challenge`` on the authorize leg, so the IdP will
    require the verifier here.
    """
    discovery = await get_discovery()
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri or settings.oidc_redirect_uri,
        "code_verifier": code_verifier,
    }
    auth = (settings.oidc_client_id, settings.oidc_client_secret)
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                discovery.token_endpoint,
                data=payload,
                auth=auth,
                headers={"Accept": "application/json"},
            )
            # Don't leak the response body — IdP errors may echo back
            # the redirect URI which a SOC scrub log shouldn't see in
            # plaintext. Just raise on non-2xx with the status code.
            if resp.status_code >= 400:
                raise OidcError(f"token endpoint returned {resp.status_code}")
            return resp.json()
    except httpx.HTTPError as exc:
        raise OidcError(f"token exchange failed: {exc}") from exc


async def validate_id_token(
    id_token: str,
    *,
    expected_nonce: str,
    audience: str | None = None,
) -> dict[str, Any]:
    """Verify signature + issuer + audience + exp + nonce. Returns the
    decoded claims on success; raises OidcError on any failure.

    The signing key is fetched via ``get_signing_key`` (httpx-backed
    JWKS fetch + cache), then handed to PyJWT for signature + claim
    verification.

    We pass ``options={"require": ["exp", "iat", "iss", "aud", "sub"]}``
    so PyJWT refuses a token that's missing any of the mandatory
    claims — that's the line where a misconfigured IdP becomes a
    silent vulnerability if we ever fall back to "missing claim is
    OK".
    """
    issuer_url = settings.oidc_issuer_url
    audience = audience or settings.oidc_client_id
    discovery = _discovery_cache.get(issuer_url)
    if discovery is None:
        # Callers reach this after exchange_code has already populated
        # the cache, so missing discovery here would be a logic bug —
        # fail loudly rather than swallowing.
        raise OidcError("oidc discovery has not been initialised")

    try:
        header = jwt.get_unverified_header(id_token)
    except jwt.PyJWTError as exc:
        raise OidcError(f"id_token header parse failed: {exc}") from exc
    kid = header.get("kid")
    if not kid:
        raise OidcError("id_token header missing kid")

    signing_key = await get_signing_key(discovery.jwks_uri, kid)

    try:
        claims = jwt.decode(
            id_token,
            signing_key,
            algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
            audience=audience,
            issuer=discovery.issuer,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise OidcError("id_token expired") from exc
    except jwt.InvalidIssuerError as exc:
        raise OidcError("id_token issuer mismatch") from exc
    except jwt.InvalidAudienceError as exc:
        raise OidcError("id_token audience mismatch") from exc
    except jwt.PyJWTError as exc:
        raise OidcError(f"id_token validation failed: {exc}") from exc

    nonce_claim = claims.get("nonce")
    if nonce_claim != expected_nonce:
        raise OidcError("id_token nonce mismatch")
    return claims


# ---------- Test hooks ---------------------------------------------


def _reset_caches_for_tests() -> None:
    """Tests that swap the issuer URL between cases need to drop the
    cached discovery doc + JWKS keys. Production never calls this."""
    _discovery_cache.clear()
    _jwks_cache.clear()
