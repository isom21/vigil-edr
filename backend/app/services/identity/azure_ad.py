"""Microsoft Graph `/auditLogs/signIns` client (Phase 4 #4.3).

Pulls Azure AD interactive + non-interactive sign-in logs via the
Microsoft Graph beta endpoint and normalises them into the common
identity-event shape so the worker + detectors stay
provider-agnostic.

Reference:
  https://learn.microsoft.com/en-us/graph/api/signin-list

Auth flow: OAuth2 client_credentials against the operator-configured
Azure tenant. We exchange the cached client_id / client_secret for a
short-lived bearer token (typ ~60 min TTL).

The config dict the API hands us looks like:

    {
        "tenant_id":     "<azure-tenant-uuid>",
        "client_id":     "<app-registration-client-id>",
        "client_secret": "<app-registration-secret>",
    }

The app registration needs `AuditLog.Read.All` application
permission; the admin consent dance happens out-of-band when the
operator first wires the integration.

We use `httpx.AsyncClient` (not `aiohttp`) so the existing test
infrastructure's `respx` mocks intercept the OAuth + Graph calls
without an extra transport shim — same convention as
`app.services.intel.custom_json`.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any, cast

import httpx
import structlog

from app.services.identity import GeoPoint, IdentityEvent, parse_iso_ts

log = structlog.get_logger()


_DEFAULT_TIMEOUT_S: float = 30.0

# Hard cap on per-tick page size — same rationale as the Okta client.
AZURE_PAGE_LIMIT: int = 1000

# Token cache TTL haircut — Azure returns the lifetime in seconds in
# `expires_in`. We expire local copies 60 s before the upstream claim
# so a poll mid-window doesn't 401 on a token that just rolled over.
_TOKEN_EXPIRY_SAFETY_S: float = 60.0


class AzureConfigError(ValueError):
    """The stored config is missing a required field. Raised at poll
    time so the worker records `last_error` against the source row."""


def _require(config: dict[str, Any], key: str) -> str:
    value = config.get(key)
    if not isinstance(value, str) or not value.strip():
        raise AzureConfigError(f"Azure AD config missing required field: {key}")
    return value.strip()


async def _acquire_token(
    config: dict[str, Any],
    client: httpx.AsyncClient,
) -> tuple[str, float]:
    """Run an OAuth2 client_credentials exchange. Returns (token,
    expires_at_monotonic).

    Raises RuntimeError on a non-2xx response so the caller records
    `last_error` and skips the rest of this tick."""
    tenant_id = _require(config, "tenant_id")
    client_id = _require(config, "client_id")
    client_secret = _require(config, "client_secret")
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials",
    }
    resp = await client.post(url, data=data)
    if resp.status_code >= 400:
        body = resp.text[:512]
        raise RuntimeError(f"Azure AD token endpoint returned {resp.status_code}: {body}")
    payload = resp.json()
    token = payload.get("access_token")
    expires_in = payload.get("expires_in")
    if not isinstance(token, str) or not isinstance(expires_in, int | float):
        raise RuntimeError("Azure AD token endpoint returned malformed payload")
    expires_at = time.monotonic() + max(0.0, float(expires_in) - _TOKEN_EXPIRY_SAFETY_S)
    return token, expires_at


def _extract_actor_email(event: dict[str, Any]) -> str:
    """Graph carries the signing-in user under `userPrincipalName`
    (UPN), which is the closest thing to an email Azure offers. For
    guest accounts that's `<external>#EXT#@<tenant>.onmicrosoft.com`;
    the detectors don't try to dereference that — they just use it
    as a stable per-actor grouping key."""
    upn = event.get("userPrincipalName")
    if isinstance(upn, str) and upn:
        return upn.strip().lower()
    return ""


def _extract_src_ip(event: dict[str, Any]) -> str | None:
    ip = event.get("ipAddress")
    if isinstance(ip, str) and ip:
        return ip
    return None


def _extract_geo(event: dict[str, Any]) -> GeoPoint | None:
    """Graph nests geo under `location.geoCoordinates` (lat/lon) plus
    a top-level `location.countryOrRegion`. Either half can be
    missing on a corporate-network sign-in that didn't trigger geo
    resolution."""
    loc = event.get("location") or {}
    coords = loc.get("geoCoordinates") or {}
    lat = coords.get("latitude")
    lon = coords.get("longitude")
    country = loc.get("countryOrRegion")
    if not isinstance(lat, int | float) or not isinstance(lon, int | float):
        return None
    out: GeoPoint = {"lat": float(lat), "lon": float(lon)}
    if isinstance(country, str) and country:
        out["country"] = country
    return out


def _extract_success(event: dict[str, Any]) -> bool:
    """Graph carries a `status.errorCode` integer — 0 means success;
    any non-zero is a failure (the specific code is the AAD error
    catalogue, e.g. 50126 = wrong password, 50053 = locked out,
    50158 = MFA required). The detectors look at `action` for MFA
    semantics; here we only need the binary."""
    status = event.get("status") or {}
    code = status.get("errorCode")
    if isinstance(code, int | float):
        return int(code) == 0
    return False


def _extract_action(event: dict[str, Any]) -> str:
    """Graph doesn't carry a discrete `action` field — every row
    is a sign-in attempt. We synthesise a value from the auth
    method + status so the downstream detectors can pattern-match on
    MFA-specific flows (e.g. `mfa_challenge`) without provider-
    specific code paths."""
    # `authenticationDetails` is a list of step records; the last
    # entry typically carries the final MFA outcome.
    details = event.get("authenticationDetails")
    if isinstance(details, list) and details:
        last = details[-1]
        if isinstance(last, dict):
            requirement = last.get("authenticationStepRequirement")
            if isinstance(requirement, str) and "mfa" in requirement.lower():
                return "azure.signin.mfa_challenge"
    # Status 50158 specifically means "MFA required" — the user's
    # primary credential succeeded but the MFA prompt is pending.
    status = event.get("status") or {}
    code = status.get("errorCode")
    if isinstance(code, int | float) and int(code) == 50158:
        return "azure.signin.mfa_challenge"
    return "azure.signin"


def _normalise_event(raw: dict[str, Any]) -> IdentityEvent | None:
    ts_raw = raw.get("createdDateTime")
    if not isinstance(ts_raw, str):
        return None
    try:
        ts = parse_iso_ts(ts_raw)
    except ValueError:
        return None
    event: IdentityEvent = {
        "ts": ts,
        "actor_email": _extract_actor_email(raw),
        "action": _extract_action(raw),
        "src_ip": _extract_src_ip(raw),
        "src_geo": _extract_geo(raw),
        "success": _extract_success(raw),
    }
    return event


async def fetch_events(
    config: dict[str, Any],
    after_ts: datetime | None,
    *,
    client: httpx.AsyncClient | None = None,
    limit: int = AZURE_PAGE_LIMIT,
    token_override: str | None = None,
) -> list[IdentityEvent]:
    """Pull a page of Azure AD sign-in events strictly after
    `after_ts`. `after_ts=None` fetches the most recent page.

    `token_override` lets tests skip the OAuth2 exchange entirely
    when mocking the Graph endpoint at the integration boundary;
    production calls leave it None and pay one extra round-trip per
    fresh token.
    """
    url = "https://graph.microsoft.com/beta/auditLogs/signIns"
    params: dict[str, str] = {"$top": str(min(int(limit), AZURE_PAGE_LIMIT))}
    if after_ts is not None:
        # Graph uses `$filter=createdDateTime gt …` for strict-greater
        # cursoring; the timestamp must be ISO-8601 Z.
        ts_str = after_ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        params["$filter"] = f"createdDateTime gt {ts_str}"

    own_client = client is None
    cl = client if client is not None else httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT_S)
    try:
        token = token_override
        if token is None:
            token, _ = await _acquire_token(config, cl)
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        resp = await cl.get(url, headers=headers, params=params)
        if resp.status_code >= 400:
            body = resp.text[:512]
            raise RuntimeError(f"Graph signIns returned {resp.status_code}: {body}")
        payload = resp.json()
    finally:
        if own_client:
            await cl.aclose()

    raw_list = payload.get("value") if isinstance(payload, dict) else None
    if not isinstance(raw_list, list):
        raise RuntimeError("Graph signIns returned a payload without `value`")

    out: list[IdentityEvent] = []
    for raw in raw_list:
        if not isinstance(raw, dict):
            continue
        ev = _normalise_event(cast(dict[str, Any], raw))
        if ev is not None:
            out.append(ev)
    log.info("identity.azure_ad.fetched", count=len(out))
    return out


__all__ = ["AZURE_PAGE_LIMIT", "AzureConfigError", "fetch_events"]
