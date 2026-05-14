"""Okta System Log API v1 client (Phase 4 #4.3).

Pulls `GET /api/v1/logs` from an operator-configured Okta tenant
using a Single-Sign-On API token (SSWS scheme). Returns the events
normalised into the common identity-event shape so the detectors and
the worker stay provider-agnostic.

Reference: https://developer.okta.com/docs/reference/api/system-log/

The config dict the API hands us looks like:

    {
        "domain": "example.okta.com",  # no scheme
        "api_token": "00abc…",          # SSWS token
    }

Auth: `Authorization: SSWS <token>` header. Okta accepts ISO-8601
`since=` and a `limit` (max 1000) to scope the page; pagination is
implemented via the `Link: <url>; rel="next"` response header, but
the monitor only ever asks for one page per tick because the cadence
is short (5 min default) and the burst that exceeds 1000 events per
tick is an attack signal in its own right.

We use `httpx.AsyncClient` (not `aiohttp`) so the existing test
infrastructure's `respx` mocks work without an extra transport
shim — same convention as `app.services.intel.taxii`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import httpx
import structlog

from app.services.identity import GeoPoint, IdentityEvent, parse_iso_ts

log = structlog.get_logger()


# Hard cap on per-tick fetch so a misconfigured `since` cursor that
# reaches back to the start of the tenant's history can't blow memory.
OKTA_PAGE_LIMIT: int = 1000

# Default outer HTTP timeout. The Okta SLA is well under this; the
# generous floor is so a transiently slow upstream just records
# `last_error` and moves on rather than wedging the worker loop.
_DEFAULT_TIMEOUT_S: float = 30.0


class OktaConfigError(ValueError):
    """The stored config is missing a required field. Raised at poll
    time so the worker records `last_error` against the source row."""


def _require(config: dict[str, Any], key: str) -> str:
    value = config.get(key)
    if not isinstance(value, str) or not value.strip():
        raise OktaConfigError(f"Okta config missing required field: {key}")
    return value.strip()


def _extract_actor_email(event: dict[str, Any]) -> str:
    """Okta puts the acting principal under `actor.alternateId` (the
    user's primary email) most of the time. For service-account
    flows the field can be a `<id>@<domain>` synthetic; we still
    take it as-is — the detectors only use it as a grouping key."""
    actor = event.get("actor") or {}
    alt = actor.get("alternateId")
    if isinstance(alt, str) and alt:
        return alt.strip().lower()
    return ""


def _extract_src_ip(event: dict[str, Any]) -> str | None:
    """The first client.ipAddress entry — Okta always carries it on
    sign-in events. NULL on internal admin events that don't have a
    client IP."""
    client = event.get("client") or {}
    ip = client.get("ipAddress")
    if isinstance(ip, str) and ip:
        return ip
    return None


def _extract_geo(event: dict[str, Any]) -> GeoPoint | None:
    """Okta's geographicalContext carries lat/lon under `geolocation`
    and the ISO country code under `country`. We tolerate either
    half missing — the impossible-travel detector skips events
    without coordinates."""
    client = event.get("client") or {}
    geo = client.get("geographicalContext") or {}
    geoloc = geo.get("geolocation") or {}
    lat = geoloc.get("lat")
    lon = geoloc.get("lon")
    country = geo.get("country")
    if not isinstance(lat, int | float) or not isinstance(lon, int | float):
        return None
    out: GeoPoint = {"lat": float(lat), "lon": float(lon)}
    if isinstance(country, str) and country:
        out["country"] = country
    return out


def _extract_success(event: dict[str, Any]) -> bool:
    """Okta tags every event with `outcome.result` in
    `{SUCCESS, FAILURE, SKIPPED, ALLOW, DENY, CHALLENGE}`. Anything
    other than `SUCCESS` / `ALLOW` we treat as not-successful for the
    detectors — `CHALLENGE` is interesting (MFA prompt) but the
    detector logic explicitly looks for that via `action` rather than
    `success`."""
    outcome = event.get("outcome") or {}
    result = outcome.get("result")
    return result in ("SUCCESS", "ALLOW")


def _normalise_event(raw: dict[str, Any]) -> IdentityEvent | None:
    """Lower one upstream Okta log row into our common shape. Returns
    None when the row is unusable (missing ts / eventType)."""
    ts_raw = raw.get("published")
    if not isinstance(ts_raw, str):
        return None
    try:
        ts = parse_iso_ts(ts_raw)
    except ValueError:
        return None
    action = raw.get("eventType")
    if not isinstance(action, str):
        return None
    event: IdentityEvent = {
        "ts": ts,
        "actor_email": _extract_actor_email(raw),
        "action": action,
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
    limit: int = OKTA_PAGE_LIMIT,
) -> list[IdentityEvent]:
    """Pull a page of Okta System Log events strictly after `after_ts`.

    `after_ts=None` fetches the most recent page; the worker uses this
    on first poll so we don't reach back to the start of time. A
    HTTP / parse error propagates as RuntimeError so the worker
    records `last_error` on the source row.

    `client` lets tests inject a pre-mocked transport; production
    callers leave it None and we open a fresh client with the
    default timeout.
    """
    domain = _require(config, "domain")
    api_token = _require(config, "api_token")
    url = f"https://{domain}/api/v1/logs"
    params: dict[str, str] = {"limit": str(min(int(limit), OKTA_PAGE_LIMIT))}
    if after_ts is not None:
        # Okta's `since` parameter is a strict lower bound — events
        # with ts > since are returned. We send the high-water mark
        # in ISO-8601 with explicit `Z` (Okta tolerates `+00:00` but
        # the docs spell `Z`).
        params["since"] = after_ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }

    own_client = client is None
    cl = client if client is not None else httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT_S)
    try:
        resp = await cl.get(url, headers=headers, params=params)
        if resp.status_code >= 400:
            body = resp.text[:512]
            raise RuntimeError(f"Okta API returned {resp.status_code}: {body}")
        raw_list = resp.json()
    finally:
        if own_client:
            await cl.aclose()

    if not isinstance(raw_list, list):
        raise RuntimeError("Okta API returned a non-list payload")

    out: list[IdentityEvent] = []
    for raw in raw_list:
        if not isinstance(raw, dict):
            continue
        ev = _normalise_event(cast(dict[str, Any], raw))
        if ev is not None:
            out.append(ev)
    log.info("identity.okta.fetched", count=len(out), domain=domain)
    return out


__all__ = ["OKTA_PAGE_LIMIT", "OktaConfigError", "fetch_events"]
