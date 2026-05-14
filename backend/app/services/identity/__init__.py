"""Identity threat detection services (Phase 4 #4.3).

Three submodules wire together:

  * `okta` — Okta System Log API v1 client (aiohttp).
  * `azure_ad` — Microsoft Graph `/auditLogs/signIns` client (aiohttp).
  * `detectors` — pure functions that turn normalised event sequences
    into alert decisions (impossible travel, brute force, MFA bombing,
    password spray).

Both fetchers return events in a common normalised dict shape:

    {
        "ts": datetime,          # UTC
        "actor_email": str,      # downcased; "" when unknown
        "action": str,           # provider-native event type
        "src_ip": str | None,
        "src_geo": {"lat": float, "lon": float, "country": str} | None,
        "success": bool,
    }

This keeps the worker + detectors free of provider-specific shape
knowledge — the only place that touches the upstream JSON layouts is
inside each fetcher module.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TypedDict


class GeoPoint(TypedDict, total=False):
    lat: float
    lon: float
    country: str


def parse_iso_ts(raw: str) -> datetime:
    """Parse an ISO-8601 timestamp into a tz-aware UTC datetime.

    Both Okta and Microsoft Graph emit `…Z`-suffixed strings that
    Python's `fromisoformat` only learned to handle in 3.11; we
    normalise the suffix here so both fetchers share one parse path.
    Raises ValueError on malformed input — the caller catches it
    and drops the row.
    """
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


class IdentityEvent(TypedDict):
    """Normalised shape every fetcher returns. `src_ip` and `src_geo`
    are `| None` for providers that don't resolve geo (e.g. Okta when
    the IP isn't in the geo database); all keys are always present."""

    ts: object  # datetime (UTC). object-typed so the TypedDict stays import-cheap.
    actor_email: str
    action: str
    src_ip: str | None
    src_geo: GeoPoint | None
    success: bool


__all__ = ["GeoPoint", "IdentityEvent", "parse_iso_ts"]
