"""Identity threat detectors (Phase 4 #4.3).

Pure functions over the normalised identity-event stream
(`app.services.identity.IdentityEvent`). Every detector returns a
``DetectorHit`` (or ``None`` when no alert should fire) so the worker
can map hits 1:1 to ``Alert`` rows without re-deriving severity or
summary text.

Detector catalog:

* `impossible_travel(prev, curr, max_kmph=800)` — two successful
  logins from the same actor whose geo coordinates would require
  travel faster than 800 km/h (commercial-jet ceiling). Returns a
  hit when the implied speed exceeds the threshold AND both events
  carry geo coordinates.
* `brute_force(events, window_s=300, threshold=10)` — count failed
  logins for one actor inside a sliding window. Returns a hit when
  the count crosses `threshold`.
* `mfa_bomb(events, window_s=300, threshold=5)` — count MFA
  challenges (any provider) for one actor inside the window.
  `threshold` MFA prompts inside the window implies push-fatigue
  abuse.
* `password_spray(events_by_ip, window_s=300, distinct_users=8)` —
  one source IP touching `distinct_users` distinct accounts inside
  the window with a failed credential. The classic horizontal sweep
  pattern.

Why separate functions per detector and not a single pipeline:

1. Each detector has its own input shape (pair-vs-list-vs-grouped),
   so a single pipeline would still need a per-detector adapter.
2. Tests live one-to-one against these functions, which keeps the
   pure-logic surface small and the property tests local.
3. The worker can run any subset of detectors per source. A future
   "only impossible travel for this Okta tenant" config knob lives
   on the source row, not in shared code.
"""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from app.models import Severity
from app.models.synthetic_rules import (
    IDENTITY_BRUTE_FORCE_RULE_ID,
    IDENTITY_IMPOSSIBLE_TRAVEL_RULE_ID,
    IDENTITY_MFA_BOMB_RULE_ID,
    IDENTITY_PASSWORD_SPRAY_RULE_ID,
)
from app.services.identity import IdentityEvent

# Earth's mean radius in km (WGS-84 approximation good to 0.5%).
_EARTH_RADIUS_KM: float = 6371.0


@dataclass(frozen=True)
class DetectorHit:
    """Decoupled from `app.models.Alert` so detectors stay pure and
    callable from tests without a DB session. The worker maps each
    hit 1:1 onto an Alert row."""

    rule_id: object  # uuid.UUID, kept as object to avoid an import dep.
    severity: Severity
    summary: str
    details: dict[str, Any]


# ----------------------------------------------------------------------
# Impossible travel
# ----------------------------------------------------------------------


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in km. Inlined rather than pulled from a
    geo library because the detector cares about a single comparison;
    a 30-line haversine is less surface area than another dependency."""
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlmb / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return _EARTH_RADIUS_KM * c


def _coords(event: IdentityEvent) -> tuple[float, float] | None:
    geo = event.get("src_geo")
    if not isinstance(geo, dict):
        return None
    lat = geo.get("lat")
    lon = geo.get("lon")
    if not isinstance(lat, int | float) or not isinstance(lon, int | float):
        return None
    return float(lat), float(lon)


def impossible_travel(
    prev: IdentityEvent,
    curr: IdentityEvent,
    *,
    max_kmph: float = 800.0,
) -> DetectorHit | None:
    """Compare two successful logins for the same actor. Returns a
    hit when the implied travel speed exceeds `max_kmph` and both
    events carry coordinates. Same-actor + ordering is the caller's
    responsibility (the worker pre-groups by `actor_email`)."""
    prev_coords = _coords(prev)
    curr_coords = _coords(curr)
    if prev_coords is None or curr_coords is None:
        return None
    prev_ts = prev.get("ts")
    curr_ts = curr.get("ts")
    if not isinstance(prev_ts, datetime) or not isinstance(curr_ts, datetime):
        return None
    delta_s = (curr_ts - prev_ts).total_seconds()
    if delta_s <= 0:
        return None
    distance_km = _haversine_km(*prev_coords, *curr_coords)
    # Skip noisy near-zero deltas (same building, same city).
    if distance_km < 50.0:
        return None
    speed_kmph = distance_km / (delta_s / 3600.0)
    if speed_kmph < max_kmph:
        return None
    actor = prev.get("actor_email") or curr.get("actor_email") or "unknown"
    return DetectorHit(
        rule_id=IDENTITY_IMPOSSIBLE_TRAVEL_RULE_ID,
        severity=Severity.HIGH,
        summary=(
            f"Impossible travel: {actor} moved {distance_km:.0f} km in "
            f"{delta_s / 60:.0f} min ({speed_kmph:.0f} km/h)"
        ),
        details={
            "detector": "identity_impossible_travel",
            "actor_email": actor,
            "distance_km": round(distance_km, 1),
            "delta_seconds": round(delta_s, 1),
            "speed_kmph": round(speed_kmph, 1),
            "threshold_kmph": max_kmph,
            "prev": {
                "ts": prev_ts.isoformat(),
                "src_ip": prev.get("src_ip"),
                "src_geo": prev.get("src_geo"),
            },
            "curr": {
                "ts": curr_ts.isoformat(),
                "src_ip": curr.get("src_ip"),
                "src_geo": curr.get("src_geo"),
            },
        },
    )


# ----------------------------------------------------------------------
# Brute force
# ----------------------------------------------------------------------


def _newest_ts(events: Iterable[IdentityEvent]) -> datetime | None:
    out: datetime | None = None
    for event in events:
        ts = event.get("ts")
        if isinstance(ts, datetime) and (out is None or ts > out):
            out = ts
    return out


def brute_force(
    events: Sequence[IdentityEvent],
    *,
    window_s: int = 300,
    threshold: int = 10,
) -> DetectorHit | None:
    """Count failed login attempts for one actor inside a sliding
    window ending at the newest event. Returns a hit when the count
    crosses `threshold`.

    Caller pre-groups by `actor_email`; we count across the whole
    sequence and use the newest ts as the window upper bound.
    """
    if not events:
        return None
    newest = _newest_ts(events)
    if newest is None:
        return None
    lower = newest - timedelta(seconds=window_s)
    failures = [
        e
        for e in events
        if isinstance(e.get("ts"), datetime)
        and not e.get("success")
        and e["ts"] >= lower  # type: ignore[operator]
        and e["ts"] <= newest  # type: ignore[operator]
    ]
    # `> threshold` (strict): the default threshold=10 fires on the
    # 11th failure, matching the operator-facing description
    # ("more than 10 failed logins in 5 min").
    if len(failures) <= threshold:
        return None
    actor = next((e.get("actor_email") for e in failures if e.get("actor_email")), "unknown")
    src_ips = sorted({ip for e in failures if (ip := e.get("src_ip"))})
    return DetectorHit(
        rule_id=IDENTITY_BRUTE_FORCE_RULE_ID,
        severity=Severity.HIGH,
        summary=f"Brute-force: {len(failures)} failed logins for {actor} in {window_s}s",
        details={
            "detector": "identity_brute_force",
            "actor_email": actor,
            "failure_count": len(failures),
            "window_seconds": window_s,
            "threshold": threshold,
            "src_ips": src_ips,
            "window_end_ts": newest.isoformat(),
        },
    )


# ----------------------------------------------------------------------
# MFA bombing
# ----------------------------------------------------------------------


# Action tokens that indicate an MFA challenge was issued. Okta tags
# the upstream eventType with `system.mfa.factor.activate` /
# `user.authentication.auth_via_mfa` and the Azure synth lives in
# the azure_ad client (`azure.signin.mfa_challenge`). We keep this
# list small and explicit so a benign new event type can't get folded
# into MFA detection by accident.
_MFA_ACTIONS: frozenset[str] = frozenset(
    {
        "user.authentication.auth_via_mfa",
        "system.push.send_factor_verify_push",
        "user.mfa.attempt_bypass",
        "azure.signin.mfa_challenge",
    }
)


def is_mfa_event(event: IdentityEvent) -> bool:
    """Public predicate so the worker can pre-filter MFA events
    before invoking the detector. Lower-case match on the action
    token."""
    action = event.get("action")
    if not isinstance(action, str):
        return False
    return action in _MFA_ACTIONS


def mfa_bomb(
    events: Sequence[IdentityEvent],
    *,
    window_s: int = 300,
    threshold: int = 5,
) -> DetectorHit | None:
    """Count MFA challenges for one actor inside the window. Caller
    pre-groups by `actor_email`."""
    if not events:
        return None
    newest = _newest_ts(events)
    if newest is None:
        return None
    lower = newest - timedelta(seconds=window_s)
    challenges = [
        e
        for e in events
        if isinstance(e.get("ts"), datetime)
        and is_mfa_event(e)
        and e["ts"] >= lower  # type: ignore[operator]
        and e["ts"] <= newest  # type: ignore[operator]
    ]
    if len(challenges) < threshold:
        return None
    actor = next((e.get("actor_email") for e in challenges if e.get("actor_email")), "unknown")
    return DetectorHit(
        rule_id=IDENTITY_MFA_BOMB_RULE_ID,
        severity=Severity.HIGH,
        summary=(f"MFA bombing: {len(challenges)} MFA prompts for {actor} in {window_s}s"),
        details={
            "detector": "identity_mfa_bomb",
            "actor_email": actor,
            "challenge_count": len(challenges),
            "window_seconds": window_s,
            "threshold": threshold,
            "window_end_ts": newest.isoformat(),
        },
    )


# ----------------------------------------------------------------------
# Password spray
# ----------------------------------------------------------------------


def password_spray(
    events_by_ip: Mapping[str, Sequence[IdentityEvent]],
    *,
    window_s: int = 300,
    distinct_users: int = 8,
) -> list[DetectorHit]:
    """Look for source IPs touching many distinct accounts with
    failed credentials inside the window. Returns one hit per
    offending IP (a single tick can flag multiple IPs from the same
    botnet, so we return a list rather than a single hit)."""
    hits: list[DetectorHit] = []
    for src_ip, events in events_by_ip.items():
        if not events:
            continue
        newest = _newest_ts(events)
        if newest is None:
            continue
        lower = newest - timedelta(seconds=window_s)
        actors: set[str] = set()
        failures_in_window = 0
        for event in events:
            ts = event.get("ts")
            if not isinstance(ts, datetime):
                continue
            if ts < lower or ts > newest:
                continue
            if event.get("success"):
                continue
            actor = event.get("actor_email")
            if not isinstance(actor, str) or not actor:
                continue
            actors.add(actor)
            failures_in_window += 1
        # `> distinct_users` (strict): default 8 fires on the 9th
        # distinct account, matching the operator description
        # ("more than 8 distinct accounts from one IP in 5 min").
        if len(actors) <= distinct_users:
            continue
        hits.append(
            DetectorHit(
                rule_id=IDENTITY_PASSWORD_SPRAY_RULE_ID,
                severity=Severity.HIGH,
                summary=(
                    f"Password spray: {src_ip} touched {len(actors)} distinct "
                    f"accounts in {window_s}s"
                ),
                details={
                    "detector": "identity_password_spray",
                    "src_ip": src_ip,
                    "distinct_actor_count": len(actors),
                    "failure_count": failures_in_window,
                    "window_seconds": window_s,
                    "threshold_distinct_users": distinct_users,
                    "window_end_ts": newest.isoformat(),
                    "sample_actors": sorted(actors)[:20],
                },
            )
        )
    return hits


# ----------------------------------------------------------------------
# Helpers shared with the worker
# ----------------------------------------------------------------------


def group_by_actor(
    events: Iterable[IdentityEvent],
) -> dict[str, list[IdentityEvent]]:
    """Bucket events by actor_email. Empty / missing emails are
    grouped under `""` (the detectors then skip those because their
    actor lookups return "unknown")."""
    out: dict[str, list[IdentityEvent]] = defaultdict(list)
    for event in events:
        actor = event.get("actor_email") or ""
        out[actor].append(event)
    return dict(out)


def group_by_ip(
    events: Iterable[IdentityEvent],
) -> dict[str, list[IdentityEvent]]:
    """Bucket events by source IP. Events without a `src_ip` are
    skipped — the password-spray detector keys on IP and has nothing
    useful to say about ip-less events."""
    out: dict[str, list[IdentityEvent]] = defaultdict(list)
    for event in events:
        ip = event.get("src_ip")
        if not isinstance(ip, str) or not ip:
            continue
        out[ip].append(event)
    return dict(out)


__all__ = [
    "DetectorHit",
    "brute_force",
    "group_by_actor",
    "group_by_ip",
    "impossible_travel",
    "is_mfa_event",
    "mfa_bomb",
    "password_spray",
]
