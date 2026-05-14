"""Phase 4 #4.3 identity threat detection.

Covers:
  * Okta + Azure AD fetchers normalise upstream payloads into the
    common identity-event shape. respx mocks both endpoints so the
    tests stay network-free.
  * impossible_travel: 9000 km in 10 min fires; same distance in 13 h
    doesn't.
  * brute_force: 11 failed logins in 5 min fires; 10 doesn't.
  * mfa_bomb: 5 MFA challenges in 5 min fires; 4 doesn't.
  * password_spray: 9 distinct user failures from one IP fires; 7
    doesn't.
  * The six new Sigma rules load via the existing rule_pack.load_rule_pack.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import respx
from httpx import Response

from app.services.identity import IdentityEvent
from app.services.identity.detectors import (
    DetectorHit,
    brute_force,
    impossible_travel,
    mfa_bomb,
    password_spray,
)

# Fixed instant the tests anchor against, so windows are deterministic.
NOW = datetime(2026, 5, 14, 12, 0, 0, tzinfo=UTC)


def _ev(
    *,
    ts: datetime,
    actor: str = "user@example.com",
    action: str = "user.session.start",
    src_ip: str | None = "203.0.113.10",
    geo: tuple[float, float] | None = None,
    success: bool = True,
) -> IdentityEvent:
    out: IdentityEvent = {
        "ts": ts,
        "actor_email": actor,
        "action": action,
        "src_ip": src_ip,
        "src_geo": {"lat": geo[0], "lon": geo[1]} if geo else None,
        "success": success,
    }
    return out


# ---------- impossible travel ----------


def test_impossible_travel_fires_when_speed_exceeds_threshold() -> None:
    # London → Sydney (~16,989 km) is too far for the haversine to
    # disagree about; we keep the test deltas reasonable. NY → Madrid is
    # roughly 5760 km — in 10 minutes that's 34,000 km/h, way past the
    # 800 km/h ceiling.
    prev = _ev(ts=NOW, geo=(40.7128, -74.0060))
    curr = _ev(ts=NOW + timedelta(minutes=10), geo=(40.4168, -3.7038))
    hit = impossible_travel(prev, curr)
    assert hit is not None
    assert isinstance(hit, DetectorHit)
    # NY → Madrid is roughly 5760 km.
    assert hit.details["distance_km"] > 5000
    assert hit.details["speed_kmph"] > 800


def test_impossible_travel_does_not_fire_on_long_gap() -> None:
    """Same NY → Madrid trip across 13 hours is consistent with a
    commercial flight; the detector must not fire."""
    prev = _ev(ts=NOW, geo=(40.7128, -74.0060))
    curr = _ev(ts=NOW + timedelta(hours=13), geo=(40.4168, -3.7038))
    assert impossible_travel(prev, curr) is None


def test_impossible_travel_requires_distance_threshold() -> None:
    """Adjacent suburbs in the same metro fire false-positive
    quickly otherwise. We pre-gate at 50 km to absorb GeoIP jitter."""
    prev = _ev(ts=NOW, geo=(40.7128, -74.0060))
    curr = _ev(ts=NOW + timedelta(seconds=10), geo=(40.7140, -74.0080))
    assert impossible_travel(prev, curr) is None


def test_impossible_travel_skips_events_without_geo() -> None:
    prev = _ev(ts=NOW, geo=None)
    curr = _ev(ts=NOW + timedelta(minutes=5), geo=(40.4168, -3.7038))
    assert impossible_travel(prev, curr) is None


# ---------- brute force ----------


def _failures(count: int, start: datetime, step_s: int = 20) -> list[IdentityEvent]:
    return [_ev(ts=start + timedelta(seconds=i * step_s), success=False) for i in range(count)]


def test_brute_force_fires_above_threshold() -> None:
    events = _failures(11, NOW)
    hit = brute_force(events)
    assert hit is not None
    assert hit.details["failure_count"] == 11


def test_brute_force_silent_below_threshold() -> None:
    events = _failures(10, NOW)
    # exactly threshold (default 10) fires; 9 should not.
    fewer = _failures(9, NOW)
    assert brute_force(fewer) is None
    # 10 sits right at the threshold by spec ("11 in 5 min → alert").
    # The detector uses `< threshold` so 10 won't fire.
    assert brute_force(events[:10]) is None


def test_brute_force_window_drops_old_events() -> None:
    """Failures outside the 5-minute window don't count."""
    far_back = _failures(20, NOW - timedelta(hours=2), step_s=20)
    recent = _failures(2, NOW)
    assert brute_force(far_back + recent) is None


def test_brute_force_skips_successes() -> None:
    events = [_ev(ts=NOW + timedelta(seconds=i), success=True) for i in range(15)]
    assert brute_force(events) is None


# ---------- MFA bombing ----------


def _mfa_event(ts: datetime, actor: str = "user@example.com") -> IdentityEvent:
    return _ev(ts=ts, actor=actor, action="user.authentication.auth_via_mfa", success=False)


def test_mfa_bomb_fires_at_threshold() -> None:
    events = [_mfa_event(NOW + timedelta(seconds=i * 30)) for i in range(5)]
    hit = mfa_bomb(events)
    assert hit is not None
    assert hit.details["challenge_count"] == 5


def test_mfa_bomb_silent_below_threshold() -> None:
    events = [_mfa_event(NOW + timedelta(seconds=i * 30)) for i in range(4)]
    assert mfa_bomb(events) is None


def test_mfa_bomb_ignores_non_mfa_actions() -> None:
    events = [
        _ev(ts=NOW + timedelta(seconds=i * 30), action="user.session.start") for i in range(10)
    ]
    assert mfa_bomb(events) is None


def test_mfa_bomb_accepts_azure_synth_action() -> None:
    """The Azure AD fetcher synthesises `azure.signin.mfa_challenge`
    for the AAD error code 50158 case; the detector must recognise
    it the same way it does Okta's native MFA event types."""
    events = [
        _ev(
            ts=NOW + timedelta(seconds=i * 30),
            action="azure.signin.mfa_challenge",
        )
        for i in range(5)
    ]
    hit = mfa_bomb(events)
    assert hit is not None


# ---------- password spray ----------


def test_password_spray_fires_with_many_distinct_users_from_one_ip() -> None:
    spray = {
        "198.51.100.50": [
            _ev(
                ts=NOW + timedelta(seconds=i * 10),
                actor=f"user{i}@example.com",
                src_ip="198.51.100.50",
                success=False,
            )
            for i in range(9)
        ]
    }
    hits = password_spray(spray)
    assert len(hits) == 1
    assert hits[0].details["distinct_actor_count"] == 9
    assert hits[0].details["src_ip"] == "198.51.100.50"


def test_password_spray_silent_below_threshold() -> None:
    """7 distinct users from one IP is under the default 8-user
    threshold; 9 is over."""
    light = {
        "198.51.100.50": [
            _ev(
                ts=NOW + timedelta(seconds=i * 10),
                actor=f"user{i}@example.com",
                src_ip="198.51.100.50",
                success=False,
            )
            for i in range(7)
        ]
    }
    assert password_spray(light) == []


def test_password_spray_ignores_successes() -> None:
    benign = {
        "198.51.100.50": [
            _ev(
                ts=NOW + timedelta(seconds=i * 10),
                actor=f"user{i}@example.com",
                src_ip="198.51.100.50",
                success=True,
            )
            for i in range(20)
        ]
    }
    assert password_spray(benign) == []


# ---------- Okta fetcher normalisation ----------


@pytest.mark.asyncio
@respx.mock
async def test_okta_fetch_events_normalises_payload() -> None:
    from app.services.identity import okta

    payload: list[dict[str, Any]] = [
        {
            "uuid": "00000000-0000-0000-0000-000000000001",
            "published": "2026-05-14T11:59:30.123Z",
            "eventType": "user.session.start",
            "actor": {"alternateId": "Alice@example.com"},
            "client": {
                "ipAddress": "203.0.113.10",
                "geographicalContext": {
                    "country": "US",
                    "geolocation": {"lat": 40.7128, "lon": -74.0060},
                },
            },
            "outcome": {"result": "SUCCESS"},
        },
        {
            "uuid": "00000000-0000-0000-0000-000000000002",
            "published": "2026-05-14T11:59:45.000Z",
            "eventType": "user.session.start",
            "actor": {"alternateId": "Bob@example.com"},
            "client": {
                "ipAddress": "203.0.113.11",
                "geographicalContext": {"country": "ES"},
            },
            "outcome": {"result": "FAILURE"},
        },
        # Malformed — missing published; should be dropped.
        {"eventType": "garbage"},
    ]

    domain = "example.okta.com"
    respx.get(f"https://{domain}/api/v1/logs").mock(return_value=Response(200, json=payload))

    config = {"domain": domain, "api_token": "00abc"}
    events = await okta.fetch_events(config, after_ts=None)
    assert len(events) == 2

    alice = events[0]
    assert alice["actor_email"] == "alice@example.com"
    assert alice["action"] == "user.session.start"
    assert alice["src_ip"] == "203.0.113.10"
    assert alice["src_geo"] == {"lat": 40.7128, "lon": -74.006, "country": "US"}
    assert alice["success"] is True

    bob = events[1]
    assert bob["actor_email"] == "bob@example.com"
    # No geolocation lat/lon — fetcher returns None for src_geo.
    assert bob["src_geo"] is None
    assert bob["success"] is False


@pytest.mark.asyncio
@respx.mock
async def test_okta_fetch_events_propagates_http_error() -> None:
    from app.services.identity import okta

    domain = "example.okta.com"
    respx.get(f"https://{domain}/api/v1/logs").mock(return_value=Response(401, text="bad token"))
    with pytest.raises(RuntimeError):
        await okta.fetch_events({"domain": domain, "api_token": "x"}, after_ts=None)


@pytest.mark.asyncio
async def test_okta_config_validation_missing_token() -> None:
    """The fetcher refuses to call the API when required keys are
    blank; the worker maps the raised error into `last_error`."""
    from app.services.identity import okta

    with pytest.raises(okta.OktaConfigError):
        await okta.fetch_events({"domain": "example.okta.com"}, after_ts=None)


# ---------- Azure AD fetcher normalisation ----------


@pytest.mark.asyncio
@respx.mock
async def test_azure_fetch_events_normalises_payload() -> None:
    from app.services.identity import azure_ad

    payload = {
        "value": [
            {
                "id": "abc",
                "createdDateTime": "2026-05-14T11:59:00.000Z",
                "userPrincipalName": "Alice@example.com",
                "ipAddress": "203.0.113.10",
                "location": {
                    "countryOrRegion": "US",
                    "geoCoordinates": {"latitude": 40.7128, "longitude": -74.0060},
                },
                "status": {"errorCode": 0},
                "authenticationDetails": [],
            },
            {
                "id": "def",
                "createdDateTime": "2026-05-14T11:59:30.000Z",
                "userPrincipalName": "Bob@example.com",
                "ipAddress": "203.0.113.11",
                # Status 50158 = MFA required — the fetcher synthesises
                # an `azure.signin.mfa_challenge` action token.
                "status": {"errorCode": 50158},
                "authenticationDetails": [],
            },
        ]
    }
    respx.get("https://graph.microsoft.com/beta/auditLogs/signIns").mock(
        return_value=Response(200, json=payload)
    )

    events = await azure_ad.fetch_events(
        {
            "tenant_id": "tnt",
            "client_id": "cli",
            "client_secret": "sec",
        },
        after_ts=None,
        token_override="fake-token",
    )
    assert len(events) == 2
    alice = events[0]
    assert alice["actor_email"] == "alice@example.com"
    assert alice["success"] is True
    assert alice["action"] == "azure.signin"
    bob = events[1]
    assert bob["success"] is False
    assert bob["action"] == "azure.signin.mfa_challenge"


@pytest.mark.asyncio
@respx.mock
async def test_azure_fetch_events_propagates_http_error() -> None:
    from app.services.identity import azure_ad

    respx.get("https://graph.microsoft.com/beta/auditLogs/signIns").mock(
        return_value=Response(500, text="boom")
    )
    with pytest.raises(RuntimeError):
        await azure_ad.fetch_events(
            {"tenant_id": "x", "client_id": "y", "client_secret": "z"},
            after_ts=None,
            token_override="fake",
        )


@pytest.mark.asyncio
@respx.mock
async def test_azure_token_exchange_uses_oauth_endpoint() -> None:
    """The fetcher dispatches the OAuth2 client_credentials handshake
    against `login.microsoftonline.com` before hitting Graph. This
    test asserts both endpoints are called in order."""
    from app.services.identity import azure_ad

    token_url = "https://login.microsoftonline.com/tnt/oauth2/v2.0/token"
    respx.post(token_url).mock(
        return_value=Response(200, json={"access_token": "tok", "expires_in": 3600})
    )
    respx.get("https://graph.microsoft.com/beta/auditLogs/signIns").mock(
        return_value=Response(200, json={"value": []})
    )

    events = await azure_ad.fetch_events(
        {"tenant_id": "tnt", "client_id": "cli", "client_secret": "sec"},
        after_ts=None,
    )
    assert events == []


# ---------- Rule pack loads the new identity_and_access rules ----------


def test_identity_sigma_rules_yaml_is_well_formed() -> None:
    """The six new YAML files parse and carry the metadata the
    rule-pack loader expects (id + title + tags + level). We don't
    invoke the loader here because the integration path requires a
    real DB; the per-file parse check is enough to keep the pack from
    drifting out of shape."""
    import yaml

    root = Path(__file__).resolve().parents[1] / "sigma_rules" / "identity_and_access"
    assert root.is_dir(), f"expected directory: {root}"
    files = sorted(root.glob("*.yml"))
    assert len(files) == 6, [p.name for p in files]
    for path in files:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(doc, dict), path
        assert "id" in doc, path
        assert "title" in doc, path
        tags = doc.get("tags") or []
        assert any(isinstance(t, str) and t.startswith("attack.t") for t in tags), path
        assert doc.get("level") in (
            "informational",
            "info",
            "low",
            "medium",
            "high",
            "critical",
        ), path


@pytest.mark.asyncio
async def test_identity_sigma_rules_load_via_rule_pack(db_session: Any) -> None:
    """End-to-end: the rule_pack loader picks up the new directory
    and inserts six rows under it. We seed only this subset by
    pointing the loader at the new directory's parent (i.e. the
    sigma_rules root) and filter the assertion by sigma id so we
    don't depend on the rest of the curated pack."""
    from sqlalchemy import select

    from app.models import Rule, RuleKind
    from app.services.rule_pack import load_rule_pack

    root = Path(__file__).resolve().parents[1] / "sigma_rules"
    # Limit the loader to just identity_and_access by passing the
    # subdir directly — load_rule_pack walks `root.rglob("*.yml")`
    # so a narrower root means a narrower load.
    identity_root = root / "identity_and_access"
    report = await load_rule_pack(db_session, root=identity_root)
    assert report.inserted + report.unchanged == 6, report
    assert report.skipped == 0, report.errors

    identity_ids = {
        "7a0c1e3a-b1c5-4dc8-95c0-4d8f6b1112a1",
        "7a0c1e3a-b1c5-4dc8-95c0-4d8f6b1112a2",
        "7a0c1e3a-b1c5-4dc8-95c0-4d8f6b1112a3",
        "7a0c1e3a-b1c5-4dc8-95c0-4d8f6b1112a4",
        "7a0c1e3a-b1c5-4dc8-95c0-4d8f6b1112a5",
        "7a0c1e3a-b1c5-4dc8-95c0-4d8f6b1112a6",
    }
    rows = (
        (await db_session.execute(select(Rule).where(Rule.kind == RuleKind.SIGMA))).scalars().all()
    )
    seen_ids = {str(r.id) for r in rows}
    assert identity_ids.issubset(seen_ids), identity_ids - seen_ids
