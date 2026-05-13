"""Phase 1 #1.8: ATT&CK Navigator JSON aggregation endpoint.

Covers:
  * `GET /api/mitre/navigator.json` returns a v4.5 layer with one
    technique row per distinct technique seen on alerts in the window,
    counted via `count(*) GROUP BY technique`.
  * `window_hours` query param caps at 720 (validation).
  * Analysts only see alerts from hosts they can reach (host-scoping
    via `apply_host_scope`).
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from sqlalchemy import insert


@pytest_asyncio.fixture
async def _navigator_seed(db_session, admin_user, analyst_user):
    from app.models import (
        Alert,
        AlertState,
        Host,
        HostGroup,
        HostStatus,
        OsFamily,
        Rule,
        RuleKind,
        Severity,
        host_in_group,
        user_host_group,
    )

    visible = Host(
        hostname=f"vis-{os.urandom(3).hex()}",
        os_family=OsFamily.LINUX,
        status=HostStatus.ONLINE,
    )
    hidden = Host(
        hostname=f"hid-{os.urandom(3).hex()}",
        os_family=OsFamily.LINUX,
        status=HostStatus.ONLINE,
    )
    db_session.add_all([visible, hidden])
    await db_session.flush()

    grp = HostGroup(name=f"grp-{os.urandom(3).hex()}")
    db_session.add(grp)
    await db_session.flush()
    await db_session.execute(insert(host_in_group).values(host_id=visible.id, host_group_id=grp.id))
    await db_session.execute(
        insert(user_host_group).values(user_id=analyst_user.id, host_group_id=grp.id)
    )

    rule = Rule(
        kind=RuleKind.SIGMA,
        name=f"r-{os.urandom(3).hex()}",
        severity=Severity.HIGH,
    )
    db_session.add(rule)
    await db_session.flush()

    now = datetime.now(UTC)
    # Two alerts on the analyst-visible host, both tagged T1059.001;
    # one of them also has T1547.001.
    a1 = Alert(
        host_id=visible.id,
        rule_id=rule.id,
        severity=Severity.HIGH,
        state=AlertState.NEW,
        summary="alert vis-1",
        mitre_techniques=["T1059.001"],
        opened_at=now - timedelta(hours=1),
    )
    a2 = Alert(
        host_id=visible.id,
        rule_id=rule.id,
        severity=Severity.HIGH,
        state=AlertState.NEW,
        summary="alert vis-2",
        mitre_techniques=["T1059.001", "T1547.001"],
        opened_at=now - timedelta(hours=2),
    )
    # One on the hidden host — analyst shouldn't count this.
    a3 = Alert(
        host_id=hidden.id,
        rule_id=rule.id,
        severity=Severity.HIGH,
        state=AlertState.NEW,
        summary="alert hidden",
        mitre_techniques=["T1486"],
        opened_at=now - timedelta(hours=3),
    )
    # One stale alert outside the default window (168h = 7 days).
    a4 = Alert(
        host_id=visible.id,
        rule_id=rule.id,
        severity=Severity.HIGH,
        state=AlertState.NEW,
        summary="alert stale",
        mitre_techniques=["T9999"],
        opened_at=now - timedelta(days=14),
    )
    # One alert with no techniques — shouldn't contribute.
    a5 = Alert(
        host_id=visible.id,
        rule_id=rule.id,
        severity=Severity.HIGH,
        state=AlertState.NEW,
        summary="alert untagged",
        opened_at=now - timedelta(hours=1),
    )
    db_session.add_all([a1, a2, a3, a4, a5])
    await db_session.flush()

    return {"visible": visible, "hidden": hidden, "alerts": (a1, a2, a3, a4, a5)}


@pytest.mark.asyncio
async def test_admin_navigator_layer_shape(http_client, _navigator_seed, admin_headers):
    resp = await http_client.get("/api/mitre/navigator.json", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["domain"] == "enterprise-attack"
    assert body["versions"]["layer"] == "4.5"
    counts = {t["techniqueID"]: t["score"] for t in body["techniques"]}
    # Admin sees both hosts. T1059.001 fires on a1 and a2; T1547.001 on a2;
    # T1486 on a3. The stale T9999 is outside the default 7-day window.
    assert counts.get("T1059.001") == 2
    assert counts.get("T1547.001") == 1
    assert counts.get("T1486") == 1
    assert "T9999" not in counts
    # Gradient max should match the biggest score we surfaced.
    assert body["gradient"]["maxValue"] == 2


@pytest.mark.asyncio
async def test_analyst_navigator_scopes_to_visible_hosts(
    http_client, _navigator_seed, analyst_headers
):
    resp = await http_client.get("/api/mitre/navigator.json", headers=analyst_headers)
    assert resp.status_code == 200, resp.text
    counts = {t["techniqueID"]: t["score"] for t in resp.json()["techniques"]}
    # Visible host's tags only — hidden host's T1486 must be absent.
    assert counts.get("T1059.001") == 2
    assert counts.get("T1547.001") == 1
    assert "T1486" not in counts


@pytest.mark.asyncio
async def test_navigator_respects_window_hours(http_client, _navigator_seed, admin_headers):
    """A wide window picks up the stale T9999 alert."""
    resp = await http_client.get(
        "/api/mitre/navigator.json?window_hours=720", headers=admin_headers
    )
    assert resp.status_code == 200, resp.text
    counts = {t["techniqueID"]: t["score"] for t in resp.json()["techniques"]}
    assert counts.get("T9999") == 1


@pytest.mark.asyncio
async def test_navigator_window_hours_validation(http_client, admin_headers):
    """`window_hours` rejects values <= 0 and > 720."""
    resp = await http_client.get("/api/mitre/navigator.json?window_hours=0", headers=admin_headers)
    assert resp.status_code == 422
    resp = await http_client.get(
        "/api/mitre/navigator.json?window_hours=99999", headers=admin_headers
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_navigator_requires_auth(http_client):
    resp = await http_client.get("/api/mitre/navigator.json")
    assert resp.status_code == 401
