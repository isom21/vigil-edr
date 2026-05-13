"""Phase 1 #1.11 — Incidents alert grouping.

Covers:
  * Grouping rule v1 (same host, within window → one incident; outside
    window → new incident; different hosts never share).
  * `_run_once` (worker driver) groups exactly the alerts the test set
    up and is idempotent.
  * RBAC on list/detail/state/assign — admin sees all, non-admin sees
    only incidents whose host is in their groups, out-of-scope mutations
    return 404 (M-audit-and-auth #7).
  * State transitions follow the allowed graph (open → investigating
    → resolved → closed; closed is terminal).
  * Assign sets/clears the assignee_id and audits.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from sqlalchemy import insert, select


def _test_session_maker(db_session):
    """SAVEPOINT-isolated session-maker for the worker."""

    @asynccontextmanager
    async def _maker():
        yield db_session

    return _maker


# ---------- env parsing ----------


def test_interval_floor_is_10s() -> None:
    """Tight polls are wasteful; floor 10 s defends against a typo."""
    from app.workers.incident_grouper import _interval_seconds

    os.environ["VIGIL_INCIDENT_GROUPER_INTERVAL_S"] = "1"
    try:
        assert _interval_seconds() == 10
    finally:
        os.environ.pop("VIGIL_INCIDENT_GROUPER_INTERVAL_S", None)


def test_interval_falls_back_to_default_on_garbage() -> None:
    from app.workers.incident_grouper import _interval_seconds

    os.environ["VIGIL_INCIDENT_GROUPER_INTERVAL_S"] = "abc"
    try:
        assert _interval_seconds() == 60
    finally:
        os.environ.pop("VIGIL_INCIDENT_GROUPER_INTERVAL_S", None)


def test_window_clamps_to_floor_and_cap() -> None:
    """A 1-second window is meaningless; a 1-year window is a typo."""
    from app.workers.incident_grouper import _window_seconds

    os.environ["VIGIL_INCIDENT_WINDOW_S"] = "1"
    try:
        assert _window_seconds() == 60
    finally:
        os.environ.pop("VIGIL_INCIDENT_WINDOW_S", None)

    os.environ["VIGIL_INCIDENT_WINDOW_S"] = "9999999"
    try:
        assert _window_seconds() == 86400
    finally:
        os.environ.pop("VIGIL_INCIDENT_WINDOW_S", None)


# ---------- grouping logic ----------


@pytest_asyncio.fixture
async def _alerts_two_hosts(db_session, analyst_user):
    """Two hosts with three alerts each, spaced so the grouper should
    produce one incident per host plus a second incident for the row
    that lands outside the window."""
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
    db_session.add(alpha)
    await db_session.flush()
    await db_session.execute(insert(host_in_group).values(host_id=a.id, host_group_id=alpha.id))
    await db_session.execute(
        insert(user_host_group).values(user_id=analyst_user.id, host_group_id=alpha.id)
    )

    rule = Rule(
        kind=RuleKind.SIGMA,
        name=f"rule-{os.urandom(3).hex()}",
        severity=Severity.MEDIUM,
    )
    db_session.add(rule)
    await db_session.flush()

    now = datetime.now(UTC)
    # All three host-A alerts within a 5-minute window — should glue.
    a1 = Alert(
        host_id=a.id,
        rule_id=rule.id,
        severity=Severity.MEDIUM,
        state=AlertState.NEW,
        summary="A1",
        opened_at=now - timedelta(seconds=120),
    )
    a2 = Alert(
        host_id=a.id,
        rule_id=rule.id,
        severity=Severity.HIGH,
        state=AlertState.NEW,
        summary="A2",
        opened_at=now - timedelta(seconds=60),
    )
    a3 = Alert(
        host_id=a.id,
        rule_id=rule.id,
        severity=Severity.LOW,
        state=AlertState.NEW,
        summary="A3",
        opened_at=now - timedelta(seconds=10),
    )
    # Host-B has two close-together alerts and one outside the window.
    b1 = Alert(
        host_id=b.id,
        rule_id=rule.id,
        severity=Severity.LOW,
        state=AlertState.NEW,
        summary="B1",
        opened_at=now - timedelta(seconds=90),
    )
    b2 = Alert(
        host_id=b.id,
        rule_id=rule.id,
        severity=Severity.MEDIUM,
        state=AlertState.NEW,
        summary="B2",
        opened_at=now - timedelta(seconds=30),
    )
    db_session.add_all([a1, a2, a3, b1, b2])
    await db_session.flush()
    return {
        "host_a": a,
        "host_b": b,
        "alpha": alpha,
        "rule": rule,
        "a1": a1,
        "a2": a2,
        "a3": a3,
        "b1": b1,
        "b2": b2,
    }


@pytest.mark.asyncio
async def test_regroup_recent_glues_same_host_within_window(db_session, _alerts_two_hosts):
    from app.services.incident_grouping import regroup_recent

    grouped = await regroup_recent(db_session, window_s=600)
    assert grouped == 5

    # All three host-A alerts share one incident.
    a_ids = {
        _alerts_two_hosts["a1"].incident_id,
        _alerts_two_hosts["a2"].incident_id,
        _alerts_two_hosts["a3"].incident_id,
    }
    await db_session.refresh(_alerts_two_hosts["a1"])
    await db_session.refresh(_alerts_two_hosts["a2"])
    await db_session.refresh(_alerts_two_hosts["a3"])
    assert _alerts_two_hosts["a1"].incident_id is not None
    assert _alerts_two_hosts["a1"].incident_id == _alerts_two_hosts["a2"].incident_id
    assert _alerts_two_hosts["a2"].incident_id == _alerts_two_hosts["a3"].incident_id

    # Host-B two alerts share one incident, different from host-A's.
    assert _alerts_two_hosts["b1"].incident_id == _alerts_two_hosts["b2"].incident_id
    assert _alerts_two_hosts["b1"].incident_id != _alerts_two_hosts["a1"].incident_id
    _ = a_ids


@pytest.mark.asyncio
async def test_regroup_severity_bumps_to_max(db_session, _alerts_two_hosts):
    """The incident severity is the max severity of its grouped alerts."""
    from app.models import Incident, Severity
    from app.services.incident_grouping import regroup_recent

    await regroup_recent(db_session, window_s=600)
    await db_session.refresh(_alerts_two_hosts["a2"])
    incident = await db_session.get(Incident, _alerts_two_hosts["a2"].incident_id)
    assert incident is not None
    # Host-A alerts: medium + high + low → max=high.
    assert incident.severity == Severity.HIGH


@pytest.mark.asyncio
async def test_regroup_is_idempotent(db_session, _alerts_two_hosts):
    """Second pass finds nothing — the alerts already have incident_id."""
    from app.services.incident_grouping import regroup_recent

    first = await regroup_recent(db_session, window_s=600)
    second = await regroup_recent(db_session, window_s=600)
    assert first == 5
    assert second == 0


@pytest.mark.asyncio
async def test_regroup_splits_outside_window(db_session, analyst_user):
    """A second alert on the same host but outside the window must
    open a fresh incident, not extend the previous one."""
    from app.models import (
        Alert,
        AlertState,
        Host,
        HostStatus,
        Incident,
        OsFamily,
        Rule,
        RuleKind,
        Severity,
    )
    from app.services.incident_grouping import regroup_recent

    host = Host(
        hostname=f"win-{os.urandom(3).hex()}", os_family=OsFamily.LINUX, status=HostStatus.ONLINE
    )
    db_session.add(host)
    await db_session.flush()
    rule = Rule(kind=RuleKind.SIGMA, name=f"rule-{os.urandom(3).hex()}", severity=Severity.LOW)
    db_session.add(rule)
    await db_session.flush()

    now = datetime.now(UTC)
    # 100 s apart with a 60 s window → must split into two incidents.
    near = Alert(
        host_id=host.id,
        rule_id=rule.id,
        severity=Severity.LOW,
        state=AlertState.NEW,
        summary="near",
        opened_at=now - timedelta(seconds=10),
    )
    far = Alert(
        host_id=host.id,
        rule_id=rule.id,
        severity=Severity.LOW,
        state=AlertState.NEW,
        summary="far",
        opened_at=now - timedelta(seconds=110),
    )
    db_session.add_all([near, far])
    await db_session.flush()

    await regroup_recent(db_session, window_s=60)
    await db_session.refresh(near)
    await db_session.refresh(far)
    assert near.incident_id is not None
    assert far.incident_id is not None
    assert near.incident_id != far.incident_id
    # Two incidents on this host.
    count = (
        (await db_session.execute(select(Incident).where(Incident.host_id == host.id)))
        .scalars()
        .all()
    )
    assert len(count) == 2


@pytest.mark.asyncio
async def test_regroup_skips_null_host(db_session, analyst_user):
    """Synthetic null-host alerts (audit-chain breaks etc.) don't
    group in v1 — they have nowhere to go."""
    from app.models import Alert, AlertState, Rule, RuleKind, Severity
    from app.services.incident_grouping import regroup_recent

    rule = Rule(kind=RuleKind.IOC, name=f"sys-rule-{os.urandom(3).hex()}", severity=Severity.HIGH)
    db_session.add(rule)
    await db_session.flush()
    a = Alert(
        host_id=None,
        rule_id=rule.id,
        severity=Severity.HIGH,
        state=AlertState.NEW,
        summary="audit chain break",
    )
    db_session.add(a)
    await db_session.flush()
    grouped = await regroup_recent(db_session, window_s=600)
    assert grouped == 0
    await db_session.refresh(a)
    assert a.incident_id is None


@pytest.mark.asyncio
async def test_worker_run_once_uses_session_maker(db_session, _alerts_two_hosts):
    from app.workers import incident_grouper

    sm = _test_session_maker(db_session)
    grouped = await incident_grouper._run_once(session_maker=sm)
    # 3 from host-A + 2 from host-B = 5.
    assert grouped == 5


# ---------- API: list / detail / state / assign ----------


@pytest_asyncio.fixture
async def _incident_seed(db_session, admin_user, analyst_user):
    """Two hosts, one incident each. Analyst can see host_a only."""
    from app.models import (
        Host,
        HostGroup,
        HostStatus,
        Incident,
        IncidentStatus,
        OsFamily,
        Severity,
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

    inc_a = Incident(
        host_id=a.id,
        title="incident A",
        severity=Severity.MEDIUM,
        status=IncidentStatus.OPEN,
    )
    inc_b = Incident(
        host_id=b.id,
        title="incident B",
        severity=Severity.HIGH,
        status=IncidentStatus.OPEN,
    )
    db_session.add_all([inc_a, inc_b])
    await db_session.flush()
    return {"host_a": a, "host_b": b, "incident_a": inc_a, "incident_b": inc_b}


@pytest.mark.asyncio
async def test_admin_lists_all_incidents(http_client, _incident_seed, admin_headers):
    resp = await http_client.get("/api/incidents", headers=admin_headers)
    assert resp.status_code == 200
    body = resp.json()
    ids = {item["id"] for item in body["items"]}
    assert str(_incident_seed["incident_a"].id) in ids
    assert str(_incident_seed["incident_b"].id) in ids


@pytest.mark.asyncio
async def test_analyst_only_sees_in_scope_incidents(http_client, _incident_seed, analyst_headers):
    resp = await http_client.get("/api/incidents", headers=analyst_headers)
    assert resp.status_code == 200
    body = resp.json()
    ids = {item["id"] for item in body["items"]}
    assert str(_incident_seed["incident_a"].id) in ids
    assert str(_incident_seed["incident_b"].id) not in ids


@pytest.mark.asyncio
async def test_analyst_get_out_of_scope_returns_404(http_client, _incident_seed, analyst_headers):
    resp = await http_client.get(
        f"/api/incidents/{_incident_seed['incident_b'].id}", headers=analyst_headers
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_admin_state_transition_open_to_investigating(
    http_client, _incident_seed, admin_headers
):
    resp = await http_client.post(
        f"/api/incidents/{_incident_seed['incident_a'].id}/state",
        json={"to_state": "investigating"},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "investigating"


@pytest.mark.asyncio
async def test_state_transition_rejects_disallowed(
    http_client, _incident_seed, admin_headers, db_session
):
    """closed is terminal — can't move out of it."""
    from app.models import IncidentStatus

    inc = _incident_seed["incident_a"]
    inc.status = IncidentStatus.CLOSED
    await db_session.flush()

    resp = await http_client.post(
        f"/api/incidents/{inc.id}/state",
        json={"to_state": "investigating"},
        headers=admin_headers,
    )
    assert resp.status_code == 400
    assert "not allowed" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_state_transition_to_resolved_sets_closed_at(
    http_client, _incident_seed, admin_headers, db_session
):
    inc = _incident_seed["incident_a"]
    resp = await http_client.post(
        f"/api/incidents/{inc.id}/state",
        json={"to_state": "resolved"},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "resolved"
    assert body["closed_at"] is not None


@pytest.mark.asyncio
async def test_analyst_out_of_scope_state_returns_404(
    http_client, _incident_seed, analyst_headers, admin_headers
):
    resp = await http_client.post(
        f"/api/incidents/{_incident_seed['incident_b'].id}/state",
        json={"to_state": "investigating"},
        headers=analyst_headers,
    )
    assert resp.status_code == 404

    # Belt + braces: as admin, re-read confirms the mutation didn't land.
    admin_resp = await http_client.get(
        f"/api/incidents/{_incident_seed['incident_b'].id}", headers=admin_headers
    )
    assert admin_resp.status_code == 200
    assert admin_resp.json()["status"] == "open"


@pytest.mark.asyncio
async def test_admin_assigns_incident(http_client, _incident_seed, admin_headers, admin_user):
    resp = await http_client.post(
        f"/api/incidents/{_incident_seed['incident_a'].id}/assign",
        json={"assignee_id": str(admin_user.id)},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["assignee_id"] == str(admin_user.id)


@pytest.mark.asyncio
async def test_admin_unassigns_incident(
    http_client, _incident_seed, admin_headers, admin_user, db_session
):
    inc = _incident_seed["incident_a"]
    inc.assignee_id = admin_user.id
    await db_session.flush()
    resp = await http_client.post(
        f"/api/incidents/{inc.id}/assign",
        json={"assignee_id": None},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["assignee_id"] is None


@pytest.mark.asyncio
async def test_assign_to_unknown_user_returns_404(http_client, _incident_seed, admin_headers):
    from uuid import uuid4

    resp = await http_client.post(
        f"/api/incidents/{_incident_seed['incident_a'].id}/assign",
        json={"assignee_id": str(uuid4())},
        headers=admin_headers,
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_analyst_out_of_scope_assign_returns_404(
    http_client, _incident_seed, analyst_headers, analyst_user, admin_headers
):
    resp = await http_client.post(
        f"/api/incidents/{_incident_seed['incident_b'].id}/assign",
        json={"assignee_id": str(analyst_user.id)},
        headers=analyst_headers,
    )
    assert resp.status_code == 404

    admin_resp = await http_client.get(
        f"/api/incidents/{_incident_seed['incident_b'].id}", headers=admin_headers
    )
    assert admin_resp.status_code == 200
    assert admin_resp.json()["assignee_id"] is None


@pytest.mark.asyncio
async def test_detail_includes_grouped_alerts(
    http_client, _incident_seed, admin_headers, db_session
):
    """The detail payload embeds the grouped alerts."""
    from app.models import Alert, AlertState, Rule, RuleKind, Severity

    rule = Rule(kind=RuleKind.SIGMA, name=f"r-{os.urandom(3).hex()}", severity=Severity.MEDIUM)
    db_session.add(rule)
    await db_session.flush()
    alert = Alert(
        host_id=_incident_seed["host_a"].id,
        rule_id=rule.id,
        severity=Severity.MEDIUM,
        state=AlertState.NEW,
        summary="grouped alert",
        incident_id=_incident_seed["incident_a"].id,
    )
    db_session.add(alert)
    await db_session.flush()

    resp = await http_client.get(
        f"/api/incidents/{_incident_seed['incident_a'].id}", headers=admin_headers
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["alert_count"] == 1
    assert len(body["alerts"]) == 1
    assert body["alerts"][0]["id"] == str(alert.id)
