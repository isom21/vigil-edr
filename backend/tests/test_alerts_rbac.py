"""Host-group scope on the Alerts mutation endpoints.

Review findings.md Top-20 #1 / #2: `change_state` and `assign` both
looked up the alert by id and acted on it without first checking that
the actor could see the underlying host. A non-admin analyst could
mutate alerts on hosts outside their host groups by guessing or
enumerating ids.

Mirrors test_jobs_rbac.py:
  * Two hosts (A, B), each in its own group.
  * The analyst is assigned to group-alpha (host A only).
  * One alert per host.
  * Admin can mutate either; analyst can mutate only the A alert.

403/404 unification: out-of-scope mutations come back as 404 so the
caller can't distinguish "doesn't exist" from "not allowed".
"""

from __future__ import annotations

import os

import pytest
import pytest_asyncio
from sqlalchemy import insert


@pytest_asyncio.fixture
async def _alerts_seed(db_session, admin_user, analyst_user):
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
    beta = HostGroup(name=f"beta-{os.urandom(3).hex()}")
    db_session.add_all([alpha, beta])
    await db_session.flush()

    await db_session.execute(insert(host_in_group).values(host_id=a.id, host_group_id=alpha.id))
    await db_session.execute(insert(host_in_group).values(host_id=b.id, host_group_id=beta.id))
    await db_session.execute(
        insert(user_host_group).values(user_id=analyst_user.id, host_group_id=alpha.id)
    )

    rule = Rule(kind=RuleKind.SIGMA, name=f"rule-{os.urandom(3).hex()}", severity=Severity.MEDIUM)
    db_session.add(rule)
    await db_session.flush()

    alert_a = Alert(
        host_id=a.id,
        rule_id=rule.id,
        severity=Severity.MEDIUM,
        state=AlertState.NEW,
        summary="alert on host A",
    )
    alert_b = Alert(
        host_id=b.id,
        rule_id=rule.id,
        severity=Severity.MEDIUM,
        state=AlertState.NEW,
        summary="alert on host B",
    )
    db_session.add_all([alert_a, alert_b])
    await db_session.flush()

    return {
        "host_a": a,
        "host_b": b,
        "alert_a": alert_a,
        "alert_b": alert_b,
    }


# ---------- change_state ----------


@pytest.mark.asyncio
async def test_admin_changes_state_of_any_alert(http_client, _alerts_seed, admin_headers):
    resp = await http_client.post(
        f"/api/alerts/{_alerts_seed['alert_b'].id}/state",
        json={"to_state": "investigating"},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["state"] == "investigating"


@pytest.mark.asyncio
async def test_analyst_changes_state_of_in_scope_alert(http_client, _alerts_seed, analyst_headers):
    resp = await http_client.post(
        f"/api/alerts/{_alerts_seed['alert_a'].id}/state",
        json={"to_state": "investigating"},
        headers=analyst_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["state"] == "investigating"


@pytest.mark.asyncio
async def test_analyst_out_of_scope_state_change_returns_404_and_no_mutation(
    http_client, _alerts_seed, analyst_headers, admin_headers
):
    resp = await http_client.post(
        f"/api/alerts/{_alerts_seed['alert_b'].id}/state",
        json={"to_state": "false_positive"},
        headers=analyst_headers,
    )
    assert resp.status_code == 404

    # Belt-and-braces: re-read as admin to confirm the state didn't move.
    admin_resp = await http_client.get(
        f"/api/alerts/{_alerts_seed['alert_b'].id}", headers=admin_headers
    )
    assert admin_resp.status_code == 200
    assert admin_resp.json()["state"] == "new"
    assert admin_resp.json()["closed_at"] is None


# ---------- assign ----------


@pytest.mark.asyncio
async def test_admin_assigns_any_alert(http_client, _alerts_seed, admin_headers, admin_user):
    resp = await http_client.post(
        f"/api/alerts/{_alerts_seed['alert_b'].id}/assign",
        json={"assignee_id": str(admin_user.id)},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["assignee_id"] == str(admin_user.id)


@pytest.mark.asyncio
async def test_analyst_assigns_in_scope_alert(
    http_client, _alerts_seed, analyst_headers, analyst_user
):
    resp = await http_client.post(
        f"/api/alerts/{_alerts_seed['alert_a'].id}/assign",
        json={"assignee_id": str(analyst_user.id)},
        headers=analyst_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["assignee_id"] == str(analyst_user.id)


@pytest.mark.asyncio
async def test_analyst_out_of_scope_assign_returns_404_and_no_mutation(
    http_client, _alerts_seed, analyst_headers, analyst_user, admin_headers
):
    resp = await http_client.post(
        f"/api/alerts/{_alerts_seed['alert_b'].id}/assign",
        json={"assignee_id": str(analyst_user.id)},
        headers=analyst_headers,
    )
    assert resp.status_code == 404

    admin_resp = await http_client.get(
        f"/api/alerts/{_alerts_seed['alert_b'].id}", headers=admin_headers
    )
    assert admin_resp.status_code == 200
    assert admin_resp.json()["assignee_id"] is None
