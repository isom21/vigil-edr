"""M-audit-and-auth #10: synthetic alerts with host_id IS NULL.

The audit-chain-break detector (and any future manager-internal
detection) writes Alert rows with `host_id=None` — there's no host
to attribute the alert to. Two things have to hold:

  1. Admins see those rows everywhere (list, detail, mutations,
     SSE broker payloads — `host_visible_to(admin, None) == True`).
  2. Non-admins don't (`host_visible_to(non_admin, None) == False`),
     and the list/stats queries' `apply_host_scope` filter naturally
     drops null-host rows for non-admins via SQL NULL handling.

Investigation endpoints (`/context`, `/process/{pid}`) require a real
host; they 404 on synthetic alerts because there's nothing to
investigate.
"""

from __future__ import annotations

import os
import uuid

import pytest
import pytest_asyncio
from sqlalchemy import insert


@pytest_asyncio.fixture
async def _synth_alert_seed(db_session, admin_user, analyst_user):
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

    # Real host that the analyst can see, so we can prove the synthetic
    # alert is filtered while a real one passes through the same scope.
    real = Host(
        hostname=f"real-{os.urandom(3).hex()}",
        os_family=OsFamily.LINUX,
        status=HostStatus.ONLINE,
    )
    db_session.add(real)
    await db_session.flush()
    group = HostGroup(name=f"grp-{os.urandom(3).hex()}")
    db_session.add(group)
    await db_session.flush()
    await db_session.execute(insert(host_in_group).values(host_id=real.id, host_group_id=group.id))
    await db_session.execute(
        insert(user_host_group).values(user_id=analyst_user.id, host_group_id=group.id)
    )

    rule = Rule(kind=RuleKind.IOC, name=f"rule-{os.urandom(3).hex()}", severity=Severity.CRITICAL)
    db_session.add(rule)
    await db_session.flush()

    synthetic = Alert(
        host_id=None,
        rule_id=rule.id,
        severity=Severity.CRITICAL,
        state=AlertState.NEW,
        summary="synthetic chain-break",
    )
    real_alert = Alert(
        host_id=real.id,
        rule_id=rule.id,
        severity=Severity.MEDIUM,
        state=AlertState.NEW,
        summary="real alert on visible host",
    )
    db_session.add_all([synthetic, real_alert])
    await db_session.flush()
    return {
        "real_host": real,
        "synthetic": synthetic,
        "real_alert": real_alert,
    }


# ---------- list ----------


@pytest.mark.asyncio
async def test_admin_list_includes_synthetic_alerts(http_client, _synth_alert_seed, admin_headers):
    resp = await http_client.get("/api/alerts?limit=100", headers=admin_headers)
    assert resp.status_code == 200
    items = resp.json()["items"]
    ids = {item["id"] for item in items}
    assert str(_synth_alert_seed["synthetic"].id) in ids
    # Synthetic alert renders with null host_id and null hostname.
    synth_item = next(i for i in items if i["id"] == str(_synth_alert_seed["synthetic"].id))
    assert synth_item["host_id"] is None
    assert synth_item["host_hostname"] is None


@pytest.mark.asyncio
async def test_analyst_list_excludes_synthetic_alerts(
    http_client, _synth_alert_seed, analyst_headers
):
    resp = await http_client.get("/api/alerts?limit=100", headers=analyst_headers)
    assert resp.status_code == 200
    items = resp.json()["items"]
    ids = {item["id"] for item in items}
    assert str(_synth_alert_seed["synthetic"].id) not in ids
    # The visible-host alert still surfaces.
    assert str(_synth_alert_seed["real_alert"].id) in ids


# ---------- detail ----------


@pytest.mark.asyncio
async def test_admin_get_synthetic_alert(http_client, _synth_alert_seed, admin_headers):
    resp = await http_client.get(
        f"/api/alerts/{_synth_alert_seed['synthetic'].id}", headers=admin_headers
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["host_id"] is None
    assert body["host_hostname"] is None


@pytest.mark.asyncio
async def test_analyst_get_synthetic_returns_404(http_client, _synth_alert_seed, analyst_headers):
    resp = await http_client.get(
        f"/api/alerts/{_synth_alert_seed['synthetic'].id}", headers=analyst_headers
    )
    assert resp.status_code == 404


# ---------- mutations ----------


@pytest.mark.asyncio
async def test_admin_changes_state_of_synthetic_alert(
    http_client, _synth_alert_seed, admin_headers
):
    resp = await http_client.post(
        f"/api/alerts/{_synth_alert_seed['synthetic'].id}/state",
        json={"to_state": "investigating"},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["state"] == "investigating"


@pytest.mark.asyncio
async def test_analyst_state_change_on_synthetic_returns_404(
    http_client, _synth_alert_seed, analyst_headers
):
    resp = await http_client.post(
        f"/api/alerts/{_synth_alert_seed['synthetic'].id}/state",
        json={"to_state": "investigating"},
        headers=analyst_headers,
    )
    assert resp.status_code == 404


# ---------- investigation ----------


@pytest.mark.asyncio
async def test_admin_context_for_synthetic_returns_404(
    http_client, _synth_alert_seed, admin_headers
):
    """No host → no telemetry window to fetch → 404, not a 500."""
    resp = await http_client.get(
        f"/api/alerts/{_synth_alert_seed['synthetic'].id}/context", headers=admin_headers
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_admin_process_detail_for_synthetic_returns_404(
    http_client, _synth_alert_seed, admin_headers
):
    resp = await http_client.get(
        f"/api/alerts/{_synth_alert_seed['synthetic'].id}/process/1234", headers=admin_headers
    )
    assert resp.status_code == 404


# ---------- visibility helper ----------


@pytest.mark.asyncio
async def test_host_visible_to_none_admin_true_analyst_false(
    db_session, admin_user, analyst_user
) -> None:
    """`host_visible_to(actor, None, db)` is the public contract — admins
    see synthetic alerts, others don't."""
    from app.core.deps import Actor
    from app.models import UserRole
    from app.services.scoping import host_visible_to

    admin_actor = Actor(kind="user", user=admin_user, token_id=None)
    analyst_actor = Actor(kind="user", user=analyst_user, token_id=None)

    assert await host_visible_to(admin_actor, None, db_session) is True
    assert await host_visible_to(analyst_actor, None, db_session) is False

    # Quiet the unused-import linter when this file gets reformatted.
    _ = (uuid.uuid4(), UserRole)
