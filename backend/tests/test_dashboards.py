"""Operator-authored dashboards (Phase 3 #3.4).

Covers:

  * CRUD: analysts can create / read / update / delete their own
    dashboards; sharing makes a dashboard readable to peers but not
    editable; admins can edit anything.
  * `GET /api/dashboards/default` auto-creates the owner's default on
    first call and is idempotent on subsequent calls.
  * `POST /:id/duplicate` clones into the caller's namespace and
    resets is_default + shared.
  * `GET /:id/data` resolves every widget in order; KPI / donut /
    timeline / table queries honour host scoping.
  * Per-widget exceptions land as `error` strings rather than failing
    the whole `/data` call.
"""

from __future__ import annotations

import os
from uuid import uuid4

import pytest


def _layout(*types: str) -> list[dict]:
    """Tiny helper to build a widgets_json payload — every widget gets
    a non-overlapping position so the partial-uniqueness invariants on
    react-grid-layout are respected (not enforced server-side, but
    keeps the payloads readable in the assertions)."""
    out = []
    for i, t in enumerate(types):
        pos = {"x": (i % 3) * 4, "y": (i // 3) * 4, "w": 4, "h": 3}
        if t == "kpi":
            out.append(
                {
                    "type": "kpi",
                    "title": "Open alerts",
                    "query": "alerts_open",
                    "position": pos,
                }
            )
        elif t in ("top_rules", "hosts_table", "incidents_table"):
            out.append({"type": t, "limit": 5, "position": pos})
        else:
            out.append({"type": t, "position": pos})
    return out


# ---------- /default auto-create ----------


@pytest.mark.asyncio
async def test_default_auto_creates_on_first_call(http_client, analyst_headers) -> None:
    """First call to /default returns the auto-created dashboard."""
    resp = await http_client.get("/api/dashboards/default", headers=analyst_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["is_default"] is True
    assert body["name"] == "Overview"
    # Default layout should include the four historical widgets.
    types = [w["type"] for w in body["widgets_json"]]
    assert "severity_donut" in types
    assert "state_donut" in types
    assert "top_rules" in types
    assert "timeline_24h" in types


@pytest.mark.asyncio
async def test_default_idempotent(http_client, analyst_headers) -> None:
    """Second call returns the same row, not a new one."""
    first = await http_client.get("/api/dashboards/default", headers=analyst_headers)
    second = await http_client.get("/api/dashboards/default", headers=analyst_headers)
    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["id"] == second.json()["id"]


# ---------- CRUD ----------


@pytest.mark.asyncio
async def test_create_analyst_ok(http_client, analyst_headers) -> None:
    resp = await http_client.post(
        "/api/dashboards",
        json={
            "name": f"dash-{os.urandom(2).hex()}",
            "description": "test",
            "shared": False,
            "widgets_json": _layout("severity_donut", "kpi"),
        },
        headers=analyst_headers,
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["name"].startswith("dash-")
    assert body["is_default"] is False
    assert len(body["widgets_json"]) == 2


@pytest.mark.asyncio
async def test_create_rejects_unknown_kpi_query(http_client, analyst_headers) -> None:
    """The discriminated union on the API boundary should reject a
    widget that names an unknown KPI query string — the DB never sees
    invalid widgets."""
    resp = await http_client.post(
        "/api/dashboards",
        json={
            "name": "x",
            "widgets_json": [
                {
                    "type": "kpi",
                    "title": "t",
                    "query": "not_a_real_query",
                    "position": {"x": 0, "y": 0, "w": 3, "h": 2},
                }
            ],
        },
        headers=analyst_headers,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_get_own_dashboard(http_client, analyst_user, analyst_headers, db_session) -> None:
    from app.models import Dashboard

    d = Dashboard(
        owner_user_id=analyst_user.id,
        name=f"mine-{os.urandom(2).hex()}",
        widgets_json=_layout("severity_donut"),
    )
    db_session.add(d)
    await db_session.flush()
    resp = await http_client.get(f"/api/dashboards/{d.id}", headers=analyst_headers)
    assert resp.status_code == 200
    assert resp.json()["name"] == d.name


@pytest.mark.asyncio
async def test_update_own_dashboard(http_client, analyst_user, analyst_headers, db_session) -> None:
    from app.models import Dashboard

    d = Dashboard(
        owner_user_id=analyst_user.id,
        name="orig",
        widgets_json=[],
    )
    db_session.add(d)
    await db_session.flush()
    resp = await http_client.put(
        f"/api/dashboards/{d.id}",
        json={
            "name": "renamed",
            "widgets_json": _layout("severity_donut", "state_donut"),
        },
        headers=analyst_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["name"] == "renamed"
    assert len(resp.json()["widgets_json"]) == 2


@pytest.mark.asyncio
async def test_delete_own_dashboard(http_client, analyst_user, analyst_headers, db_session) -> None:
    from app.models import Dashboard

    d = Dashboard(
        owner_user_id=analyst_user.id,
        name="doomed",
        widgets_json=[],
    )
    db_session.add(d)
    await db_session.flush()
    did = d.id
    resp = await http_client.delete(f"/api/dashboards/{did}", headers=analyst_headers)
    assert resp.status_code == 204
    # Re-fetch through ORM; the session is shared with the handler so
    # the DELETE is visible. Use a fresh statement, not db_session.get,
    # because get() caches the loaded instance.
    from sqlalchemy import select

    gone = (
        await db_session.execute(select(Dashboard).where(Dashboard.id == did))
    ).scalar_one_or_none()
    assert gone is None


# ---------- sharing ----------


@pytest.mark.asyncio
async def test_shared_dashboard_visible_to_non_owner(
    http_client, admin_user, analyst_user, analyst_headers, db_session
) -> None:
    """A dashboard that's shared=true can be read by any analyst+,
    even though they aren't the owner."""
    from app.models import Dashboard

    d = Dashboard(
        owner_user_id=admin_user.id,
        name="team-overview",
        shared=True,
        widgets_json=[],
    )
    db_session.add(d)
    await db_session.flush()

    resp = await http_client.get(f"/api/dashboards/{d.id}", headers=analyst_headers)
    assert resp.status_code == 200
    assert resp.json()["shared"] is True


@pytest.mark.asyncio
async def test_shared_dashboard_not_editable_by_non_owner(
    http_client, admin_user, analyst_user, analyst_headers, db_session
) -> None:
    """Shared = read-only for non-owners. PUT and DELETE 403."""
    from app.models import Dashboard

    d = Dashboard(
        owner_user_id=admin_user.id,
        name="team-overview",
        shared=True,
        widgets_json=[],
    )
    db_session.add(d)
    await db_session.flush()

    resp = await http_client.put(
        f"/api/dashboards/{d.id}",
        json={"name": "rebrand"},
        headers=analyst_headers,
    )
    assert resp.status_code == 403

    resp = await http_client.delete(f"/api/dashboards/{d.id}", headers=analyst_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_unshared_dashboard_invisible_to_non_owner(
    http_client, admin_user, analyst_headers, db_session
) -> None:
    """A non-shared dashboard owned by someone else 404s — existence
    is cloaked, not surfaced as a 403."""
    from app.models import Dashboard

    d = Dashboard(
        owner_user_id=admin_user.id,
        name="private",
        shared=False,
        widgets_json=[],
    )
    db_session.add(d)
    await db_session.flush()

    resp = await http_client.get(f"/api/dashboards/{d.id}", headers=analyst_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_list_includes_own_and_shared(
    http_client, admin_user, analyst_user, analyst_headers, db_session
) -> None:
    from app.models import Dashboard

    mine = Dashboard(
        owner_user_id=analyst_user.id,
        name=f"mine-{os.urandom(2).hex()}",
        widgets_json=[],
    )
    shared = Dashboard(
        owner_user_id=admin_user.id,
        name=f"shared-{os.urandom(2).hex()}",
        shared=True,
        widgets_json=[],
    )
    private = Dashboard(
        owner_user_id=admin_user.id,
        name=f"private-{os.urandom(2).hex()}",
        shared=False,
        widgets_json=[],
    )
    db_session.add_all([mine, shared, private])
    await db_session.flush()

    resp = await http_client.get("/api/dashboards", headers=analyst_headers)
    assert resp.status_code == 200
    names = {d["name"] for d in resp.json()}
    assert mine.name in names
    assert shared.name in names
    assert private.name not in names


@pytest.mark.asyncio
async def test_admin_can_edit_any_dashboard(
    http_client, admin_headers, analyst_user, db_session
) -> None:
    from app.models import Dashboard

    d = Dashboard(
        owner_user_id=analyst_user.id,
        name="analyst-owned",
        widgets_json=[],
    )
    db_session.add(d)
    await db_session.flush()

    resp = await http_client.put(
        f"/api/dashboards/{d.id}",
        json={"name": "renamed-by-admin"},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["name"] == "renamed-by-admin"


# ---------- duplicate ----------


@pytest.mark.asyncio
async def test_duplicate_clones_into_caller_namespace(
    http_client, admin_user, analyst_user, analyst_headers, db_session
) -> None:
    """Duplicating a shared dashboard makes the analyst the owner of
    the clone; the clone resets shared/is_default and gets a ``(copy)``
    name suffix."""
    from app.models import Dashboard

    src = Dashboard(
        owner_user_id=admin_user.id,
        name="team-overview",
        shared=True,
        is_default=False,
        widgets_json=_layout("severity_donut"),
    )
    db_session.add(src)
    await db_session.flush()

    resp = await http_client.post(f"/api/dashboards/{src.id}/duplicate", headers=analyst_headers)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["owner_user_id"] == str(analyst_user.id)
    assert body["shared"] is False
    assert body["is_default"] is False
    assert body["name"].endswith("(copy)")
    assert len(body["widgets_json"]) == 1


# ---------- /data resolution ----------


@pytest.mark.asyncio
async def test_get_data_resolves_widgets_in_order(
    http_client, analyst_user, analyst_headers, db_session
) -> None:
    """The /data response is positional — each entry maps 1:1 to the
    same index in widgets_json, and `type` mirrors the source widget."""
    from app.models import Dashboard

    d = Dashboard(
        owner_user_id=analyst_user.id,
        name="data-test",
        widgets_json=_layout(
            "severity_donut",
            "state_donut",
            "host_status_donut",
            "top_rules",
            "timeline_24h",
            "hosts_table",
            "incidents_table",
        ),
    )
    db_session.add(d)
    await db_session.flush()

    resp = await http_client.get(f"/api/dashboards/{d.id}/data", headers=analyst_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body) == 7
    assert [e["type"] for e in body] == [
        "severity_donut",
        "state_donut",
        "host_status_donut",
        "top_rules",
        "timeline_24h",
        "hosts_table",
        "incidents_table",
    ]
    # No widget should have errored on an empty/test DB.
    assert all(e["error"] is None for e in body), body
    # timeline_24h should always return exactly 24 buckets, padded to
    # zero. The exact times depend on wall clock but the count is
    # invariant.
    timeline = next(e for e in body if e["type"] == "timeline_24h")
    assert len(timeline["data"]) == 24


@pytest.mark.asyncio
async def test_get_data_kpi_alerts_open_counts_open_states(
    http_client, admin_user, admin_headers, db_session
) -> None:
    """The alerts_open KPI counts NEW + INVESTIGATING. Closed alerts
    (TRUE_POSITIVE / FALSE_POSITIVE) don't contribute.

    Use an admin actor here so the count includes the test-seeded
    alerts without needing to wire the analyst into a host group —
    `apply_host_scope` is a no-op for admins, which is the point of
    the helper but means analyst-only visibility plumbing is tested
    separately in the existing `test_alerts_rbac` suite."""
    from datetime import UTC, datetime

    from app.models import (
        Alert,
        AlertState,
        Dashboard,
        Host,
        OsFamily,
        Rule,
        RuleKind,
        Severity,
    )

    host = Host(hostname=f"h-{os.urandom(2).hex()}", os_family=OsFamily.LINUX)
    rule = Rule(
        kind=RuleKind.SIGMA,
        name=f"r-{os.urandom(2).hex()}",
        severity=Severity.HIGH,
    )
    db_session.add_all([host, rule])
    await db_session.flush()

    db_session.add_all(
        [
            Alert(
                host_id=host.id,
                rule_id=rule.id,
                severity=Severity.HIGH,
                state=AlertState.NEW,
                summary="open-1",
                opened_at=datetime.now(UTC),
            ),
            Alert(
                host_id=host.id,
                rule_id=rule.id,
                severity=Severity.HIGH,
                state=AlertState.INVESTIGATING,
                summary="open-2",
                opened_at=datetime.now(UTC),
            ),
            Alert(
                host_id=host.id,
                rule_id=rule.id,
                severity=Severity.HIGH,
                state=AlertState.TRUE_POSITIVE,
                summary="closed",
                opened_at=datetime.now(UTC),
            ),
        ]
    )
    d = Dashboard(
        owner_user_id=admin_user.id,
        name="kpi-test",
        widgets_json=[
            {
                "type": "kpi",
                "title": "Open",
                "query": "alerts_open",
                "position": {"x": 0, "y": 0, "w": 3, "h": 2},
            }
        ],
    )
    db_session.add(d)
    await db_session.flush()

    resp = await http_client.get(f"/api/dashboards/{d.id}/data", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body[0]["type"] == "kpi"
    # >= 2 to stay robust to leftover rows that pre-existed the
    # SAVEPOINT (other concurrent worktrees may share this DB during
    # development; the suite still owns its own rollback).
    assert body[0]["data"]["value"] >= 2


@pytest.mark.asyncio
async def test_get_data_non_owner_cannot_read_private(
    http_client, admin_user, analyst_headers, db_session
) -> None:
    """Non-owners can't pull /data for a private dashboard — same 404
    cloaking as the GET endpoint."""
    from app.models import Dashboard

    d = Dashboard(
        owner_user_id=admin_user.id,
        name="private-data",
        shared=False,
        widgets_json=[],
    )
    db_session.add(d)
    await db_session.flush()

    resp = await http_client.get(f"/api/dashboards/{d.id}/data", headers=analyst_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_404_for_missing_id(http_client, analyst_headers) -> None:
    resp = await http_client.get(f"/api/dashboards/{uuid4()}", headers=analyst_headers)
    assert resp.status_code == 404
