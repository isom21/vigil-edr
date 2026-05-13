"""Agent rollout cohorts + auto-rollback tests (Phase 3 #3.3).

Covers:

  * ``assign_cohort`` is stable across calls and deterministic in the
    seed.
  * ``cohort_label`` partitions the [0, 100) range into canary / early
    / mainline at the documented boundaries.
  * ``eligible_for_update`` gates correctly on the percentage AND on
    the host's current agent_version vs. ``cohort_target_version``.
  * The ``rollout_monitor`` worker trips ``cohort_rolled_out_pct`` to
    0 once the failure threshold is exceeded within the window.
  * ``POST /api/rollouts/{policy_id}/advance`` writes an audit row
    capturing the from/to percentage.
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select


def _test_session_maker(db_session):
    @asynccontextmanager
    async def _maker():
        yield db_session

    return _maker


async def _make_policy(
    db_session,
    *,
    name: str | None = None,
    pct: int = 50,
    target: str | None = "1.4.0",
):
    from app.models import Policy

    p = Policy(
        name=name or f"pol-{uuid.uuid4().hex[:8]}",
        rollout_cohort="default",
        cohort_target_version=target,
        cohort_rolled_out_pct=pct,
    )
    db_session.add(p)
    await db_session.flush()
    return p


async def _make_host(db_session, *, policy_id=None, agent_version: str | None = "1.3.0"):
    from app.models import Host, OsFamily

    h = Host(
        hostname=f"host-{uuid.uuid4().hex[:8]}",
        os_family=OsFamily.LINUX,
        agent_version=agent_version,
        policy_id=policy_id,
    )
    db_session.add(h)
    await db_session.flush()
    return h


# ---------- assign_cohort / cohort_label ----------


def test_assign_cohort_stable():
    from app.services.rollout import assign_cohort

    hid = uuid.UUID("00000000-0000-0000-0000-000000000001")
    seed = "vigil-cohort-v1"
    a = assign_cohort(hid, seed)
    b = assign_cohort(hid, seed)
    assert a == b
    assert 0 <= a <= 99


def test_assign_cohort_distinct_seeds_diverge():
    from app.services.rollout import assign_cohort

    hid = uuid.UUID("11111111-1111-1111-1111-111111111111")
    # Not a uniqueness *contract*, but blake2b should differ on the
    # vast majority of seed pairs; if this ever flakes, find a better
    # pair rather than weaken the assertion.
    assert assign_cohort(hid, "seed-A") != assign_cohort(hid, "seed-B")


def test_cohort_label_boundaries():
    from app.services.rollout import cohort_label

    assert cohort_label(0) == "canary"
    assert cohort_label(4) == "canary"
    assert cohort_label(5) == "early"
    assert cohort_label(24) == "early"
    assert cohort_label(25) == "mainline"
    assert cohort_label(99) == "mainline"


# ---------- eligible_for_update ----------


@pytest.mark.asyncio
async def test_eligible_requires_target_version(db_session):
    from app.services.rollout import eligible_for_update

    p = await _make_policy(db_session, pct=100, target=None)
    h = await _make_host(db_session, policy_id=p.id, agent_version="1.3.0")
    assert eligible_for_update(h, p) is False


@pytest.mark.asyncio
async def test_eligible_zero_pct_blocks_all(db_session):
    from app.services.rollout import eligible_for_update

    p = await _make_policy(db_session, pct=0, target="1.4.0")
    h = await _make_host(db_session, policy_id=p.id, agent_version="1.3.0")
    assert eligible_for_update(h, p) is False


@pytest.mark.asyncio
async def test_eligible_skips_already_current(db_session):
    from app.services.rollout import eligible_for_update

    p = await _make_policy(db_session, pct=100, target="1.4.0")
    h = await _make_host(db_session, policy_id=p.id, agent_version="1.4.0")
    assert eligible_for_update(h, p) is False


@pytest.mark.asyncio
async def test_eligible_full_rollout_includes_outdated(db_session):
    from app.services.rollout import eligible_for_update

    p = await _make_policy(db_session, pct=100, target="1.4.0")
    h = await _make_host(db_session, policy_id=p.id, agent_version="1.3.0")
    assert eligible_for_update(h, p) is True


# ---------- Rollout monitor trips the breaker ----------


@pytest.mark.asyncio
async def test_monitor_trips_on_threshold(db_session, monkeypatch):
    from app.models import RolloutEvent, RolloutStatus
    from app.workers import rollout_monitor

    monkeypatch.setenv("VIGIL_ROLLOUT_FAILURE_THRESHOLD", "3")
    monkeypatch.setenv("VIGIL_ROLLOUT_FAILURE_WINDOW_S", "600")

    p = await _make_policy(db_session, pct=25, target="1.4.0")
    now = datetime.now(UTC)
    for _ in range(3):
        h = await _make_host(db_session, policy_id=p.id)
        db_session.add(
            RolloutEvent(
                host_id=h.id,
                policy_id=p.id,
                cohort="canary",
                version_from="1.3.0",
                version_to="1.4.0",
                status=RolloutStatus.FAILED.value,
                started_at=now - timedelta(seconds=60),
            )
        )
    await db_session.flush()

    tripped = await rollout_monitor._run_once(session_maker=_test_session_maker(db_session))
    assert tripped == 1
    await db_session.refresh(p)
    assert p.cohort_rolled_out_pct == 0


@pytest.mark.asyncio
async def test_monitor_ignores_stale_failures(db_session, monkeypatch):
    from app.models import RolloutEvent, RolloutStatus
    from app.workers import rollout_monitor

    monkeypatch.setenv("VIGIL_ROLLOUT_FAILURE_THRESHOLD", "3")
    monkeypatch.setenv("VIGIL_ROLLOUT_FAILURE_WINDOW_S", "60")

    p = await _make_policy(db_session, pct=50, target="1.4.0")
    now = datetime.now(UTC)
    for _ in range(5):
        h = await _make_host(db_session, policy_id=p.id)
        db_session.add(
            RolloutEvent(
                host_id=h.id,
                policy_id=p.id,
                cohort="canary",
                version_from="1.3.0",
                version_to="1.4.0",
                status=RolloutStatus.FAILED.value,
                # Older than the 60s window — should be ignored.
                started_at=now - timedelta(seconds=600),
            )
        )
    await db_session.flush()

    tripped = await rollout_monitor._run_once(session_maker=_test_session_maker(db_session))
    assert tripped == 0
    await db_session.refresh(p)
    assert p.cohort_rolled_out_pct == 50


@pytest.mark.asyncio
async def test_monitor_skips_already_zero_policy(db_session, monkeypatch):
    """A policy already at 0% doesn't get re-alerted; the breaker is
    edge-triggered on the transition from non-zero → 0."""
    from app.models import RolloutEvent, RolloutStatus
    from app.workers import rollout_monitor

    monkeypatch.setenv("VIGIL_ROLLOUT_FAILURE_THRESHOLD", "3")
    monkeypatch.setenv("VIGIL_ROLLOUT_FAILURE_WINDOW_S", "600")

    p = await _make_policy(db_session, pct=0, target="1.4.0")
    now = datetime.now(UTC)
    for _ in range(5):
        h = await _make_host(db_session, policy_id=p.id)
        db_session.add(
            RolloutEvent(
                host_id=h.id,
                policy_id=p.id,
                cohort="canary",
                version_from="1.3.0",
                version_to="1.4.0",
                status=RolloutStatus.FAILED.value,
                started_at=now - timedelta(seconds=60),
            )
        )
    await db_session.flush()

    tripped = await rollout_monitor._run_once(session_maker=_test_session_maker(db_session))
    assert tripped == 0


# ---------- Advance endpoint audits the change ----------


@pytest.mark.asyncio
async def test_advance_records_audit(http_client, admin_headers, db_session):
    from app.models import AuditLog

    p = await _make_policy(db_session, pct=10, target="1.4.0")
    resp = await http_client.post(
        f"/api/rollouts/{p.id}/advance",
        json={"to_pct": 50},
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["cohort_rolled_out_pct"] == 50

    rows = (
        (await db_session.execute(select(AuditLog).where(AuditLog.action == "rollout.advance")))
        .scalars()
        .all()
    )
    assert len(rows) >= 1
    row = rows[-1]
    assert row.resource_type == "policy"
    assert row.resource_id == str(p.id)
    assert row.payload["to_pct"] == 50
    assert row.payload["from_pct"] == 10


@pytest.mark.asyncio
async def test_advance_admin_only(http_client, analyst_headers, db_session):
    p = await _make_policy(db_session, pct=10)
    resp = await http_client.post(
        f"/api/rollouts/{p.id}/advance",
        json={"to_pct": 50},
        headers=analyst_headers,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_list_rollouts_returns_per_policy(http_client, analyst_headers, db_session):
    p = await _make_policy(db_session, pct=25, target="1.4.0")
    resp = await http_client.get("/api/rollouts", headers=analyst_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    ids = {row["policy_id"] for row in body}
    assert str(p.id) in ids
    match = next(row for row in body if row["policy_id"] == str(p.id))
    assert match["cohort_rolled_out_pct"] == 25
    assert match["cohort_target_version"] == "1.4.0"
    # Three canonical cohort labels always present even with no events.
    labels = {c["cohort"] for c in match["cohorts"]}
    assert {"canary", "early", "mainline"}.issubset(labels)
