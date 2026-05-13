"""Phase 2 #2.13 — process-tree-aware incident grouping.

When the v1 window grouper attaches 2+ alerts to the same incident and
those alerts trace back to a shared process ancestor on the same host,
the incident's `grouping_reason` is promoted from `window` to
`process_tree`. The label is informational — the alert→incident
mapping itself isn't reshuffled.

These tests poke `regroup_recent` directly so they exercise the full
pass (window grouping + tree refinement) under SAVEPOINT isolation.
The Phase 2 #2.6 `process_chain` table may or may not exist yet on
this deployment, so the tests bring up a minimal compatible shape via
`CREATE TABLE IF NOT EXISTS`.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from sqlalchemy import text


async def _ensure_process_chain_shape(db_session) -> None:
    """Bring up a `process_chain` table with the columns the grouper
    queries. If the Phase 2 #2.6 migration has shipped, the table
    already exists with more columns — `IF NOT EXISTS` makes this a
    no-op there.
    """
    await db_session.execute(
        text("CREATE TABLE IF NOT EXISTS process_chain (  host_id uuid, pid int, parent_pid int)")
    )


@pytest_asyncio.fixture
async def _two_alerts_same_parent(db_session):
    """Two alerts on the same host, each with its own pid, both
    descended from the same parent process."""
    from app.models import (
        Alert,
        AlertState,
        Host,
        HostStatus,
        OsFamily,
        Rule,
        RuleKind,
        Severity,
    )

    host = Host(
        hostname=f"host-{os.urandom(3).hex()}",
        os_family=OsFamily.LINUX,
        status=HostStatus.ONLINE,
    )
    db_session.add(host)
    await db_session.flush()

    rule = Rule(
        kind=RuleKind.SIGMA,
        name=f"rule-{os.urandom(3).hex()}",
        severity=Severity.MEDIUM,
    )
    db_session.add(rule)
    await db_session.flush()

    now = datetime.now(UTC)
    a1 = Alert(
        host_id=host.id,
        rule_id=rule.id,
        severity=Severity.MEDIUM,
        state=AlertState.NEW,
        summary="alert one",
        opened_at=now - timedelta(seconds=60),
        details={"process": {"pid": 1001, "name": "child1"}},
    )
    a2 = Alert(
        host_id=host.id,
        rule_id=rule.id,
        severity=Severity.MEDIUM,
        state=AlertState.NEW,
        summary="alert two",
        opened_at=now - timedelta(seconds=30),
        # Defensive: this one uses the metadata.process shape so we
        # also cover the IOC/anomaly producer path.
        details={"metadata": {"process": {"pid": 1002, "name": "child2"}}},
    )
    db_session.add_all([a1, a2])
    await db_session.flush()
    return {"host": host, "rule": rule, "a1": a1, "a2": a2}


@pytest.mark.asyncio
async def test_process_tree_grouping_marks_reason(db_session, _two_alerts_same_parent):
    """Two alerts sharing an ancestor pid → incident.grouping_reason='process_tree'."""
    from app.models import Incident
    from app.services.incident_grouping import regroup_recent

    host = _two_alerts_same_parent["host"]
    await _ensure_process_chain_shape(db_session)
    # Seed process_chain so pids 1001 and 1002 both point at parent 999.
    # The Phase 2 #2.6 table (if it shipped) has extra NOT NULL columns
    # (id, started_at). Detect the live schema and pick the right INSERT
    # shape so the test works whether or not that sibling migration has
    # landed in this deployment.
    has_id_col = (
        await db_session.execute(
            text(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_name = 'process_chain' AND column_name = 'id'"
            )
        )
    ).first() is not None
    from app.models.tenant import DEFAULT_TENANT_ID

    if has_id_col:
        await db_session.execute(
            text(
                "INSERT INTO process_chain (id, host_id, pid, parent_pid, started_at, tenant_id) "
                "VALUES "
                "  (gen_random_uuid(), :h, 1001, 999, now(), :t), "
                "  (gen_random_uuid(), :h, 1002, 999, now(), :t), "
                "  (gen_random_uuid(), :h, 999, NULL, now(), :t)"
            ),
            {"h": str(host.id), "t": str(DEFAULT_TENANT_ID)},
        )
    else:
        await db_session.execute(
            text(
                "INSERT INTO process_chain (host_id, pid, parent_pid, tenant_id) "
                "VALUES (:h, 1001, 999, :t), (:h, 1002, 999, :t), (:h, 999, NULL, :t)"
            ),
            {"h": str(host.id), "t": str(DEFAULT_TENANT_ID)},
        )

    grouped = await regroup_recent(db_session, window_s=600)
    assert grouped == 2

    await db_session.refresh(_two_alerts_same_parent["a1"])
    await db_session.refresh(_two_alerts_same_parent["a2"])
    inc_id = _two_alerts_same_parent["a1"].incident_id
    assert inc_id is not None
    assert _two_alerts_same_parent["a2"].incident_id == inc_id

    incident = await db_session.get(Incident, inc_id)
    assert incident is not None
    assert incident.grouping_reason.value == "process_tree"


@pytest.mark.asyncio
async def test_no_process_chain_falls_back_to_window(db_session, _two_alerts_same_parent):
    """No process_chain rows → grouping_reason stays 'window'."""
    from app.models import Incident
    from app.services.incident_grouping import regroup_recent

    # Table exists but is empty — we want the "row missing" branch,
    # not the "table missing" branch.
    await _ensure_process_chain_shape(db_session)
    host = _two_alerts_same_parent["host"]
    await db_session.execute(
        text("DELETE FROM process_chain WHERE host_id = :h"), {"h": str(host.id)}
    )

    grouped = await regroup_recent(db_session, window_s=600)
    assert grouped == 2

    await db_session.refresh(_two_alerts_same_parent["a1"])
    inc = await db_session.get(Incident, _two_alerts_same_parent["a1"].incident_id)
    assert inc is not None
    assert inc.grouping_reason.value == "window"
