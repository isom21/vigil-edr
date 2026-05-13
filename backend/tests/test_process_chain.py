"""Phase 2 #2.6 cross-process correlation graph store.

Covers:
  * The indexer turns a `process_started` doc into a row with the
    right host/pid/parent_pid/started_at/sha256 fields. A duplicate
    pass collapses via ON CONFLICT (host_id, pid, started_at).
  * A `process_exited` doc patches `ended_at` on the latest open row
    for the same (host, pid).
  * `process_graph.ancestors` walks parent_pid back to the root.
  * `process_graph.descendants` walks forward and orders children
    breadth-first.
  * `process_graph.cross_host_lineage` groups by image_sha256 across
    hosts and orders newest first.
  * The host endpoint 404s for hosts the actor can't see, returns the
    chain for hosts they can.
  * The alert endpoint resolves the trigger pid from `alert.details`
    and surfaces 404 when the alert host isn't visible.
  * Retention sweep deletes rows older than the configured cut-off
    and leaves recent rows alone.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select


@pytest_asyncio.fixture
async def host_a(db_session):
    from app.models import Host, HostStatus, OsFamily

    h = Host(
        hostname=f"host-a-{os.urandom(3).hex()}",
        os_family=OsFamily.LINUX,
        status=HostStatus.ONLINE,
    )
    db_session.add(h)
    await db_session.flush()
    return h


@pytest_asyncio.fixture
async def host_b(db_session):
    from app.models import Host, HostStatus, OsFamily

    h = Host(
        hostname=f"host-b-{os.urandom(3).hex()}",
        os_family=OsFamily.LINUX,
        status=HostStatus.ONLINE,
    )
    db_session.add(h)
    await db_session.flush()
    return h


# ---------- indexer ----------


@pytest.mark.asyncio
async def test_indexer_process_started_inserts_row(db_session, host_a) -> None:
    from app.models import ProcessChain
    from app.workers.process_chain_indexer import handle_doc

    started = datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC)
    doc = {
        "@timestamp": started.isoformat(),
        "event": {"action": "process_started", "created": started.isoformat()},
        "host": {"id": str(host_a.id)},
        "process": {
            "pid": 4321,
            "parent": {"pid": 1},
            "executable": "/usr/bin/bash",
            "command_line": "bash -i",
            "hash": {"sha256": "a" * 64},
            "start": started.isoformat(),
        },
    }
    inserted = await handle_doc(db_session, doc)
    await db_session.flush()
    assert inserted is True

    row = (
        await db_session.execute(
            select(ProcessChain).where(ProcessChain.host_id == host_a.id, ProcessChain.pid == 4321)
        )
    ).scalar_one()
    assert row.parent_pid == 1
    assert row.exec_path == "/usr/bin/bash"
    assert row.image_sha256 == "a" * 64
    assert row.command_line == "bash -i"
    assert row.started_at == started
    assert row.ended_at is None


@pytest.mark.asyncio
async def test_indexer_duplicate_process_started_no_conflict(db_session, host_a) -> None:
    """Two `process_started` deliveries for the same (host, pid,
    started_at) collapse onto one row via ON CONFLICT DO NOTHING."""
    from app.models import ProcessChain
    from app.workers.process_chain_indexer import handle_doc

    started = datetime(2026, 5, 13, 12, 5, 0, tzinfo=UTC)
    doc = {
        "@timestamp": started.isoformat(),
        "event": {"action": "process_started", "created": started.isoformat()},
        "host": {"id": str(host_a.id)},
        "process": {
            "pid": 555,
            "parent": {"pid": 1},
            "executable": "/bin/cat",
            "start": started.isoformat(),
        },
    }
    await handle_doc(db_session, doc)
    await handle_doc(db_session, doc)
    await db_session.flush()

    rows = (
        (
            await db_session.execute(
                select(ProcessChain).where(
                    ProcessChain.host_id == host_a.id, ProcessChain.pid == 555
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_indexer_process_exited_patches_ended_at(db_session, host_a) -> None:
    from app.models import ProcessChain
    from app.workers.process_chain_indexer import handle_doc

    started = datetime(2026, 5, 13, 12, 10, 0, tzinfo=UTC)
    exited = started + timedelta(seconds=42)

    await handle_doc(
        db_session,
        {
            "@timestamp": started.isoformat(),
            "event": {"action": "process_started", "created": started.isoformat()},
            "host": {"id": str(host_a.id)},
            "process": {
                "pid": 9001,
                "parent": {"pid": 1},
                "executable": "/usr/bin/sleep",
                "start": started.isoformat(),
            },
        },
    )
    await db_session.flush()

    patched = await handle_doc(
        db_session,
        {
            "@timestamp": exited.isoformat(),
            "event": {"action": "process_exited", "created": exited.isoformat()},
            "host": {"id": str(host_a.id)},
            "process": {"pid": 9001},
        },
    )
    await db_session.flush()
    assert patched is True

    row = (
        await db_session.execute(
            select(ProcessChain).where(ProcessChain.host_id == host_a.id, ProcessChain.pid == 9001)
        )
    ).scalar_one()
    assert row.ended_at == exited


@pytest.mark.asyncio
async def test_indexer_ignores_non_process_actions(db_session, host_a) -> None:
    from app.workers.process_chain_indexer import handle_doc

    inserted = await handle_doc(
        db_session,
        {
            "@timestamp": "2026-05-13T12:00:00+00:00",
            "event": {"action": "file_created"},
            "host": {"id": str(host_a.id)},
            "process": {"pid": 12, "parent": {"pid": 1}},
        },
    )
    assert inserted is False


# ---------- graph queries ----------


async def _seed_chain(db, host_id, *, base_pid: int = 1000) -> None:
    """Insert a 4-deep chain: pid 1 → 100 → 200 → 300 plus a sibling
    400 spawned by 100. Times are synthetic but ordered."""
    from app.workers.process_chain_indexer import handle_doc

    base = datetime(2026, 5, 13, 13, 0, 0, tzinfo=UTC)
    spec = [
        # (pid, parent_pid, offset_seconds)
        (1, None, 0),
        (100, 1, 5),
        (200, 100, 10),
        (300, 200, 15),
        (400, 100, 7),
    ]
    for pid, parent_pid, offset in spec:
        started = base + timedelta(seconds=offset)
        parent_block = {"parent": {"pid": parent_pid}} if parent_pid else {}
        proc: dict = {
            "pid": pid,
            "executable": f"/bin/proc-{pid}",
            "start": started.isoformat(),
            **parent_block,
        }
        await handle_doc(
            db,
            {
                "@timestamp": started.isoformat(),
                "event": {"action": "process_started", "created": started.isoformat()},
                "host": {"id": str(host_id)},
                "process": proc,
            },
        )
    await db.flush()


@pytest.mark.asyncio
async def test_ancestors_walks_to_root(db_session, host_a) -> None:
    from app.services import process_graph

    await _seed_chain(db_session, host_a.id)
    chain = await process_graph.ancestors(db_session, host_id=host_a.id, pid=300)
    pids = [r.pid for r in chain]
    # Root-first ordering: pid 1 at index 0, the queried pid 300 last.
    assert pids[0] == 1
    assert pids[-1] == 300
    assert 100 in pids
    assert 200 in pids
    assert 400 not in pids


@pytest.mark.asyncio
async def test_descendants_walks_forward(db_session, host_a) -> None:
    from app.services import process_graph

    await _seed_chain(db_session, host_a.id)
    chain = await process_graph.descendants(db_session, host_id=host_a.id, pid=100)
    pids = {r.pid for r in chain}
    assert 200 in pids
    assert 300 in pids
    assert 400 in pids
    assert 100 not in pids  # the seed pid itself is excluded
    assert 1 not in pids


@pytest.mark.asyncio
async def test_ancestors_no_rows_returns_empty(db_session, host_a) -> None:
    from app.services import process_graph

    chain = await process_graph.ancestors(db_session, host_id=host_a.id, pid=999)
    assert chain == []


@pytest.mark.asyncio
async def test_cross_host_lineage_groups_by_sha256(db_session, host_a, host_b) -> None:
    """The same binary running on two hosts surfaces both starts."""
    from app.services import process_graph
    from app.workers.process_chain_indexer import handle_doc

    sha = "b" * 64
    t0 = datetime(2026, 5, 13, 14, 0, 0, tzinfo=UTC)
    for host, pid, offset in [(host_a, 11, 0), (host_b, 22, 10)]:
        started = t0 + timedelta(seconds=offset)
        await handle_doc(
            db_session,
            {
                "@timestamp": started.isoformat(),
                "event": {"action": "process_started", "created": started.isoformat()},
                "host": {"id": str(host.id)},
                "process": {
                    "pid": pid,
                    "executable": "/usr/bin/malware",
                    "hash": {"sha256": sha},
                    "start": started.isoformat(),
                },
            },
        )
    await db_session.flush()

    rows = await process_graph.cross_host_lineage(db_session, image_sha256=sha)
    host_ids = {r.host_id for r in rows}
    assert host_a.id in host_ids
    assert host_b.id in host_ids
    # Newest-first ordering: the host_b row (later started) comes first.
    assert rows[0].host_id == host_b.id


# ---------- HTTP API ----------


@pytest.mark.asyncio
async def test_host_process_chain_admin_sees_chain(
    http_client, admin_headers, db_session, host_a
) -> None:
    await _seed_chain(db_session, host_a.id)
    r = await http_client.get(
        f"/api/hosts/{host_a.id}/process_chain?pid=300",
        headers=admin_headers,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["pid"] == 300
    ancestor_pids = [n["pid"] for n in body["ancestors"]]
    assert ancestor_pids[0] == 1
    assert 100 in ancestor_pids


@pytest.mark.asyncio
async def test_host_process_chain_404_when_not_visible(
    http_client, analyst_headers, db_session
) -> None:
    """A host that isn't in any of the analyst's groups returns 404
    (not 403, per M-audit-and-auth #7)."""
    from app.models import Host, HostStatus, OsFamily

    other = Host(
        hostname=f"hidden-{os.urandom(3).hex()}",
        os_family=OsFamily.LINUX,
        status=HostStatus.ONLINE,
    )
    db_session.add(other)
    await db_session.flush()
    r = await http_client.get(
        f"/api/hosts/{other.id}/process_chain?pid=1",
        headers=analyst_headers,
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_alert_process_chain_resolves_from_details_pid(
    http_client, admin_headers, db_session, host_a
) -> None:
    from app.models import Alert, AlertState, Rule, RuleKind, Severity

    rule = Rule(
        kind=RuleKind.SIGMA,
        name=f"rule-{os.urandom(3).hex()}",
        severity=Severity.HIGH,
    )
    db_session.add(rule)
    await db_session.flush()
    alert = Alert(
        host_id=host_a.id,
        rule_id=rule.id,
        severity=Severity.HIGH,
        state=AlertState.NEW,
        summary="test",
        details={"pid": 300},
        opened_at=datetime.now(UTC),
    )
    db_session.add(alert)
    await db_session.flush()
    await _seed_chain(db_session, host_a.id)

    r = await http_client.get(
        f"/api/alerts/{alert.id}/process_chain",
        headers=admin_headers,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["pid"] == 300
    assert any(n["pid"] == 100 for n in body["ancestors"])


@pytest.mark.asyncio
async def test_alert_process_chain_404_when_alert_missing(http_client, admin_headers) -> None:
    r = await http_client.get(
        f"/api/alerts/{uuid4()}/process_chain",
        headers=admin_headers,
    )
    assert r.status_code == 404


# ---------- retention ----------


@pytest.mark.asyncio
async def test_retention_sweep_drops_old_rows(db_session, host_a, monkeypatch) -> None:
    from app.models import ProcessChain
    from app.workers.process_chain_indexer import _sweep_retention

    old = datetime.now(UTC) - timedelta(days=120)
    recent = datetime.now(UTC) - timedelta(days=1)
    db_session.add_all(
        [
            ProcessChain(
                host_id=host_a.id,
                pid=10,
                parent_pid=1,
                exec_path="/bin/old",
                started_at=old,
            ),
            ProcessChain(
                host_id=host_a.id,
                pid=11,
                parent_pid=1,
                exec_path="/bin/recent",
                started_at=recent,
            ),
        ]
    )
    await db_session.flush()

    monkeypatch.setenv("VIGIL_PROCESS_CHAIN_RETENTION_DAYS", "90")
    removed = await _sweep_retention(db_session)
    await db_session.flush()
    assert removed == 1

    remaining_pids = {
        r.pid
        for r in (
            await db_session.execute(select(ProcessChain).where(ProcessChain.host_id == host_a.id))
        ).scalars()
    }
    assert remaining_pids == {11}
