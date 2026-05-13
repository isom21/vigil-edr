"""Alert deduplication (Phase 1 #1.10).

The producer hook is in `app.services.alert_dedup`:
  * `dedup_key_for(rule_id, host_id, ecs)` — sha256-hex of a stable
    canonical signal (process.executable > file.path > destination.ip
    > event.id), so re-detonations of the same artefact collapse onto
    one alert row.
  * `find_open_dupe` — sliding-window probe that returns the most
    recently-occurred OPEN alert sharing the key, or None.
  * `bump_occurrence` — in-place increment of `occurrence_count` +
    refresh of `last_occurred_at`.

These tests pin:
  * Key stability + sensitivity to the rule/host/signal tuple.
  * Fallback ordering — process.executable wins over file.path which
    wins over destination.ip which wins over event.id.
  * The DB-level probe respects the window and the state filter.
  * The IOC detector's `emit_alerts` calls the dedup branch and bumps
    instead of inserting; it skips queueing a second command for the
    deduped row.

Tests use the SAVEPOINT-isolated db_session fixture from conftest;
the producer-side path is exercised against a real PG schema so the
ORM mapping (server_default, indexes) matches what migrations build.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import pytest_asyncio

# ---------------------------------------------------------------------------
# dedup_key_for — pure function, no DB needed.
# ---------------------------------------------------------------------------


def test_dedup_key_is_deterministic() -> None:
    from app.services.alert_dedup import dedup_key_for

    rule = uuid4()
    host = uuid4()
    ecs = {"process": {"executable": "/usr/bin/curl"}}
    k1 = dedup_key_for(rule, host, ecs)
    k2 = dedup_key_for(rule, host, ecs)
    assert k1 == k2
    assert len(k1) == 64  # sha256 hex


def test_dedup_key_differs_per_rule() -> None:
    from app.services.alert_dedup import dedup_key_for

    host = uuid4()
    ecs = {"process": {"executable": "/usr/bin/curl"}}
    assert dedup_key_for(uuid4(), host, ecs) != dedup_key_for(uuid4(), host, ecs)


def test_dedup_key_differs_per_host() -> None:
    from app.services.alert_dedup import dedup_key_for

    rule = uuid4()
    ecs = {"process": {"executable": "/usr/bin/curl"}}
    assert dedup_key_for(rule, uuid4(), ecs) != dedup_key_for(rule, uuid4(), ecs)


def test_dedup_key_differs_per_signal() -> None:
    from app.services.alert_dedup import dedup_key_for

    rule = uuid4()
    host = uuid4()
    k1 = dedup_key_for(rule, host, {"process": {"executable": "/a"}})
    k2 = dedup_key_for(rule, host, {"process": {"executable": "/b"}})
    assert k1 != k2


def test_dedup_key_signal_precedence_executable_wins() -> None:
    """When process.executable is present, file.path / destination.ip /
    event.id are ignored — that's the most specific signal."""
    from app.services.alert_dedup import dedup_key_for

    rule = uuid4()
    host = uuid4()
    base = dedup_key_for(rule, host, {"process": {"executable": "/x"}})
    # Adding lower-precedence fields must not change the key.
    decorated = dedup_key_for(
        rule,
        host,
        {
            "process": {"executable": "/x"},
            "file": {"path": "/should-be-ignored"},
            "destination": {"ip": "1.2.3.4"},
            "event": {"id": "evt-1"},
        },
    )
    assert base == decorated


def test_dedup_key_signal_precedence_file_path_over_dest_ip() -> None:
    from app.services.alert_dedup import dedup_key_for

    rule = uuid4()
    host = uuid4()
    just_path = dedup_key_for(rule, host, {"file": {"path": "/y"}})
    with_ip = dedup_key_for(rule, host, {"file": {"path": "/y"}, "destination": {"ip": "1.2.3.4"}})
    assert just_path == with_ip


def test_dedup_key_signal_precedence_dest_ip_over_event_id() -> None:
    from app.services.alert_dedup import dedup_key_for

    rule = uuid4()
    host = uuid4()
    a = dedup_key_for(rule, host, {"destination": {"ip": "1.2.3.4"}})
    b = dedup_key_for(rule, host, {"destination": {"ip": "1.2.3.4"}, "event": {"id": "evt-1"}})
    assert a == b


def test_dedup_key_falls_back_to_event_id_when_only_field() -> None:
    from app.services.alert_dedup import dedup_key_for

    rule = uuid4()
    host = uuid4()
    a = dedup_key_for(rule, host, {"event": {"id": "abc"}})
    b = dedup_key_for(rule, host, {"event": {"id": "xyz"}})
    assert a != b


def test_dedup_key_empty_ecs_still_returns_a_key() -> None:
    """Producers must always get a key back, even when ECS has no
    useful signal. The fallback collapses all such alerts onto one
    row per (rule, host) — acceptable: rare in practice and the
    operator can manually re-investigate."""
    from app.services.alert_dedup import dedup_key_for

    k = dedup_key_for(uuid4(), uuid4(), {})
    assert isinstance(k, str)
    assert len(k) == 64


def test_dedup_key_tolerates_null_host_id() -> None:
    """Synthetic / manager-internal alerts (audit chain break) have
    host_id=None. Producers still need a key."""
    from app.services.alert_dedup import dedup_key_for

    k1 = dedup_key_for(uuid4(), None, {"process": {"executable": "/x"}})
    k2 = dedup_key_for(uuid4(), None, {"process": {"executable": "/x"}})
    assert k1 != k2  # different rule ids
    same_rule = uuid4()
    assert dedup_key_for(same_rule, None, {"process": {"executable": "/x"}}) == dedup_key_for(
        same_rule, None, {"process": {"executable": "/x"}}
    )


# ---------------------------------------------------------------------------
# Fixtures for DB-backed tests.
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def _dedup_host(db_session):
    from app.models import Host, HostStatus, OsFamily

    h = Host(
        hostname=f"dedup-host-{os.urandom(3).hex()}",
        os_family=OsFamily.LINUX,
        status=HostStatus.ONLINE,
    )
    db_session.add(h)
    await db_session.flush()
    return h


@pytest_asyncio.fixture
async def _dedup_rule(db_session):
    from app.models import Rule, RuleKind, Severity

    r = Rule(
        kind=RuleKind.IOC,
        name=f"dedup-rule-{os.urandom(3).hex()}",
        severity=Severity.MEDIUM,
    )
    db_session.add(r)
    await db_session.flush()
    return r


# ---------------------------------------------------------------------------
# find_open_dupe + bump_occurrence
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_find_open_dupe_returns_none_when_no_match(db_session) -> None:
    from app.services.alert_dedup import find_open_dupe

    found = await find_open_dupe(db_session, dedup_key="a" * 64, window_seconds=300)
    assert found is None


@pytest.mark.asyncio
async def test_find_open_dupe_returns_open_alert_inside_window(
    db_session, _dedup_host, _dedup_rule
) -> None:
    from app.models import Alert, AlertState, Severity
    from app.services.alert_dedup import find_open_dupe

    key = "b" * 64
    now = datetime.now(UTC)
    a = Alert(
        host_id=_dedup_host.id,
        rule_id=_dedup_rule.id,
        severity=Severity.MEDIUM,
        state=AlertState.NEW,
        summary="x",
        dedup_key=key,
        last_occurred_at=now - timedelta(seconds=30),
    )
    db_session.add(a)
    await db_session.flush()

    found = await find_open_dupe(db_session, dedup_key=key, window_seconds=300, now=now)
    assert found is not None
    assert found.id == a.id


@pytest.mark.asyncio
async def test_find_open_dupe_skips_alert_outside_window(
    db_session, _dedup_host, _dedup_rule
) -> None:
    from app.models import Alert, AlertState, Severity
    from app.services.alert_dedup import find_open_dupe

    key = "c" * 64
    now = datetime.now(UTC)
    old = Alert(
        host_id=_dedup_host.id,
        rule_id=_dedup_rule.id,
        severity=Severity.MEDIUM,
        state=AlertState.NEW,
        summary="x",
        dedup_key=key,
        # 10 min ago, with a 5-min window.
        last_occurred_at=now - timedelta(minutes=10),
    )
    db_session.add(old)
    await db_session.flush()

    found = await find_open_dupe(db_session, dedup_key=key, window_seconds=300, now=now)
    assert found is None


@pytest.mark.asyncio
async def test_find_open_dupe_skips_closed_alerts(db_session, _dedup_host, _dedup_rule) -> None:
    """A false_positive / true_positive disposition makes the alert
    invisible to dedup — a fresh recurrence after triage must fire
    a new row so analysts notice."""
    from app.models import Alert, AlertState, Severity
    from app.services.alert_dedup import find_open_dupe

    key = "d" * 64
    now = datetime.now(UTC)
    for closed in (AlertState.FALSE_POSITIVE, AlertState.TRUE_POSITIVE):
        a = Alert(
            host_id=_dedup_host.id,
            rule_id=_dedup_rule.id,
            severity=Severity.MEDIUM,
            state=closed,
            summary=f"closed-{closed.value}",
            dedup_key=key,
            last_occurred_at=now - timedelta(seconds=15),
        )
        db_session.add(a)
    await db_session.flush()

    found = await find_open_dupe(db_session, dedup_key=key, window_seconds=300, now=now)
    assert found is None


@pytest.mark.asyncio
async def test_find_open_dupe_prefers_most_recent_occurrence(
    db_session, _dedup_host, _dedup_rule
) -> None:
    """If two open alerts share a key (shouldn't happen in steady
    state but can during catch-up), the producer collapses onto the
    newest one."""
    from app.models import Alert, AlertState, Severity
    from app.services.alert_dedup import find_open_dupe

    key = "e" * 64
    now = datetime.now(UTC)
    older = Alert(
        host_id=_dedup_host.id,
        rule_id=_dedup_rule.id,
        severity=Severity.MEDIUM,
        state=AlertState.NEW,
        summary="older",
        dedup_key=key,
        last_occurred_at=now - timedelta(seconds=120),
    )
    newer = Alert(
        host_id=_dedup_host.id,
        rule_id=_dedup_rule.id,
        severity=Severity.MEDIUM,
        state=AlertState.INVESTIGATING,
        summary="newer",
        dedup_key=key,
        last_occurred_at=now - timedelta(seconds=30),
    )
    db_session.add_all([older, newer])
    await db_session.flush()

    found = await find_open_dupe(db_session, dedup_key=key, window_seconds=300, now=now)
    assert found is not None
    assert found.id == newer.id


@pytest.mark.asyncio
async def test_bump_occurrence_increments_and_refreshes(
    db_session, _dedup_host, _dedup_rule
) -> None:
    from app.models import Alert, AlertState, Severity
    from app.services.alert_dedup import bump_occurrence

    start = datetime.now(UTC) - timedelta(seconds=60)
    a = Alert(
        host_id=_dedup_host.id,
        rule_id=_dedup_rule.id,
        severity=Severity.MEDIUM,
        state=AlertState.NEW,
        summary="x",
        dedup_key="f" * 64,
        last_occurred_at=start,
    )
    db_session.add(a)
    await db_session.flush()

    later = start + timedelta(seconds=30)
    bump_occurrence(a, now=later)
    await db_session.flush()
    assert a.occurrence_count == 2
    assert a.last_occurred_at == later

    # Multiple bumps stack.
    later2 = later + timedelta(seconds=10)
    bump_occurrence(a, now=later2)
    await db_session.flush()
    assert a.occurrence_count == 3
    assert a.last_occurred_at == later2


# ---------------------------------------------------------------------------
# IOC detector emit_alerts integration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_emit_alerts_first_match_inserts_with_dedup_key(
    db_session, _dedup_host, _dedup_rule
) -> None:
    """First detonation: emit_alerts must insert a row, set dedup_key,
    set occurrence_count=1, and report (id, created=True)."""
    from sqlalchemy import select

    from app.models import Alert, RuleAction, Severity
    from app.services.alert_dedup import dedup_key_for
    from app.services.detector import Match, emit_alerts

    ecs = {"process": {"executable": "/usr/bin/curl"}}
    matches = [
        Match(
            rule_id=_dedup_rule.id,
            rule_name=_dedup_rule.name,
            severity=Severity.MEDIUM,
            action=RuleAction.ALERT,
            summary="match-1",
            matched_field="process.executable",
            matched_value="/usr/bin/curl",
        )
    ]
    results = await emit_alerts(db_session, host_id=_dedup_host.id, matches=matches, ecs=ecs)
    assert len(results) == 1
    alert_id, created = results[0]
    assert created is True

    rows = (await db_session.execute(select(Alert).where(Alert.id == alert_id))).scalars().all()
    assert len(rows) == 1
    a = rows[0]
    assert a.dedup_key == dedup_key_for(_dedup_rule.id, _dedup_host.id, ecs)
    assert a.occurrence_count == 1


@pytest.mark.asyncio
async def test_emit_alerts_second_match_bumps_existing(
    db_session, _dedup_host, _dedup_rule
) -> None:
    """Re-detonation inside the window: emit_alerts must bump the
    existing row, not insert a second one."""
    from sqlalchemy import select

    from app.models import Alert, RuleAction, Severity
    from app.services.detector import Match, emit_alerts

    ecs = {"process": {"executable": "/usr/bin/curl"}}
    matches = [
        Match(
            rule_id=_dedup_rule.id,
            rule_name=_dedup_rule.name,
            severity=Severity.MEDIUM,
            action=RuleAction.ALERT,
            summary="match",
            matched_field="process.executable",
            matched_value="/usr/bin/curl",
        )
    ]
    r1 = await emit_alerts(db_session, host_id=_dedup_host.id, matches=matches, ecs=ecs)
    r2 = await emit_alerts(db_session, host_id=_dedup_host.id, matches=matches, ecs=ecs)

    assert r1[0][0] == r2[0][0]  # same alert id
    assert r1[0][1] is True  # first was created
    assert r2[0][1] is False  # second was a bump

    rows = (
        (await db_session.execute(select(Alert).where(Alert.host_id == _dedup_host.id)))
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].occurrence_count == 2


@pytest.mark.asyncio
async def test_emit_alerts_different_signal_creates_separate_row(
    db_session, _dedup_host, _dedup_rule
) -> None:
    """Two different executables hit the same rule — they must produce
    two distinct alert rows."""
    from sqlalchemy import select

    from app.models import Alert, RuleAction, Severity
    from app.services.detector import Match, emit_alerts

    m = Match(
        rule_id=_dedup_rule.id,
        rule_name=_dedup_rule.name,
        severity=Severity.MEDIUM,
        action=RuleAction.ALERT,
        summary="match",
        matched_field="process.executable",
        matched_value="/x",
    )
    await emit_alerts(
        db_session,
        host_id=_dedup_host.id,
        matches=[m],
        ecs={"process": {"executable": "/usr/bin/curl"}},
    )
    await emit_alerts(
        db_session,
        host_id=_dedup_host.id,
        matches=[m],
        ecs={"process": {"executable": "/usr/bin/wget"}},
    )

    rows = (
        (await db_session.execute(select(Alert).where(Alert.host_id == _dedup_host.id)))
        .scalars()
        .all()
    )
    assert len(rows) == 2
    assert {r.occurrence_count for r in rows} == {1}


@pytest.mark.asyncio
async def test_emit_alerts_after_window_creates_new_row(
    db_session, _dedup_host, _dedup_rule, monkeypatch
) -> None:
    """An alert older than the window must NOT be coalesced; a fresh
    detonation gets its own row even with an identical key."""
    from sqlalchemy import select

    from app.models import Alert, AlertState, RuleAction, Severity
    from app.services.alert_dedup import dedup_key_for
    from app.services.detector import Match, emit_alerts

    ecs = {"process": {"executable": "/usr/bin/curl"}}
    key = dedup_key_for(_dedup_rule.id, _dedup_host.id, ecs)
    stale = Alert(
        host_id=_dedup_host.id,
        rule_id=_dedup_rule.id,
        severity=Severity.MEDIUM,
        state=AlertState.NEW,
        summary="stale",
        dedup_key=key,
        last_occurred_at=datetime.now(UTC) - timedelta(minutes=10),
    )
    db_session.add(stale)
    await db_session.flush()

    matches = [
        Match(
            rule_id=_dedup_rule.id,
            rule_name=_dedup_rule.name,
            severity=Severity.MEDIUM,
            action=RuleAction.ALERT,
            summary="fresh",
            matched_field="process.executable",
            matched_value="/usr/bin/curl",
        )
    ]
    results = await emit_alerts(db_session, host_id=_dedup_host.id, matches=matches, ecs=ecs)
    assert results[0][1] is True  # created, not deduped

    rows = (
        (await db_session.execute(select(Alert).where(Alert.host_id == _dedup_host.id)))
        .scalars()
        .all()
    )
    assert len(rows) == 2


@pytest.mark.asyncio
async def test_emit_alerts_skips_command_queue_on_dedup(
    db_session, _dedup_host, _dedup_rule
) -> None:
    """A bump must NOT requeue the response action: the original
    command from the first detonation is already pending or completed."""
    from sqlalchemy import select

    from app.models import Command, RuleAction, Severity
    from app.services.detector import Match, emit_alerts

    matches = [
        Match(
            rule_id=_dedup_rule.id,
            rule_name=_dedup_rule.name,
            severity=Severity.MEDIUM,
            action=RuleAction.BLOCK,
            summary="match",
            matched_field="process.executable",
            matched_value="/usr/bin/curl",
        )
    ]
    ecs = {"process": {"executable": "/usr/bin/curl"}}
    await emit_alerts(db_session, host_id=_dedup_host.id, matches=matches, ecs=ecs)
    cmds_before = (
        (await db_session.execute(select(Command).where(Command.host_id == _dedup_host.id)))
        .scalars()
        .all()
    )

    # Second call should bump, not insert a second command.
    await emit_alerts(db_session, host_id=_dedup_host.id, matches=matches, ecs=ecs)
    cmds_after = (
        (await db_session.execute(select(Command).where(Command.host_id == _dedup_host.id)))
        .scalars()
        .all()
    )
    assert len(cmds_after) == len(cmds_before)


# ---------------------------------------------------------------------------
# Schema surface check — AlertOut carries the new fields.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_alert_out_surfaces_dedup_fields(db_session, _dedup_host, _dedup_rule) -> None:
    from app.models import Alert, AlertState, Severity
    from app.schemas.alert import AlertOut

    a = Alert(
        host_id=_dedup_host.id,
        rule_id=_dedup_rule.id,
        severity=Severity.MEDIUM,
        state=AlertState.NEW,
        summary="x",
        dedup_key="g" * 64,
        occurrence_count=7,
        last_occurred_at=datetime.now(UTC),
    )
    db_session.add(a)
    await db_session.flush()
    out = AlertOut.model_validate(a)
    assert out.occurrence_count == 7
    assert out.last_occurred_at == a.last_occurred_at
