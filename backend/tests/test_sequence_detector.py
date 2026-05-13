"""Phase 2 #2.3: sequence / behavioral rules engine.

Covers:
  * YAML parser accepts the canonical example and rejects malformed
    bodies with `SequenceParseError`.
  * Mini expression language: equality, inequality, `~` ilike,
    `in (...)`, `and` / `or` / `not`.
  * `flatten_event` lowers an ECS doc to the flat view the predicate
    language reads from; `classify_event_kind` returns the right
    label for the canonical event shapes.
  * `SequenceEvaluator` advances state and emits a completed match
    for a two-leg sequence; doesn't emit when the second leg arrives
    after the window expires; doesn't emit when the second leg fires
    on a different host.
  * `replay_events` materialises a managed Rule + inserts an Alert
    for a completed sequence; second matching pass folds onto the
    open alert via dedup.
  * The API mounts under `/api/sequence-rules` and the smoke check
    returns 401 unauthenticated.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from sqlalchemy import select


def _test_session_maker(db_session):
    @asynccontextmanager
    async def _maker():
        yield db_session

    return _maker


# ---------- YAML parser ----------


def test_parse_yaml_canonical_example() -> None:
    from app.services.sequence import parse_yaml

    body = """
trigger:
  event_kind: process_started
  where: executable_basename == "rundll32.exe"
followed_by:
  within: 5s
  event_kind: network_connection
  where: dst_port == 443
then:
  emit_alert:
    severity: high
    message: "rundll32 network connect"
"""
    parsed = parse_yaml(body)
    assert parsed.trigger.event_kind == "process_started"
    assert len(parsed.legs) == 1
    assert parsed.legs[0].event_kind == "network_connection"
    assert parsed.legs[0].within_s == 5.0
    assert parsed.emit.severity == "high"
    assert parsed.emit.message == "rundll32 network connect"


def test_parse_yaml_rejects_unknown_event_kind() -> None:
    from app.services.sequence import SequenceParseError, parse_yaml

    body = """
trigger:
  event_kind: not_a_thing
followed_by:
  - within: 1s
    event_kind: process_started
then:
  emit_alert:
    message: "x"
"""
    with pytest.raises(SequenceParseError):
        parse_yaml(body)


def test_parse_yaml_rejects_missing_followed_by() -> None:
    from app.services.sequence import SequenceParseError, parse_yaml

    body = """
trigger:
  event_kind: process_started
then:
  emit_alert:
    message: "x"
"""
    with pytest.raises(SequenceParseError):
        parse_yaml(body)


def test_parse_duration_units() -> None:
    from app.services.sequence import SequenceParseError, parse_duration

    assert parse_duration("5s") == 5.0
    assert parse_duration("200ms") == 0.2
    assert parse_duration("2m") == 120.0
    assert parse_duration("1h") == 3600.0
    assert parse_duration(10) == 10.0
    with pytest.raises(SequenceParseError):
        parse_duration("five hours")


# ---------- expression language ----------


def test_compile_predicate_equality_and_ilike() -> None:
    from app.services.sequence import compile_predicate

    p = compile_predicate('executable_basename == "RUNDLL32.EXE"')
    assert p.apply({"executable_basename": "RUNDLL32.EXE"})
    assert not p.apply({"executable_basename": "rundll32.exe"})

    p2 = compile_predicate('command_line ~ "encodedcommand"')
    assert p2.apply({"command_line": "powershell -EncodedCommand AAA"})
    assert not p2.apply({"command_line": "powershell -nop"})


def test_compile_predicate_in_list_and_negation() -> None:
    from app.services.sequence import compile_predicate

    p = compile_predicate('executable_basename in ("a.exe", "b.exe", "c.exe")')
    assert p.apply({"executable_basename": "b.exe"})
    assert not p.apply({"executable_basename": "d.exe"})

    p_neg = compile_predicate('executable_basename not in ("ok.exe", "fine.exe")')
    assert p_neg.apply({"executable_basename": "bad.exe"})
    assert not p_neg.apply({"executable_basename": "ok.exe"})


def test_compile_predicate_and_or_grouping() -> None:
    from app.services.sequence import compile_predicate

    p = compile_predicate(
        'executable_basename == "cmd.exe" and (command_line ~ "/c" or command_line ~ "/k")'
    )
    assert p.apply({"executable_basename": "cmd.exe", "command_line": "cmd.exe /c whoami"})
    assert p.apply({"executable_basename": "cmd.exe", "command_line": "cmd.exe /k pause"})
    assert not p.apply({"executable_basename": "cmd.exe", "command_line": "cmd.exe noflag"})
    assert not p.apply({"executable_basename": "powershell.exe", "command_line": "/c x"})


def test_compile_predicate_missing_field_is_false() -> None:
    """Comparing a field absent from the event must NOT throw; it
    just means the predicate doesn't match this event."""
    from app.services.sequence import compile_predicate

    p = compile_predicate("dst_port == 443")
    assert not p.apply({})  # field not present
    assert p.apply({"dst_port": 443})


def test_compile_predicate_empty_is_always_true() -> None:
    from app.services.sequence import compile_predicate

    p = compile_predicate(None)
    assert p.apply({"anything": "goes"})
    p2 = compile_predicate("   ")
    assert p2.apply({})


# ---------- ECS classification + flatten ----------


def test_classify_event_kind_process_and_network() -> None:
    from app.services.sequence import classify_event_kind

    assert (
        classify_event_kind(
            {
                "event": {"action": "start", "category": ["process"]},
                "process": {"pid": 1, "executable": "C:\\Windows\\System32\\rundll32.exe"},
            }
        )
        == "process_started"
    )
    assert (
        classify_event_kind(
            {
                "event": {"action": "connection_started", "category": ["network"]},
                "network": {"direction": "outbound"},
                "destination": {"ip": "1.2.3.4", "port": 443},
            }
        )
        == "network_connection"
    )


def test_flatten_event_executable_basename() -> None:
    from app.services.sequence import flatten_event

    view = flatten_event(
        {
            "host": {"id": "h1"},
            "event": {"id": "e1", "action": "start", "category": ["process"]},
            "process": {"pid": 1234, "executable": "C:\\Windows\\System32\\rundll32.exe"},
        }
    )
    assert view["executable_basename"] == "rundll32.exe"
    assert view["host_id"] == "h1"
    assert view["pid"] == 1234


# ---------- evaluator ----------


def _proc_event(host: str, exe: str, *, eid: str, pid: int = 1000) -> dict:
    return {
        "host": {"id": host},
        "event": {"id": eid, "action": "start", "category": ["process"]},
        "process": {"pid": pid, "executable": exe},
    }


def _net_event(host: str, port: int, *, eid: str, direction: str = "outbound") -> dict:
    return {
        "host": {"id": host},
        "event": {"id": eid, "action": "connection_started", "category": ["network"]},
        "network": {"direction": direction},
        "destination": {"ip": "1.2.3.4", "port": port},
    }


def test_evaluator_emits_on_complete_sequence() -> None:
    from app.services.sequence import SequenceEvaluator, parse_yaml

    body = """
trigger:
  event_kind: process_started
  where: executable_basename == "rundll32.exe"
followed_by:
  within: 5s
  event_kind: network_connection
  where: dst_port == 443
then:
  emit_alert:
    severity: high
    message: "rundll32 + net"
"""
    parsed = parse_yaml(body)
    ev = SequenceEvaluator()
    ev.register_rule("r1", parsed)
    t = 1000.0
    matches = ev.feed_event(
        _proc_event("h1", "C:/Windows/System32/rundll32.exe", eid="e1"), now_ts=t
    )
    assert matches == []
    matches = ev.feed_event(_net_event("h1", 443, eid="e2"), now_ts=t + 1.0)
    assert len(matches) == 1
    assert matches[0].rule_id == "r1"
    assert matches[0].host_id == "h1"
    assert matches[0].severity == "high"
    assert matches[0].event_ids == ["e1", "e2"]


def test_evaluator_does_not_emit_after_window_expires() -> None:
    from app.services.sequence import SequenceEvaluator, parse_yaml

    body = """
trigger:
  event_kind: process_started
  where: executable_basename == "rundll32.exe"
followed_by:
  within: 5s
  event_kind: network_connection
  where: dst_port == 443
then:
  emit_alert:
    message: "x"
"""
    ev = SequenceEvaluator()
    ev.register_rule("r1", parse_yaml(body))
    t = 1000.0
    ev.feed_event(_proc_event("h1", "C:/Windows/System32/rundll32.exe", eid="e1"), now_ts=t)
    # 10s later — way past the 5s window
    matches = ev.feed_event(_net_event("h1", 443, eid="e2"), now_ts=t + 10.0)
    assert matches == []


def test_evaluator_isolates_per_host() -> None:
    from app.services.sequence import SequenceEvaluator, parse_yaml

    body = """
trigger:
  event_kind: process_started
  where: executable_basename == "rundll32.exe"
followed_by:
  within: 5s
  event_kind: network_connection
  where: dst_port == 443
then:
  emit_alert:
    message: "x"
"""
    ev = SequenceEvaluator()
    ev.register_rule("r1", parse_yaml(body))
    t = 1000.0
    ev.feed_event(_proc_event("hA", "C:/Windows/System32/rundll32.exe", eid="eA"), now_ts=t)
    # Different host's network event must not complete the sequence.
    matches = ev.feed_event(_net_event("hB", 443, eid="eB"), now_ts=t + 1.0)
    assert matches == []


def test_evaluator_does_not_emit_when_only_trigger_matches() -> None:
    from app.services.sequence import SequenceEvaluator, parse_yaml

    body = """
trigger:
  event_kind: process_started
  where: executable_basename == "rundll32.exe"
followed_by:
  within: 5s
  event_kind: network_connection
  where: dst_port == 443
then:
  emit_alert:
    message: "x"
"""
    ev = SequenceEvaluator()
    ev.register_rule("r1", parse_yaml(body))
    t = 1000.0
    matches = ev.feed_event(
        _proc_event("h1", "C:/Windows/System32/rundll32.exe", eid="e1"), now_ts=t
    )
    assert matches == []
    # No second leg fired — evaluator should still have a pending partial,
    # but no emission.
    assert ev.pending_count() == 1
    ev.gc(t + 100.0)
    assert ev.pending_count() == 0


def test_evaluator_three_leg_sequence() -> None:
    """A three-leg sequence advances through both intermediate legs
    before emitting on the final one."""
    from app.services.sequence import SequenceEvaluator, parse_yaml

    body = """
trigger:
  event_kind: process_started
  where: executable_basename == "explorer.exe"
followed_by:
  - within: 10s
    event_kind: process_started
    where: executable_basename == "cmd.exe"
  - within: 10s
    event_kind: process_started
    where: executable_basename == "rundll32.exe"
then:
  emit_alert:
    message: "chain"
"""
    ev = SequenceEvaluator()
    ev.register_rule("r1", parse_yaml(body))
    t = 1000.0
    ev.feed_event(_proc_event("h1", "C:/Windows/explorer.exe", eid="e1"), now_ts=t)
    ev.feed_event(_proc_event("h1", "C:/Windows/cmd.exe", eid="e2"), now_ts=t + 1)
    matches = ev.feed_event(
        _proc_event("h1", "C:/Windows/System32/rundll32.exe", eid="e3"), now_ts=t + 2
    )
    assert len(matches) == 1
    assert matches[0].event_ids == ["e1", "e2", "e3"]


# ---------- end-to-end with DB ----------


@pytest_asyncio.fixture
async def sequence_rule_row(db_session):
    """A single SequenceRule pinned to the canonical rundll32 + net
    example so the e2e test can drive the worker."""
    from app.models import SequenceRule, Severity

    body = """
trigger:
  event_kind: process_started
  where: executable_basename == "rundll32.exe"
followed_by:
  within: 5s
  event_kind: network_connection
  where: dst_port == 443
then:
  emit_alert:
    severity: high
    message: "rundll32 network connect"
"""
    srule = SequenceRule(
        name="rundll32-then-https",
        description="test rule",
        yaml_body=body,
        window_s=5,
        enabled=True,
        severity=Severity.HIGH,
        mitre_techniques=["T1055"],
    )
    db_session.add(srule)
    await db_session.flush()
    return srule


@pytest_asyncio.fixture
async def host_row(db_session):
    """A test host so emitted alerts have a valid host_id FK."""
    import os

    from app.models import Host, OsFamily

    host = Host(
        hostname=f"h-seq-{os.urandom(3).hex()}.test",
        os_family=OsFamily.WINDOWS,
        os_version="10",
    )
    db_session.add(host)
    await db_session.flush()
    return host


@pytest.mark.asyncio
async def test_replay_events_emits_alert(db_session, sequence_rule_row, host_row) -> None:
    """End-to-end: synthetic events through `replay_events` materialise
    a managed Rule + insert one Alert with the correct attribution."""
    from app.models import Alert, Rule
    from app.workers.sequence_detector import replay_events

    host_id = str(host_row.id)
    events = [
        {
            "host": {"id": host_id},
            "event": {"id": "ev-1", "action": "start", "category": ["process"]},
            "process": {"pid": 4321, "executable": "C:\\Windows\\System32\\rundll32.exe"},
        },
        {
            "host": {"id": host_id},
            "event": {"id": "ev-2", "action": "connection_started", "category": ["network"]},
            "network": {"direction": "outbound"},
            "destination": {"ip": "1.2.3.4", "port": 443},
        },
    ]

    emitted = await replay_events(events, session_maker=_test_session_maker(db_session))
    assert emitted == 1

    # The managed Rule was created.
    await db_session.refresh(sequence_rule_row)
    assert sequence_rule_row.managed_rule_id is not None
    rule = await db_session.get(Rule, sequence_rule_row.managed_rule_id)
    assert rule is not None
    assert rule.name == f"sequence:{sequence_rule_row.name}"

    # The alert landed on the right host and rule.
    alerts = (
        (await db_session.execute(select(Alert).where(Alert.rule_id == rule.id))).scalars().all()
    )
    assert len(alerts) == 1
    a = alerts[0]
    assert str(a.host_id) == host_id
    assert a.severity.value == "high"
    assert a.details is not None
    assert a.details.get("engine") == "sequence"
    assert a.details.get("event_ids") == ["ev-1", "ev-2"]
    # MITRE tags copied from the SequenceRule onto the Alert row.
    assert a.mitre_techniques == ["T1055"]
    # hit_count + last_hit_at bumped.
    assert sequence_rule_row.hit_count == 1
    assert sequence_rule_row.last_hit_at is not None


@pytest.mark.asyncio
async def test_replay_events_deduplicates_repeat_match(
    db_session, sequence_rule_row, host_row
) -> None:
    """A second matching pass within the dedup window folds onto the
    existing alert via `bump_occurrence` rather than inserting a new
    row."""
    from app.models import Alert
    from app.workers.sequence_detector import replay_events

    host_id = str(host_row.id)
    events = [
        {
            "host": {"id": host_id},
            "event": {"id": "ev-a1", "action": "start", "category": ["process"]},
            "process": {"pid": 4321, "executable": "C:\\Windows\\System32\\rundll32.exe"},
        },
        {
            "host": {"id": host_id},
            "event": {"id": "ev-a2", "action": "connection_started", "category": ["network"]},
            "network": {"direction": "outbound"},
            "destination": {"ip": "1.2.3.4", "port": 443},
        },
    ]
    await replay_events(events, session_maker=_test_session_maker(db_session))
    # Second pass — same canonical event signal (process.executable
    # identical), so dedup folds onto the existing open alert.
    events2 = [
        {
            "host": {"id": host_id},
            "event": {"id": "ev-b1", "action": "start", "category": ["process"]},
            "process": {"pid": 7777, "executable": "C:\\Windows\\System32\\rundll32.exe"},
        },
        {
            "host": {"id": host_id},
            "event": {"id": "ev-b2", "action": "connection_started", "category": ["network"]},
            "network": {"direction": "outbound"},
            "destination": {"ip": "1.2.3.4", "port": 443},
        },
    ]
    emitted2 = await replay_events(events2, session_maker=_test_session_maker(db_session))
    # `replay_events` returns the number of newly-inserted alerts; a
    # dedup-bumped match returns 0.
    assert emitted2 == 0
    await db_session.refresh(sequence_rule_row)
    alerts = (
        (
            await db_session.execute(
                select(Alert).where(Alert.rule_id == sequence_rule_row.managed_rule_id)
            )
        )
        .scalars()
        .all()
    )
    assert len(alerts) == 1
    # occurrence_count is now 2 (the original insert is 1, the dedup
    # bump adds 1).
    assert alerts[0].occurrence_count == 2


@pytest.mark.asyncio
async def test_replay_events_skips_disabled_rule(db_session, sequence_rule_row, host_row) -> None:
    """A disabled rule must not fire even if its sequence completes."""
    from app.models import Alert
    from app.workers.sequence_detector import replay_events

    sequence_rule_row.enabled = False
    await db_session.flush()

    host_id = str(host_row.id)
    events = [
        {
            "host": {"id": host_id},
            "event": {"id": "x1", "action": "start", "category": ["process"]},
            "process": {"pid": 1, "executable": "C:\\Windows\\System32\\rundll32.exe"},
        },
        {
            "host": {"id": host_id},
            "event": {"id": "x2", "action": "connection_started", "category": ["network"]},
            "network": {"direction": "outbound"},
            "destination": {"ip": "1.2.3.4", "port": 443},
        },
    ]
    emitted = await replay_events(events, session_maker=_test_session_maker(db_session))
    assert emitted == 0
    # No managed rule was created either.
    await db_session.refresh(sequence_rule_row)
    assert sequence_rule_row.managed_rule_id is None
    # And no alerts inserted under any rule that could be ours.
    alerts = (await db_session.execute(select(Alert))).scalars().all()
    assert all(a.rule_id is None or a.summary != "rundll32 network connect" for a in alerts)


# ---------- API smoke ----------


@pytest.mark.asyncio
async def test_api_list_requires_auth(http_client) -> None:
    resp = await http_client.get("/api/sequence-rules")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_api_create_and_list_round_trip(http_client, admin_headers, db_session) -> None:
    from app.models import SequenceRule

    body = """
trigger:
  event_kind: process_started
  where: executable_basename == "rundll32.exe"
followed_by:
  within: 5s
  event_kind: network_connection
  where: dst_port == 443
then:
  emit_alert:
    severity: high
    message: "rundll32 net"
"""
    payload = {
        "name": "api-roundtrip-sequence",
        "description": "via API",
        "yaml_body": body,
        "window_s": 5,
        "enabled": True,
        "severity": "high",
        "mitre_techniques": ["T1055"],
    }
    resp = await http_client.post("/api/sequence-rules", json=payload, headers=admin_headers)
    assert resp.status_code == 201, resp.text
    created = resp.json()
    assert created["name"] == payload["name"]
    assert created["window_s"] == 5
    assert created["mitre_techniques"] == ["T1055"]
    sid = created["id"]

    # Round-trips through DB
    row = await db_session.get(SequenceRule, sid)
    assert row is not None
    assert row.yaml_body == body

    resp_list = await http_client.get("/api/sequence-rules", headers=admin_headers)
    assert resp_list.status_code == 200
    assert resp_list.json()["total"] >= 1


@pytest.mark.asyncio
async def test_api_create_rejects_bad_yaml(http_client, admin_headers) -> None:
    payload = {
        "name": "broken-rule",
        "yaml_body": (
            "trigger:\n  event_kind: nope\n"
            "followed_by:\n  - event_kind: any\n"
            "then:\n  emit_alert:\n    message: 'x'\n"
        ),
        "window_s": 5,
        "enabled": True,
        "severity": "medium",
    }
    resp = await http_client.post("/api/sequence-rules", json=payload, headers=admin_headers)
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_api_write_forbidden_for_analyst(http_client, analyst_headers) -> None:
    payload = {
        "name": "analyst-cannot-create",
        "yaml_body": (
            "trigger:\n  event_kind: process_started\n"
            "followed_by:\n  - within: 1s\n    event_kind: network_connection\n"
            "then:\n  emit_alert:\n    message: 'x'\n"
        ),
        "window_s": 5,
        "enabled": True,
        "severity": "medium",
    }
    resp = await http_client.post("/api/sequence-rules", json=payload, headers=analyst_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_api_analyst_can_read(http_client, analyst_headers, admin_headers) -> None:
    body = (
        "trigger:\n  event_kind: process_started\n"
        "followed_by:\n  - within: 1s\n    event_kind: network_connection\n"
        "then:\n  emit_alert:\n    message: 'x'\n"
    )
    create_payload = {
        "name": "analyst-can-read",
        "yaml_body": body,
        "window_s": 5,
        "enabled": True,
        "severity": "medium",
    }
    resp = await http_client.post("/api/sequence-rules", json=create_payload, headers=admin_headers)
    assert resp.status_code == 201, resp.text
    sid = resp.json()["id"]
    # Analyst GET works
    resp_get = await http_client.get(f"/api/sequence-rules/{sid}", headers=analyst_headers)
    assert resp_get.status_code == 200


# ---------- env opt-out ----------


def test_env_opt_out_keeps_loop_quiet(monkeypatch) -> None:
    """`VIGIL_SEQUENCE_DETECTOR_ENABLED=0` short-circuits run_forever."""
    import asyncio

    from app.workers import sequence_detector

    monkeypatch.setenv("VIGIL_SEQUENCE_DETECTOR_ENABLED", "0")
    # `run_forever` must return cleanly without spinning anything up.
    asyncio.run(sequence_detector.run_forever())


# ---------- sample rule pack ----------


def test_sample_rules_compile() -> None:
    """Every YAML in `backend/sequence_rules/` must parse cleanly so
    a typo in the pack is caught before it lands."""
    from pathlib import Path

    from app.services.sequence import parse_yaml

    root = Path(__file__).resolve().parents[1] / "sequence_rules"
    files = list(root.glob("*.yml"))
    assert len(files) >= 6, f"expected at least 6 sample rules, found {len(files)}"
    for path in files:
        text = path.read_text()
        # Strip the schema's outer `name:` / `description:` / `window_s:`
        # / `severity:` / `mitre_techniques:` — the YAML body fed to the
        # evaluator is just the detection part. Our sample files
        # include the operator-facing wrapper for clarity; the parser
        # itself accepts the wrapper untouched because it ignores
        # unknown top-level keys.
        parsed = parse_yaml(text, default_window_s=60)
        assert parsed.trigger is not None
        assert len(parsed.legs) >= 1


# ---------- worker dispatch under managed Rule ----------


@pytest.mark.asyncio
async def test_ensure_managed_rule_kind_sigma(db_session, sequence_rule_row) -> None:
    """`_ensure_managed_rule` materialises a kind=SIGMA Rule mirroring
    the intel-feed pattern, so existing alert UI / rule lookup keep
    working without a new RuleKind value."""
    from app.models import RuleKind
    from app.workers.sequence_detector import _ensure_managed_rule

    rule = await _ensure_managed_rule(db_session, sequence_rule_row)
    assert rule.kind is RuleKind.SIGMA
    assert rule.name == f"sequence:{sequence_rule_row.name}"
    # Calling it again returns the same rule (cached lookup).
    rule2 = await _ensure_managed_rule(db_session, sequence_rule_row)
    assert rule.id == rule2.id


@pytest.mark.asyncio
async def test_ts_now_marker_present(db_session, sequence_rule_row, host_row) -> None:
    """Sanity probe so a future refactor that drops `last_occurred_at`
    or similar fields on the Alert row gets caught here."""
    from app.models import Alert
    from app.workers.sequence_detector import replay_events

    host_id = str(host_row.id)
    events = [
        {
            "host": {"id": host_id},
            "event": {"id": "tprobe-1", "action": "start", "category": ["process"]},
            "process": {"pid": 9999, "executable": "C:\\rundll32.exe"},
        },
        {
            "host": {"id": host_id},
            "event": {"id": "tprobe-2", "action": "connection_started", "category": ["network"]},
            "network": {"direction": "outbound"},
            "destination": {"ip": "8.8.8.8", "port": 443},
        },
    ]
    await replay_events(events, session_maker=_test_session_maker(db_session))
    alerts = (await db_session.execute(select(Alert))).scalars().all()
    relevant = [a for a in alerts if a.details and a.details.get("engine") == "sequence"]
    assert relevant
    a = relevant[0]
    assert a.last_occurred_at is not None
    assert a.opened_at is not None
    # last_occurred_at should be roughly now.
    delta = (datetime.now(UTC) - a.last_occurred_at).total_seconds()
    assert delta < 60
