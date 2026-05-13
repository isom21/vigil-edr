"""Phase 3 #3.5 — Playbook / runbook automation.

Covers:
  * YAML parser accepts the supported step kinds and rejects malformed
    bodies with `PlaybookParseError`.
  * `matches_alert` honours OR-semantics across rule_id / severity /
    mitre technique triggers; all-NULL triggers stay dormant.
  * `execute_playbook` walks a multi-step body and records each step's
    outcome into the run row; `branch_if` skips the next step on a
    false condition; `partial` status when some steps fail and others
    succeed.
  * `_fire_matching_playbooks` is invoked when an alert is created via
    `queue_command_for_match` and publishes one Kafka envelope per
    match (publish is mocked because tests don't have a broker).
  * The CRUD API:
      - YAML parse errors return 422
      - non-admin write is 403
      - viewer + analyst can read
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from sqlalchemy import select


def _test_session_maker(db_session):
    @asynccontextmanager
    async def _maker():
        yield db_session

    return _maker


def _host_kwargs() -> dict[str, object]:
    from app.models import HostStatus, OsFamily

    return {
        "hostname": f"h-{os.urandom(3).hex()}",
        "os_family": OsFamily.LINUX,
        "status": HostStatus.ONLINE,
    }


# ---------- YAML parser ----------


def test_parse_yaml_canonical_example() -> None:
    from app.services.playbooks import parse_yaml

    body = """
steps:
  - isolate: {}
  - kill:
      pid_from: alert
  - wait_seconds:
      n: 30
  - branch_if:
      condition: 'alert.severity == "critical"'
  - notify_slack:
      channel_id: 11111111-1111-1111-1111-111111111111
"""
    parsed = parse_yaml(body)
    kinds = [s.kind for s in parsed.steps]
    assert kinds == ["isolate", "kill", "wait_seconds", "branch_if", "notify_slack"]


def test_parse_yaml_rejects_unknown_step() -> None:
    from app.services.playbooks import PlaybookParseError, parse_yaml

    with pytest.raises(PlaybookParseError):
        parse_yaml("steps:\n  - reboot: {}\n")


def test_parse_yaml_rejects_missing_steps() -> None:
    from app.services.playbooks import PlaybookParseError, parse_yaml

    with pytest.raises(PlaybookParseError):
        parse_yaml("name: just a header\n")


def test_parse_yaml_rejects_wait_out_of_range() -> None:
    from app.services.playbooks import PlaybookParseError, parse_yaml

    with pytest.raises(PlaybookParseError):
        parse_yaml("steps:\n  - wait_seconds:\n      n: 99999\n")


def test_parse_yaml_rejects_notify_without_channel() -> None:
    from app.services.playbooks import PlaybookParseError, parse_yaml

    with pytest.raises(PlaybookParseError):
        parse_yaml("steps:\n  - notify_slack: {}\n")


def test_parse_yaml_rejects_notify_with_bad_uuid() -> None:
    from app.services.playbooks import PlaybookParseError, parse_yaml

    with pytest.raises(PlaybookParseError):
        parse_yaml("steps:\n  - notify_slack:\n      channel_id: not-a-uuid\n")


def test_parse_yaml_rejects_malformed_yaml() -> None:
    from app.services.playbooks import PlaybookParseError, parse_yaml

    with pytest.raises(PlaybookParseError):
        parse_yaml("steps:\n  - isolate: [oops\n")  # unterminated


# ---------- Trigger matching ----------


def _make_playbook(**kwargs):
    from app.models import Playbook

    return Playbook(
        name=kwargs.pop("name", f"pb-{os.urandom(3).hex()}"),
        yaml_body=kwargs.pop("yaml_body", "steps:\n  - isolate: {}\n"),
        enabled=kwargs.pop("enabled", True),
        **kwargs,
    )


def test_matches_alert_rule_id_match() -> None:
    from app.models import Severity
    from app.services.playbooks import matches_alert

    rid = uuid4()
    pb = _make_playbook(trigger_rule_id=rid)
    assert matches_alert(pb, rule_id=rid, severity=Severity.LOW, mitre_techniques=None) is True
    assert matches_alert(pb, rule_id=uuid4(), severity=Severity.LOW, mitre_techniques=None) is False


def test_matches_alert_severity_floor() -> None:
    from app.models import Severity
    from app.services.playbooks import matches_alert

    pb = _make_playbook(trigger_severity="high")
    rid = uuid4()
    assert matches_alert(pb, rule_id=rid, severity=Severity.CRITICAL, mitre_techniques=None) is True
    assert matches_alert(pb, rule_id=rid, severity=Severity.HIGH, mitre_techniques=None) is True
    assert matches_alert(pb, rule_id=rid, severity=Severity.MEDIUM, mitre_techniques=None) is False


def test_matches_alert_mitre_intersection() -> None:
    from app.models import Severity
    from app.services.playbooks import matches_alert

    pb = _make_playbook(trigger_mitre_techniques=["T1003.001", "T1486"])
    rid = uuid4()
    assert (
        matches_alert(pb, rule_id=rid, severity=Severity.LOW, mitre_techniques=["T1486", "T9999"])
        is True
    )
    assert (
        matches_alert(pb, rule_id=rid, severity=Severity.LOW, mitre_techniques=["T9999"]) is False
    )


def test_matches_alert_dormant_when_all_triggers_null() -> None:
    from app.models import Severity
    from app.services.playbooks import matches_alert

    pb = _make_playbook()  # no triggers
    assert (
        matches_alert(pb, rule_id=uuid4(), severity=Severity.CRITICAL, mitre_techniques=["T1"])
        is False
    )


def test_matches_alert_skips_disabled() -> None:
    from app.models import Severity
    from app.services.playbooks import matches_alert

    rid = uuid4()
    pb = _make_playbook(trigger_rule_id=rid, enabled=False)
    assert matches_alert(pb, rule_id=rid, severity=Severity.HIGH, mitre_techniques=None) is False


# ---------- Expression language ----------


def test_eval_condition_equality_and_in() -> None:
    from app.services.playbooks import _eval_condition

    assert _eval_condition('alert.severity == "critical"', severity_value="critical") is True
    assert _eval_condition('alert.severity == "critical"', severity_value="high") is False
    assert _eval_condition('alert.severity in ("high", "critical")', severity_value="high") is True
    assert _eval_condition('alert.severity in ("high", "critical")', severity_value="low") is False
    assert _eval_condition('alert.severity != "info"', severity_value="low") is True


def test_eval_condition_rejects_unsupported() -> None:
    from app.services.playbooks import PlaybookParseError, _eval_condition

    with pytest.raises(PlaybookParseError):
        _eval_condition("alert.host_id == 12345", severity_value="high")


# ---------- Engine: end-to-end ----------


@pytest.mark.asyncio
async def test_execute_playbook_isolate_then_notify(db_session) -> None:
    """A multi-step playbook fires an ISOLATE Command and records the
    timeline. The notify step fails because the channel UUID doesn't
    exist; the run lands in `partial`."""
    from app.models import (
        Alert,
        AlertState,
        Command,
        CommandKind,
        Host,
        Playbook,
        PlaybookRunStatus,
        Rule,
        RuleAction,
        RuleKind,
        Severity,
    )
    from app.services.playbooks import execute_playbook

    host = Host(**_host_kwargs())
    rule = Rule(
        kind=RuleKind.YARA,
        name=f"r-{os.urandom(3).hex()}",
        severity=Severity.HIGH,
        action=RuleAction.ALERT,
        body="rule x { condition: true }",
    )
    db_session.add_all([host, rule])
    await db_session.flush()
    alert = Alert(
        host_id=host.id,
        rule_id=rule.id,
        severity=Severity.HIGH,
        state=AlertState.NEW,
        summary="test alert",
        details={"process": {"pid": 1234}},
    )
    db_session.add(alert)
    await db_session.flush()

    pb = Playbook(
        name=f"pb-{os.urandom(3).hex()}",
        yaml_body=(
            "steps:\n"
            "  - isolate: {}\n"
            "  - kill:\n"
            "      pid_from: alert\n"
            "  - notify_slack:\n"
            "      channel_id: 11111111-1111-1111-1111-111111111111\n"
        ),
        enabled=True,
    )
    db_session.add(pb)
    await db_session.flush()

    run = await execute_playbook(db_session, playbook=pb, alert_id=alert.id)
    assert run.status in (
        PlaybookRunStatus.PARTIAL.value,
        PlaybookRunStatus.SUCCEEDED.value,
        PlaybookRunStatus.FAILED.value,
    )
    # We expect partial: isolate + kill succeed (commands queued), notify_slack fails.
    assert run.status == PlaybookRunStatus.PARTIAL.value
    assert run.finished_at is not None
    assert len(run.steps_executed_json) == 3
    kinds = [s["kind"] for s in run.steps_executed_json]
    assert kinds == ["isolate", "kill", "notify_slack"]
    assert run.steps_executed_json[0]["outcome"] == "ok"
    assert run.steps_executed_json[1]["outcome"] == "ok"
    assert run.steps_executed_json[2]["outcome"] == "failed"

    cmds = (
        (await db_session.execute(select(Command).where(Command.triggered_by_alert_id == alert.id)))
        .scalars()
        .all()
    )
    kinds_seen = {c.kind for c in cmds}
    assert CommandKind.ISOLATE in kinds_seen
    assert CommandKind.KILL_PROCESS in kinds_seen


@pytest.mark.asyncio
async def test_execute_playbook_branch_if_skips_next(db_session) -> None:
    """branch_if with a false condition skips the immediately-following
    step. The isolate after the false branch is not executed."""
    from app.models import (
        Alert,
        AlertState,
        Command,
        CommandKind,
        Host,
        Playbook,
        Rule,
        RuleAction,
        RuleKind,
        Severity,
    )
    from app.services.playbooks import execute_playbook

    host = Host(**_host_kwargs())
    rule = Rule(
        kind=RuleKind.YARA,
        name=f"r-{os.urandom(3).hex()}",
        severity=Severity.LOW,
        action=RuleAction.ALERT,
        body="rule x { condition: true }",
    )
    db_session.add_all([host, rule])
    await db_session.flush()
    alert = Alert(
        host_id=host.id,
        rule_id=rule.id,
        severity=Severity.LOW,
        state=AlertState.NEW,
        summary="low sev",
    )
    db_session.add(alert)
    await db_session.flush()

    pb = Playbook(
        name=f"pb-{os.urandom(3).hex()}",
        yaml_body=(
            "steps:\n"
            "  - branch_if:\n"
            "      condition: "
            'alert.severity == "critical"'
            "\n"
            "  - isolate: {}\n"
            "  - wait_seconds:\n"
            "      n: 0\n"
        ),
        enabled=True,
    )
    db_session.add(pb)
    await db_session.flush()

    run = await execute_playbook(db_session, playbook=pb, alert_id=alert.id)
    assert len(run.steps_executed_json) == 3
    # branch_if itself ran and is OK; outcome flagged skipped_next=True.
    assert run.steps_executed_json[0]["kind"] == "branch_if"
    assert run.steps_executed_json[0]["outcome"] == "ok"
    assert run.steps_executed_json[0]["skipped_next"] is True
    # isolate must be marked skipped.
    assert run.steps_executed_json[1]["kind"] == "isolate"
    assert run.steps_executed_json[1]["outcome"] == "skipped"
    # wait_seconds continues normally.
    assert run.steps_executed_json[2]["kind"] == "wait_seconds"
    assert run.steps_executed_json[2]["outcome"] == "ok"

    # No ISOLATE command should have been queued — the branch suppressed it.
    cmds = (
        (
            await db_session.execute(
                select(Command).where(
                    Command.triggered_by_alert_id == alert.id, Command.kind == CommandKind.ISOLATE
                )
            )
        )
        .scalars()
        .all()
    )
    assert cmds == []


@pytest.mark.asyncio
async def test_execute_playbook_quarantine_skips_without_path(db_session) -> None:
    """quarantine step with no file.path in alert.details lands in
    `skipped`, not `failed`."""
    from app.models import (
        Alert,
        AlertState,
        Host,
        Playbook,
        PlaybookRunStatus,
        Rule,
        RuleAction,
        RuleKind,
        Severity,
    )
    from app.services.playbooks import execute_playbook

    host = Host(**_host_kwargs())
    rule = Rule(
        kind=RuleKind.YARA,
        name=f"r-{os.urandom(3).hex()}",
        severity=Severity.MEDIUM,
        action=RuleAction.ALERT,
        body="rule x { condition: true }",
    )
    db_session.add_all([host, rule])
    await db_session.flush()
    alert = Alert(
        host_id=host.id,
        rule_id=rule.id,
        severity=Severity.MEDIUM,
        state=AlertState.NEW,
        summary="no file path",
        details={"process": {"pid": 1}},
    )
    db_session.add(alert)
    await db_session.flush()

    pb = Playbook(
        name=f"pb-{os.urandom(3).hex()}",
        yaml_body="steps:\n  - quarantine:\n      path_from: alert\n",
        enabled=True,
    )
    db_session.add(pb)
    await db_session.flush()

    run = await execute_playbook(db_session, playbook=pb, alert_id=alert.id)
    # No `ok` and no `failed` — just a single `skipped`. Status maps
    # to SUCCEEDED because nothing failed.
    assert run.status == PlaybookRunStatus.SUCCEEDED.value
    assert run.steps_executed_json[0]["outcome"] == "skipped"


# ---------- response.py integration ----------


@pytest.mark.asyncio
async def test_queue_command_for_match_fires_playbook_publish(db_session) -> None:
    """When the rule's MITRE technique matches a playbook trigger,
    `queue_command_for_match` publishes one Kafka envelope. We patch
    `publish_playbook_run` since tests don't have a broker."""
    from app.models import (
        Alert,
        AlertState,
        Host,
        Playbook,
        Rule,
        RuleAction,
        RuleKind,
        Severity,
    )
    from app.services.response import queue_command_for_match

    host = Host(**_host_kwargs())
    rule = Rule(
        kind=RuleKind.SIGMA,
        name=f"r-{os.urandom(3).hex()}",
        severity=Severity.HIGH,
        action=RuleAction.ALERT,
        body="title: t",
        mitre_techniques=["T1003.001"],
    )
    db_session.add_all([host, rule])
    await db_session.flush()
    alert = Alert(
        host_id=host.id,
        rule_id=rule.id,
        severity=Severity.HIGH,
        state=AlertState.NEW,
        summary="lsass dump",
        mitre_techniques=["T1003.001"],
    )
    db_session.add(alert)
    await db_session.flush()

    pb = Playbook(
        name=f"pb-{os.urandom(3).hex()}",
        yaml_body="steps:\n  - isolate: {}\n",
        trigger_mitre_techniques=["T1003.001"],
        enabled=True,
    )
    db_session.add(pb)
    await db_session.flush()

    with patch("app.services.kafka.publish_playbook_run", new_callable=AsyncMock) as mock_pub:
        mock_pub.return_value = True
        await queue_command_for_match(
            db_session,
            host_id=host.id,
            rule_id=rule.id,
            rule_action=RuleAction.ALERT,
            alert_id=alert.id,
            ecs={"process": {"pid": 999}},
        )
    assert mock_pub.await_count == 1
    assert mock_pub.await_args is not None
    args, _ = mock_pub.await_args
    assert args[0] == pb.id
    assert args[1] == alert.id


# ---------- API: 422 on bad YAML, 403 on non-admin write ----------


@pytest.mark.asyncio
async def test_api_create_playbook_invalid_yaml_returns_422(http_client, admin_headers) -> None:
    resp = await http_client.post(
        "/api/playbooks",
        headers=admin_headers,
        json={
            "name": f"bad-{os.urandom(3).hex()}",
            "yaml_body": "steps:\n  - notify_slack: {}\n",  # missing channel_id
        },
    )
    assert resp.status_code == 422, resp.text
    assert "playbook yaml invalid" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_api_create_playbook_non_admin_403(http_client, analyst_headers) -> None:
    resp = await http_client.post(
        "/api/playbooks",
        headers=analyst_headers,
        json={
            "name": f"forbidden-{os.urandom(3).hex()}",
            "yaml_body": "steps:\n  - isolate: {}\n",
        },
    )
    assert resp.status_code == 403, resp.text


@pytest.mark.asyncio
async def test_api_create_then_list_playbook_admin(http_client, admin_headers) -> None:
    name = f"happy-{os.urandom(3).hex()}"
    resp = await http_client.post(
        "/api/playbooks",
        headers=admin_headers,
        json={
            "name": name,
            "yaml_body": "steps:\n  - isolate: {}\n",
            "trigger_severity": "high",
        },
    )
    assert resp.status_code == 201, resp.text
    pb = resp.json()
    assert pb["name"] == name
    assert pb["trigger_severity"] == "high"

    resp_list = await http_client.get("/api/playbooks", headers=admin_headers)
    assert resp_list.status_code == 200
    items = resp_list.json()["items"]
    assert any(item["id"] == pb["id"] for item in items)


@pytest.mark.asyncio
async def test_api_create_playbook_invalid_trigger_severity_422(http_client, admin_headers) -> None:
    """Pydantic Literal validation: trigger_severity must be one of the
    four allowed labels."""
    resp = await http_client.post(
        "/api/playbooks",
        headers=admin_headers,
        json={
            "name": f"bad-sev-{os.urandom(3).hex()}",
            "yaml_body": "steps:\n  - isolate: {}\n",
            "trigger_severity": "info",  # not allowed
        },
    )
    assert resp.status_code == 422


# ---------- Worker handle_message ----------


@pytest.mark.asyncio
async def test_worker_handle_message_creates_run(db_session) -> None:
    """The worker's `handle_message` resolves the playbook + alert and
    executes the run."""
    from app.models import (
        Alert,
        AlertState,
        Host,
        Playbook,
        PlaybookRun,
        Rule,
        RuleAction,
        RuleKind,
        Severity,
    )
    from app.workers.playbook_executor import handle_message

    host = Host(**_host_kwargs())
    rule = Rule(
        kind=RuleKind.YARA,
        name=f"r-{os.urandom(3).hex()}",
        severity=Severity.HIGH,
        action=RuleAction.ALERT,
        body="rule x { condition: true }",
    )
    db_session.add_all([host, rule])
    await db_session.flush()
    alert = Alert(
        host_id=host.id,
        rule_id=rule.id,
        severity=Severity.HIGH,
        state=AlertState.NEW,
        summary="worker test",
    )
    db_session.add(alert)
    await db_session.flush()

    pb = Playbook(
        name=f"pb-{os.urandom(3).hex()}",
        yaml_body="steps:\n  - isolate: {}\n",
        enabled=True,
    )
    db_session.add(pb)
    await db_session.flush()

    ok = await handle_message(
        db_session,
        {"playbook_id": str(pb.id), "alert_id": str(alert.id)},
    )
    assert ok is True
    runs = (
        (await db_session.execute(select(PlaybookRun).where(PlaybookRun.playbook_id == pb.id)))
        .scalars()
        .all()
    )
    assert len(runs) == 1


@pytest.mark.asyncio
async def test_worker_handle_message_ignores_disabled_playbook(db_session) -> None:
    from app.models import Playbook
    from app.workers.playbook_executor import handle_message

    pb = Playbook(
        name=f"pb-{os.urandom(3).hex()}",
        yaml_body="steps:\n  - isolate: {}\n",
        enabled=False,
    )
    db_session.add(pb)
    await db_session.flush()

    ok = await handle_message(
        db_session,
        {"playbook_id": str(pb.id), "alert_id": str(uuid4())},
    )
    assert ok is False
