"""Phase 2 #2.1 — MEMORY_YARA_SCAN job auto-trigger.

Three things to lock down:

1. `JobKind.MEMORY_YARA_SCAN` round-trips through the Postgres
   `job_kind` enum. If the alembic migration didn't add the value to
   the enum, inserting a Job with this kind would raise an InvalidEnumError
   *only* at flush time, which is easy to miss in dev.
2. `queue_command_for_match` queues a Job + JobRun + bridging Command
   when the rule has `auto_memory_scan=True` and the ECS event carries
   a positive `process.pid`. The Job is reported as triggered_by="rule"
   for the audit story.
3. The orthogonality: `auto_memory_scan=False` queues no memory job
   even when a pid is present. Conversely, `auto_memory_scan=True` +
   missing pid is a silent no-op (no exception, just no job).
"""

from __future__ import annotations

import os

import pytest
from sqlalchemy import select


def _host_kwargs() -> dict[str, object]:
    from app.models import HostStatus, OsFamily

    return {
        "hostname": f"h-{os.urandom(3).hex()}",
        "os_family": OsFamily.LINUX,
        "status": HostStatus.ONLINE,
    }


@pytest.mark.asyncio
async def test_memory_yara_scan_enum_round_trips(db_session) -> None:
    """Inserting a Job(kind=MEMORY_YARA_SCAN) and reading it back returns
    the same enum member — proves the migration added the enum value."""
    from app.models import (
        Host,
        Job,
        JobKind,
        JobScopeKind,
        JobStatus,
    )

    host = Host(**_host_kwargs())
    db_session.add(host)
    await db_session.flush()

    job = Job(
        kind=JobKind.MEMORY_YARA_SCAN,
        parameters={"pid": 1234},
        scope_kind=JobScopeKind.HOST_IDS,
        scope_host_ids=[str(host.id)],
        status=JobStatus.QUEUED,
        summary="enum round-trip",
        triggered_by="manual",
    )
    db_session.add(job)
    await db_session.flush()

    stmt = select(Job).where(Job.id == job.id)
    refetched = (await db_session.execute(stmt)).scalar_one()
    assert refetched.kind is JobKind.MEMORY_YARA_SCAN
    assert refetched.parameters == {"pid": 1234}


@pytest.mark.asyncio
async def test_queue_command_for_match_auto_memory_scan_creates_job(db_session) -> None:
    """With auto_memory_scan=True + process.pid present, the helper
    creates a Job(MEMORY_YARA_SCAN), one JobRun, and one bridging
    Command(RUN_JOB) tied back to the alert."""
    from app.models import (
        Alert,
        AlertState,
        CommandKind,
        Host,
        Job,
        JobKind,
        JobRun,
        Rule,
        RuleAction,
        RuleKind,
        Severity,
    )
    from app.services.response import queue_command_for_match

    host = Host(**_host_kwargs())
    rule = Rule(
        kind=RuleKind.YARA,
        name=f"r-{os.urandom(3).hex()}",
        severity=Severity.HIGH,
        action=RuleAction.ALERT,
        body='rule x { strings: $a = "x" condition: $a }',
        auto_memory_scan=True,
    )
    db_session.add_all([host, rule])
    await db_session.flush()
    alert = Alert(
        host_id=host.id,
        rule_id=rule.id,
        severity=Severity.HIGH,
        state=AlertState.NEW,
        summary="auto mem scan trigger",
    )
    db_session.add(alert)
    await db_session.flush()

    cmds = await queue_command_for_match(
        db_session,
        host_id=host.id,
        rule_id=rule.id,
        rule_action=RuleAction.ALERT,
        alert_id=alert.id,
        ecs={"process": {"pid": 4242, "executable": "/usr/bin/evil"}},
    )

    assert len(cmds) == 1, "ALERT-only + auto_memory_scan should only queue the RUN_JOB"
    cmd = cmds[0]
    assert cmd.kind is CommandKind.RUN_JOB
    assert cmd.payload["job_kind"] == JobKind.MEMORY_YARA_SCAN.value
    assert cmd.payload["parameters"] == {"pid": 4242}
    assert cmd.triggered_by_alert_id == alert.id

    jobs = (
        (await db_session.execute(select(Job).where(Job.kind == JobKind.MEMORY_YARA_SCAN)))
        .scalars()
        .all()
    )
    assert len(jobs) == 1
    job = jobs[0]
    assert job.parameters == {"pid": 4242}
    assert job.triggered_by == "rule"
    assert job.triggered_by_alert_id == alert.id
    assert job.scope_host_ids == [str(host.id)]

    runs = (await db_session.execute(select(JobRun).where(JobRun.job_id == job.id))).scalars().all()
    assert len(runs) == 1
    assert runs[0].host_id == host.id
    assert runs[0].command_id == cmd.id


@pytest.mark.asyncio
async def test_queue_command_for_match_skips_when_flag_off(db_session) -> None:
    """auto_memory_scan=False + ALERT action + pid present → no commands."""
    from app.models import (
        Alert,
        AlertState,
        Host,
        Job,
        JobKind,
        Rule,
        RuleAction,
        RuleKind,
        Severity,
    )
    from app.services.response import queue_command_for_match

    host = Host(**_host_kwargs())
    rule = Rule(
        kind=RuleKind.YARA,
        name=f"r-{os.urandom(3).hex()}",
        severity=Severity.HIGH,
        action=RuleAction.ALERT,
        body='rule x { strings: $a = "x" condition: $a }',
        auto_memory_scan=False,
    )
    db_session.add_all([host, rule])
    await db_session.flush()
    alert = Alert(
        host_id=host.id,
        rule_id=rule.id,
        severity=Severity.HIGH,
        state=AlertState.NEW,
        summary="should not memory-scan",
    )
    db_session.add(alert)
    await db_session.flush()

    cmds = await queue_command_for_match(
        db_session,
        host_id=host.id,
        rule_id=rule.id,
        rule_action=RuleAction.ALERT,
        alert_id=alert.id,
        ecs={"process": {"pid": 4242}},
    )
    assert cmds == []
    jobs = (
        (await db_session.execute(select(Job).where(Job.kind == JobKind.MEMORY_YARA_SCAN)))
        .scalars()
        .all()
    )
    assert jobs == []


@pytest.mark.asyncio
async def test_queue_command_for_match_no_pid_skips(db_session) -> None:
    """auto_memory_scan=True but missing pid → still no memory job."""
    from app.models import (
        Alert,
        AlertState,
        Host,
        Job,
        JobKind,
        Rule,
        RuleAction,
        RuleKind,
        Severity,
    )
    from app.services.response import queue_command_for_match

    host = Host(**_host_kwargs())
    rule = Rule(
        kind=RuleKind.YARA,
        name=f"r-{os.urandom(3).hex()}",
        severity=Severity.HIGH,
        action=RuleAction.ALERT,
        body='rule x { strings: $a = "x" condition: $a }',
        auto_memory_scan=True,
    )
    db_session.add_all([host, rule])
    await db_session.flush()
    alert = Alert(
        host_id=host.id,
        rule_id=rule.id,
        severity=Severity.HIGH,
        state=AlertState.NEW,
        summary="missing pid",
    )
    db_session.add(alert)
    await db_session.flush()

    # ECS without process.pid — common for file-only events.
    cmds = await queue_command_for_match(
        db_session,
        host_id=host.id,
        rule_id=rule.id,
        rule_action=RuleAction.ALERT,
        alert_id=alert.id,
        ecs={"file": {"path": "/tmp/x"}},
    )
    assert cmds == []
    jobs = (
        (await db_session.execute(select(Job).where(Job.kind == JobKind.MEMORY_YARA_SCAN)))
        .scalars()
        .all()
    )
    assert jobs == []
