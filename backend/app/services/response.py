"""Auto-trigger response actions when a rule with action=block|quarantine matches.

Called from both the IOC detector and the sigma_realtime worker after
they create an Alert row, before commit. Builds the corresponding
Command row(s) keyed to the host that produced the event.

Action semantics (post-M20):
  * RuleAction.ALERT       — no command queued; the Alert row itself
                             is the response.
  * RuleAction.BLOCK       — kill the running pid (if known) AND add
                             the offending basename to the block list
                             (kernel-side preventive).
  * RuleAction.QUARANTINE  — block + move the file to the agent's
                             quarantine directory.

Phase 2 #2.1 adds an orthogonal auto-action: when a rule has
`auto_memory_scan=True` and the ECS event carries `process.pid`, a
MEMORY_YARA_SCAN job is queued against that pid regardless of the
rule action level. The memory hits land in the Jobs UI as an
artifact rather than firing another alert directly.

Phase 3 #3.5 layers playbooks on top: in addition to the rule-driven
Command(s) above, the function asks the playbook service for any
playbooks whose triggers (rule_id / severity / mitre technique) match
the alert and publishes one Kafka message per match to
`playbook.runs`. The executor worker consumes that topic and runs
the playbook out-of-band so a slow notify step doesn't stall the
alert pipeline. Playbook fires are ADDITIVE — they don't replace
the rule's own action.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    Command,
    CommandKind,
    CommandStatus,
    Job,
    JobKind,
    JobRun,
    JobRunStatus,
    JobScopeKind,
    JobStatus,
    Rule,
    RuleAction,
)


def _basename(path: str | None) -> str | None:
    if not path:
        return None
    sep = max(path.rfind("/"), path.rfind("\\"))
    return path[sep + 1 :] if sep >= 0 else path


def _pick_block_pattern(ecs: dict[str, Any]) -> tuple[CommandKind, str] | None:
    """Pick a block target from an ECS event.

    Prefers the full executable / file path (e.g. ``/usr/local/bin/x``)
    and falls back to ``process.name`` / ``file.name`` only when no path
    is available. The kernel block lists (`process_block`, `file_block`
    in `agent-linux/ebpf/vigil.bpf.c`) and the Windows driver's
    `file_block` REG_MULTI_SZ are keyed by the resolved full path, so
    shipping a basename for a process whose ECS event already has the
    full path silently misses every exec — the kernel compares
    ``"/usr/local/bin/mimikatz.exe"`` (the resolved path it sees) to
    ``"mimikatz.exe"`` (what the manager queued) and the lookup fails.
    The kill-by-pid limb of an auto-block still fires; only the
    preventive future-exec limb breaks. See
    `docs/operator-guide.md#auto-block-fallback` for the basename
    fallback caveat operators need to know about.
    """
    process = ecs.get("process") or {}
    file_ = ecs.get("file") or {}

    proc_path = process.get("executable")
    if isinstance(proc_path, str) and proc_path:
        return CommandKind.BLOCK_PROCESS, proc_path
    proc_basename = process.get("name") or _basename(process.get("executable"))
    if proc_basename:
        return CommandKind.BLOCK_PROCESS, proc_basename

    file_path = file_.get("path")
    if isinstance(file_path, str) and file_path:
        return CommandKind.BLOCK_FILE, file_path
    file_basename = file_.get("name") or _basename(file_.get("path"))
    if file_basename:
        return CommandKind.BLOCK_FILE, file_basename

    return None


async def queue_command_for_match(
    db: AsyncSession,
    *,
    host_id: UUID,
    rule_id: UUID,
    rule_action: RuleAction,
    alert_id: UUID,
    ecs: dict[str, Any],
) -> list[Command]:
    """Translate an alert match into 0+ Command rows. Empty list when
    the action is ALERT-only or the event lacks the fields needed.

    Independently of the action level, if the matched rule has
    `auto_memory_scan=True` and the event carries `process.pid`, this
    also queues a MEMORY_YARA_SCAN Job + JobRun + bridging Command.
    The Job is reported as triggered_by="rule" so the audit story
    looks the same as a sweep_scheduler-fired job.
    """
    cmds: list[Command] = []

    if rule_action != RuleAction.ALERT:
        # Both BLOCK and QUARANTINE first kill any running matching pid,
        # then add the basename to the kernel-side block list.
        pid = (ecs.get("process") or {}).get("pid")
        if isinstance(pid, int) and pid > 0:
            cmds.append(
                Command(
                    host_id=host_id,
                    kind=CommandKind.KILL_PROCESS,
                    status=CommandStatus.PENDING,
                    payload={"pid": int(pid)},
                    triggered_by_alert_id=alert_id,
                    triggered_by_rule_id=rule_id,
                )
            )

        picked = _pick_block_pattern(ecs)
        if picked is not None:
            kind, pattern = picked
            cmds.append(
                Command(
                    host_id=host_id,
                    kind=kind,
                    status=CommandStatus.PENDING,
                    payload={"pattern": pattern},
                    triggered_by_alert_id=alert_id,
                    triggered_by_rule_id=rule_id,
                )
            )

        if rule_action == RuleAction.QUARANTINE:
            file_path = (ecs.get("file") or {}).get("path")
            if isinstance(file_path, str) and file_path:
                cmds.append(
                    Command(
                        host_id=host_id,
                        kind=CommandKind.QUARANTINE_FILE,
                        status=CommandStatus.PENDING,
                        payload={"path": file_path, "delete_original": True},
                        triggered_by_alert_id=alert_id,
                        triggered_by_rule_id=rule_id,
                    )
                )

    for c in cmds:
        db.add(c)

    # Phase 2 #2.1: orthogonal to the action level, fire a memory YARA
    # job if the rule asked for it and we have a pid to target.
    rule = await db.get(Rule, rule_id)
    if rule is not None and rule.auto_memory_scan:
        pid = (ecs.get("process") or {}).get("pid")
        if isinstance(pid, int) and pid > 0:
            mem_cmd = await _queue_memory_yara_job(
                db,
                host_id=host_id,
                rule_id=rule_id,
                alert_id=alert_id,
                pid=int(pid),
            )
            cmds.append(mem_cmd)

    # Phase 3 #3.5: look up matching playbooks and hand them to the
    # executor worker via Kafka. We need the alert's severity + the
    # rule's mitre techniques to match triggers; pull both from the
    # in-session alert row so we don't double-query.
    await _fire_matching_playbooks(db, rule_id=rule_id, alert_id=alert_id)

    if cmds:
        await db.flush()
    return cmds


async def _fire_matching_playbooks(
    db: AsyncSession,
    *,
    rule_id: UUID,
    alert_id: UUID,
) -> None:
    """Match playbooks against the alert and publish one Kafka message
    per match. Errors are logged + swallowed — playbook publication is
    additive automation, never a blocker for the alert pipeline."""
    from app.models import Alert
    from app.services.kafka import publish_playbook_run
    from app.services.playbooks import find_matching_playbooks

    try:
        alert = await db.get(Alert, alert_id)
        if alert is None:
            return
        # mitre_techniques on the alert is the frozen snapshot from
        # fire-time (Phase 1 #1.8) — match against that so future
        # rule edits don't retroactively change which playbooks
        # would have fired.
        playbooks = await find_matching_playbooks(
            db,
            rule_id=rule_id,
            severity=alert.severity,
            mitre_techniques=alert.mitre_techniques,
        )
        for pb in playbooks:
            await publish_playbook_run(pb.id, alert_id)
    except Exception:  # noqa: BLE001
        import structlog

        structlog.get_logger().exception(
            "playbook.match.failed", rule_id=str(rule_id), alert_id=str(alert_id)
        )


async def _queue_memory_yara_job(
    db: AsyncSession,
    *,
    host_id: UUID,
    rule_id: UUID,
    alert_id: UUID,
    pid: int,
) -> Command:
    """Create the Job + JobRun + bridging Command for a Phase 2 #2.1
    memory YARA scan. Returns the Command so the caller can include it
    in the row count for audit + dispatch."""
    parameters = {"pid": pid}
    job = Job(
        kind=JobKind.MEMORY_YARA_SCAN,
        parameters=parameters,
        scope_kind=JobScopeKind.HOST_IDS,
        scope_host_ids=[str(host_id)],
        status=JobStatus.QUEUED,
        summary=f"Auto memory YARA scan · pid {pid}",
        triggered_by_alert_id=alert_id,
        triggered_by="rule",
    )
    db.add(job)
    await db.flush()

    run = JobRun(
        id=uuid4(),
        job_id=job.id,
        host_id=host_id,
        status=JobRunStatus.QUEUED,
    )
    db.add(run)
    await db.flush()

    cmd = Command(
        host_id=host_id,
        kind=CommandKind.RUN_JOB,
        status=CommandStatus.PENDING,
        payload={
            "job_id": str(job.id),
            "run_id": str(run.id),
            "job_kind": JobKind.MEMORY_YARA_SCAN.value,
            "parameters": parameters,
        },
        triggered_by_alert_id=alert_id,
        triggered_by_rule_id=rule_id,
    )
    db.add(cmd)
    await db.flush()
    run.command_id = cmd.id
    job.status = JobStatus.RUNNING
    return cmd
