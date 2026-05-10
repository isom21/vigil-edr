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
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Command, CommandKind, CommandStatus, RuleAction


def _basename(path: str | None) -> str | None:
    if not path:
        return None
    sep = max(path.rfind("/"), path.rfind("\\"))
    return path[sep + 1 :] if sep >= 0 else path


def _pick_block_pattern(ecs: dict[str, Any]) -> tuple[CommandKind, str] | None:
    """Pick a block target from an ECS event. Process events get the
    executable basename; file events get the file basename. Returns
    the kind + pattern, or None if neither is available."""
    process = ecs.get("process") or {}
    file_ = ecs.get("file") or {}

    proc_name = process.get("name") or _basename(process.get("executable"))
    if proc_name:
        return CommandKind.BLOCK_PROCESS, proc_name

    file_name = file_.get("name") or _basename(file_.get("path"))
    if file_name:
        return CommandKind.BLOCK_FILE, file_name

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
    """
    if rule_action == RuleAction.ALERT:
        return []

    cmds: list[Command] = []

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
    if cmds:
        await db.flush()
    return cmds
