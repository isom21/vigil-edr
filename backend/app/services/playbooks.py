"""Playbook engine (Phase 3 #3.5).

YAML parser + step executor for response chains. When an alert fires
with a matching playbook, the executor walks the playbook's `steps`
sequentially and records each step's outcome into the run row.

Supported step kinds (the wire vocabulary is fixed — adding a new step
is a new entry in `STEP_KINDS`):

  * `isolate` — `{network_allowlist_ips?: [str]}`. Queues an
    `ISOLATE` Command against the alert's host.
  * `kill` — `{pid_from: "alert"}`. Reads `process.pid` from the
    alert's `details` and queues a `KILL_PROCESS` Command.
  * `quarantine` — `{path_from: "alert"}`. Reads `file.path` from
    the alert's `details` and queues a `QUARANTINE_FILE` Command.
  * `memory_yara` — `{rule_id: "..."}`. Currently advisory — records
    the requested rule_id on the step outcome. The full MEMORY_YARA
    job is fired through the standard rule auto-action path, not via
    the playbook engine, to avoid duplicating Job lifecycle code.
  * `triage_collect` — Queues a TRIAGE_COLLECT Job (delegated to the
    Jobs engine). Best-effort: if the host is offline, the run logs
    `outcome=skipped`.
  * `notify_slack` — `{channel_id}`. Fires a NotificationChannel of
    kind=slack synchronously. Pre-resolves the channel.
  * `notify_pagerduty` — same shape, kind=pagerduty.
  * `notify_email` — same shape, kind=email.
  * `wait_seconds` — `{n: int}`. Sleeps the engine for `n` seconds.
    Bounded by `MAX_WAIT_SECONDS` so a typo can't wedge the worker.
  * `branch_if` — `{condition: "alert.severity == \"critical\""}`.
    Evaluates the condition; on False, skips to the next non-nested
    step (i.e., the immediate sibling, not a nested branch's children).
    The mini-expression language supports equality with string and
    severity literals and `in (...)` for severity sets.

Engine ordering: steps run sequentially within a single run; we don't
parallelise even when steps are independent, because the operator's
intent in a YAML body is usually "do A, then B" not "do A and B
in parallel".

The engine is intentionally *additive*: the rule's own RuleAction
fires through `app.services.response.queue_command_for_match`
independently. Playbooks layer extra response actions on top.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import structlog
import yaml
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    Alert,
    Command,
    CommandKind,
    CommandStatus,
    Job,
    JobKind,
    JobRun,
    JobRunStatus,
    JobScopeKind,
    JobStatus,
    NotificationChannel,
    NotificationChannelKind,
    Playbook,
    PlaybookRun,
    PlaybookRunStatus,
    Severity,
)

log = structlog.get_logger()


# --------- Parsing ---------


class PlaybookParseError(ValueError):
    """Raised when a playbook YAML body can't be parsed. The API
    surface returns this as 422 so the operator sees the line, not a
    500."""


STEP_KINDS: set[str] = {
    "isolate",
    "kill",
    "quarantine",
    "memory_yara",
    "triage_collect",
    "notify_slack",
    "notify_pagerduty",
    "notify_email",
    "wait_seconds",
    "branch_if",
}

# Severity ranking — sourced from `app.services.routing.SEVERITY_ORDER`
# but duplicated here so a future split (e.g., dropping `info` from
# triggers) doesn't have to coordinate two files.
_SEVERITY_RANK: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

MAX_WAIT_SECONDS = 600  # 10 min — anything longer should be a separate playbook trigger.
MAX_STEPS = 64  # Hard cap so a runaway playbook can't burn a worker indefinitely.


@dataclass(frozen=True)
class ParsedStep:
    kind: str
    params: dict[str, Any]

    def as_outcome_stub(self) -> dict[str, Any]:
        return {"kind": self.kind, "params": dict(self.params)}


@dataclass
class ParsedPlaybook:
    """The shape the engine consumes. Triggers are pulled from the
    Playbook row's columns, not from the YAML body — keeps the YAML
    focused on response actions and lets indexes work on triggers."""

    steps: list[ParsedStep] = field(default_factory=list)


def parse_yaml(body: str) -> ParsedPlaybook:
    """Validate + normalise a playbook YAML body.

    The body must be a mapping with one key, `steps`, whose value is a
    list of step objects. Each step is a mapping with exactly one
    top-level key whose name is one of `STEP_KINDS`. The value under
    that key carries the step's params.
    """
    try:
        doc = yaml.safe_load(body)
    except yaml.YAMLError as exc:
        raise PlaybookParseError(f"yaml parse failed: {exc}") from exc
    if not isinstance(doc, dict):
        raise PlaybookParseError("playbook body must be a YAML mapping at the top level")
    steps_raw = doc.get("steps")
    if not isinstance(steps_raw, list) or not steps_raw:
        raise PlaybookParseError("playbook body must have a non-empty 'steps' list")
    if len(steps_raw) > MAX_STEPS:
        raise PlaybookParseError(f"playbook has too many steps (cap={MAX_STEPS})")

    steps: list[ParsedStep] = []
    for idx, raw in enumerate(steps_raw):
        if not isinstance(raw, dict) or len(raw) != 1:
            raise PlaybookParseError(f"step {idx}: must be a single-key mapping (kind: params)")
        kind, params = next(iter(raw.items()))
        if kind not in STEP_KINDS:
            raise PlaybookParseError(
                f"step {idx}: unknown step kind {kind!r}; valid: {sorted(STEP_KINDS)}"
            )
        if params is None:
            params = {}
        if not isinstance(params, dict):
            raise PlaybookParseError(
                f"step {idx} ({kind}): params must be a mapping, got {type(params).__name__}"
            )
        _validate_step_params(idx, kind, params)
        steps.append(ParsedStep(kind=kind, params=params))
    return ParsedPlaybook(steps=steps)


def _validate_step_params(idx: int, kind: str, params: dict[str, Any]) -> None:
    """Per-kind shape check. Errors here become 422 at the API."""
    if kind == "isolate":
        ips = params.get("network_allowlist_ips")
        if ips is not None and not (isinstance(ips, list) and all(isinstance(x, str) for x in ips)):
            raise PlaybookParseError(
                f"step {idx} (isolate): 'network_allowlist_ips' must be a list of strings"
            )
    elif kind == "kill":
        src = params.get("pid_from", "alert")
        if src not in ("alert",):
            raise PlaybookParseError(f"step {idx} (kill): 'pid_from' must be 'alert' (got {src!r})")
    elif kind == "quarantine":
        src = params.get("path_from", "alert")
        if src not in ("alert",):
            raise PlaybookParseError(
                f"step {idx} (quarantine): 'path_from' must be 'alert' (got {src!r})"
            )
    elif kind == "memory_yara":
        rid = params.get("rule_id")
        if rid is not None and not isinstance(rid, str):
            raise PlaybookParseError(f"step {idx} (memory_yara): 'rule_id' must be a string")
    elif kind == "triage_collect":
        # No required params; the host comes from the alert envelope.
        pass
    elif kind in ("notify_slack", "notify_pagerduty", "notify_email"):
        cid = params.get("channel_id")
        if not isinstance(cid, str) or not cid.strip():
            raise PlaybookParseError(
                f"step {idx} ({kind}): 'channel_id' is required and must be a non-empty string"
            )
        try:
            UUID(cid)
        except (TypeError, ValueError) as exc:
            raise PlaybookParseError(f"step {idx} ({kind}): 'channel_id' must be a UUID") from exc
    elif kind == "wait_seconds":
        n = params.get("n")
        if not isinstance(n, int) or n < 0 or n > MAX_WAIT_SECONDS:
            raise PlaybookParseError(
                f"step {idx} (wait_seconds): 'n' must be int 0..{MAX_WAIT_SECONDS}"
            )
    elif kind == "branch_if":
        cond = params.get("condition")
        if not isinstance(cond, str) or not cond.strip():
            raise PlaybookParseError(
                f"step {idx} (branch_if): 'condition' must be a non-empty string"
            )


# --------- Trigger matching ---------


def matches_alert(
    playbook: Playbook,
    *,
    rule_id: UUID,
    severity: Severity,
    mitre_techniques: Iterable[str] | None,
) -> bool:
    """OR-semantics across the three trigger fields. A playbook with
    all NULL triggers is dormant (returns False)."""
    if not playbook.enabled:
        return False
    matched_any = False
    has_any_trigger = False

    if playbook.trigger_rule_id is not None:
        has_any_trigger = True
        if playbook.trigger_rule_id == rule_id:
            matched_any = True

    if playbook.trigger_severity is not None:
        has_any_trigger = True
        # severity floor — same semantics as the routing layer.
        wanted = _SEVERITY_RANK.get(playbook.trigger_severity, -1)
        actual = _SEVERITY_RANK.get(severity.value, -1)
        if wanted >= 0 and actual >= wanted:
            matched_any = True

    if playbook.trigger_mitre_techniques:
        has_any_trigger = True
        alert_techs = set(mitre_techniques or [])
        if alert_techs.intersection(playbook.trigger_mitre_techniques):
            matched_any = True

    return has_any_trigger and matched_any


async def find_matching_playbooks(
    db: AsyncSession,
    *,
    rule_id: UUID,
    severity: Severity,
    mitre_techniques: Iterable[str] | None,
) -> list[Playbook]:
    """Return enabled playbooks whose triggers match this alert.

    Cheap: there's a small population of playbooks (operator-authored,
    not auto-generated), so a full scan is fine. If this ever becomes
    a hot path the trigger columns are individually indexable.
    """
    rows = (await db.execute(select(Playbook).where(Playbook.enabled.is_(True)))).scalars().all()
    mitre_list = list(mitre_techniques or [])
    return [
        p
        for p in rows
        if matches_alert(p, rule_id=rule_id, severity=severity, mitre_techniques=mitre_list)
    ]


# --------- Expression language for branch_if ---------


# Minimal, deliberately-not-Python expression form. Supports:
#   alert.severity == "critical"
#   alert.severity in ("high", "critical")
#   alert.severity != "info"
# Variables: only `alert.severity` for now. Future fields land in
# `_EXPR_VARS_FOR_RUN`.


_EQUALITY_RE = re.compile(
    r'^\s*(alert\.severity)\s*(==|!=)\s*"([a-z]+)"\s*$',
    re.IGNORECASE,
)
_IN_RE = re.compile(
    r"^\s*(alert\.severity)\s+in\s+\(\s*([^)]+)\s*\)\s*$",
    re.IGNORECASE,
)


def _eval_condition(condition: str, *, severity_value: str) -> bool:
    """Evaluate the mini-expression. Unknown variables / shapes raise
    PlaybookParseError so the caller records `outcome=failed` rather
    than silently treating them as False."""
    m = _EQUALITY_RE.match(condition)
    if m is not None:
        op = m.group(2)
        wanted = m.group(3).lower()
        actual = severity_value
        return (actual == wanted) if op == "==" else (actual != wanted)
    m2 = _IN_RE.match(condition)
    if m2 is not None:
        raw = m2.group(2)
        wanted_set = {
            tok.strip().strip('"').strip("'").lower() for tok in raw.split(",") if tok.strip()
        }
        return severity_value in wanted_set
    raise PlaybookParseError(
        f"branch_if: unsupported condition {condition!r}; "
        'use \'alert.severity == "high"\' or \'alert.severity in ("high","critical")\''
    )


# --------- Engine ---------


@dataclass
class AlertContext:
    """The slice of an alert the engine reads."""

    alert_id: UUID
    host_id: UUID | None
    severity: Severity
    details: dict[str, Any] | None
    rule_id: UUID


async def _context_from_alert(db: AsyncSession, alert: Alert) -> AlertContext:
    return AlertContext(
        alert_id=alert.id,
        host_id=alert.host_id,
        severity=alert.severity,
        details=alert.details,
        rule_id=alert.rule_id,
    )


def _pid_from_alert(ctx: AlertContext) -> int | None:
    details = ctx.details or {}
    # Alerts created by the IOC + sigma detectors store the matched ECS
    # in `details`; the detectors normalise to ECS keys.
    ecs_proc = (details.get("ecs") or {}).get("process") or details.get("process") or {}
    pid = ecs_proc.get("pid")
    if isinstance(pid, int) and pid > 0:
        return pid
    # Some detectors stash pid at a top-level shorthand.
    pid2 = details.get("pid")
    if isinstance(pid2, int) and pid2 > 0:
        return pid2
    return None


def _path_from_alert(ctx: AlertContext) -> str | None:
    details = ctx.details or {}
    ecs_file = (details.get("ecs") or {}).get("file") or details.get("file") or {}
    path = ecs_file.get("path")
    if isinstance(path, str) and path:
        return path
    p2 = details.get("path")
    return p2 if isinstance(p2, str) and p2 else None


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


async def _run_isolate(
    db: AsyncSession,
    *,
    ctx: AlertContext,
    params: dict[str, Any],
) -> dict[str, Any]:
    """Queue an ISOLATE Command for the alert's host."""
    if ctx.host_id is None:
        return {"outcome": "skipped", "reason": "alert has no host_id"}
    payload: dict[str, Any] = {}
    ips = params.get("network_allowlist_ips")
    if ips:
        payload["network_allowlist_ips"] = list(ips)
    cmd = Command(
        host_id=ctx.host_id,
        kind=CommandKind.ISOLATE,
        status=CommandStatus.PENDING,
        payload=payload,
        triggered_by_alert_id=ctx.alert_id,
        triggered_by_rule_id=ctx.rule_id,
    )
    db.add(cmd)
    await db.flush()
    return {"outcome": "ok", "command_id": str(cmd.id)}


async def _run_kill(
    db: AsyncSession,
    *,
    ctx: AlertContext,
    params: dict[str, Any],
) -> dict[str, Any]:
    if ctx.host_id is None:
        return {"outcome": "skipped", "reason": "alert has no host_id"}
    pid = _pid_from_alert(ctx)
    if pid is None:
        return {"outcome": "skipped", "reason": "alert.details has no process.pid"}
    cmd = Command(
        host_id=ctx.host_id,
        kind=CommandKind.KILL_PROCESS,
        status=CommandStatus.PENDING,
        payload={"pid": pid},
        triggered_by_alert_id=ctx.alert_id,
        triggered_by_rule_id=ctx.rule_id,
    )
    db.add(cmd)
    await db.flush()
    return {"outcome": "ok", "command_id": str(cmd.id), "pid": pid}


async def _run_quarantine(
    db: AsyncSession,
    *,
    ctx: AlertContext,
    params: dict[str, Any],
) -> dict[str, Any]:
    if ctx.host_id is None:
        return {"outcome": "skipped", "reason": "alert has no host_id"}
    path = _path_from_alert(ctx)
    if path is None:
        return {"outcome": "skipped", "reason": "alert.details has no file.path"}
    cmd = Command(
        host_id=ctx.host_id,
        kind=CommandKind.QUARANTINE_FILE,
        status=CommandStatus.PENDING,
        payload={"path": path, "delete_original": True},
        triggered_by_alert_id=ctx.alert_id,
        triggered_by_rule_id=ctx.rule_id,
    )
    db.add(cmd)
    await db.flush()
    return {"outcome": "ok", "command_id": str(cmd.id), "path": path}


async def _run_memory_yara(
    db: AsyncSession,
    *,
    ctx: AlertContext,
    params: dict[str, Any],
) -> dict[str, Any]:
    """Record the desired YARA rule_id. The actual MEMORY_YARA_SCAN
    Job is queued by `app.services.response` when the rule has
    `auto_memory_scan=True`; the playbook step is a marker so the
    operator sees the intent on the run timeline.

    We could also queue the Job directly here, but doing so risks
    double-firing when both the rule and the playbook ask for memory
    scanning. Treat this step as advisory."""
    rid = params.get("rule_id")
    return {"outcome": "ok", "requested_rule_id": rid}


async def _run_triage_collect(
    db: AsyncSession,
    *,
    ctx: AlertContext,
    params: dict[str, Any],
) -> dict[str, Any]:
    """Queue a TRIAGE_COLLECT Job against the alert's host."""
    if ctx.host_id is None:
        return {"outcome": "skipped", "reason": "alert has no host_id"}
    job = Job(
        kind=JobKind.TRIAGE_COLLECT,
        parameters={},
        scope_kind=JobScopeKind.HOST_IDS,
        scope_host_ids=[str(ctx.host_id)],
        status=JobStatus.QUEUED,
        summary=f"Playbook triage collect · alert {ctx.alert_id}",
        triggered_by_alert_id=ctx.alert_id,
        triggered_by="playbook",
    )
    db.add(job)
    await db.flush()
    run = JobRun(
        job_id=job.id,
        host_id=ctx.host_id,
        status=JobRunStatus.QUEUED,
    )
    db.add(run)
    await db.flush()
    cmd = Command(
        host_id=ctx.host_id,
        kind=CommandKind.RUN_JOB,
        status=CommandStatus.PENDING,
        payload={
            "job_id": str(job.id),
            "run_id": str(run.id),
            "job_kind": JobKind.TRIAGE_COLLECT.value,
            "parameters": {},
        },
        triggered_by_alert_id=ctx.alert_id,
        triggered_by_rule_id=ctx.rule_id,
    )
    db.add(cmd)
    await db.flush()
    run.command_id = cmd.id
    job.status = JobStatus.RUNNING
    return {"outcome": "ok", "job_id": str(job.id)}


async def _run_notify(
    db: AsyncSession,
    *,
    ctx: AlertContext,
    params: dict[str, Any],
    expected_kind: NotificationChannelKind,
) -> dict[str, Any]:
    """Resolve + fire a NotificationChannel.

    Decryption + actual dispatch live in `app.services.routing`. We
    pre-resolve the channel here so a non-existent ID or a wrong-kind
    channel surfaces as a step failure with a useful error, not a
    silent no-op deep in the dispatcher.
    """
    cid_str = params["channel_id"]
    cid = UUID(cid_str)
    ch = await db.get(NotificationChannel, cid)
    if ch is None:
        return {"outcome": "failed", "error": f"notification channel {cid_str} not found"}
    if ch.kind is not expected_kind:
        return {
            "outcome": "failed",
            "error": (
                f"channel {cid_str} is kind={ch.kind.value} but step requires {expected_kind.value}"
            ),
        }
    if not ch.enabled:
        return {"outcome": "skipped", "reason": f"channel {cid_str} is disabled"}
    # Import locally so the playbook engine doesn't pull httpx /
    # smtplib at import time — the tests don't need them.
    from app.services.routing import (
        AlertEnvelope,
        decrypt_config,
        envelope_from_alert,
    )

    # Build the envelope. If the alert row is in our session, we have
    # everything we need without another query; if it isn't, fetch.
    alert = await db.get(Alert, ctx.alert_id)
    if alert is None:
        return {"outcome": "failed", "error": "alert row vanished mid-run"}
    envelope: AlertEnvelope = await envelope_from_alert(db, alert)

    try:
        config = decrypt_config(ch.encrypted_config)
    except Exception as exc:  # noqa: BLE001
        return {"outcome": "failed", "error": f"channel config decrypt failed: {exc}"}

    # Fire. Each sender is async and returns on success; raises
    # ChannelDispatchError on failure. We don't retry inside the
    # playbook engine — retries are the routing worker's job; here
    # we record what happened and move on.
    import httpx

    from app.services.routing import (
        ChannelDispatchError,
        _email_send,
        _pagerduty_post,
        _slack_post,
    )

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            if expected_kind is NotificationChannelKind.SLACK:
                await _slack_post(client, config["webhook_url"], envelope)
            elif expected_kind is NotificationChannelKind.PAGERDUTY:
                await _pagerduty_post(client, config["integration_key"], envelope)
            elif expected_kind is NotificationChannelKind.EMAIL:
                await _email_send(config, envelope)
    except ChannelDispatchError as exc:
        return {"outcome": "failed", "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return {"outcome": "failed", "error": f"{type(exc).__name__}: {exc}"}
    return {"outcome": "ok", "channel_id": cid_str}


async def _run_wait_seconds(
    db: AsyncSession,
    *,
    ctx: AlertContext,
    params: dict[str, Any],
) -> dict[str, Any]:
    n = int(params.get("n", 0))
    n = max(0, min(n, MAX_WAIT_SECONDS))
    await asyncio.sleep(n)
    return {"outcome": "ok", "slept_s": n}


def _eval_branch_if(*, ctx: AlertContext, params: dict[str, Any]) -> dict[str, Any]:
    cond = params["condition"]
    try:
        truthy = _eval_condition(cond, severity_value=ctx.severity.value)
    except PlaybookParseError as exc:
        return {"outcome": "failed", "error": str(exc), "skipped_next": False}
    return {
        "outcome": "ok",
        "condition": cond,
        "truthy": truthy,
        # The driver loop reads `skipped_next` to know whether to skip
        # the immediately-following step. Naming the field this way
        # keeps the timeline UI self-explanatory.
        "skipped_next": not truthy,
    }


_STEP_DISPATCH = {
    "isolate": _run_isolate,
    "kill": _run_kill,
    "quarantine": _run_quarantine,
    "memory_yara": _run_memory_yara,
    "triage_collect": _run_triage_collect,
    "wait_seconds": _run_wait_seconds,
}


async def _run_step(
    db: AsyncSession,
    *,
    ctx: AlertContext,
    step: ParsedStep,
) -> dict[str, Any]:
    started = _now_iso()
    try:
        if step.kind == "notify_slack":
            outcome = await _run_notify(
                db,
                ctx=ctx,
                params=step.params,
                expected_kind=NotificationChannelKind.SLACK,
            )
        elif step.kind == "notify_pagerduty":
            outcome = await _run_notify(
                db,
                ctx=ctx,
                params=step.params,
                expected_kind=NotificationChannelKind.PAGERDUTY,
            )
        elif step.kind == "notify_email":
            outcome = await _run_notify(
                db,
                ctx=ctx,
                params=step.params,
                expected_kind=NotificationChannelKind.EMAIL,
            )
        elif step.kind == "branch_if":
            outcome = _eval_branch_if(ctx=ctx, params=step.params)
        else:
            fn = _STEP_DISPATCH[step.kind]
            outcome = await fn(db, ctx=ctx, params=step.params)
    except Exception as exc:  # noqa: BLE001 — playbook step errors must not crash the engine
        log.exception("playbook.step.failed", kind=step.kind)
        outcome = {"outcome": "failed", "error": f"{type(exc).__name__}: {exc}"}
    finished = _now_iso()
    record = step.as_outcome_stub()
    record["started_at"] = started
    record["finished_at"] = finished
    record.update(outcome)
    return record


# --------- Top-level: run a playbook ---------


async def execute_playbook(
    db: AsyncSession,
    *,
    playbook: Playbook,
    alert_id: UUID,
) -> PlaybookRun:
    """Synchronous-per-step execution of a playbook against an alert.

    Returns the finalised PlaybookRun row. Always flushes so the
    caller's session sees the run + step rows; the caller is
    responsible for committing (the executor worker does this).
    """
    alert = await db.get(Alert, alert_id)
    if alert is None:
        run = PlaybookRun(
            playbook_id=playbook.id,
            alert_id=alert_id,
            status=PlaybookRunStatus.FAILED.value,
            steps_executed_json=[],
            error="alert not found",
            finished_at=datetime.now(UTC),
        )
        db.add(run)
        await db.flush()
        return run

    ctx = await _context_from_alert(db, alert)
    run = PlaybookRun(
        playbook_id=playbook.id,
        alert_id=alert.id,
        status=PlaybookRunStatus.RUNNING.value,
        steps_executed_json=[],
    )
    db.add(run)
    await db.flush()

    try:
        parsed = parse_yaml(playbook.yaml_body)
    except PlaybookParseError as exc:
        run.status = PlaybookRunStatus.FAILED.value
        run.error = str(exc)
        run.finished_at = datetime.now(UTC)
        await db.flush()
        return run

    outcomes: list[dict[str, Any]] = []
    skip_next = False
    any_failed = False
    any_ok = False
    for step in parsed.steps:
        if skip_next:
            outcomes.append(
                {
                    **step.as_outcome_stub(),
                    "outcome": "skipped",
                    "reason": "skipped by preceding branch_if",
                    "started_at": _now_iso(),
                    "finished_at": _now_iso(),
                }
            )
            skip_next = False
            continue
        record = await _run_step(db, ctx=ctx, step=step)
        outcomes.append(record)
        outc = record.get("outcome")
        if outc == "failed":
            any_failed = True
        elif outc == "ok":
            any_ok = True
        if step.kind == "branch_if" and record.get("skipped_next"):
            skip_next = True
        # JSONB on SQLA needs a fresh assignment when the list is
        # mutated in-place — bind a new list each iteration so the
        # `flush` further down picks up the change. Cheap: bounded N.
        run.steps_executed_json = list(outcomes)

    run.finished_at = datetime.now(UTC)
    if any_failed and any_ok:
        run.status = PlaybookRunStatus.PARTIAL.value
    elif any_failed:
        run.status = PlaybookRunStatus.FAILED.value
    else:
        run.status = PlaybookRunStatus.SUCCEEDED.value
    await db.flush()
    return run
