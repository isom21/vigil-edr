"""Honeytoken deployment + hit-recording (Phase 4 #4.5).

Mirrors `services.device_control`: edits to a `honeytoken` row queue
`DEPLOY_HONEYTOKEN` commands per affected host. A single command
carries every enabled token currently in scope for the host — the
agent rebuilds its decoy set on each receipt, so the manager can ship
authoritative state without diffs.

`record_hit` is the inbound path. The gRPC handler calls it whenever a
`HoneytokenHit` ClientMessage arrives. We insert a `honeytoken_hit`
row + an `Alert` row pointing at the synthetic `HONEYTOKEN_HIT_RULE_ID`,
bump the hit counter on the parent token, and return the alert so the
broker/notifier paths can pick it up via the usual stream.
"""

from __future__ import annotations

import base64
import binascii
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    Alert,
    AlertState,
    Command,
    CommandKind,
    CommandStatus,
    Honeytoken,
    HoneytokenHit,
    Host,
    HostStatus,
    Rule,
    RuleAction,
    RuleKind,
    Severity,
    host_in_group,
)
from app.models.synthetic_rules import HONEYTOKEN_HIT_RULE_ID


async def _ensure_honeytoken_rule(db: AsyncSession) -> None:
    """Idempotently create the synthetic Rule that honeytoken-hit
    alerts attach to. Matches the `_ensure_reenrollment_rule` pattern
    in `services.enrollment` so every honeytoken alert in the UI sits
    under the same rule_id."""
    existing = await db.get(Rule, HONEYTOKEN_HIT_RULE_ID)
    if existing is not None:
        return
    rule = Rule(
        id=HONEYTOKEN_HIT_RULE_ID,
        name="Honeytoken touched",
        kind=RuleKind.IOC,
        action=RuleAction.ALERT,
        severity=Severity.CRITICAL,
        enabled=True,
        description=(
            "Synthetic rule — fires when an agent observes a touch on "
            "a deployed honeytoken (fake credentials, fake file, fake "
            "registry key). Decoys are never legitimately accessed, "
            "so any interaction is a high-signal compromise indicator."
        ),
    )
    db.add(rule)
    await db.flush()


def _payload_bytes(token: Honeytoken) -> bytes:
    """Canonical wire-format bytes for the agent. For fake_file the
    operator can either supply `payload_json={"body": "<base64>"}`
    or a free-form dict we JSON-encode. Other kinds pass the dict
    through as JSON.
    """
    if not token.payload_json:
        return b""
    body = token.payload_json.get("body") if isinstance(token.payload_json, dict) else None
    if isinstance(body, str):
        # `body` is base64 of the raw bytes the operator wants written.
        try:
            return base64.b64decode(body, validate=True)
        except (ValueError, binascii.Error):
            pass
    import json

    return json.dumps(token.payload_json, sort_keys=True).encode("utf-8")


def _spec_for(token: Honeytoken) -> dict:
    return {
        "id": str(token.id),
        "kind": token.kind,
        "name": token.name,
        "target_path": token.target_path or "",
        "payload_b64": base64.b64encode(_payload_bytes(token)).decode("ascii"),
    }


async def effective_tokens_for_host(
    db: AsyncSession, tenant_id: UUID, host_group_ids: list[UUID]
) -> list[Honeytoken]:
    """Return enabled honeytokens applicable to a host. Globals
    (`host_group_id IS NULL`) plus any policy targeting one of the
    host's groups. Tenant-scoped — different tenants can't see each
    other's decoys."""
    stmt = (
        select(Honeytoken)
        .where(
            Honeytoken.tenant_id == tenant_id,
            Honeytoken.enabled.is_(True),
            (Honeytoken.host_group_id.is_(None)) | (Honeytoken.host_group_id.in_(host_group_ids)),
        )
        .order_by(Honeytoken.name)
    )
    return list((await db.execute(stmt)).scalars().all())


async def push_to_host(
    db: AsyncSession,
    host: Host,
    *,
    issued_by_user_id: UUID | None = None,
) -> Command | None:
    """Queue one `DEPLOY_HONEYTOKEN` command carrying the full
    in-scope token set for this host. Returns the Command, or None
    when no tokens apply (we still skip queuing in that case — there's
    nothing for the agent to plant, and we don't want to bombard
    every host with empty `specs` lists)."""
    group_stmt = select(host_in_group.c.host_group_id).where(host_in_group.c.host_id == host.id)
    group_ids = [g for (g,) in (await db.execute(group_stmt)).all()]
    tokens = await effective_tokens_for_host(db, host.tenant_id, group_ids)
    if not tokens:
        return None

    cmd = Command(
        tenant_id=host.tenant_id,
        host_id=host.id,
        kind=CommandKind.DEPLOY_HONEYTOKEN,
        status=CommandStatus.PENDING,
        payload={"specs": [_spec_for(t) for t in tokens]},
        issued_by_user_id=issued_by_user_id,
    )
    db.add(cmd)
    await db.flush()
    for token in tokens:
        token.deployed_count = (token.deployed_count or 0) + 1
    return cmd


async def push_to_group(
    db: AsyncSession,
    tenant_id: UUID,
    host_group_id: UUID | None,
    *,
    issued_by_user_id: UUID | None = None,
) -> int:
    """Fan out a `DEPLOY_HONEYTOKEN` per host affected by an edit.
    `host_group_id=None` means a global token changed — every
    non-decommissioned host in the tenant is in scope. Returns the
    number of hosts the agent will deploy on (commands queued).
    """
    if host_group_id is None:
        host_stmt = select(Host).where(
            Host.tenant_id == tenant_id,
            Host.status != HostStatus.DECOMMISSIONED,
        )
    else:
        host_stmt = (
            select(Host)
            .join(host_in_group, host_in_group.c.host_id == Host.id)
            .where(
                host_in_group.c.host_group_id == host_group_id,
                Host.tenant_id == tenant_id,
                Host.status != HostStatus.DECOMMISSIONED,
            )
        )
    hosts = list((await db.execute(host_stmt)).scalars().all())
    queued = 0
    for host in hosts:
        cmd = await push_to_host(db, host, issued_by_user_id=issued_by_user_id)
        if cmd is not None:
            queued += 1
    return queued


async def record_hit(
    db: AsyncSession,
    *,
    honeytoken_id: UUID,
    host_id: UUID,
    process_pid: int | None,
    process_executable: str | None,
    hit_at: datetime | None = None,
) -> HoneytokenHit | None:
    """Persist a hit + raise a critical Alert via the synthetic rule.

    Returns the HoneytokenHit row (with `alert_id` populated), or None
    if either the honeytoken or host has been deleted between the
    agent observing the hit and the manager processing the message.
    Tenant scoping is inherited from the Honeytoken row — the alert /
    hit rows are stamped with that tenant_id regardless of what the
    Host carries (the operator's tenant owns the decoy).
    """
    token = await db.get(Honeytoken, honeytoken_id)
    if token is None:
        return None
    host = await db.get(Host, host_id)
    if host is None:
        return None
    when = hit_at or datetime.now(UTC)

    await _ensure_honeytoken_rule(db)

    alert = Alert(
        tenant_id=token.tenant_id,
        host_id=host.id,
        rule_id=HONEYTOKEN_HIT_RULE_ID,
        severity=Severity.CRITICAL,
        action_taken=RuleAction.ALERT,
        state=AlertState.NEW,
        summary=f"Honeytoken touched: {token.name!r}",
        details={
            "honeytoken_id": str(token.id),
            "honeytoken_name": token.name,
            "honeytoken_kind": token.kind,
            "target_path": token.target_path,
            "process_pid": process_pid,
            "process_executable": process_executable,
            "host_id": str(host.id),
            "hit_at": when.isoformat(),
            "detector": "honeytoken_hit_v1",
        },
    )
    db.add(alert)
    await db.flush()

    hit = HoneytokenHit(
        tenant_id=token.tenant_id,
        honeytoken_id=token.id,
        host_id=host.id,
        hit_at=when,
        process_pid=process_pid,
        process_executable=process_executable,
        alert_id=alert.id,
    )
    db.add(hit)
    token.hit_count = (token.hit_count or 0) + 1
    await db.flush()
    return hit
