"""Device control policy push helper (Phase 3 #3.10).

Whenever a `device_policy` row changes the manager queues one
`DEVICE_CONTROL_SYNC` command per affected host. The command payload
carries the *effective* policy for that host — the union of global
(host_group_id IS NULL) and every group the host belongs to.

Conflict resolution when multiple policies apply to one host:

  * Each kind (usb_block / usb_read_only / usb_allow_only) is treated
    as a separate dimension. The agent maintains one effective policy
    file per kind, so the manager picks the most-recently-updated
    enabled policy per kind and ships it. Disabled policies act as
    tombstones — they generate a sync with `enabled=false` so the
    agent can clear any previously-applied policy.

We push one command per (host, kind) combination so the agent's
dispatch path stays simple (one command → one apply call → one OS
side-effect).
"""

from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    Command,
    CommandKind,
    CommandStatus,
    DevicePolicy,
    Host,
    HostStatus,
    host_in_group,
)


async def effective_policies_for_host(
    db: AsyncSession, host_group_ids: Sequence[UUID]
) -> list[DevicePolicy]:
    """Return the effective DevicePolicy rows for a host belonging to
    the supplied groups. Includes globals (`host_group_id IS NULL`).

    Ordering: enabled policies first, then by `updated_at` descending.
    The caller picks the most-recent enabled policy per kind; disabled
    entries surface as tombstones so the agent can clear stale state.
    """
    stmt = (
        select(DevicePolicy)
        .where(
            (DevicePolicy.host_group_id.is_(None))
            | (DevicePolicy.host_group_id.in_(list(host_group_ids)))
        )
        .order_by(DevicePolicy.enabled.desc(), DevicePolicy.updated_at.desc())
    )
    return list((await db.execute(stmt)).scalars().all())


def _payload_for(policy: DevicePolicy) -> dict:
    return {
        "kind": policy.kind,
        "allowed_vids": list(policy.allowed_vendor_ids or []),
        "allowed_pids": list(policy.allowed_product_ids or []),
        "enabled": bool(policy.enabled),
        # Carrying the policy id back lets the agent log + the operator
        # correlate the resulting CommandResult with the source row
        # without an extra round-trip.
        "policy_id": str(policy.id),
    }


async def push_to_host(
    db: AsyncSession,
    host: Host,
    *,
    issued_by_user_id: UUID | None = None,
) -> list[Command]:
    """Materialise the effective device policy set for `host` and
    queue one `DEVICE_CONTROL_SYNC` command per (kind) the host should
    receive. Returns the queued Command rows.

    Returns the empty list if the host has no applicable policies.
    """
    group_stmt = select(host_in_group.c.host_group_id).where(host_in_group.c.host_id == host.id)
    group_ids = [g for (g,) in (await db.execute(group_stmt)).all()]
    policies = await effective_policies_for_host(db, group_ids)
    if not policies:
        return []

    # Group by kind. The first policy per kind in the sort order is
    # "winning" (enabled-first, then most-recent). If only disabled
    # policies exist for a kind we still ship one so the agent can
    # tear down any previously-applied state.
    seen: set[str] = set()
    queued: list[Command] = []
    for policy in policies:
        if policy.kind in seen:
            continue
        seen.add(policy.kind)
        cmd = Command(
            host_id=host.id,
            kind=CommandKind.DEVICE_CONTROL_SYNC,
            status=CommandStatus.PENDING,
            payload=_payload_for(policy),
            issued_by_user_id=issued_by_user_id,
        )
        db.add(cmd)
        queued.append(cmd)
    if queued:
        await db.flush()
    return queued


async def push_to_group(
    db: AsyncSession,
    host_group_id: UUID | None,
    *,
    issued_by_user_id: UUID | None = None,
) -> int:
    """Fan out a `DEVICE_CONTROL_SYNC` per host affected by an edit to
    `host_group_id`. Returns the number of hosts updated (not the
    number of commands; a single host may receive one command per
    kind).

    `host_group_id=None` means a global policy changed — every
    non-decommissioned host is in scope.
    """
    if host_group_id is None:
        host_stmt = select(Host).where(Host.status != HostStatus.DECOMMISSIONED)
    else:
        host_stmt = (
            select(Host)
            .join(host_in_group, host_in_group.c.host_id == Host.id)
            .where(
                host_in_group.c.host_group_id == host_group_id,
                Host.status != HostStatus.DECOMMISSIONED,
            )
        )
    hosts = list((await db.execute(host_stmt)).scalars().all())
    if not hosts:
        return 0

    updated = 0
    for host in hosts:
        cmds = await push_to_host(db, host, issued_by_user_id=issued_by_user_id)
        if cmds:
            updated += 1
    return updated
