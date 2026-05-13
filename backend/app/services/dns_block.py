"""DNS block / sinkhole resync helper (Phase 2 #2.12).

Whenever the DNS block list changes (single create, single delete, or
a bulk import), `queue_resync_commands` walks every host eligible to
receive an update and queues one `DNS_BLOCK_SYNC` command per host.
The command payload carries the *full* effective set for that host
(globals + every group the host belongs to); the agent's job is to
mirror it into the kernel map atomically.

Why whole-list rather than incremental:

  * The map is small (≤4096 entries) and resync is cheap.
  * Whole-list gives the agent a clear correctness invariant —
    "after this command, kernel == manager view" — without per-entry
    add/remove bookkeeping that could drift on retry.
  * Multiple commands for the same host coalesce naturally at the
    agent's dispatch site: the last one wins.
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
    DnsBlockAction,
    DnsBlockEntry,
    Host,
    HostStatus,
    host_in_group,
)


async def effective_set_for_host_groups(
    db: AsyncSession, host_group_ids: Sequence[UUID]
) -> tuple[list[str], list[str]]:
    """Return `(block_domains, sinkhole_domains)` for the union of
    globals (host_group_id IS NULL) and the supplied group ids.

    The two lists are sorted + de-duplicated so the agent receives a
    deterministic payload; that makes the command notify-pipeline's
    coalescing cheap and the e2e tests easy to compare against.
    """
    stmt = select(DnsBlockEntry.domain, DnsBlockEntry.action).where(
        (DnsBlockEntry.host_group_id.is_(None))
        | (DnsBlockEntry.host_group_id.in_(list(host_group_ids)))
    )
    rows = (await db.execute(stmt)).all()
    block: set[str] = set()
    sinkhole: set[str] = set()
    for domain, action in rows:
        if action == DnsBlockAction.SINKHOLE.value:
            sinkhole.add(domain)
        else:
            block.add(domain)
    return sorted(block), sorted(sinkhole)


async def _hosts_in_scope(
    db: AsyncSession, host_group_id: UUID | None
) -> list[tuple[UUID, list[UUID]]]:
    """List the (host_id, [group_id, ...]) for hosts that need a
    resync after an entry in `host_group_id` (None = global) changed.

    For a global edit every non-decommissioned host needs the resync;
    for a group-scoped edit only members of that group do.
    """
    if host_group_id is None:
        host_stmt = select(Host.id).where(Host.status != HostStatus.DECOMMISSIONED)
    else:
        host_stmt = (
            select(Host.id)
            .join(host_in_group, host_in_group.c.host_id == Host.id)
            .where(
                host_in_group.c.host_group_id == host_group_id,
                Host.status != HostStatus.DECOMMISSIONED,
            )
        )
    host_ids = [r for (r,) in (await db.execute(host_stmt)).all()]
    if not host_ids:
        return []

    # Pull each host's group memberships in one round-trip.
    group_stmt = select(host_in_group.c.host_id, host_in_group.c.host_group_id).where(
        host_in_group.c.host_id.in_(host_ids)
    )
    by_host: dict[UUID, list[UUID]] = {h: [] for h in host_ids}
    for h, g in (await db.execute(group_stmt)).all():
        by_host[h].append(g)
    return [(h, by_host[h]) for h in host_ids]


async def queue_resync_commands(
    db: AsyncSession,
    *,
    host_group_id: UUID | None,
    issued_by_user_id: UUID | None,
) -> int:
    """Queue a `DNS_BLOCK_SYNC` command for every host affected by an
    edit to `host_group_id` (None = global edit). Returns the number
    of commands queued.

    Callers are responsible for the actual audit row — this helper
    intentionally stays focused on the dispatch fan-out so it can be
    reused from create, delete, and bulk-import endpoints.
    """
    scope = await _hosts_in_scope(db, host_group_id)
    if not scope:
        return 0

    # Precompute the global set once — every host receives the global
    # entries on top of its own group entries.
    queued = 0
    for host_id, group_ids in scope:
        block, sinkhole = await effective_set_for_host_groups(db, group_ids)
        cmd = Command(
            host_id=host_id,
            kind=CommandKind.DNS_BLOCK_SYNC,
            status=CommandStatus.PENDING,
            payload={"block_domains": block, "sinkhole_domains": sinkhole},
            issued_by_user_id=issued_by_user_id,
        )
        db.add(cmd)
        queued += 1
    if queued:
        await db.flush()
    return queued
