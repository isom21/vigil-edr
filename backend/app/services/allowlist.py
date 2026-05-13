"""Application allowlist service (Phase 2 #2.8).

Two public helpers:

  * :func:`record_observed_hash` — used by the learner worker. Inserts
    a new row when an agent reports a SHA-256 we haven't seen for a
    given group, and bumps last_seen on every subsequent observation.
    Idempotent: re-calling with the same (group, hash) is a no-op
    aside from the last_seen update.
  * :func:`push_allowlist_to_agent` — used by the API write paths.
    Queues an ``allowlist_sync`` :class:`Command` per host in the
    target group; the gRPC dispatcher then translates each row into
    an :class:`AllowlistSyncCmd` on the wire.

The service writes Commands rather than pushing directly on the gRPC
stream because (a) the gRPC server is process-local to the host
stream, while writes can come from any uvicorn worker, and (b) the
existing Command pipeline already handles retry / watchdog / audit
breadcrumbing — there's no need for a parallel mechanism here.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    AllowlistEntry,
    AllowlistMode,
    AllowlistModeRow,
    Command,
    CommandKind,
    Host,
    host_in_group,
)

log = structlog.get_logger()

__all__ = (
    "record_observed_hash",
    "push_allowlist_to_agent",
    "current_mode",
    "list_entries_for_group",
)


def _now() -> datetime:
    return datetime.now(UTC)


async def current_mode(db: AsyncSession, host_group_id: UUID) -> AllowlistMode:
    """Return the current mode for a host group.

    Missing row == OFF (no allowlist configured). Read-only, used by
    both the API handlers and the dispatch path.
    """
    row = await db.get(AllowlistModeRow, host_group_id)
    if row is None:
        return AllowlistMode.OFF
    try:
        return AllowlistMode(row.mode)
    except ValueError:
        # Defensive — the migration CHECK shouldn't permit this, but
        # don't crash the API if someone hand-edited the row.
        log.warning("allowlist.bad_mode_in_db", host_group_id=str(host_group_id), value=row.mode)
        return AllowlistMode.OFF


async def list_entries_for_group(db: AsyncSession, host_group_id: UUID) -> list[AllowlistEntry]:
    """All approved entries for a group, ordered by created_at."""
    rows = (
        (
            await db.execute(
                select(AllowlistEntry)
                .where(AllowlistEntry.host_group_id == host_group_id)
                .order_by(AllowlistEntry.created_at)
            )
        )
        .scalars()
        .all()
    )
    return list(rows)


async def record_observed_hash(
    db: AsyncSession,
    *,
    host_group_id: UUID,
    sha256: str,
    exec_path: str | None = None,
    publisher: str | None = None,
) -> AllowlistEntry:
    """Record one observed binary for a host group.

    Called by the learner worker on every ProcessStarted event whose
    host belongs to a group in LEARN mode. Implements upsert semantics
    via the (host_group_id, sha256) unique constraint:

      * new (group, hash) → INSERT with learned=True + first_seen=now.
      * existing → UPDATE last_seen=now (and preserve exec_path /
        publisher if they were NULL).

    Returns the row in its post-write state. The caller is expected
    to commit; this function only flushes.
    """
    norm = sha256.strip().lower()
    if len(norm) != 64:
        raise ValueError("sha256 must be 64 hex chars")

    now = _now()
    existing = (
        await db.execute(
            select(AllowlistEntry).where(
                AllowlistEntry.host_group_id == host_group_id,
                AllowlistEntry.sha256 == norm,
            )
        )
    ).scalar_one_or_none()

    if existing is not None:
        existing.last_seen = now
        if existing.exec_path is None and exec_path:
            existing.exec_path = exec_path
        if existing.publisher is None and publisher:
            existing.publisher = publisher
        await db.flush()
        return existing

    row = AllowlistEntry(
        host_group_id=host_group_id,
        sha256=norm,
        exec_path=exec_path,
        publisher=publisher,
        first_seen=now,
        last_seen=now,
        learned=True,
        manual=False,
    )
    db.add(row)
    await db.flush()
    return row


async def push_allowlist_to_agent(
    db: AsyncSession,
    *,
    host_group_id: UUID,
    issued_by_user_id: UUID | None = None,
) -> int:
    """Queue an allowlist_sync Command for every host in the group.

    Returns the number of Commands enqueued. The function builds the
    payload — ``{"mode": "...", "hashes": [hex, ...]}`` — once and
    reuses it across hosts so the wire body is identical regardless
    of which host_id the sync lands on.

    Hosts not in the group don't get a sync. When a host moves into
    the group later, the operator can re-invoke this (or — once the
    learner triggers it — we'll publish a follow-up sync on
    membership change).
    """
    mode = await current_mode(db, host_group_id)
    entries = await list_entries_for_group(db, host_group_id)
    hashes = [e.sha256 for e in entries]

    payload = {"mode": mode.value, "hashes": hashes}

    host_ids = (
        (
            await db.execute(
                select(Host.id)
                .join(host_in_group, host_in_group.c.host_id == Host.id)
                .where(host_in_group.c.host_group_id == host_group_id)
            )
        )
        .scalars()
        .all()
    )

    queued = 0
    for hid in host_ids:
        db.add(
            Command(
                host_id=hid,
                kind=CommandKind.ALLOWLIST_SYNC,
                payload=payload,
                issued_by_user_id=issued_by_user_id,
            )
        )
        queued += 1
    await db.flush()
    log.info(
        "allowlist.push",
        host_group_id=str(host_group_id),
        mode=mode.value,
        hashes=len(hashes),
        hosts=queued,
    )
    return queued


async def upsert_mode(
    db: AsyncSession,
    *,
    host_group_id: UUID,
    mode: AllowlistMode,
    updated_by_user_id: UUID | None,
) -> AllowlistModeRow:
    """Insert-or-update the mode row for a group, stamping the right
    lifecycle timestamps as the mode transitions."""
    now = _now()
    stmt = (
        pg_insert(AllowlistModeRow)
        .values(
            host_group_id=host_group_id,
            mode=mode.value,
            enabled_at=now if mode is not AllowlistMode.OFF else None,
            learn_started_at=now if mode is AllowlistMode.LEARN else None,
            learn_completed_at=now if mode is AllowlistMode.ENFORCE else None,
            updated_by_user_id=updated_by_user_id,
            updated_at=now,
        )
        .on_conflict_do_update(
            index_elements=[AllowlistModeRow.host_group_id],
            set_={
                "mode": mode.value,
                "enabled_at": now if mode is not AllowlistMode.OFF else None,
                # Transitioning back into LEARN restarts the clock so
                # the UI's "learning for N hours" reflects this pass,
                # not the very first one.
                "learn_started_at": now
                if mode is AllowlistMode.LEARN
                else AllowlistModeRow.__table__.c.learn_started_at,
                "learn_completed_at": now
                if mode is AllowlistMode.ENFORCE
                else AllowlistModeRow.__table__.c.learn_completed_at,
                "updated_by_user_id": updated_by_user_id,
                "updated_at": now,
            },
        )
        .returning(AllowlistModeRow)
    )
    res = await db.execute(stmt)
    row = res.scalar_one()
    await db.flush()
    return row
