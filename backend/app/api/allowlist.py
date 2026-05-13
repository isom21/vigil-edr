"""Application allowlist CRUD + mode control (Phase 2 #2.8).

All writes are admin-only and audited. Reads require analyst.

Endpoint shape:

  GET  /api/host-groups/{group_id}/allowlist          → mode + count
  PUT  /api/host-groups/{group_id}/allowlist/mode     → switch mode
  GET  /api/host-groups/{group_id}/allowlist/entries  → list approvals
  POST /api/host-groups/{group_id}/allowlist/entries  → add manual approval
  DELETE /api/host-groups/{group_id}/allowlist/entries/{entry_id}

A mode flip or entry mutation queues an :class:`AllowlistSyncCmd`
for every host in the group via
:func:`app.services.allowlist.push_allowlist_to_agent`; the gRPC
dispatcher pushes it down the bidi stream from there.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, status
from sqlalchemy import select

from app.core.deps import DbSession, RequireAdmin, RequireAnalyst
from app.core.errors import bad_request, not_found
from app.models import AllowlistEntry, AllowlistMode, AllowlistModeRow, HostGroup
from app.schemas.allowlist import (
    AllowlistEntryCreate,
    AllowlistEntryOut,
    AllowlistModeOut,
    AllowlistModeUpdate,
)
from app.services import audit
from app.services.allowlist import (
    current_mode,
    list_entries_for_group,
    push_allowlist_to_agent,
    upsert_mode,
)

router = APIRouter(prefix="/api/host-groups", tags=["allowlist"])


async def _require_group(db, group_id: UUID) -> HostGroup:
    g = await db.get(HostGroup, group_id)
    if g is None:
        raise not_found("host_group", str(group_id))
    return g


@router.get("/{group_id}/allowlist", response_model=AllowlistModeOut)
async def get_mode(
    group_id: UUID,
    db: DbSession,
    actor: RequireAnalyst,
) -> AllowlistModeOut:
    await _require_group(db, group_id)
    row = await db.get(AllowlistModeRow, group_id)
    mode = await current_mode(db, group_id)
    entries = await list_entries_for_group(db, group_id)
    if row is None:
        # Synthesize a default-shaped response for groups that have
        # never been touched.
        return AllowlistModeOut(
            host_group_id=group_id,
            mode=mode,
            enabled_at=None,
            learn_started_at=None,
            learn_completed_at=None,
            updated_at=datetime.now(UTC),
            entry_count=len(entries),
        )
    out = AllowlistModeOut.model_validate(row)
    out.entry_count = len(entries)
    return out


@router.put("/{group_id}/allowlist/mode", response_model=AllowlistModeOut)
async def update_mode(
    group_id: UUID,
    payload: AllowlistModeUpdate,
    db: DbSession,
    actor: RequireAdmin,
) -> AllowlistModeOut:
    await _require_group(db, group_id)
    row = await upsert_mode(
        db,
        host_group_id=group_id,
        mode=payload.mode,
        updated_by_user_id=actor.user.id,
    )
    queued = await push_allowlist_to_agent(
        db,
        host_group_id=group_id,
        issued_by_user_id=actor.user.id,
    )
    await audit.record(
        db,
        actor=actor,
        action="allowlist.mode.set",
        resource_type="host_group",
        resource_id=str(group_id),
        payload={"mode": payload.mode.value, "commands_queued": queued},
    )
    await db.commit()
    out = AllowlistModeOut.model_validate(row)
    out.entry_count = len(await list_entries_for_group(db, group_id))
    return out


@router.get(
    "/{group_id}/allowlist/entries",
    response_model=list[AllowlistEntryOut],
)
async def list_entries(
    group_id: UUID,
    db: DbSession,
    actor: RequireAnalyst,
) -> list[AllowlistEntryOut]:
    await _require_group(db, group_id)
    rows = await list_entries_for_group(db, group_id)
    return [AllowlistEntryOut.model_validate(r) for r in rows]


@router.post(
    "/{group_id}/allowlist/entries",
    response_model=AllowlistEntryOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_entry(
    group_id: UUID,
    payload: AllowlistEntryCreate,
    db: DbSession,
    actor: RequireAdmin,
) -> AllowlistEntryOut:
    await _require_group(db, group_id)
    # Manual upsert — if the learner already saw this hash, flip its
    # `manual` flag rather than reject the create. Operators expect
    # "I added it" to be a stable post-condition regardless of whether
    # the learner got there first.
    existing = (
        await db.execute(
            select(AllowlistEntry).where(
                AllowlistEntry.host_group_id == group_id,
                AllowlistEntry.sha256 == payload.sha256,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        existing.manual = True
        if payload.exec_path:
            existing.exec_path = payload.exec_path
        if payload.publisher:
            existing.publisher = payload.publisher
        if existing.created_by_user_id is None:
            existing.created_by_user_id = actor.user.id
        row = existing
    else:
        row = AllowlistEntry(
            host_group_id=group_id,
            sha256=payload.sha256,
            exec_path=payload.exec_path,
            publisher=payload.publisher,
            learned=False,
            manual=True,
            created_by_user_id=actor.user.id,
        )
        db.add(row)
    await db.flush()
    queued = await push_allowlist_to_agent(
        db,
        host_group_id=group_id,
        issued_by_user_id=actor.user.id,
    )
    await audit.record(
        db,
        actor=actor,
        action="allowlist.entry.create",
        resource_type="allowlist_entry",
        resource_id=str(row.id),
        payload={
            "host_group_id": str(group_id),
            "sha256": row.sha256,
            "commands_queued": queued,
        },
    )
    await db.commit()
    return AllowlistEntryOut.model_validate(row)


@router.delete(
    "/{group_id}/allowlist/entries/{entry_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_entry(
    group_id: UUID,
    entry_id: UUID,
    db: DbSession,
    actor: RequireAdmin,
) -> None:
    await _require_group(db, group_id)
    row = await db.get(AllowlistEntry, entry_id)
    if row is None or row.host_group_id != group_id:
        raise not_found("allowlist_entry", str(entry_id))
    # Refuse to delete the last entry while in ENFORCE — would
    # immediately lock the group out of every binary. Operators
    # who actually want that need to flip to OFF first.
    mode = await current_mode(db, group_id)
    if mode is AllowlistMode.ENFORCE:
        remaining = (
            (
                await db.execute(
                    select(AllowlistEntry).where(AllowlistEntry.host_group_id == group_id)
                )
            )
            .scalars()
            .all()
        )
        if len(remaining) <= 1:
            raise bad_request(
                "refusing to delete the last allowlist entry while in enforce mode; "
                "switch the group to off/learn first"
            )
    sha = row.sha256
    await db.delete(row)
    await db.flush()
    queued = await push_allowlist_to_agent(
        db,
        host_group_id=group_id,
        issued_by_user_id=actor.user.id,
    )
    await audit.record(
        db,
        actor=actor,
        action="allowlist.entry.delete",
        resource_type="allowlist_entry",
        resource_id=str(entry_id),
        payload={
            "host_group_id": str(group_id),
            "sha256": sha,
            "commands_queued": queued,
        },
    )
    await db.commit()
