"""DNS block / sinkhole CRUD + bulk import (Phase 2 #2.12).

Admin-only writes; analyst+ can read. Every mutation is audited and
fans out a `DNS_BLOCK_SYNC` command per affected host so the agent's
kernel-side map converges within seconds (commands ride the existing
notify pipeline, no extra polling).
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, status
from sqlalchemy import select

from app.core.deps import DbSession, RequireAdmin, RequireAnalyst
from app.core.errors import conflict, not_found
from app.models import DnsBlockEntry
from app.schemas.dns_block import (
    DnsBlockBulkImport,
    DnsBlockBulkImportResult,
    DnsBlockEntryCreate,
    DnsBlockEntryOut,
)
from app.services import audit
from app.services.dns_block import queue_resync_commands

router = APIRouter(prefix="/api/dns-blocks", tags=["dns-block"])


@router.get("", response_model=list[DnsBlockEntryOut])
async def list_entries(
    db: DbSession,
    _actor: RequireAnalyst,
    host_group_id: UUID | None = None,
) -> list[DnsBlockEntryOut]:
    stmt = select(DnsBlockEntry).order_by(DnsBlockEntry.domain)
    if host_group_id is not None:
        stmt = stmt.where(DnsBlockEntry.host_group_id == host_group_id)
    rows = (await db.execute(stmt)).scalars().all()
    return [DnsBlockEntryOut.model_validate(r) for r in rows]


@router.post("", response_model=DnsBlockEntryOut, status_code=status.HTTP_201_CREATED)
async def create_entry(
    payload: DnsBlockEntryCreate, db: DbSession, actor: RequireAdmin
) -> DnsBlockEntryOut:
    # Pre-check the (host_group_id, domain) uniqueness in-tx so we can
    # surface a clean 409 without relying on IntegrityError catch-and-
    # rollback (which would dissolve the test-suite SAVEPOINT and is
    # also semantically heavier than a quick SELECT).
    dup_stmt = select(DnsBlockEntry).where(DnsBlockEntry.domain == payload.domain)
    if payload.host_group_id is None:
        dup_stmt = dup_stmt.where(DnsBlockEntry.host_group_id.is_(None))
    else:
        dup_stmt = dup_stmt.where(DnsBlockEntry.host_group_id == payload.host_group_id)
    if (await db.execute(dup_stmt)).scalar_one_or_none() is not None:
        raise conflict(
            f"dns block entry already exists for "
            f"{payload.domain} (scope={payload.host_group_id or 'global'})"
        )

    entry = DnsBlockEntry(
        host_group_id=payload.host_group_id,
        domain=payload.domain,
        action=payload.action.value,
        created_by_user_id=actor.user.id,
        expires_at=payload.expires_at,
    )
    db.add(entry)
    await db.flush()

    await audit.record(
        db,
        actor=actor,
        action="dns_block.create",
        resource_type="dns_block_entry",
        resource_id=str(entry.id),
        payload={
            "domain": entry.domain,
            "action": entry.action,
            "host_group_id": str(entry.host_group_id) if entry.host_group_id else None,
            "expires_at": entry.expires_at.isoformat() if entry.expires_at else None,
        },
    )

    await queue_resync_commands(
        db,
        host_group_id=entry.host_group_id,
        issued_by_user_id=actor.user.id,
    )
    return DnsBlockEntryOut.model_validate(entry)


@router.delete("/{entry_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_entry(entry_id: UUID, db: DbSession, actor: RequireAdmin) -> None:
    entry = await db.get(DnsBlockEntry, entry_id)
    if entry is None:
        raise not_found("dns_block_entry", str(entry_id))
    snapshot = {
        "domain": entry.domain,
        "action": entry.action,
        "host_group_id": str(entry.host_group_id) if entry.host_group_id else None,
    }
    affected_group = entry.host_group_id
    await db.delete(entry)
    await db.flush()

    await audit.record(
        db,
        actor=actor,
        action="dns_block.delete",
        resource_type="dns_block_entry",
        resource_id=str(entry_id),
        payload=snapshot,
    )

    await queue_resync_commands(
        db,
        host_group_id=affected_group,
        issued_by_user_id=actor.user.id,
    )


@router.post(
    "/import",
    response_model=DnsBlockBulkImportResult,
    status_code=status.HTTP_201_CREATED,
)
async def bulk_import(
    payload: DnsBlockBulkImport, db: DbSession, actor: RequireAdmin
) -> DnsBlockBulkImportResult:
    """Idempotent bulk insert. Domains that already exist for the
    target scope are skipped, not errored — operators can re-run a
    feed import without an explicit dedupe step.
    """
    # One round-trip to find which domains are already present in the
    # target scope. Cheaper than per-row INSERT-then-rollback and
    # gives us a precise `skipped` count for the response.
    existing_stmt = select(DnsBlockEntry.domain).where(DnsBlockEntry.domain.in_(payload.domains))
    if payload.host_group_id is None:
        existing_stmt = existing_stmt.where(DnsBlockEntry.host_group_id.is_(None))
    else:
        existing_stmt = existing_stmt.where(DnsBlockEntry.host_group_id == payload.host_group_id)
    existing = {d for (d,) in (await db.execute(existing_stmt)).all()}

    inserted = 0
    skipped = 0
    for domain in payload.domains:
        if domain in existing:
            skipped += 1
            continue
        db.add(
            DnsBlockEntry(
                host_group_id=payload.host_group_id,
                domain=domain,
                action=payload.action.value,
                created_by_user_id=actor.user.id,
            )
        )
        inserted += 1
    if inserted:
        await db.flush()

    await audit.record(
        db,
        actor=actor,
        action="dns_block.import",
        resource_type="dns_block_entry",
        resource_id=str(payload.host_group_id) if payload.host_group_id else "global",
        payload={
            "host_group_id": str(payload.host_group_id) if payload.host_group_id else None,
            "action": payload.action.value,
            "inserted": inserted,
            "skipped": skipped,
            "total": len(payload.domains),
        },
    )

    if inserted:
        await queue_resync_commands(
            db,
            host_group_id=payload.host_group_id,
            issued_by_user_id=actor.user.id,
        )
    return DnsBlockBulkImportResult(inserted=inserted, skipped=skipped)
