"""M12.f audit log integrity endpoint.

Admin-only. Returns the result of running the HMAC chain verifier
across the entire audit_log table. Operators can also run
`python -m app.services.audit_verifier` from the host to get the
same result over the CLI.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import func, select

from app.core.deps import DbSession, RequireAdmin
from app.models import AuditLog
from app.schemas.common import Page
from app.services.audit_verifier import cache_get, cache_lock, cache_record, verify_chain

router = APIRouter(prefix="/api/audit", tags=["audit"])


class ChainBreakOut(BaseModel):
    seq: int
    row_id: str
    reason: str
    expected_hmac_hex: str | None
    actual_hmac_hex: str | None


class VerifyResultOut(BaseModel):
    ok: bool
    rows_examined: int
    chain_rows: int
    breaks: list[ChainBreakOut]
    # When this result was computed. `cached=True` means the value
    # comes from the background loop's last pass; `cached=False`
    # means it was just walked from `?refresh=1` (or because the
    # loop hasn't run yet — first-call cold start).
    last_run_at: datetime | None
    cached: bool


class AuditEntryOut(BaseModel):
    id: UUID
    seq: int
    ts: datetime
    actor_kind: str
    user_id: UUID | None
    api_token_id: UUID | None
    action: str
    resource_type: str | None
    resource_id: str | None
    payload: dict | None
    ip: str | None


@router.get("", response_model=Page[AuditEntryOut])
async def list_audit(
    db: DbSession,
    _admin: RequireAdmin,
    action: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    actor_kind: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = 100,
    offset: int = 0,
) -> Page[AuditEntryOut]:
    """M22.d: paginated audit log viewer.

    Filterable by action / resource_type / resource_id / actor_kind /
    time range. Newest rows first. Admin-only — the audit log is
    privileged content and analyst tokens have no business reading it.
    """
    stmt = select(AuditLog)
    count_stmt = select(func.count(AuditLog.id))
    if action:
        stmt = stmt.where(AuditLog.action == action)
        count_stmt = count_stmt.where(AuditLog.action == action)
    if resource_type:
        stmt = stmt.where(AuditLog.resource_type == resource_type)
        count_stmt = count_stmt.where(AuditLog.resource_type == resource_type)
    if resource_id:
        stmt = stmt.where(AuditLog.resource_id == resource_id)
        count_stmt = count_stmt.where(AuditLog.resource_id == resource_id)
    if actor_kind:
        stmt = stmt.where(AuditLog.actor_kind == actor_kind)
        count_stmt = count_stmt.where(AuditLog.actor_kind == actor_kind)
    if since:
        stmt = stmt.where(AuditLog.ts >= since)
        count_stmt = count_stmt.where(AuditLog.ts >= since)
    if until:
        stmt = stmt.where(AuditLog.ts <= until)
        count_stmt = count_stmt.where(AuditLog.ts <= until)
    stmt = stmt.order_by(AuditLog.seq.desc()).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).scalars().all()
    total = (await db.execute(count_stmt)).scalar_one()
    return Page(
        items=[
            AuditEntryOut(
                id=r.id,
                seq=r.seq,
                ts=r.ts,
                actor_kind=r.actor_kind,
                user_id=r.user_id,
                api_token_id=r.api_token_id,
                action=r.action,
                resource_type=r.resource_type,
                resource_id=r.resource_id,
                payload=r.payload,
                ip=r.ip,
            )
            for r in rows
        ],
        total=int(total),
        limit=limit,
        offset=offset,
    )


@router.get("/verify", response_model=VerifyResultOut)
async def verify(
    db: DbSession,
    _admin: RequireAdmin,
    refresh: bool = False,
) -> VerifyResultOut:
    """Return the audit-chain verifier result.

    Default path serves the cached result from the background loop
    (`workers.audit_verifier_loop`), which runs every
    `VIGIL_AUDIT_VERIFIER_INTERVAL_S` (default 300 s). `verify_chain`
    is O(n) over `audit_log` and on a multi-million-row table the
    live walk is expensive enough to time out a UI poll — the loop
    amortises it.

    `?refresh=1` forces a fresh walk on the request thread and
    overwrites the cache. Useful when an operator just rotated the
    HMAC key or wants live confirmation of a fix; otherwise leave
    it off.

    Cold start: if the loop hasn't recorded a pass yet (`make up`
    just started, or `VIGIL_AUDIT_VERIFIER_INTERVAL_S=0`), the first
    call runs live as a fallback.
    """
    if refresh:
        async with cache_lock():
            result = await verify_chain(db)
            cache_record(result)
            cached_flag = False
            last_run_at = datetime.now(UTC)
    else:
        cached, ran_at = cache_get()
        if cached is None:
            # Loop hasn't run yet — fall back to live so cold-start
            # callers don't get a confusing "no data" shape. Cache
            # what we got so the next call is free.
            async with cache_lock():
                cached, ran_at = cache_get()  # re-check under lock
                if cached is None:
                    result = await verify_chain(db)
                    cache_record(result)
                    cached_flag = False
                    last_run_at = datetime.now(UTC)
                else:
                    result = cached
                    cached_flag = True
                    last_run_at = ran_at
        else:
            result = cached
            cached_flag = True
            last_run_at = ran_at

    return VerifyResultOut(
        ok=result.ok,
        rows_examined=result.rows_examined,
        chain_rows=result.chain_rows,
        breaks=[
            ChainBreakOut(
                seq=b.seq,
                row_id=b.row_id,
                reason=b.reason,
                expected_hmac_hex=b.expected_hmac.hex() if b.expected_hmac else None,
                actual_hmac_hex=b.actual_hmac.hex() if b.actual_hmac else None,
            )
            for b in result.breaks
        ],
        last_run_at=last_run_at,
        cached=cached_flag,
    )
