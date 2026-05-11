"""M12.f audit log integrity endpoint.

Admin-only. Returns the result of running the HMAC chain verifier
across the entire audit_log table. Operators can also run
`python -m app.services.audit_verifier` from the host to get the
same result over the CLI.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import func, select

from app.core.deps import DbSession, RequireAdmin
from app.models import AuditLog
from app.schemas.common import Page
from app.services.audit_verifier import verify_chain

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
) -> VerifyResultOut:
    """Run the audit chain verifier and return the result.

    O(n) over the audit_log table — for very large logs this should
    be invoked from a maintenance window, not the live request
    path. Currently no incremental verification (M12.f follow-up).
    """
    result = await verify_chain(db)
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
    )
