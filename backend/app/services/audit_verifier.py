"""M12.f audit log HMAC chain verifier.

Walks audit_log rows in seq order, recomputes the HMAC chain, and
reports breaks. A break means one of:

  * A row was UPDATEd (the M16.a INSERT-only privileges deny this
    from the manager's runtime pool, but a privileged DB-level
    attacker — anyone who can reach the table as the owner role —
    can still bypass).
  * A row was DELETEd (same).
  * A row was INSERTed at the wrong sequence position.
  * The HMAC key was changed without resetting the chain (which
    would invalidate every row written under the old key).

Rows whose `row_hmac` is NULL are treated as the pre-chain era —
they're skipped silently. The chain starts at the first row with
a non-NULL row_hmac.

The verifier connects via `VIGIL_PG_DSN_AUDIT` (the writer role) so
its connection pool stays isolated from the manager's runtime pool.
Falls back to `VIGIL_PG_DSN` when the audit DSN is unset, for dev
environments that haven't been bootstrapped through install.sh yet.

CLI usage:
    python -m app.services.audit_verifier
"""

from __future__ import annotations

import asyncio
import logging
import sys
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import settings
from app.core.db import SessionLocal
from app.models import AuditLog
from app.services.audit import canonical_row_bytes, compute_row_hmac


@dataclass
class ChainBreak:
    seq: int
    row_id: str
    reason: str
    expected_hmac: bytes | None
    actual_hmac: bytes | None
    # Phase 3 #3.1 / CODE-25: chains are per-tenant. Carrying tenant_id
    # on the break lets the audit-verifier-loop write the chain-break
    # Alert against the correct tenant rather than DEFAULT_TENANT_ID.
    # Optional because pre-tenancy rows (NULL tenant_id) can still be
    # observed in older databases.
    tenant_id: uuid.UUID | None = None


@dataclass
class VerifyResult:
    rows_examined: int
    chain_rows: int  # rows that had a row_hmac (i.e. participate in the chain)
    breaks: list[ChainBreak]

    @property
    def ok(self) -> bool:
        return not self.breaks


# Module-level cache populated by the background loop (M-audit-and-auth
# #6) and read by GET /api/audit/verify. `verify_chain` walks every
# row in seq order; on a multi-million-row table the live path is
# expensive enough that we want the request handler to serve the
# loop's most recent result unless an operator asks for `?refresh=1`.
_last_result: VerifyResult | None = None
_last_run_at: datetime | None = None
_cache_lock = asyncio.Lock()


def cache_record(result: VerifyResult) -> None:
    """Update the cached verifier result. Called by the background
    loop after each pass and by the /verify endpoint when invoked
    with `?refresh=1`."""
    global _last_result, _last_run_at
    _last_result = result
    _last_run_at = datetime.now(UTC)


def cache_get() -> tuple[VerifyResult | None, datetime | None]:
    """Return the cached `(result, ran_at)` pair, or `(None, None)` if
    the loop hasn't recorded a pass yet."""
    return _last_result, _last_run_at


def cache_lock() -> asyncio.Lock:
    """Serialises refresh-on-demand runs so two concurrent
    `?refresh=1` callers don't race on the same expensive walk."""
    return _cache_lock


async def verify_chain(db: AsyncSession) -> VerifyResult:
    """Walk every audit row in (tenant_id, seq) order, recomputing
    each tenant's HMAC chain independently and reporting any breaks.

    Phase 3 #3.1: chains are per-tenant. We sort by tenant then seq
    so each tenant's rows are contiguous, and we reset the
    chain-walker state (``prev_hmac``, ``chain_started``) on every
    tenant boundary. A break inside tenant A cannot cascade into
    tenant B — they're independent walks sharing one verifier pass.
    """
    stmt = select(AuditLog).order_by(AuditLog.tenant_id.asc(), AuditLog.seq.asc())
    breaks: list[ChainBreak] = []
    prev_hmac: bytes | None = None
    chain_started = False
    chain_rows = 0
    rows_examined = 0
    current_tenant: object | None = None
    async for row in (await db.stream(stmt)).scalars():
        rows_examined += 1
        if row.tenant_id != current_tenant:
            # New tenant — reset the walker. The first non-NULL
            # row_hmac with this tenant_id is that tenant's genesis.
            current_tenant = row.tenant_id
            prev_hmac = None
            chain_started = False
        if row.row_hmac is None:
            # Pre-chain row, or a row written while VIGIL_AUDIT_HMAC_KEY
            # was unset. Skip without breaking the chain — the chain
            # resumes at the next non-null row in this tenant.
            continue
        chain_rows += 1
        # Recompute what this row's HMAC should have been.
        canonical = canonical_row_bytes(
            seq=row.seq,
            actor_kind=row.actor_kind,
            user_id=str(row.user_id) if row.user_id else None,
            api_token_id=str(row.api_token_id) if row.api_token_id else None,
            action=row.action,
            resource_type=row.resource_type,
            resource_id=row.resource_id,
            payload=row.payload,
            ip=row.ip,
            ts_iso=row.ts.isoformat() if row.ts else "",
            tenant_id=str(row.tenant_id) if row.tenant_id else None,
        )
        if not chain_started:
            # First chain row in this tenant — its prev_hmac should
            # be NULL.
            if row.prev_hmac is not None:
                breaks.append(
                    ChainBreak(
                        seq=row.seq,
                        row_id=str(row.id),
                        reason="first chain row has non-NULL prev_hmac",
                        expected_hmac=None,
                        actual_hmac=row.prev_hmac,
                        tenant_id=row.tenant_id,
                    )
                )
            chain_started = True
        else:
            if row.prev_hmac != prev_hmac:
                breaks.append(
                    ChainBreak(
                        seq=row.seq,
                        row_id=str(row.id),
                        reason="prev_hmac mismatch — row tampered or one missing",
                        expected_hmac=prev_hmac,
                        actual_hmac=row.prev_hmac,
                        tenant_id=row.tenant_id,
                    )
                )
        try:
            expected = compute_row_hmac(row.prev_hmac, canonical)
        except RuntimeError:
            # VIGIL_AUDIT_HMAC_KEY unset — can't verify.
            return VerifyResult(rows_examined, chain_rows, breaks)
        if expected != row.row_hmac:
            breaks.append(
                ChainBreak(
                    seq=row.seq,
                    row_id=str(row.id),
                    reason="row_hmac mismatch — row content tampered",
                    expected_hmac=expected,
                    actual_hmac=row.row_hmac,
                    tenant_id=row.tenant_id,
                )
            )
        prev_hmac = row.row_hmac

    return VerifyResult(rows_examined, chain_rows, breaks)


def _verifier_session_factory() -> async_sessionmaker:
    """Open a session against the audit-writer DSN when set, else fall
    back to the runtime pool. The runtime pool can still SELECT, so
    dev/test environments work without provisioning the second role."""
    if settings.pg_dsn_audit:
        engine = create_async_engine(settings.pg_dsn_audit, pool_pre_ping=True, echo=False)
        return async_sessionmaker(engine, expire_on_commit=False)
    return SessionLocal


async def _cli() -> int:
    logging.basicConfig(level=logging.INFO)
    session_factory = _verifier_session_factory()
    async with session_factory() as db:
        result = await verify_chain(db)
    print(
        f"audit chain: examined {result.rows_examined} rows, "
        f"{result.chain_rows} chain rows, breaks={len(result.breaks)}"
    )
    for b in result.breaks:
        print(f"  break at seq={b.seq} id={b.row_id}: {b.reason}")
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(_cli()))
