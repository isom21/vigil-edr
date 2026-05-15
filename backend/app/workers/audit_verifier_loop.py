"""Periodic audit-chain verifier (M-audit-and-auth #6).

`services.audit_verifier.verify_chain` exists and works — the
reviewer's finding was that it was CLI-only. A break in the HMAC
chain is the trip-wire for "someone has been editing the audit log";
catching it days late defeats the purpose, so a background loop runs
the verifier on a schedule and surfaces breaks two ways:

  1. Prometheus gauges (`edr_manager_audit_chain_breaks` +
     `_rows_examined` + `_last_run_timestamp`). The latter is the
     trip-wire for "the verifier itself has stopped" — a stale
     timestamp gauge is its own alarm.
  2. A SYSTEM-actor alert in the alerts pipeline so SOC analysts see
     it next to detection alerts. Synthetic rule id
     `a0a0a0a0-0000-0000-0000-000000000006` so all such alerts attach
     to a single row in the alerts UI (mirrors the M12.e
     re-enrollment-rule pattern).

Interval comes from `VIGIL_AUDIT_VERIFIER_INTERVAL_S` (default 300 s)
so operators can dial it up under heavy write load — verify_chain
walks every chained row, so on a multi-million-row table the pass
isn't cheap.

The loop's lifecycle is owned by `app.main.lifespan`. The loop runs
inside the manager process and uses the verifier-writer DSN
(VIGIL_PG_DSN_AUDIT after M16.a fixed) so the read connection stays
isolated from the runtime pool — no risk of one slow verify run
starving the request path.
"""

from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime
from uuid import UUID

import structlog
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import settings
from app.core.db import SessionLocal
from app.core.metrics import (
    audit_chain_breaks,
    audit_chain_last_run_timestamp,
    audit_chain_rows_examined,
)
from app.models import Alert, AlertState, Rule, RuleAction, RuleKind, Severity
from app.models.synthetic_rules import AUDIT_CHAIN_BREAK_RULE_ID
from app.models.tenant import DEFAULT_TENANT_ID
from app.services.audit import hmac_key_fingerprint
from app.services.audit_verifier import cache_record, verify_chain

log = structlog.get_logger()

__all__ = ("AUDIT_CHAIN_BREAK_RULE_ID", "run_forever")


def _interval_seconds() -> int:
    raw = os.environ.get("VIGIL_AUDIT_VERIFIER_INTERVAL_S", "300")
    try:
        v = int(raw)
        return max(30, v)  # never tighter than 30 s; verify_chain isn't free
    except ValueError:
        return 300


def _verifier_engine_factory():
    """Open a session factory against the audit-writer DSN if set,
    else fall back to the runtime pool. Mirrors
    audit_verifier._verifier_session_factory but kept local so the
    loop can dispose its own engine cleanly on shutdown.

    Under `VIGIL_TEST_ENV=1` we also build a fresh engine even when
    `pg_dsn_audit` is unset: the pytest harness runs each test on a
    new event loop, and `SessionLocal`'s pool retains asyncpg
    connections bound to whichever loop first checked them out.
    A subsequent test loop then fails pool_pre_ping with
    "Event loop is closed" when SQLAlchemy probes the stale
    connection. An owned-and-disposed engine sidesteps the pool entirely.

    The owned engine uses NullPool because it lives for exactly one
    verify_chain pass. Pooling adds nothing on a one-shot engine, and
    pool_pre_ping under pytest-asyncio's per-test loops surfaces the
    "Future attached to a different loop" / "Event loop is closed"
    races that gave this code its name.
    """
    dsn = settings.pg_dsn_audit
    if dsn is None and os.environ.get("VIGIL_TEST_ENV") == "1":
        dsn = settings.pg_dsn
    if dsn:
        eng = create_async_engine(dsn, poolclass=NullPool, echo=False)
        return async_sessionmaker(eng, expire_on_commit=False), eng
    return SessionLocal, None


async def _ensure_rule_and_open_alert(
    *,
    seq: int,
    reason: str,
    ts: datetime,
    tenant_id: UUID | None,
) -> None:
    """Open one Alert row when a chain break is observed. We write
    through the runtime pool (SessionLocal) because we WANT this
    alert to be `INSERT`-only audit-loggable from the manager side —
    just like every other alert. The detail of the break sits in
    `details` so analysts can see seq/reason without re-running the
    verifier.

    The alert is synthetic: `host_id` is NULL (the chain break is
    about the manager process itself, not any specific endpoint).
    Admins see it in the alerts list / SSE stream via the
    null-host-handling in `host_visible_to`; non-admins don't.
    """
    async with SessionLocal() as db:
        rule = await db.get(Rule, AUDIT_CHAIN_BREAK_RULE_ID)
        if rule is None:
            db.add(
                Rule(
                    id=AUDIT_CHAIN_BREAK_RULE_ID,
                    name="M16: audit_log HMAC-chain break",
                    kind=RuleKind.IOC,
                    action=RuleAction.ALERT,
                    severity=Severity.CRITICAL,
                    enabled=True,
                    description=(
                        "Synthetic rule — fires when the audit_log HMAC chain "
                        "verifier detects a break. A break means an audit row "
                        "was UPDATEd / DELETEd / re-keyed without recomputing "
                        "the chain. The role split (M16.a fixed) makes this "
                        "very hard from the runtime pool; if you see this "
                        "fire, investigate the host running the manager."
                    ),
                )
            )
            await db.flush()
        db.add(
            Alert(
                # CODE-25: chains are per-tenant — stamp the alert with
                # the tenant the broken row belonged to. Pre-tenancy
                # rows can carry NULL tenant_id; fall back to the seed
                # tenant in that case rather than the column default,
                # so analysts reviewing the seed tenant still see it.
                tenant_id=tenant_id if tenant_id is not None else DEFAULT_TENANT_ID,
                host_id=None,
                rule_id=AUDIT_CHAIN_BREAK_RULE_ID,
                severity=Severity.CRITICAL,
                action_taken=RuleAction.ALERT,
                state=AlertState.NEW,
                summary=f"audit_log chain break at seq={seq}",
                details={
                    "seq": seq,
                    "reason": reason,
                    "observed_at": ts.isoformat(),
                    "detector": "audit_verifier_v1",
                    "tenant_id": str(tenant_id) if tenant_id else None,
                },
            )
        )
        await db.commit()


async def _run_once() -> None:
    session_factory, owned_engine = _verifier_engine_factory()
    try:
        async with session_factory() as db:
            result = await verify_chain(db)
    finally:
        if owned_engine is not None:
            await owned_engine.dispose()

    now = datetime.now(UTC)
    audit_chain_breaks.set(len(result.breaks))
    audit_chain_rows_examined.set(result.rows_examined)
    audit_chain_last_run_timestamp.set(now.timestamp())
    # Surface to /api/audit/verify so the request path can serve the
    # cached result rather than re-walk the table on every call.
    cache_record(result)

    key_fp = hmac_key_fingerprint()
    if result.ok:
        log.info(
            "audit_verifier.ok",
            rows_examined=result.rows_examined,
            chain_rows=result.chain_rows,
            key_fingerprint=key_fp,
        )
        return

    # Tag the breaks-detected log with the active key fingerprint so
    # operators can correlate a wave of `row_hmac mismatch` breaks
    # with a recent VIGIL_AUDIT_HMAC_KEY rotation rather than reading
    # them as real tampering. If the fingerprint here doesn't match
    # the previous ok-line's fingerprint, that's the cause.
    log.error(
        "audit_verifier.breaks_detected",
        rows_examined=result.rows_examined,
        chain_rows=result.chain_rows,
        n_breaks=len(result.breaks),
        key_fingerprint=key_fp,
    )
    # Open one alert per distinct break seq. If a future run sees the
    # same break still present, the alert won't dedupe automatically —
    # operators close the alert when they've investigated. That's
    # consistent with how the detector pipeline handles ongoing
    # conditions (e.g. an ioc match that keeps firing).
    for b in result.breaks:
        try:
            await _ensure_rule_and_open_alert(
                seq=b.seq,
                reason=b.reason,
                ts=now,
                tenant_id=b.tenant_id,
            )
        except Exception:  # pragma: no cover — alert write itself is best-effort
            log.exception("audit_verifier.alert_write_failed", seq=b.seq)


async def run_forever() -> None:
    """Main loop. Wrapped in lifespan as a background task."""
    interval = _interval_seconds()
    log.info("audit_verifier.loop.starting", interval_s=interval)
    while True:
        try:
            await _run_once()
        except asyncio.CancelledError:
            log.info("audit_verifier.loop.cancelled")
            raise
        except Exception:  # pragma: no cover — never let the loop die
            log.exception("audit_verifier.loop.iteration_failed")
        try:
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            log.info("audit_verifier.loop.cancelled")
            raise
