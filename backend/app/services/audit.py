"""Append-only audit log helper.

M12.f tamper-evidence: every row written through `record()` carries
an HMAC of (`prev_row_hmac` || `canonical_payload`), keyed off
`VIGIL_AUDIT_HMAC_KEY`. The chain is verifiable via the verifier in
`app.services.audit_verifier`.

If `VIGIL_AUDIT_HMAC_KEY` is unset the chain stays dormant — rows
write with NULL hmac fields, and the verifier treats them as the
pre-chain era. This keeps dev environments simple while production
deployments turn on tamper-evidence by setting the key.

After the M16.a (fixed) role split, the runtime user has only
SELECT + INSERT on `audit_log` and USAGE + SELECT on
`audit_log_seq`. Both INSERT-only and the no-UPDATE rule are
load-bearing for tamper-evidence. The chain-write path therefore:

  * Takes a transaction-scoped advisory lock instead of `FOR UPDATE`
    (FOR UPDATE needs UPDATE privilege).
  * Allocates `seq` via `nextval()` (USAGE on the sequence is
    sufficient) and computes `ts` client-side so we can derive the
    canonical bytes + row_hmac BEFORE the INSERT. The row goes in
    fully-formed — there's no follow-up UPDATE to set row_hmac
    (UPDATE would also fail under the role split).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import Actor
from app.models import AuditLog


def _load_hmac_key() -> bytes | None:
    raw = os.environ.get("VIGIL_AUDIT_HMAC_KEY")
    if not raw:
        return None
    # Accept hex (preferred — easy to rotate as a string), otherwise
    # treat the raw bytes as the key. Reject keys shorter than 16
    # bytes — too short to provide meaningful tamper-evidence.
    try:
        decoded = bytes.fromhex(raw)
        if len(decoded) >= 16:
            return decoded
    except ValueError:
        pass
    if len(raw) >= 16:
        return raw.encode("utf-8")
    return None


# Cache the key at import time. Rotating the key requires a process
# restart, which is desired — silent rotation could mask a break.
#
# Operational note (LOW #2): the key load is per-process. If you
# rotate `VIGIL_AUDIT_HMAC_KEY` without restarting every manager
# worker (FastAPI process + each long-lived background task that
# imports this module), some processes keep computing HMACs under
# the old key and the chain verifier will report a break at the
# rotation point. Recipe: stop all manager processes, swap the
# secret, start everything back up. The verifier's "first break"
# row is then row N of the new chain.
_HMAC_KEY = _load_hmac_key()


def canonical_row_bytes(
    *,
    seq: int,
    actor_kind: str,
    user_id: str | None,
    api_token_id: str | None,
    action: str,
    resource_type: str | None,
    resource_id: str | None,
    payload: dict[str, Any] | None,
    ip: str | None,
    ts_iso: str,
) -> bytes:
    """Stable canonical encoding of an audit row for HMAC computation.

    Encoding uses sorted JSON (sort_keys=True, separators with no
    whitespace, UTF-8) so the same logical row always serialises to
    the same bytes regardless of how Python iterates the dict, what
    SQLAlchemy returns from the DB, or whether the row was just
    written or fetched back later.
    """
    obj = {
        "seq": seq,
        "actor_kind": actor_kind,
        "user_id": user_id,
        "api_token_id": api_token_id,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "payload": payload,
        "ip": ip,
        "ts": ts_iso,
    }
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_row_hmac(prev_hmac: bytes | None, canonical: bytes) -> bytes:
    """HMAC-SHA256 of `prev_hmac || canonical`. Empty prev for the
    chain root."""
    if _HMAC_KEY is None:
        raise RuntimeError("VIGIL_AUDIT_HMAC_KEY not set")
    h = hmac.new(_HMAC_KEY, digestmod=hashlib.sha256)
    h.update(prev_hmac if prev_hmac is not None else b"")
    h.update(canonical)
    return h.digest()


def hmac_key_fingerprint() -> str | None:
    """Short, stable identifier for the currently-loaded HMAC key.

    Returns the first 8 hex chars of sha256(_HMAC_KEY), or None when
    the chain is dormant. Operators can compare this fingerprint
    pre- and post-restart to confirm a rotation actually took effect
    (or, when chain breaks suddenly appear, to confirm a rotation is
    the cause and not real tampering).

    Truncating the digest is deliberate: 8 hex chars = 32 bits of
    entropy, enough to distinguish rotations but small enough that
    the fingerprint itself reveals nothing useful about the secret.
    """
    if _HMAC_KEY is None:
        return None
    return hashlib.sha256(_HMAC_KEY).hexdigest()[:8]


async def record(
    db: AsyncSession,
    *,
    actor: Actor | None,
    action: str,
    resource_type: str | None = None,
    resource_id: str | None = None,
    payload: dict[str, Any] | None = None,
    ip: str | None = None,
) -> None:
    user_id = actor.user.id if actor else None
    api_token_id = actor.token_id if actor and actor.kind == "api_token" else None
    actor_kind = actor.kind if actor else "system"

    if _HMAC_KEY is None:
        # Chain dormant. seq + ts get assigned by the server
        # defaults; prev_hmac and row_hmac stay NULL. We rely on the
        # default-DEFAULT path so this branch keeps working in dev
        # environments that never set VIGIL_AUDIT_HMAC_KEY.
        db.add(
            AuditLog(
                user_id=user_id,
                api_token_id=api_token_id,
                actor_kind=actor_kind,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                payload=payload,
                ip=ip,
            )
        )
        return

    # Chain active. Both the lock and the seq allocation live in this
    # transaction; the advisory lock serialises concurrent writers so
    # the seq → hmac → INSERT sequence is total-ordered.
    #
    # Original implementation took the lock via `SELECT … FOR UPDATE`
    # on the chain-head row, then INSERTed with NULL row_hmac and a
    # follow-up UPDATE to fill it in. Both FOR UPDATE and the UPDATE
    # need UPDATE privilege on audit_log — after the M16.a (fixed)
    # role split the runtime user has only SELECT + INSERT, so both
    # paths raise InsufficientPrivilege. Granting UPDATE back to
    # vigil_manager would undo the whole ownership split.
    #
    # Switch to a transaction-scoped advisory lock (doesn't require
    # any table privilege; auto-releases on COMMIT/ROLLBACK) and
    # build the row fully-formed so we INSERT once. The magic key
    # below is stable across the project — don't reuse it for another
    # lock purpose. Generated as
    # `hashtext('vigil_audit_chain_head')::bigint`.
    await db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": 6841837422913824317})

    prev_hmac = (
        await db.execute(
            select(AuditLog.row_hmac)
            .where(AuditLog.row_hmac.is_not(None))
            .order_by(AuditLog.seq.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    # Allocate seq + ts client-side so we can derive the canonical
    # bytes BEFORE the INSERT. USAGE on audit_log_seq is sufficient
    # for nextval; the schema's DEFAULT nextval(...) still works for
    # rows that bypass this helper (CLI tools, future workers) — we
    # just don't rely on it here.
    seq = (await db.execute(text("SELECT nextval('audit_log_seq')"))).scalar_one()
    ts = datetime.now(UTC)

    canonical = canonical_row_bytes(
        seq=seq,
        actor_kind=actor_kind,
        user_id=str(user_id) if user_id else None,
        api_token_id=str(api_token_id) if api_token_id else None,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        payload=payload,
        ip=ip,
        ts_iso=ts.isoformat(),
    )
    row_hmac = compute_row_hmac(prev_hmac, canonical)

    db.add(
        AuditLog(
            seq=seq,
            ts=ts,
            user_id=user_id,
            api_token_id=api_token_id,
            actor_kind=actor_kind,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            payload=payload,
            ip=ip,
            prev_hmac=prev_hmac,
            row_hmac=row_hmac,
        )
    )
