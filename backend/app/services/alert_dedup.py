"""Alert deduplication helpers (Phase 1 #1.10).

Alert producers (sigma_realtime, IOC detector, future YARA detector)
compute a stable dedup key per (rule_id, host_id, canonical_event
signal) and, within a sliding window, bump `occurrence_count` +
refresh `last_occurred_at` on the most recent OPEN alert sharing that
key instead of inserting a duplicate row.

The "canonical event signal" is the most specific ECS field available:
process.executable > file.path > destination.ip > event.id. The first
three are stable across re-detonations of the same artefact /
connection / file write. `event.id` is a UUID per event, so it only
helps when none of the above are populated — in practice it falls
back to "one event = one alert" (i.e. no dedup), which is the
conservative behaviour.

Closed alerts (false_positive / true_positive) never coalesce: an
analyst dispositioning a false_positive should still hear about a
fresh recurrence, so the dedup probe filters `state IN (new,
investigating)`.

Behavioural note: this is the producer-side dedup. The HTTP API still
inserts unique alerts (e.g. manual fire-by-test). The audit log isn't
involved — workers don't audit, the alert insert *is* the record.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Alert, AlertState


def dedup_key_for(rule_id: UUID, host_id: UUID | None, ecs: dict[str, Any]) -> str:
    """Stable sha256-hex key for an alert producer to probe with.

    The signal is the most specific ECS field available so re-detonations
    of the same artefact / file / connection collapse onto one row.
    process.executable wins because it's both stable and high-signal
    (one binary, repeated runs); file.path catches drive-by writes;
    destination.ip covers C2 beacons that don't go through a named
    process; event.id is the last-resort fallback (effectively
    one-event-one-alert).

    Passing host_id=None (synthetic / manager-internal alerts) is
    fine — the key folds in the literal "None" string, so two
    manager-side detections of the same rule still cluster.
    """
    process = ecs.get("process") or {}
    fil = ecs.get("file") or {}
    dest = ecs.get("destination") or {}
    event = ecs.get("event") or {}
    signal = process.get("executable") or fil.get("path") or dest.get("ip") or event.get("id") or ""
    canonical = f"{rule_id}|{host_id}|{signal}".encode()
    return sha256(canonical).hexdigest()


async def find_open_dupe(
    db: AsyncSession,
    *,
    dedup_key: str,
    window_seconds: int,
    now: datetime | None = None,
) -> Alert | None:
    """Look up the most recently-occurred OPEN alert (state in {new,
    investigating}) sharing `dedup_key` whose `last_occurred_at` is
    inside the sliding window. Returns the Alert row (still attached
    to `db`) or None.

    The caller is responsible for bumping `occurrence_count` +
    `last_occurred_at`. We don't do it here so the worker keeps the
    pattern "probe, then either UPDATE or INSERT" in one obvious
    place.
    """
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(seconds=window_seconds)
    stmt = (
        select(Alert)
        .where(
            Alert.dedup_key == dedup_key,
            Alert.last_occurred_at > cutoff,
            Alert.state.in_((AlertState.NEW, AlertState.INVESTIGATING)),
        )
        .order_by(Alert.last_occurred_at.desc())
        .limit(1)
    )
    return (await db.execute(stmt)).scalars().first()


def bump_occurrence(alert: Alert, *, now: datetime | None = None) -> None:
    """In-place bump of an existing open alert's occurrence_count +
    last_occurred_at. Caller flushes / commits."""
    alert.occurrence_count = (alert.occurrence_count or 1) + 1
    alert.last_occurred_at = now or datetime.now(UTC)
