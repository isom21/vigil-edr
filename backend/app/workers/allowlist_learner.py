"""Phase 2 #2.8: application-allowlist learner worker.

Periodic loop that walks groups currently in LEARN mode and pulls
recently-observed (sha256, exec_path) pairs into ``allowlist_entry``.

In this PR the learner uses an in-process queue
(:func:`stage_observation`) that the gRPC ingest path posts to
whenever it normalises a ProcessStarted event for a host belonging to
a group in LEARN mode. A follow-up PR will replace this with a Kafka
subscription against ``telemetry.normalized`` so the learner survives
manager restarts without losing the in-flight buffer.

Lifecycle mirrors :mod:`app.workers.intel_ingest`:
``run_forever`` ticks every :func:`_interval_seconds`, calling
:func:`_run_once`, and ``VIGIL_ALLOWLIST_LEARNER_ENABLED=0`` turns
the loop off at boot.
"""

from __future__ import annotations

import asyncio
import os
from collections import deque
from collections.abc import Callable, Iterable
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import SessionLocal
from app.models import AllowlistMode, AllowlistModeRow, host_in_group
from app.services.allowlist import record_observed_hash

SessionMaker = Callable[[], AbstractAsyncContextManager[AsyncSession]]

log = structlog.get_logger()


@dataclass(frozen=True)
class _Observation:
    """One ProcessStarted event the learner is interested in."""

    host_id: UUID
    sha256: str
    exec_path: str | None


# In-process staging queue. The gRPC ingest path appends to this when
# a ProcessStarted event lands; the worker drains on every tick.
#
# This is intentionally an in-memory deque rather than a thread/async
# queue — the worker drains in-process, with no contention. If we
# scale beyond a single manager instance, the follow-up PR moves this
# onto Kafka; for now an in-process buffer is the simplest thing.
_PENDING: deque[_Observation] = deque(maxlen=10_000)


def stage_observation(host_id: UUID, sha256: str, exec_path: str | None = None) -> None:
    """Called by the gRPC normalizer. Cheap — just appends.

    The worker resolves host → host-groups → mode on its own tick, so
    the caller doesn't need to know whether the host is in a group
    that cares.
    """
    if not sha256:
        return
    norm = sha256.strip().lower()
    if len(norm) != 64:
        return
    _PENDING.append(_Observation(host_id=host_id, sha256=norm, exec_path=exec_path))


def _drain_pending() -> list[_Observation]:
    """Pop everything currently queued. Race with stage_observation
    is benign — anything added after the drain returns lands on the
    next tick."""
    out: list[_Observation] = []
    while _PENDING:
        try:
            out.append(_PENDING.popleft())
        except IndexError:
            break
    return out


def _interval_seconds() -> int:
    raw = os.environ.get("VIGIL_ALLOWLIST_LEARNER_INTERVAL_S", "30")
    try:
        return max(5, int(raw))
    except ValueError:
        return 30


async def _hosts_in_learn_mode(db: AsyncSession) -> dict[UUID, list[UUID]]:
    """Return host_id → list[host_group_id] for every host belonging
    to at least one group currently in LEARN mode.

    Built once per tick so we don't issue N+1 queries per observation.
    """
    rows = (
        await db.execute(
            select(host_in_group.c.host_id, host_in_group.c.host_group_id)
            .join(
                AllowlistModeRow,
                AllowlistModeRow.host_group_id == host_in_group.c.host_group_id,
            )
            .where(AllowlistModeRow.mode == AllowlistMode.LEARN.value)
        )
    ).all()
    mapping: dict[UUID, list[UUID]] = {}
    for host_id, group_id in rows:
        mapping.setdefault(host_id, []).append(group_id)
    return mapping


async def _persist_batch(db: AsyncSession, observations: Iterable[_Observation]) -> tuple[int, int]:
    """Resolve each observation against the learn-mode map and
    upsert. Returns (recorded, skipped). Skipped covers observations
    from hosts that aren't in any learn-mode group — the worker drains
    them regardless so the queue doesn't grow unbounded across mode
    flips."""
    learn_map = await _hosts_in_learn_mode(db)
    if not learn_map:
        return 0, sum(1 for _ in observations)

    recorded = 0
    skipped = 0
    # Dedup within a tick — observing the same hash twice in one
    # batch costs one upsert, not two.
    seen: set[tuple[UUID, str]] = set()
    for ob in observations:
        groups = learn_map.get(ob.host_id)
        if not groups:
            skipped += 1
            continue
        for gid in groups:
            key = (gid, ob.sha256)
            if key in seen:
                continue
            seen.add(key)
            await record_observed_hash(
                db,
                host_group_id=gid,
                sha256=ob.sha256,
                exec_path=ob.exec_path,
            )
            recorded += 1
    return recorded, skipped


async def _run_once(
    session_maker: SessionMaker | None = None,
    *,
    extra_observations: list[_Observation] | None = None,
) -> int:
    """One pass — drain + persist. Returns the number of (group,hash)
    pairs upserted this pass.

    Tests pass `extra_observations` to inject observations directly
    instead of going through the in-process queue.
    """
    sm: SessionMaker = session_maker if session_maker is not None else SessionLocal
    queued = _drain_pending()
    if extra_observations:
        queued.extend(extra_observations)
    if not queued:
        return 0
    async with sm() as db:
        recorded, skipped = await _persist_batch(db, queued)
        await db.commit()
    if recorded or skipped:
        log.info(
            "allowlist_learner.tick",
            recorded=recorded,
            skipped=skipped,
        )
    return recorded


async def trigger_persist(
    observations: list[_Observation],
    session_maker: SessionMaker | None = None,
) -> int:
    """Force a sync of the supplied observations. Used by tests
    and the periodic-tick path alike."""
    return await _run_once(session_maker=session_maker, extra_observations=observations)


async def run_forever() -> None:
    """Main loop. Wrapped in lifespan as a background task."""
    interval = _interval_seconds()
    log.info("allowlist_learner.loop.starting", interval_s=interval)
    while True:
        try:
            await _run_once()
        except asyncio.CancelledError:
            log.info("allowlist_learner.loop.cancelled")
            raise
        except Exception:  # pragma: no cover — never let the loop die
            log.exception("allowlist_learner.loop.iteration_failed")
        try:
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            log.info("allowlist_learner.loop.cancelled")
            raise


# Re-export the staging dataclass for tests.
Observation = _Observation
__all__ = (
    "Observation",
    "stage_observation",
    "trigger_persist",
    "run_forever",
    "_run_once",
    "_drain_pending",
    "_interval_seconds",
)
