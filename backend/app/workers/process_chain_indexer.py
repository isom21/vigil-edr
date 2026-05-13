"""Process-chain indexer (Phase 2 #2.6).

Tails `telemetry.normalized` and materialises process_started /
process_exited events into the `process_chain` table so the alert
investigation view can walk lineage in Postgres without re-fetching
OpenSearch.

Insert semantics: `ON CONFLICT (host_id, pid, started_at) DO NOTHING`.
Kafka redelivers, agent retries, and the indexer's own idempotency on
restart all collapse onto the same row. Update semantics: when a
`process_exited` event arrives, we UPDATE `ended_at` on the latest
matching row by `(host_id, pid)` whose `ended_at` is still NULL.

Retention: a periodic sweep deletes rows whose `started_at` is older
than `VIGIL_PROCESS_CHAIN_RETENTION_DAYS` (default 90). Long-running
processes are kept regardless — the sweep filters by `started_at`,
not `ended_at`, so a year-long systemd process stays in the graph.

The worker wraps Kafka consumption in `run_forever()` to match the
shape of `intel_ingest`'s lifespan integration in `app.main`. The
inner consume loop is identical to `indexer.py` / `siem_forwarder.py`.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import UTC, datetime, timedelta
from uuid import UUID

import structlog
from aiokafka import AIOKafkaConsumer
from sqlalchemy import delete, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import SessionLocal
from app.models import ProcessChain

log = structlog.get_logger()

# How often the retention sweep fires. The sweep is cheap (an indexed
# DELETE by started_at) so a daily cadence is fine.
RETENTION_SWEEP_INTERVAL_S = 24 * 3600


def _parse_iso(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def _extract_host_id(doc: dict) -> UUID | None:
    raw = (doc.get("host") or {}).get("id")
    if not raw:
        return None
    try:
        return UUID(raw)
    except (TypeError, ValueError):
        return None


def _extract_pid(proc: dict) -> int | None:
    raw = proc.get("pid")
    return raw if isinstance(raw, int) and raw > 0 else None


def _doc_started_at(doc: dict, proc: dict) -> datetime:
    """Pick the most authoritative timestamp for a process_started row.
    Prefer the agent-supplied `process.start` (true wall-clock start of
    the process); fall back to event timestamps so the row still lands
    when the agent didn't fill `start`."""
    for candidate in (
        proc.get("start"),
        (doc.get("event") or {}).get("created"),
        doc.get("@timestamp"),
    ):
        parsed = _parse_iso(candidate)
        if parsed is not None:
            return parsed
    return datetime.now(UTC)


async def _handle_process_started(db: AsyncSession, doc: dict) -> bool:
    host_id = _extract_host_id(doc)
    if host_id is None:
        return False
    proc = doc.get("process") or {}
    pid = _extract_pid(proc)
    if pid is None:
        return False
    parent_raw = (proc.get("parent") or {}).get("pid")
    parent_pid = parent_raw if isinstance(parent_raw, int) and parent_raw > 0 else None
    sha256 = (proc.get("hash") or {}).get("sha256")
    if isinstance(sha256, str):
        sha256 = sha256.lower()
        if len(sha256) != 64:
            sha256 = None
    else:
        sha256 = None
    started_at = _doc_started_at(doc, proc)
    stmt = (
        pg_insert(ProcessChain)
        .values(
            host_id=host_id,
            pid=pid,
            parent_pid=parent_pid,
            exec_path=proc.get("executable"),
            image_sha256=sha256,
            command_line=proc.get("command_line"),
            started_at=started_at,
        )
        .on_conflict_do_nothing(
            constraint="uq_process_chain_host_id_pid_started_at",
        )
    )
    await db.execute(stmt)
    return True


async def _handle_process_exited(db: AsyncSession, doc: dict) -> bool:
    host_id = _extract_host_id(doc)
    if host_id is None:
        return False
    proc = doc.get("process") or {}
    pid = _extract_pid(proc)
    if pid is None:
        return False
    ended_at = _parse_iso((doc.get("event") or {}).get("created")) or _parse_iso(
        doc.get("@timestamp")
    )
    if ended_at is None:
        ended_at = datetime.now(UTC)
    # Patch the latest open row for this (host, pid). A future exit
    # event after pid reuse won't disturb an already-closed prior row.
    subq = text(
        """
        SELECT id FROM process_chain
        WHERE host_id = :host_id AND pid = :pid AND ended_at IS NULL
        ORDER BY started_at DESC
        LIMIT 1
        """
    )
    row = (await db.execute(subq, {"host_id": host_id, "pid": pid})).first()
    if row is None:
        return False
    await db.execute(
        update(ProcessChain).where(ProcessChain.id == row[0]).values(ended_at=ended_at)
    )
    return True


async def handle_doc(db: AsyncSession, doc: dict) -> bool:
    """Route one normalised ECS doc into the graph. Returns True iff a
    row was inserted or updated. The test suite calls this directly."""
    action = (doc.get("event") or {}).get("action")
    if action == "process_started":
        return await _handle_process_started(db, doc)
    if action == "process_exited":
        return await _handle_process_exited(db, doc)
    return False


def _retention_days() -> int:
    raw = os.environ.get(
        "VIGIL_PROCESS_CHAIN_RETENTION_DAYS",
        str(settings.process_chain_retention_days),
    )
    try:
        return max(1, int(raw))
    except ValueError:
        return settings.process_chain_retention_days


async def _sweep_retention(db: AsyncSession) -> int:
    cutoff = datetime.now(UTC) - timedelta(days=_retention_days())
    result = await db.execute(delete(ProcessChain).where(ProcessChain.started_at < cutoff))
    return getattr(result, "rowcount", 0) or 0


async def _retention_loop() -> None:
    """Separate task: periodic sweep. Decoupled from Kafka consumption
    so a busy ingest stream doesn't starve the cleanup or vice-versa."""
    while True:
        try:
            await asyncio.sleep(RETENTION_SWEEP_INTERVAL_S)
        except asyncio.CancelledError:
            raise
        try:
            async with SessionLocal() as db:
                removed = await _sweep_retention(db)
                await db.commit()
            if removed:
                log.info("process_chain.retention.swept", removed=removed)
        except Exception:  # pragma: no cover — never let the loop die
            log.exception("process_chain.retention.failed")


class ProcessChainIndexer:
    def __init__(self) -> None:
        self.consumer: AIOKafkaConsumer | None = None
        self._stop = asyncio.Event()

    async def start(self) -> None:
        self.consumer = AIOKafkaConsumer(
            settings.topic_telemetry_normalized,
            bootstrap_servers=settings.kafka_brokers,
            group_id="process_chain_indexer",
            enable_auto_commit=False,
            auto_offset_reset="latest",
            session_timeout_ms=15_000,
            max_poll_interval_ms=300_000,
        )
        await self.consumer.start()
        log.info(
            "process_chain.indexer.start",
            topic=settings.topic_telemetry_normalized,
        )

    async def stop(self) -> None:
        self._stop.set()
        if self.consumer is not None:
            await self.consumer.stop()
        log.info("process_chain.indexer.stop")

    async def run(self) -> None:
        assert self.consumer is not None
        while not self._stop.is_set():
            try:
                msg = await asyncio.wait_for(self.consumer.getone(), timeout=1.0)
            except TimeoutError:
                continue
            if msg.value is None:
                await self.consumer.commit()
                continue
            try:
                doc = json.loads(msg.value)
            except Exception:
                log.exception("process_chain.indexer.decode_failed", offset=msg.offset)
                await self.consumer.commit()
                continue
            try:
                async with SessionLocal() as db:
                    await handle_doc(db, doc)
                    await db.commit()
            except Exception:
                log.exception("process_chain.indexer.handle_failed", offset=msg.offset)
            await self.consumer.commit()


async def run_forever() -> None:
    """Lifespan entry point. Mirrors `intel_ingest.run_forever` so
    `app.main` can wire it the same way."""
    worker = ProcessChainIndexer()
    sweep_task: asyncio.Task | None = None
    try:
        await worker.start()
    except asyncio.CancelledError:
        raise
    except Exception:
        log.exception("process_chain.indexer.start_failed")
        # Sleep before re-raising so the lifespan doesn't tight-loop on
        # a missing Kafka. Operator notices the missing rows via the
        # alert investigation UI and brings Kafka back up.
        await asyncio.sleep(30)
        raise
    sweep_task = asyncio.create_task(_retention_loop())
    try:
        await worker.run()
    finally:
        if sweep_task is not None:
            sweep_task.cancel()
            try:
                await sweep_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        await worker.stop()
