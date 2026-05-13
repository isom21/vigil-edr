"""Phase 3 #3.2: S3 cold archive for OpenSearch indices.

Two operations:

  * ``freeze_index(index_name, db)`` — scrolls every document out of an
    OpenSearch index, compresses the NDJSON stream with zstd, uploads
    the blob to MinIO under ``<index_name>.ndjson.zst``, closes the
    index, and records the result in ``archive_job``. Used by the
    daily archive worker and operator-driven freezes via the API.
  * ``rehydrate(job, db)`` — downloads the blob, re-indexes its
    documents back into ``<index_name>-rehydrated``, and registers a
    short-lived alias so existing queries pick the rehydrated data up
    without referring to the suffix.

Both paths write through the existing ``ArchiveJob`` row so the UI's
list view can render real-time progress (status field), and so a crash
mid-freeze leaves a ``failed`` row with the error rather than orphaning
state. The OpenSearch interactions go through the shared
``app.services.opensearch._client`` builder; the MinIO leg uses
the existing MinIO client + executor pattern from ``app.services.minio``.
"""

from __future__ import annotations

import asyncio
import io
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import structlog
import zstandard as zstd
from minio.error import S3Error
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models import ArchiveJob, ArchiveJobStatus
from app.services import opensearch as os_svc
from app.services.minio import _client as _minio_client

log = structlog.get_logger()

# Conservative scroll batch size. Telemetry docs are <2 KiB on average,
# so 1000 docs/batch keeps each scroll RTT under ~2 MiB even for the
# fattest indices.
_SCROLL_SIZE = 1000
_SCROLL_KEEPALIVE = "2m"


def _archive_key(index_name: str) -> str:
    """Stable S3 key for an index's frozen blob. Single-level layout —
    the index name itself contains the date stripe, so a flat namespace
    is fine and saves a bucket listing for "is this frozen yet?"."""
    return f"{index_name}.ndjson.zst"


def _ensure_archive_bucket() -> None:
    cli = _minio_client()
    if not cli.bucket_exists(settings.archive_bucket):
        cli.make_bucket(settings.archive_bucket)


async def _scroll_all(index_name: str) -> tuple[bytes, int]:
    """Scroll every doc out of ``index_name`` and return the
    zstd-compressed NDJSON bytes plus a doc count.

    Buffers in memory because (a) the MinIO put_object API wants a
    length-prefixed stream and (b) the largest daily index in dev is
    ~50 MiB compressed, well under the manager's memory budget. If
    that ceiling moves we'd switch to multipart upload + a streaming
    zstd compressor.
    """
    client = os_svc._client()
    raw_buf = io.BytesIO()
    compressor = zstd.ZstdCompressor(level=10)
    # `stream_writer` lets us write NDJSON line by line and have zstd
    # flush blocks behind it. We flush with FLUSH_FRAME (not close) to
    # emit the frame epilogue without closing the underlying BytesIO —
    # python-zstandard's stream_writer.close() also closes its wrapped
    # stream, which would make buf.getvalue() raise.
    writer = compressor.stream_writer(raw_buf)
    doc_count = 0
    try:
        resp = await client.search(
            index=index_name,
            body={"query": {"match_all": {}}},
            params={"scroll": _SCROLL_KEEPALIVE, "size": _SCROLL_SIZE},
        )
        while True:
            hits = resp.get("hits", {}).get("hits", [])
            if not hits:
                break
            for h in hits:
                # Persist the bare _source plus the original _id so a
                # later rehydrate can preserve doc identity.
                row = {"_id": h.get("_id"), "_source": h.get("_source") or {}}
                writer.write((json.dumps(row, separators=(",", ":")) + "\n").encode("utf-8"))
                doc_count += 1
            scroll_id = resp.get("_scroll_id")
            if not scroll_id:
                break
            resp = await client.scroll(
                body={"scroll_id": scroll_id},
                params={"scroll": _SCROLL_KEEPALIVE},
            )
        writer.flush(zstd.FLUSH_FRAME)
    finally:
        await client.close()
    return raw_buf.getvalue(), doc_count


async def _put_archive(index_name: str, blob: bytes) -> str:
    """Upload the compressed NDJSON to MinIO. Returns the object key."""
    key = _archive_key(index_name)
    loop = asyncio.get_running_loop()

    def _go() -> None:
        _ensure_archive_bucket()
        _minio_client().put_object(
            bucket_name=settings.archive_bucket,
            object_name=key,
            data=io.BytesIO(blob),
            length=len(blob),
            content_type="application/zstd",
        )

    await loop.run_in_executor(None, _go)
    return key


async def _close_index(index_name: str) -> None:
    """Close the OpenSearch index so it stops serving searches +
    consuming heap. Safe to skip on rehydrate-only environments."""
    client = os_svc._client()
    try:
        await client.indices.close(index=index_name)
    finally:
        await client.close()


async def freeze_index(index_name: str, db: AsyncSession) -> ArchiveJob:
    """Freeze ``index_name`` to MinIO + close it. Writes the state
    machine into ``archive_job`` row by row so operators can see
    progress mid-flight.

    Idempotent at the index level: a previous successful freeze leaves
    a ``frozen`` row with the same ``index_name`` + a populated
    ``s3_key``. Callers should check before invoking — we'll happily
    overwrite the blob if asked to.
    """
    job = ArchiveJob(
        index_name=index_name,
        status=ArchiveJobStatus.FREEZING.value,
        started_at=datetime.now(UTC),
    )
    db.add(job)
    await db.flush()

    try:
        blob, doc_count = await _scroll_all(index_name)
        key = await _put_archive(index_name, blob)
        await _close_index(index_name)
        job.status = ArchiveJobStatus.FROZEN.value
        job.s3_key = key
        job.doc_count = doc_count
        job.finished_at = datetime.now(UTC)
        log.info(
            "archive.freeze.ok",
            index=index_name,
            doc_count=doc_count,
            bytes=len(blob),
            s3_key=key,
        )
    except Exception as exc:  # noqa: BLE001
        job.status = ArchiveJobStatus.FAILED.value
        job.error = str(exc)
        job.finished_at = datetime.now(UTC)
        log.warning("archive.freeze.failed", index=index_name, error=str(exc))
    return job


async def _fetch_archive(s3_key: str) -> bytes:
    loop = asyncio.get_running_loop()

    def _go() -> bytes:
        try:
            resp = _minio_client().get_object(
                bucket_name=settings.archive_bucket, object_name=s3_key
            )
            try:
                return resp.read()
            finally:
                resp.close()
                resp.release_conn()
        except S3Error as exc:
            raise RuntimeError(f"archive blob missing: {exc.code}") from exc

    return await loop.run_in_executor(None, _go)


async def rehydrate(job: ArchiveJob, db: AsyncSession) -> str:
    """Pull the frozen blob back into OpenSearch under
    ``<index>-rehydrated`` and register an alias matching the original
    index name so downstream queries find it without code changes.

    Returns the rehydrated index name.
    """
    if not job.s3_key:
        raise RuntimeError("rehydrate: archive_job has no s3_key")
    target_index = f"{job.index_name}-rehydrated"

    job.status = ArchiveJobStatus.REHYDRATING.value
    job.started_at = datetime.now(UTC)
    await db.flush()

    try:
        blob = await _fetch_archive(job.s3_key)
        # The frames we write with flush(FLUSH_FRAME) lack the content
        # size header that one-shot decompress() requires, so we go
        # through stream_reader which doesn't need it.
        decompressor = zstd.ZstdDecompressor()
        raw = decompressor.stream_reader(io.BytesIO(blob)).read()

        client = os_svc._client()
        try:
            # Recreate the target index empty so a partial rehydrate
            # can be rerun without leaving stale docs.
            if await client.indices.exists(index=target_index):
                await client.indices.delete(index=target_index)
            await client.indices.create(index=target_index)

            # NDJSON-in, bulk-out. Build a single bulk body and POST
            # in one shot — the indices we freeze are bounded by the
            # daily rollover so the body fits comfortably.
            bulk_lines: list[str] = []
            for line in raw.decode("utf-8").splitlines():
                if not line:
                    continue
                row = json.loads(line)
                src = row.get("_source") or {}
                meta: dict[str, Any] = {"index": {"_index": target_index}}
                if row.get("_id"):
                    meta["index"]["_id"] = row["_id"]
                bulk_lines.append(json.dumps(meta, separators=(",", ":")))
                bulk_lines.append(json.dumps(src, separators=(",", ":")))
            if bulk_lines:
                # Trailing newline is mandatory per the _bulk wire format.
                body = "\n".join(bulk_lines) + "\n"
                await client.bulk(body=body, params={"refresh": "wait_for"})

            # Alias mirrors the original index name. Existing queries
            # that hit `telemetry-*` automatically include rehydrated
            # data; analysts don't need to know about the suffix.
            try:
                await client.indices.put_alias(index=target_index, name=job.index_name)
            except Exception:  # pragma: no cover — alias may already exist
                pass
        finally:
            await client.close()

        job.status = ArchiveJobStatus.REHYDRATED.value
        job.finished_at = datetime.now(UTC)
        log.info("archive.rehydrate.ok", index=job.index_name, target=target_index)
        return target_index
    except Exception as exc:  # noqa: BLE001
        job.status = ArchiveJobStatus.FAILED.value
        job.error = str(exc)
        job.finished_at = datetime.now(UTC)
        log.warning("archive.rehydrate.failed", index=job.index_name, error=str(exc))
        raise


async def list_cold_indices() -> list[str]:
    """Return telemetry-/alerts- indices whose age exceeds the cold-tier
    boundary. Worker uses this to pick freeze candidates each tick.

    The cold-tier age is measured against the ``YYYYMMDD`` stripe in the
    index name rather than the OpenSearch creation timestamp — that
    timestamp moves around if an index is reopened, and the daily roll
    name is the operator-visible fact anyway.
    """
    client = os_svc._client()
    try:
        cats = await client.cat.indices(index="telemetry-*,alerts-*", params={"format": "json"})
    finally:
        await client.close()
    cutoff_days = settings.ilm_cold_days
    now = datetime.now(UTC)
    out: list[str] = []
    for row in cats or []:
        name = row.get("index")
        if not name:
            continue
        # telemetry-YYYYMMDD / alerts-YYYYMMDD — strip the prefix and
        # parse. Ignore anything else (e.g. sigma-rules) defensively.
        stripe = name.rsplit("-", 1)[-1]
        if len(stripe) != 8 or not stripe.isdigit():
            continue
        try:
            d = datetime.strptime(stripe, "%Y%m%d").replace(tzinfo=UTC)
        except ValueError:
            continue
        age_days = (now - d).days
        if age_days >= cutoff_days:
            out.append(name)
    return out


async def already_frozen(db: AsyncSession, index_name: str) -> bool:
    """True iff there's a ``frozen`` row for this index. The freeze
    worker uses this to skip indices it's already shipped."""
    from sqlalchemy import select

    row = (
        await db.execute(
            select(ArchiveJob.id).where(
                ArchiveJob.index_name == index_name,
                ArchiveJob.status == ArchiveJobStatus.FROZEN.value,
            )
        )
    ).first()
    return row is not None


async def get_job(db: AsyncSession, job_id: UUID) -> ArchiveJob | None:
    return await db.get(ArchiveJob, job_id)
