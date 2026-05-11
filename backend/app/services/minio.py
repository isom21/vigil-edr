"""MinIO (S3-compatible) object-store helpers for the Jobs engine.

M23.a: the manager owns the bucket credentials. It hands agents
short-lived presigned PUT URLs to upload artifacts/snapshots, and
hands analysts short-lived presigned GET URLs to download them. No
long-lived credentials ever leave the manager process.

The MinIO client itself is sync; we run the few presign + stat calls
in a thread executor when invoked from FastAPI/asyncio code so the
event loop isn't blocked on socket I/O.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta
from functools import lru_cache

from minio import Minio
from minio.error import S3Error

from app.core.config import settings


@lru_cache(maxsize=1)
def _client() -> Minio:
    return Minio(
        endpoint=settings.minio_endpoint,
        access_key=settings.minio_access_key,
        secret_key=settings.minio_secret_key,
        secure=settings.minio_secure,
    )


def _ensure_bucket(bucket: str) -> None:
    """Idempotently create the bucket. The minio-init container should
    already have done this, but devs running the manager outside compose
    benefit from a manager-side fallback."""
    cli = _client()
    if not cli.bucket_exists(bucket):
        cli.make_bucket(bucket)


async def presigned_put(
    *,
    bucket: str,
    key: str,
    ttl_seconds: int | None = None,
) -> str:
    """Hand an uploader a presigned PUT URL. Default TTL is the value
    set in settings.minio_presign_put_ttl_seconds."""
    ttl = ttl_seconds or settings.minio_presign_put_ttl_seconds
    loop = asyncio.get_running_loop()

    def _go() -> str:
        _ensure_bucket(bucket)
        return _client().presigned_put_object(
            bucket_name=bucket,
            object_name=key,
            expires=timedelta(seconds=ttl),
        )

    return await loop.run_in_executor(None, _go)


async def presigned_get(
    *,
    bucket: str,
    key: str,
    ttl_seconds: int | None = None,
    download_filename: str | None = None,
) -> str:
    """Hand a downloader a presigned GET URL. If `download_filename` is
    provided, the URL also forces a Content-Disposition so the browser
    saves with that name rather than the bare object key."""
    ttl = ttl_seconds or settings.minio_presign_get_ttl_seconds
    loop = asyncio.get_running_loop()

    response_headers: dict[str, str | list[str] | tuple[str]] | None = None
    if download_filename:
        # Quote the filename per RFC 6266 ext-value rules. The Python
        # minio SDK accepts a dict and forwards as response-* params.
        safe = download_filename.replace('"', "")
        response_headers = {
            "response-content-disposition": f'attachment; filename="{safe}"',
        }

    def _go() -> str:
        return _client().presigned_get_object(
            bucket_name=bucket,
            object_name=key,
            expires=timedelta(seconds=ttl),
            response_headers=response_headers,
        )

    return await loop.run_in_executor(None, _go)


async def stat_object(*, bucket: str, key: str) -> dict[str, str | int]:
    """Return size + etag + last_modified for an artifact. Used by the
    Jobs engine to record the final size + hash once the agent's upload
    is confirmed (the agent reports its own SHA-256; we cross-check the
    HEAD size and stash the MinIO etag for storage-side auditing)."""
    loop = asyncio.get_running_loop()

    def _go() -> dict[str, str | int]:
        st = _client().stat_object(bucket_name=bucket, object_name=key)
        return {
            "size": st.size or 0,
            "etag": (st.etag or "").strip('"'),
            "last_modified": st.last_modified.isoformat() if st.last_modified else "",
        }

    return await loop.run_in_executor(None, _go)


async def remove_object(*, bucket: str, key: str) -> None:
    """Best-effort delete used by retention / TTL sweeps. Swallows
    NoSuchKey so callers don't have to special-case 'already gone'."""
    loop = asyncio.get_running_loop()

    def _go() -> None:
        try:
            _client().remove_object(bucket_name=bucket, object_name=key)
        except S3Error as e:
            if e.code not in {"NoSuchKey", "NoSuchBucket"}:
                raise

    await loop.run_in_executor(None, _go)
