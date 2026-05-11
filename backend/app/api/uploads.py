"""Artifact upload / download proxy (M23.k).

Agents PUT artifact bodies here using an HMAC-signed upload token they
got from the gRPC `RequestArtifactUpload` call. The manager validates
the token, streams the body to MinIO using its own credentials, and
returns 200. Avoids exposing MinIO directly to the agent network.

Analysts GET via /api/downloads/{artifact_id}; the manager streams the
object back. JWT-authenticated, host-scope checked.
"""

from __future__ import annotations

import asyncio
import io
from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Header, Request, status
from fastapi.responses import StreamingResponse
from minio.error import S3Error

from app.core.config import settings
from app.core.db import SessionLocal
from app.core.deps import DbSession, RequireAnalyst
from app.core.errors import bad_request, forbidden, not_found
from app.models import JobArtifact, JobRun
from app.services import audit
from app.services import minio as minio_svc
from app.services.scoping import host_visible_to
from app.services.uploads import verify_upload_token

# Agent → manager proxy; un-prefixed because the agent's HTTP client
# joins this onto its REST endpoint.
upload_router = APIRouter(prefix="/api", tags=["uploads"])

# Analyst → manager download.
download_router = APIRouter(prefix="/api", tags=["uploads"])


@upload_router.put("/uploads", status_code=status.HTTP_204_NO_CONTENT)
async def upload_artifact(
    request: Request,
    x_vigil_upload_token: str = Header(..., alias="X-Vigil-Upload-Token"),
    x_vigil_bucket: str = Header(..., alias="X-Vigil-Bucket"),
    x_vigil_object_key: str = Header(..., alias="X-Vigil-Object-Key"),
    content_length: int | None = Header(None),
) -> None:
    """Agent body → manager → MinIO. Validates the HMAC token + bucket
    allowlist + size cap before the write."""
    claim = verify_upload_token(x_vigil_upload_token)
    if claim is None:
        raise forbidden("invalid or expired upload token")
    if claim.bucket != x_vigil_bucket or claim.object_key != x_vigil_object_key:
        raise forbidden("token does not authorize this object")
    if claim.bucket not in {
        settings.minio_bucket_artifacts,
        settings.minio_bucket_snapshots,
    }:
        raise forbidden("bucket not in allowlist")
    if content_length is None:
        raise bad_request("content-length header required")
    if content_length < 0 or content_length > settings.upload_max_bytes:
        raise bad_request(f"content-length out of range (max {settings.upload_max_bytes})")

    # Read the full body into memory. For artifacts we expect up to
    # ~512 MiB; streaming-without-buffer to MinIO needs more plumbing
    # (multipart upload) and is a follow-up. Per-upload cap above
    # bounds memory growth.
    body = await request.body()
    if len(body) != content_length:
        raise bad_request("content-length did not match body size")

    # MinIO put_object is sync; run in the default executor so the
    # event loop stays responsive while large bodies upload.
    loop = asyncio.get_running_loop()

    def _go() -> None:
        client = minio_svc._client()
        client.put_object(
            bucket_name=claim.bucket,
            object_name=claim.object_key,
            data=io.BytesIO(body),
            length=len(body),
            # MinIO infers content-type from extension; agents send
            # plain JSON or octet-stream, both fine to default.
        )

    try:
        await loop.run_in_executor(None, _go)
    except S3Error as e:
        # Code/path captured in the manager log; agent gets a 500 so
        # it surfaces the failure on the JobRun.
        raise bad_request(f"minio put failed: {e.code}") from e


@download_router.get("/downloads/{artifact_id}")
async def download_artifact(
    artifact_id: UUID,
    db: DbSession,
    actor: RequireAnalyst,
) -> StreamingResponse:
    art = await db.get(JobArtifact, artifact_id)
    if art is None:
        raise not_found("artifact", str(artifact_id))
    run = await db.get(JobRun, art.job_run_id)
    if run is None:
        raise not_found("job_run", str(art.job_run_id))
    if not await host_visible_to(actor, run.host_id, db):
        raise forbidden("artifact's host is outside your groups")

    # Audit-log the access. We're streaming the bytes, so do this BEFORE
    # opening the upstream GET so the row is on disk even if MinIO
    # connection blips mid-stream.
    art.downloaded_by_user_id = actor.user.id
    art.downloaded_at = datetime.now(UTC)
    await audit.record(
        db,
        actor=actor,
        action="artifact.download",
        resource_type="artifact",
        resource_id=str(art.id),
        payload={"job_run_id": str(art.job_run_id), "size_bytes": art.size_bytes},
    )
    await db.commit()

    filename = art.object_key.rsplit("/", 1)[-1]

    def _iter():
        # Open a fresh MinIO connection per request — keeps streaming
        # response decoupled from the SQLAlchemy session.
        client = minio_svc._client()
        resp = client.get_object(bucket_name=art.bucket, object_name=art.object_key)
        try:
            yield from resp.stream(64 * 1024)
        finally:
            resp.close()
            resp.release_conn()

    return StreamingResponse(
        _iter(),
        media_type="application/octet-stream",
        headers={
            "Content-Length": str(art.size_bytes),
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


__all__ = ["upload_router", "download_router"]
# SessionLocal kept imported for parallelism with other modules; not
# used directly here because we rely on the DbSession dependency.
_ = SessionLocal
