"""Submit a SHA-256 to a detonation provider (Phase 4 #4.4).

``submit_for_analysis`` is the public entry point. The flow:

  1. Look up the provider (operator-chosen, else the first enabled
     row in the actor's tenant).
  2. Pull the sample bytes from the quarantine object store
     (``vigil-artifacts`` bucket, key ``quarantine/<sha256>``).
  3. Decrypt the provider config in-process.
  4. Insert a ``DetonationJob`` row in ``queued`` state.
  5. Call the provider's ``submit`` — on success, flip the row to
     ``running`` and stash the provider task id; on transport error,
     flip to ``failed`` and stash the message.

Steps 4-5 are split so that a transport error against a flaky sandbox
still produces an audit-traceable job row. The poller worker is what
drives the row from ``running`` to ``verdict``/``failed``.

The sample-fetch path is intentionally permissive: managers in
single-host dev environments often don't have quarantined bytes
mirrored into MinIO. The submitter records the absence as a
``failed`` job rather than refusing the request, so the operator sees
the failure in the UI and can wire the upload path on their side.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models import DetonationJob, DetonationJobStatus, DetonationProvider
from app.services import minio as minio_svc
from app.services.detonation import get_client
from app.services.encryption import decrypt_config

log = structlog.get_logger()


class SampleUnavailableError(RuntimeError):
    """Couldn't locate the sample bytes for a sha256 in object storage."""


def _quarantine_key(sha256: str) -> str:
    """Conventional MinIO key for a quarantined sample.

    The agent's quarantine sweep is expected to upload the offending
    file's bytes into the artifacts bucket under this key shape — same
    bucket the Jobs engine writes acquisition artifacts to. Single
    location keeps the upload-proxy allowlist tight.
    """
    return f"quarantine/{sha256.lower()}"


async def _fetch_sample_bytes(sha256: str) -> bytes:
    """Read a quarantined sample's bytes out of MinIO.

    Raises ``SampleUnavailableError`` when the object isn't present so the
    caller can record a clean ``failed`` job row.
    """
    bucket = settings.minio_bucket_artifacts
    key = _quarantine_key(sha256)
    loop = asyncio.get_running_loop()

    def _go() -> bytes:
        client = minio_svc._client()
        resp = client.get_object(bucket_name=bucket, object_name=key)
        try:
            return resp.read()
        finally:
            resp.close()
            resp.release_conn()

    try:
        return await loop.run_in_executor(None, _go)
    except Exception as exc:  # noqa: BLE001
        raise SampleUnavailableError(
            f"sample bytes not available for sha256={sha256}: {exc}"
        ) from exc


async def _pick_provider(
    db: AsyncSession,
    *,
    tenant_id: UUID,
    provider_id: UUID | None,
) -> DetonationProvider | None:
    """Resolve which provider to submit to.

    ``provider_id`` explicit → look up by id and tenant; None → first
    enabled provider in the tenant.
    """
    if provider_id is not None:
        stmt = select(DetonationProvider).where(
            DetonationProvider.id == provider_id,
            DetonationProvider.tenant_id == tenant_id,
        )
        return (await db.execute(stmt)).scalar_one_or_none()
    stmt = (
        select(DetonationProvider)
        .where(
            DetonationProvider.tenant_id == tenant_id,
            DetonationProvider.enabled.is_(True),
        )
        .order_by(DetonationProvider.created_at.asc())
        .limit(1)
    )
    return (await db.execute(stmt)).scalar_one_or_none()


async def submit_for_analysis(
    db: AsyncSession,
    *,
    sha256: str,
    tenant_id: UUID,
    provider_id: UUID | None = None,
    sample_bytes: bytes | None = None,
    sample_name: str | None = None,
) -> DetonationJob:
    """Queue a sha256 for sandbox analysis.

    ``sample_bytes`` may be passed by callers that already have the
    bytes in hand (tests, an in-process detector that quarantined the
    sample on this manager). Otherwise the function pulls them from
    MinIO via ``_fetch_sample_bytes``.

    The returned ``DetonationJob`` is always flushed but never
    committed — the caller owns the transaction so the audit log + the
    job row land atomically.
    """
    provider = await _pick_provider(db, tenant_id=tenant_id, provider_id=provider_id)
    if provider is None:
        raise RuntimeError("no detonation provider available for tenant")

    job = DetonationJob(
        tenant_id=tenant_id,
        provider_id=provider.id,
        sha256=sha256.lower(),
        status=DetonationJobStatus.QUEUED,
        submitted_at=datetime.now(UTC),
    )
    db.add(job)
    await db.flush()

    config: dict[str, Any] = decrypt_config(provider.config_encrypted)

    if sample_bytes is None:
        try:
            sample_bytes = await _fetch_sample_bytes(sha256)
        except SampleUnavailableError as exc:
            job.status = DetonationJobStatus.FAILED
            job.error = str(exc)
            job.finished_at = datetime.now(UTC)
            await db.flush()
            return job

    client = get_client(provider.kind)
    try:
        external_id = await client.submit(config, sample_bytes, sample_name or f"{sha256}.bin")
    except NotImplementedError as exc:
        job.status = DetonationJobStatus.FAILED
        job.error = str(exc)
        job.finished_at = datetime.now(UTC)
        await db.flush()
        return job
    except Exception as exc:  # noqa: BLE001
        job.status = DetonationJobStatus.FAILED
        job.error = f"submit failed: {exc}"
        job.finished_at = datetime.now(UTC)
        await db.flush()
        log.warning(
            "detonation.submit_failed",
            sha256=sha256,
            provider_id=str(provider.id),
            error=str(exc),
        )
        return job

    job.external_id = external_id
    job.status = DetonationJobStatus.RUNNING
    await db.flush()
    log.info(
        "detonation.submitted",
        sha256=sha256,
        provider_id=str(provider.id),
        external_id=external_id,
    )
    return job
