"""Phase 3 #3.2: OpenSearch ILM + S3 cold archive.

Mocks OpenSearch by stubbing the AsyncOpenSearch client builder, and
MinIO by replacing its module-level ``_client`` factory with an
in-memory dict-backed fake. Exercises:

  * ``freeze_index`` scrolls every doc, compresses with zstd, uploads
    the NDJSON blob to the in-memory bucket, closes the index, and
    records a ``frozen`` archive_job row.
  * ``rehydrate`` decompresses + bulk-indexes back into
    ``<index>-rehydrated`` and registers the alias.
  * The freeze→rehydrate roundtrip preserves doc ``_source`` content.
  * NDJSON compression: the uploaded bytes are a valid zstd frame whose
    payload is line-delimited JSON.
  * API endpoints — list/jobs/rehydrate role gates + happy path.
  * The ILM ``ensure_ilm_policy`` issues a PUT to the ISM plugin and
    a put_index_template for the linking template.
"""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
import zstandard as zstd
from sqlalchemy import select

# ---------- In-memory MinIO fake ----------


class _FakeMinio:
    """Drop-in replacement for the minio.Minio client. Backs the bucket
    contents with a {(bucket, key): bytes} dict so freeze→rehydrate can
    round-trip through it without touching the real service."""

    def __init__(self) -> None:
        self.buckets: set[str] = set()
        self.objects: dict[tuple[str, str], bytes] = {}

    def bucket_exists(self, bucket: str) -> bool:
        return bucket in self.buckets

    def make_bucket(self, bucket: str) -> None:
        self.buckets.add(bucket)

    def put_object(
        self,
        *,
        bucket_name: str,
        object_name: str,
        data: io.BytesIO,
        length: int,
        content_type: str = "application/octet-stream",
    ) -> None:
        if bucket_name not in self.buckets:
            raise RuntimeError(f"bucket {bucket_name} missing")
        body = data.read()
        assert len(body) == length
        self.objects[(bucket_name, object_name)] = body

    def get_object(self, *, bucket_name: str, object_name: str):
        key = (bucket_name, object_name)
        if key not in self.objects:
            from minio.error import S3Error

            raise S3Error(
                code="NoSuchKey",
                message="not found",
                resource=object_name,
                request_id="",
                host_id="",
                response=MagicMock(),
            )
        data = self.objects[key]

        class _Resp:
            def __init__(self, b: bytes) -> None:
                self._b = b

            def read(self) -> bytes:
                return self._b

            def close(self) -> None:
                pass

            def release_conn(self) -> None:
                pass

        return _Resp(data)


# ---------- In-memory OpenSearch fake ----------


class _FakeIndicesNamespace:
    """The AsyncOpenSearch client's `.indices` namespace exposes
    methods like `close`, `exists`, `create`, `put_alias`, etc. We
    deliberately keep this distinct from the parent's
    `indices_data` dict so the parent can keep using a plain dict for
    its own bookkeeping."""

    def __init__(self, parent: _FakeOS) -> None:
        self.parent = parent

    async def close(self, *, index: str) -> dict[str, Any]:
        self.parent.closed.add(index)
        return {"acknowledged": True}

    async def exists(self, *, index: str) -> bool:
        return index in self.parent.indices_data

    async def create(self, *, index: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        self.parent.indices_data.setdefault(index, [])
        return {"acknowledged": True}

    async def delete(self, *, index: str) -> dict[str, Any]:
        self.parent.indices_data.pop(index, None)
        return {"acknowledged": True}

    async def put_alias(self, *, index: str, name: str) -> dict[str, Any]:
        self.parent.aliases.setdefault(name, []).append(index)
        return {"acknowledged": True}

    async def put_index_template(self, *, name: str, body: dict[str, Any]) -> dict[str, Any]:
        self.parent.put_templates.append((name, body))
        return {"acknowledged": True}

    async def exists_index_template(self, *, name: str) -> bool:
        return False


class _FakeCat:
    def __init__(self, parent: _FakeOS) -> None:
        self.parent = parent

    async def indices(
        self,
        *,
        index: str = "",
        params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        del params  # accepted for signature compat
        del index
        return [{"index": name} for name in self.parent.indices_data]


class _FakeTransport:
    def __init__(self, parent: _FakeOS) -> None:
        self.parent = parent

    async def perform_request(self, method: str, path: str, body: Any = None) -> Any:
        self.parent.transport_calls.append((method, path, body))
        return {"acknowledged": True}


class _FakeOS:
    """Minimal AsyncOpenSearch fake. Backing store is the per-index
    list of hits, keyed by index name. The `.indices` namespace,
    `.cat`, and `.transport` mirror the AsyncOpenSearch surface our
    archive service touches."""

    def __init__(self) -> None:
        self.indices_data: dict[str, list[dict[str, Any]]] = {}
        self.aliases: dict[str, list[str]] = {}
        self.closed: set[str] = set()
        self.indexed: list[dict[str, Any]] = []
        self.transport_calls: list[tuple[str, str, Any]] = []
        self.put_templates: list[tuple[str, dict[str, Any]]] = []

        self.indices = _FakeIndicesNamespace(self)
        self.cat = _FakeCat(self)
        self.transport = _FakeTransport(self)

    async def search(
        self,
        *,
        index: str,
        body: dict[str, Any],
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        del body, params
        docs = self.indices_data.get(index, [])
        scroll_id = f"scroll-{index}"
        return {"_scroll_id": scroll_id, "hits": {"hits": docs}}

    async def scroll(
        self,
        *,
        body: dict[str, Any],
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        del params
        # Second call returns no more docs — tests use single-batch indices.
        return {"_scroll_id": body.get("scroll_id"), "hits": {"hits": []}}

    async def bulk(
        self,
        *,
        body: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        del params
        # _bulk wire format: alternating action / source NDJSON lines.
        lines = [ln for ln in body.splitlines() if ln]
        for i in range(0, len(lines), 2):
            meta = json.loads(lines[i])
            src = json.loads(lines[i + 1]) if i + 1 < len(lines) else {}
            target = meta["index"]["_index"]
            self.indices_data.setdefault(target, []).append(
                {"_id": meta["index"].get("_id"), "_source": src}
            )
            self.indexed.append({"_index": target, "_id": meta["index"].get("_id"), "_source": src})
        return {"errors": False}

    async def close(self) -> None:
        pass


# ---------- Fixtures ----------


@pytest.fixture
def fake_minio(monkeypatch: pytest.MonkeyPatch) -> _FakeMinio:
    """Replace the module-level _client builder with our fake."""
    fake = _FakeMinio()

    # Pre-create the archive bucket so put_object doesn't raise when
    # the service skips the make_bucket idempotency path.
    fake.make_bucket("vigil-archive")

    def _factory() -> _FakeMinio:
        return fake

    monkeypatch.setattr("app.services.minio._client", _factory)
    monkeypatch.setattr("app.services.archive._minio_client", _factory)
    return fake


@pytest.fixture
def fake_os(monkeypatch: pytest.MonkeyPatch) -> _FakeOS:
    fake = _FakeOS()

    def _factory() -> _FakeOS:
        return fake

    monkeypatch.setattr("app.services.opensearch._client", _factory)
    monkeypatch.setattr("app.services.archive.os_svc._client", _factory)
    return fake


# ---------- Service-layer ----------


@pytest.mark.asyncio
async def test_freeze_index_uploads_compressed_ndjson(db_session, fake_minio, fake_os):
    from app.models import ArchiveJob
    from app.services.archive import freeze_index

    fake_os.indices_data["telemetry-20260101"] = [
        {"_id": "a", "_source": {"event": {"id": "a"}, "message": "first"}},
        {"_id": "b", "_source": {"event": {"id": "b"}, "message": "second"}},
    ]

    job = await freeze_index("telemetry-20260101", db_session)
    await db_session.flush()

    assert job.status == "frozen", job.error
    assert job.doc_count == 2
    assert job.s3_key == "telemetry-20260101.ndjson.zst"
    assert "telemetry-20260101" in fake_os.closed

    # Blob is in the fake bucket and decompresses to NDJSON.
    blob = fake_minio.objects[("vigil-archive", "telemetry-20260101.ndjson.zst")]
    raw = zstd.ZstdDecompressor().stream_reader(io.BytesIO(blob)).read()
    lines = raw.decode("utf-8").splitlines()
    assert len(lines) == 2
    rows = [json.loads(ln) for ln in lines]
    assert {r["_id"] for r in rows} == {"a", "b"}
    assert rows[0]["_source"]["message"] in {"first", "second"}

    # The row landed in the DB.
    found = await db_session.get(ArchiveJob, job.id)
    assert found is not None
    assert found.status == "frozen"


@pytest.mark.asyncio
async def test_freeze_index_records_failure_on_scroll_error(db_session, fake_minio, fake_os):
    """A flaky OpenSearch shouldn't leave a half-written row — the job
    flips to ``failed`` with the error captured."""
    from app.services.archive import freeze_index

    async def _boom(*a: Any, **kw: Any) -> Any:
        raise RuntimeError("scroll exploded")

    fake_os.search = _boom  # type: ignore[method-assign]

    job = await freeze_index("telemetry-20260101", db_session)
    assert job.status == "failed"
    assert job.error and "scroll exploded" in job.error
    assert job.finished_at is not None


@pytest.mark.asyncio
async def test_rehydrate_roundtrip(db_session, fake_minio, fake_os):
    """freeze → drop the data → rehydrate and confirm the docs come
    back into `<index>-rehydrated` with the source alias attached."""
    from app.services.archive import freeze_index, rehydrate

    fake_os.indices_data["telemetry-20260101"] = [
        {"_id": "doc1", "_source": {"event": {"id": "doc1"}, "host": {"id": "h1"}}},
        {"_id": "doc2", "_source": {"event": {"id": "doc2"}, "host": {"id": "h2"}}},
    ]
    job = await freeze_index("telemetry-20260101", db_session)
    assert job.status == "frozen"

    # Simulate the cold index being closed/deleted — the rehydrate
    # should not depend on the original index existing.
    fake_os.indices_data.pop("telemetry-20260101", None)

    target = await rehydrate(job, db_session)
    assert target == "telemetry-20260101-rehydrated"
    assert job.status == "rehydrated"
    docs = fake_os.indices_data["telemetry-20260101-rehydrated"]
    assert {d["_id"] for d in docs} == {"doc1", "doc2"}
    # Alias points back at the rehydrated index.
    assert "telemetry-20260101-rehydrated" in fake_os.aliases["telemetry-20260101"]


@pytest.mark.asyncio
async def test_rehydrate_fails_without_s3_key(db_session, fake_minio, fake_os):
    from app.models import ArchiveJob, ArchiveJobStatus
    from app.services.archive import rehydrate

    job = ArchiveJob(
        index_name="telemetry-20260101",
        status=ArchiveJobStatus.FROZEN.value,
        s3_key=None,
    )
    db_session.add(job)
    await db_session.flush()

    with pytest.raises(RuntimeError, match="no s3_key"):
        await rehydrate(job, db_session)


# ---------- ILM policy ----------


@pytest.mark.asyncio
async def test_ensure_ilm_policy_puts_policy_and_template():
    from app.services.opensearch import ensure_ilm_policy

    fake = _FakeOS()
    await ensure_ilm_policy(fake)  # type: ignore[arg-type]

    # Policy PUT went to the ISM plugin URL.
    transport_calls = fake.transport_calls
    assert len(transport_calls) == 1
    method, path, body = transport_calls[0]
    assert method == "PUT"
    assert path == "/_plugins/_ism/policies/vigil_telemetry_ilm"
    assert body and "policy" in body
    states = {s["name"] for s in body["policy"]["states"]}
    assert states == {"hot", "warm", "cold", "delete"}

    # Linking index template was applied via put_index_template.
    assert any(name == "vigil_telemetry" for name, _ in fake.put_templates)


# ---------- list_cold_indices ----------


@pytest.mark.asyncio
async def test_list_cold_indices_picks_only_past_cutoff(fake_os):
    from app.services.archive import list_cold_indices

    today = datetime.now(UTC)
    fresh = (today - timedelta(days=10)).strftime("telemetry-%Y%m%d")
    cold = (today - timedelta(days=120)).strftime("telemetry-%Y%m%d")
    cold_alerts = (today - timedelta(days=120)).strftime("alerts-%Y%m%d")
    fake_os.indices_data[fresh] = []
    fake_os.indices_data[cold] = []
    fake_os.indices_data[cold_alerts] = []
    fake_os.indices_data["sigma-rules"] = []  # ignored — no date stripe

    out = await list_cold_indices()
    assert set(out) == {cold, cold_alerts}


# ---------- API ----------


@pytest.mark.asyncio
async def test_list_frozen_admin_sees_frozen_only(
    http_client, admin_headers, db_session, fake_minio, fake_os
):
    from app.models import ArchiveJob, ArchiveJobStatus

    db_session.add(
        ArchiveJob(
            index_name="telemetry-20260101",
            status=ArchiveJobStatus.FROZEN.value,
            s3_key="telemetry-20260101.ndjson.zst",
        )
    )
    db_session.add(
        ArchiveJob(
            index_name="telemetry-20260102",
            status=ArchiveJobStatus.FAILED.value,
            error="kaboom",
        )
    )
    await db_session.flush()

    resp = await http_client.get("/api/archive", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    statuses = {r["status"] for r in body}
    assert statuses == {"frozen"}
    assert any(r["index_name"] == "telemetry-20260101" for r in body)


@pytest.mark.asyncio
async def test_list_jobs_includes_all_states(http_client, admin_headers, db_session):
    from app.models import ArchiveJob, ArchiveJobStatus

    db_session.add(
        ArchiveJob(
            index_name="telemetry-20260101",
            status=ArchiveJobStatus.FROZEN.value,
            s3_key="telemetry-20260101.ndjson.zst",
        )
    )
    db_session.add(
        ArchiveJob(
            index_name="telemetry-20260102",
            status=ArchiveJobStatus.FAILED.value,
            error="kaboom",
        )
    )
    await db_session.flush()
    resp = await http_client.get("/api/archive/jobs", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    statuses = {r["status"] for r in body}
    assert statuses == {"frozen", "failed"}


@pytest.mark.asyncio
async def test_rehydrate_admin_only(http_client, admin_headers, analyst_headers, db_session):
    from app.models import ArchiveJob, ArchiveJobStatus

    job = ArchiveJob(
        index_name="telemetry-20260101",
        status=ArchiveJobStatus.FROZEN.value,
        s3_key="telemetry-20260101.ndjson.zst",
    )
    db_session.add(job)
    await db_session.flush()

    resp = await http_client.post(f"/api/archive/{job.id}/rehydrate", headers=analyst_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_rehydrate_unknown_404(http_client, admin_headers):
    resp = await http_client.post(f"/api/archive/{uuid4()}/rehydrate", headers=admin_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_rehydrate_non_frozen_400(http_client, admin_headers, db_session):
    from app.models import ArchiveJob, ArchiveJobStatus

    job = ArchiveJob(
        index_name="telemetry-20260101",
        status=ArchiveJobStatus.PENDING.value,
    )
    db_session.add(job)
    await db_session.flush()

    resp = await http_client.post(f"/api/archive/{job.id}/rehydrate", headers=admin_headers)
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_rehydrate_audits(http_client, admin_headers, db_session, fake_minio, fake_os):
    """A successful rehydrate POST writes an audit row before the
    background task runs."""
    from app.models import ArchiveJob, ArchiveJobStatus, AuditLog

    job = ArchiveJob(
        index_name="telemetry-20260101",
        status=ArchiveJobStatus.FROZEN.value,
        s3_key="telemetry-20260101.ndjson.zst",
    )
    db_session.add(job)
    await db_session.flush()

    # Patch the background-task entry point so the test's session
    # isn't fighting with a parallel SessionLocal lookup.
    with patch("app.api.archive._do_rehydrate", new=AsyncMock()):
        resp = await http_client.post(f"/api/archive/{job.id}/rehydrate", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "rehydrating"

    rows = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.action == "archive.rehydrate",
                    AuditLog.resource_id == str(job.id),
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
    payload = rows[0].payload or {}
    assert payload.get("s3_key") == "telemetry-20260101.ndjson.zst"
    assert payload.get("target_index") == "telemetry-20260101-rehydrated"


# ---------- Worker ----------


@pytest.mark.asyncio
async def test_worker_run_once_freezes_new_indices(db_session, fake_minio, fake_os):
    """The worker freezes cold indices it hasn't seen before and
    leaves already-frozen ones alone."""
    from contextlib import asynccontextmanager

    from app.models import ArchiveJob, ArchiveJobStatus
    from app.workers.archive_worker import _run_once

    today = datetime.now(UTC)
    cold_a = (today - timedelta(days=120)).strftime("telemetry-%Y%m%d")
    cold_b = (today - timedelta(days=200)).strftime("alerts-%Y%m%d")
    fake_os.indices_data[cold_a] = [
        {"_id": "x", "_source": {"event": {"id": "x"}}},
    ]
    fake_os.indices_data[cold_b] = [
        {"_id": "y", "_source": {"event": {"id": "y"}}},
    ]
    # Pre-existing frozen row for cold_b — worker should skip it.
    db_session.add(
        ArchiveJob(
            index_name=cold_b,
            status=ArchiveJobStatus.FROZEN.value,
            s3_key=f"{cold_b}.ndjson.zst",
        )
    )
    await db_session.flush()

    @asynccontextmanager
    async def _sm():
        yield db_session

    n = await _run_once(session_maker=_sm)
    assert n == 1
    rows = (
        (await db_session.execute(select(ArchiveJob).where(ArchiveJob.index_name == cold_a)))
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].status == "frozen"
