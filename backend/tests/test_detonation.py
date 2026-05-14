"""Phase 4 #4.4 network sandbox / detonation.

Covers:
  * Submitter records a queued ``DetonationJob`` row, then flips it to
    ``running`` on a successful Cuckoo submit.
  * Polling a running task through to a Cuckoo verdict (score=7) flips
    the row to ``status=verdict``, ``verdict_label=malicious``, and
    inserts a fresh IocEntry under the synthetic per-tenant
    ``detonation:<tenant>`` feed (lazy-created).
  * A 500 from Cuckoo's view endpoint flips the row to ``failed`` and
    records the error message.
  * The VMRay + ANY.RUN stubs raise NotImplementedError cleanly so the
    submitter records a ``failed`` job row rather than crashing the
    request.
  * Non-admin actors get 403 on the manual submit endpoint.
  * The Fernet config round-trips through the shared encryption helper.
"""

from __future__ import annotations

import base64
import os
from contextlib import asynccontextmanager

import pytest
import pytest_asyncio
import respx
from httpx import Response


def _test_session_maker(db_session):
    @asynccontextmanager
    async def _maker():
        yield db_session

    return _maker


# ---------- crypto round-trip ----------


def test_provider_config_round_trip(monkeypatch) -> None:
    """Encrypt/decrypt is symmetric under the dev-default key."""
    from app.core import config
    from app.services.encryption import decrypt_config, encrypt_config

    monkeypatch.setattr(config.settings, "notification_encryption_key", "")
    blob = encrypt_config({"base_url": "https://cuckoo.example.com", "api_token": "abc"})
    assert decrypt_config(blob) == {
        "base_url": "https://cuckoo.example.com",
        "api_token": "abc",
    }


# ---------- DB fixtures ----------


@pytest_asyncio.fixture
async def _provider(db_session):
    from app.models import DetonationProvider, DetonationProviderKind
    from app.services.encryption import encrypt_config

    config = {"base_url": "https://cuckoo.example.com", "api_token": "tok-xyz"}
    p = DetonationProvider(
        kind=DetonationProviderKind.CUCKOO.value,
        name=f"cuckoo-test-{os.urandom(3).hex()}",
        config_encrypted=encrypt_config(config),
        enabled=True,
    )
    db_session.add(p)
    await db_session.flush()
    return p


@pytest_asyncio.fixture
async def _vmray_provider(db_session):
    from app.models import DetonationProvider, DetonationProviderKind
    from app.services.encryption import encrypt_config

    p = DetonationProvider(
        kind=DetonationProviderKind.VMRAY.value,
        name=f"vmray-test-{os.urandom(3).hex()}",
        config_encrypted=encrypt_config({"base_url": "https://vmray.example.com"}),
        enabled=True,
    )
    db_session.add(p)
    await db_session.flush()
    return p


@pytest_asyncio.fixture
async def _anyrun_provider(db_session):
    from app.models import DetonationProvider, DetonationProviderKind
    from app.services.encryption import encrypt_config

    p = DetonationProvider(
        kind=DetonationProviderKind.ANYRUN.value,
        name=f"anyrun-test-{os.urandom(3).hex()}",
        config_encrypted=encrypt_config({"base_url": "https://anyrun.example.com"}),
        enabled=True,
    )
    db_session.add(p)
    await db_session.flush()
    return p


# ---------- submitter ----------


@pytest.mark.asyncio
@respx.mock
async def test_submit_records_queued_then_running(db_session, _provider) -> None:
    """Successful submit flips the job from queued → running and stashes
    the provider's task id."""
    from app.models import DetonationJobStatus
    from app.models.tenant import DEFAULT_TENANT_ID
    from app.services.detonation.submitter import submit_for_analysis

    respx.post("https://cuckoo.example.com/tasks/create/file").mock(
        return_value=Response(200, json={"task_id": 4242})
    )

    sha = "a" * 64
    job = await submit_for_analysis(
        db_session,
        sha256=sha,
        tenant_id=DEFAULT_TENANT_ID,
        sample_bytes=b"MZ\x90\x00...",
        sample_name="evil.exe",
    )
    assert job.sha256 == sha
    assert job.status == DetonationJobStatus.RUNNING
    assert job.external_id == "4242"
    assert job.provider_id == _provider.id
    assert job.error is None


@pytest.mark.asyncio
@respx.mock
async def test_poll_verdict_malicious_creates_ioc(db_session, _provider) -> None:
    """A Cuckoo verdict with score >= 5 flips the row to verdict +
    label=malicious AND materialises an IocEntry under a synthetic
    detonation feed."""
    from sqlalchemy import select

    from app.models import DetonationJobStatus, IocEntry, IocKind
    from app.models.tenant import DEFAULT_TENANT_ID
    from app.services.detonation.submitter import submit_for_analysis
    from app.workers.detonation_poller import _run_once

    respx.post("https://cuckoo.example.com/tasks/create/file").mock(
        return_value=Response(200, json={"task_id": 99})
    )
    respx.get("https://cuckoo.example.com/tasks/view/99").mock(
        return_value=Response(200, json={"task": {"status": "reported"}})
    )
    respx.get("https://cuckoo.example.com/tasks/report/99").mock(
        return_value=Response(
            200,
            json={
                "info": {"score": 7.5},
                "signatures": [{"name": "ransomware_files"}],
            },
        )
    )

    sha = "b" * 64
    job = await submit_for_analysis(
        db_session,
        sha256=sha,
        tenant_id=DEFAULT_TENANT_ID,
        sample_bytes=b"sample-bytes",
    )
    await db_session.flush()

    changed = await _run_once(session_maker=_test_session_maker(db_session))
    assert changed == 1

    await db_session.refresh(job)
    assert job.status == DetonationJobStatus.VERDICT
    assert job.verdict_label == "malicious"
    assert job.verdict_score == pytest.approx(7.5)
    assert job.finished_at is not None

    # IocEntry was created under the synthetic feed.
    iocs = (
        (
            await db_session.execute(
                select(IocEntry).where(
                    IocEntry.kind == IocKind.HASH_SHA256,
                    IocEntry.value_normalized == sha,
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(iocs) == 1
    assert iocs[0].source_id is not None


@pytest.mark.asyncio
@respx.mock
async def test_poll_500_marks_failed(db_session, _provider) -> None:
    """A 500 from Cuckoo flips the row to failed with the error stashed."""
    from app.models import DetonationJobStatus
    from app.models.tenant import DEFAULT_TENANT_ID
    from app.services.detonation.submitter import submit_for_analysis
    from app.workers.detonation_poller import _run_once

    respx.post("https://cuckoo.example.com/tasks/create/file").mock(
        return_value=Response(200, json={"task_id": 7})
    )
    respx.get("https://cuckoo.example.com/tasks/view/7").mock(
        return_value=Response(500, text="cuckoo dead")
    )

    sha = "c" * 64
    job = await submit_for_analysis(
        db_session,
        sha256=sha,
        tenant_id=DEFAULT_TENANT_ID,
        sample_bytes=b"sample",
    )
    await db_session.flush()

    await _run_once(session_maker=_test_session_maker(db_session))
    await db_session.refresh(job)
    assert job.status == DetonationJobStatus.FAILED
    assert job.error is not None
    assert "500" in job.error
    assert job.finished_at is not None


@pytest.mark.asyncio
async def test_submit_to_vmray_stub_fails_cleanly(db_session, _vmray_provider) -> None:
    """VMRay stub raises NotImplementedError → submitter records the
    job as failed (no exception escapes the call)."""
    from app.models import DetonationJobStatus
    from app.models.tenant import DEFAULT_TENANT_ID
    from app.services.detonation.submitter import submit_for_analysis

    job = await submit_for_analysis(
        db_session,
        sha256="d" * 64,
        tenant_id=DEFAULT_TENANT_ID,
        provider_id=_vmray_provider.id,
        sample_bytes=b"sample",
    )
    assert job.status == DetonationJobStatus.FAILED
    assert "VMRay" in (job.error or "")


@pytest.mark.asyncio
async def test_submit_to_anyrun_stub_fails_cleanly(db_session, _anyrun_provider) -> None:
    from app.models import DetonationJobStatus
    from app.models.tenant import DEFAULT_TENANT_ID
    from app.services.detonation.submitter import submit_for_analysis

    job = await submit_for_analysis(
        db_session,
        sha256="e" * 64,
        tenant_id=DEFAULT_TENANT_ID,
        provider_id=_anyrun_provider.id,
        sample_bytes=b"sample",
    )
    assert job.status == DetonationJobStatus.FAILED
    assert "ANY.RUN" in (job.error or "")


# ---------- API ----------


@pytest.mark.asyncio
async def test_non_admin_submit_is_403(http_client, analyst_headers, _provider) -> None:
    """Manual submit is admin-only — analyst gets 403."""
    body = {
        "sha256": "a" * 64,
        "sample_b64": base64.b64encode(b"sample").decode(),
    }
    resp = await http_client.post("/api/detonation/submit", json=body, headers=analyst_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
@respx.mock
async def test_admin_submit_creates_job(http_client, admin_headers, _provider) -> None:
    """Admin can submit; the response is the freshly-flushed job row."""
    respx.post("https://cuckoo.example.com/tasks/create/file").mock(
        return_value=Response(200, json={"task_id": 1234})
    )
    body = {
        "sha256": "f" * 64,
        "provider_id": str(_provider.id),
        "sample_b64": base64.b64encode(b"sample-bytes").decode(),
    }
    resp = await http_client.post("/api/detonation/submit", json=body, headers=admin_headers)
    assert resp.status_code == 201, resp.text
    payload = resp.json()
    assert payload["sha256"] == "f" * 64
    assert payload["status"] in {"running", "queued"}
    assert payload["provider_id"] == str(_provider.id)


@pytest.mark.asyncio
async def test_provider_crud_admin_only(http_client, admin_headers, analyst_headers) -> None:
    """Providers CRUD is admin-only; the kind validation gates Cuckoo on
    ``base_url``."""
    # Analyst can't list (admin gate on read too).
    resp = await http_client.get("/api/detonation/providers", headers=analyst_headers)
    assert resp.status_code == 403

    # Admin: missing base_url → 400.
    resp = await http_client.post(
        "/api/detonation/providers",
        json={"kind": "cuckoo", "name": "p1", "config": {}},
        headers=admin_headers,
    )
    assert resp.status_code == 400
    assert "base_url" in resp.json()["detail"]

    # Admin: well-formed create → 201.
    resp = await http_client.post(
        "/api/detonation/providers",
        json={
            "kind": "cuckoo",
            "name": "p1",
            "config": {"base_url": "https://cuckoo.example.com"},
        },
        headers=admin_headers,
    )
    assert resp.status_code == 201, resp.text
    provider_id = resp.json()["id"]

    # Update.
    resp = await http_client.patch(
        f"/api/detonation/providers/{provider_id}",
        json={"enabled": False},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False

    # Delete.
    resp = await http_client.delete(
        f"/api/detonation/providers/{provider_id}", headers=admin_headers
    )
    assert resp.status_code == 204


# ---------- detonation feed lifecycle ----------


@pytest.mark.asyncio
async def test_ensure_detonation_feed_is_idempotent(db_session) -> None:
    """Repeated calls return the same feed row (no fragmentation)."""
    from app.models.tenant import DEFAULT_TENANT_ID
    from app.workers.detonation_poller import _ensure_detonation_feed

    feed1 = await _ensure_detonation_feed(db_session, DEFAULT_TENANT_ID)
    feed2 = await _ensure_detonation_feed(db_session, DEFAULT_TENANT_ID)
    assert feed1.id == feed2.id
    assert feed1.managed_rule_id is not None
    assert feed1.managed_rule_id == feed2.managed_rule_id


# ---------- score → label ----------


def test_label_for_score_bucketing() -> None:
    from app.models import DetonationVerdictLabel
    from app.services.detonation import label_for_score

    assert label_for_score(0.0) is DetonationVerdictLabel.BENIGN
    assert label_for_score(1.9) is DetonationVerdictLabel.BENIGN
    assert label_for_score(2.0) is DetonationVerdictLabel.SUSPICIOUS
    assert label_for_score(4.9) is DetonationVerdictLabel.SUSPICIOUS
    assert label_for_score(5.0) is DetonationVerdictLabel.MALICIOUS
    assert label_for_score(10.0) is DetonationVerdictLabel.MALICIOUS
    assert label_for_score(None) is DetonationVerdictLabel.BENIGN
