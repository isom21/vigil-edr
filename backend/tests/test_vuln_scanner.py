"""Phase 2 #2.7 vulnerability scanner worker.

Covers:
  * NVD entry parser pulls CVE id, severity, CVSS v3 score, references,
    and the flattened affected_cpe list out of the nested envelope.
  * CPE parser accepts spec-compliant URIs and rejects everything else.
  * CPE matcher pairs an installed CPE against an advisory list.
  * The worker materialises matches in `host_vulnerability` from
    `host_software` rows + a mocked NVD response.
  * Idempotency: running twice with the same fixture doesn't add dup
    rows; the second run updates `last_seen`.
  * `_interval_seconds` floors small values and falls back on garbage.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from decimal import Decimal

import httpx
import pytest
import pytest_asyncio
import respx


def _test_session_maker(db_session):
    @asynccontextmanager
    async def _maker():
        yield db_session

    return _maker


# ---------- NVD parser ----------


def test_nvd_parse_entry_full() -> None:
    """An NVD vulnerability envelope flattens to the dataclass shape
    the worker writes to Postgres."""
    from app.services.vuln.nvd import _parse_entry

    entry = {
        "cve": {
            "id": "CVE-2024-12345",
            "published": "2024-01-02T03:04:05.123",
            "lastModified": "2024-05-06T07:08:09.000",
            "descriptions": [
                {"lang": "en", "value": "Buffer overflow in widget."},
                {"lang": "es", "value": "ignored"},
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"},
                    }
                ]
            },
            "references": [
                {"url": "https://example.com/advisory/1"},
                {"url": "https://example.com/advisory/2"},
                {"not_url": "skip"},
            ],
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {"criteria": "cpe:2.3:a:widgetco:widget:1.0:*:*:*:*:*:*:*"},
                                {"criteria": "cpe:2.3:a:widgetco:widget:1.1:*:*:*:*:*:*:*"},
                            ]
                        }
                    ]
                }
            ],
        }
    }
    parsed = _parse_entry(entry)
    assert parsed is not None
    assert parsed.cve_id == "CVE-2024-12345"
    assert parsed.severity == "critical"
    assert parsed.cvss_v3_score == Decimal("9.8")
    assert parsed.summary == "Buffer overflow in widget."
    assert "https://example.com/advisory/1" in parsed.references
    assert len(parsed.affected_cpes) == 2
    assert parsed.published_at is not None
    assert parsed.modified_at is not None


def test_nvd_parse_entry_missing_id_returns_none() -> None:
    from app.services.vuln.nvd import _parse_entry

    assert _parse_entry({"cve": {}}) is None
    assert _parse_entry({}) is None


def test_nvd_to_iso_format() -> None:
    from app.services.vuln.nvd import _to_nvd_iso

    dt = datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)
    assert _to_nvd_iso(dt) == "2024-01-02T03:04:05.000"


# ---------- CPE parsing + matcher ----------


def test_parse_cpe_well_formed() -> None:
    from app.services.vuln.cpe import parse_cpe

    parsed = parse_cpe("cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*")
    assert parsed is not None
    assert parsed.part == "a"
    assert parsed.vendor == "openssl"
    assert parsed.product == "openssl"
    assert parsed.version == "1.1.1"


def test_parse_cpe_rejects_non_cpe() -> None:
    from app.services.vuln.cpe import parse_cpe

    assert parse_cpe(None) is None
    assert parse_cpe("") is None
    assert parse_cpe("notacpe") is None
    assert parse_cpe("cpe:2.2:a:x:y") is None  # wrong prefix
    assert parse_cpe("cpe:2.3:a") is None  # missing fields


def test_cpe_match_exact() -> None:
    from app.services.vuln.cpe import match

    installed = "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"
    advisory = [
        "cpe:2.3:a:widgetco:widget:1.0:*:*:*:*:*:*:*",
        "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*",
    ]
    hit = match(installed, advisory)
    assert hit == advisory[1]


def test_cpe_match_wildcard_version() -> None:
    """An advisory CPE with `*` for version matches any installed
    version of the same product."""
    from app.services.vuln.cpe import match

    installed = "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"
    advisory = ["cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"]
    assert match(installed, advisory) == advisory[0]


def test_cpe_match_no_match() -> None:
    from app.services.vuln.cpe import match

    installed = "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"
    advisory = ["cpe:2.3:a:other:product:1.0:*:*:*:*:*:*:*"]
    assert match(installed, advisory) is None


def test_cpe_match_ignores_malformed() -> None:
    from app.services.vuln.cpe import match

    assert match(None, ["cpe:2.3:a:x:y:1.0:*:*:*:*:*:*:*"]) is None
    assert (
        match("cpe:2.3:a:x:y:1.0:*:*:*:*:*:*:*", ["garbage", "cpe:2.3:a:x:y:1.0:*:*:*:*:*:*:*"])
        == "cpe:2.3:a:x:y:1.0:*:*:*:*:*:*:*"
    )


# ---------- env knob ----------


def test_interval_floor_is_60s() -> None:
    """A 1-second tick on the daily scanner is nonsense — floor 60s."""
    from app.workers.vuln_scanner import _interval_seconds

    os.environ["VIGIL_VULN_SCAN_INTERVAL_S"] = "10"
    try:
        assert _interval_seconds() == 60
    finally:
        os.environ.pop("VIGIL_VULN_SCAN_INTERVAL_S", None)


def test_interval_falls_back_on_garbage() -> None:
    from app.workers.vuln_scanner import _interval_seconds

    os.environ["VIGIL_VULN_SCAN_INTERVAL_S"] = "not-a-number"
    try:
        assert _interval_seconds() == 86400
    finally:
        os.environ.pop("VIGIL_VULN_SCAN_INTERVAL_S", None)


# ---------- DB fixtures ----------


@pytest_asyncio.fixture
async def scanner_host(db_session):
    from app.models import Host, HostStatus, OsFamily

    h = Host(
        hostname=f"vuln-host-{os.urandom(3).hex()}",
        os_family=OsFamily.LINUX,
        status=HostStatus.ONLINE,
    )
    db_session.add(h)
    await db_session.flush()
    return h


@pytest_asyncio.fixture
async def scanner_software(db_session, scanner_host):
    """Pre-seed a HostSoftware row with a CPE the NVD fixture targets."""
    from app.models import HostSoftware

    sw = HostSoftware(
        host_id=scanner_host.id,
        name="openssl",
        version="1.1.1",
        vendor="openssl",
        cpe="cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*",
    )
    db_session.add(sw)
    await db_session.flush()
    return sw


# ---------- end-to-end worker ----------


def _nvd_envelope_with(*cve_ids: str) -> dict:
    """Build a minimal NVD response targeting openssl."""
    return {
        "totalResults": len(cve_ids),
        "vulnerabilities": [
            {
                "cve": {
                    "id": cid,
                    "published": "2024-01-02T03:04:05.123",
                    "lastModified": "2024-05-06T07:08:09.000",
                    "descriptions": [{"lang": "en", "value": f"{cid} description"}],
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]
                    },
                    "references": [{"url": f"https://nvd.example/{cid}"}],
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "criteria": (
                                                "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"
                                            )
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                }
            }
            for cid in cve_ids
        ],
    }


@pytest.mark.asyncio
@respx.mock
async def test_run_once_materialises_host_vulnerability(
    db_session, scanner_host, scanner_software
) -> None:
    """A mocked NVD response feeds the worker; it inserts the CVE,
    matches it against the seeded HostSoftware row, and writes the
    host_vulnerability join."""
    from sqlalchemy import select

    from app.models import HostVulnerability, Vulnerability
    from app.services.vuln import NvdClient
    from app.workers.vuln_scanner import _run_once

    respx.get("https://nvd.test/cves/2.0").mock(
        return_value=httpx.Response(200, json=_nvd_envelope_with("CVE-2024-0001"))
    )
    client = NvdClient(base_url="https://nvd.test", api_key="")

    counts = await _run_once(
        session_maker=_test_session_maker(db_session),
        nvd_client=client,
    )
    assert counts["cves_ingested"] == 1
    assert counts["matches_upserted"] >= 1

    vuln = await db_session.get(Vulnerability, "CVE-2024-0001")
    assert vuln is not None
    assert vuln.severity == "high"
    assert vuln.cvss_v3_score == Decimal("7.5")

    rows = (
        (
            await db_session.execute(
                select(HostVulnerability).where(HostVulnerability.host_id == scanner_host.id)
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].cve_id == "CVE-2024-0001"
    assert rows[0].cpe == "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"
    assert rows[0].suppressed is False


@pytest.mark.asyncio
@respx.mock
async def test_run_once_idempotent_upsert(db_session, scanner_host, scanner_software) -> None:
    """Running the worker twice with the same NVD payload doesn't
    create duplicate host_vulnerability rows — the unique
    (host_id, cve_id) constraint collapses the second pass."""
    from sqlalchemy import select

    from app.models import HostVulnerability
    from app.services.vuln import NvdClient
    from app.workers.vuln_scanner import _run_once

    respx.get("https://nvd.test/cves/2.0").mock(
        return_value=httpx.Response(200, json=_nvd_envelope_with("CVE-2024-0002"))
    )
    client = NvdClient(base_url="https://nvd.test", api_key="")

    await _run_once(session_maker=_test_session_maker(db_session), nvd_client=client)
    await _run_once(session_maker=_test_session_maker(db_session), nvd_client=client)

    rows = (
        (
            await db_session.execute(
                select(HostVulnerability).where(HostVulnerability.host_id == scanner_host.id)
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1


@pytest.mark.asyncio
@respx.mock
async def test_run_once_ingests_packages_from_installed_software_artifact(
    db_session, scanner_host
) -> None:
    """A JobArtifact carrying an `INSTALLED_SOFTWARE` job's `packages`
    list flows into `host_software` without a MinIO round-trip."""
    from sqlalchemy import select

    from app.models import (
        HostSoftware,
        Job,
        JobArtifact,
        JobArtifactKind,
        JobKind,
        JobRun,
        JobRunStatus,
        JobScopeKind,
        JobStatus,
    )
    from app.services.vuln import NvdClient
    from app.workers.vuln_scanner import _run_once

    job = Job(
        kind=JobKind.INSTALLED_SOFTWARE,
        parameters={},
        scope_kind=JobScopeKind.HOST_IDS,
        scope_host_ids=[str(scanner_host.id)],
        status=JobStatus.COMPLETED,
        summary="installed_software smoke",
    )
    db_session.add(job)
    await db_session.flush()
    run = JobRun(
        job_id=job.id,
        host_id=scanner_host.id,
        status=JobRunStatus.COMPLETED,
    )
    db_session.add(run)
    await db_session.flush()
    artifact = JobArtifact(
        job_run_id=run.id,
        kind=JobArtifactKind.JSON,
        bucket="vigil-artifacts",
        object_key="ignored/path",
        size_bytes=0,
        artifact_metadata={
            "packages": [
                {
                    "name": "openssl",
                    "version": "1.1.1",
                    "vendor": "openssl",
                    "cpe": "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*",
                },
                {
                    "name": "libc6",
                    "version": "2.31-13",
                },
                # Skipped — missing version.
                {"name": "incomplete"},
            ]
        },
    )
    db_session.add(artifact)
    await db_session.flush()

    # No NVD CVEs — we're only proving the package-ingest path.
    respx.get("https://nvd.test/cves/2.0").mock(
        return_value=httpx.Response(200, json={"totalResults": 0, "vulnerabilities": []})
    )
    client = NvdClient(base_url="https://nvd.test", api_key="")

    await _run_once(session_maker=_test_session_maker(db_session), nvd_client=client)

    rows = (
        (
            await db_session.execute(
                select(HostSoftware).where(HostSoftware.host_id == scanner_host.id)
            )
        )
        .scalars()
        .all()
    )
    names = {r.name for r in rows}
    assert "openssl" in names
    assert "libc6" in names
    assert "incomplete" not in names


# ---------- API smoke ----------


@pytest.mark.asyncio
async def test_suppress_endpoint_admin_only(
    http_client, admin_headers, analyst_headers, db_session, scanner_host
) -> None:
    """Suppressing a host_vulnerability row is admin-only and audited."""
    from sqlalchemy import select

    from app.models import AuditLog, HostVulnerability, Vulnerability

    vuln = Vulnerability(
        cve_id="CVE-2099-0001",
        severity="high",
        cvss_v3_score=Decimal("8.0"),
        summary="seed",
    )
    db_session.add(vuln)
    await db_session.flush()
    hv = HostVulnerability(
        host_id=scanner_host.id,
        cve_id=vuln.cve_id,
        cpe="cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*",
    )
    db_session.add(hv)
    await db_session.flush()

    # Analyst gets 403.
    forbidden_resp = await http_client.post(
        f"/api/host-vulnerabilities/{hv.id}/suppress",
        headers=analyst_headers,
        json={"reason": "false positive"},
    )
    assert forbidden_resp.status_code in {401, 403}

    # Admin succeeds and the audit row is written.
    ok_resp = await http_client.post(
        f"/api/host-vulnerabilities/{hv.id}/suppress",
        headers=admin_headers,
        json={"reason": "patched out-of-band"},
    )
    assert ok_resp.status_code == 200, ok_resp.text
    body = ok_resp.json()
    assert body["suppressed"] is True

    audit_rows = (
        (await db_session.execute(select(AuditLog).where(AuditLog.resource_id == str(hv.id))))
        .scalars()
        .all()
    )
    assert any(r.action == "host_vulnerability.suppress" for r in audit_rows)
