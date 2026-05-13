"""POST /api/jobs with kind=triage_collect (Phase 2 #2.10).

Coverage:
  * admin creates a triage_collect job → 201 + audit row.
  * analyst attempts the same → 403 (kind is admin-only).
  * the audit row records the kind, scope and host count so the
    incident-response post-mortem can reconstruct who pulled
    secrets-bearing artifacts off which hosts.
"""

from __future__ import annotations

import os

import pytest
import pytest_asyncio
from sqlalchemy import desc, select


@pytest_asyncio.fixture
async def _triage_host(db_session):
    """A single online linux host the job can fan out to. Both admin
    and analyst can see it without a group restriction (no group means
    superuser semantics for admin and `visible_host_ids = []` for
    analyst; we add the analyst to the host's group so the fanout
    target list is non-empty)."""
    from sqlalchemy import insert

    from app.models import (
        Host,
        HostGroup,
        HostStatus,
        OsFamily,
        host_in_group,
    )

    host = Host(
        hostname=f"triage-host-{os.urandom(3).hex()}",
        os_family=OsFamily.LINUX,
        status=HostStatus.ONLINE,
    )
    group = HostGroup(name=f"triage-grp-{os.urandom(3).hex()}")
    db_session.add_all([host, group])
    await db_session.flush()
    await db_session.execute(insert(host_in_group).values(host_id=host.id, host_group_id=group.id))
    return host, group


@pytest.mark.asyncio
async def test_admin_creates_triage_collect_job(http_client, _triage_host, admin_headers):
    host, _ = _triage_host
    resp = await http_client.post(
        "/api/jobs",
        headers=admin_headers,
        json={
            "kind": "triage_collect",
            "parameters": {
                "include_registry": True,
                "include_mft": True,
                "include_prefetch": True,
                "include_browser": True,
                "include_event_log": True,
                "include_systemd_journal": True,
                "include_persistence": True,
                "max_size_mb": 1024,
            },
            "scope": {"kind": "host_ids", "host_ids": [str(host.id)]},
            "summary": "ir triage on suspect host",
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["kind"] == "triage_collect"
    assert body["status"] == "running"
    assert len(body["runs"]) == 1
    assert body["runs"][0]["host_id"] == str(host.id)


@pytest.mark.asyncio
async def test_analyst_forbidden_from_triage_collect(
    http_client, _triage_host, analyst_user, analyst_headers, db_session
):
    """analyst attempt should 403 — triage_collect is in
    JOB_KIND_ADMIN_ONLY because the bundle aggregates secrets-bearing
    files (SAM/SECURITY hives, browser passwords DB)."""
    from sqlalchemy import insert

    from app.models import user_host_group

    host, group = _triage_host
    # Put the analyst in the host's group so the failure can't be
    # confused with a scoping miss — without this the auth check
    # short-circuits before reaching the JOB_KIND_ADMIN_ONLY gate.
    await db_session.execute(
        insert(user_host_group).values(user_id=analyst_user.id, host_group_id=group.id)
    )

    resp = await http_client.post(
        "/api/jobs",
        headers=analyst_headers,
        json={
            "kind": "triage_collect",
            "parameters": {},
            "scope": {"kind": "host_ids", "host_ids": [str(host.id)]},
        },
    )
    assert resp.status_code == 403, resp.text
    assert "admin" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_triage_collect_audit_row_recorded(
    http_client, _triage_host, admin_headers, db_session, admin_user
):
    from app.models import AuditLog

    host, _ = _triage_host
    resp = await http_client.post(
        "/api/jobs",
        headers=admin_headers,
        json={
            "kind": "triage_collect",
            "parameters": {"max_size_mb": 512},
            "scope": {"kind": "host_ids", "host_ids": [str(host.id)]},
        },
    )
    assert resp.status_code == 201, resp.text
    job_id = resp.json()["id"]

    rows = (
        (
            await db_session.execute(
                select(AuditLog)
                .where(AuditLog.action == "job.create")
                .where(AuditLog.resource_id == job_id)
                .order_by(desc(AuditLog.ts))
            )
        )
        .scalars()
        .all()
    )
    assert rows, "job.create audit row should be present"
    audit = rows[0]
    assert audit.actor_kind == "user"
    assert audit.user_id == admin_user.id
    payload = audit.payload or {}
    assert payload.get("kind") == "triage_collect"
    assert payload.get("host_count") == 1


@pytest.mark.asyncio
async def test_triage_collect_enum_value_accepted(http_client, _triage_host, admin_headers):
    """Regression guard: the pydantic enum binding must accept the new
    `triage_collect` literal. Before adding it to JobKind, this POST
    would have been rejected at the schema layer with a 422."""
    host, _ = _triage_host
    resp = await http_client.post(
        "/api/jobs",
        headers=admin_headers,
        json={
            "kind": "triage_collect",
            "parameters": {},
            "scope": {"kind": "host_ids", "host_ids": [str(host.id)]},
        },
    )
    assert resp.status_code == 201
