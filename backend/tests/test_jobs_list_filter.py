"""GET /api/jobs?triggered_by_alert_id=<uuid> — deep-link filter.

Lets AlertDetailPanel's "Tracked in Jobs →" link land on a pre-filtered
Jobs view. The query param is the only addition to list_jobs; the
existing kind/status filters keep behaving the same.
"""

from __future__ import annotations

import os
from uuid import uuid4

import pytest


@pytest.fixture
async def _job_seed(db_session):
    """One job with triggered_by_alert_id set, one without."""
    from app.models import (
        Alert,
        AlertState,
        Host,
        HostStatus,
        Job,
        JobKind,
        JobScopeKind,
        JobStatus,
        OsFamily,
        Rule,
        RuleAction,
        RuleKind,
        Severity,
    )

    host = Host(
        hostname=f"h-{os.urandom(3).hex()}",
        os_family=OsFamily.LINUX,
        status=HostStatus.ONLINE,
    )
    rule = Rule(
        kind=RuleKind.SIGMA,
        name=f"r-{os.urandom(3).hex()}",
        severity=Severity.HIGH,
        action=RuleAction.ALERT,
    )
    db_session.add_all([host, rule])
    await db_session.flush()

    alert = Alert(
        host_id=host.id,
        rule_id=rule.id,
        severity=Severity.HIGH,
        state=AlertState.NEW,
        summary="seed",
    )
    db_session.add(alert)
    await db_session.flush()

    triggered = Job(
        kind=JobKind.KILL_PROCESS,
        parameters={},
        scope_kind=JobScopeKind.HOST_IDS,
        scope_host_ids=[str(host.id)],
        status=JobStatus.QUEUED,
        summary="auto-response to alert",
        triggered_by_alert_id=alert.id,
        triggered_by="rule",
    )
    manual = Job(
        kind=JobKind.PROCESS_SNAPSHOT,
        parameters={},
        scope_kind=JobScopeKind.HOST_IDS,
        scope_host_ids=[str(host.id)],
        status=JobStatus.QUEUED,
        summary="manual snapshot",
        triggered_by="manual",
    )
    db_session.add_all([triggered, manual])
    await db_session.flush()
    return alert, triggered, manual


@pytest.mark.asyncio
async def test_list_jobs_filters_by_triggered_by_alert_id(http_client, _job_seed, admin_headers):
    alert, triggered, manual = _job_seed

    resp = await http_client.get(
        f"/api/jobs?triggered_by_alert_id={alert.id}",
        headers=admin_headers,
    )
    assert resp.status_code == 200
    ids = {item["id"] for item in resp.json()["items"]}
    assert str(triggered.id) in ids
    assert str(manual.id) not in ids


@pytest.mark.asyncio
async def test_list_jobs_unfiltered_returns_both(http_client, _job_seed, admin_headers):
    _, triggered, manual = _job_seed

    resp = await http_client.get("/api/jobs", headers=admin_headers)
    assert resp.status_code == 200
    ids = {item["id"] for item in resp.json()["items"]}
    assert str(triggered.id) in ids
    assert str(manual.id) in ids


@pytest.mark.asyncio
async def test_list_jobs_filter_unknown_alert_returns_empty(http_client, _job_seed, admin_headers):
    resp = await http_client.get(
        f"/api/jobs?triggered_by_alert_id={uuid4()}",
        headers=admin_headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["items"] == []
    assert body["total"] == 0
