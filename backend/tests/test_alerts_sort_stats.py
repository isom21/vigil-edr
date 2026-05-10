"""Tests for the M7.7 alert console: sort param + /stats aggregations.

Both auto-skip when there's no DB configured (see conftest._pg_dsn).
"""
from __future__ import annotations

import os

import pytest


def _seed_alert(db_session, host, rule, severity, state, summary):
    from app.models import Alert

    a = Alert(
        host_id=host.id,
        rule_id=rule.id,
        severity=severity,
        state=state,
        summary=summary,
    )
    db_session.add(a)
    return a


@pytest.fixture
async def two_alerts(db_session):
    from app.models import (
        AlertState,
        Host,
        HostStatus,
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
        kind=RuleKind.YARA,
        name=f"r-{os.urandom(3).hex()}",
        severity=Severity.HIGH,
        action=RuleAction.DETECT,
    )
    db_session.add_all([host, rule])
    await db_session.flush()
    a1 = _seed_alert(db_session, host, rule, Severity.HIGH, AlertState.NEW, "first")
    a2 = _seed_alert(
        db_session, host, rule, Severity.CRITICAL, AlertState.NEW, "second"
    )
    await db_session.flush()
    return a1, a2, host, rule


@pytest.mark.asyncio
async def test_list_alerts_rejects_unknown_sort_field(
    http_client, two_alerts, admin_headers
):
    resp = await http_client.get(
        "/api/alerts?sort=invented_field:asc", headers=admin_headers
    )
    assert resp.status_code == 400
    assert "sort field" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_list_alerts_rejects_unknown_sort_direction(
    http_client, two_alerts, admin_headers
):
    resp = await http_client.get(
        "/api/alerts?sort=opened_at:sideways", headers=admin_headers
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_list_alerts_includes_host_hostname(
    http_client, two_alerts, admin_headers
):
    _, _, host, _ = two_alerts
    resp = await http_client.get("/api/alerts", headers=admin_headers)
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert any(item["host_hostname"] == host.hostname for item in items)
    assert all("rule_name" in item for item in items)


@pytest.mark.asyncio
async def test_list_alerts_q_filters_summary(
    http_client, two_alerts, admin_headers
):
    resp = await http_client.get("/api/alerts?q=first", headers=admin_headers)
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) >= 1
    assert all("first" in item["summary"] for item in items)


@pytest.mark.asyncio
async def test_alert_stats_severity(http_client, two_alerts, admin_headers):
    resp = await http_client.get("/api/alerts/stats?bucket=severity", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    by_key = {b["key"]: b["count"] for b in data}
    # The two seeded alerts add one HIGH and one CRITICAL.
    assert by_key.get("high", 0) >= 1
    assert by_key.get("critical", 0) >= 1


@pytest.mark.asyncio
async def test_alert_stats_hour_returns_24_buckets(
    http_client, two_alerts, admin_headers
):
    resp = await http_client.get("/api/alerts/stats?bucket=hour", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 24
    # Buckets are ISO timestamps; counts are non-negative ints.
    for b in data:
        assert isinstance(b["count"], int)
        assert b["count"] >= 0


@pytest.mark.asyncio
async def test_alert_stats_rejects_unknown_bucket(http_client, admin_headers):
    resp = await http_client.get(
        "/api/alerts/stats?bucket=bogus", headers=admin_headers
    )
    assert resp.status_code == 400
