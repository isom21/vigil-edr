"""Phase 1 #1.8: MITRE ATT&CK technique field on rules + alerts.

Covers:
  * Rule create/update accepts `mitre_techniques`, normalises (upper +
    trim + dedupe), and stores via the JSON column.
  * Rule create/update writes the techniques into the audit payload.
  * Alert detail endpoint surfaces `mitre_techniques`.
  * The IOC detector worker snapshots the rule's tags onto the alert
    so later rule edits don't rewrite history.
"""

from __future__ import annotations

import os

import pytest
import pytest_asyncio


@pytest_asyncio.fixture
async def _ioc_rule(db_session):
    from app.models import IocEntry, IocKind, Rule, RuleKind, Severity

    rule = Rule(
        kind=RuleKind.IOC,
        name=f"mitre-rule-{os.urandom(3).hex()}",
        severity=Severity.HIGH,
        mitre_techniques=["T1059.001", "T1547.001"],
    )
    rule.iocs = [
        IocEntry(
            kind=IocKind.HASH_SHA256,
            value="a" * 64,
            value_normalized="a" * 64,
        )
    ]
    db_session.add(rule)
    await db_session.flush()
    return rule


# ---------- API: rule create / update ----------


@pytest.mark.asyncio
async def test_create_rule_with_mitre_techniques(http_client, admin_headers):
    resp = await http_client.post(
        "/api/rules",
        json={
            "kind": "yara",
            "name": f"yara-{os.urandom(3).hex()}",
            "severity": "medium",
            "action": "alert",
            # Mixed-case + duplicate + whitespace; backend normalises.
            "body": 'rule t { strings: $a = "x" condition: $a }',
            "mitre_techniques": ["t1059.001", " T1547.001 ", "T1059.001"],
        },
        headers=admin_headers,
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["mitre_techniques"] == ["T1059.001", "T1547.001"]


@pytest.mark.asyncio
async def test_update_rule_replaces_mitre_techniques(http_client, admin_headers):
    create = await http_client.post(
        "/api/rules",
        json={
            "kind": "yara",
            "name": f"yara-{os.urandom(3).hex()}",
            "body": 'rule t { strings: $a = "x" condition: $a }',
            "mitre_techniques": ["T1059"],
        },
        headers=admin_headers,
    )
    assert create.status_code == 201, create.text
    rid = create.json()["id"]

    resp = await http_client.patch(
        f"/api/rules/{rid}",
        json={"mitre_techniques": ["T1547.001"]},
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["mitre_techniques"] == ["T1547.001"]


@pytest.mark.asyncio
async def test_update_rule_clears_techniques_with_empty_list(http_client, admin_headers):
    """A list with only whitespace / blank entries normalises to None."""
    create = await http_client.post(
        "/api/rules",
        json={
            "kind": "yara",
            "name": f"yara-{os.urandom(3).hex()}",
            "body": 'rule t { strings: $a = "x" condition: $a }',
            "mitre_techniques": ["T1059"],
        },
        headers=admin_headers,
    )
    rid = create.json()["id"]

    resp = await http_client.patch(
        f"/api/rules/{rid}",
        json={"mitre_techniques": ["  ", ""]},
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["mitre_techniques"] is None


@pytest.mark.asyncio
async def test_rule_update_audit_payload_includes_techniques(
    http_client, admin_headers, db_session
):
    from sqlalchemy import select

    from app.models import AuditLog

    create = await http_client.post(
        "/api/rules",
        json={
            "kind": "yara",
            "name": f"yara-{os.urandom(3).hex()}",
            "body": 'rule t { strings: $a = "x" condition: $a }',
        },
        headers=admin_headers,
    )
    rid = create.json()["id"]

    resp = await http_client.patch(
        f"/api/rules/{rid}",
        json={"mitre_techniques": ["T1059.001"]},
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text

    row = (
        await db_session.execute(
            select(AuditLog)
            .where(AuditLog.action == "rule.update", AuditLog.resource_id == rid)
            .order_by(AuditLog.seq.desc())
            .limit(1)
        )
    ).scalar_one()
    assert row.payload is not None
    assert row.payload.get("mitre_techniques") == ["T1059.001"]


# ---------- Alert detail surfaces the field ----------


@pytest.mark.asyncio
async def test_alert_detail_returns_mitre_techniques(
    http_client, admin_headers, db_session, _ioc_rule
):
    from app.models import (
        Alert,
        AlertState,
        Host,
        HostStatus,
        OsFamily,
        Severity,
    )

    host = Host(
        hostname=f"h-{os.urandom(3).hex()}",
        os_family=OsFamily.LINUX,
        status=HostStatus.ONLINE,
    )
    db_session.add(host)
    await db_session.flush()

    alert = Alert(
        host_id=host.id,
        rule_id=_ioc_rule.id,
        severity=Severity.HIGH,
        state=AlertState.NEW,
        summary="ioc match",
        mitre_techniques=["T1059.001"],
    )
    db_session.add(alert)
    await db_session.flush()

    resp = await http_client.get(f"/api/alerts/{alert.id}", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["mitre_techniques"] == ["T1059.001"]


# ---------- detector worker copies tags onto emitted alerts ----------


@pytest.mark.asyncio
async def test_emit_alerts_copies_mitre_techniques(db_session, _ioc_rule):
    """The Match-to-Alert helper used by the IOC detector must snapshot
    the rule's MITRE tags onto the new alert row."""
    from app.models import Host, HostStatus, OsFamily
    from app.services.detector import IocSnapshot, emit_alerts, evaluate

    host = Host(
        hostname=f"h-{os.urandom(3).hex()}",
        os_family=OsFamily.LINUX,
        status=HostStatus.ONLINE,
    )
    db_session.add(host)
    await db_session.flush()

    snap = await IocSnapshot.load(db_session)
    ecs = {
        "host": {"id": str(host.id)},
        "process": {"hash": {"sha256": "a" * 64}},
        "event": {"id": "ev-mitre-1"},
    }
    matches = evaluate(ecs, snap)
    assert matches, "fixture rule should match the synthetic ECS event"
    # The snapshot carried the techniques tuple.
    assert any(m.mitre_techniques and "T1059.001" in m.mitre_techniques for m in matches)

    alert_ids = await emit_alerts(db_session, host_id=host.id, matches=matches, ecs=ecs)
    assert alert_ids

    from sqlalchemy import select

    from app.models import Alert

    # PR #41 (dedup) changed `emit_alerts` to return `[(alert_id, was_new), ...]`
    # tuples instead of plain UUIDs. Unpack the first slot.
    first_alert_id = alert_ids[0][0] if isinstance(alert_ids[0], tuple) else alert_ids[0]
    alert = (await db_session.execute(select(Alert).where(Alert.id == first_alert_id))).scalar_one()
    assert alert.mitre_techniques is not None
    assert "T1059.001" in alert.mitre_techniques
    assert "T1547.001" in alert.mitre_techniques
