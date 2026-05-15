"""Regression tests for CODE-22..26 — every alert / incident factory
must stamp tenant_id from the originating host's tenant, not the
SQLAlchemy column default (DEFAULT_TENANT_ID).

These tests bypass the worker loop / Kafka stack and call the alert-
emitting helpers directly. The point isn't to re-prove the workers
boot — it's to lock the tenant-routing invariant in place so a future
refactor can't silently regress it.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select


@pytest_asyncio.fixture
async def _two_tenant_hosts(db_session: Any, tenant_a: Any, tenant_b: Any) -> tuple[Any, Any]:
    """Materialise one host per tenant for routing tests."""
    from app.models import Host, HostStatus, OsFamily

    h_a = Host(
        tenant_id=tenant_a.id,
        hostname=f"host-a-{os.urandom(3).hex()}",
        os_family=OsFamily.LINUX,
        status=HostStatus.ONLINE,
    )
    h_b = Host(
        tenant_id=tenant_b.id,
        hostname=f"host-b-{os.urandom(3).hex()}",
        os_family=OsFamily.LINUX,
        status=HostStatus.ONLINE,
    )
    db_session.add_all([h_a, h_b])
    await db_session.flush()
    return h_a, h_b


@pytest.mark.asyncio
async def test_detector_emit_alerts_stamps_host_tenant_id(
    db_session: Any, _two_tenant_hosts: tuple[Any, Any]
) -> None:
    """services.detector.emit_alerts must stamp the host's tenant_id on
    every Alert it inserts (CODE-25). A miss here is the regression we
    fix in this PR — the SQLAlchemy column default would otherwise
    silently route every alert onto DEFAULT_TENANT_ID.

    Exercises the ECS-path (the production path post-normalizer-update)
    where the normalizer has stamped `tenant.id` on the ECS doc.
    """
    from app.models import Alert, Rule, RuleAction, RuleKind, Severity
    from app.services.detector import Match, emit_alerts

    h_a, h_b = _two_tenant_hosts
    rule = Rule(
        kind=RuleKind.IOC,
        name=f"tenant-route-rule-{os.urandom(3).hex()}",
        severity=Severity.MEDIUM,
        tenant_id=h_a.tenant_id,
    )
    db_session.add(rule)
    await db_session.flush()

    matches = [
        Match(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=Severity.MEDIUM,
            action=RuleAction.ALERT,
            summary="tenant routing test",
            matched_field="file.path",
            matched_value="/tmp/x",
            mitre_techniques=None,
        )
    ]
    ecs_a = {
        "host": {"id": str(h_a.id)},
        "tenant": {"id": str(h_a.tenant_id)},
        "event": {"id": str(uuid4())},
    }
    ecs_b = {
        "host": {"id": str(h_b.id)},
        "tenant": {"id": str(h_b.tenant_id)},
        "event": {"id": str(uuid4())},
    }

    out_a = await emit_alerts(db_session, host_id=h_a.id, matches=matches, ecs=ecs_a)
    out_b = await emit_alerts(db_session, host_id=h_b.id, matches=matches, ecs=ecs_b)
    await db_session.flush()

    assert len(out_a) == 1 and out_a[0][1] is True
    assert len(out_b) == 1 and out_b[0][1] is True

    a_alert = (await db_session.execute(select(Alert).where(Alert.id == out_a[0][0]))).scalar_one()
    b_alert = (await db_session.execute(select(Alert).where(Alert.id == out_b[0][0]))).scalar_one()

    assert a_alert.tenant_id == h_a.tenant_id, (
        "alert for tenant A host landed on the wrong tenant — CODE-25 regression"
    )
    assert b_alert.tenant_id == h_b.tenant_id, (
        "alert for tenant B host landed on the wrong tenant — CODE-25 regression"
    )
    assert a_alert.tenant_id != b_alert.tenant_id


@pytest.mark.asyncio
async def test_detector_falls_back_to_host_lookup_when_ecs_tenant_missing(
    db_session: Any, _two_tenant_hosts: tuple[Any, Any]
) -> None:
    """When ECS lacks tenant.id (pre-normalizer-update backlog), the
    factory must look the Host row up against the in-scope session.
    Uses `db.get(Host, ...)` so the test savepoint sees the host the
    fixture just flushed (the module-level host_cache would miss
    because it opens its own connection)."""
    from app.models import Alert, Rule, RuleAction, RuleKind, Severity
    from app.services.detector import Match, emit_alerts

    h_a, _ = _two_tenant_hosts
    rule = Rule(
        kind=RuleKind.IOC,
        name=f"tenant-fallback-rule-{os.urandom(3).hex()}",
        severity=Severity.MEDIUM,
        tenant_id=h_a.tenant_id,
    )
    db_session.add(rule)
    await db_session.flush()

    ecs = {"host": {"id": str(h_a.id)}, "event": {"id": str(uuid4())}}  # no tenant.id
    out = await emit_alerts(
        db_session,
        host_id=h_a.id,
        matches=[
            Match(
                rule_id=rule.id,
                rule_name=rule.name,
                severity=Severity.MEDIUM,
                action=RuleAction.ALERT,
                summary="fallback path",
                matched_field="file.path",
                matched_value="/tmp/z",
                mitre_techniques=None,
            )
        ],
        ecs=ecs,
    )
    await db_session.flush()
    alert = (await db_session.execute(select(Alert).where(Alert.id == out[0][0]))).scalar_one()
    assert alert.tenant_id == h_a.tenant_id


@pytest.mark.asyncio
async def test_detector_prefers_ecs_tenant_id_when_present(
    db_session: Any, _two_tenant_hosts: tuple[Any, Any]
) -> None:
    """The normalizer stamps tenant.id on every ECS doc. emit_alerts
    must trust that field when present (avoiding a host_cache round-
    trip) and fall back to the cache only when the field is missing."""
    from app.models import Alert, Rule, RuleAction, RuleKind, Severity
    from app.services.detector import Match, emit_alerts

    h_a, _ = _two_tenant_hosts
    rule = Rule(
        kind=RuleKind.IOC,
        name=f"tenant-ecs-rule-{os.urandom(3).hex()}",
        severity=Severity.MEDIUM,
        tenant_id=h_a.tenant_id,
    )
    db_session.add(rule)
    await db_session.flush()

    ecs = {
        "host": {"id": str(h_a.id)},
        "tenant": {"id": str(h_a.tenant_id)},
        "event": {"id": str(uuid4())},
    }
    out = await emit_alerts(
        db_session,
        host_id=h_a.id,
        matches=[
            Match(
                rule_id=rule.id,
                rule_name=rule.name,
                severity=Severity.MEDIUM,
                action=RuleAction.ALERT,
                summary="ecs.tenant.id path",
                matched_field="file.path",
                matched_value="/tmp/y",
                mitre_techniques=None,
            )
        ],
        ecs=ecs,
    )
    await db_session.flush()
    alert = (await db_session.execute(select(Alert).where(Alert.id == out[0][0]))).scalar_one()
    assert alert.tenant_id == h_a.tenant_id


@pytest.mark.asyncio
async def test_incident_grouping_copies_seed_alert_tenant_id(
    db_session: Any, _two_tenant_hosts: tuple[Any, Any]
) -> None:
    """CODE-26: incident_grouping must copy tenant_id from the seed
    alert. Two alerts in tenant A grouped into an incident must land
    on tenant A, not the column default."""
    from app.models import (
        Alert,
        AlertState,
        Incident,
        Rule,
        RuleAction,
        RuleKind,
        Severity,
    )
    from app.services.incident_grouping import regroup_recent

    h_a, _ = _two_tenant_hosts
    rule = Rule(
        kind=RuleKind.IOC,
        name=f"tenant-incident-rule-{os.urandom(3).hex()}",
        severity=Severity.MEDIUM,
        tenant_id=h_a.tenant_id,
    )
    db_session.add(rule)
    await db_session.flush()

    now = datetime.now(UTC)
    a1 = Alert(
        tenant_id=h_a.tenant_id,
        host_id=h_a.id,
        rule_id=rule.id,
        severity=Severity.MEDIUM,
        action_taken=RuleAction.ALERT,
        state=AlertState.NEW,
        summary="seed",
        opened_at=now,
    )
    a2 = Alert(
        tenant_id=h_a.tenant_id,
        host_id=h_a.id,
        rule_id=rule.id,
        severity=Severity.MEDIUM,
        action_taken=RuleAction.ALERT,
        state=AlertState.NEW,
        summary="followup",
        opened_at=now,
    )
    db_session.add_all([a1, a2])
    await db_session.flush()

    # Default grouping window is plenty wide for two same-second alerts.
    await regroup_recent(db_session, window_s=3600)
    await db_session.flush()

    # Both alerts should land on the same incident, and that incident
    # must carry tenant A's id.
    refreshed = (
        (await db_session.execute(select(Alert).where(Alert.id.in_([a1.id, a2.id]))))
        .scalars()
        .all()
    )
    incident_ids = {a.incident_id for a in refreshed}
    assert None not in incident_ids, "grouper failed to attach an incident"
    assert len(incident_ids) == 1
    inc = (
        await db_session.execute(select(Incident).where(Incident.id == next(iter(incident_ids))))
    ).scalar_one()
    assert inc.tenant_id == h_a.tenant_id, (
        "incident did not inherit tenant_id from seed alert — CODE-26 regression"
    )


@pytest.mark.asyncio
async def test_silence_alert_stamps_host_tenant_id(
    db_session: Any, _two_tenant_hosts: tuple[Any, Any]
) -> None:
    """workers.silence._fire_alert reads tenant_id straight off the
    Host row (no host_cache hop). Locks in the cheap path."""
    from datetime import timedelta

    from app.models import Alert
    from app.workers import silence as silence_mod
    from app.workers.silence import SILENCE_RULE_ID

    h_a, h_b = _two_tenant_hosts
    worker = silence_mod.SilenceWorker.__new__(silence_mod.SilenceWorker)
    worker._threshold = timedelta(seconds=60)
    await worker._fire_alert(db_session, h_a, silence_seconds=120)
    await worker._fire_alert(db_session, h_b, silence_seconds=120)
    await db_session.flush()

    by_host = {
        a.host_id: a
        for a in (
            await db_session.execute(select(Alert).where(Alert.rule_id == SILENCE_RULE_ID))
        ).scalars()
    }
    assert by_host[h_a.id].tenant_id == h_a.tenant_id
    assert by_host[h_b.id].tenant_id == h_b.tenant_id
    assert by_host[h_a.id].tenant_id != by_host[h_b.id].tenant_id


def test_chain_break_dataclass_carries_tenant_id() -> None:
    """Compile-time guard for CODE-25: `ChainBreak` exposes `tenant_id`
    so `_ensure_rule_and_open_alert` can stamp the synthetic chain-
    break Alert with the broken row's tenant rather than the column
    default. The end-to-end helper opens its own SessionLocal so it
    can't share the test session's savepoint — coverage of the
    write path stays in test_audit_verifier_loop.py."""
    from uuid import UUID as _UUID

    from app.services.audit_verifier import ChainBreak

    tid = _UUID("00000000-0000-0000-0000-000000000123")
    cb = ChainBreak(
        seq=7,
        row_id="r",
        reason="row_hmac mismatch — row content tampered",
        expected_hmac=None,
        actual_hmac=None,
        tenant_id=tid,
    )
    assert cb.tenant_id == tid
    # Optional field — pre-tenancy rows can still produce a break.
    cb_legacy = ChainBreak(
        seq=8,
        row_id="r2",
        reason="first chain row has non-NULL prev_hmac",
        expected_hmac=None,
        actual_hmac=None,
    )
    assert cb_legacy.tenant_id is None
