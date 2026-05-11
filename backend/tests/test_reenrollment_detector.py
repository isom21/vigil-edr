"""M12.e re-enrollment detector — shared between REST and gRPC enroll.

Reviewer's HIGH finding: the gRPC enroll path skipped the M12.e
detector entirely because the helper lived in `api/enrollment.py`. An
attacker wiping the agent's identity dir would use gRPC (the agent's
normal channel), so the alert the SOC was promised never fired.

The detector now lives in `services/enrollment.py::detect_reenrollment`
and both REST and gRPC paths call it. These tests pin the detector's
contract directly (it's a pure DB-side operation) — the integration
of REST/gRPC is already covered by the existing race tests + the live
enrollment smoke.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine


def _pg_dsn() -> str | None:
    if v := os.environ.get("VIGIL_TEST_PG_DSN"):
        return v
    if v := os.environ.get("VIGIL_PG_DSN"):
        return v
    if v := os.environ.get("VIGIL_DATABASE_URL"):
        if v.startswith("postgresql+psycopg://"):
            return v.replace("postgresql+psycopg://", "postgresql+asyncpg://", 1)
        if v.startswith("postgresql://"):
            return v.replace("postgresql://", "postgresql+asyncpg://", 1)
        return v
    return None


@pytest_asyncio.fixture
async def engine() -> Any:
    dsn = _pg_dsn()
    if dsn is None:
        pytest.skip("No PG DSN configured.")
    e = create_async_engine(dsn, pool_pre_ping=True, echo=False)
    try:
        yield e
    finally:
        await e.dispose()


async def _seed_host(engine: Any, hostname: str, enrolled_at: datetime) -> Any:
    from app.models import Host, HostStatus

    async with AsyncSession(engine) as db:
        h = Host(
            hostname=hostname,
            os_family="linux",
            status=HostStatus.ONLINE,
            enrolled_at=enrolled_at,
        )
        db.add(h)
        await db.commit()
        await db.refresh(h)
        return h


async def _clean_up(engine: Any, host_ids: list[Any]) -> None:
    from app.models import Alert, Host

    async with AsyncSession(engine) as db:
        await db.execute(delete(Alert).where(Alert.host_id.in_(host_ids)))
        await db.execute(delete(Host).where(Host.id.in_(host_ids)))
        await db.commit()


@pytest.mark.asyncio
async def test_fires_when_recent_host_with_same_hostname_exists(engine: Any) -> None:
    from app.models import Alert
    from app.services.enrollment import REENROLLMENT_RULE_ID, detect_reenrollment

    hostname = f"reenroll-test-{uuid4().hex[:8]}"
    prior = await _seed_host(engine, hostname, datetime.now(UTC) - timedelta(seconds=60))
    new = await _seed_host(engine, hostname, datetime.now(UTC))

    try:
        async with AsyncSession(engine) as db:
            await detect_reenrollment(
                db,
                hostname=hostname,
                os_family="linux",
                new_host_id=new.id,
                now=datetime.now(UTC),
                source="grpc",
                source_ip="10.0.0.5",
            )
            await db.commit()

        async with AsyncSession(engine) as db:
            alerts = (
                (
                    await db.execute(
                        select(Alert).where(
                            Alert.host_id == new.id,
                            Alert.rule_id == REENROLLMENT_RULE_ID,
                        )
                    )
                )
                .scalars()
                .all()
            )
            assert len(alerts) == 1, f"expected 1 alert, got {len(alerts)}"
            details = alerts[0].details or {}
            assert details["hostname"] == hostname
            assert details["source"] == "grpc"
            assert details["ip"] == "10.0.0.5"
            assert details["prior_host_id"] == str(prior.id)
    finally:
        await _clean_up(engine, [prior.id, new.id])


@pytest.mark.asyncio
async def test_does_not_fire_when_no_recent_prior(engine: Any) -> None:
    from app.models import Alert
    from app.services.enrollment import REENROLLMENT_RULE_ID, detect_reenrollment

    hostname = f"reenroll-test-{uuid4().hex[:8]}"
    # Prior enrollment well outside the 1-hour default window.
    prior = await _seed_host(engine, hostname, datetime.now(UTC) - timedelta(days=2))
    new = await _seed_host(engine, hostname, datetime.now(UTC))

    try:
        async with AsyncSession(engine) as db:
            await detect_reenrollment(
                db,
                hostname=hostname,
                os_family="linux",
                new_host_id=new.id,
                now=datetime.now(UTC),
                source="grpc",
                source_ip="10.0.0.5",
            )
            await db.commit()

        async with AsyncSession(engine) as db:
            alerts = (
                (
                    await db.execute(
                        select(Alert).where(
                            Alert.host_id == new.id,
                            Alert.rule_id == REENROLLMENT_RULE_ID,
                        )
                    )
                )
                .scalars()
                .all()
            )
            assert alerts == []
    finally:
        await _clean_up(engine, [prior.id, new.id])


@pytest.mark.asyncio
async def test_does_not_fire_when_prior_is_decommissioned(engine: Any) -> None:
    from app.models import Alert, Host, HostStatus
    from app.services.enrollment import REENROLLMENT_RULE_ID, detect_reenrollment

    hostname = f"reenroll-test-{uuid4().hex[:8]}"
    prior = await _seed_host(engine, hostname, datetime.now(UTC) - timedelta(seconds=60))
    # Flip the prior to DECOMMISSIONED so the detector should skip it
    # (a legitimate decommission-then-re-enroll workflow shouldn't
    # alarm).
    async with AsyncSession(engine) as db:
        h = await db.get(Host, prior.id)
        assert h is not None
        h.status = HostStatus.DECOMMISSIONED
        await db.commit()
    new = await _seed_host(engine, hostname, datetime.now(UTC))

    try:
        async with AsyncSession(engine) as db:
            await detect_reenrollment(
                db,
                hostname=hostname,
                os_family="linux",
                new_host_id=new.id,
                now=datetime.now(UTC),
                source="grpc",
                source_ip=None,
            )
            await db.commit()

        async with AsyncSession(engine) as db:
            alerts = (
                (
                    await db.execute(
                        select(Alert).where(
                            Alert.host_id == new.id,
                            Alert.rule_id == REENROLLMENT_RULE_ID,
                        )
                    )
                )
                .scalars()
                .all()
            )
            assert alerts == []
    finally:
        await _clean_up(engine, [prior.id, new.id])


@pytest.mark.asyncio
async def test_records_source_grpc_in_alert_payload(engine: Any) -> None:
    """Regression guard against the gRPC silence the reviewer flagged —
    if `source` ever stops being threaded through, this assertion
    catches it before the SOC has to figure out which RPC triggered."""
    from app.models import Alert
    from app.services.enrollment import REENROLLMENT_RULE_ID, detect_reenrollment

    hostname = f"reenroll-test-{uuid4().hex[:8]}"
    prior = await _seed_host(engine, hostname, datetime.now(UTC) - timedelta(seconds=10))
    new = await _seed_host(engine, hostname, datetime.now(UTC))

    try:
        async with AsyncSession(engine) as db:
            await detect_reenrollment(
                db,
                hostname=hostname,
                os_family="linux",
                new_host_id=new.id,
                now=datetime.now(UTC),
                source="grpc",
                source_ip=None,
            )
            await db.commit()

        async with AsyncSession(engine) as db:
            alert = (
                await db.execute(
                    select(Alert).where(
                        Alert.host_id == new.id,
                        Alert.rule_id == REENROLLMENT_RULE_ID,
                    )
                )
            ).scalar_one()
            details = alert.details or {}
            assert details["source"] == "grpc"
            assert details["detector"] == "reenrollment_v1"
    finally:
        await _clean_up(engine, [prior.id, new.id])
