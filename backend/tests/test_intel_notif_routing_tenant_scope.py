"""Regression tests for CODE-10, CODE-11, CODE-12.

Three small routers — intel feeds, notification channels, routing
rules — previously had no tenant scope. Each had its own model with
a tenant_id column already; the routers just never filtered or
stamped it.

Plus: routing.create / routing.update referenced channel_ids and
host_group_id without checking same-tenant, so a tenant-A routing
rule could fan out alerts to tenant-B's Slack webhook (or filter
on tenant-B's host group).
"""

from __future__ import annotations

import json
import os
from typing import Any

import pytest
import pytest_asyncio


@pytest_asyncio.fixture
async def _per_tenant_feeds(db_session: Any, tenant_a: Any, tenant_b: Any) -> tuple[Any, Any]:
    from app.models import IntelFeed, IntelFeedKind

    a = IntelFeed(
        tenant_id=tenant_a.id,
        name=f"feed-a-{os.urandom(2).hex()}",
        kind=IntelFeedKind.ABUSECH_CSV,
        url="https://example.invalid/a.csv",
        interval_s=3600,
        enabled=True,
    )
    b = IntelFeed(
        tenant_id=tenant_b.id,
        name=f"feed-b-{os.urandom(2).hex()}",
        kind=IntelFeedKind.ABUSECH_CSV,
        url="https://example.invalid/b.csv",
        interval_s=3600,
        enabled=True,
    )
    db_session.add_all([a, b])
    await db_session.flush()
    return a, b


@pytest_asyncio.fixture
async def _per_tenant_channels(db_session: Any, tenant_a: Any, tenant_b: Any) -> tuple[Any, Any]:
    from app.models import NotificationChannel, NotificationChannelKind
    from app.services.routing import encrypt_config

    cfg = {"webhook_url": "https://hooks.slack.com/services/T/B/x"}
    a = NotificationChannel(
        tenant_id=tenant_a.id,
        name=f"chan-a-{os.urandom(2).hex()}",
        kind=NotificationChannelKind.SLACK,
        encrypted_config=encrypt_config(cfg),
        enabled=True,
    )
    b = NotificationChannel(
        tenant_id=tenant_b.id,
        name=f"chan-b-{os.urandom(2).hex()}",
        kind=NotificationChannelKind.SLACK,
        encrypted_config=encrypt_config(cfg),
        enabled=True,
    )
    db_session.add_all([a, b])
    await db_session.flush()
    return a, b


# ---------- intel feeds (CODE-10) -----------------------------------------


@pytest.mark.asyncio
async def test_intel_list_invisibility(
    http_client: Any, admin_in_a: Any, _per_tenant_feeds: tuple[Any, Any]
) -> None:
    from tests.conftest import headers_for

    a, b = _per_tenant_feeds
    resp = await http_client.get("/api/intel/feeds", headers=headers_for(admin_in_a))
    assert resp.status_code == 200
    ids = {item["id"] for item in resp.json()["items"]}
    assert str(a.id) in ids
    assert str(b.id) not in ids


@pytest.mark.asyncio
async def test_intel_get_404_cross_tenant(
    http_client: Any, admin_in_a: Any, _per_tenant_feeds: tuple[Any, Any]
) -> None:
    from tests.conftest import headers_for

    _, b = _per_tenant_feeds
    resp = await http_client.get(f"/api/intel/feeds/{b.id}", headers=headers_for(admin_in_a))
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_intel_patch_404_cross_tenant(
    http_client: Any, admin_in_a: Any, _per_tenant_feeds: tuple[Any, Any]
) -> None:
    from tests.conftest import headers_for

    _, b = _per_tenant_feeds
    resp = await http_client.patch(
        f"/api/intel/feeds/{b.id}",
        json={"enabled": False},
        headers=headers_for(admin_in_a),
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_intel_trigger_pull_404_cross_tenant(
    http_client: Any, admin_in_a: Any, _per_tenant_feeds: tuple[Any, Any]
) -> None:
    from tests.conftest import headers_for

    _, b = _per_tenant_feeds
    resp = await http_client.post(f"/api/intel/feeds/{b.id}/pull", headers=headers_for(admin_in_a))
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_intel_create_stamps_actor_tenant(
    http_client: Any, admin_in_a: Any, tenant_a: Any, db_session: Any
) -> None:
    from uuid import UUID

    from sqlalchemy import select

    from app.models import IntelFeed
    from tests.conftest import headers_for

    resp = await http_client.post(
        "/api/intel/feeds",
        json={
            "name": f"new-feed-{os.urandom(2).hex()}",
            "kind": "abusech_csv",
            "url": "https://example.invalid/new.csv",
            "interval_s": 3600,
            "enabled": True,
        },
        headers=headers_for(admin_in_a),
    )
    assert resp.status_code == 201, resp.text
    new_id = UUID(resp.json()["id"])
    row = (await db_session.execute(select(IntelFeed).where(IntelFeed.id == new_id))).scalar_one()
    assert row.tenant_id == tenant_a.id


# ---------- notification channels (CODE-11) -------------------------------


@pytest.mark.asyncio
async def test_notif_list_invisibility(
    http_client: Any, admin_in_a: Any, _per_tenant_channels: tuple[Any, Any]
) -> None:
    from tests.conftest import headers_for

    a, b = _per_tenant_channels
    resp = await http_client.get("/api/notifications/channels", headers=headers_for(admin_in_a))
    assert resp.status_code == 200
    ids = {item["id"] for item in resp.json()}
    assert str(a.id) in ids
    assert str(b.id) not in ids


@pytest.mark.asyncio
async def test_notif_get_404_cross_tenant(
    http_client: Any, admin_in_a: Any, _per_tenant_channels: tuple[Any, Any]
) -> None:
    from tests.conftest import headers_for

    _, b = _per_tenant_channels
    resp = await http_client.get(
        f"/api/notifications/channels/{b.id}", headers=headers_for(admin_in_a)
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_notif_create_stamps_actor_tenant(
    http_client: Any, admin_in_a: Any, tenant_a: Any, db_session: Any
) -> None:
    from uuid import UUID

    from sqlalchemy import select

    from app.models import NotificationChannel
    from tests.conftest import headers_for

    resp = await http_client.post(
        "/api/notifications/channels",
        json={
            "name": f"new-chan-{os.urandom(2).hex()}",
            "kind": "slack",
            "config": {"webhook_url": "https://hooks.slack.com/services/T/B/x"},
            "enabled": True,
        },
        headers=headers_for(admin_in_a),
    )
    assert resp.status_code == 201, resp.text
    new_id = UUID(resp.json()["id"])
    row = (
        await db_session.execute(
            select(NotificationChannel).where(NotificationChannel.id == new_id)
        )
    ).scalar_one()
    assert row.tenant_id == tenant_a.id


# ---------- routing rules (CODE-12) ---------------------------------------


@pytest.mark.asyncio
async def test_routing_rejects_cross_tenant_channel_id(
    http_client: Any,
    admin_in_a: Any,
    _per_tenant_channels: tuple[Any, Any],
) -> None:
    """A tenant-A routing rule referencing a tenant-B channel must
    400 — otherwise alerts fan out cross-tenant at fire-time."""
    from tests.conftest import headers_for

    _, b = _per_tenant_channels
    resp = await http_client.post(
        "/api/notifications/rules",
        json={
            "name": f"rule-{os.urandom(2).hex()}",
            "min_severity": "high",
            "channel_ids": [str(b.id)],
            "enabled": True,
        },
        headers=headers_for(admin_in_a),
    )
    assert resp.status_code == 400, resp.text
    detail = json.dumps(resp.json())
    assert "unknown notification channel" in detail


@pytest.mark.asyncio
async def test_routing_rejects_cross_tenant_host_group(
    http_client: Any,
    db_session: Any,
    admin_in_a: Any,
    tenant_b: Any,
) -> None:
    from app.models import HostGroup
    from tests.conftest import headers_for

    foreign = HostGroup(tenant_id=tenant_b.id, name=f"b-grp-{os.urandom(2).hex()}")
    db_session.add(foreign)
    await db_session.flush()
    resp = await http_client.post(
        "/api/notifications/rules",
        json={
            "name": f"rule-{os.urandom(2).hex()}",
            "min_severity": "high",
            "host_group_id": str(foreign.id),
            "channel_ids": [],
            "enabled": True,
        },
        headers=headers_for(admin_in_a),
    )
    assert resp.status_code == 400, resp.text
    assert "unknown host_group_id" in resp.json()["detail"]
