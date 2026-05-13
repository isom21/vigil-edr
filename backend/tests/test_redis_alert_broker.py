"""Phase 1 #1.13: alert-broker Redis pub/sub + dedup-lock tests.

In multi-instance mode the broker fan-out path:

1. Every instance still polls the alerts table independently.
2. Before publishing, the instance races for a per-alert lock
   (`SET vigil:broker:lock:<id> NX PX 1500`).
3. The lock winner publishes JSON on `vigil:alerts:broadcast`.
4. Every instance's subscriber task receives the publish and pipes
   the event into its local SSE queues.

We exercise the four moving parts in isolation with fakeredis (no
DB required — the poll loop is tested separately in the legacy
broker tests).
"""

from __future__ import annotations

import asyncio
import json

import pytest
from fakeredis import aioredis as fakeredis_aio


@pytest.fixture
async def single_fake_redis():
    """Single fakeredis client suitable for tests that pretend to be
    one replica + manually exercise lock semantics."""
    client = fakeredis_aio.FakeRedis(decode_responses=False)
    yield client
    await client.aclose()


def _make_event(alert_id: str = "alert-1") -> dict:
    """Minimum-shape SSE event for fan-out tests. The broker doesn't
    introspect the payload — it forwards verbatim."""
    return {"id": alert_id, "severity": "high", "summary": "x"}


async def test_dedup_lock_first_writer_wins(single_fake_redis) -> None:
    """`SET key NX PX` only succeeds the first time inside the TTL."""
    won_a = await single_fake_redis.set("vigil:broker:lock:alert-1", b"1", nx=True, px=1500)
    won_b = await single_fake_redis.set("vigil:broker:lock:alert-1", b"1", nx=True, px=1500)
    assert won_a is True
    assert won_b is None or won_b is False


async def test_broker_fanout_publishes_once_per_alert(single_fake_redis) -> None:
    """Two instances racing the same alert id only end up with one
    publish on the channel."""
    from app.services.alert_broker import REDIS_CHANNEL, AlertBroker

    broker_a = AlertBroker()
    broker_b = AlertBroker()
    broker_a._redis = single_fake_redis
    broker_b._redis = single_fake_redis

    # Set up a passive subscriber so we can count messages published
    # to the channel.
    pubsub = single_fake_redis.pubsub(ignore_subscribe_messages=True)
    await pubsub.subscribe(REDIS_CHANNEL)

    event = _make_event("alert-shared-1")
    # Race: A wins the lock, B should be a no-op.
    await broker_a._fanout(event, "alert-shared-1")
    await broker_b._fanout(event, "alert-shared-1")

    # Drain messages with a small grace window — fakeredis publish is
    # synchronous so this is mostly a formality.
    received = []
    for _ in range(5):
        msg = await pubsub.get_message(timeout=0.2)
        if msg and msg.get("type") == "message":
            received.append(msg)
    await pubsub.unsubscribe(REDIS_CHANNEL)
    await pubsub.aclose()

    assert len(received) == 1, f"expected exactly one publish, got {len(received)}"
    payload = json.loads(received[0]["data"])
    assert payload["id"] == "alert-shared-1"


async def test_broker_subscriber_pipes_publishes_to_local_queue(single_fake_redis) -> None:
    """The subscriber task hooks each pub/sub message into local
    subscriber queues so SSE clients see the event."""
    from app.services.alert_broker import AlertBroker

    broker = AlertBroker()
    broker._redis = single_fake_redis
    await broker.start()
    try:
        async with broker.subscribe() as q:
            # Allow the subscriber task to attach. The publish below
            # races the subscribe, so we publish AFTER subscribe()
            # has finalised its `_subs` registration (yield is what
            # the contextmanager waits on).
            await asyncio.sleep(0.05)
            event = _make_event("alert-pub-1")
            await broker._fanout(event, "alert-pub-1")
            # Pull from the local queue (the subscriber task should
            # forward the publish back here within a short window).
            received = await asyncio.wait_for(q.get(), timeout=2.0)
        assert received["id"] == "alert-pub-1"
    finally:
        await broker.stop()


async def test_broker_fanout_falls_back_to_local_on_publish_failure(
    monkeypatch, single_fake_redis
) -> None:
    """If `publish` raises, the broker still delivers the event
    locally so the connected client doesn't lose the alert."""
    from app.services.alert_broker import AlertBroker

    broker = AlertBroker()
    broker._redis = single_fake_redis

    async def _boom(*_a, **_kw):
        raise RuntimeError("redis publish exploded")

    monkeypatch.setattr(single_fake_redis, "publish", _boom)
    async with broker.subscribe() as q:
        await broker._fanout(_make_event("alert-fallback"), "alert-fallback")
        received = await asyncio.wait_for(q.get(), timeout=2.0)
    assert received["id"] == "alert-fallback"


async def test_broker_single_instance_path_unchanged() -> None:
    """With no Redis client, fan-out goes straight to the local
    queues — same shape as the original M22.b implementation."""
    from app.services.alert_broker import AlertBroker

    broker = AlertBroker()
    # _redis defaults to None; do nothing else.
    async with broker.subscribe() as q:
        await broker._fanout(_make_event("alert-local"), "alert-local")
        received = await asyncio.wait_for(q.get(), timeout=2.0)
    assert received["id"] == "alert-local"
