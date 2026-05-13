"""Phase 2 #2.9 — container telemetry on process events.

Two contracts under test:

1. `to_ecs` lifts the protobuf `ProcessEvent.container_*` fields onto
   the ECS-aligned `container.id` / `container.image.name` /
   `container.runtime` keys. Bare-metal processes (no container.id on
   the wire) emit no `container` block at all.

2. `AlertDetail.container` carries the attribution from the
   triggering telemetry doc. The test stubs `fetch_events_by_ids` so
   the alert-lookup path doesn't need a real OpenSearch cluster, and
   verifies the resolver picks the first doc with a populated
   `container.id`.
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from app.proto_gen.edr.v1 import events_pb2
from app.services.normalizer import to_ecs


def _make_process_event(
    container_id: str = "",
    container_image: str = "",
    container_runtime: int = events_pb2.CONTAINER_RUNTIME_UNKNOWN,
) -> events_pb2.EndpointEvent:
    ev = events_pb2.EndpointEvent(
        event_id="01H000000000000000000PROC1",
        host_id="00000000-0000-0000-0000-000000000001",
        agent_id="00000000-0000-0000-0000-000000000001",
        agent_version="0.0.0-test",
        action="process_started",
    )
    ev.category.append(events_pb2.EVENT_CATEGORY_PROCESS)
    proc = ev.process
    proc.process.pid = 4242
    proc.executable = "/usr/bin/cat"
    proc.name = "cat"
    proc.command_line = "cat /etc/passwd"
    proc.action = events_pb2.PROCESS_ACTION_START
    proc.container_id = container_id
    proc.container_image = container_image
    proc.container_runtime = container_runtime  # pyright: ignore[reportAttributeAccessIssue]
    return ev


def test_to_ecs_docker_emits_container_block() -> None:
    ev = _make_process_event(
        container_id="abc123def4567890abc123def4567890abc123def4567890abc123def4567890",
        container_image="nginx:1.27.0",
        container_runtime=events_pb2.CONTAINER_RUNTIME_DOCKER,
    )
    doc = to_ecs(ev)
    assert doc["container"]["id"].startswith("abc123")
    assert doc["container"]["image"]["name"] == "nginx:1.27.0"
    assert doc["container"]["runtime"] == "docker"


@pytest.mark.parametrize(
    "runtime_enum,token",
    [
        (events_pb2.CONTAINER_RUNTIME_DOCKER, "docker"),
        (events_pb2.CONTAINER_RUNTIME_CONTAINERD, "containerd"),
        (events_pb2.CONTAINER_RUNTIME_CRI_O, "cri_o"),
        (events_pb2.CONTAINER_RUNTIME_PODMAN, "podman"),
    ],
)
def test_to_ecs_runtime_tokens(runtime_enum: int, token: str) -> None:
    ev = _make_process_event(container_id="x" * 64, container_runtime=runtime_enum)
    doc = to_ecs(ev)
    assert doc["container"]["runtime"] == token


def test_to_ecs_skips_image_when_runtime_lookup_failed() -> None:
    """Agent couldn't reach the runtime socket → image stays empty.
    The normalizer must omit `container.image` entirely (pruned by
    _prune_none) rather than indexing an empty-string keyword."""
    ev = _make_process_event(
        container_id="d" * 64,
        container_image="",
        container_runtime=events_pb2.CONTAINER_RUNTIME_CONTAINERD,
    )
    doc = to_ecs(ev)
    assert doc["container"]["id"] == "d" * 64
    assert "image" not in doc["container"]


def test_to_ecs_bare_metal_emits_no_container_block() -> None:
    ev = _make_process_event()
    doc = to_ecs(ev)
    assert "container" not in doc


def test_to_ecs_unknown_runtime_omits_runtime_field() -> None:
    """Agent saw a container id it couldn't classify (no matching
    cgroup path prefix). We emit container.id so the SOC still has
    something to pivot on, but no `runtime` field — UNKNOWN must not
    leak to the index as a real value."""
    ev = _make_process_event(
        container_id="z" * 64,
        container_runtime=events_pb2.CONTAINER_RUNTIME_UNKNOWN,
    )
    doc = to_ecs(ev)
    assert doc["container"]["id"] == "z" * 64
    assert "runtime" not in doc["container"]


# ---------- AlertDetail.container resolver ----------


@pytest.mark.asyncio
async def test_alert_detail_returns_container_from_trigger_doc(
    http_client, admin_headers, db_session
):
    from app.models import (
        Alert,
        AlertState,
        Host,
        HostStatus,
        OsFamily,
        Rule,
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
    )
    db_session.add_all([host, rule])
    await db_session.flush()

    alert = Alert(
        host_id=host.id,
        rule_id=rule.id,
        severity=Severity.HIGH,
        state=AlertState.NEW,
        summary="container test alert",
        telemetry_doc_ids=["01H000000000000000000PROC1"],
    )
    db_session.add(alert)
    await db_session.flush()

    trigger_doc = {
        "event": {"id": "01H000000000000000000PROC1", "action": "process_started"},
        "host": {"id": str(host.id)},
        "process": {"pid": 4242, "executable": "/usr/bin/cat"},
        "container": {
            "id": "a" * 64,
            "image": {"name": "nginx:1.27.0"},
            "runtime": "docker",
        },
    }

    async def _stub_fetch(client, ids):
        return [trigger_doc] if ids == ["01H000000000000000000PROC1"] else []

    with patch("app.services.opensearch.fetch_events_by_ids", new=_stub_fetch):
        resp = await http_client.get(f"/api/alerts/{alert.id}", headers=admin_headers)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["container"] is not None
    assert body["container"]["id"] == "a" * 64
    assert body["container"]["image"] == "nginx:1.27.0"
    assert body["container"]["runtime"] == "docker"


@pytest.mark.asyncio
async def test_alert_detail_container_is_none_for_bare_metal_trigger(
    http_client, admin_headers, db_session
):
    """Triggering doc has no `container` block → AlertDetail.container is null."""
    from app.models import (
        Alert,
        AlertState,
        Host,
        HostStatus,
        OsFamily,
        Rule,
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
    )
    db_session.add_all([host, rule])
    await db_session.flush()

    alert = Alert(
        host_id=host.id,
        rule_id=rule.id,
        severity=Severity.HIGH,
        state=AlertState.NEW,
        summary="bare-metal alert",
        telemetry_doc_ids=["01H000000000000000000PROC2"],
    )
    db_session.add(alert)
    await db_session.flush()

    bare_metal_doc = {
        "event": {"id": "01H000000000000000000PROC2", "action": "process_started"},
        "host": {"id": str(host.id)},
        "process": {"pid": 1234, "executable": "/usr/bin/cat"},
    }

    async def _stub_fetch(client, ids):
        return [bare_metal_doc]

    with patch("app.services.opensearch.fetch_events_by_ids", new=_stub_fetch):
        resp = await http_client.get(f"/api/alerts/{alert.id}", headers=admin_headers)

    assert resp.status_code == 200, resp.text
    assert resp.json()["container"] is None


# ---------- HostDetail.container_runtimes_seen ----------


@pytest.mark.asyncio
async def test_host_detail_returns_container_runtimes_seen(http_client, admin_headers, db_session):
    """The /api/hosts/{id} endpoint runs a 24h terms agg over
    `container.runtime` and surfaces the result. Stub the underlying
    OpenSearch client so the test doesn't need a live cluster."""
    from app.models import Host, HostStatus, OsFamily

    host = Host(
        hostname=f"h-{os.urandom(3).hex()}",
        os_family=OsFamily.LINUX,
        status=HostStatus.ONLINE,
    )
    db_session.add(host)
    await db_session.flush()

    class _StubOSClient:
        async def search(self, *_, **__):
            return {
                "aggregations": {
                    "runtimes": {
                        "buckets": [
                            {"key": "docker", "doc_count": 42},
                            {"key": "containerd", "doc_count": 7},
                        ]
                    }
                }
            }

        async def close(self):
            pass

    with patch("app.services.opensearch._client", return_value=_StubOSClient()):
        resp = await http_client.get(f"/api/hosts/{host.id}", headers=admin_headers)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["container_runtimes_seen"] == ["docker", "containerd"]


@pytest.mark.asyncio
async def test_host_detail_empty_runtimes_when_opensearch_unavailable(
    http_client, admin_headers, db_session
):
    """OpenSearch down → endpoint must still return the host with an
    empty container_runtimes_seen list, not a 5xx."""
    from app.models import Host, HostStatus, OsFamily

    host = Host(
        hostname=f"h-{os.urandom(3).hex()}",
        os_family=OsFamily.LINUX,
        status=HostStatus.ONLINE,
    )
    db_session.add(host)
    await db_session.flush()

    class _BrokenOSClient:
        async def search(self, *_, **__):
            raise RuntimeError("opensearch unreachable")

        async def close(self):
            pass

    with patch("app.services.opensearch._client", return_value=_BrokenOSClient()):
        resp = await http_client.get(f"/api/hosts/{host.id}", headers=admin_headers)

    assert resp.status_code == 200, resp.text
    assert resp.json()["container_runtimes_seen"] == []
