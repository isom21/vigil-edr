"""Device control / USB block policy tests (Phase 3 #3.10).

Covers:
  * CRUD + role gates (analyst can list, admin mutates).
  * VID/PID normalisation (lowercase 4-hex; reject non-hex).
  * Unique-scope behaviour: same name global + group-scoped is fine,
    same name in same group is a 409.
  * Audit row written on create/update/delete.
  * `push_to_group` fans out one DEVICE_CONTROL_SYNC command per
    affected host, with the effective policy payload.
  * gRPC `_command_to_pb` translates DEVICE_CONTROL_SYNC into the
    proto envelope (kind / vids / pids / enabled).
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

# ---------- Schema helpers ----------


def test_normalise_vid_strips_prefix_and_lowercases() -> None:
    from app.schemas.device_policy import DevicePolicyCreate

    out = DevicePolicyCreate(
        kind="usb_block",  # type: ignore[arg-type]
        name="p",
        allowed_vendor_ids=["0x046D", "04F9"],
        allowed_product_ids=["c52b", "0123"],
    )
    assert out.allowed_vendor_ids == ["046d", "04f9"]
    assert out.allowed_product_ids == ["c52b", "0123"]


def test_normalise_vid_rejects_non_hex() -> None:
    from app.schemas.device_policy import DevicePolicyCreate

    with pytest.raises(ValueError):
        DevicePolicyCreate(
            kind="usb_block",  # type: ignore[arg-type]
            name="p",
            allowed_vendor_ids=["zzzz"],
        )


# ---------- API role gates ----------


@pytest.mark.asyncio
async def test_create_blocks_analyst(http_client, analyst_headers) -> None:
    resp = await http_client.post(
        "/api/device-policies",
        json={"name": "n", "kind": "usb_block"},
        headers=analyst_headers,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_list_allows_analyst(http_client, analyst_headers, admin_headers) -> None:
    await http_client.post(
        "/api/device-policies",
        json={"name": f"p-{uuid.uuid4().hex[:6]}", "kind": "usb_block"},
        headers=admin_headers,
    )
    resp = await http_client.get("/api/device-policies", headers=analyst_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


# ---------- Create + audit + conflict ----------


@pytest.mark.asyncio
async def test_create_audit_and_payload(http_client, admin_headers, db_session) -> None:
    from app.models import AuditLog

    resp = await http_client.post(
        "/api/device-policies",
        json={
            "name": "Block all USB",
            "kind": "usb_block",
            "allowed_vendor_ids": ["046D"],
            "allowed_product_ids": ["C52B"],
        },
        headers=admin_headers,
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["name"] == "Block all USB"
    assert body["kind"] == "usb_block"
    assert body["allowed_vendor_ids"] == ["046d"]
    assert body["allowed_product_ids"] == ["c52b"]
    assert body["host_group_id"] is None
    assert body["enabled"] is True

    rows = (
        (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == "device_policy.create")
            )
        )
        .scalars()
        .all()
    )
    assert rows
    assert rows[-1].payload["name"] == "Block all USB"


@pytest.mark.asyncio
async def test_create_duplicate_scope_conflicts(http_client, admin_headers) -> None:
    body = {"name": "dup", "kind": "usb_block"}
    first = await http_client.post("/api/device-policies", json=body, headers=admin_headers)
    assert first.status_code == 201
    second = await http_client.post("/api/device-policies", json=body, headers=admin_headers)
    assert second.status_code == 409


@pytest.mark.asyncio
async def test_same_name_different_scope_ok(http_client, admin_headers, db_session) -> None:
    """Global + group-scoped policies sharing a name coexist —
    Postgres uniqueness treats NULL as distinct."""
    from app.models import HostGroup

    group = HostGroup(name=f"g-{uuid.uuid4().hex[:8]}")
    db_session.add(group)
    await db_session.flush()

    a = await http_client.post(
        "/api/device-policies",
        json={"name": "shared", "kind": "usb_block"},
        headers=admin_headers,
    )
    assert a.status_code == 201
    b = await http_client.post(
        "/api/device-policies",
        json={"name": "shared", "kind": "usb_block", "host_group_id": str(group.id)},
        headers=admin_headers,
    )
    assert b.status_code == 201


# ---------- Update ----------


@pytest.mark.asyncio
async def test_update_audits_and_pushes(http_client, admin_headers, db_session) -> None:
    from app.models import AuditLog

    create = await http_client.post(
        "/api/device-policies",
        json={"name": "patch-me", "kind": "usb_block"},
        headers=admin_headers,
    )
    policy_id = create.json()["id"]

    resp = await http_client.patch(
        f"/api/device-policies/{policy_id}",
        json={"enabled": False, "description": "off for now"},
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["enabled"] is False
    assert resp.json()["description"] == "off for now"

    rows = (
        (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == "device_policy.update")
            )
        )
        .scalars()
        .all()
    )
    assert rows


# ---------- Delete ----------


@pytest.mark.asyncio
async def test_delete_audit_and_404(http_client, admin_headers, db_session) -> None:
    from app.models import AuditLog

    create = await http_client.post(
        "/api/device-policies",
        json={"name": "gone", "kind": "usb_block"},
        headers=admin_headers,
    )
    policy_id = create.json()["id"]
    resp = await http_client.delete(f"/api/device-policies/{policy_id}", headers=admin_headers)
    assert resp.status_code == 204

    missing = await http_client.delete(f"/api/device-policies/{policy_id}", headers=admin_headers)
    assert missing.status_code == 404

    rows = (
        (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == "device_policy.delete")
            )
        )
        .scalars()
        .all()
    )
    assert rows


# ---------- Push fan-out ----------


@pytest.mark.asyncio
async def test_create_queues_device_control_sync_command(
    http_client, admin_headers, db_session
) -> None:
    from app.models import Command, CommandKind, Host, OsFamily

    host = Host(hostname=f"h-{uuid.uuid4().hex[:8]}", os_family=OsFamily.LINUX)
    db_session.add(host)
    await db_session.flush()

    resp = await http_client.post(
        "/api/device-policies",
        json={
            "name": "fanout",
            "kind": "usb_block",
            "allowed_vendor_ids": ["046d"],
            "allowed_product_ids": ["c52b"],
        },
        headers=admin_headers,
    )
    assert resp.status_code == 201

    cmds = (
        (
            await db_session.execute(
                select(Command).where(
                    Command.host_id == host.id,
                    Command.kind == CommandKind.DEVICE_CONTROL_SYNC,
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(cmds) == 1
    payload = cmds[0].payload
    assert payload["kind"] == "usb_block"
    assert payload["allowed_vids"] == ["046d"]
    assert payload["allowed_pids"] == ["c52b"]
    assert payload["enabled"] is True


@pytest.mark.asyncio
async def test_group_scoped_policy_skips_non_member_hosts(
    http_client, admin_headers, db_session
) -> None:
    from app.models import Command, CommandKind, Host, HostGroup, OsFamily, host_in_group

    member = Host(hostname=f"m-{uuid.uuid4().hex[:8]}", os_family=OsFamily.LINUX)
    outsider = Host(hostname=f"o-{uuid.uuid4().hex[:8]}", os_family=OsFamily.LINUX)
    group = HostGroup(name=f"g-{uuid.uuid4().hex[:8]}")
    db_session.add_all([member, outsider, group])
    await db_session.flush()
    await db_session.execute(
        host_in_group.insert().values(host_id=member.id, host_group_id=group.id)
    )

    resp = await http_client.post(
        "/api/device-policies",
        json={
            "name": "scoped",
            "kind": "usb_read_only",
            "host_group_id": str(group.id),
        },
        headers=admin_headers,
    )
    assert resp.status_code == 201

    member_cmds = (
        (
            await db_session.execute(
                select(Command).where(
                    Command.host_id == member.id,
                    Command.kind == CommandKind.DEVICE_CONTROL_SYNC,
                )
            )
        )
        .scalars()
        .all()
    )
    outsider_cmds = (
        (
            await db_session.execute(
                select(Command).where(
                    Command.host_id == outsider.id,
                    Command.kind == CommandKind.DEVICE_CONTROL_SYNC,
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(member_cmds) == 1
    assert outsider_cmds == []


# ---------- gRPC translation ----------


def test_command_to_pb_device_control_sync_translates_payload() -> None:
    from app.grpc.services import _command_to_pb
    from app.models import Command, CommandKind, CommandStatus

    cmd = Command(
        id=uuid.uuid4(),
        host_id=uuid.uuid4(),
        kind=CommandKind.DEVICE_CONTROL_SYNC,
        status=CommandStatus.PENDING,
        payload={
            "kind": "usb_allow_only",
            "allowed_vids": ["046d", "04f9"],
            "allowed_pids": ["c52b", "0123"],
            "enabled": True,
        },
    )
    pb = _command_to_pb(cmd)
    assert pb is not None
    assert pb.device_control_sync.kind == "usb_allow_only"
    assert list(pb.device_control_sync.allowed_vids) == ["046d", "04f9"]
    assert list(pb.device_control_sync.allowed_pids) == ["c52b", "0123"]
    assert pb.device_control_sync.enabled is True


def test_command_to_pb_device_control_sync_tombstone() -> None:
    """`enabled=false` is a valid tombstone payload — the agent should
    clear any previously-applied policy of this kind."""
    from app.grpc.services import _command_to_pb
    from app.models import Command, CommandKind, CommandStatus

    cmd = Command(
        id=uuid.uuid4(),
        host_id=uuid.uuid4(),
        kind=CommandKind.DEVICE_CONTROL_SYNC,
        status=CommandStatus.PENDING,
        payload={
            "kind": "usb_block",
            "allowed_vids": [],
            "allowed_pids": [],
            "enabled": False,
        },
    )
    pb = _command_to_pb(cmd)
    assert pb is not None
    assert pb.device_control_sync.enabled is False
    assert list(pb.device_control_sync.allowed_vids) == []
