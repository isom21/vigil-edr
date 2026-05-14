"""Deception / honeytoken tests (Phase 4 #4.5).

Covers:
  * CRUD + role gates (analyst can list, admin mutates).
  * Audit row written on create/update/delete.
  * `push_to_group` fans out one DEPLOY_HONEYTOKEN command per host.
  * `record_hit` writes a HoneytokenHit + a critical Alert via the
    synthetic `HONEYTOKEN_HIT_RULE_ID`.
  * gRPC `_command_to_pb` translates DEPLOY_HONEYTOKEN into the proto
    envelope (specs[].id, kind, payload bytes, target_path).
"""

from __future__ import annotations

import base64
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select

# ---------- API role gates ----------


@pytest.mark.asyncio
async def test_create_blocks_analyst(http_client, analyst_headers) -> None:
    resp = await http_client.post(
        "/api/honeytokens",
        json={"name": "n", "kind": "fake_file"},
        headers=analyst_headers,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_list_allows_analyst(http_client, analyst_headers, admin_headers) -> None:
    await http_client.post(
        "/api/honeytokens",
        json={"name": f"hp-{uuid.uuid4().hex[:6]}", "kind": "fake_file"},
        headers=admin_headers,
    )
    resp = await http_client.get("/api/honeytokens", headers=analyst_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


# ---------- Create + audit + conflict ----------


@pytest.mark.asyncio
async def test_create_audit_and_payload(http_client, admin_headers, db_session) -> None:
    from app.models import AuditLog

    resp = await http_client.post(
        "/api/honeytokens",
        json={
            "name": "decoy-creds-finance",
            "kind": "fake_file",
            "target_path": "/var/lib/secrets/aws.creds",
            "payload_json": {"body": base64.b64encode(b"AKIA...").decode()},
        },
        headers=admin_headers,
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["name"] == "decoy-creds-finance"
    assert body["kind"] == "fake_file"
    assert body["target_path"] == "/var/lib/secrets/aws.creds"
    assert body["enabled"] is True
    assert body["host_group_id"] is None

    rows = (
        (await db_session.execute(select(AuditLog).where(AuditLog.action == "honeytoken.create")))
        .scalars()
        .all()
    )
    assert rows
    assert rows[-1].payload["name"] == "decoy-creds-finance"


@pytest.mark.asyncio
async def test_create_duplicate_name_conflicts(http_client, admin_headers) -> None:
    body = {"name": "dup", "kind": "fake_file"}
    first = await http_client.post("/api/honeytokens", json=body, headers=admin_headers)
    assert first.status_code == 201
    second = await http_client.post("/api/honeytokens", json=body, headers=admin_headers)
    assert second.status_code == 409


# ---------- Update + delete ----------


@pytest.mark.asyncio
async def test_update_audits_and_changes(http_client, admin_headers, db_session) -> None:
    from app.models import AuditLog

    create = await http_client.post(
        "/api/honeytokens",
        json={"name": "patch-me", "kind": "fake_file"},
        headers=admin_headers,
    )
    token_id = create.json()["id"]

    resp = await http_client.patch(
        f"/api/honeytokens/{token_id}",
        json={"enabled": False, "target_path": "/tmp/decoy.dat"},
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["enabled"] is False
    assert resp.json()["target_path"] == "/tmp/decoy.dat"

    rows = (
        (await db_session.execute(select(AuditLog).where(AuditLog.action == "honeytoken.update")))
        .scalars()
        .all()
    )
    assert rows


@pytest.mark.asyncio
async def test_delete_audit_and_404(http_client, admin_headers, db_session) -> None:
    from app.models import AuditLog

    create = await http_client.post(
        "/api/honeytokens",
        json={"name": "gone", "kind": "fake_regkey"},
        headers=admin_headers,
    )
    token_id = create.json()["id"]
    resp = await http_client.delete(f"/api/honeytokens/{token_id}", headers=admin_headers)
    assert resp.status_code == 204

    missing = await http_client.delete(f"/api/honeytokens/{token_id}", headers=admin_headers)
    assert missing.status_code == 404

    rows = (
        (await db_session.execute(select(AuditLog).where(AuditLog.action == "honeytoken.delete")))
        .scalars()
        .all()
    )
    assert rows


# ---------- Push fan-out ----------


@pytest.mark.asyncio
async def test_create_queues_deploy_command_per_host(
    http_client, admin_headers, db_session
) -> None:
    from app.models import Command, CommandKind, Host, OsFamily

    host = Host(hostname=f"h-{uuid.uuid4().hex[:8]}", os_family=OsFamily.LINUX)
    db_session.add(host)
    await db_session.flush()

    resp = await http_client.post(
        "/api/honeytokens",
        json={
            "name": "fanout-decoy",
            "kind": "fake_file",
            "target_path": "/etc/.decoy",
            "payload_json": {"body": base64.b64encode(b"decoy").decode()},
        },
        headers=admin_headers,
    )
    assert resp.status_code == 201, resp.text

    cmds = (
        (
            await db_session.execute(
                select(Command).where(
                    Command.host_id == host.id,
                    Command.kind == CommandKind.DEPLOY_HONEYTOKEN,
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(cmds) == 1
    payload = cmds[0].payload
    assert isinstance(payload["specs"], list)
    spec = payload["specs"][0]
    assert spec["name"] == "fanout-decoy"
    assert spec["kind"] == "fake_file"
    assert spec["target_path"] == "/etc/.decoy"
    # b64-encoded raw bytes of "decoy".
    assert base64.b64decode(spec["payload_b64"]) == b"decoy"


@pytest.mark.asyncio
async def test_group_scoped_token_skips_non_member_hosts(
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
        "/api/honeytokens",
        json={
            "name": "scoped-decoy",
            "kind": "fake_file",
            "target_path": "/tmp/decoy.dat",
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
                    Command.kind == CommandKind.DEPLOY_HONEYTOKEN,
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
                    Command.kind == CommandKind.DEPLOY_HONEYTOKEN,
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(member_cmds) == 1
    assert outsider_cmds == []


# ---------- record_hit creates synthetic-rule Alert ----------


@pytest.mark.asyncio
async def test_record_hit_creates_critical_alert(db_session) -> None:
    from app.models import Alert, Honeytoken, Host, OsFamily, Rule, Severity
    from app.models.synthetic_rules import HONEYTOKEN_HIT_RULE_ID
    from app.services.honeytoken import record_hit

    host = Host(hostname=f"h-{uuid.uuid4().hex[:8]}", os_family=OsFamily.LINUX)
    token = Honeytoken(
        kind="fake_file",
        name=f"decoy-{uuid.uuid4().hex[:8]}",
        target_path="/tmp/decoy",
        payload_json={},
    )
    db_session.add_all([host, token])
    await db_session.flush()

    hit = await record_hit(
        db_session,
        honeytoken_id=token.id,
        host_id=host.id,
        process_pid=4242,
        process_executable="/usr/bin/cat",
        hit_at=datetime.now(UTC),
    )
    assert hit is not None
    assert hit.alert_id is not None

    alert = await db_session.get(Alert, hit.alert_id)
    assert alert is not None
    assert alert.severity == Severity.CRITICAL
    assert alert.rule_id == HONEYTOKEN_HIT_RULE_ID
    assert alert.details["honeytoken_id"] == str(token.id)
    assert alert.details["process_pid"] == 4242

    # Synthetic rule got bootstrapped.
    synth = await db_session.get(Rule, HONEYTOKEN_HIT_RULE_ID)
    assert synth is not None
    assert synth.severity == Severity.CRITICAL

    # Counter bumped on the parent token.
    await db_session.refresh(token)
    assert token.hit_count == 1


@pytest.mark.asyncio
async def test_record_hit_missing_token_is_noop(db_session) -> None:
    from app.models import Host, OsFamily
    from app.services.honeytoken import record_hit

    host = Host(hostname=f"h-{uuid.uuid4().hex[:8]}", os_family=OsFamily.LINUX)
    db_session.add(host)
    await db_session.flush()

    result = await record_hit(
        db_session,
        honeytoken_id=uuid.uuid4(),
        host_id=host.id,
        process_pid=None,
        process_executable=None,
    )
    assert result is None


# ---------- gRPC translation ----------


def test_command_to_pb_deploy_honeytoken_translates_payload() -> None:
    from app.grpc.services import _command_to_pb
    from app.models import Command, CommandKind, CommandStatus

    spec_id = str(uuid.uuid4())
    cmd = Command(
        id=uuid.uuid4(),
        host_id=uuid.uuid4(),
        kind=CommandKind.DEPLOY_HONEYTOKEN,
        status=CommandStatus.PENDING,
        payload={
            "specs": [
                {
                    "id": spec_id,
                    "kind": "fake_file",
                    "name": "decoy-1",
                    "target_path": "/tmp/decoy",
                    "payload_b64": base64.b64encode(b"hello").decode(),
                },
                {
                    "id": str(uuid.uuid4()),
                    "kind": "fake_regkey",
                    "name": "decoy-reg",
                    "target_path": r"HKLM\SOFTWARE\Acme\Decoy",
                    "payload_b64": base64.b64encode(b"x").decode(),
                },
            ]
        },
    )
    pb = _command_to_pb(cmd)
    assert pb is not None
    specs = list(pb.deploy_honeytoken.specs)
    assert len(specs) == 2
    assert specs[0].id == spec_id
    assert specs[0].kind == "fake_file"
    assert specs[0].name == "decoy-1"
    assert specs[0].target_path == "/tmp/decoy"
    assert specs[0].payload == b"hello"
    assert specs[1].kind == "fake_regkey"


def test_command_to_pb_deploy_honeytoken_skips_malformed_specs() -> None:
    from app.grpc.services import _command_to_pb
    from app.models import Command, CommandKind, CommandStatus

    cmd = Command(
        id=uuid.uuid4(),
        host_id=uuid.uuid4(),
        kind=CommandKind.DEPLOY_HONEYTOKEN,
        status=CommandStatus.PENDING,
        payload={
            "specs": [
                {"id": "", "kind": "fake_file"},  # empty id -> skipped
                {"id": "abc", "kind": "fake_file", "name": "ok", "payload_b64": ""},
            ]
        },
    )
    pb = _command_to_pb(cmd)
    assert pb is not None
    specs = list(pb.deploy_honeytoken.specs)
    assert len(specs) == 1
    assert specs[0].id == "abc"
