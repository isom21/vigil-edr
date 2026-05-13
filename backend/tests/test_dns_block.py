"""DNS block / sinkhole tests (Phase 2 #2.12).

Covers:
  * CRUD + role gates (analyst can list, admin mutates).
  * Domain normalisation (case, trailing dot, dedupe in bulk import).
  * Unique-scope behaviour: same domain global + group-scoped is fine,
    same domain in same group is a 409.
  * Audit row written on create/delete/import.
  * `queue_resync_commands` fans out one DNS_BLOCK_SYNC command per
    affected host with a deterministic payload.
  * gRPC `_command_to_pb` translates DNS_BLOCK_SYNC into the proto
    envelope and rejects nothing — empty lists are a valid resync.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

# ---------- Schema helpers ----------


def test_normalise_domain_strips_dot_and_lowercases() -> None:
    from app.schemas.dns_block import DnsBlockEntryCreate

    out = DnsBlockEntryCreate(domain="Evil.Example.COM.")
    assert out.domain == "evil.example.com"


def test_normalise_domain_rejects_path_shaped_input() -> None:
    from app.schemas.dns_block import DnsBlockEntryCreate

    with pytest.raises(ValueError):
        DnsBlockEntryCreate(domain="evil.com/path")


def test_bulk_import_dedupes_and_normalises() -> None:
    from app.schemas.dns_block import DnsBlockBulkImport

    out = DnsBlockBulkImport(domains=["A.example.com", "a.example.com.", "b.example.com", " "])
    # The blank entry drops out, the duplicate dedupes.
    assert out.domains == ["a.example.com", "b.example.com"]


# ---------- API role gates ----------


@pytest.mark.asyncio
async def test_create_blocks_analyst(http_client, analyst_headers) -> None:
    resp = await http_client.post(
        "/api/dns-blocks",
        json={"domain": "evil.example.com"},
        headers=analyst_headers,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_list_allows_analyst(http_client, analyst_headers, admin_headers) -> None:
    await http_client.post(
        "/api/dns-blocks", json={"domain": "evil.example.com"}, headers=admin_headers
    )
    resp = await http_client.get("/api/dns-blocks", headers=analyst_headers)
    assert resp.status_code == 200
    rows = resp.json()
    assert any(r["domain"] == "evil.example.com" for r in rows)


# ---------- Create + audit + conflict ----------


@pytest.mark.asyncio
async def test_create_audit_and_payload(http_client, admin_headers, db_session) -> None:
    from app.models import AuditLog

    resp = await http_client.post(
        "/api/dns-blocks",
        json={"domain": "Bad.Example.COM.", "action": "block"},
        headers=admin_headers,
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["domain"] == "bad.example.com"
    assert body["action"] == "block"
    assert body["host_group_id"] is None

    rows = (
        (await db_session.execute(select(AuditLog).where(AuditLog.action == "dns_block.create")))
        .scalars()
        .all()
    )
    assert rows
    assert rows[-1].payload["domain"] == "bad.example.com"


@pytest.mark.asyncio
async def test_create_duplicate_scope_conflicts(http_client, admin_headers) -> None:
    body = {"domain": "dup.example.com"}
    first = await http_client.post("/api/dns-blocks", json=body, headers=admin_headers)
    assert first.status_code == 201
    second = await http_client.post("/api/dns-blocks", json=body, headers=admin_headers)
    assert second.status_code == 409


@pytest.mark.asyncio
async def test_same_domain_different_scope_ok(http_client, admin_headers, db_session) -> None:
    """Global + group-scoped entries for the same domain coexist —
    Postgres uniqueness treats NULL as distinct, so the UNIQUE
    (host_group_id, domain) constraint doesn't fire."""
    from app.models import HostGroup

    group = HostGroup(name=f"g-{uuid.uuid4().hex[:8]}")
    db_session.add(group)
    await db_session.flush()

    a = await http_client.post(
        "/api/dns-blocks", json={"domain": "both.example.com"}, headers=admin_headers
    )
    assert a.status_code == 201
    b = await http_client.post(
        "/api/dns-blocks",
        json={"domain": "both.example.com", "host_group_id": str(group.id)},
        headers=admin_headers,
    )
    assert b.status_code == 201


# ---------- Delete ----------


@pytest.mark.asyncio
async def test_delete_audit_and_404(http_client, admin_headers, db_session) -> None:
    from app.models import AuditLog

    create = await http_client.post(
        "/api/dns-blocks", json={"domain": "gone.example.com"}, headers=admin_headers
    )
    entry_id = create.json()["id"]

    resp = await http_client.delete(f"/api/dns-blocks/{entry_id}", headers=admin_headers)
    assert resp.status_code == 204

    missing = await http_client.delete(f"/api/dns-blocks/{entry_id}", headers=admin_headers)
    assert missing.status_code == 404

    rows = (
        (await db_session.execute(select(AuditLog).where(AuditLog.action == "dns_block.delete")))
        .scalars()
        .all()
    )
    assert rows


# ---------- Bulk import ----------


@pytest.mark.asyncio
async def test_bulk_import_dedupes_existing(http_client, admin_headers) -> None:
    body = {"domains": ["one.example.com", "two.example.com", "three.example.com"]}
    first = await http_client.post("/api/dns-blocks/import", json=body, headers=admin_headers)
    assert first.status_code == 201
    assert first.json() == {"inserted": 3, "skipped": 0}

    second_body = {"domains": ["two.example.com", "three.example.com", "four.example.com"]}
    second = await http_client.post(
        "/api/dns-blocks/import", json=second_body, headers=admin_headers
    )
    assert second.status_code == 201
    assert second.json() == {"inserted": 1, "skipped": 2}


# ---------- Resync command fan-out ----------


@pytest.mark.asyncio
async def test_create_queues_dns_block_sync_command(http_client, admin_headers, db_session) -> None:
    from app.models import Command, CommandKind, Host, OsFamily

    host = Host(hostname=f"h-{uuid.uuid4().hex[:8]}", os_family=OsFamily.LINUX)
    db_session.add(host)
    await db_session.flush()

    resp = await http_client.post(
        "/api/dns-blocks", json={"domain": "fanout.example.com"}, headers=admin_headers
    )
    assert resp.status_code == 201

    cmds = (
        (
            await db_session.execute(
                select(Command).where(
                    Command.host_id == host.id, Command.kind == CommandKind.DNS_BLOCK_SYNC
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(cmds) == 1
    assert "fanout.example.com" in cmds[0].payload["block_domains"]


@pytest.mark.asyncio
async def test_group_scoped_entry_skips_non_member_hosts(
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
        "/api/dns-blocks",
        json={"domain": "scoped.example.com", "host_group_id": str(group.id)},
        headers=admin_headers,
    )
    assert resp.status_code == 201

    member_cmds = (
        (
            await db_session.execute(
                select(Command).where(
                    Command.host_id == member.id, Command.kind == CommandKind.DNS_BLOCK_SYNC
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
                    Command.host_id == outsider.id, Command.kind == CommandKind.DNS_BLOCK_SYNC
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(member_cmds) == 1
    assert outsider_cmds == []


# ---------- gRPC translation ----------


def test_command_to_pb_dns_block_sync_translates_payload() -> None:
    from app.grpc.services import _command_to_pb
    from app.models import Command, CommandKind, CommandStatus

    cmd = Command(
        id=uuid.uuid4(),
        host_id=uuid.uuid4(),
        kind=CommandKind.DNS_BLOCK_SYNC,
        status=CommandStatus.PENDING,
        payload={
            "block_domains": ["a.example.com", "b.example.com"],
            "sinkhole_domains": ["s.example.com"],
        },
    )
    pb = _command_to_pb(cmd)
    assert pb is not None
    assert list(pb.dns_block_sync.block_domains) == ["a.example.com", "b.example.com"]
    assert list(pb.dns_block_sync.sinkhole_domains) == ["s.example.com"]


def test_command_to_pb_dns_block_sync_empty_lists_ok() -> None:
    """An empty resync is a valid resync — it tells the agent to
    drop everything from its kernel map."""
    from app.grpc.services import _command_to_pb
    from app.models import Command, CommandKind, CommandStatus

    cmd = Command(
        id=uuid.uuid4(),
        host_id=uuid.uuid4(),
        kind=CommandKind.DNS_BLOCK_SYNC,
        status=CommandStatus.PENDING,
        payload={"block_domains": [], "sinkhole_domains": []},
    )
    pb = _command_to_pb(cmd)
    assert pb is not None
    assert list(pb.dns_block_sync.block_domains) == []
    assert list(pb.dns_block_sync.sinkhole_domains) == []
