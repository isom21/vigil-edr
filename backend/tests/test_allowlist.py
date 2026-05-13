"""Application allowlist tests (Phase 2 #2.8).

Covers:

  * CRUD + role gates (admin can mutate, analyst can read).
  * Mode flip queues allowlist_sync Commands for every host in the
    group, with mode + hashes encoded into the payload.
  * Manual entry merges with a previously-learned entry rather than
    duplicating — the (group, sha256) unique constraint guarantees
    this.
  * The learner worker upserts on (group, sha256), bumps last_seen,
    and skips observations from hosts that aren't in a learn-mode
    group.
  * gRPC translation of an ALLOWLIST_SYNC Command produces an
    AllowlistSyncCmd with the correct mode + 32-byte hash bytes.
  * Audit row written for mode changes + entry mutations.
  * Refusal to delete the last entry while ENFORCEing — a footgun
    that would lock the group out of every binary at once.
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager

import pytest
from sqlalchemy import select


def _test_session_maker(db_session):
    @asynccontextmanager
    async def _maker():
        yield db_session

    return _maker


# ---------- Helpers ----------


async def _make_group(db_session, name: str | None = None):
    from app.models import HostGroup

    g = HostGroup(name=name or f"grp-{uuid.uuid4().hex[:8]}")
    db_session.add(g)
    await db_session.flush()
    return g


async def _make_host_in_group(db_session, group_id):
    from app.models import Host, OsFamily, host_in_group

    h = Host(
        hostname=f"host-{uuid.uuid4().hex[:8]}",
        os_family=OsFamily.LINUX,
    )
    db_session.add(h)
    await db_session.flush()
    await db_session.execute(host_in_group.insert().values(host_id=h.id, host_group_id=group_id))
    await db_session.flush()
    return h


# ---------- API role gates ----------


@pytest.mark.asyncio
async def test_get_mode_default_off(http_client, admin_headers, db_session):
    g = await _make_group(db_session)
    resp = await http_client.get(f"/api/host-groups/{g.id}/allowlist", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["mode"] == "off"
    assert body["entry_count"] == 0


@pytest.mark.asyncio
async def test_mode_flip_admin_only(http_client, admin_headers, analyst_headers, db_session):
    g = await _make_group(db_session)
    # Analyst can read but not flip.
    resp = await http_client.put(
        f"/api/host-groups/{g.id}/allowlist/mode",
        json={"mode": "learn"},
        headers=analyst_headers,
    )
    assert resp.status_code == 403

    resp = await http_client.put(
        f"/api/host-groups/{g.id}/allowlist/mode",
        json={"mode": "learn"},
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["mode"] == "learn"
    assert body["learn_started_at"] is not None


@pytest.mark.asyncio
async def test_unknown_group_404(http_client, admin_headers):
    bogus = uuid.uuid4()
    resp = await http_client.get(f"/api/host-groups/{bogus}/allowlist", headers=admin_headers)
    assert resp.status_code == 404


# ---------- Mode flip queues sync commands ----------


@pytest.mark.asyncio
async def test_mode_flip_queues_sync_commands(http_client, admin_headers, db_session):
    from app.models import Command, CommandKind

    g = await _make_group(db_session)
    h1 = await _make_host_in_group(db_session, g.id)
    h2 = await _make_host_in_group(db_session, g.id)

    resp = await http_client.put(
        f"/api/host-groups/{g.id}/allowlist/mode",
        json={"mode": "learn"},
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text

    rows = (
        (
            await db_session.execute(
                select(Command).where(Command.kind == CommandKind.ALLOWLIST_SYNC)
            )
        )
        .scalars()
        .all()
    )
    host_ids = {r.host_id for r in rows}
    assert host_ids == {h1.id, h2.id}
    for r in rows:
        assert r.payload["mode"] == "learn"
        assert r.payload["hashes"] == []


# ---------- Manual entry CRUD ----------


@pytest.mark.asyncio
async def test_create_entry_admin_only(http_client, admin_headers, analyst_headers, db_session):
    g = await _make_group(db_session)
    sha = "a" * 64
    resp = await http_client.post(
        f"/api/host-groups/{g.id}/allowlist/entries",
        json={"sha256": sha, "exec_path": "/usr/bin/x"},
        headers=analyst_headers,
    )
    assert resp.status_code == 403

    resp = await http_client.post(
        f"/api/host-groups/{g.id}/allowlist/entries",
        json={"sha256": sha, "exec_path": "/usr/bin/x"},
        headers=admin_headers,
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["sha256"] == sha
    assert body["manual"] is True
    assert body["learned"] is False
    assert body["exec_path"] == "/usr/bin/x"


@pytest.mark.asyncio
async def test_create_entry_rejects_bad_sha(http_client, admin_headers, db_session):
    g = await _make_group(db_session)
    # too short
    resp = await http_client.post(
        f"/api/host-groups/{g.id}/allowlist/entries",
        json={"sha256": "abc"},
        headers=admin_headers,
    )
    assert resp.status_code == 422
    # non-hex
    resp = await http_client.post(
        f"/api/host-groups/{g.id}/allowlist/entries",
        json={"sha256": "Z" * 64},
        headers=admin_headers,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_entry_merges_with_learned(http_client, admin_headers, db_session):
    """A learner-added entry that an operator subsequently approves
    should flip `manual` rather than 409."""
    from app.models import AllowlistEntry
    from app.services.allowlist import record_observed_hash

    g = await _make_group(db_session)
    sha = "b" * 64
    learned = await record_observed_hash(
        db_session, host_group_id=g.id, sha256=sha, exec_path="/usr/bin/y"
    )
    assert learned.learned is True and learned.manual is False
    learned_id = learned.id
    # Flush so the http_client (same session) sees it.
    await db_session.flush()

    resp = await http_client.post(
        f"/api/host-groups/{g.id}/allowlist/entries",
        json={"sha256": sha, "publisher": "Acme Co"},
        headers=admin_headers,
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["id"] == str(learned_id)
    assert body["manual"] is True
    assert body["learned"] is True
    assert body["publisher"] == "Acme Co"

    # Still exactly one row in the DB.
    rows = (
        (
            await db_session.execute(
                select(AllowlistEntry).where(AllowlistEntry.host_group_id == g.id)
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_list_entries_includes_learned_and_manual(http_client, admin_headers, db_session):
    from app.services.allowlist import record_observed_hash

    g = await _make_group(db_session)
    await record_observed_hash(db_session, host_group_id=g.id, sha256="c" * 64)
    await db_session.flush()
    resp = await http_client.post(
        f"/api/host-groups/{g.id}/allowlist/entries",
        json={"sha256": "d" * 64},
        headers=admin_headers,
    )
    assert resp.status_code == 201

    resp = await http_client.get(
        f"/api/host-groups/{g.id}/allowlist/entries", headers=admin_headers
    )
    assert resp.status_code == 200, resp.text
    items = resp.json()
    shas = sorted(i["sha256"] for i in items)
    assert shas == sorted(["c" * 64, "d" * 64])


@pytest.mark.asyncio
async def test_delete_entry_admin_only(http_client, admin_headers, analyst_headers, db_session):
    g = await _make_group(db_session)
    sha = "e" * 64
    resp = await http_client.post(
        f"/api/host-groups/{g.id}/allowlist/entries",
        json={"sha256": sha},
        headers=admin_headers,
    )
    eid = resp.json()["id"]

    resp = await http_client.delete(
        f"/api/host-groups/{g.id}/allowlist/entries/{eid}",
        headers=analyst_headers,
    )
    assert resp.status_code == 403

    resp = await http_client.delete(
        f"/api/host-groups/{g.id}/allowlist/entries/{eid}",
        headers=admin_headers,
    )
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_delete_last_entry_refused_in_enforce(http_client, admin_headers, db_session):
    g = await _make_group(db_session)
    sha = "f" * 64
    resp = await http_client.post(
        f"/api/host-groups/{g.id}/allowlist/entries",
        json={"sha256": sha},
        headers=admin_headers,
    )
    eid = resp.json()["id"]

    resp = await http_client.put(
        f"/api/host-groups/{g.id}/allowlist/mode",
        json={"mode": "enforce"},
        headers=admin_headers,
    )
    assert resp.status_code == 200

    resp = await http_client.delete(
        f"/api/host-groups/{g.id}/allowlist/entries/{eid}",
        headers=admin_headers,
    )
    assert resp.status_code == 400
    assert "enforce" in resp.json()["detail"]


# ---------- Audit ----------


@pytest.mark.asyncio
async def test_mode_flip_audited(http_client, admin_headers, db_session):
    from app.models import AuditLog

    g = await _make_group(db_session)
    resp = await http_client.put(
        f"/api/host-groups/{g.id}/allowlist/mode",
        json={"mode": "learn"},
        headers=admin_headers,
    )
    assert resp.status_code == 200

    rows = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.action == "allowlist.mode.set",
                    AuditLog.resource_id == str(g.id),
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].payload["mode"] == "learn"


# ---------- Service-layer ----------


@pytest.mark.asyncio
async def test_record_observed_hash_upserts(db_session):
    from app.models import AllowlistEntry
    from app.services.allowlist import record_observed_hash

    g = await _make_group(db_session)
    sha = "1" * 64
    row1 = await record_observed_hash(
        db_session, host_group_id=g.id, sha256=sha, exec_path="/usr/bin/x"
    )
    first_seen = row1.first_seen
    last_seen_1 = row1.last_seen
    row2 = await record_observed_hash(
        db_session, host_group_id=g.id, sha256=sha, exec_path="/usr/bin/x"
    )
    assert row2.id == row1.id
    # first_seen pinned, last_seen advances.
    assert row2.first_seen == first_seen
    assert row2.last_seen is not None and last_seen_1 is not None
    assert row2.last_seen >= last_seen_1

    rows = (
        (
            await db_session.execute(
                select(AllowlistEntry).where(AllowlistEntry.host_group_id == g.id)
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_record_observed_hash_rejects_bad_shape(db_session):
    from app.services.allowlist import record_observed_hash

    g = await _make_group(db_session)
    with pytest.raises(ValueError):
        await record_observed_hash(db_session, host_group_id=g.id, sha256="short")


# ---------- Learner worker ----------


@pytest.mark.asyncio
async def test_learner_persists_only_for_learn_mode(db_session):
    from app.models import AllowlistEntry
    from app.services.allowlist import upsert_mode
    from app.workers.allowlist_learner import Observation, trigger_persist

    learn_group = await _make_group(db_session)
    off_group = await _make_group(db_session)

    await upsert_mode(
        db_session,
        host_group_id=learn_group.id,
        mode=__import__("app.models", fromlist=["AllowlistMode"]).AllowlistMode.LEARN,
        updated_by_user_id=None,
    )
    # Off-group stays at the default (no row) — verify the learner
    # still drains those observations without recording.

    h_learn = await _make_host_in_group(db_session, learn_group.id)
    h_off = await _make_host_in_group(db_session, off_group.id)
    await db_session.flush()

    obs = [
        Observation(host_id=h_learn.id, sha256="a" * 64, exec_path="/bin/a"),
        Observation(host_id=h_off.id, sha256="b" * 64, exec_path="/bin/b"),
        # Same host, second hash — both should land.
        Observation(host_id=h_learn.id, sha256="c" * 64, exec_path="/bin/c"),
        # Dup-within-batch — should not produce two rows for the same
        # (group, hash).
        Observation(host_id=h_learn.id, sha256="a" * 64, exec_path="/bin/a"),
    ]
    recorded = await trigger_persist(obs, session_maker=_test_session_maker(db_session))
    assert recorded == 2

    rows = (
        (
            await db_session.execute(
                select(AllowlistEntry).where(AllowlistEntry.host_group_id == learn_group.id)
            )
        )
        .scalars()
        .all()
    )
    assert {r.sha256 for r in rows} == {"a" * 64, "c" * 64}

    rows_off = (
        (
            await db_session.execute(
                select(AllowlistEntry).where(AllowlistEntry.host_group_id == off_group.id)
            )
        )
        .scalars()
        .all()
    )
    assert rows_off == []


# ---------- gRPC translation ----------


def test_grpc_translation_allowlist_sync():
    """Round-trip a Command(kind=allowlist_sync) through the gRPC
    translator and verify the resulting protobuf carries the correct
    mode + raw 32-byte hash bytes."""
    from app.grpc.services import _command_to_pb
    from app.models import Command, CommandKind
    from app.proto_gen.edr.v1 import control_pb2

    sha_hex = "ab" * 32
    cmd = Command(
        id=uuid.uuid4(),
        host_id=uuid.uuid4(),
        kind=CommandKind.ALLOWLIST_SYNC,
        payload={"mode": "enforce", "hashes": [sha_hex, "0" * 64]},
    )
    pb = _command_to_pb(cmd)
    assert pb is not None
    assert pb.WhichOneof("body") == "allowlist_sync"
    assert pb.allowlist_sync.mode == control_pb2.ALLOWLIST_MODE_ENFORCE
    assert len(pb.allowlist_sync.hashes) == 2
    assert pb.allowlist_sync.hashes[0] == bytes.fromhex(sha_hex)
    assert pb.allowlist_sync.hashes[1] == bytes.fromhex("0" * 64)


def test_grpc_translation_skips_bad_hex():
    """Malformed hex digests get dropped without poisoning the sync."""
    from app.grpc.services import _command_to_pb
    from app.models import Command, CommandKind

    cmd = Command(
        id=uuid.uuid4(),
        host_id=uuid.uuid4(),
        kind=CommandKind.ALLOWLIST_SYNC,
        payload={
            "mode": "learn",
            "hashes": [
                "a" * 64,  # valid
                "Z" * 64,  # not hex
                "short",  # wrong length
                42,  # wrong type
            ],
        },
    )
    pb = _command_to_pb(cmd)
    assert pb is not None
    assert len(pb.allowlist_sync.hashes) == 1
    assert pb.allowlist_sync.hashes[0] == bytes.fromhex("a" * 64)


# ---------- push_allowlist_to_agent fan-out ----------


@pytest.mark.asyncio
async def test_push_allowlist_to_agent_fans_per_host(db_session):
    from app.models import AllowlistMode, Command, CommandKind
    from app.services.allowlist import push_allowlist_to_agent, record_observed_hash, upsert_mode

    g = await _make_group(db_session)
    h1 = await _make_host_in_group(db_session, g.id)
    h2 = await _make_host_in_group(db_session, g.id)
    # Host in another group — must NOT receive a sync.
    other = await _make_group(db_session)
    h_other = await _make_host_in_group(db_session, other.id)
    await upsert_mode(
        db_session,
        host_group_id=g.id,
        mode=AllowlistMode.ENFORCE,
        updated_by_user_id=None,
    )
    await record_observed_hash(db_session, host_group_id=g.id, sha256="9" * 64)
    queued = await push_allowlist_to_agent(db_session, host_group_id=g.id)
    assert queued == 2

    rows = (
        (
            await db_session.execute(
                select(Command).where(Command.kind == CommandKind.ALLOWLIST_SYNC)
            )
        )
        .scalars()
        .all()
    )
    host_ids = {r.host_id for r in rows}
    assert host_ids == {h1.id, h2.id}
    assert h_other.id not in host_ids
    for r in rows:
        assert r.payload["mode"] == "enforce"
        assert r.payload["hashes"] == ["9" * 64]
