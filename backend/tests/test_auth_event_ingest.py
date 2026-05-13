"""Phase 2 #2.4 — auth event ingest path.

Two contracts under test:

1. `to_ecs` maps every (AuthKind, AuthResult) pair onto the right ECS
   shape — `event.category=["authentication"]`, `event.action` from
   AuthKind, `event.outcome` from AuthResult, principal under `user.*`,
   network origin under `source.ip`, Kerberos-specific bits under
   `kerberos.*`.

2. The gRPC fan-out copies AuthEvent payloads onto `topic_auth` in
   addition to `topic_telemetry_raw`. A stub producer captures every
   `send_bytes` call and the test reproduces the exact filter the
   real handler runs (one record per topic per event), without needing
   the full HostStream wired up.
"""

from __future__ import annotations

from app.core.config import settings
from app.proto_gen.edr.v1 import events_pb2
from app.services.normalizer import to_ecs


def _make_auth_event(
    auth_kind: events_pb2.AuthKind = events_pb2.AUTH_KIND_LOGON,
    result: events_pb2.AuthResult = events_pb2.AUTH_RESULT_SUCCESS,
    **fields: object,
) -> events_pb2.EndpointEvent:
    ev = events_pb2.EndpointEvent(
        event_id="01H000000000000000000AUTH1",
        host_id="00000000-0000-0000-0000-000000000001",
        agent_id="00000000-0000-0000-0000-000000000001",
        agent_version="0.0.0-test",
    )
    auth = ev.auth
    auth.auth_kind = auth_kind
    auth.result = result
    for k, v in fields.items():
        setattr(auth, k, v)
    return ev


def test_to_ecs_logon_success_maps_to_authentication_category() -> None:
    ev = _make_auth_event(
        user="alice",
        user_domain="CORP",
        source_ip="10.0.0.5",
        target_host="db01",
        logon_type=10,
        event_id_raw=4624,
    )
    doc = to_ecs(ev)
    assert doc["event"]["category"] == ["authentication"]
    assert doc["event"]["action"] == "logon"
    assert doc["event"]["outcome"] == "success"
    assert doc["user"] == {"name": "alice", "domain": "CORP"}
    assert doc["source"] == {"ip": "10.0.0.5"}
    assert doc["host"]["name"] == "db01"
    assert doc["winlog"] == {"logon": {"type": 10}, "event_id": 4624}


def test_to_ecs_logon_failure_includes_reason() -> None:
    ev = _make_auth_event(
        auth_kind=events_pb2.AUTH_KIND_LOGON,
        result=events_pb2.AUTH_RESULT_FAILURE,
        user="bob",
        source_ip="192.168.1.10",
        failure_reason="bad_password",
        event_id_raw=4625,
    )
    doc = to_ecs(ev)
    assert doc["event"]["outcome"] == "failure"
    assert doc["event"]["reason"] == "bad_password"
    assert doc["user"]["name"] == "bob"
    assert doc["winlog"]["event_id"] == 4625


def test_to_ecs_kerberos_tgt_carries_ticket_kind() -> None:
    ev = _make_auth_event(
        auth_kind=events_pb2.AUTH_KIND_KERBEROS_TGT,
        result=events_pb2.AUTH_RESULT_UNKNOWN,
        user="svc-app",
        user_domain="CORP",
        service_name="krbtgt/CORP",
        ticket_kind="TGT",
        event_id_raw=4768,
    )
    doc = to_ecs(ev)
    assert doc["event"]["action"] == "kerberos_tgt"
    assert doc["event"]["outcome"] == "unknown"
    assert doc["kerberos"] == {"ticket": {"kind": "TGT"}}
    assert doc["service"] == {"name": "krbtgt/CORP"}


def test_to_ecs_kerberos_tgs_with_target_user() -> None:
    ev = _make_auth_event(
        auth_kind=events_pb2.AUTH_KIND_KERBEROS_TGS,
        result=events_pb2.AUTH_RESULT_SUCCESS,
        user="alice",
        target_user="svc-sql",
        service_name="MSSQLSvc/db01",
        ticket_kind="TGS",
        event_id_raw=4769,
    )
    doc = to_ecs(ev)
    assert doc["event"]["action"] == "kerberos_tgs"
    assert doc["user"]["name"] == "alice"
    assert doc["user"]["target"] == {"name": "svc-sql"}


def test_to_ecs_logoff_minimal_payload() -> None:
    ev = _make_auth_event(
        auth_kind=events_pb2.AUTH_KIND_LOGOFF,
        result=events_pb2.AUTH_RESULT_SUCCESS,
        user="alice",
    )
    doc = to_ecs(ev)
    assert doc["event"]["action"] == "logoff"
    assert doc["event"]["outcome"] == "success"
    assert "source" not in doc
    assert "winlog" not in doc


def test_to_ecs_nt_logon_maps_action() -> None:
    ev = _make_auth_event(
        auth_kind=events_pb2.AUTH_KIND_NT_LOGON,
        result=events_pb2.AUTH_RESULT_FAILURE,
        user="bob",
        event_id_raw=4776,
    )
    doc = to_ecs(ev)
    assert doc["event"]["action"] == "nt_logon"
    assert doc["event"]["outcome"] == "failure"
    assert doc["winlog"]["event_id"] == 4776


# ---------------------------------------------------------------------------
# gRPC fan-out: AuthEvent payloads go to both topic_telemetry_raw and
# topic_auth. Non-auth payloads only land on topic_telemetry_raw. We
# reproduce the filter inline so the test is independent of the
# HostStream's many ambient dependencies (asyncpg LISTEN, mTLS context,
# rate-limit bucket).


class _StubProducer:
    """Records (topic, key, value) per send_bytes call."""

    def __init__(self) -> None:
        self.sent: list[tuple[str, str | None, bytes]] = []

    async def send_bytes(self, topic: str, key: str | None, value: bytes) -> None:
        self.sent.append((topic, key, value))


async def _fanout(
    producer: _StubProducer, host_id: str, events: list[events_pb2.EndpointEvent]
) -> None:
    """Mirror of the inline gRPC ingest fan-out for tests."""
    for ev in events:
        payload_bytes = ev.SerializeToString()
        await producer.send_bytes(settings.topic_telemetry_raw, host_id, payload_bytes)
        if ev.WhichOneof("payload") == "auth":
            await producer.send_bytes(settings.topic_auth, host_id, payload_bytes)


def test_grpc_fanout_duplicates_auth_events_to_auth_topic() -> None:
    import asyncio

    host_id = "00000000-0000-0000-0000-000000000001"
    auth_ev = _make_auth_event(user="alice", source_ip="10.0.0.5")
    process_ev = events_pb2.EndpointEvent(
        event_id="01H000000000000000000PROC1",
        host_id=host_id,
        agent_id=host_id,
    )
    process_ev.process.executable = "/bin/ls"

    producer = _StubProducer()
    asyncio.run(_fanout(producer, host_id, [auth_ev, process_ev]))

    topics = [t for (t, _, _) in producer.sent]
    assert topics.count(settings.topic_telemetry_raw) == 2
    assert topics.count(settings.topic_auth) == 1

    # The auth-topic record must contain the AuthEvent payload bytes;
    # round-trip to confirm we copied the same SerializeToString output.
    (_, _, auth_topic_value) = next(
        item for item in producer.sent if item[0] == settings.topic_auth
    )
    parsed = events_pb2.EndpointEvent()
    parsed.ParseFromString(auth_topic_value)
    assert parsed.WhichOneof("payload") == "auth"
    assert parsed.auth.user == "alice"


def test_grpc_fanout_skips_auth_topic_when_no_auth_event() -> None:
    import asyncio

    host_id = "00000000-0000-0000-0000-000000000002"
    process_ev = events_pb2.EndpointEvent(event_id="01H000000000000000000PROC2", host_id=host_id)
    process_ev.process.executable = "/bin/ls"

    producer = _StubProducer()
    asyncio.run(_fanout(producer, host_id, [process_ev]))

    assert all(t == settings.topic_telemetry_raw for (t, _, _) in producer.sent)
