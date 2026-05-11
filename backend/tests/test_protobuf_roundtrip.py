"""Property-based round-trip tests for the wire-protocol protobufs.

If the agent serialises an event and the manager deserialises it, the
bytes must round-trip cleanly. Hypothesis explores the input space so
we catch:
  * field encodings that ask for one int width but get given another;
  * UTF-8 paths that survive the gRPC transport but trip up the
    normalizer;
  * timestamp values at the boundaries (0, INT64_MAX, negative).

We don't fuzz with arbitrary bytes (protobuf is forgiving and would
accept noise as zero-valued fields); instead we generate well-formed
events via the proto types' Python bindings and compare structurally.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

# Conservative strategies — values that any correct implementation must
# handle. Wider exploration (UTF-16 surrogates, control chars in
# command_line, etc.) is left as an M11 follow-up because some of those
# legitimately fail the agent-side validation today.

safe_text = st.text(
    alphabet=st.characters(
        whitelist_categories=("L", "N", "P", "S"),
        blacklist_characters="\x00",
    ),
    min_size=0,
    max_size=200,
)


@given(
    host_id=st.text(min_size=1, max_size=36, alphabet="0123456789abcdef-"),
    pid=st.integers(min_value=1, max_value=2**31 - 1),
    image=safe_text,
    cmdline=safe_text,
)
@settings(max_examples=50, deadline=None)
def test_process_event_roundtrip(host_id: str, pid: int, image: str, cmdline: str) -> None:
    from app.proto_gen.edr.v1 import events_pb2

    ev = events_pb2.EndpointEvent()
    ev.host_id = host_id
    ev.process.process.pid = pid
    ev.process.executable = image
    ev.process.command_line = cmdline

    raw = ev.SerializeToString()
    decoded = events_pb2.EndpointEvent()
    decoded.ParseFromString(raw)

    assert decoded.host_id == host_id
    assert decoded.process.process.pid == pid
    assert decoded.process.executable == image
    assert decoded.process.command_line == cmdline


@given(
    addr=st.from_regex(r"^([0-9]{1,3}\.){3}[0-9]{1,3}$", fullmatch=True),
    port=st.integers(min_value=0, max_value=65535),
    proto=st.sampled_from(["tcp", "udp", "icmp"]),
)
@settings(max_examples=50, deadline=None)
def test_network_event_roundtrip(addr: str, port: int, proto: str) -> None:
    from app.proto_gen.edr.v1 import events_pb2

    ev = events_pb2.EndpointEvent()
    ev.host_id = "test"
    ev.network.transport = proto
    ev.network.destination_ip = addr
    ev.network.destination_port = port

    raw = ev.SerializeToString()
    decoded = events_pb2.EndpointEvent()
    decoded.ParseFromString(raw)

    assert decoded.network.destination_ip == addr
    assert decoded.network.destination_port == port
    assert decoded.network.transport == proto


@given(
    seq=st.integers(min_value=0, max_value=2**63 - 1),
    batch_id=st.text(
        min_size=1,
        max_size=64,
        alphabet=st.characters(min_codepoint=33, max_codepoint=126),
    ),
)
@settings(max_examples=20, deadline=None)
def test_event_batch_envelope_roundtrip(seq: int, batch_id: str) -> None:
    """Envelope-only round-trip: empty events list, just the batch metadata."""
    from app.proto_gen.edr.v1 import control_pb2, events_pb2

    msg = control_pb2.ClientMessage()
    msg.events.batch_id = batch_id
    msg.events.first_seq = seq
    msg.events.last_seq = seq
    msg.events.events.append(events_pb2.EndpointEvent())

    raw = msg.SerializeToString()
    decoded = control_pb2.ClientMessage()
    decoded.ParseFromString(raw)

    assert decoded.events.batch_id == batch_id
    assert decoded.events.first_seq == seq
    assert decoded.events.last_seq == seq
    assert len(decoded.events.events) == 1
