"""gRPC AgentService implementation.

Handles two RPCs:
- Enroll: anonymous TLS, agent submits CSR + enrollment token, gets cert back.
- HostStream: long-lived bidi over mTLS. Inbound events are forwarded to the
  Kafka raw topic. Outbound: rule sync at start + periodic pongs.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from uuid import UUID

import grpc
import structlog
from google.protobuf import timestamp_pb2
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.db import SessionLocal
from app.models import (
    Command,
    CommandKind,
    CommandStatus,
    Host,
    HostStatus,
    IocEntry,
    Job,
    JobArtifact,
    JobArtifactKind,
    JobKind,
    JobRun,
    JobRunStatus,
    Rule,
    RuleKind,
)
from app.proto_gen.edr.v1 import (
    common_pb2,
    control_pb2,
    control_pb2_grpc,
)
from app.services import audit
from app.services import minio as minio_svc  # noqa: F401 — kept for legacy callers
from app.services.ca import CaService
from app.services.enrollment import (
    EnrollmentTokenInvalid,
    bind_token_to_host,
    consume_token,
    detect_reenrollment,
)
from app.services.jobs import (
    aggregate_status,
    artifact_bucket_for,
    artifact_object_key,
)
from app.services.kafka import producer
from app.services.uploads import issue_upload_token

log = structlog.get_logger()


PB_OS_FAMILY: dict[str, str] = {"windows": "windows", "linux": "linux", "macos": "macos"}

# M9.5: minimum agent wire-protocol version this manager accepts.
# Bump together with any breaking change to the protobuf schema.
MIN_AGENT_PROTOCOL_VERSION = 1

# M17.f: gRPC ingest rate-limit defaults. Per-host_id token bucket
# capping events/sec so a misbehaving (or compromised) agent can't
# saturate Kafka. Configurable via env.
import os as _os  # noqa: E402

GRPC_RL_MAX_EVENTS_PER_SEC = int(_os.environ.get("VIGIL_GRPC_RL_EVENTS_PER_SEC", 1000))
GRPC_RL_BURST = int(_os.environ.get("VIGIL_GRPC_RL_BURST", 5000))


class _HostBucket:
    """Token bucket: capacity refilled at `rate` tokens/sec, capped
    at `burst`. Each event consumes one token. When empty, the gRPC
    handler logs + drops the message (forwarding zero events to
    Kafka). This isolates the bad-agent failure from the rest of the
    fleet."""

    __slots__ = ("tokens", "last")

    def __init__(self) -> None:
        self.tokens = float(GRPC_RL_BURST)
        self.last = 0.0

    def admit(self, now: float, want: int) -> int:
        """Try to consume `want` tokens; return how many were granted."""
        if self.last == 0.0:
            self.last = now
        # Refill.
        elapsed = now - self.last
        if elapsed > 0:
            self.tokens = min(
                float(GRPC_RL_BURST), self.tokens + elapsed * GRPC_RL_MAX_EVENTS_PER_SEC
            )
            self.last = now
        granted = min(int(self.tokens), want)
        self.tokens -= granted
        return granted


# Per-host_id bucket, keyed by uuid. Cleaned up on stream close.
_GRPC_BUCKETS: dict[str, _HostBucket] = {}


def _now_pb() -> timestamp_pb2.Timestamp:
    ts = timestamp_pb2.Timestamp()
    ts.GetCurrentTime()
    return ts


def _pb_severity(s: str) -> int:
    return {
        "info": common_pb2.SEVERITY_INFO,
        "low": common_pb2.SEVERITY_LOW,
        "medium": common_pb2.SEVERITY_MEDIUM,
        "high": common_pb2.SEVERITY_HIGH,
        "critical": common_pb2.SEVERITY_CRITICAL,
    }.get(s, common_pb2.SEVERITY_UNSPECIFIED)


def _pb_action(a: str) -> int:
    # Map user-facing action names to the wire enum. Legacy DETECT/KILL
    # values are kept on the wire so older agents stay compatible;
    # the manager picks `kill` vs `block` vs `quarantine` per command
    # kind when emitting actual response commands.
    #
    # Match statement (not a dict.get) so adding a new RuleAction
    # without updating this mapping is a hard typecheck/test failure
    # rather than a silent RULE_ACTION_UNSPECIFIED ship — the previous
    # dict.get would have sent UNSPECIFIED to every agent on the next
    # rule sync without anything noticing.
    match a:
        case "alert":
            return common_pb2.RULE_ACTION_DETECT
        case "block":
            return common_pb2.RULE_ACTION_BLOCK
        case "quarantine":
            return common_pb2.RULE_ACTION_QUARANTINE
        case _:
            # Defensive — RuleAction enum is closed; this should never
            # fire in normal operation. Log loudly so a future enum
            # member that slips past the typechecker surfaces.
            log.warning("grpc._pb_action.unknown_action", action=a)
            return common_pb2.RULE_ACTION_UNSPECIFIED


def _pb_ioc_kind(k: str) -> int:
    return {
        "hash_sha256": control_pb2.IOC_KIND_HASH_SHA256,
        "hash_md5": control_pb2.IOC_KIND_HASH_MD5,
        "hash_sha1": control_pb2.IOC_KIND_HASH_SHA1,
        "filename": control_pb2.IOC_KIND_FILENAME,
        "filepath": control_pb2.IOC_KIND_FILEPATH,
    }.get(k, control_pb2.IOC_KIND_UNSPECIFIED)


def _command_to_pb(cmd: Command) -> control_pb2.Command | None:
    """Translate a PG Command row into the protobuf Command message that the
    agent expects on the gRPC stream. Returns None for an unsupported kind so
    the caller can mark the row as FAILED rather than blocking the queue.
    """
    pb = control_pb2.Command(command_id=str(cmd.id), issued_at=_now_pb())
    payload = cmd.payload or {}
    if cmd.kind == CommandKind.KILL_PROCESS:
        pid = int(payload.get("pid") or 0)
        if pid <= 0:
            return None
        pb.kill.target.pid = pid
        return pb
    if cmd.kind == CommandKind.BLOCK_PROCESS:
        pat = str(payload.get("pattern") or "")
        if not pat:
            return None
        pb.block_process.pattern = pat
        return pb
    if cmd.kind == CommandKind.BLOCK_FILE:
        pat = str(payload.get("pattern") or "")
        if not pat:
            return None
        pb.block_file.pattern = pat
        return pb
    if cmd.kind == CommandKind.UNBLOCK_PROCESS:
        pat = str(payload.get("pattern") or "")
        if not pat:
            return None
        pb.unblock_process.pattern = pat
        return pb
    if cmd.kind == CommandKind.UNBLOCK_FILE:
        pat = str(payload.get("pattern") or "")
        if not pat:
            return None
        pb.unblock_file.pattern = pat
        return pb
    if cmd.kind == CommandKind.ISOLATE:
        # Booleans default to False on missing key — translate.
        pb.isolate.isolate = bool(payload.get("isolate", True))
        for ip in payload.get("allowlist_ips", []) or []:
            if isinstance(ip, str) and ip.strip():
                pb.isolate.allowlist_ips.append(ip.strip())
        return pb
    if cmd.kind == CommandKind.QUARANTINE_FILE:
        path = str(payload.get("path") or "")
        if not path:
            return None
        pb.quarantine_file.path = path
        pb.quarantine_file.delete_original = bool(payload.get("delete_original", False))
        return pb
    if cmd.kind == CommandKind.RELEASE_QUARANTINE:
        sha256 = str(payload.get("sha256") or "")
        if not sha256:
            return None
        pb.release_quarantine.sha256 = sha256
        pb.release_quarantine.target_path = str(payload.get("target_path") or "")
        return pb
    if cmd.kind == CommandKind.RUN_JOB:
        # Jobs engine envelope. Payload shape was written by
        # services.jobs.fanout and contains job_id / run_id / job_kind /
        # parameters. The agent's JobDispatcher (agent-core::jobs)
        # routes by job_kind.
        import json as _json

        job_id = str(payload.get("job_id") or "")
        run_id = str(payload.get("run_id") or "")
        job_kind = str(payload.get("job_kind") or "")
        if not (job_id and run_id and job_kind):
            return None
        pb.run_job.job_id = job_id
        pb.run_job.run_id = run_id
        pb.run_job.job_kind = job_kind
        pb.run_job.parameters_json = _json.dumps(payload.get("parameters") or {})
        return pb
    return None


def _peer_host_id(context: grpc.aio.ServicerContext) -> str | None:
    """Extract host_id from the client cert's CN. Returns None if unavailable
    (e.g. plaintext channel during local dev).
    """
    auth_ctx = context.auth_context()
    cn_iter = auth_ctx.get("x509_common_name", [])
    cn = list(cn_iter) if cn_iter else []
    if cn:
        return cn[0].decode() if isinstance(cn[0], bytes) else cn[0]
    return None


def _check_host_admission(host: Host, peer_fingerprint: str | None) -> tuple[bool, str | None]:
    """Decide whether the host is allowed on the gRPC stream.

    Returns ``(True, None)`` to admit, or ``(False, reason)`` for the
    caller to abort with UNAUTHENTICATED. Two gates:

      * status == DECOMMISSIONED — the operator's PATCH /api/hosts/<id>
        promised this would reject future connections; without this
        the cert keeps working until expiry.
      * cert fingerprint mismatch — if the host row's
        cert_fingerprint disagrees with the peer's, only the cert we
        actually issued can stream. The host row's value is missing
        for pre-fingerprint enrollments; we skip the compare in that
        case rather than lock the fleet out.
    """
    if host.status == HostStatus.DECOMMISSIONED:
        return False, "host decommissioned"
    if peer_fingerprint and host.cert_fingerprint and peer_fingerprint != host.cert_fingerprint:
        return False, "cert revoked"
    return True, None


def _peer_cert_fingerprint(context: grpc.aio.ServicerContext) -> str | None:
    """Return SHA-256 fingerprint (lowercase hex) of the peer cert, matching
    the format `CaService.sign_csr` writes to `Host.cert_fingerprint`.

    Returns None for plaintext channels or any failure to parse — caller
    must decide whether to abort. We don't raise from here so the
    fingerprint compare can sit alongside the existing CN read without
    forcing every test path through cert parsing.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    auth_ctx = context.auth_context()
    pem_iter = auth_ctx.get("x509_pem_cert", [])
    if not pem_iter:
        return None
    pem = next(iter(pem_iter), None)
    if pem is None:
        return None
    pem_bytes = pem.encode() if isinstance(pem, str) else pem
    try:
        cert = x509.load_pem_x509_certificate(pem_bytes)
    except ValueError:
        return None
    return cert.fingerprint(hashes.SHA256()).hex()


class AgentService(control_pb2_grpc.AgentServiceServicer):
    """Server-side handlers. Each method gets its own DB session."""

    async def Enroll(  # noqa: N802 - gRPC method
        self,
        request: control_pb2.EnrollRequest,
        context: grpc.aio.ServicerContext,
    ) -> control_pb2.EnrollResponse:
        async with SessionLocal() as db:
            try:
                resp = await self._do_enroll(request, db, context)
                await db.commit()
                return resp
            except grpc.aio.AioRpcError:
                await db.rollback()
                raise
            except Exception as exc:  # pragma: no cover - defensive
                await db.rollback()
                log.exception("grpc.enroll.error", error=str(exc))
                await context.abort(grpc.StatusCode.INTERNAL, "internal error")
                raise

    async def _do_enroll(
        self,
        request: control_pb2.EnrollRequest,
        db: AsyncSession,
        context: grpc.aio.ServicerContext,
    ) -> control_pb2.EnrollResponse:
        if not request.enrollment_token:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "missing token")
        if not request.csr_pem:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "missing csr")
        if not request.hostname:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "missing hostname")

        # Atomic UPDATE ... WHERE used_at IS NULL RETURNING — see
        # services/enrollment.py. Same gate the REST path uses, so the
        # two never disagree about which call wins under contention.
        try:
            token_id = await consume_token(db, request.enrollment_token)
        except EnrollmentTokenInvalid:
            await context.abort(grpc.StatusCode.PERMISSION_DENIED, "invalid or expired token")
        now = datetime.now(UTC)

        os_family = PB_OS_FAMILY.get(request.os.family.lower())
        if os_family is None:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "unknown os.family")

        host = Host(
            hostname=request.hostname,
            os_family=os_family,
            os_version=request.os.version or None,
            os_platform=request.os.platform or None,
            os_arch=request.os.architecture or None,
            agent_version=request.agent_version or None,
            status=HostStatus.PENDING,
            enrolled_at=now,
        )
        db.add(host)
        await db.flush()

        # M12.e re-enrollment anomaly. The REST path had this for a
        # while; the gRPC path was silent — exactly the path an attacker
        # who wiped the agent's identity dir would use, since the agent
        # itself only ever calls the gRPC Enroll. Both paths now feed
        # the same detector in services/enrollment.py.
        await detect_reenrollment(
            db,
            hostname=request.hostname,
            os_family=os_family,
            new_host_id=host.id,
            now=now,
            source="grpc",
            source_ip=context.peer() if hasattr(context, "peer") else None,
        )

        ca = CaService(db)
        issued = await ca.sign_csr(request.csr_pem, host_id=str(host.id), hostname=request.hostname)
        host.cert_fingerprint = issued.fingerprint_sha256

        await bind_token_to_host(db, token_id, host.id)

        await audit.record(
            db,
            actor=None,
            action="host.enroll",
            resource_type="host",
            resource_id=str(host.id),
            payload={"via": "grpc", "hostname": request.hostname},
        )

        not_after_pb = timestamp_pb2.Timestamp()
        not_after_pb.FromDatetime(issued.not_after.replace(tzinfo=None))

        return control_pb2.EnrollResponse(
            host_id=str(host.id),
            client_cert_pem=issued.cert_pem.encode(),
            ca_chain_pem=issued.ca_chain_pem.encode(),
            cert_not_after=not_after_pb,
        )

    async def HostStream(  # noqa: N802
        self,
        request_iterator: AsyncIterator[control_pb2.ClientMessage],
        context: grpc.aio.ServicerContext,
    ) -> AsyncIterator[control_pb2.ServerMessage]:
        host_id_str = _peer_host_id(context)
        if host_id_str is None:
            log.warning("grpc.host_stream.no_peer_cert")
            await context.abort(grpc.StatusCode.UNAUTHENTICATED, "client cert required")
            return
        try:
            host_id = UUID(host_id_str)
        except ValueError:
            await context.abort(grpc.StatusCode.UNAUTHENTICATED, "client cert CN is not a UUID")
            return

        peer_fingerprint = _peer_cert_fingerprint(context)
        log.info("grpc.host_stream.open", host_id=host_id_str)

        async with SessionLocal() as db:
            host = await db.get(Host, host_id)
            if host is None:
                log.warning("grpc.host_stream.unknown_host", host_id=host_id_str)
                await context.abort(grpc.StatusCode.UNAUTHENTICATED, "unknown host")
                return
            # M24.a: a decommissioned host's cert stays cryptographically
            # valid for the rest of its lifetime; the docs claimed the
            # decommission PATCH revokes future connections but nothing
            # actually checked. The cert-pin compare handles the parallel
            # case where two hosts share a CN.
            admitted, reason = _check_host_admission(host, peer_fingerprint)
            if not admitted:
                log.warning(
                    "grpc.host_stream.rejected",
                    host_id=host_id_str,
                    reason=reason,
                    presented_fingerprint=peer_fingerprint,
                    expected_fingerprint=host.cert_fingerprint,
                )
                await context.abort(grpc.StatusCode.UNAUTHENTICATED, reason or "rejected")
                return
            host.status = HostStatus.ONLINE
            host.last_seen_at = datetime.now(UTC)
            await db.commit()

            # Push initial rule sync to the agent. Also remember the
            # latest rule mtime so the resync dispatcher below knows
            # what counts as "new edits since this stream opened".
            initial = await self._build_rule_sync(db)
            initial_rule_mtime = (
                await db.execute(select(func.max(Rule.updated_at)))
            ).scalar_one_or_none()

        # Send rule sync first.
        yield control_pb2.ServerMessage(rules=initial)

        # Heartbeat sender — pong every 30s; cancelled when the stream ends.
        async def _pinger(out: asyncio.Queue):
            try:
                while True:
                    await asyncio.sleep(30)
                    pong = control_pb2.Pong(ts=_now_pb())
                    await out.put(control_pb2.ServerMessage(pong=pong))
            except asyncio.CancelledError:
                return

        # Command dispatcher (Top-20 #12). Pre-fix this polled PG every
        # 500 ms — 2 q/s × N hosts at idle, visible in pg_stat_activity
        # at 1k-host fleets. Now uses LISTEN/NOTIFY on a per-host
        # channel: the migration 7d3f8e1a2b4c installed an AFTER INSERT
        # trigger on `commands` that calls
        # `pg_notify('vigil_cmd_<host_uuid_underscored>', new.id)`.
        # `listen_for_commands` opens a dedicated asyncpg connection
        # (the LISTEN holds the connection for its lifetime, so we
        # can't borrow from the SQLAlchemy pool), yields an asyncio
        # Event we await between drains. A 30 s timeout fallback covers
        # a missed-NOTIFY edge case (NOTIFYs are delivered at COMMIT
        # but if the listener's reconnect raced a COMMIT mid-flight,
        # the fallback poll picks it up within the SLA).
        async def _command_dispatcher(out: asyncio.Queue):
            from app.services.command_notify import listen_for_commands

            async def _drain_pending() -> None:
                async with SessionLocal() as cdb:
                    stmt = (
                        select(Command)
                        .where(
                            Command.host_id == host_id,
                            Command.status == CommandStatus.PENDING,
                        )
                        .order_by(Command.created_at.asc())
                        .limit(16)
                    )
                    pending = (await cdb.execute(stmt)).scalars().all()
                    for cmd in pending:
                        pb = _command_to_pb(cmd)
                        if pb is None:
                            cmd.status = CommandStatus.FAILED
                            cmd.error = "unsupported command kind"
                            cmd.completed_at = datetime.now(UTC)
                            continue
                        cmd.status = CommandStatus.DISPATCHED
                        cmd.dispatched_at = datetime.now(UTC)
                        await out.put(control_pb2.ServerMessage(command=pb))
                    if pending:
                        await cdb.commit()

            try:
                async with listen_for_commands(host_id) as notify_event:
                    # Drain once at start so commands queued while the
                    # listener was being set up don't have to wait for
                    # the fallback timer.
                    try:
                        await _drain_pending()
                    except Exception:
                        log.exception(
                            "grpc.command_dispatcher.initial_drain_failed",
                            host_id=host_id_str,
                        )
                    while True:
                        try:
                            await asyncio.wait_for(notify_event.wait(), timeout=30.0)
                        except TimeoutError:
                            pass  # fallback poll — covers missed NOTIFY
                        notify_event.clear()
                        try:
                            await _drain_pending()
                        except Exception:
                            log.exception(
                                "grpc.command_dispatcher.drain_failed",
                                host_id=host_id_str,
                            )
            except asyncio.CancelledError:
                return

        # Rule-resync dispatcher (review MEDIUM #15). Pre-fix, agents
        # received RuleSync exactly once at stream open and never again
        # — toggling a YARA / IOC rule in the UI did not reach
        # already-connected agents until they reconnected. We poll
        # `MAX(Rule.updated_at)` at 2 s cadence and push a fresh
        # RuleSync whenever it advances. Simpler than wiring asyncpg
        # LISTEN through the SQLAlchemy pool and good enough for the
        # low-hundreds fleet size we target. Latency ≤ 2 s.
        async def _rule_resync_dispatcher(out: asyncio.Queue, last_mtime):
            try:
                while True:
                    await asyncio.sleep(2.0)
                    try:
                        async with SessionLocal() as cdb:
                            current = (
                                await cdb.execute(select(func.max(Rule.updated_at)))
                            ).scalar_one_or_none()
                            if current is not None and current != last_mtime:
                                fresh = await self._build_rule_sync(cdb)
                                await out.put(control_pb2.ServerMessage(rules=fresh))
                                last_mtime = current
                    except Exception:
                        log.exception("grpc.rule_resync.error", host_id=host_id_str)
            except asyncio.CancelledError:
                return

        out_queue: asyncio.Queue = asyncio.Queue()
        ping_task = asyncio.create_task(_pinger(out_queue))
        cmd_task = asyncio.create_task(_command_dispatcher(out_queue))
        resync_task = asyncio.create_task(_rule_resync_dispatcher(out_queue, initial_rule_mtime))

        try:
            consume_task = asyncio.create_task(
                self._consume_client(host_id, request_iterator, context)
            )
            try:
                while not context.cancelled() and not consume_task.done():
                    try:
                        msg = await asyncio.wait_for(out_queue.get(), timeout=1.0)
                    except TimeoutError:
                        continue
                    yield msg
            finally:
                consume_task.cancel()
                with contextlib.suppress(BaseException):
                    await consume_task
        finally:
            ping_task.cancel()
            cmd_task.cancel()
            resync_task.cancel()
            with contextlib.suppress(BaseException):
                await ping_task
            with contextlib.suppress(BaseException):
                await cmd_task
            with contextlib.suppress(BaseException):
                await resync_task
            async with SessionLocal() as db:
                h = await db.get(Host, host_id)
                if h is not None:
                    h.status = HostStatus.OFFLINE
                    await db.commit()
            # M-grpc-hygiene #3: drop the per-host token bucket so the
            # global dict doesn't grow unbounded over the manager's
            # lifetime. The previous comment on _GRPC_BUCKETS claimed
            # "cleaned up on stream close" — no code did it.
            _GRPC_BUCKETS.pop(host_id_str, None)
            log.info("grpc.host_stream.close", host_id=host_id_str)

    async def _consume_client(
        self,
        host_id: UUID,
        request_iterator: AsyncIterator[control_pb2.ClientMessage],
        context: grpc.aio.ServicerContext,
    ) -> None:
        last_seen_update = datetime.now(UTC)
        async for msg in request_iterator:
            kind = msg.WhichOneof("payload")
            if kind == "events":
                # M7.7: previous shape `for ev in events: await send_bytes(...)`
                # serialised one Kafka publish per event with acks=all and
                # idempotence on; under sustained file_open load (~50/sec)
                # the await chain saturated and ~50% of events were lost.
                #
                # Fix: parallelise the per-event sends via asyncio.gather
                # so the producer's batching window can absorb the burst
                # in a single broker round-trip. The events keep their
                # individual Kafka records (the normalizer expects one
                # event per record), so the wire schema is unchanged.
                if msg.events.events:
                    # M17.f: per-host_id token bucket. A misbehaving
                    # agent can't saturate Kafka for the rest of the
                    # fleet — over-rate events are dropped at the gRPC
                    # boundary, surfaced via a counter we emit to the
                    # journal periodically (M14.b will turn this into
                    # a metric).
                    import time as _time

                    bucket = _GRPC_BUCKETS.setdefault(str(host_id), _HostBucket())
                    want = len(msg.events.events)
                    granted = bucket.admit(_time.monotonic(), want)
                    if granted < want:
                        log.warning(
                            "grpc.ingest.rate_limited",
                            host_id=str(host_id),
                            want=want,
                            granted=granted,
                            dropped=want - granted,
                        )
                    if granted > 0:
                        # Phase 2 #2.4: AuthEvent payloads get a second
                        # copy on `topic_auth` so brute-force / UEBA
                        # workers don't have to subscribe to the full
                        # telemetry firehose. The original record stays
                        # on `topic_telemetry_raw` for the normalizer.
                        sends: list = []
                        for ev in msg.events.events[:granted]:
                            payload_bytes = ev.SerializeToString()
                            sends.append(
                                producer.send_bytes(
                                    settings.topic_telemetry_raw,
                                    str(host_id),
                                    payload_bytes,
                                )
                            )
                            if ev.WhichOneof("payload") == "auth":
                                sends.append(
                                    producer.send_bytes(
                                        settings.topic_auth,
                                        str(host_id),
                                        payload_bytes,
                                    )
                                )
                        await asyncio.gather(*sends)
            elif kind == "heartbeat":
                # LOW #6: observe the heartbeat-to-heartbeat gap as a
                # Prometheus histogram so operators can alert on
                # sub-silence-worker gaps (the silence worker is 10
                # min by default; the restart takeover gap is <1 s,
                # so anything between is "the gRPC stream survived
                # but the agent stopped talking" — interesting).
                now = datetime.now(UTC)
                from app.core.metrics import agent_heartbeat_lag_seconds

                agent_heartbeat_lag_seconds.observe((now - last_seen_update).total_seconds())
                # Throttle DB writes — once per ~30s.
                if (now - last_seen_update).total_seconds() >= 30:
                    async with SessionLocal() as db:
                        h = await db.get(Host, host_id)
                        if h is None:
                            continue
                        # M24.a: catch decommission that happened
                        # after the stream opened. The next heartbeat
                        # tick is the soonest we can fail it. Cert
                        # fingerprint can't change mid-stream (it's
                        # pinned at TLS handshake), so we skip that leg
                        # of admission here.
                        admitted, reason = _check_host_admission(h, None)
                        if not admitted:
                            log.warning(
                                "grpc.host_stream.rejected_mid_stream",
                                host_id=str(host_id),
                                reason=reason,
                            )
                            await context.abort(
                                grpc.StatusCode.UNAUTHENTICATED, reason or "rejected"
                            )
                            return
                        h.last_seen_at = now
                        await db.commit()
                    last_seen_update = now
            elif kind == "hello":
                # M9.5: enforce minimum protocol_version + record
                # capabilities. Manager bumps MIN_AGENT_PROTOCOL_VERSION
                # together with breaking schema changes.
                pv = msg.hello.protocol_version or 0
                caps = msg.hello.capabilities or ""
                log.info(
                    "grpc.host_stream.hello",
                    host_id=str(host_id),
                    agent_version=msg.hello.host.agent_version,
                    protocol_version=pv,
                    capabilities=caps,
                )
                if pv != 0 and pv < MIN_AGENT_PROTOCOL_VERSION:
                    log.warning(
                        "grpc.host_stream.protocol_too_old",
                        host_id=str(host_id),
                        agent_pv=pv,
                        minimum=MIN_AGENT_PROTOCOL_VERSION,
                    )
                    await context.abort(
                        grpc.StatusCode.FAILED_PRECONDITION,
                        f"agent protocol_version={pv} below minimum supported "
                        f"{MIN_AGENT_PROTOCOL_VERSION}; please upgrade the agent",
                    )
                    return
                # Persist the agent's advertised capabilities on the Host
                # row. Useful for fleet-wide rollout dashboards (M14).
                async with SessionLocal() as db:
                    h = await db.get(Host, host_id)
                    if h is not None:
                        h.capabilities = caps
                        await db.commit()
            elif kind == "command_result":
                log.info(
                    "grpc.host_stream.command_result",
                    host_id=str(host_id),
                    command_id=msg.command_result.command_id,
                    success=msg.command_result.success,
                )
                # Mark the corresponding row in the commands table.
                try:
                    cmd_uuid = UUID(msg.command_result.command_id)
                    async with SessionLocal() as db:
                        cmd = await db.get(Command, cmd_uuid)
                        if cmd is not None:
                            cmd.status = (
                                CommandStatus.SUCCEEDED
                                if msg.command_result.success
                                else CommandStatus.FAILED
                            )
                            cmd.completed_at = datetime.now(UTC)
                            if msg.command_result.error:
                                cmd.error = msg.command_result.error[:512]
                            # M23.c: mirror onto the JobRun so the Jobs
                            # page reflects terminal status, then
                            # re-aggregate the parent Job.
                            if cmd.kind == CommandKind.RUN_JOB:
                                run_stmt = select(JobRun).where(JobRun.command_id == cmd.id)
                                run = (await db.execute(run_stmt)).scalar_one_or_none()
                                if run is not None:
                                    run.status = (
                                        JobRunStatus.COMPLETED
                                        if msg.command_result.success
                                        else JobRunStatus.FAILED
                                    )
                                    run.completed_at = datetime.now(UTC)
                                    if msg.command_result.error:
                                        run.error = msg.command_result.error[:1024]
                                    await db.flush()
                                    job_status = await aggregate_status(db, run.job_id)
                                    job = await db.get(Job, run.job_id)
                                    if job is not None:
                                        job.status = job_status
                            await db.commit()
                except Exception:
                    log.exception(
                        "grpc.command_result.persist_failed",
                        command_id=msg.command_result.command_id,
                    )
            elif kind == "job_progress":
                await self._handle_job_progress(host_id, msg.job_progress)
            elif kind == "job_artifact":
                await self._handle_job_artifact(host_id, msg.job_artifact)
            else:
                log.debug("grpc.host_stream.unknown_payload", host_id=str(host_id), kind=kind)

    # M23.c -----------------------------------------------------------
    # Jobs progress + artifact + presigned-upload glue.

    async def _handle_job_progress(
        self,
        host_id: UUID,
        progress: control_pb2.JobProgress,
    ) -> None:
        try:
            run_uuid = UUID(progress.run_id)
        except ValueError:
            log.warning("grpc.job_progress.bad_run_id", run_id=progress.run_id)
            return
        async with SessionLocal() as db:
            run = await db.get(JobRun, run_uuid)
            if run is None or run.host_id != host_id:
                log.warning(
                    "grpc.job_progress.unknown_run",
                    run_id=progress.run_id,
                    host_id=str(host_id),
                )
                return
            # Wire status → ORM status. JOB_RUN_STATUS_UNSPECIFIED keeps
            # the current value (agents can pulse progress without
            # restating the status field).
            wire = progress.status
            ALL = control_pb2.JobRunStatus  # type: ignore[attr-defined]  # noqa: N806 — wire enum constant
            if wire == ALL.JOB_RUN_STATUS_RUNNING:
                run.status = JobRunStatus.RUNNING
            elif wire == ALL.JOB_RUN_STATUS_DISPATCHED:
                run.status = JobRunStatus.DISPATCHED
            elif wire == ALL.JOB_RUN_STATUS_COMPLETED:
                run.status = JobRunStatus.COMPLETED
                run.completed_at = datetime.now(UTC)
            elif wire == ALL.JOB_RUN_STATUS_FAILED:
                run.status = JobRunStatus.FAILED
                run.completed_at = datetime.now(UTC)
            elif wire == ALL.JOB_RUN_STATUS_CANCELED:
                run.status = JobRunStatus.CANCELED
                run.completed_at = datetime.now(UTC)
            elif wire == ALL.JOB_RUN_STATUS_TIMEOUT:
                run.status = JobRunStatus.TIMEOUT
                run.completed_at = datetime.now(UTC)
            run.progress_pct = max(0, min(100, int(progress.progress_pct)))
            if progress.progress_message:
                run.progress_message = progress.progress_message[:256]
            if progress.error:
                run.error = progress.error[:1024]
            run.last_progress_at = datetime.now(UTC)
            # Roll up the parent Job if the run reached a terminal
            # state — list/list-runs pages should reflect it.
            if run.status in {
                JobRunStatus.COMPLETED,
                JobRunStatus.FAILED,
                JobRunStatus.CANCELED,
                JobRunStatus.TIMEOUT,
            }:
                await db.flush()
                job_status = await aggregate_status(db, run.job_id)
                job = await db.get(Job, run.job_id)
                if job is not None:
                    job.status = job_status
            await db.commit()

    async def _handle_job_artifact(
        self,
        host_id: UUID,
        report: control_pb2.JobArtifactReport,
    ) -> None:
        try:
            run_uuid = UUID(report.run_id)
        except ValueError:
            log.warning("grpc.job_artifact.bad_run_id", run_id=report.run_id)
            return
        kind_str = report.artifact_kind or "file"
        try:
            kind = JobArtifactKind(kind_str)
        except ValueError:
            log.warning("grpc.job_artifact.bad_kind", kind=kind_str)
            return
        async with SessionLocal() as db:
            run = await db.get(JobRun, run_uuid)
            if run is None or run.host_id != host_id:
                log.warning(
                    "grpc.job_artifact.unknown_run",
                    run_id=report.run_id,
                    host_id=str(host_id),
                )
                return
            # Cross-check that the bucket the agent reports matches one
            # we own. Refuse arbitrary buckets so a compromised agent
            # can't make us index objects in unrelated buckets.
            if report.bucket not in {
                settings.minio_bucket_artifacts,
                settings.minio_bucket_snapshots,
            }:
                log.warning(
                    "grpc.job_artifact.unknown_bucket",
                    bucket=report.bucket,
                    run_id=report.run_id,
                )
                return
            metadata: dict = {}
            if report.metadata_json:
                try:
                    import json as _json

                    metadata = _json.loads(report.metadata_json) or {}
                    if not isinstance(metadata, dict):
                        metadata = {"value": metadata}
                except (ValueError, TypeError):
                    metadata = {"raw": report.metadata_json[:1024]}
            artifact = JobArtifact(
                job_run_id=run.id,
                kind=kind,
                bucket=report.bucket,
                object_key=report.object_key[:512],
                size_bytes=int(report.size_bytes),
                sha256=report.sha256[:64] if report.sha256 else None,
                artifact_metadata=metadata,
            )
            db.add(artifact)
            await audit.record(
                db,
                actor=None,
                action="artifact.upload",
                resource_type="artifact",
                resource_id=str(artifact.id),
                payload={
                    "run_id": str(run.id),
                    "host_id": str(host_id),
                    "size_bytes": int(report.size_bytes),
                    "kind": kind_str,
                },
            )
            await db.commit()

    async def RequestArtifactUpload(  # noqa: N802 - gRPC method
        self,
        request: control_pb2.ArtifactUploadRequest,
        context: grpc.aio.ServicerContext,
    ) -> control_pb2.ArtifactUploadGrant:
        host_id_str = _peer_host_id(context)
        if not host_id_str:
            await context.abort(grpc.StatusCode.UNAUTHENTICATED, "no client cert")
        try:
            host_uuid = UUID(host_id_str)
            run_uuid = UUID(request.run_id)
        except ValueError:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "bad uuid")
            raise

        try:
            JobArtifactKind(request.artifact_kind or "file")
        except ValueError:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "unknown artifact_kind")
            raise

        async with SessionLocal() as db:
            run = await db.get(JobRun, run_uuid)
            if run is None or run.host_id != host_uuid:
                await context.abort(grpc.StatusCode.PERMISSION_DENIED, "run not on this host")
            assert run is not None  # for type narrowing past abort()
            job = await db.get(Job, run.job_id)
            if job is None:
                await context.abort(grpc.StatusCode.FAILED_PRECONDITION, "job gone")
            assert job is not None
            bucket = artifact_bucket_for(JobKind(job.kind.value))

        object_key = artifact_object_key(
            run_id=run_uuid,
            original_name=request.original_filename or "artifact.bin",
        )
        # M23.k: the agent uploads to the manager's REST proxy, not
        # directly to MinIO. The manager validates the HMAC-signed
        # token, then writes to MinIO with its own credentials.
        token, expires_at = issue_upload_token(
            run_id=run_uuid,
            bucket=bucket,
            object_key=object_key,
        )
        upload_url = f"{settings.manager_public_url.rstrip('/')}/api/uploads"
        expires_pb = timestamp_pb2.Timestamp()
        expires_pb.FromDatetime(expires_at.replace(tzinfo=None))
        log.info(
            "grpc.artifact_upload.granted",
            host_id=str(host_uuid),
            run_id=request.run_id,
            artifact_kind=request.artifact_kind,
            bucket=bucket,
            object_key=object_key,
            via="manager_proxy",
        )
        return control_pb2.ArtifactUploadGrant(
            url=upload_url,
            bucket=bucket,
            object_key=object_key,
            expires_at=expires_pb,
            required_headers={
                "X-Vigil-Upload-Token": token,
                "X-Vigil-Bucket": bucket,
                "X-Vigil-Object-Key": object_key,
            },
        )

    # End M23.c -------------------------------------------------------

    # Phase 1 #1.4 — live-response remote shell -----------------------
    #
    # Wire model: the agent dials `TerminalStream` as the gRPC client
    # after it receives a `TerminalOpen` directive (via the existing
    # HostStream command path; agent-side wiring lives in
    # agent-{linux,windows}). The agent sends `TerminalClientMessage`
    # over its outbound half (request_iterator below); the manager
    # sends `TerminalServerMessage` over the response half. Field
    # naming on the proto reflects the *operator's* semantic POV —
    # `TerminalClientMessage.input` carries operator → PTY bytes, and
    # `TerminalServerMessage.output` carries PTY → operator bytes —
    # but the gRPC client role belongs to the agent because the
    # agent owns the PTY. This handler is the bidirectional bridge
    # between the agent's gRPC stream and the operator's WebSocket
    # (paired in-process by `session_id` through the broker).
    #
    # Auth: the agent presents its mTLS cert; we verify the cert CN
    # matches the host_id that the operator's REST POST bound the
    # session to. The analyst RBAC + host_visible_to check ran in
    # `app.api.host_terminal.open_terminal_session` — the gRPC half
    # only confirms agent identity.

    async def TerminalStream(  # noqa: N802 — gRPC method
        self,
        request_iterator: AsyncIterator[control_pb2.TerminalClientMessage],
        context: grpc.aio.ServicerContext,
    ) -> AsyncIterator[control_pb2.TerminalServerMessage]:
        from app.services.terminal import broker as _terminal_broker

        host_id_str = _peer_host_id(context)
        if host_id_str is None:
            await context.abort(grpc.StatusCode.UNAUTHENTICATED, "client cert required")
            return
        try:
            host_uuid = UUID(host_id_str)
        except ValueError:
            await context.abort(grpc.StatusCode.UNAUTHENTICATED, "client cert CN is not a UUID")
            return

        # First inbound message has to be TerminalOpen so we can pair
        # the stream with the operator's WebSocket. We pull it
        # explicitly off the iterator below; any other payload type
        # first means the agent is broken or the call is malicious.
        first: control_pb2.TerminalClientMessage | None = None
        async for msg in request_iterator:
            first = msg
            break
        if first is None:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "no open message")
            return
        if first.WhichOneof("payload") != "open":
            await context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                "first message must be TerminalOpen",
            )
            return
        try:
            session_id = UUID(first.open.session_id)
            requested_host = UUID(first.open.host_id)
        except ValueError:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "bad uuid in TerminalOpen")
            return

        if requested_host != host_uuid:
            await context.abort(
                grpc.StatusCode.PERMISSION_DENIED,
                "TerminalOpen host_id != peer cert host_id",
            )
            return
        session = _terminal_broker.get(session_id)
        if session is None:
            await context.abort(grpc.StatusCode.NOT_FOUND, "unknown session_id")
            return
        if session.host_id != host_uuid:
            await context.abort(
                grpc.StatusCode.PERMISSION_DENIED,
                "session bound to a different host",
            )
            return

        log.info(
            "grpc.terminal_stream.open",
            host_id=host_id_str,
            session_id=str(session_id),
        )

        # Drain remaining agent → manager messages into the broker so
        # the WS relay forwards them on.
        async def _from_agent() -> None:
            try:
                async for msg in request_iterator:
                    kind = msg.WhichOneof("payload")
                    if kind == "input":
                        # The agent puts PTY stdout/stderr on the
                        # `input` field semantically (we reuse the
                        # operator-side message type so the bidi
                        # half remains one shape).
                        await session.agent_to_ops.put(("output", msg.input.data))
                    elif kind == "close":
                        await session.agent_to_ops.put(
                            ("exit", (0, msg.close.reason or "agent_close"))
                        )
                        return
            except (asyncio.CancelledError, grpc.aio.AioRpcError):
                return

        inbound_task = asyncio.create_task(_from_agent())
        try:
            while not session.closed.is_set():
                try:
                    kind, payload = await asyncio.wait_for(session.ops_to_agent.get(), timeout=1.0)
                except TimeoutError:
                    continue
                if kind == "input":
                    yield control_pb2.TerminalServerMessage(
                        output=control_pb2.TerminalIO(data=payload),
                    )
                elif kind == "resize":
                    # TerminalServerMessage has no resize field; the
                    # current wire shape doesn't propagate operator
                    # SIGWINCH downstream. Skipping is fine for the
                    # MVP — xterm.js still renders at the new size on
                    # the operator's side, and most shells re-flow
                    # on the next prompt. A future schema bump can
                    # add `TerminalServerMessage.resize` if needed.
                    continue
                elif kind == "close":
                    yield control_pb2.TerminalServerMessage(
                        exit=control_pb2.TerminalExit(
                            exit_code=0, reason=str(payload) or "operator_close"
                        ),
                    )
                    return
        except asyncio.CancelledError:
            pass
        finally:
            inbound_task.cancel()
            with contextlib.suppress(BaseException):
                await inbound_task
            log.info(
                "grpc.terminal_stream.close",
                host_id=host_id_str,
                session_id=str(session_id),
            )
            await _terminal_broker.close(session_id)

    # End Phase 1 #1.4 ------------------------------------------------

    async def _build_rule_sync(self, db: AsyncSession) -> control_pb2.RuleSync:
        """Snapshot enabled YARA + IOC rules and pack into a RuleSync message.

        Sigma rules are evaluated server-side; agents don't receive them.
        """
        stmt = select(Rule).where(Rule.enabled.is_(True)).options(selectinload(Rule.iocs))
        rows = (await db.execute(stmt)).scalars().all()

        sync = control_pb2.RuleSync(rules_version=int(datetime.now(UTC).timestamp()))
        for r in rows:
            if r.kind is RuleKind.YARA and r.body:
                # `severity`/`action`/`kind` are protobuf enums (ints on
                # the wire). protoc-generated stubs collide with our
                # SQLAlchemy app-side enum names of the same shape, so
                # pyright infers the wrong type here. Suppressing the
                # arg-type check is correct: at runtime these are
                # plain ints accepted by the proto enum field.
                sync.yara.append(
                    control_pb2.YaraRule(
                        id=str(r.id),
                        name=r.name,
                        source=r.body,
                        severity=_pb_severity(r.severity.value),  # pyright: ignore[reportArgumentType]
                        action=_pb_action(r.action.value),  # pyright: ignore[reportArgumentType]
                    )
                )
            elif r.kind is RuleKind.IOC:
                # One IocRule per (rule, kind) — agents typically index hash, name, path separately.
                by_kind: dict[str, list[IocEntry]] = {}
                for entry in r.iocs:
                    by_kind.setdefault(entry.kind.value, []).append(entry)
                for kind, entries in by_kind.items():
                    sync.iocs.append(
                        control_pb2.IocRule(
                            id=str(r.id),
                            name=r.name,
                            kind=_pb_ioc_kind(kind),  # pyright: ignore[reportArgumentType]
                            values=[e.value_normalized for e in entries],
                            severity=_pb_severity(r.severity.value),  # pyright: ignore[reportArgumentType]
                            action=_pb_action(r.action.value),  # pyright: ignore[reportArgumentType]
                        )
                    )
        return sync
