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
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.db import SessionLocal
from app.core.security import hash_enrollment_token
from app.models import (
    Command,
    CommandKind,
    CommandStatus,
    EnrollmentToken,
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
    return {
        "alert": common_pb2.RULE_ACTION_DETECT,
        "block": common_pb2.RULE_ACTION_BLOCK,
        "quarantine": common_pb2.RULE_ACTION_QUARANTINE,
    }.get(a, common_pb2.RULE_ACTION_UNSPECIFIED)


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

        th = hash_enrollment_token(request.enrollment_token)
        token = (
            await db.execute(select(EnrollmentToken).where(EnrollmentToken.token_hash == th))
        ).scalar_one_or_none()
        now = datetime.now(UTC)
        if token is None or token.used_at is not None or token.expires_at < now:
            await context.abort(grpc.StatusCode.PERMISSION_DENIED, "invalid or expired token")

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

        ca = CaService(db)
        issued = await ca.sign_csr(request.csr_pem, host_id=str(host.id), hostname=request.hostname)
        host.cert_fingerprint = issued.fingerprint_sha256

        token.used_at = now
        token.used_by_host_id = host.id

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

        log.info("grpc.host_stream.open", host_id=host_id_str)

        async with SessionLocal() as db:
            host = await db.get(Host, host_id)
            if host is None:
                log.warning("grpc.host_stream.unknown_host", host_id=host_id_str)
                await context.abort(grpc.StatusCode.UNAUTHENTICATED, "unknown host")
                return
            host.status = HostStatus.ONLINE
            host.last_seen_at = datetime.now(UTC)
            await db.commit()

            # Push initial rule sync to the agent.
            initial = await self._build_rule_sync(db)

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

        # Command dispatcher — polls PG for pending commands for this host
        # at 500ms cadence, pushes them onto out_queue, marks DISPATCHED.
        async def _command_dispatcher(out: asyncio.Queue):
            try:
                while True:
                    try:
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
                    except Exception:
                        log.exception("grpc.command_dispatcher.error", host_id=host_id_str)
                    await asyncio.sleep(0.5)
            except asyncio.CancelledError:
                return

        out_queue: asyncio.Queue = asyncio.Queue()
        ping_task = asyncio.create_task(_pinger(out_queue))
        cmd_task = asyncio.create_task(_command_dispatcher(out_queue))

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
            with contextlib.suppress(BaseException):
                await ping_task
            with contextlib.suppress(BaseException):
                await cmd_task
            async with SessionLocal() as db:
                h = await db.get(Host, host_id)
                if h is not None:
                    h.status = HostStatus.OFFLINE
                    await db.commit()
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
                        sends = [
                            producer.send_bytes(
                                settings.topic_telemetry_raw,
                                str(host_id),
                                ev.SerializeToString(),
                            )
                            for ev in msg.events.events[:granted]
                        ]
                        await asyncio.gather(*sends)
            elif kind == "heartbeat":
                # Throttle DB writes — once per ~30s.
                now = datetime.now(UTC)
                if (now - last_seen_update).total_seconds() >= 30:
                    async with SessionLocal() as db:
                        h = await db.get(Host, host_id)
                        if h is not None:
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
                except (ValueError, Exception):
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
