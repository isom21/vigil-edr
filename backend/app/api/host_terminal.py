"""Phase 1 #1.4 — live-response remote shell.

Two HTTP surfaces:

  * ``POST /api/hosts/{id}/terminal`` mints a short-lived session token
    + ``session_id`` for the analyst. RBAC: analyst+, plus the standard
    host-group visibility gate. Records ``host.terminal.open`` so the
    audit log shows who started which session before any I/O flows.

  * ``GET /api/hosts/{id}/terminal/ws?token=…`` upgrades to a
    WebSocket and proxies bytes to/from the gRPC ``TerminalStream``
    the agent dials in on. Coalesces I/O into batches and writes one
    ``host.terminal.io`` audit row per batch (``terminal_audit_batch_*``
    settings cap row volume — full keystroke logging would blow up
    the audit chain).

The WebSocket path validates the token, so the analyst is
authenticated by the *signed claim* rather than the bearer header
(``EventSource``-style — most browsers can't set Authorization on
``new WebSocket(url)``).
"""

from __future__ import annotations

import asyncio
import binascii
import json
import time
from datetime import datetime
from uuid import UUID, uuid4

import structlog
from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel

from app.core.config import settings
from app.core.db import SessionLocal
from app.core.deps import DbSession, RequireAnalyst
from app.core.errors import not_found
from app.models import Host
from app.services import audit
from app.services.scoping import host_visible_to
from app.services.terminal import (
    b64decode_urlsafe,
    b64encode_urlsafe,
    broker,
    issue_session_token,
    verify_session_token,
)

log = structlog.get_logger()

router = APIRouter(prefix="/api/hosts", tags=["terminal"])


class TerminalSessionResponse(BaseModel):
    session_id: str
    token: str
    expires_at: datetime
    ws_url: str


@router.post(
    "/{host_id}/terminal",
    response_model=TerminalSessionResponse,
    status_code=status.HTTP_201_CREATED,
)
async def open_terminal_session(
    host_id: UUID,
    db: DbSession,
    actor: RequireAnalyst,
) -> TerminalSessionResponse:
    """Mint a short-lived session token for a live-response terminal.

    The token rides in the WebSocket URL (``?token=…``) since browsers
    can't set Authorization on ``new WebSocket(...)``. The token is
    HMAC-signed and tied to the (host_id, user_id, session_id) tuple
    so the WS handler can re-verify without consulting the DB.
    """
    host = await db.get(Host, host_id)
    if host is None:
        raise not_found("host")
    if not await host_visible_to(actor, host_id, db):
        # 403/404 unification: matches every other host-scoped endpoint.
        raise not_found("host", str(host_id))

    session_id = uuid4()
    token, sid, expires_at = issue_session_token(
        host_id=host_id, user_id=actor.user.id, session_id=session_id
    )
    await audit.record(
        db,
        actor=actor,
        action="host.terminal.open",
        resource_type="host",
        resource_id=str(host_id),
        payload={"session_id": str(sid)},
    )
    await db.commit()

    return TerminalSessionResponse(
        session_id=str(sid),
        token=token,
        expires_at=expires_at,
        ws_url=f"/api/hosts/{host_id}/terminal/ws?token={token}",
    )


@router.websocket("/{host_id}/terminal/ws")
async def terminal_websocket(
    websocket: WebSocket,
    host_id: UUID,
    token: str = Query(...),
) -> None:
    """Bidirectional terminal proxy.

    Frames on the wire:

    * Operator → manager (text JSON):
        ``{"t":"in","d":"<base64 stdin>"}`` — input bytes
        ``{"t":"resize","cols":N,"rows":N}`` — SIGWINCH
        ``{"t":"close"}`` — analyst-initiated close
    * Manager → operator (text JSON):
        ``{"t":"out","d":"<base64 stdout/stderr>"}``
        ``{"t":"exit","code":N,"reason":"..."}``

    Base64 framing keeps the JSON channel clean and avoids edge cases
    around mid-byte UTF-8 splits when the agent emits raw bytes from
    the PTY master.
    """
    claim = verify_session_token(token)
    if claim is None or claim.host_id != host_id:
        # Reject before the upgrade completes — saves us a 1006 close.
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="invalid token")
        return

    await websocket.accept()
    session = await broker.open(session_id=claim.session_id, host_id=host_id, user_id=claim.user_id)

    # Coalesce stdin/stdout into audit batches. One row per
    # `terminal_audit_batch_bytes` of buffered data OR per
    # `terminal_audit_batch_s` seconds, whichever lands first.
    audit_batches: dict[str, _AuditBatch] = {
        "stdin": _AuditBatch(direction="stdin"),
        "stdout": _AuditBatch(direction="stdout"),
    }
    state = _SessionState(
        idle_deadline=time.monotonic() + settings.terminal_idle_s,
        close_reason="stream_close",
    )
    close_event = asyncio.Event()

    async def _flush(direction: str) -> None:
        batch = audit_batches[direction]
        if not batch.bytes_count:
            return
        # Open a fresh DB session — the WS handler's own request
        # context is not async-with-able here.
        async with SessionLocal() as adb:
            await audit.record(
                adb,
                actor=None,
                action="host.terminal.io",
                resource_type="host",
                resource_id=str(host_id),
                payload={
                    "session_id": str(claim.session_id),
                    "direction": direction,
                    "bytes": batch.bytes_count,
                    "first_64_hex": batch.first_64_hex,
                },
            )
            await adb.commit()
        batch.reset()

    async def _from_ops_to_agent() -> None:
        try:
            while True:
                raw = await websocket.receive_text()
                state.idle_deadline = time.monotonic() + settings.terminal_idle_s
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                kind = msg.get("t")
                if kind == "in":
                    try:
                        data = b64decode_urlsafe(msg.get("d", ""))
                    except (ValueError, binascii.Error):
                        continue
                    audit_batches["stdin"].add(data)
                    if audit_batches["stdin"].full(settings.terminal_audit_batch_bytes):
                        await _flush("stdin")
                    await session.ops_to_agent.put(("input", data))
                elif kind == "resize":
                    cols = int(msg.get("cols", 80) or 0)
                    rows = int(msg.get("rows", 24) or 0)
                    await session.ops_to_agent.put(("resize", (cols, rows)))
                elif kind == "close":
                    state.close_reason = "operator_close"
                    await session.ops_to_agent.put(("close", "operator_close"))
                    return
        except WebSocketDisconnect:
            state.close_reason = "ws_disconnect"
        except Exception:  # pragma: no cover — defensive
            log.exception("terminal.ws.ops_to_agent.error", session_id=str(claim.session_id))

    async def _from_agent_to_ops() -> None:
        try:
            while True:
                kind, payload = await session.agent_to_ops.get()
                state.idle_deadline = time.monotonic() + settings.terminal_idle_s
                if kind == "output":
                    audit_batches["stdout"].add(payload)
                    if audit_batches["stdout"].full(settings.terminal_audit_batch_bytes):
                        await _flush("stdout")
                    await websocket.send_text(
                        json.dumps({"t": "out", "d": b64encode_urlsafe(payload)})
                    )
                elif kind == "exit":
                    code, reason = payload
                    state.close_reason = str(reason)
                    await websocket.send_text(
                        json.dumps({"t": "exit", "code": int(code), "reason": str(reason)})
                    )
                    return
        except WebSocketDisconnect:
            return
        except Exception:  # pragma: no cover — defensive
            log.exception("terminal.ws.agent_to_ops.error", session_id=str(claim.session_id))

    async def _periodic_flush() -> None:
        try:
            while True:
                await asyncio.sleep(settings.terminal_audit_batch_s)
                await _flush("stdin")
                await _flush("stdout")
                if time.monotonic() >= state.idle_deadline:
                    state.close_reason = "idle_timeout"
                    close_event.set()
                    return
        except asyncio.CancelledError:
            return

    ops_task = asyncio.create_task(_from_ops_to_agent())
    agent_task = asyncio.create_task(_from_agent_to_ops())
    flush_task = asyncio.create_task(_periodic_flush())
    close_task = asyncio.create_task(close_event.wait())

    try:
        await asyncio.wait(
            [ops_task, agent_task, close_task],
            return_when=asyncio.FIRST_COMPLETED,
        )
    finally:
        for t in (flush_task, ops_task, agent_task, close_task):
            t.cancel()
        for t in (flush_task, ops_task, agent_task, close_task):
            try:
                await t
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass

        # Final flush so trailing bytes still leave an audit row.
        await _flush("stdin")
        await _flush("stdout")

        await broker.close(claim.session_id)

        async with SessionLocal() as adb:
            await audit.record(
                adb,
                actor=None,
                action="host.terminal.close",
                resource_type="host",
                resource_id=str(host_id),
                payload={
                    "session_id": str(claim.session_id),
                    "reason": state.close_reason,
                },
            )
            await adb.commit()

        try:
            await websocket.close()
        except RuntimeError:
            # Already closed.
            pass


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


class _SessionState:
    __slots__ = ("idle_deadline", "close_reason")

    def __init__(self, *, idle_deadline: float, close_reason: str) -> None:
        self.idle_deadline = idle_deadline
        self.close_reason = close_reason


class _AuditBatch:
    __slots__ = ("direction", "bytes_count", "first_64_hex", "_first_locked")

    def __init__(self, *, direction: str) -> None:
        self.direction = direction
        self.bytes_count = 0
        self.first_64_hex = ""
        # The "first 64 bytes hex" should reflect the first bytes of
        # the entire emitted batch (i.e. the new batch after a flush);
        # we lock it on the first add() so the preview stays stable
        # across multiple adds before the flush.
        self._first_locked = False

    def add(self, chunk: bytes) -> None:
        if not chunk:
            return
        if not self._first_locked:
            self.first_64_hex = chunk[:64].hex()
            self._first_locked = True
        self.bytes_count += len(chunk)

    def full(self, threshold_bytes: int) -> bool:
        return self.bytes_count >= threshold_bytes

    def reset(self) -> None:
        self.bytes_count = 0
        self.first_64_hex = ""
        self._first_locked = False
