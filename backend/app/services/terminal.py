"""Phase 1 #1.4 — live-response remote shell.

Shared helpers for the terminal session subsystem:

  * HMAC-signed short-lived session tokens (same shape as
    `app.services.uploads` — stateless, no DB row needed).
  * An in-process broker that pairs the operator's WebSocket relay
    with the gRPC ``TerminalStream`` the agent dials in on. The
    broker is intentionally simple: a dict keyed by session_id whose
    values are a pair of asyncio queues (``ops_to_agent`` and
    ``agent_to_ops``). The WS pushes onto ``ops_to_agent`` and pops
    from ``agent_to_ops``; the gRPC handler does the inverse.

The token + broker live separately so:

  * RBAC checks (analyst+, host_visible_to) happen at the REST
    surface where we have an Actor.
  * The gRPC handler — which only sees the agent's mTLS identity —
    just confirms the presented session_id is alive in the broker
    and that the agent cert's host_id matches what the token claimed.

I/O is audit-logged in coalesced batches under ``host.terminal.io``
to avoid recording the full keystroke stream. The payload carries the
direction, the byte count, and the first 64 bytes hex-encoded as a
tamper signal — enough to forensically confirm the broad shape of
the session without leaking every secret an analyst pasted into a
remote root shell.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from app.core.config import settings

_TOKEN_PREFIX = "vts1"  # vigil-terminal-session v1
# Token TTL is short by design — the analyst is expected to open the
# WebSocket right after the POST returns. Long-lived tokens would
# defeat the per-session audit trail.
_TOKEN_TTL_SECONDS = 60


@dataclass(frozen=True)
class TerminalSessionClaim:
    session_id: UUID
    host_id: UUID
    user_id: UUID
    expires_at: datetime


def issue_session_token(
    *, host_id: UUID, user_id: UUID, session_id: UUID | None = None
) -> tuple[str, UUID, datetime]:
    """Return ``(token, session_id, expires_at)``.

    Token format mirrors ``services.uploads``:
    ``vts1.<b64(payload)>.<b64(hmac)>`` where payload is
    ``session_id|host_id|user_id|expires_unix``.
    """
    sid = session_id or uuid4()
    expires_at = datetime.now(UTC) + timedelta(seconds=_TOKEN_TTL_SECONDS)
    payload = _canonical(sid, host_id, user_id, expires_at)
    sig = hmac.new(_key(), payload.encode("utf-8"), hashlib.sha256).digest()
    token = ".".join([_TOKEN_PREFIX, _b64(payload.encode("utf-8")), _b64(sig)])
    return token, sid, expires_at


def verify_session_token(token: str) -> TerminalSessionClaim | None:
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != _TOKEN_PREFIX:
        return None
    try:
        payload_bytes = _b64_decode(parts[1])
        sig_bytes = _b64_decode(parts[2])
    except (ValueError, TypeError):
        return None
    expected = hmac.new(_key(), payload_bytes, hashlib.sha256).digest()
    if not hmac.compare_digest(sig_bytes, expected):
        return None
    try:
        payload = payload_bytes.decode("utf-8")
        sid_s, host_s, user_s, exp_s = payload.split("|", 3)
        expires_at = datetime.fromtimestamp(int(exp_s), tz=UTC)
    except (ValueError, OverflowError):
        return None
    if expires_at < datetime.now(UTC):
        return None
    try:
        return TerminalSessionClaim(
            session_id=UUID(sid_s),
            host_id=UUID(host_s),
            user_id=UUID(user_s),
            expires_at=expires_at,
        )
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# In-process session broker.
# ---------------------------------------------------------------------------


@dataclass
class TerminalSession:
    session_id: UUID
    host_id: UUID
    user_id: UUID
    # WS → agent direction.
    ops_to_agent: asyncio.Queue = field(default_factory=asyncio.Queue)
    # agent → WS direction.
    agent_to_ops: asyncio.Queue = field(default_factory=asyncio.Queue)
    # Set by either side to signal the other to close.
    closed: asyncio.Event = field(default_factory=asyncio.Event)


class TerminalBroker:
    """Pairs WebSocket and gRPC TerminalStream halves by session_id.

    The broker is a singleton; both halves look up the same session by
    id. The dict is small (one entry per active terminal session) and
    only lives in-process — terminals do not survive manager restarts
    by design.
    """

    def __init__(self) -> None:
        self._sessions: dict[UUID, TerminalSession] = {}
        self._lock = asyncio.Lock()

    async def open(self, *, session_id: UUID, host_id: UUID, user_id: UUID) -> TerminalSession:
        async with self._lock:
            if session_id in self._sessions:
                raise KeyError("session already open")
            session = TerminalSession(session_id=session_id, host_id=host_id, user_id=user_id)
            self._sessions[session_id] = session
            return session

    def get(self, session_id: UUID) -> TerminalSession | None:
        return self._sessions.get(session_id)

    async def close(self, session_id: UUID) -> None:
        async with self._lock:
            session = self._sessions.pop(session_id, None)
        if session is not None:
            session.closed.set()


broker = TerminalBroker()


# ---------------------------------------------------------------------------
# Internal helpers (private to this module).
# ---------------------------------------------------------------------------


def _canonical(session_id: UUID, host_id: UUID, user_id: UUID, expires_at: datetime) -> str:
    return f"{session_id}|{host_id}|{user_id}|{int(expires_at.timestamp())}"


def _key() -> bytes:
    # Reuse the same independent key the upload tokens use — already
    # rotated separately from jwt_secret by install.sh. Sharing the
    # key is OK because the prefix (vts1 vs vau1) plus the canonical
    # payload differ, so a captured upload token can never validate
    # as a terminal session token or vice versa.
    if settings.upload_token_key:
        return settings.upload_token_key.encode("utf-8")
    return settings.jwt_secret.encode("utf-8")


def b64encode_urlsafe(b: bytes) -> str:
    """URL-safe base64, no padding. Matches the JS frontend's encoder."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64decode_urlsafe(s: str) -> bytes:
    """Inverse of `b64encode_urlsafe`; tolerates missing padding."""
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# Backwards-compat aliases used internally in this module.
_b64 = b64encode_urlsafe
_b64_decode = b64decode_urlsafe
