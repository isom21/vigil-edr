"""LISTEN/NOTIFY wiring for the per-host command dispatcher (Top-20 #12).

The gRPC bidi stream's command dispatcher used to poll `commands`
every 500 ms; this module replaces the poll loop with a Postgres
NOTIFY listener so the dispatcher only re-queries when a fresh row
lands.

Each gRPC stream opens its own asyncpg connection here because LISTEN
holds the underlying connection for the listen's lifetime — checking
one out of SQLAlchemy's request pool would starve the request path.
The connection is short-lived (lifetime of the stream) and only does
LISTEN, so connection-pool overhead is negligible vs the savings
from killing the 2 q/s/host poll.

Channel naming: pg's `pg_notify` channel names can't contain dashes
in every client (they sometimes get interpreted as token boundaries).
Host IDs are UUIDs with dashes, so we replace `-` with `_` on both
sides — must match the trigger in migration `7d3f8e1a2b4c`.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from uuid import UUID

import asyncpg
import structlog

from app.core.config import settings

log = structlog.get_logger()


def channel_for(host_id: UUID) -> str:
    """The pg_notify channel name for a given host."""
    return f"vigil_cmd_{str(host_id).replace('-', '_')}"


def _asyncpg_dsn() -> str:
    """SQLAlchemy DSNs have a `+asyncpg` driver suffix; asyncpg's own
    `connect()` doesn't recognise it. Strip the suffix when present."""
    dsn = settings.pg_dsn
    return dsn.replace("postgresql+asyncpg://", "postgresql://", 1)


@asynccontextmanager
async def listen_for_commands(host_id: UUID) -> AsyncIterator[asyncio.Event]:
    """Yield an `asyncio.Event` that fires when a new command row is
    INSERTed for `host_id`. The event is cleared by the caller after
    each wakeup so it can re-arm.

    The asyncpg connection is owned by this context manager and
    closed when the caller exits. The trigger payload (the command id)
    is logged at debug level but otherwise unused — the caller re-
    queries the table to pick up multiple rows at once.
    """
    notify_event = asyncio.Event()
    channel = channel_for(host_id)

    def _on_notify(_conn, _pid, _channel, payload):
        log.debug(
            "grpc.command_notify.received",
            host_id=str(host_id),
            payload=payload,
        )
        notify_event.set()

    conn = await asyncpg.connect(_asyncpg_dsn())
    try:
        await conn.add_listener(channel, _on_notify)
        try:
            yield notify_event
        finally:
            try:
                await conn.remove_listener(channel, _on_notify)
            except Exception:  # pragma: no cover — best-effort cleanup
                log.debug("grpc.command_notify.remove_listener_failed", host_id=str(host_id))
    finally:
        await conn.close()
