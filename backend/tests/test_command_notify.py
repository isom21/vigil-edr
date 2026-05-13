"""Top-20 #12: pg_notify trigger + listener wiring.

The gRPC command dispatcher used to poll commands every 500 ms; it
now LISTENs on a per-host channel that the `commands_notify_insert`
trigger fires from. Tests pin the contract:

  * Inserting a command for host X fires NOTIFY on channel
    `vigil_cmd_<X_with_dashes_replaced>`.
  * The listener helper from `app.services.command_notify` receives
    that notify and sets the asyncio.Event.
  * A command for a different host doesn't wake the listener.

Asyncpg LISTEN holds the connection, so the helper opens its own.
We commit the test fixture's seed data via the SAVEPOINT-isolated
session, then COMMIT inside the helper's path to fire the trigger.
Because the listener uses a separate connection, it sees the
COMMITted row.
"""

from __future__ import annotations

import asyncio
import os
import uuid

import asyncpg
import pytest

_DEFAULT_TENANT = "00000000-0000-0000-0000-000000000001"


def _async_dsn() -> str | None:
    if v := os.environ.get("VIGIL_TEST_PG_DSN"):
        return v.replace("postgresql+asyncpg://", "postgresql://", 1)
    if v := os.environ.get("VIGIL_PG_DSN"):
        return v.replace("postgresql+asyncpg://", "postgresql://", 1)
    return None


def _skip_if_no_dsn() -> None:
    if _async_dsn() is None:
        pytest.skip("No PG DSN configured.")


def test_channel_name_replaces_dashes() -> None:
    from app.services.command_notify import channel_for

    h = uuid.UUID("12345678-1234-1234-1234-123456789abc")
    assert channel_for(h) == "vigil_cmd_12345678_1234_1234_1234_123456789abc"


@pytest.mark.asyncio
async def test_listen_receives_notify_for_matching_host() -> None:
    """End-to-end: INSERT a command, listener fires its event."""
    _skip_if_no_dsn()
    from app.services.command_notify import listen_for_commands

    # Pre-create a host so the FK constraint is satisfied.
    setup_conn = await asyncpg.connect(_async_dsn())
    host_id = uuid.uuid4()
    try:
        # Best-effort: insert a host row. The hostname column is unique.
        await setup_conn.execute(
            """
            INSERT INTO hosts (
                id, hostname, os_family, status,
                created_at, updated_at, tenant_id
            )
            VALUES ($1, $2, 'linux', 'online', now(), now(), $3)
            """,
            host_id,
            f"notify-host-{os.urandom(3).hex()}",
            _DEFAULT_TENANT,
        )

        async with listen_for_commands(host_id) as notify_event:
            # Insert a command for this host on a separate connection so
            # the COMMIT fires the trigger.
            writer = await asyncpg.connect(_async_dsn())
            try:
                cmd_id = uuid.uuid4()
                await writer.execute(
                    """
                    INSERT INTO commands (
                        id, host_id, kind, status, payload,
                        created_at, updated_at, tenant_id
                    )
                    VALUES (
                        $1, $2, 'kill_process', 'pending', '{}'::jsonb,
                        now(), now(), $3
                    )
                    """,
                    cmd_id,
                    host_id,
                    _DEFAULT_TENANT,
                )
            finally:
                await writer.close()

            # Notify is delivered post-COMMIT; wait briefly.
            try:
                await asyncio.wait_for(notify_event.wait(), timeout=5.0)
            except TimeoutError:
                pytest.fail("listen_for_commands didn't observe NOTIFY within 5 s")
    finally:
        # Clean up — the test isn't using db_session, so we own the rows.
        await setup_conn.execute("DELETE FROM commands WHERE host_id = $1", host_id)
        await setup_conn.execute("DELETE FROM hosts WHERE id = $1", host_id)
        await setup_conn.close()


@pytest.mark.asyncio
async def test_listen_ignores_other_hosts() -> None:
    """A command for a different host_id doesn't wake the listener."""
    _skip_if_no_dsn()
    from app.services.command_notify import listen_for_commands

    listener_host = uuid.uuid4()
    other_host = uuid.uuid4()
    setup_conn = await asyncpg.connect(_async_dsn())
    try:
        await setup_conn.execute(
            """
            INSERT INTO hosts (
                id, hostname, os_family, status,
                created_at, updated_at, tenant_id
            )
            VALUES
                ($1, $2, 'linux', 'online', now(), now(), $5),
                ($3, $4, 'linux', 'online', now(), now(), $5)
            """,
            listener_host,
            f"listener-host-{os.urandom(3).hex()}",
            other_host,
            f"other-host-{os.urandom(3).hex()}",
            _DEFAULT_TENANT,
        )

        async with listen_for_commands(listener_host) as notify_event:
            writer = await asyncpg.connect(_async_dsn())
            try:
                await writer.execute(
                    """
                    INSERT INTO commands (
                        id, host_id, kind, status, payload,
                        created_at, updated_at, tenant_id
                    )
                    VALUES (
                        $1, $2, 'kill_process', 'pending', '{}'::jsonb,
                        now(), now(), $3
                    )
                    """,
                    uuid.uuid4(),
                    other_host,
                    _DEFAULT_TENANT,
                )
            finally:
                await writer.close()

            # Listener should NOT fire; 1s wait is enough to prove the
            # negative (NOTIFY would have landed within ms).
            try:
                await asyncio.wait_for(notify_event.wait(), timeout=1.0)
                pytest.fail("listen_for_commands woke on a different host's command")
            except TimeoutError:
                pass  # expected
    finally:
        await setup_conn.execute(
            "DELETE FROM commands WHERE host_id IN ($1, $2)", listener_host, other_host
        )
        await setup_conn.execute(
            "DELETE FROM hosts WHERE id IN ($1, $2)", listener_host, other_host
        )
        await setup_conn.close()
