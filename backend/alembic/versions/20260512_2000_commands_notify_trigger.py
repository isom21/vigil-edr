"""Add commands.notify trigger so the gRPC dispatcher can LISTEN instead of poll.

Top-20 #12: the per-host bidi-stream's `_command_dispatcher` polled
`commands` every 500 ms for new PENDING rows. At ~2 PG queries/sec
× N hosts that's 200 q/s for a 100-host fleet and 2000 q/s at 1000
hosts — visible in `pg_stat_activity` and a load drag.

This migration installs a row-level AFTER INSERT trigger that calls
`pg_notify('vigil_cmd_<host_id_underscored>', <command_id>)`. The
dispatcher LISTENs on that channel and only re-queries the table on
notification, falling back to a 30 s poll for missed-notification
safety. Channel names can't have dashes (per pg docs they're treated
as separator chars in some clients); we normalise the host_id UUID to
underscore form server-side so the listener matches.

The trigger fires under the writer's privileges, so any role that can
INSERT into `commands` can also fire the NOTIFY — no extra GRANT
needed.

Revision ID: 7d3f8e1a2b4c
Revises: 2a8c3f7b1e9d
Create Date: 2026-05-12
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "7d3f8e1a2b4c"
down_revision: str | None = "2a8c3f7b1e9d"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION vigil_notify_command_insert() RETURNS TRIGGER AS $$
        BEGIN
            PERFORM pg_notify(
                'vigil_cmd_' || replace(NEW.host_id::text, '-', '_'),
                NEW.id::text
            );
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        DROP TRIGGER IF EXISTS commands_notify_insert ON commands;
        CREATE TRIGGER commands_notify_insert
            AFTER INSERT ON commands
            FOR EACH ROW
            EXECUTE FUNCTION vigil_notify_command_insert();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS commands_notify_insert ON commands;")
    op.execute("DROP FUNCTION IF EXISTS vigil_notify_command_insert();")
