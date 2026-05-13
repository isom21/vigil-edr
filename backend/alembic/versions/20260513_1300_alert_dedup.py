"""Alert deduplication: dedup_key + occurrence_count + last_occurred_at.

Phase 1 #1.10. Alert producers (sigma_realtime, IOC detector, future
YARA detector) compute a stable dedup key from
(rule_id, host_id, hash(canonical_event_signal)) where the canonical
signal is the most specific ECS field available — process.executable,
file.path, destination.ip, or event.id. Within a configurable sliding
window (`VIGIL_ALERT_DEDUP_WINDOW_S`, default 300 s) the producer
bumps `occurrence_count` + refreshes `last_occurred_at` on an existing
open alert (state in {new, investigating}) with the same key instead
of inserting a duplicate row. Closed alerts (false_positive /
true_positive) never coalesce — a fresh recurrence after triage gets
its own row so analysts notice.

Schema:
  * `dedup_key`         VARCHAR(64)  NULL   — sha256 hex, lazy backfill
  * `occurrence_count`  INTEGER  NOT NULL DEFAULT 1
  * `last_occurred_at`  TIMESTAMPTZ NOT NULL DEFAULT now()

We index `dedup_key` and `last_occurred_at` separately so the open-
alert probe (WHERE dedup_key = $1 AND state IN (...) AND
last_occurred_at > $2) plans well. No UNIQUE constraint — closed
alerts intentionally share a key with future recurrences.

Existing rows backfill cleanly: `dedup_key` stays NULL (so no probe
can ever match them — they're treated as singletons until they close),
`occurrence_count` defaults to 1 via the server default,
`last_occurred_at` defaults to now() at migration time which keeps
the row out of the sliding window after a few minutes — safe.

Revision ID: 8e2a5c1f4d09
Revises: 7d3f8e1a2b4c
Create Date: 2026-05-13
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "8e2a5c1f4d09"
down_revision: str | None = "7d3f8e1a2b4c"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "alerts",
        sa.Column("dedup_key", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "alerts",
        sa.Column(
            "occurrence_count",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
    )
    op.add_column(
        "alerts",
        sa.Column(
            "last_occurred_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index(
        "ix_alerts_dedup_key",
        "alerts",
        ["dedup_key"],
        unique=False,
    )
    op.create_index(
        "ix_alerts_last_occurred_at",
        "alerts",
        ["last_occurred_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_alerts_last_occurred_at", table_name="alerts")
    op.drop_index("ix_alerts_dedup_key", table_name="alerts")
    op.drop_column("alerts", "last_occurred_at")
    op.drop_column("alerts", "occurrence_count")
    op.drop_column("alerts", "dedup_key")
