"""intel_feeds + ioc_entries.source_id (Phase 1 #1.9 threat-intel ingest).

Adds the table the periodic ingest worker pulls from + a back-pointer
on `ioc_entries` to the originating feed so a feed deletion (and a
subsequent re-ingest with a different set of indicators) can diff
old-vs-new at the row level rather than wiping every IOC under the
managed rule blind.

Shape:
  * `intel_feeds.kind`: enum taxii | abusech_csv | custom_json. New
    pluggable puller is registered server-side; the column gates which
    one runs.
  * `intel_feeds.encrypted_auth`: Fernet ciphertext bytes. Holds either
    a TAXII basic-auth token or a custom_json Authorization header
    value; NULL for anonymous feeds (abuse.ch's public urlhaus dump
    is the canonical example).
  * `intel_feeds.managed_rule_id`: FK to `rules.id`. One Rule per feed
    (kind=ioc, name="intel:<feed_name>"). Created lazily by the worker
    on first successful pull so a feed row that never makes its first
    cycle (bad URL, etc.) doesn't pollute the rules list.
  * `ioc_entries.source_id`: nullable FK back to `intel_feeds.id`. NULL
    rows are operator-entered IOCs (the existing path); non-NULL rows
    are feed-materialised. ON DELETE SET NULL so deleting the feed
    leaves a paper trail (the entries vanish via the managed-Rule
    cascade, but if the operator manually re-parents an entry to a
    different rule before deleting the feed the source attribution
    survives as NULL).

Revision ID: a83f1c4e6d72
Revises: 7d3f8e1a2b4c
Create Date: 2026-05-13
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "a83f1c4e6d72"
down_revision: str | None = "9a4f3b2c7d18"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Enum type holding the puller-kind values. `create_type=True` here
    # — first appearance of the type in the schema.
    intel_feed_kind = sa.Enum(
        "taxii",
        "abusech_csv",
        "custom_json",
        name="intel_feed_kind",
        create_type=True,
    )

    op.create_table(
        "intel_feeds",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("kind", intel_feed_kind, nullable=False),
        sa.Column("url", sa.String(2048), nullable=False),
        # Fernet ciphertext bytes. NULL = anonymous pull.
        sa.Column("encrypted_auth", sa.LargeBinary(), nullable=True),
        # Per-feed pull cadence (seconds). Worker's outer loop runs at
        # VIGIL_INTEL_INGEST_INTERVAL_S and checks each row's
        # interval_s + last_pulled_at to decide whether THIS row is due.
        sa.Column(
            "interval_s",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("3600"),
        ),
        sa.Column("last_pulled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "entry_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column(
            "enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.true(),
        ),
        sa.Column("managed_rule_id", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_unique_constraint("uq_intel_feeds_name", "intel_feeds", ["name"])
    op.create_foreign_key(
        "fk_intel_feeds_managed_rule_id_rules",
        "intel_feeds",
        "rules",
        ["managed_rule_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_intel_feeds_enabled", "intel_feeds", ["enabled"])

    op.add_column(
        "ioc_entries",
        sa.Column("source_id", sa.Uuid(), nullable=True),
    )
    op.create_foreign_key(
        "fk_ioc_entries_source_id_intel_feeds",
        "ioc_entries",
        "intel_feeds",
        ["source_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_ioc_entries_source_id", "ioc_entries", ["source_id"])


def downgrade() -> None:
    op.drop_index("ix_ioc_entries_source_id", table_name="ioc_entries")
    op.drop_constraint(
        "fk_ioc_entries_source_id_intel_feeds",
        "ioc_entries",
        type_="foreignkey",
    )
    op.drop_column("ioc_entries", "source_id")

    op.drop_index("ix_intel_feeds_enabled", table_name="intel_feeds")
    op.drop_constraint(
        "fk_intel_feeds_managed_rule_id_rules",
        "intel_feeds",
        type_="foreignkey",
    )
    op.drop_constraint("uq_intel_feeds_name", "intel_feeds", type_="unique")
    op.drop_table("intel_feeds")
    sa.Enum(name="intel_feed_kind").drop(op.get_bind(), checkfirst=False)
