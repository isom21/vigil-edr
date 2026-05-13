"""Schema-level multi-tenancy (Phase 3 #3.1).

Adds the ``tenant`` table + a ``tenant_id`` column on every domain
table. Seeds a single ``default`` tenant with a fixed UUID so
existing single-tenant deployments transparently keep working: the
backfill points every pre-existing row at the seeded tenant via the
column DEFAULT, and that DEFAULT is then dropped so application
code must set ``tenant_id`` explicitly on new rows. (Without that
drop the FK would silently mask "forgot to scope" bugs.)

Composite indexes mirror the query shapes the app code uses today —
admin lists tend to filter on ``(tenant_id, status_column, ts desc)``,
so the new indexes lead with ``tenant_id`` for cardinality and add
the secondary keys for the existing UI sorts.

The audit chain (M12.f) becomes per-tenant in this migration too —
the new ``(tenant_id, prev_hash)`` index supports the verifier's
per-tenant walk. We don't reseed existing chain rows: they were all
written under the default tenant and the chain stays continuous
because every row already carries the default UUID after backfill.

Revision ID: e1a2b3c4d5e6
Revises: e4d5e6f7a8b9
Create Date: 2026-05-13
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e1a2b3c4d5e6"
down_revision: str | None = "e4d5e6f7a8b9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# The seeded default tenant UUID — duplicated as a string literal here
# so the migration is self-contained (alembic env can't import app
# code during downgrade without a working DB). Must match
# ``app.models.tenant.DEFAULT_TENANT_ID``.
DEFAULT_TENANT_ID_SQL: str = "00000000-0000-0000-0000-000000000001"

# Tables that get a tenant_id column. Order is independent — the
# column add is idempotent, no FKs between siblings, all reference
# `tenant.id`. Listed roughly by feature area so review can match
# the spec.
#
# `is_super_admin` lives on `users` and is added separately below
# (it's not a tenant_id column, but adding it in the same migration
# keeps the multi-tenancy patch a single revision step).
TENANTED_TABLES: list[str] = [
    # Identity / auth
    "users",
    "api_tokens",
    "enrollment_tokens",
    "certificate_authority",
    # Fleet
    "hosts",
    "host_groups",
    # Detection
    "rules",
    "rule_groups",
    "ioc_entries",
    "sequence_rules",
    "intel_feeds",
    "saved_hunt",
    "hunt_run",
    "policies",
    # Triage
    "alerts",
    "alert_state_history",
    "incidents",
    "commands",
    "jobs",
    "job_runs",
    "job_artifacts",
    "quarantined_files",
    # Behavior / store
    "process_baseline",
    "process_chain",
    "allowlist_mode",
    "allowlist_entry",
    "dns_block_entry",
    # Ops
    "notification_channels",
    "routing_rules",
    "siem_destinations",
    # Vulnerability assessment
    "vulnerability",
    "host_software",
    "host_vulnerability",
    # Audit chain — per-tenant
    "audit_log",
]


def upgrade() -> None:
    # ---- tenant table + seed -------------------------------------------------
    op.create_table(
        "tenant",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("slug", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column(
            "disabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_tenant"),
        sa.UniqueConstraint("slug", name="uq_tenant_slug"),
    )
    op.create_index("ix_tenant_slug", "tenant", ["slug"], unique=True)

    # Seed the default tenant before any FK references it. Idempotent —
    # if a previous migration attempt half-applied, the slug uniqueness
    # constraint forces a single row.
    op.execute(
        sa.text(
            f"INSERT INTO tenant (id, slug, name, disabled) "
            f"VALUES ('{DEFAULT_TENANT_ID_SQL}'::uuid, 'default', 'Default tenant', FALSE) "
            f"ON CONFLICT (id) DO NOTHING"
        )
    )

    # ---- per-table tenant_id column + FK + index -----------------------------
    for table in TENANTED_TABLES:
        # The server_default carries the default tenant id long enough
        # for the backfill — any rows already in the table on
        # upgrade-from-d5e6f7a8b9c0 land on the default tenant. We drop
        # the default at the end so new INSERTs must specify tenant_id.
        op.add_column(
            table,
            sa.Column(
                "tenant_id",
                sa.Uuid(),
                nullable=False,
                server_default=sa.text(f"'{DEFAULT_TENANT_ID_SQL}'::uuid"),
            ),
        )
        op.create_foreign_key(
            f"fk_{table}_tenant_id_tenant",
            table,
            "tenant",
            ["tenant_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        op.create_index(
            f"ix_{table}_tenant_id",
            table,
            ["tenant_id"],
            unique=False,
        )

    # ---- composite indexes for the hot query shapes --------------------------
    # Common filter pattern is `tenant_id` first, then the existing
    # status / time fields the UI sorts by. Where an existing index
    # already covered the secondary column (e.g. `ix_alerts_state`)
    # we leave it — Postgres uses the new composite for cross-tenant
    # filters and the old one for tenant-blind admin tooling.
    op.create_index(
        "ix_alerts_tenant_state_opened",
        "alerts",
        ["tenant_id", "state", sa.text("opened_at DESC")],
    )
    op.create_index(
        "ix_commands_tenant_status",
        "commands",
        ["tenant_id", "status"],
    )
    op.create_index(
        "ix_jobs_tenant_status",
        "jobs",
        ["tenant_id", "status"],
    )
    op.create_index(
        "ix_incidents_tenant_status_opened",
        "incidents",
        ["tenant_id", "status", sa.text("opened_at DESC")],
    )
    op.create_index(
        "ix_audit_log_tenant_prev_hmac",
        "audit_log",
        ["tenant_id", "prev_hmac"],
    )
    op.create_index(
        "ix_audit_log_tenant_seq",
        "audit_log",
        ["tenant_id", "seq"],
    )

    # ---- is_super_admin on users --------------------------------------------
    op.add_column(
        "users",
        sa.Column(
            "is_super_admin",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )

    # ---- drop server defaults so app code must set tenant_id ---------------
    # The backfill happened implicitly via the DEFAULT during ADD
    # COLUMN. Dropping the default now turns a "forgot to scope"
    # INSERT into a NOT NULL violation in tests rather than a silent
    # write to the wrong tenant in prod.
    for table in TENANTED_TABLES:
        op.alter_column(table, "tenant_id", server_default=None)


def downgrade() -> None:
    # Drop composite indexes first.
    op.drop_index("ix_audit_log_tenant_seq", table_name="audit_log")
    op.drop_index("ix_audit_log_tenant_prev_hmac", table_name="audit_log")
    op.drop_index("ix_incidents_tenant_status_opened", table_name="incidents")
    op.drop_index("ix_jobs_tenant_status", table_name="jobs")
    op.drop_index("ix_commands_tenant_status", table_name="commands")
    op.drop_index("ix_alerts_tenant_state_opened", table_name="alerts")

    # Drop is_super_admin.
    op.drop_column("users", "is_super_admin")

    # Per-table teardown.
    for table in reversed(TENANTED_TABLES):
        op.drop_index(f"ix_{table}_tenant_id", table_name=table)
        op.drop_constraint(f"fk_{table}_tenant_id_tenant", table, type_="foreignkey")
        op.drop_column(table, "tenant_id")

    op.drop_index("ix_tenant_slug", table_name="tenant")
    op.drop_table("tenant")
