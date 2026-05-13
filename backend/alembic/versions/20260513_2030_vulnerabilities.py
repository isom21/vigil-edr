"""Vulnerability assessment (Phase 2 #2.7).

NVD-driven vulnerability inventory. Three tables:

  * `vulnerability`: master catalog of CVEs ingested from the NVD 2.0
    API. Primary key is the CVE id text. CVSS v3 score lives in a
    `numeric(3,1)` column so an analyst sort by severity matches the
    arithmetic ordering rather than the lexicographic ordering of the
    severity label. `references_json` + `affected_cpe_json` hold the
    NVD-shaped sub-objects untouched so the UI can show what NVD
    publishes without us re-modelling everything ahead of need.

  * `host_software`: agent-reported installed package inventory. One
    row per (host, package, version) triple. The agent emits these as
    `INSTALLED_SOFTWARE` job artifacts (read from
    `artifact_metadata.packages` — no MinIO download). `cpe` is
    nullable because vendor / version → CPE resolution isn't always
    possible at agent time; the scanner backfills when NVD's affected
    list yields a unique match. The (host_id, cpe) index supports the
    scanner's "what's installed on this host that matches CVE X?"
    pivot.

  * `host_vulnerability`: the materialised join. One row per
    (host, CVE) match. Unique on the same pair so the scanner can
    INSERT … ON CONFLICT DO UPDATE the `last_seen` timestamp without
    accidentally creating duplicates. `suppressed` is an admin-only
    flag that hides the row from the default alert/list view without
    deleting the evidence — the audit trail captures who and when.

Revision ID: d4d5e6f7a8b9
Revises: d8b9c0d1e2f3
Create Date: 2026-05-13
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "d4d5e6f7a8b9"
down_revision: str | None = "d8b9c0d1e2f3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "vulnerability",
        sa.Column("cve_id", sa.Text(), primary_key=True),
        sa.Column("severity", sa.Text(), nullable=True),
        sa.Column("cvss_v3_score", sa.Numeric(3, 1), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column(
            "references_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "affected_cpe_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index("ix_vulnerability_severity", "vulnerability", ["severity"])
    op.create_index("ix_vulnerability_cvss_v3_score", "vulnerability", ["cvss_v3_score"])
    op.create_index("ix_vulnerability_modified_at", "vulnerability", ["modified_at"])

    op.create_table(
        "host_software",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("host_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("version", sa.Text(), nullable=False),
        sa.Column("vendor", sa.Text(), nullable=True),
        sa.Column("cpe", sa.Text(), nullable=True),
        sa.Column(
            "first_seen",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "last_seen",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(
            ["host_id"],
            ["hosts.id"],
            ondelete="CASCADE",
            name="fk_host_software_host_id_hosts",
        ),
    )
    op.create_index("ix_host_software_host_id_cpe", "host_software", ["host_id", "cpe"])
    op.create_index("ix_host_software_host_id", "host_software", ["host_id"])
    # Idempotent ingest: the scanner upserts per (host_id, name, version);
    # without this constraint a re-pull would duplicate rows.
    op.create_unique_constraint(
        "uq_host_software_host_id_name_version",
        "host_software",
        ["host_id", "name", "version"],
    )

    op.create_table(
        "host_vulnerability",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("host_id", sa.Uuid(), nullable=False),
        sa.Column("cve_id", sa.Text(), nullable=False),
        sa.Column("cpe", sa.Text(), nullable=True),
        sa.Column(
            "first_seen",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "last_seen",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "suppressed",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("suppressed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("suppressed_by_user_id", sa.Uuid(), nullable=True),
        sa.ForeignKeyConstraint(
            ["host_id"],
            ["hosts.id"],
            ondelete="CASCADE",
            name="fk_host_vulnerability_host_id_hosts",
        ),
        sa.ForeignKeyConstraint(
            ["cve_id"],
            ["vulnerability.cve_id"],
            ondelete="CASCADE",
            name="fk_host_vulnerability_cve_id_vulnerability",
        ),
        sa.ForeignKeyConstraint(
            ["suppressed_by_user_id"],
            ["users.id"],
            ondelete="SET NULL",
            name="fk_host_vulnerability_suppressed_by_user_id_users",
        ),
        sa.UniqueConstraint("host_id", "cve_id", name="uq_host_vulnerability_host_id_cve_id"),
    )
    op.create_index("ix_host_vulnerability_host_id", "host_vulnerability", ["host_id"])
    op.create_index("ix_host_vulnerability_cve_id", "host_vulnerability", ["cve_id"])
    op.create_index("ix_host_vulnerability_suppressed", "host_vulnerability", ["suppressed"])


def downgrade() -> None:
    op.drop_index("ix_host_vulnerability_suppressed", table_name="host_vulnerability")
    op.drop_index("ix_host_vulnerability_cve_id", table_name="host_vulnerability")
    op.drop_index("ix_host_vulnerability_host_id", table_name="host_vulnerability")
    op.drop_table("host_vulnerability")

    op.drop_constraint("uq_host_software_host_id_name_version", "host_software", type_="unique")
    op.drop_index("ix_host_software_host_id", table_name="host_software")
    op.drop_index("ix_host_software_host_id_cpe", table_name="host_software")
    op.drop_table("host_software")

    op.drop_index("ix_vulnerability_modified_at", table_name="vulnerability")
    op.drop_index("ix_vulnerability_cvss_v3_score", table_name="vulnerability")
    op.drop_index("ix_vulnerability_severity", table_name="vulnerability")
    op.drop_table("vulnerability")
