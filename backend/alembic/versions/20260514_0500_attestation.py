"""Hardware-backed boot-state attestation (Phase 4 #4.10).

Adds the two tables that back the TPM attestation feature plus the
``request_attestation`` enum value for `command_kind`.

  * ``attestation_golden`` — one row per host. Holds the promoted PCR
    set (JSONB list of ``{index, bank, digest_hex}`` triples) and the
    SHA-256 fingerprint of the AK certificate that signed the quote
    when the operator promoted. ``host_id`` is the primary key so
    each host has at most one golden baseline; re-promoting overwrites.
  * ``attestation_event`` — append-only history of every quote / report
    the manager received. ``matches_golden`` is computed at insert
    time so the host detail endpoint can render status without
    re-running the PCR diff. ``diverged_pcrs`` is the set of PCR
    indices that differed from the golden baseline (empty array on
    a clean match, the full set on the first-ever report before any
    golden is promoted).

The ``ALTER TYPE command_kind ADD VALUE IF NOT EXISTS 'request_attestation'``
uses the same standalone-statement pattern as the DNS block + device
control migrations. Postgres has no ``DROP VALUE`` for enums so the
downgrade leaves it in place — safe because nothing references it
after the rest of the schema rolls back.

Revision ID: f6f7a8b9c0d1
Revises: f2b3c4d5e6f7
Create Date: 2026-05-14
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "f6f7a8b9c0d1"
down_revision: str | None = "f2b3c4d5e6f7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "attestation_golden",
        sa.Column("host_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column(
            "pcr_values_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("ak_cert_fingerprint", sa.Text(), nullable=True),
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("recorded_by_user_id", sa.Uuid(), nullable=True),
        sa.ForeignKeyConstraint(
            ["host_id"],
            ["hosts.id"],
            ondelete="CASCADE",
            name="fk_attestation_golden_host_id_hosts",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenant.id"],
            ondelete="RESTRICT",
            name="fk_attestation_golden_tenant_id_tenant",
        ),
        sa.ForeignKeyConstraint(
            ["recorded_by_user_id"],
            ["users.id"],
            ondelete="SET NULL",
            name="fk_attestation_golden_user_id_users",
        ),
        sa.PrimaryKeyConstraint("host_id", name="pk_attestation_golden"),
    )

    op.create_table(
        "attestation_event",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("host_id", sa.Uuid(), nullable=False),
        sa.Column(
            "pcr_values_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("matches_golden", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "diverged_pcrs",
            postgresql.ARRAY(sa.Integer()),
            nullable=False,
            server_default=sa.text("'{}'::int[]"),
        ),
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["host_id"],
            ["hosts.id"],
            ondelete="CASCADE",
            name="fk_attestation_event_host_id_hosts",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenant.id"],
            ondelete="RESTRICT",
            name="fk_attestation_event_tenant_id_tenant",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_attestation_event"),
    )
    op.create_index(
        "ix_attestation_event_host_recorded",
        "attestation_event",
        ["host_id", sa.text("recorded_at DESC")],
        unique=False,
    )

    op.execute("ALTER TYPE command_kind ADD VALUE IF NOT EXISTS 'request_attestation'")


def downgrade() -> None:
    op.drop_index("ix_attestation_event_host_recorded", table_name="attestation_event")
    op.drop_table("attestation_event")
    op.drop_table("attestation_golden")
    # Postgres has no `ALTER TYPE ... DROP VALUE`. The enum value stays
    # in place; nothing references it after the tables drop.
