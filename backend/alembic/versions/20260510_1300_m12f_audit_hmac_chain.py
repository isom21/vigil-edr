"""M12.f: audit_log HMAC chain columns

Adds tamper-evidence to the existing append-only audit log: every
new row carries an HMAC of (prev_row_hmac || canonical_payload),
keyed off VIGIL_AUDIT_HMAC_KEY. A periodic verifier walks the chain
and reports breaks — the only ways a chain breaks are:

  * A row was UPDATEd (which the M16.a INSERT-only privileges
    already deny via REVOKE, but a sufficiently privileged
    attacker — or a misconfigured DB role — could bypass).
  * A row was DELETEd (same).
  * A row was INSERTed at the wrong sequence position (i.e.
    smuggling in a forged history before the next legit write).

`seq` is BIGSERIAL so verification is total-order independent of
clock drift / NTP jumps. `prev_hmac` and `row_hmac` are nullable
because rows written before this migration have no HMAC — the
verifier treats those rows as the pre-chain era and starts the
chain at the first row where row_hmac IS NOT NULL.

Revision ID: 9b5f3e7c1d82
Revises: 8a4f2d6e0b71
Create Date: 2026-05-10
"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "9b5f3e7c1d82"
down_revision: str | None = "8a4f2d6e0b71"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "audit_log",
        sa.Column("seq", sa.BigInteger(), nullable=True),
    )
    # The sequence backs the seq column. We DON'T attach it as the
    # column default at the SQLAlchemy layer (the audit service
    # writes the value explicitly via the chain head select-for-update
    # path) because we want strict serialization with the HMAC
    # computation.
    op.execute("CREATE SEQUENCE IF NOT EXISTS audit_log_seq")
    op.execute(
        "ALTER TABLE audit_log ALTER COLUMN seq SET DEFAULT nextval('audit_log_seq')"
    )
    # Backfill: assign sequence values to existing rows in ts order so
    # the chain has a sane base. Existing rows still won't have HMAC
    # values — the verifier treats those as the pre-chain era.
    op.execute(
        """
        WITH ordered AS (
            SELECT id, row_number() OVER (ORDER BY ts, id) AS rn
            FROM audit_log
            WHERE seq IS NULL
        )
        UPDATE audit_log a
        SET seq = o.rn
        FROM ordered o
        WHERE a.id = o.id
        """
    )
    op.execute(
        "SELECT setval('audit_log_seq', COALESCE((SELECT MAX(seq) FROM audit_log), 0) + 1, false)"
    )
    op.alter_column("audit_log", "seq", nullable=False)
    op.create_unique_constraint("uq_audit_log_seq", "audit_log", ["seq"])
    op.create_index("ix_audit_log_seq", "audit_log", ["seq"], unique=True)

    op.add_column(
        "audit_log",
        sa.Column("prev_hmac", sa.LargeBinary(length=32), nullable=True),
    )
    op.add_column(
        "audit_log",
        sa.Column("row_hmac", sa.LargeBinary(length=32), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("audit_log", "row_hmac")
    op.drop_column("audit_log", "prev_hmac")
    op.drop_index("ix_audit_log_seq", table_name="audit_log")
    op.drop_constraint("uq_audit_log_seq", "audit_log", type_="unique")
    op.alter_column("audit_log", "seq", server_default=None)
    op.drop_column("audit_log", "seq")
    op.execute("DROP SEQUENCE IF EXISTS audit_log_seq")
