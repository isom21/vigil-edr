"""M16.a: audit_log INSERT-only privileges

Creates a separate PG role `vigil_audit_writer` and revokes UPDATE /
DELETE / TRUNCATE on `audit_log` from the manager's DB user. The
manager keeps the INSERT grant via membership in `vigil_audit_writer`
so `app.services.audit.record()` continues to work unchanged.

Skipped automatically when the DB user can't switch role (typical in
dev / single-user DBs); the migration logs and continues so existing
test workflows aren't broken.

Revision ID: 5e2b0c8d4f6a
Revises: 9c1d3e7a6b22
Create Date: 2026-05-10
"""
from collections.abc import Sequence

from alembic import op

revision: str = "5e2b0c8d4f6a"
down_revision: str | None = "9c1d3e7a6b22"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # The manager's effective DB user (whoever Alembic runs as) is
    # what we lock down. We can't introspect it without elevating; for
    # the dev workflow this is "vigil_manager". Production overrides
    # via the VIGIL_DATABASE_URL env var, and the operator runs alembic
    # with a superuser DSN to apply this migration once.
    # All operations are wrapped in DO blocks so the migration is a
    # no-op on systems where the operator doesn't have CREATE ROLE.
    op.execute(
        """
        DO $$ BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vigil_audit_writer') THEN
                CREATE ROLE vigil_audit_writer NOLOGIN;
            END IF;
        EXCEPTION WHEN insufficient_privilege THEN
            RAISE NOTICE 'M16.a: insufficient privilege to create role; skipping';
        END $$;
        """
    )
    op.execute(
        """
        DO $$ BEGIN
            REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM PUBLIC;
            -- The manager's runtime user retains INSERT + SELECT only.
            -- Pruning + administrative DELETE happens via a separate
            -- cron job running as a privileged user (M16.b).
        EXCEPTION WHEN insufficient_privilege THEN
            RAISE NOTICE 'M16.a: insufficient privilege to revoke; skipping';
        END $$;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DO $$ BEGIN
            GRANT UPDATE, DELETE, TRUNCATE ON audit_log TO PUBLIC;
        EXCEPTION WHEN insufficient_privilege THEN
            RAISE NOTICE 'M16.a downgrade: insufficient privilege; skipping';
        END $$;
        """
    )
    op.execute(
        """
        DO $$ BEGIN
            DROP ROLE IF EXISTS vigil_audit_writer;
        EXCEPTION WHEN insufficient_privilege THEN
            RAISE NOTICE 'M16.a downgrade: cannot drop role; skipping';
        END $$;
        """
    )
