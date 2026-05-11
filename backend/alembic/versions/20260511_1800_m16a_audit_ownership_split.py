"""M16.a (fixed): audit_log ownership split — real INSERT-only at DB role level.

The original M16.a (revision ``5e2b0c8d4f6a``) revoked UPDATE / DELETE /
TRUNCATE from PUBLIC. Two problems made this a no-op:

  1. PostgreSQL does not apply ``REVOKE … FROM PUBLIC`` to the table
     owner. The runtime user ``edr`` owned ``audit_log`` and kept full
     write rights.
  2. The dev docker-compose used to initialise Postgres with
     ``POSTGRES_USER: edr``, which made ``edr`` the bootstrap superuser.
     Superusers bypass GRANT / REVOKE checks entirely, so GRANT-based
     hardening against ``edr`` was invisible. The bootstrap superuser
     can't be demoted (`ALTER ROLE … NOSUPERUSER` refuses), so the dev
     compose now bootstraps with ``postgres`` and an init script
     creates ``edr`` as a non-superuser owner of the ``edr`` database.
     See ``deploy/postgres-init.sql`` and ``docs/install.md``.

With ``edr`` no longer a superuser, ownership transfer + GRANT/REVOKE
on ``audit_log`` actually take effect.

This migration:
  * Creates a dedicated ``vigil_audit_writer`` LOGIN role.
  * Transfers ``audit_log`` and ``audit_log_seq`` ownership to it.
  * Drops UPDATE / DELETE / TRUNCATE from ``edr`` and leaves only
    SELECT + INSERT on the table, USAGE + SELECT on the sequence.

After this migration, ``UPDATE`` / ``DELETE`` / ``TRUNCATE`` on
``audit_log`` from the manager's runtime pool raise
``InsufficientPrivilege``. A separate pruning worker (M16.b, not yet
built) will connect as ``vigil_audit_writer`` and is the only path
to deleting rows.

Prereqs to apply this migration:
  - The DB user running Alembic must have CREATEROLE (``edr`` does in
    dev) and must currently own ``audit_log`` (``edr`` does).
  - ``VIGIL_AUDIT_OWNER_PASSWORD`` must be set in the migration env.
    install.sh writes this during bootstrap; production operators
    provision it through their secrets manager.

After this migration, future schema changes on ``audit_log`` itself
must be applied through a connection with sufficient privilege —
typically by setting ``VIGIL_PG_DSN`` to the writer's DSN for that
Alembic run.

The chain verifier (``app.services.audit_verifier``) reads via
``VIGIL_PG_DSN_AUDIT`` (the writer DSN) so its connection pool stays
isolated from the runtime pool.

Revision ID: c41d5b7e9f02
Revises: c7a3f4e92b18
Create Date: 2026-05-11
"""

from __future__ import annotations

import os
from collections.abc import Sequence

from alembic import op

revision: str = "c41d5b7e9f02"
down_revision: str | None = "c7a3f4e92b18"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_PASSWORD_ENV = "VIGIL_AUDIT_OWNER_PASSWORD"


def _writer_password() -> str:
    pw = os.environ.get(_PASSWORD_ENV)
    if not pw:
        raise RuntimeError(
            f"{_PASSWORD_ENV} not set. install.sh writes it during bootstrap; "
            "production operators must supply it via their secrets manager "
            "before running this migration."
        )
    # PG quoted identifiers can't contain a literal single quote unless
    # escaped. Reject anything ambiguous rather than guess at the
    # escape rules.
    if "'" in pw or "\\" in pw:
        raise RuntimeError(
            f"{_PASSWORD_ENV} contains a single quote or backslash; choose "
            "a password without either character."
        )
    return pw


def upgrade() -> None:
    password = _writer_password()

    # Provision the role. Idempotent so re-running on a partial apply
    # doesn't fail. LOGIN because Alembic + the verifier connect as
    # this role; password rotation goes through ALTER ROLE on
    # subsequent runs.
    op.execute(
        f"""
        DO $do$ BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vigil_audit_writer') THEN
                CREATE ROLE vigil_audit_writer LOGIN PASSWORD '{password}';
            ELSE
                ALTER ROLE vigil_audit_writer LOGIN PASSWORD '{password}';
            END IF;
        END $do$;
        """
    )

    # The current owner (edr) must be a member of the new owner role
    # to transfer ownership. Grant the membership, do the transfer,
    # then revoke — the runtime user must not retain a path back to
    # full rights via SET ROLE.
    op.execute("GRANT vigil_audit_writer TO edr;")
    # PG also requires the new owner to hold CREATE on the containing
    # schema before ALTER TABLE ... OWNER TO will accept it ("the new
    # owner must be able to own objects in the schema"). USAGE pairs
    # so the writer can look up audit_log by name without further
    # grants. The schema's owner is `pg_database_owner` (effectively
    # edr in dev), so edr is allowed to grant on it.
    op.execute("GRANT USAGE, CREATE ON SCHEMA public TO vigil_audit_writer;")
    op.execute("ALTER TABLE audit_log OWNER TO vigil_audit_writer;")
    op.execute("ALTER SEQUENCE audit_log_seq OWNER TO vigil_audit_writer;")

    # Lock down the runtime user. After the OWNER TO transfer, only
    # the new owner (vigil_audit_writer) can REVOKE/GRANT on the
    # table — `edr` doesn't own it any more. `edr` is still a member
    # of `vigil_audit_writer` at this point (we revoke that membership
    # last), so SET LOCAL ROLE switches the session and the next
    # REVOKE/GRANT statements execute as the owner. RESET ROLE drops
    # back to edr before the final REVOKE membership step.
    op.execute("SET LOCAL ROLE vigil_audit_writer;")
    op.execute("REVOKE ALL ON audit_log FROM edr;")
    op.execute("GRANT SELECT, INSERT ON audit_log TO edr;")
    op.execute("GRANT USAGE, SELECT ON SEQUENCE audit_log_seq TO edr;")
    op.execute("RESET ROLE;")

    # Drop the temporary membership so the runtime user has no
    # `SET ROLE vigil_audit_writer` path back to full rights.
    op.execute("REVOKE vigil_audit_writer FROM edr;")


def downgrade() -> None:
    # Return ownership to edr and restore full rights. The role is
    # left in place because dropping it would require nulling out any
    # objects it still owns; the operator can drop manually if they
    # really want to remove the trace.
    op.execute("GRANT vigil_audit_writer TO edr;")
    op.execute("SET LOCAL ROLE vigil_audit_writer;")
    op.execute("ALTER TABLE audit_log OWNER TO edr;")
    op.execute("ALTER SEQUENCE audit_log_seq OWNER TO edr;")
    op.execute("RESET ROLE;")
    op.execute("GRANT ALL ON audit_log TO edr;")
    op.execute("GRANT ALL ON SEQUENCE audit_log_seq TO edr;")
    op.execute("REVOKE ALL ON SCHEMA public FROM vigil_audit_writer;")
    op.execute("REVOKE vigil_audit_writer FROM edr;")
