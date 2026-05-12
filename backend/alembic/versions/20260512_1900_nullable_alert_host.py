"""Make alerts.host_id nullable for synthetic system alerts.

Audit-chain-break alerts (M-audit-and-auth #6, rule
`a0a0a0a0-0000-0000-0000-000000000006`) and similar manager-internal
detections don't belong to any host. The verifier loop previously
papered over the NOT NULL with a "first host we find" fallback, then
a log-line if the fleet had no hosts yet; both shapes are wrong —
the alert is about the manager, not whichever host happened to be
listed.

Drop the NOT NULL so synthetic alerts can be inserted with
`host_id=NULL`. Non-admin RBAC scoping already filters via
`apply_host_scope`'s `host_column.in_(visible)` which excludes NULL
in SQL, so analysts won't see system alerts they shouldn't. Admin
endpoints switch the INNER JOIN on `hosts` to LEFT OUTER JOIN so
null-host rows still come back.

Revision ID: 2a8c3f7b1e9d
Revises: f1a2b3c4d5e6
Create Date: 2026-05-12
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "2a8c3f7b1e9d"
down_revision: str | None = "f1a2b3c4d5e6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column("alerts", "host_id", nullable=True)


def downgrade() -> None:
    # If any synthetic alerts exist with host_id IS NULL, downgrade
    # will fail until they're deleted; that's intentional — silently
    # dropping rows here would be worse.
    op.alter_column("alerts", "host_id", nullable=False)
