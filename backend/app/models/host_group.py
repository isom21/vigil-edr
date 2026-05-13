"""Host groups (M7.5 RBAC).

A `HostGroup` is a labelled collection of hosts. Users can be assigned
to one or more groups, which scopes their visibility into hosts /
alerts / commands. Admins implicitly see all groups.

The two many-to-many association tables are plain SQL (no models) since
their only purpose is to express membership.
"""

from __future__ import annotations

import uuid

from sqlalchemy import Column, ForeignKey, String, Table
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UuidPkMixin
from app.models.tenant import DEFAULT_TENANT_ID

# user <-> host group: M:N
user_host_group = Table(
    "user_host_group",
    Base.metadata,
    Column("user_id", ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("host_group_id", ForeignKey("host_groups.id", ondelete="CASCADE"), primary_key=True),
)

# host <-> host group: M:N
host_in_group = Table(
    "host_in_group",
    Base.metadata,
    Column("host_id", ForeignKey("hosts.id", ondelete="CASCADE"), primary_key=True),
    Column("host_group_id", ForeignKey("host_groups.id", ondelete="CASCADE"), primary_key=True),
)


class HostGroup(UuidPkMixin, TimestampMixin, Base):
    """Named bucket of hosts for RBAC scoping."""

    __tablename__ = "host_groups"

    # Phase 3 #3.1: tenant scoping. Defaults to the seeded default
    # tenant so existing fixtures + bootstrap flows that don't pass
    # tenant_id keep working unchanged.
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenant.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
    )

    name: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(512))
