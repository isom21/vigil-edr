"""Tenant — schema-level multi-tenancy (Phase 3 #3.1).

A Tenant is the top-level isolation boundary. Every domain row
(hosts, alerts, rules, jobs, incidents, audit entries…) carries a
``tenant_id`` FK so the same manager can serve multiple SOCs without
cross-tenant data leakage. Single-tenant deployments transparently
keep working: the migration backfills existing rows to the seeded
``default`` tenant (UUID
``00000000-0000-0000-0000-000000000001``) and every domain model
defaults a freshly-constructed row to the same ID, so test fixtures
and call sites that pre-date this work don't need to change.

The audit chain (M12.f) is keyed per-tenant: each tenant's HMAC
chain has its own genesis row and is verified independently, so a
break in one tenant cannot taint another's tamper-evidence story.

The ``slug`` is the operator-visible short name (e.g. ``acme-corp``,
``default``) — used in URLs, audit payloads, and the tenant
switcher. ``name`` is the human-readable display string.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import Boolean, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UuidPkMixin

# The fixed UUID for the seeded default tenant. Every pre-existing row
# is backfilled to this value, and every domain model uses it as its
# server- and Python-side default — so single-tenant deployments and
# existing tests don't have to thread tenant_id through every call
# site. Don't change this constant: rotating it would orphan every
# backfilled row.
DEFAULT_TENANT_ID: UUID = UUID("00000000-0000-0000-0000-000000000001")


class Tenant(UuidPkMixin, TimestampMixin, Base):
    __tablename__ = "tenant"

    # URL-safe short name. Unique across the whole installation; the
    # tenant switcher in the UI lists tenants by slug.
    slug: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    # Human-readable display name. Not unique — two SOCs can both call
    # themselves "Security Operations" but only one of them gets
    # ``security-operations`` as a slug.
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # Soft-disable. Disabled tenants still exist (their data is
    # untouched) but no token issued against them validates and the
    # tenant switcher hides them unless the operator explicitly toggles
    # "show disabled".
    disabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
