"""In-memory host metadata cache for normalizer + alert-factory enrichment.

Agents include only `host.id` (UUID) on every event, not the hostname or
OS family — those are sent once via the Hello message at connect time
and stored on the Host row in PG.

To make telemetry docs immediately useful in OpenSearch (so analysts can
search by hostname), the normalizer worker injects host.hostname and
host.os on every doc by reading from PG. We cache lookups for ~60s
since hostnames change rarely; on cache miss we hit the DB once.

Phase 3 #3.6 (CODE-22, CODE-23, CODE-24): the cache also returns the
host's tenant_id. The normalizer stamps `tenant.id` on every ECS doc so
hunt + sigma queries can filter cross-tenant traffic, and every alert
factory looks up the host's tenant_id before constructing the Alert row
(without this every alert lands on DEFAULT_TENANT_ID — the
SQLAlchemy column default — regardless of which tenant the host
belongs to).

Cache miss has zero impact on doc shape — we just emit the doc without
the hostname / tenant.id fields. The indexer mapping treats both as
nullable.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING
from uuid import UUID

from app.core.db import SessionLocal
from app.models import Host

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

# Single in-process cache. Each entry is (hostname, os_family, tenant_id, expires_at).
_CACHE: dict[UUID, tuple[str | None, str | None, UUID | None, float]] = {}
_TTL_S = 60.0


async def host_meta_for(host_id: UUID) -> tuple[str | None, str | None, UUID | None]:
    """Return (hostname, os_family, tenant_id) for a host_id; Nones if unknown.

    Cached for ~60s. On miss, opens a fresh AsyncSession for one query.
    """
    now = time.monotonic()
    entry = _CACHE.get(host_id)
    if entry is not None and entry[3] > now:
        return entry[0], entry[1], entry[2]

    async with SessionLocal() as db:
        h = await db.get(Host, host_id)

    hostname = h.hostname if h else None
    os_family = h.os_family.value if h else None
    tenant_id = h.tenant_id if h else None
    _CACHE[host_id] = (hostname, os_family, tenant_id, now + _TTL_S)
    return hostname, os_family, tenant_id


async def hostname_for(host_id: UUID) -> tuple[str | None, str | None]:
    """Back-compat wrapper that drops tenant_id. Prefer host_meta_for for new code."""
    hn, osf, _ = await host_meta_for(host_id)
    return hn, osf


async def tenant_id_for(host_id: UUID) -> UUID | None:
    """Return the host's tenant_id (cached). None when the host is unknown.

    Used by alert factories that don't have a DB session in scope at the
    point of lookup. When you DO have a session (the common case), prefer
    ``resolve_alert_tenant_id`` below — it uses the session's identity map
    and so works inside a test-suite savepoint where this cache cannot.
    """
    _, _, tid = await host_meta_for(host_id)
    return tid


async def resolve_alert_tenant_id(
    db: AsyncSession,
    *,
    host_id: UUID,
    ecs_tenant_id: str | None,
) -> UUID | None:
    """Resolve the tenant_id an alert factory should stamp on its Alert.

    Order of preference:
      1. ``ecs_tenant_id`` (the normalizer stamps `tenant.id` on every
         post-Phase-3 ECS doc — that field is authoritative for the
         host the event came from).
      2. ``Host.tenant_id`` looked up against the provided session.
         Using the session keeps this readable inside test transactions
         that haven't yet committed (the module-level host_cache opens
         a fresh connection and so misses uncommitted hosts).

    Returns None only when the host is gone (deleted between event
    arrival and alert emission) and the ECS doc didn't carry tenant.id.
    Callers should drop the alert rather than fall back to
    DEFAULT_TENANT_ID — silently mis-tagging is exactly the regression
    CODE-22..26 fixed.
    """
    from app.models import Host

    if ecs_tenant_id:
        try:
            return UUID(ecs_tenant_id)
        except ValueError:
            pass  # malformed → fall through to the DB
    host = await db.get(Host, host_id)
    return host.tenant_id if host is not None else None


def invalidate(host_id: UUID) -> None:
    """Drop the cached entry for `host_id`. Currently unused; exposed for
    future host-update flows that want to push the new hostname / tenant
    through immediately rather than waiting for the TTL."""
    _CACHE.pop(host_id, None)
