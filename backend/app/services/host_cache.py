"""In-memory host metadata cache for normalizer enrichment.

Agents include only `host.id` (UUID) on every event, not the hostname or
OS family — those are sent once via the Hello message at connect time
and stored on the Host row in PG.

To make telemetry docs immediately useful in OpenSearch (so analysts can
search by hostname), the normalizer worker injects host.hostname and
host.os on every doc by reading from PG. We cache lookups for ~60s
since hostnames change rarely; on cache miss we hit the DB once.

Cache miss has zero impact on doc shape — we just emit the doc without
the hostname field. The indexer mapping treats host.hostname as
nullable, so unenriched docs continue to flow.
"""
from __future__ import annotations

import time
from typing import Optional
from uuid import UUID

from sqlalchemy import select

from app.core.db import SessionLocal
from app.models import Host


# Single in-process cache. Each entry is (hostname, os_family, expires_at).
_CACHE: dict[UUID, tuple[Optional[str], Optional[str], float]] = {}
_TTL_S = 60.0


async def hostname_for(host_id: UUID) -> tuple[Optional[str], Optional[str]]:
    """Return (hostname, os_family) for a host_id; (None, None) if unknown.

    Cached for ~60s. On miss, opens a fresh AsyncSession for one query.
    """
    now = time.monotonic()
    entry = _CACHE.get(host_id)
    if entry is not None and entry[2] > now:
        return entry[0], entry[1]

    async with SessionLocal() as db:
        h = await db.get(Host, host_id)

    hostname = h.hostname if h else None
    os_family = h.os_family.value if h else None
    _CACHE[host_id] = (hostname, os_family, now + _TTL_S)
    return hostname, os_family


def invalidate(host_id: UUID) -> None:
    """Drop the cached entry for `host_id`. Currently unused; exposed for
    future host-update flows that want to push the new hostname through
    immediately rather than waiting for the TTL."""
    _CACHE.pop(host_id, None)
