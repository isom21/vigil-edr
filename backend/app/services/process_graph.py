"""Process-chain graph queries (Phase 2 #2.6).

Recursive CTE walks over `process_chain` to materialise the lineage of
a pid on one host. Postgres caps the recursion depth implicitly via the
JOIN graph terminating at NULL parent_pid; we also cap at 64 hops as a
defensive bound against a synthetic cycle in the data.

Each row is the most recent `process_chain` record for the (host_id,
pid) pair when several start times collide (a pid getting reused after
a wrap is the common case). The CTE picks the row with the matching
started_at first, then prefers the most recent start when walking
parent links.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ProcessChain

MAX_DEPTH = 64


def _row_to_model(row) -> ProcessChain:
    return ProcessChain(
        id=row.id,
        host_id=row.host_id,
        pid=row.pid,
        parent_pid=row.parent_pid,
        exec_path=row.exec_path,
        image_sha256=row.image_sha256,
        command_line=row.command_line,
        started_at=row.started_at,
        ended_at=row.ended_at,
        created_at=row.created_at,
    )


async def ancestors(db: AsyncSession, *, host_id: UUID, pid: int) -> list[ProcessChain]:
    """Walk parent_pid backwards from `pid` until root. Returned root
    → leaf. The starting row itself is included as the last element."""
    stmt = text(
        """
        WITH RECURSIVE walk AS (
            SELECT *, 0 AS depth
            FROM process_chain
            WHERE host_id = :host_id AND pid = :pid
            ORDER BY started_at DESC
            LIMIT 1
        ),
        chain AS (
            SELECT * FROM walk
            UNION ALL
            SELECT pc.*, c.depth + 1 AS depth
            FROM process_chain pc
            JOIN chain c
              ON pc.host_id = c.host_id
             AND pc.pid = c.parent_pid
             AND pc.started_at <= c.started_at
            WHERE c.depth < :max_depth
        )
        SELECT DISTINCT ON (pid) id, host_id, pid, parent_pid, exec_path,
               image_sha256, command_line, started_at, ended_at, created_at, depth
        FROM chain
        ORDER BY pid, started_at DESC
        """
    )
    result = await db.execute(stmt, {"host_id": host_id, "pid": pid, "max_depth": MAX_DEPTH})
    rows = list(result.mappings().all())
    rows.sort(key=lambda r: r["depth"], reverse=True)
    return [
        ProcessChain(
            id=r["id"],
            host_id=r["host_id"],
            pid=r["pid"],
            parent_pid=r["parent_pid"],
            exec_path=r["exec_path"],
            image_sha256=r["image_sha256"],
            command_line=r["command_line"],
            started_at=r["started_at"],
            ended_at=r["ended_at"],
            created_at=r["created_at"],
        )
        for r in rows
    ]


async def descendants(db: AsyncSession, *, host_id: UUID, pid: int) -> list[ProcessChain]:
    """Walk forward: every process whose parent_pid chain leads back to
    `pid`. Returned in BFS order (closest children first)."""
    stmt = text(
        """
        WITH RECURSIVE chain AS (
            SELECT *, 0 AS depth
            FROM process_chain
            WHERE host_id = :host_id AND pid = :pid
            UNION ALL
            SELECT pc.*, c.depth + 1 AS depth
            FROM process_chain pc
            JOIN chain c
              ON pc.host_id = c.host_id
             AND pc.parent_pid = c.pid
             AND pc.started_at >= c.started_at
            WHERE c.depth < :max_depth
        )
        SELECT id, host_id, pid, parent_pid, exec_path, image_sha256,
               command_line, started_at, ended_at, created_at, depth
        FROM chain
        WHERE depth > 0
        ORDER BY depth, started_at
        """
    )
    result = await db.execute(stmt, {"host_id": host_id, "pid": pid, "max_depth": MAX_DEPTH})
    rows = list(result.mappings().all())
    return [
        ProcessChain(
            id=r["id"],
            host_id=r["host_id"],
            pid=r["pid"],
            parent_pid=r["parent_pid"],
            exec_path=r["exec_path"],
            image_sha256=r["image_sha256"],
            command_line=r["command_line"],
            started_at=r["started_at"],
            ended_at=r["ended_at"],
            created_at=r["created_at"],
        )
        for r in rows
    ]


async def cross_host_lineage(
    db: AsyncSession,
    *,
    image_sha256: str,
    limit: int = 100,
) -> list[ProcessChain]:
    """Every observed start of the same binary across the fleet.
    Sorted newest first so the analyst pivots into recent activity."""
    stmt = text(
        """
        SELECT id, host_id, pid, parent_pid, exec_path, image_sha256,
               command_line, started_at, ended_at, created_at
        FROM process_chain
        WHERE image_sha256 = :image_sha256
        ORDER BY started_at DESC
        LIMIT :limit
        """
    )
    result = await db.execute(stmt, {"image_sha256": image_sha256, "limit": limit})
    rows = list(result.mappings().all())
    return [
        ProcessChain(
            id=r["id"],
            host_id=r["host_id"],
            pid=r["pid"],
            parent_pid=r["parent_pid"],
            exec_path=r["exec_path"],
            image_sha256=r["image_sha256"],
            command_line=r["command_line"],
            started_at=r["started_at"],
            ended_at=r["ended_at"],
            created_at=r["created_at"],
        )
        for r in rows
    ]
