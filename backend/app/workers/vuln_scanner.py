"""Daily vulnerability scanner (Phase 2 #2.7).

Three-stage pass per tick:

  1. Pull the NVD delta since `last_pull_seen_at` into `vulnerability`.
     `last_pull_seen_at` is the max `modified_at` we last observed; on
     the first run we seed it to "30 days ago" so the worker doesn't
     try to ingest the entire NVD corpus on boot. NVD itself recommends
     incremental sync via `lastModStartDate`.

  2. Walk every `INSTALLED_SOFTWARE` JobArtifact and merge its
     `artifact_metadata.packages` array into `host_software`. We read
     from the metadata column directly — no MinIO round-trip, which
     keeps the worker fast and means the scanner can run even when the
     object store is unreachable.

  3. For every host with software, run the CPE matcher against the
     CVE table and UPSERT `host_vulnerability`. The unique
     `(host_id, cve_id)` constraint lets us collapse the matcher's
     potentially-many `(host_id, cve_id, advisory_cpe)` outputs into
     one row that captures the first matching advisory CPE.

Lifecycle copies `intel_ingest.py`: a `run_forever()` outer loop that
sleeps `VIGIL_VULN_SCAN_INTERVAL_S` between passes, each pass calling
the testable `_run_once()`. Tests pass a `session_maker` shim that
yields the SAVEPOINT-scoped fixture session so DB state stays inside
the test transaction.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import SessionLocal
from app.models import (
    HostSoftware,
    HostVulnerability,
    Job,
    JobArtifact,
    JobKind,
    JobRun,
    Vulnerability,
)
from app.services.vuln import NvdClient, NvdVulnerability, match, parse_cpe

SessionMaker = Callable[[], AbstractAsyncContextManager[AsyncSession]]

log = structlog.get_logger()

# Initial-sync window: how far back we look when the table is empty.
# 30 days is conservative — NVD's published guidance is 120 days as
# the "last 4 months" window. We keep ours shorter so the first scan
# doesn't pull tens of thousands of rows on a dev box.
_INITIAL_LOOKBACK_DAYS = 30

__all__ = (
    "run_forever",
    "_run_once",
    "_interval_seconds",
    "_upsert_vulnerability",
    "_upsert_host_software",
    "_compute_matches",
)


def _interval_seconds() -> int:
    raw = os.environ.get("VIGIL_VULN_SCAN_INTERVAL_S", "86400")
    try:
        return max(60, int(raw))
    except ValueError:
        return 86400


async def _last_modified_seen(db: AsyncSession) -> datetime:
    """Return the max modified_at in `vulnerability`, or the lookback
    floor when the table is empty. The worker uses this as
    `lastModStartDate` on the next NVD pull."""
    stmt = (
        select(Vulnerability.modified_at)
        .order_by(Vulnerability.modified_at.desc().nulls_last())
        .limit(1)
    )
    result = (await db.execute(stmt)).scalar_one_or_none()
    if result is not None:
        if result.tzinfo is None:
            result = result.replace(tzinfo=UTC)
        return result
    return datetime.now(UTC) - timedelta(days=_INITIAL_LOOKBACK_DAYS)


async def _upsert_vulnerability(db: AsyncSession, v: NvdVulnerability) -> None:
    """INSERT … ON CONFLICT DO UPDATE so a re-pull keeps the row's
    `created_at` stable but refreshes the mutable fields."""
    stmt = (
        pg_insert(Vulnerability)
        .values(
            cve_id=v.cve_id,
            severity=v.severity,
            cvss_v3_score=v.cvss_v3_score,
            summary=v.summary,
            references_json=list(v.references),
            affected_cpe_json=list(v.affected_cpes),
            published_at=v.published_at,
            modified_at=v.modified_at,
        )
        .on_conflict_do_update(
            index_elements=[Vulnerability.cve_id],
            set_={
                "severity": v.severity,
                "cvss_v3_score": v.cvss_v3_score,
                "summary": v.summary,
                "references_json": list(v.references),
                "affected_cpe_json": list(v.affected_cpes),
                "published_at": v.published_at,
                "modified_at": v.modified_at,
            },
        )
    )
    await db.execute(stmt)


async def _upsert_host_software(
    db: AsyncSession,
    host_id: UUID,
    pkg: dict[str, Any],
    now: datetime,
) -> None:
    """One package row. We key the upsert on (host_id, name, version)
    so a host reinstalling the same package version touches only
    `last_seen` — the agent emits a fresh artifact daily and we don't
    want to lose `first_seen`."""
    name = (pkg.get("name") or "").strip()
    version = (pkg.get("version") or "").strip()
    if not name or not version:
        return
    vendor = pkg.get("vendor") or None
    cpe = pkg.get("cpe") or None
    stmt = (
        pg_insert(HostSoftware)
        .values(
            host_id=host_id,
            name=name,
            version=version,
            vendor=vendor,
            cpe=cpe,
            first_seen=now,
            last_seen=now,
        )
        .on_conflict_do_update(
            constraint="uq_host_software_host_id_name_version",
            set_={"last_seen": now, "vendor": vendor, "cpe": cpe},
        )
    )
    await db.execute(stmt)


def _compute_matches(
    installed: list[HostSoftware],
    vulnerabilities: list[Vulnerability],
) -> list[tuple[UUID, str, str | None]]:
    """Return [(host_id, cve_id, matching_advisory_cpe)] tuples.

    Pure helper for the test path; the worker calls it on the rows it
    loaded out of the DB."""
    out: list[tuple[UUID, str, str | None]] = []
    for sw in installed:
        if not sw.cpe:
            continue
        inst = parse_cpe(sw.cpe)
        if inst is None:
            continue
        for vuln in vulnerabilities:
            adv_list = vuln.affected_cpe_json or []
            if not isinstance(adv_list, list):
                continue
            hit = match(inst, [c for c in adv_list if isinstance(c, str)])
            if hit is None:
                continue
            out.append((sw.host_id, vuln.cve_id, hit))
    return out


async def _refresh_host_software_from_artifacts(db: AsyncSession, now: datetime) -> int:
    """Walk every INSTALLED_SOFTWARE artifact's `artifact_metadata.packages`
    array and merge each row into host_software. Returns the number of
    packages we attempted to upsert (duplicates collapse via the unique
    constraint)."""
    stmt = (
        select(JobArtifact, JobRun.host_id)
        .join(JobRun, JobRun.id == JobArtifact.job_run_id)
        .join(Job, Job.id == JobRun.job_id)
        .where(Job.kind == JobKind.INSTALLED_SOFTWARE)
    )
    rows = (await db.execute(stmt)).all()
    n = 0
    for artifact, host_id in rows:
        meta = artifact.artifact_metadata or {}
        packages = meta.get("packages") if isinstance(meta, dict) else None
        if not isinstance(packages, list):
            continue
        for pkg in packages:
            if not isinstance(pkg, dict):
                continue
            await _upsert_host_software(db, host_id, pkg, now)
            n += 1
    return n


async def _upsert_host_vulnerabilities(
    db: AsyncSession,
    matches: list[tuple[UUID, str, str | None]],
    now: datetime,
) -> int:
    """UPSERT one row per (host_id, cve_id) pair. New rows pick up
    `first_seen=now`; existing rows refresh `last_seen` + the matched
    advisory CPE without disturbing the suppression flag."""
    inserted_or_touched = 0
    for host_id, cve_id, cpe in matches:
        stmt = (
            pg_insert(HostVulnerability)
            .values(
                host_id=host_id,
                cve_id=cve_id,
                cpe=cpe,
                first_seen=now,
                last_seen=now,
            )
            .on_conflict_do_update(
                constraint="uq_host_vulnerability_host_id_cve_id",
                set_={"last_seen": now, "cpe": cpe},
            )
        )
        await db.execute(stmt)
        inserted_or_touched += 1
    return inserted_or_touched


async def _run_once(
    session_maker: SessionMaker | None = None,
    *,
    nvd_client: NvdClient | None = None,
    now: datetime | None = None,
) -> dict[str, int]:
    """One scan pass. Returns counts the test path can assert on."""
    sm: SessionMaker = session_maker if session_maker is not None else SessionLocal
    moment = now or datetime.now(UTC)
    client = nvd_client or NvdClient()

    cve_count = 0
    pkg_count = 0
    match_count = 0
    async with sm() as db:
        last_seen = await _last_modified_seen(db)
        try:
            cves = await client.fetch_modified(last_mod_start=last_seen, last_mod_end=moment)
        except Exception as exc:  # noqa: BLE001
            log.warning("vuln_scanner.nvd_fetch_failed", error=str(exc))
            cves = []
        for v in cves:
            await _upsert_vulnerability(db, v)
            cve_count += 1

        pkg_count = await _refresh_host_software_from_artifacts(db, moment)

        # Pull every vulnerability + every host_software row back out
        # of the same session so the matcher sees the inserts we just
        # made above. For a daily scan this is fine; if the catalog
        # grows past a few hundred thousand rows we'll want a smarter
        # join in SQL.
        vulns = list((await db.execute(select(Vulnerability))).scalars().all())
        installed = list((await db.execute(select(HostSoftware))).scalars().all())
        matches = _compute_matches(installed, vulns)
        match_count = await _upsert_host_vulnerabilities(db, matches, moment)
        await db.commit()

    return {
        "cves_ingested": cve_count,
        "packages_seen": pkg_count,
        "matches_upserted": match_count,
    }


async def run_forever() -> None:
    """Main loop. Wrapped in lifespan as a background task."""
    interval = _interval_seconds()
    log.info("vuln_scanner.loop.starting", interval_s=interval)
    while True:
        try:
            await _run_once()
        except asyncio.CancelledError:
            log.info("vuln_scanner.loop.cancelled")
            raise
        except Exception:  # pragma: no cover — never let the loop die
            log.exception("vuln_scanner.loop.iteration_failed")
        try:
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            log.info("vuln_scanner.loop.cancelled")
            raise
