"""Detonation poller — drives ``DetonationJob`` rows to a verdict (Phase 4 #4.4).

Walks every ``running`` job on each tick, asks the matching provider
for the current status, and writes the outcome back to the row. On a
``malicious`` verdict the worker bootstraps a synthetic per-tenant
``intel_feeds`` row called ``detonation:<tenant>`` (one per tenant,
derived deterministically from the tenant uuid so re-runs don't
fragment) and inserts a fresh ``IocEntry(kind=hash_sha256)`` under
that feed's managed rule. The existing IOC detector picks the hash
up on subsequent host activity without a new code path.

Lifecycle / opt-out shape mirrors ``intel_ingest.py`` — a per-tenant
namespace, the same outer-tick env var pattern, and exception
swallowing in the inner loop so one flaky provider can't take the
whole worker down.

Tuning:
  * ``VIGIL_DETONATION_POLLER_INTERVAL_S`` (default 30, floor 5).
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import SessionLocal
from app.models import (
    DetonationJob,
    DetonationJobStatus,
    DetonationProvider,
    DetonationProviderKind,
    DetonationVerdictLabel,
    IntelFeed,
    IntelFeedKind,
    IocEntry,
    IocKind,
    Rule,
    RuleAction,
    RuleKind,
    Severity,
)
from app.services.detonation import get_client, label_for_score
from app.services.encryption import decrypt_config

SessionMaker = Callable[[], AbstractAsyncContextManager[AsyncSession]]

log = structlog.get_logger()

__all__ = (
    "DETONATION_FEED_NAMESPACE",
    "_ensure_detonation_feed",
    "_interval_seconds",
    "_poll_job",
    "_run_once",
    "run_forever",
)


# Stable UUID5 namespace for derived per-tenant detonation feed ids.
# Picking a fixed namespace means a tenant's feed id is identical
# across redeploys / test runs, so a re-init can't strand pre-existing
# IocEntry rows whose ``source_id`` references the old uuid.
DETONATION_FEED_NAMESPACE: uuid.UUID = uuid.UUID("c0c0c0c0-0000-0000-0000-de70ac10cafe")


def _detonation_feed_id(tenant_id: UUID) -> UUID:
    return uuid.uuid5(DETONATION_FEED_NAMESPACE, str(tenant_id))


def _interval_seconds() -> int:
    raw = os.environ.get("VIGIL_DETONATION_POLLER_INTERVAL_S", "30")
    try:
        return max(5, int(raw))
    except ValueError:
        return 30


async def _ensure_detonation_feed(db: AsyncSession, tenant_id: UUID) -> IntelFeed:
    """Idempotently create the synthetic per-tenant detonation feed +
    its managed Rule. Returns the feed.

    Same lazy-init shape as ``services.enrollment._ensure_reenrollment_rule``
    — the row is keyed by a deterministic UUID derived from the tenant
    so concurrent submitters land on the same row and the IocEntry
    ``source_id`` FK stays stable across re-inits.
    """
    feed_id = _detonation_feed_id(tenant_id)
    feed = await db.get(IntelFeed, feed_id)
    if feed is not None:
        if feed.managed_rule_id is None or await db.get(Rule, feed.managed_rule_id) is None:
            feed.managed_rule_id = (await _create_managed_rule(db, tenant_id, feed.name)).id
        return feed

    feed_name = f"detonation:{tenant_id}"
    feed = IntelFeed(
        id=feed_id,
        tenant_id=tenant_id,
        name=feed_name,
        # CUSTOM_JSON is the closest existing kind for a non-pulled
        # synthetic feed; the kind only matters at pull time and the
        # ingest worker never sees this feed (we don't enable the row).
        kind=IntelFeedKind.CUSTOM_JSON,
        url="internal://detonation",
        enabled=False,
        interval_s=3600,
    )
    db.add(feed)
    await db.flush()
    rule = await _create_managed_rule(db, tenant_id, feed_name)
    feed.managed_rule_id = rule.id
    return feed


async def _create_managed_rule(db: AsyncSession, tenant_id: UUID, feed_name: str) -> Rule:
    rule = Rule(
        tenant_id=tenant_id,
        kind=RuleKind.IOC,
        name=feed_name,
        description=(
            "Auto-managed: SHA-256 hashes the sandbox marked malicious. "
            "Add a host-side detection path by leaving this rule enabled; "
            "delete the rule to opt out of automatic IOC feedback."
        ),
        severity=Severity.HIGH,
        action=RuleAction.ALERT,
        enabled=True,
    )
    db.add(rule)
    await db.flush()
    return rule


async def _materialise_ioc(
    db: AsyncSession,
    *,
    tenant_id: UUID,
    sha256: str,
) -> bool:
    """Insert an IocEntry tying ``sha256`` to the synthetic detonation
    feed. Returns True when a new row was inserted, False when the
    indicator was already present (re-detonation of the same sample)."""
    feed = await _ensure_detonation_feed(db, tenant_id)
    rule_id = feed.managed_rule_id
    if rule_id is None:
        # _ensure_detonation_feed always populates this; bail defensively
        # so we don't write an orphan IocEntry on an unexpected schema
        # state.
        return False
    normalised = sha256.lower().strip()
    existing = (
        await db.execute(
            select(IocEntry.id).where(
                IocEntry.source_id == feed.id,
                IocEntry.kind == IocKind.HASH_SHA256,
                IocEntry.value_normalized == normalised,
            )
        )
    ).first()
    if existing is not None:
        return False
    db.add(
        IocEntry(
            tenant_id=tenant_id,
            rule_id=rule_id,
            kind=IocKind.HASH_SHA256,
            value=normalised,
            value_normalized=normalised,
            source_id=feed.id,
        )
    )
    # Bump the rule's revision so agents flush their IOC caches.
    rule = await db.get(Rule, rule_id)
    if rule is not None:
        rule.revision += 1
    return True


async def _poll_job(
    db: AsyncSession,
    job: DetonationJob,
    provider: DetonationProvider,
) -> None:
    """Poll one running job. Writes the outcome back to ``job``.

    Caller owns the surrounding transaction + commit.
    """
    if job.external_id is None:
        # Defensive: a row with no external_id can't be polled. Mark
        # failed so the operator sees a clear terminal state.
        job.status = DetonationJobStatus.FAILED
        job.error = "missing external task id"
        job.finished_at = datetime.now(UTC)
        return

    try:
        config: dict[str, Any] = decrypt_config(provider.config_encrypted)
    except Exception as exc:  # noqa: BLE001
        job.status = DetonationJobStatus.FAILED
        job.error = f"config decrypt failed: {exc}"
        job.finished_at = datetime.now(UTC)
        return

    client = get_client(DetonationProviderKind.coerce(provider.kind))
    try:
        result = await client.poll(config, job.external_id)
    except NotImplementedError as exc:
        job.status = DetonationJobStatus.FAILED
        job.error = str(exc)
        job.finished_at = datetime.now(UTC)
        return
    except Exception as exc:  # noqa: BLE001
        job.status = DetonationJobStatus.FAILED
        job.error = f"poll failed: {exc}"
        job.finished_at = datetime.now(UTC)
        log.warning(
            "detonation.poll_failed",
            job_id=str(job.id),
            external_id=job.external_id,
            error=str(exc),
        )
        return

    status = result.get("status")
    if status == "running":
        return
    if status == "failed":
        job.status = DetonationJobStatus.FAILED
        job.error = str(result.get("error") or "provider reported failure")
        job.finished_at = datetime.now(UTC)
        return
    if status != "verdict":
        log.warning("detonation.unknown_status", job_id=str(job.id), provider_status=status)
        return

    score = result.get("score")
    label = label_for_score(score if isinstance(score, (int, float)) else None)
    job.status = DetonationJobStatus.VERDICT
    job.verdict_score = float(score) if isinstance(score, (int, float)) else None
    job.verdict_label = label.value
    job.finished_at = datetime.now(UTC)

    if label is DetonationVerdictLabel.MALICIOUS:
        inserted = await _materialise_ioc(db, tenant_id=job.tenant_id, sha256=job.sha256)
        if inserted:
            log.info(
                "detonation.ioc_added",
                sha256=job.sha256,
                tenant_id=str(job.tenant_id),
                score=job.verdict_score,
            )


async def _run_once(session_maker: SessionMaker | None = None) -> int:
    """One pass over all running jobs. Returns the number processed."""
    sm: SessionMaker = session_maker if session_maker is not None else SessionLocal
    processed = 0
    async with sm() as db:
        stmt = select(DetonationJob, DetonationProvider).join(
            DetonationProvider, DetonationProvider.id == DetonationJob.provider_id
        )
        stmt = stmt.where(DetonationJob.status == DetonationJobStatus.RUNNING)
        rows = (await db.execute(stmt)).all()
        for job, provider in rows:
            try:
                await _poll_job(db, job, provider)
            except Exception:  # noqa: BLE001 — never let one job kill the loop
                log.exception("detonation.poll_iteration_failed", job_id=str(job.id))
            processed += 1
        await db.commit()
    return processed


async def run_forever() -> None:
    """Main loop. Wrapped in lifespan as a background task."""
    interval = _interval_seconds()
    log.info("detonation_poller.loop.starting", interval_s=interval)
    while True:
        try:
            await _run_once()
        except asyncio.CancelledError:
            log.info("detonation_poller.loop.cancelled")
            raise
        except Exception:  # pragma: no cover — never let the loop die
            log.exception("detonation_poller.loop.iteration_failed")
        try:
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            log.info("detonation_poller.loop.cancelled")
            raise
