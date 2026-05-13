"""Phase 1 #1.9: threat-intel feed ingest worker.

Periodic worker that walks `intel_feeds`, pulls each enabled row whose
`last_pulled_at` is older than its own `interval_s`, and materialises
the parsed indicators into `ioc_entries` under a managed `Rule` of
kind=IOC. The managed-Rule pattern keeps the existing IOC detector
firing on intel hits without a new code path on the agent side.

Refresh policy is full replace per pull: we diff `(kind, value)`
tuples against the existing rows tied to this feed's `source_id`,
INSERT the new ones, and DELETE the dropped ones. The Rule itself
keeps its `id` so the agent's rule-cache invalidation key
(`rule.revision`) bumps on every materialisation.

Wired in `app.main.lifespan` next to the other background loops.

Tuning knobs:
  * `VIGIL_INTEL_INGEST_INTERVAL_S` — outer scheduler tick. Default
    60 s; floor 10 s. The actual per-feed cadence is on the row
    (`interval_s`).
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from datetime import UTC, datetime, timedelta
from uuid import UUID

import structlog
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.db import SessionLocal
from app.models import (
    IntelFeed,
    IocEntry,
    IocKind,
    Rule,
    RuleAction,
    RuleKind,
    Severity,
)
from app.services.intel import ParsedIndicator, get_puller
from app.services.intel.crypto import decrypt_auth

SessionMaker = Callable[[], AbstractAsyncContextManager[AsyncSession]]

log = structlog.get_logger()

__all__ = (
    "run_forever",
    "_run_once",
    "_pull_feed",
    "_interval_seconds",
    "_normalize_ioc",
)


def _interval_seconds() -> int:
    raw = os.environ.get("VIGIL_INTEL_INGEST_INTERVAL_S", "60")
    try:
        return max(10, int(raw))
    except ValueError:
        return 60


def _normalize_ioc(kind: IocKind, value: str) -> str:
    """Mirror `app.api.rules._normalize_ioc` exactly. Worker and manual
    rule-edit path must agree on the normalised form so the IOC
    detector matches against the same key shape regardless of where the
    entry came from."""
    v = value.strip()
    if kind in (IocKind.HASH_SHA256, IocKind.HASH_MD5, IocKind.HASH_SHA1):
        return v.lower()
    if kind is IocKind.FILENAME:
        return v.lower()
    if kind is IocKind.FILEPATH:
        return v.replace("\\", "/").lower()
    return v


async def _ensure_managed_rule(db: AsyncSession, feed: IntelFeed) -> Rule:
    """Make sure the feed's managed Rule exists; return it. Created
    lazily on first successful pull so a feed that never connects
    doesn't leave a stub Rule lying around."""
    if feed.managed_rule_id is not None:
        rule = await db.get(Rule, feed.managed_rule_id)
        if rule is not None:
            return rule
        # FK SET NULL fired (operator deleted the rule manually) — fall
        # through to recreate so the worker stays self-healing.
    rule = Rule(
        kind=RuleKind.IOC,
        name=f"intel:{feed.name}",
        description=(
            f"Auto-managed: indicators from threat-intel feed '{feed.name}' "
            f"({feed.kind.value}). Edit the feed in /intel; manual edits to "
            "the rule's IOC list will be overwritten on the next pull."
        ),
        severity=Severity.MEDIUM,
        action=RuleAction.ALERT,
        enabled=True,
    )
    db.add(rule)
    await db.flush()
    feed.managed_rule_id = rule.id
    return rule


async def _diff_and_apply(
    db: AsyncSession,
    feed: IntelFeed,
    rule: Rule,
    pulled: list[ParsedIndicator],
) -> tuple[int, int, int]:
    """Idempotent diff: insert the new (kind, normalised_value)
    tuples, delete the rows tied to this feed that aren't in the pull.

    Returns (added, removed, total_after).
    """
    # Pre-normalise the pull set so dup-within-pull collapses too.
    desired: dict[tuple[IocKind, str], str] = {}
    for ind in pulled:
        norm = _normalize_ioc(ind.kind, ind.value)
        if not norm:
            continue
        desired.setdefault((ind.kind, norm), ind.value)

    existing_rows = (
        (await db.execute(select(IocEntry).where(IocEntry.source_id == feed.id))).scalars().all()
    )
    existing_keys = {(r.kind, r.value_normalized): r for r in existing_rows}

    added = 0
    for key, raw_value in desired.items():
        if key in existing_keys:
            continue
        kind, norm = key
        db.add(
            IocEntry(
                rule_id=rule.id,
                kind=kind,
                value=raw_value,
                value_normalized=norm,
                source_id=feed.id,
            )
        )
        added += 1

    removed_ids: list[UUID] = [row.id for key, row in existing_keys.items() if key not in desired]
    if removed_ids:
        await db.execute(delete(IocEntry).where(IocEntry.id.in_(removed_ids)))
    removed = len(removed_ids)

    # Bump rule revision when content changed so agents invalidate
    # their IOC cache. Skip the bump on a no-op pull to avoid noisy
    # rule-cache resyncs on every tick.
    if added > 0 or removed > 0:
        rule.revision += 1

    total = len(desired)
    return added, removed, total


async def _pull_feed(db: AsyncSession, feed: IntelFeed) -> None:
    """Pull a single feed. Updates last_pulled_at + last_error + the
    managed rule's IOCs. Catches and records all exceptions so one
    flaky feed can't take the worker down."""
    started = datetime.now(UTC)
    auth_plaintext: str | None = None
    if feed.encrypted_auth:
        try:
            auth_plaintext = decrypt_auth(feed.encrypted_auth)
        except Exception as exc:  # noqa: BLE001
            feed.last_error = f"auth decrypt failed: {exc}"
            feed.last_pulled_at = started
            log.warning(
                "intel_ingest.auth_decrypt_failed",
                feed_id=str(feed.id),
                feed_name=feed.name,
            )
            return

    try:
        puller = get_puller(feed.kind)
    except KeyError:
        feed.last_error = f"no puller registered for kind={feed.kind.value}"
        feed.last_pulled_at = started
        return

    try:
        indicators = await puller(feed, auth_plaintext)
    except Exception as exc:  # noqa: BLE001
        # Network / parse / auth-rejected errors all land here. Record
        # the message + bail; the operator sees it on the row.
        feed.last_error = f"pull failed: {exc}"
        feed.last_pulled_at = started
        log.warning(
            "intel_ingest.pull_failed",
            feed_id=str(feed.id),
            feed_name=feed.name,
            error=str(exc),
        )
        return

    rule = await _ensure_managed_rule(db, feed)
    added, removed, total = await _diff_and_apply(db, feed, rule, indicators)
    feed.last_pulled_at = started
    feed.entry_count = total
    feed.last_error = None
    log.info(
        "intel_ingest.pull_ok",
        feed_id=str(feed.id),
        feed_name=feed.name,
        kind=feed.kind.value,
        added=added,
        removed=removed,
        total=total,
    )


def _is_due(feed: IntelFeed, now: datetime) -> bool:
    """A feed is due if it's never been pulled or its last pull is
    older than its per-row `interval_s`."""
    if feed.last_pulled_at is None:
        return True
    last = feed.last_pulled_at
    if last.tzinfo is None:
        last = last.replace(tzinfo=UTC)
    return now - last >= timedelta(seconds=feed.interval_s)


async def _run_once(
    session_maker: SessionMaker | None = None,
    *,
    force_feed_id: UUID | None = None,
) -> int:
    """One pass. Returns the number of feeds the worker actually pulled
    this pass (skipped-not-due rows don't count). The tests pass
    `force_feed_id` to bypass the due-check for a single feed — same
    code path the API's trigger-pull endpoint uses.
    """
    sm: SessionMaker = session_maker if session_maker is not None else SessionLocal
    pulled = 0
    async with sm() as db:
        stmt = select(IntelFeed).where(IntelFeed.enabled.is_(True))
        if force_feed_id is not None:
            stmt = select(IntelFeed).where(IntelFeed.id == force_feed_id)
        feeds = (
            (await db.execute(stmt.options(selectinload(IntelFeed.managed_rule)))).scalars().all()
        )
        now = datetime.now(UTC)
        for feed in feeds:
            if force_feed_id is None and not _is_due(feed, now):
                continue
            await _pull_feed(db, feed)
            pulled += 1
        await db.commit()
    return pulled


async def trigger_pull(feed_id: UUID, session_maker: SessionMaker | None = None) -> None:
    """Force-pull a single feed. The API handler calls this after
    auditing the trigger; the worker's main loop ignores the
    distinction — same `_pull_feed` codepath either way."""
    await _run_once(session_maker=session_maker, force_feed_id=feed_id)


async def run_forever() -> None:
    """Main loop. Wrapped in lifespan as a background task."""
    interval = _interval_seconds()
    log.info("intel_ingest.loop.starting", interval_s=interval)
    while True:
        try:
            await _run_once()
        except asyncio.CancelledError:
            log.info("intel_ingest.loop.cancelled")
            raise
        except Exception:  # pragma: no cover — never let the loop die
            log.exception("intel_ingest.loop.iteration_failed")
        try:
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            log.info("intel_ingest.loop.cancelled")
            raise
