"""Phase 4 #4.3 — identity threat monitor worker.

Periodic loop that walks every enabled `IdentitySource`, pulls the
upstream event stream (Okta System Log v1 / Microsoft Graph
`/auditLogs/signIns`), normalises events to the common shape, and
runs the detectors in `app.services.identity.detectors`. Hits land
as `Alert` rows under four synthetic Rules — see
`app.models.synthetic_rules` for the fixed UUIDs.

Lifecycle: mounted in `app.main.lifespan` next to `intel_ingest` and
`vuln_scanner`. Opt out per-instance with
`VIGIL_IDENTITY_MONITOR_ENABLED=0`; outer tick configured via
`VIGIL_IDENTITY_MONITOR_INTERVAL_S` (default 300 s, floor 30 s — the
upstream APIs all rate-limit below 5/min so a faster outer tick is
either burning quota for nothing or thrashing).

The detectors are pure functions, so this worker only handles:

  1. Picking the right fetcher per source kind.
  2. Threading the per-source `last_event_ts` cursor through fetches.
  3. Running each detector against the fetched window.
  4. Materialising hits as Alert rows + bumping `last_polled_at`
     + `last_event_ts` on the source row.
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
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import SessionLocal
from app.models import (
    Alert,
    AlertState,
    IdentitySource,
    IdentitySourceKind,
    Rule,
    RuleAction,
    RuleKind,
    Severity,
)
from app.models.synthetic_rules import (
    IDENTITY_BRUTE_FORCE_RULE_ID,
    IDENTITY_IMPOSSIBLE_TRAVEL_RULE_ID,
    IDENTITY_MFA_BOMB_RULE_ID,
    IDENTITY_PASSWORD_SPRAY_RULE_ID,
)
from app.services.encryption import decrypt_config
from app.services.identity import IdentityEvent
from app.services.identity import azure_ad as azure_ad_client
from app.services.identity import okta as okta_client
from app.services.identity.detectors import (
    DetectorHit,
    brute_force,
    group_by_actor,
    group_by_ip,
    impossible_travel,
    mfa_bomb,
    password_spray,
)

SessionMaker = Callable[[], AbstractAsyncContextManager[AsyncSession]]

log = structlog.get_logger()

__all__ = (
    "run_forever",
    "_run_once",
    "_poll_source",
    "_interval_seconds",
    "_ensure_synthetic_rule",
)


# Lookback window when a source has never been polled before. We
# avoid reaching back to the start of the tenant's history because
# both Okta + Graph cap us at ~1000 events per page; a fresh
# integration with a noisy log volume could lose context otherwise.
_INITIAL_LOOKBACK = timedelta(hours=1)


# Synthetic rule metadata, indexed by stable UUID. The worker
# bootstraps each row on first detection — same pattern as
# `app.workers.anomaly`'s ANOMALY_RULE_ID.
_SYNTHETIC_RULES: dict[UUID, dict[str, Any]] = {
    IDENTITY_IMPOSSIBLE_TRAVEL_RULE_ID: {
        "name": "Identity: impossible travel",
        "severity": Severity.HIGH,
        "description": (
            "Phase 4 #4.3 synthetic rule — fires when two successful logins for "
            "the same actor imply travel faster than the configured "
            "kmph threshold (default 800)."
        ),
    },
    IDENTITY_BRUTE_FORCE_RULE_ID: {
        "name": "Identity: brute-force login",
        "severity": Severity.HIGH,
        "description": (
            "Phase 4 #4.3 synthetic rule — fires on N failed login attempts "
            "for the same actor inside a sliding window (defaults: 10 in 5 "
            "minutes)."
        ),
    },
    IDENTITY_MFA_BOMB_RULE_ID: {
        "name": "Identity: MFA bombing",
        "severity": Severity.HIGH,
        "description": (
            "Phase 4 #4.3 synthetic rule — fires on N MFA challenges for the "
            "same actor inside a sliding window (defaults: 5 in 5 minutes). "
            "Catches push-fatigue / MFA-bombing attacks."
        ),
    },
    IDENTITY_PASSWORD_SPRAY_RULE_ID: {
        "name": "Identity: password spray",
        "severity": Severity.HIGH,
        "description": (
            "Phase 4 #4.3 synthetic rule — fires when one source IP touches "
            "N distinct accounts inside the window with failed credentials "
            "(defaults: 8 distinct accounts in 5 minutes)."
        ),
    },
}


def _interval_seconds() -> int:
    raw = os.environ.get(
        "VIGIL_IDENTITY_MONITOR_INTERVAL_S",
        str(settings.identity_monitor_interval_s),
    )
    try:
        return max(30, int(raw))
    except ValueError:
        return settings.identity_monitor_interval_s


async def _ensure_synthetic_rule(db: AsyncSession, rule_id: UUID) -> None:
    """Lazy bootstrap of the per-detector synthetic Rule row.

    Idempotent: a no-op when the row already exists. Same pattern as
    `app.workers.anomaly._ensure_pseudo_rule` so the alerts UI has
    something to anchor each hit against without a dedicated
    migration that hard-codes seed data.
    """
    meta = _SYNTHETIC_RULES[rule_id]
    existing = await db.get(Rule, rule_id)
    if existing is not None:
        return
    rule = Rule(
        id=rule_id,
        kind=RuleKind.SIGMA,  # closest match in the existing kind enum.
        name=meta["name"],
        description=meta["description"],
        severity=meta["severity"],
        action=RuleAction.ALERT,
        enabled=True,
    )
    db.add(rule)
    await db.flush()
    log.info("identity_monitor.rule_bootstrapped", rule_id=str(rule_id))


async def _fetch_for_source(
    source: IdentitySource,
    after_ts: datetime | None,
) -> list[IdentityEvent]:
    """Decrypt the source's config and dispatch to the right fetcher."""
    config = decrypt_config(source.config_encrypted)
    kind = IdentitySourceKind.coerce(source.kind)
    if kind is IdentitySourceKind.OKTA:
        return await okta_client.fetch_events(config, after_ts)
    if kind is IdentitySourceKind.AZURE_AD:
        return await azure_ad_client.fetch_events(config, after_ts)
    raise RuntimeError(f"unsupported identity source kind: {kind}")


def _run_detectors(events: list[IdentityEvent]) -> list[DetectorHit]:
    """Run every detector against one source's fetched window.

    Detector wiring lives here rather than in each fetcher so a third
    identity provider gets every detector for free as soon as it's
    wired into `_fetch_for_source`.
    """
    hits: list[DetectorHit] = []

    by_actor = group_by_actor(events)
    by_ip = group_by_ip(events)

    # Per-actor detectors. Impossible travel walks pairs of successful
    # logins ordered by ts (pair-with-previous, not all-pairs — the
    # O(n²) form catches every false positive a quiet network's
    # geo-jitter generates without ever firing on the realistic
    # "teleport" case). Brute force + MFA bomb scan the whole actor
    # window for failed-credential / MFA-prompt counts.
    max_kmph = float(settings.identity_impossible_travel_kmph)
    for actor, actor_events in by_actor.items():
        if not actor:
            continue
        successful = sorted(
            (e for e in actor_events if e.get("success") and isinstance(e.get("ts"), datetime)),
            key=lambda e: e["ts"],  # type: ignore[arg-type,return-value]
        )
        for i in range(1, len(successful)):
            hit = impossible_travel(successful[i - 1], successful[i], max_kmph=max_kmph)
            if hit is not None:
                hits.append(hit)
        bf = brute_force(actor_events)
        if bf is not None:
            hits.append(bf)
        mfa = mfa_bomb(actor_events)
        if mfa is not None:
            hits.append(mfa)

    # Password spray: per-IP scan.
    hits.extend(password_spray(by_ip))

    return hits


async def _materialise_hits(
    db: AsyncSession,
    tenant_id: UUID,
    hits: list[DetectorHit],
) -> int:
    """Insert one Alert row per detector hit. Returns the inserted
    count for logging.

    Identity events aren't host-keyed (the alert lives at the
    tenant + actor level), so `host_id` is NULL — matches the
    M16.a audit-chain-break + Phase 1 #1.11 ungrouped-incident
    convention.
    """
    if not hits:
        return 0
    # Ensure each referenced synthetic rule exists exactly once per
    # commit. The set() collapses duplicate references when the same
    # detector fired multiple times.
    seen_rules: set[UUID] = {h.rule_id for h in hits if isinstance(h.rule_id, UUID)}
    for rule_id in seen_rules:
        await _ensure_synthetic_rule(db, rule_id)

    inserted = 0
    for hit in hits:
        if not isinstance(hit.rule_id, UUID):
            continue
        alert = Alert(
            tenant_id=tenant_id,
            host_id=None,
            rule_id=hit.rule_id,
            severity=hit.severity,
            action_taken=RuleAction.ALERT,
            state=AlertState.NEW,
            summary=hit.summary[:512],
            details=hit.details,
        )
        db.add(alert)
        inserted += 1
    return inserted


async def _poll_source(db: AsyncSession, source: IdentitySource) -> None:
    """Pull one source and run detectors. Records `last_error` on
    failure but keeps the worker loop alive so one bad source can't
    take the whole identity-monitor down."""
    started = datetime.now(UTC)
    if source.last_event_ts is not None:
        after_ts = source.last_event_ts
    else:
        after_ts = started - _INITIAL_LOOKBACK

    try:
        events = await _fetch_for_source(source, after_ts)
    except Exception as exc:  # noqa: BLE001
        # Mark the row as polled so the next tick honours cadence; the
        # operator sees the error on the source detail card.
        source.last_polled_at = started
        log.warning(
            "identity_monitor.fetch_failed",
            source_id=str(source.id),
            kind=source.kind,
            error=str(exc),
        )
        return

    hits = _run_detectors(events)
    inserted = await _materialise_hits(db, source.tenant_id, hits)

    # Advance the cursor only when we got a clean fetch. Use the newest
    # event ts if there is one; otherwise stamp `started` so we don't
    # re-pull the same empty window forever (the rolling cursor still
    # ratchets forward on quiet tenants).
    newest: datetime | None = None
    for event in events:
        ts = event.get("ts")
        if isinstance(ts, datetime) and (newest is None or ts > newest):
            newest = ts
    if newest is not None:
        source.last_event_ts = newest
    else:
        source.last_event_ts = started
    source.last_polled_at = started
    log.info(
        "identity_monitor.poll_ok",
        source_id=str(source.id),
        kind=source.kind,
        events=len(events),
        alerts=inserted,
    )


async def _run_once(session_maker: SessionMaker | None = None) -> int:
    """One pass over every enabled identity source. Returns the
    number of sources actually polled (skipped-not-due rows don't
    count).
    """
    sm: SessionMaker = session_maker if session_maker is not None else SessionLocal
    polled = 0
    async with sm() as db:
        sources = (
            (await db.execute(select(IdentitySource).where(IdentitySource.enabled.is_(True))))
            .scalars()
            .all()
        )
        for source in sources:
            await _poll_source(db, source)
            polled += 1
        await db.commit()
    return polled


async def run_forever() -> None:
    """Main loop. Wrapped in lifespan as a background task. Mirror
    of `app.workers.intel_ingest.run_forever`."""
    interval = _interval_seconds()
    log.info("identity_monitor.loop.starting", interval_s=interval)
    while True:
        try:
            await _run_once()
        except asyncio.CancelledError:
            log.info("identity_monitor.loop.cancelled")
            raise
        except Exception:  # pragma: no cover — never let the loop die
            log.exception("identity_monitor.loop.iteration_failed")
        try:
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            log.info("identity_monitor.loop.cancelled")
            raise
