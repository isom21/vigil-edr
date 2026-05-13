"""Sequence / behavioral rules worker (Phase 2 #2.3).

Consumes `telemetry.normalized` and feeds each ECS event into the
SequenceEvaluator. When a sequence completes, an Alert row is
written under the rule's managed `Rule` (lazily created on first
hit, mirroring `intel_ingest._ensure_managed_rule`).

Lifecycle copies `intel_ingest.py`:
  * `run_forever()` — long-lived loop, started from `app.main.lifespan`.
  * `_run_once()` — one pass that processes a batch of events; the
    tests drive this directly with an injected session maker + a
    list of synthetic events bypassing Kafka.

The Kafka consumer setup is identical to sigma_realtime — same topic,
same auto-offset behaviour. Group id is `sequence_detector` so the
two workers don't fight over offsets.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import time
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager
from datetime import UTC, datetime
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
    AlertStateHistory,
    Rule,
    RuleAction,
    RuleKind,
    SequenceRule,
    Severity,
)
from app.services.alert_dedup import bump_occurrence, dedup_key_for, find_open_dupe
from app.services.sequence import (
    ParsedSequence,
    SequenceEvaluator,
    SequenceMatch,
    SequenceParseError,
    parse_yaml,
)

log = structlog.get_logger()

SessionMaker = Callable[[], AbstractAsyncContextManager[AsyncSession]]


def _resolve_severity(label: str | None, fallback: Severity) -> Severity:
    """Map an `emit_alert.severity` YAML string to the Severity enum;
    fall back to the rule's column-level severity for unknown / unset
    labels."""
    if label is None:
        return fallback
    try:
        return Severity(str(label).lower())
    except ValueError:
        return fallback


async def _ensure_managed_rule(db: AsyncSession, srule: SequenceRule) -> Rule:
    """Mirror `intel_ingest._ensure_managed_rule` for sequence rules.

    We surface the managed `Rule` as kind=SIGMA so existing alert UI
    paths (alert detail's `rule.name`, severity badges, MITRE tag
    rendering) keep working without introducing a new RuleKind value.
    The Sigma rule has no compiled body — it never fires through the
    percolator, only carries the metadata Alert rows reference.
    """
    if srule.managed_rule_id is not None:
        rule = await db.get(Rule, srule.managed_rule_id)
        if rule is not None:
            return rule
    rule = Rule(
        kind=RuleKind.SIGMA,
        name=f"sequence:{srule.name}",
        description=(
            f"Auto-managed: backs the sequence rule '{srule.name}'. "
            "Edit the sequence rule in /sequence-rules; this Rule row "
            "exists so emitted alerts have a valid rule_id FK target."
        ),
        severity=srule.severity,
        action=RuleAction.ALERT,
        enabled=True,
        mitre_techniques=list(srule.mitre_techniques) if srule.mitre_techniques else None,
    )
    db.add(rule)
    await db.flush()
    srule.managed_rule_id = rule.id
    return rule


def _compile_rules(rules: list[SequenceRule]) -> dict[str, tuple[SequenceRule, ParsedSequence]]:
    """Compile every enabled rule. Failures log + drop the rule (a
    bad rule body must not poison the whole worker)."""
    compiled: dict[str, tuple[SequenceRule, ParsedSequence]] = {}
    for srule in rules:
        if not srule.enabled:
            continue
        try:
            parsed = parse_yaml(srule.yaml_body, default_window_s=srule.window_s)
        except SequenceParseError as exc:
            log.warning(
                "sequence_detector.parse_failed",
                rule_id=str(srule.id),
                rule_name=srule.name,
                error=str(exc),
            )
            continue
        compiled[str(srule.id)] = (srule, parsed)
    return compiled


async def _emit_alert(
    db: AsyncSession,
    *,
    srule: SequenceRule,
    parsed: ParsedSequence,
    match: SequenceMatch,
    ecs: dict[str, Any],
) -> Alert | None:
    """Insert (or dedupe-bump) an Alert for a completed match.

    Returns the new Alert when a fresh row was inserted, None when
    the match folded onto an existing open alert via dedup.
    """
    try:
        host_id = UUID(match.host_id)
    except (TypeError, ValueError):
        return None

    rule = await _ensure_managed_rule(db, srule)
    severity = _resolve_severity(parsed.emit.severity, srule.severity)
    ts = datetime.now(UTC)

    dkey = dedup_key_for(rule.id, host_id, ecs)
    existing = await find_open_dupe(
        db,
        dedup_key=dkey,
        window_seconds=settings.alert_dedup_window_s,
        now=ts,
    )
    if existing is not None:
        bump_occurrence(existing, now=ts)
        await db.flush()
        log.info(
            "sequence_detector.alert_deduped",
            rule_id=str(srule.id),
            rule_name=srule.name,
            alert_id=str(existing.id),
            occurrence_count=existing.occurrence_count,
        )
        srule.hit_count = (srule.hit_count or 0) + 1
        srule.last_hit_at = ts
        return None

    summary = parsed.emit.message or f"sequence match: {srule.name}"
    alert = Alert(
        host_id=host_id,
        rule_id=rule.id,
        severity=severity,
        action_taken=RuleAction.ALERT,
        state=AlertState.NEW,
        summary=summary[:512],
        details={
            "engine": "sequence",
            "rule_name": srule.name,
            "sequence_rule_id": str(srule.id),
            "event_ids": match.event_ids,
            "window_s": srule.window_s,
        },
        dedup_key=dkey,
        last_occurred_at=ts,
        mitre_techniques=(list(srule.mitre_techniques) if srule.mitre_techniques else None),
    )
    alert.history.append(
        AlertStateHistory(
            from_state=None,
            to_state=AlertState.NEW,
            comment="auto-generated by sequence detector",
        )
    )
    db.add(alert)
    await db.flush()
    srule.hit_count = (srule.hit_count or 0) + 1
    srule.last_hit_at = ts
    log.info(
        "sequence_detector.alert_emitted",
        rule_id=str(srule.id),
        rule_name=srule.name,
        alert_id=str(alert.id),
        host_id=str(host_id),
    )
    return alert


async def _process_event(
    db: AsyncSession,
    evaluator: SequenceEvaluator,
    compiled: dict[str, tuple[SequenceRule, ParsedSequence]],
    ecs: dict[str, Any],
    *,
    now_ts: float | None = None,
) -> list[Alert]:
    """Feed one event through the evaluator + emit alerts for any
    completed matches. Returns the freshly-inserted Alert rows (dedup
    bumps don't count)."""
    matches = evaluator.feed_event(ecs, now_ts=now_ts)
    if not matches:
        return []
    emitted: list[Alert] = []
    for m in matches:
        compiled_entry = compiled.get(m.rule_id)
        if compiled_entry is None:
            continue
        srule, parsed = compiled_entry
        alert = await _emit_alert(db, srule=srule, parsed=parsed, match=m, ecs=ecs)
        if alert is not None:
            emitted.append(alert)
    return emitted


async def _run_once(
    session_maker: SessionMaker | None = None,
    *,
    events: list[dict[str, Any]] | None = None,
    evaluator: SequenceEvaluator | None = None,
) -> int:
    """One pass. Loads rules + processes the passed events synchronously.

    The Kafka consumer path doesn't go through here — `run_forever`
    pulls from Kafka directly. This helper exists for the tests +
    any future "replay" feature.
    """
    sm: SessionMaker = session_maker if session_maker is not None else SessionLocal
    emitted_total = 0
    async with sm() as db:
        srules = (
            (await db.execute(select(SequenceRule).where(SequenceRule.enabled.is_(True))))
            .scalars()
            .all()
        )
        compiled = _compile_rules(list(srules))
        ev = evaluator if evaluator is not None else SequenceEvaluator()
        for rid, (_srule, parsed) in compiled.items():
            ev.register_rule(rid, parsed)
        for ecs in events or []:
            emitted = await _process_event(db, ev, compiled, ecs)
            emitted_total += len(emitted)
        await db.commit()
    return emitted_total


# ---------------------------------------------------------------------------
# Long-lived Kafka consumer (production path)
# ---------------------------------------------------------------------------


class SequenceDetector:
    """Long-lived worker — wired into `app.main.lifespan`.

    Holds:
      * one Kafka consumer at the `telemetry.normalized` topic.
      * one in-memory SequenceEvaluator that survives the consumer's
        commit cadence (state lives in the worker process; on restart
        we lose pending partials, which is fine — partials expire
        in seconds-to-minutes anyway).
      * a cached `rule_id -> (SequenceRule, ParsedSequence)` map
        refreshed on a tick so operator edits don't need a worker
        restart.
    """

    REFRESH_INTERVAL_S = 30

    def __init__(self) -> None:
        from aiokafka import AIOKafkaConsumer  # type: ignore[import-not-found]

        self._AIOKafkaConsumer = AIOKafkaConsumer
        self.consumer: Any | None = None
        self._stop = asyncio.Event()
        self.evaluator = SequenceEvaluator()
        self._compiled: dict[str, tuple[SequenceRule, ParsedSequence]] = {}
        self._last_refresh_ts = 0.0

    async def start(self) -> None:
        await self._refresh_rules(force=True)
        self.consumer = self._AIOKafkaConsumer(
            settings.topic_telemetry_normalized,
            bootstrap_servers=settings.kafka_brokers,
            group_id="sequence_detector",
            enable_auto_commit=False,
            auto_offset_reset="latest",
            session_timeout_ms=15_000,
            max_poll_interval_ms=300_000,
        )
        await self.consumer.start()
        log.info(
            "sequence_detector.start",
            topic=settings.topic_telemetry_normalized,
            rules=len(self._compiled),
        )

    async def stop(self) -> None:
        self._stop.set()
        if self.consumer is not None:
            await self.consumer.stop()
        log.info("sequence_detector.stop")

    async def _refresh_rules(self, *, force: bool = False) -> None:
        now = time.time()
        if not force and now - self._last_refresh_ts < self.REFRESH_INTERVAL_S:
            return
        async with SessionLocal() as db:
            srules = (
                (await db.execute(select(SequenceRule).where(SequenceRule.enabled.is_(True))))
                .scalars()
                .all()
            )
            compiled = _compile_rules(list(srules))
        self._compiled = compiled
        # Drop any rule no longer present.
        for rid in list(self.evaluator._rules.keys()):  # noqa: SLF001
            if rid not in compiled:
                self.evaluator.forget_rule(rid)
        for rid, (_srule, parsed) in compiled.items():
            self.evaluator.register_rule(rid, parsed)
        self._last_refresh_ts = now

    async def _process_message(self, value: bytes | None) -> None:
        if value is None:
            return
        try:
            ecs = json.loads(value)
        except Exception:  # noqa: BLE001
            log.exception("sequence_detector.decode_failed")
            return
        async with SessionLocal() as db:
            try:
                await _process_event(db, self.evaluator, self._compiled, ecs)
                await db.commit()
            except Exception:  # noqa: BLE001
                log.exception("sequence_detector.process_failed")
                await db.rollback()

    async def run(self) -> None:
        assert self.consumer is not None
        gc_counter = 0
        while not self._stop.is_set():
            try:
                msg = await asyncio.wait_for(self.consumer.getone(), timeout=1.0)
            except TimeoutError:
                await self._refresh_rules()
                continue
            await self._process_message(msg.value)
            gc_counter += 1
            if gc_counter >= 256:
                self.evaluator.gc()
                gc_counter = 0
            await self._refresh_rules()
            await self.consumer.commit()


def _enabled_from_env() -> bool:
    """The lifespan wiring opts out via `VIGIL_SEQUENCE_DETECTOR_ENABLED=0`."""
    return os.environ.get("VIGIL_SEQUENCE_DETECTOR_ENABLED", "1") != "0"


async def run_forever() -> None:
    """Main loop. Wrapped in lifespan as a background task."""
    if not _enabled_from_env():
        log.info("sequence_detector.loop.disabled_by_env")
        return
    worker = SequenceDetector()
    await worker.start()
    try:
        await worker.run()
    except asyncio.CancelledError:
        log.info("sequence_detector.loop.cancelled")
        raise
    except Exception:  # pragma: no cover — never let the loop die quietly
        log.exception("sequence_detector.loop.crashed")
    finally:
        await worker.stop()


async def amain() -> None:
    worker = SequenceDetector()
    await worker.start()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(worker.stop()))
    try:
        await worker.run()
    finally:
        await worker.stop()


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ]
    )
    asyncio.run(amain())


# Test helper -----------------------------------------------------------------


async def replay_events(
    events: AsyncIterator[dict[str, Any]] | list[dict[str, Any]],
    *,
    session_maker: SessionMaker | None = None,
) -> int:
    """Bypass Kafka and stream events through the worker for testing.

    The smoke / unit tests use this to verify a small synthetic
    sequence emits an alert without standing up a real broker.
    """
    if isinstance(events, list):
        return await _run_once(session_maker=session_maker, events=events)
    sm: SessionMaker = session_maker if session_maker is not None else SessionLocal
    emitted_total = 0
    async with sm() as db:
        srules = (
            (await db.execute(select(SequenceRule).where(SequenceRule.enabled.is_(True))))
            .scalars()
            .all()
        )
        compiled = _compile_rules(list(srules))
        evaluator = SequenceEvaluator()
        for rid, (_srule, parsed) in compiled.items():
            evaluator.register_rule(rid, parsed)
        async for ecs in events:
            emitted = await _process_event(db, evaluator, compiled, ecs)
            emitted_total += len(emitted)
        await db.commit()
    return emitted_total


__all__ = (
    "SequenceDetector",
    "_compile_rules",
    "_ensure_managed_rule",
    "_process_event",
    "_run_once",
    "replay_events",
    "run_forever",
)
