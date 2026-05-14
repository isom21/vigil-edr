"""FastAPI entry point for the EDR manager."""

from __future__ import annotations

from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import api_router, scim_router
from app.core.config import assert_production_secrets, settings

log = structlog.get_logger()


async def _cancel_task(task, name: str) -> None:
    """Cancel a lifespan-owned task and drain its completion.

    Surfaces non-cancellation exceptions to the log — silently swallowing them
    (the historical pattern) hid shutdown bugs. We still don't re-raise so a
    single misbehaving worker can't abort the rest of the teardown.
    """
    import asyncio

    if task is None:
        return
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        return
    except Exception as exc:  # noqa: BLE001 — best-effort shutdown, log + continue
        log.warning("lifespan.shutdown.task_failed", task=name, error=str(exc))


@asynccontextmanager
async def lifespan(_app: FastAPI):
    import asyncio

    from app.core.logging import configure as _configure_logging

    _configure_logging()
    log.info("edr.backend.starting", debug=settings.debug)

    # Refuse to start if any crypto secret is still at its dev default.
    # In dev (`debug=True`) this is a no-op. The check runs before any
    # subsystem so a misconfigured prod manager never opens its sockets.
    assert_production_secrets()

    # Phase 1 #1.13: optional Redis client backing the HA primitives
    # (rate limiter, alert broker, login throttle). Empty URL keeps
    # the in-memory single-instance behaviour, which is the default.
    from app.core.redis_client import close_redis_client, init_redis_client

    redis_client_inst = await init_redis_client(settings.redis_url)
    if redis_client_inst is not None:
        # Wire the rate limiter to the shared store before the broker
        # starts so the first request after lifespan-enter already
        # picks up the cluster-wide bucket.
        from app.core.rate_limit import RedisStore

        _app.state.rate_limit_store = RedisStore(redis_client_inst)

    # Phase 1 #1.14: sync the on-disk curated rule pack into the DB.
    # Idempotent — re-running the loader is a no-op when nothing on
    # disk changed. Runs before the alert broker / workers so any
    # newly-inserted rules are visible to the first poll. Opt out
    # with `VIGIL_RULE_PACK_LOAD_ON_BOOT=0`. Failures here log a
    # warning and continue — the pack is content, not infrastructure.
    from app.services.rule_pack import load_rule_pack_at_boot

    await load_rule_pack_at_boot()

    # M22.b: kick off the alert broker so SSE subscribers can fan out
    # without each connection running its own DB poll loop. When Redis
    # is configured, `broker.start()` also subscribes to the pub/sub
    # channel so this instance hears publishes from peers.
    from app.services.alert_broker import broker

    await broker.start()

    # M-audit-and-auth #6: audit-chain verifier as a background task.
    # `VIGIL_AUDIT_VERIFIER_INTERVAL_S=0` opts out explicitly;
    # `VIGIL_TEST_ENV=1` (set by the CI workflow + the pytest harness)
    # also opts out so a parallel lifespan-mounted ASGI test doesn't
    # spin up the loop and contend with the test's own DB session.
    import os as _os

    verifier_task: asyncio.Task | None = None
    if (
        _os.environ.get("VIGIL_AUDIT_VERIFIER_INTERVAL_S", "300") != "0"
        and _os.environ.get("VIGIL_TEST_ENV") != "1"
    ):
        from app.workers.audit_verifier_loop import run_forever as _verifier_loop

        verifier_task = asyncio.create_task(_verifier_loop())

    # Top-20 #17: command-dispatch watchdog. Expires DISPATCHED rows
    # whose agent never reported back so the alert console / commands
    # UI doesn't keep stale "in flight" entries forever. Same opt-out
    # shape as the audit verifier — set interval=0 to disable,
    # VIGIL_TEST_ENV=1 keeps it off under pytest so unrelated tests
    # don't race the watchdog's UPDATEs.
    watchdog_task: asyncio.Task | None = None
    if (
        _os.environ.get("VIGIL_DISPATCH_WATCHDOG_INTERVAL_S", "60") != "0"
        and _os.environ.get("VIGIL_TEST_ENV") != "1"
    ):
        from app.workers.dispatch_watchdog import run_forever as _watchdog_loop

        watchdog_task = asyncio.create_task(_watchdog_loop())

    # Phase 1 #1.11: incident grouper.
    incident_grouper_task: asyncio.Task | None = None
    if (
        _os.environ.get("VIGIL_INCIDENT_GROUPER_INTERVAL_S", "60") != "0"
        and _os.environ.get("VIGIL_TEST_ENV") != "1"
    ):
        from app.workers.incident_grouper import run_forever as _incident_grouper_loop

        incident_grouper_task = asyncio.create_task(_incident_grouper_loop())

    # Phase 1 #1.9: threat-intel ingest worker.
    intel_ingest_task: asyncio.Task | None = None
    if (
        _os.environ.get("VIGIL_INTEL_INGEST_INTERVAL_S", "60") != "0"
        and _os.environ.get("VIGIL_TEST_ENV") != "1"
    ):
        from app.workers.intel_ingest import run_forever as _intel_loop

        intel_ingest_task = asyncio.create_task(_intel_loop())

    # Phase 4 #4.3: identity threat detection (Okta + Azure AD).
    identity_monitor_task: asyncio.Task | None = None
    if (
        _os.environ.get(
            "VIGIL_IDENTITY_MONITOR_ENABLED",
            "1" if settings.identity_monitor_enabled != "0" else "0",
        )
        != "0"
        and _os.environ.get("VIGIL_TEST_ENV") != "1"
    ):
        from app.workers.identity_monitor import run_forever as _identity_loop

        identity_monitor_task = asyncio.create_task(_identity_loop())

    # Phase 3 #3.7: webhook dispatcher worker — consumes
    # `webhook.events` and fans matching subscriptions out.
    webhook_dispatcher_task: asyncio.Task | None = None
    if (
        _os.environ.get("VIGIL_WEBHOOK_DISPATCHER_ENABLED", "1") != "0"
        and _os.environ.get("VIGIL_TEST_ENV") != "1"
    ):
        from app.workers.webhook_dispatcher import run_forever as _webhook_loop

        webhook_dispatcher_task = asyncio.create_task(_webhook_loop())

    # Phase 4 #4.1: AI summariser worker. Also consumes the webhook
    # event bus (separate consumer group) and writes one `alert_summary`
    # row per `alert.opened` envelope. Opt out via
    # `VIGIL_AI_SUMMARISER_ENABLED=0` or by leaving the API key empty
    # (the wrapper short-circuits without an HTTP call in that case).
    ai_summariser_task: asyncio.Task | None = None
    if (
        _os.environ.get(
            "VIGIL_AI_SUMMARISER_ENABLED",
            "1" if settings.ai_summariser_enabled != "0" else "0",
        )
        != "0"
        and _os.environ.get("VIGIL_TEST_ENV") != "1"
    ):
        from app.workers.ai_summariser import run_forever as _ai_summariser_loop

        ai_summariser_task = asyncio.create_task(_ai_summariser_loop())

    # Phase 2 #2.11: hunt scheduler worker.
    hunt_scheduler_task: asyncio.Task | None = None
    if (
        _os.environ.get("VIGIL_HUNT_SCHEDULER_INTERVAL_S", "60") != "0"
        and _os.environ.get("VIGIL_TEST_ENV") != "1"
    ):
        from app.workers.hunt_scheduler import run_forever as _hunt_scheduler_loop

        hunt_scheduler_task = asyncio.create_task(_hunt_scheduler_loop())

    # Phase 1 #1.5: SIEM forwarder worker.
    siem_forwarder_task: asyncio.Task | None = None
    if (
        _os.environ.get("VIGIL_SIEM_FORWARDER_ENABLED", "1") != "0"
        and _os.environ.get("VIGIL_TEST_ENV") != "1"
    ):
        from app.workers.siem_forwarder import SiemForwarder

        async def _siem_forwarder_loop() -> None:
            worker = SiemForwarder()
            try:
                await worker.start()
                await worker.run()
            finally:
                await worker.stop()

        siem_forwarder_task = asyncio.create_task(_siem_forwarder_loop())

    # Phase 2 #2.7: vulnerability scanner.
    vuln_scanner_task: asyncio.Task | None = None
    if (
        _os.environ.get("VIGIL_VULN_SCAN_INTERVAL_S", "86400") != "0"
        and _os.environ.get("VIGIL_TEST_ENV") != "1"
    ):
        from app.workers.vuln_scanner import run_forever as _vuln_loop

        vuln_scanner_task = asyncio.create_task(_vuln_loop())

    # Phase 1 #1.7: alert routing worker.
    alert_router_task: asyncio.Task | None = None
    if (
        _os.environ.get("VIGIL_ALERT_ROUTER_TICK_S", "2") != "0"
        and _os.environ.get("VIGIL_TEST_ENV") != "1"
    ):
        from app.workers.alert_router import AlertRouterWorker

        async def _alert_router_loop() -> None:
            worker = AlertRouterWorker()
            await worker.start()
            try:
                await worker.run()
            finally:
                await worker.stop()

        alert_router_task = asyncio.create_task(_alert_router_loop())

    # Phase 2 #2.8: application-allowlist learner.
    allowlist_learner_task: asyncio.Task | None = None
    if (
        _os.environ.get("VIGIL_ALLOWLIST_LEARNER_ENABLED", "1") != "0"
        and _os.environ.get("VIGIL_TEST_ENV") != "1"
    ):
        from app.workers.allowlist_learner import run_forever as _allowlist_loop

        allowlist_learner_task = asyncio.create_task(_allowlist_loop())

    # Phase 2 #2.6: process-chain indexer worker. Tails the normalised
    # telemetry stream and materialises process_started/exited into
    # the `process_chain` graph store for lineage queries.
    process_chain_task: asyncio.Task | None = None
    if (
        _os.environ.get(
            "VIGIL_PROCESS_CHAIN_INDEXER_ENABLED",
            "1" if settings.process_chain_indexer_enabled != "0" else "0",
        )
        != "0"
        and _os.environ.get("VIGIL_TEST_ENV") != "1"
    ):
        from app.workers.process_chain_indexer import run_forever as _process_chain_loop

        process_chain_task = asyncio.create_task(_process_chain_loop())

    # Phase 3 #3.2: OpenSearch ILM + S3 cold-archive worker.
    archive_worker_task: asyncio.Task | None = None
    if (
        _os.environ.get("VIGIL_ARCHIVE_WORKER_ENABLED", "1") != "0"
        and _os.environ.get("VIGIL_TEST_ENV") != "1"
    ):
        from app.workers.archive_worker import run_forever as _archive_loop

        archive_worker_task = asyncio.create_task(_archive_loop())

    # Phase 2 #2.3: sequence / behavioral rules detector.
    sequence_detector_task: asyncio.Task | None = None
    if (
        _os.environ.get("VIGIL_SEQUENCE_DETECTOR_ENABLED", "1") != "0"
        and _os.environ.get("VIGIL_TEST_ENV") != "1"
    ):
        from app.workers.sequence_detector import run_forever as _sequence_loop

        sequence_detector_task = asyncio.create_task(_sequence_loop())

    # Phase 3 #3.5: playbook executor. Consumes `playbook.runs` and
    # walks each matched playbook's steps. Same opt-out shape as the
    # other workers — set the env var to "0" to keep dormant.
    playbook_executor_task: asyncio.Task | None = None
    if (
        _os.environ.get(
            "VIGIL_PLAYBOOK_EXECUTOR_ENABLED",
            "1" if settings.playbook_executor_enabled != "0" else "0",
        )
        != "0"
        and _os.environ.get("VIGIL_TEST_ENV") != "1"
    ):
        from app.workers.playbook_executor import run_forever as _playbook_loop

        playbook_executor_task = asyncio.create_task(_playbook_loop())

    # Phase 4 #4.4: detonation poller — drives DetonationJob rows
    # to a verdict and feeds malicious hashes back into the IOC list.
    detonation_poller_task: asyncio.Task | None = None
    if (
        _os.environ.get("VIGIL_DETONATION_POLLER_ENABLED", settings.detonation_poller_enabled)
        != "0"
        and _os.environ.get("VIGIL_TEST_ENV") != "1"
    ):
        from app.workers.detonation_poller import run_forever as _detonation_loop

        detonation_poller_task = asyncio.create_task(_detonation_loop())

    # Phase 3 #3.6: external case-tracker poller (Jira + ServiceNow).
    case_sync_task: asyncio.Task | None = None
    if (
        _os.environ.get("VIGIL_CASE_SYNC_INTERVAL_S", str(settings.case_sync_interval_s)) != "0"
        and _os.environ.get("VIGIL_TEST_ENV") != "1"
    ):
        from app.workers.case_sync import run_forever as _case_sync_loop

        case_sync_task = asyncio.create_task(_case_sync_loop())
    # Phase 3 #3.3: agent rollout cohort monitor. Trips the per-policy
    # rollout breaker when failures cluster in the configured window.
    rollout_monitor_task: asyncio.Task | None = None
    if (
        _os.environ.get(
            "VIGIL_ROLLOUT_MONITOR_INTERVAL_S",
            str(settings.rollout_monitor_interval_s),
        )
        != "0"
        and _os.environ.get("VIGIL_TEST_ENV") != "1"
    ):
        from app.workers.rollout_monitor import run_forever as _rollout_monitor_loop

        rollout_monitor_task = asyncio.create_task(_rollout_monitor_loop())

    # Phase 4 #4.2: AWS CloudTrail IAM-anomaly monitor. Pulls new
    # objects from each operator-registered S3 bucket and emits
    # synthetic alerts when a fresh event escapes the per-(source,
    # principal) baseline.
    cloud_iam_monitor_task: asyncio.Task | None = None
    if (
        _os.environ.get(
            "VIGIL_CLOUD_IAM_MONITOR_ENABLED",
            "1" if settings.cloud_iam_monitor_enabled != "0" else "0",
        )
        != "0"
        and _os.environ.get("VIGIL_TEST_ENV") != "1"
    ):
        from app.workers.cloud_iam_monitor import run_forever as _cloud_iam_loop

        cloud_iam_monitor_task = asyncio.create_task(_cloud_iam_loop())

    try:
        yield
    finally:
        await _cancel_task(verifier_task, "verifier_task")
        await _cancel_task(watchdog_task, "watchdog_task")
        await _cancel_task(incident_grouper_task, "incident_grouper_task")
        await _cancel_task(intel_ingest_task, "intel_ingest_task")
        await _cancel_task(identity_monitor_task, "identity_monitor_task")
        await _cancel_task(webhook_dispatcher_task, "webhook_dispatcher_task")
        await _cancel_task(ai_summariser_task, "ai_summariser_task")
        await _cancel_task(hunt_scheduler_task, "hunt_scheduler_task")
        await _cancel_task(siem_forwarder_task, "siem_forwarder_task")
        await _cancel_task(alert_router_task, "alert_router_task")
        await _cancel_task(allowlist_learner_task, "allowlist_learner_task")
        await _cancel_task(process_chain_task, "process_chain_task")
        await _cancel_task(vuln_scanner_task, "vuln_scanner_task")
        await _cancel_task(sequence_detector_task, "sequence_detector_task")
        await _cancel_task(playbook_executor_task, "playbook_executor_task")
        await _cancel_task(detonation_poller_task, "detonation_poller_task")
        await _cancel_task(case_sync_task, "case_sync_task")
        await _cancel_task(archive_worker_task, "archive_worker_task")
        await _cancel_task(rollout_monitor_task, "rollout_monitor_task")
        await _cancel_task(cloud_iam_monitor_task, "cloud_iam_monitor_task")
        await broker.stop()
        # Close the Redis pool after every consumer has stopped using
        # it. `close_redis_client()` is a noop when no client was ever
        # opened, so single-instance deployments pay nothing here.
        _app.state.rate_limit_store = None
        await close_redis_client()
        log.info("edr.backend.stopping")


app = FastAPI(
    title="EDR Manager API",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/api/docs" if settings.debug else None,
    redoc_url=None,
    openapi_url="/api/openapi.json",
)

# CORS for the dev frontend on :5173 (Vite proxy is preferred but CORS is a safety net).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"] if settings.debug else [],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# M13.a — per-identity rate limiting. Defaults are documented in
# app/core/rate_limit.py; production overrides via VIGIL_RL_* env vars.
from app.core.rate_limit import RateLimitMiddleware  # noqa: E402

app.add_middleware(RateLimitMiddleware)

# M14.a.b — populate Prometheus request_total + request_latency_seconds
# on every HTTP request. Inserted after the rate limiter so 429s also
# count toward the request totals.
from app.core.metrics_middleware import RequestMetricsMiddleware  # noqa: E402

app.add_middleware(RequestMetricsMiddleware)


@app.exception_handler(Exception)
async def _unhandled(_request: Request, exc: Exception) -> JSONResponse:
    # Don't shadow HTTPException — FastAPI handles those before this handler runs.
    log.exception("unhandled.error", error=str(exc))
    return JSONResponse(status_code=500, content={"detail": "internal server error"})


@app.get("/api/health", tags=["meta"])
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/version", tags=["meta"])
async def version() -> dict[str, str]:
    return {"version": app.version}


app.include_router(api_router)
# Phase 3 #3.8: SCIM 2.0 — mounted at root (e.g. `/scim/v2`) so IdPs
# can hit `/scim/v2/Users` per RFC 7644.
app.include_router(scim_router)
