"""FastAPI entry point for the EDR manager."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import api_router
from app.core.config import assert_production_secrets, settings

log = structlog.get_logger()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    import asyncio

    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
    )
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

    try:
        yield
    finally:
        if verifier_task is not None:
            verifier_task.cancel()
            try:
                await verifier_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        if watchdog_task is not None:
            watchdog_task.cancel()
            try:
                await watchdog_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        if incident_grouper_task is not None:
            incident_grouper_task.cancel()
            try:
                await incident_grouper_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        if intel_ingest_task is not None:
            intel_ingest_task.cancel()
            try:
                await intel_ingest_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        if siem_forwarder_task is not None:
            siem_forwarder_task.cancel()
            try:
                await siem_forwarder_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        if alert_router_task is not None:
            alert_router_task.cancel()
            try:
                await alert_router_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
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
