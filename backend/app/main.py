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

    # M22.b: kick off the alert broker so SSE subscribers can fan out
    # without each connection running its own DB poll loop.
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
        await broker.stop()
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
