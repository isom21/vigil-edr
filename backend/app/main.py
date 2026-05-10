"""FastAPI entry point for the EDR manager."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import api_router
from app.core.config import settings

log = structlog.get_logger()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
    )
    log.info("edr.backend.starting", debug=settings.debug)
    yield
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
# app/core/rate_limit.py; production overrides via EDR_RL_* env vars.
from app.core.rate_limit import RateLimitMiddleware  # noqa: E402

app.add_middleware(RateLimitMiddleware)


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
