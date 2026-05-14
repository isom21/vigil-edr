"""Shared structlog configuration.

Every entry point (FastAPI lifespan, the gRPC server, each worker `main()`)
historically pasted the same `structlog.configure(...)` block. That drifted —
the FastAPI side included a `wrapper_class=make_filtering_bound_logger(INFO)`
filter, the workers didn't. Centralise here so a future change (log-level
flag, JSON-vs-console renderer, request-id processor) hits one place.

Idempotent: callers can re-invoke without rebinding loggers.
"""

from __future__ import annotations

import logging

import structlog

_CONFIGURED = False


def configure() -> None:
    """Bind the project-wide structlog config. Safe to call multiple times."""
    global _CONFIGURED
    if _CONFIGURED:
        return
    logging.basicConfig(level=logging.INFO)
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
    )
    _CONFIGURED = True
