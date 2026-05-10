"""Request metrics middleware (M14.a.b).

Wraps every HTTP request to populate the M14.a metric primitives:
  edr_manager_requests_total{method, route, status}
  edr_manager_request_latency_seconds{method, route}

The `route` label is the FastAPI route template (e.g.
`/api/hosts/{host_id}`) rather than the literal request path — this
keeps cardinality bounded. Falls back to `<unknown>` for paths
without a matched route.
"""
from __future__ import annotations

import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.core.metrics import request_latency_seconds, requests_total


class RequestMetricsMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request, call_next):
        start = time.perf_counter()
        try:
            response = await call_next(request)
            status = response.status_code
        except Exception:
            # Mirror starlette's default behaviour: if the handler raised,
            # the response will be 500. Still record before re-raising so
            # the metric isn't lost.
            status = 500
            elapsed = time.perf_counter() - start
            self._record(request, status, elapsed)
            raise

        elapsed = time.perf_counter() - start
        self._record(request, status, elapsed)
        return response

    def _record(self, request, status: int, elapsed: float) -> None:
        # FastAPI stores the matched route on request.scope["route"].
        # For 404s (no route) we group under <unknown>.
        route = "<unknown>"
        if scope_route := request.scope.get("route"):
            route = getattr(scope_route, "path", "<unknown>")
        method = request.method
        requests_total.labels(method=method, route=route, status=str(status)).inc()
        request_latency_seconds.labels(method=method, route=route).observe(elapsed)
