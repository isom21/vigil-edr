"""gRPC server entry point.

In M1 this is a skeleton: it imports the generated protobuf bindings (regenerated
by `make proto` from /proto) and registers handlers that return UNIMPLEMENTED.
M2 will plug in real Enroll + HostStream logic.

Run with:
    python -m app.grpc.server
"""
from __future__ import annotations

import asyncio
import logging
from concurrent import futures

import grpc
import structlog

from app.core.config import settings

log = structlog.get_logger()


def _try_import_generated() -> tuple | None:
    """Import generated protobuf modules. Returns None if codegen has not been run yet."""
    try:
        from app.proto_gen.edr.v1 import (  # type: ignore[import-not-found]
            control_pb2_grpc,
        )

        return (control_pb2_grpc,)
    except ImportError:
        return None


class AgentService:
    """Stub service. Real implementation in M2.

    The real class will inherit from ``control_pb2_grpc.AgentServiceServicer``;
    until codegen runs, we just register a placeholder so the server can start.
    """

    async def Enroll(self, request, context):  # noqa: N802 - gRPC method name
        await context.abort(grpc.StatusCode.UNIMPLEMENTED, "Enroll not implemented in M1")

    async def HostStream(self, request_iterator, context):  # noqa: N802
        await context.abort(grpc.StatusCode.UNIMPLEMENTED, "HostStream not implemented in M1")


async def serve() -> None:
    server = grpc.aio.server(futures.ThreadPoolExecutor(max_workers=10))

    generated = _try_import_generated()
    if generated is None:
        log.warning(
            "grpc.protos_not_generated",
            hint="run `make proto` from the repo root to generate bindings",
        )
    else:
        # M2: register AgentServiceServicer once handlers are real.
        log.info("grpc.protos_loaded")

    server.add_insecure_port(settings.grpc_listen)
    await server.start()
    log.info("grpc.listening", addr=settings.grpc_listen)
    try:
        await server.wait_for_termination()
    except asyncio.CancelledError:
        await server.stop(grace=5)
        raise


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    asyncio.run(serve())


if __name__ == "__main__":
    main()
