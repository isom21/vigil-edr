"""gRPC server entry point.

Run with:
    python -m app.grpc.server
"""

from __future__ import annotations

import asyncio
import socket

import grpc
import structlog

from app.core.config import settings
from app.core.db import SessionLocal
from app.proto_gen.edr.v1 import control_pb2_grpc
from app.services.ca import CaService
from app.services.kafka import producer

log = structlog.get_logger()


async def _server_credentials() -> grpc.ServerCredentials:
    """Bootstrap the manager's TLS material and return server creds.

    Server cert is signed by the same internal CA that signs agent client
    certs; clients are required to present a cert chain that validates
    against that CA (mTLS).
    """
    async with SessionLocal() as db:
        ca = CaService(db)
        # Bind the server cert to the configured listen DNS name + 'localhost'
        # plus any operator-supplied extras (Tailscale MagicDNS name, tailnet
        # IP, etc.) so agents on other hosts get a valid handshake.
        host = settings.grpc_listen.rsplit(":", 1)[0]
        san_names: list[str] = [socket.gethostname(), "localhost", "edr-manager"]
        if host and host not in ("0.0.0.0", "::"):
            san_names.append(host)
        for extra in settings.grpc_san_extras.split(","):
            extra = extra.strip()
            if extra and extra not in san_names:
                san_names.append(extra)
        material = await ca.get_or_issue_server_cert(dns_names=san_names)
        await db.commit()

    return grpc.ssl_server_credentials(
        private_key_certificate_chain_pairs=[(material.key_pem, material.cert_pem)],
        root_certificates=material.ca_chain_pem,
        require_client_auth=True,
    )


async def serve() -> None:
    from app.grpc.services import AgentService

    await producer.start()
    server = grpc.aio.server()
    control_pb2_grpc.add_AgentServiceServicer_to_server(AgentService(), server)

    creds = await _server_credentials()
    server.add_secure_port(settings.grpc_listen, creds)
    await server.start()
    log.info("grpc.listening", addr=settings.grpc_listen, mtls=True)
    try:
        await server.wait_for_termination()
    except asyncio.CancelledError:
        await server.stop(grace=5)
        raise
    finally:
        await producer.stop()


def main() -> None:
    from app.core.logging import configure as _configure_logging

    _configure_logging()
    asyncio.run(serve())


if __name__ == "__main__":
    main()
