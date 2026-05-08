"""End-to-end gRPC smoke test for the EDR manager.

1. Logs into REST and creates a fresh enrollment token.
2. Generates a P-256 keypair + CSR.
3. Calls the REST enrollment endpoint with the CSR (anonymous TLS) —
   receives a signed client cert + CA chain.
4. Opens a gRPC HostStream with that client cert (mTLS), sends Hello +
   a fake process_create EventBatch + Heartbeat.
5. Reads back the initial RuleSync from the server.

Run from the backend venv after the manager (REST + gRPC) is up:
    make backend-dev   # one shell
    make backend-grpc  # another shell
    python tools/smoke/10-grpc-smoke.py
"""
from __future__ import annotations

import asyncio
import json
import secrets
import sys
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import grpc
from google.protobuf import timestamp_pb2

from app.proto_gen.edr.v1 import common_pb2, control_pb2, control_pb2_grpc, events_pb2

REST = "http://127.0.0.1:8000"
GRPC = "localhost:50051"
EMAIL = "admin@example.local"
PASSWORD = "change-me-please-12chars"


def http_post(url: str, body: dict, token: str | None = None) -> dict:
    data = json.dumps(body).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())


def issue_token() -> tuple[str, bytes]:
    auth = http_post(f"{REST}/api/auth/login", {"email": EMAIL, "password": PASSWORD})
    access = auth["access_token"]
    enr = http_post(
        f"{REST}/api/enrollment/tokens",
        {"label": "grpc-smoke", "ttl_hours": 1},
        token=access,
    )
    return enr["token"], access.encode()


def make_csr(hostname: str) -> tuple[bytes, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, hostname),
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "agents"),
                ]
            )
        )
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM), key


async def main() -> int:
    token, _ = issue_token()
    print(f"[REST] enrollment token = {token[:16]}...")

    csr_pem, priv = make_csr("smoke-host-01")

    # Enroll over REST (server-only TLS, no client cert yet) to get the CA
    # chain the gRPC mTLS dial will trust.
    enroll_resp = http_post(
        f"{REST}/api/enrollment/enroll",
        {
            "enrollment_token": token,
            "hostname": "smoke-host-01",
            "os_family": "linux",
            "agent_version": "0.1.0-smoke",
            "csr_pem": csr_pem.decode(),
        },
    )
    print(f"[REST enroll] host_id = {enroll_resp['host_id']}")

    client_cert = enroll_resp["client_cert_pem"].encode()
    ca_chain = enroll_resp["ca_chain_pem"].encode()
    client_key = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    creds = grpc.ssl_channel_credentials(
        root_certificates=ca_chain,
        private_key=client_key,
        certificate_chain=client_cert,
    )
    options = (("grpc.ssl_target_name_override", "localhost"),)
    async with grpc.aio.secure_channel(GRPC, creds, options=options) as channel:
        stub = control_pb2_grpc.AgentServiceStub(channel)
        await asyncio.wait_for(channel.channel_ready(), timeout=10)
        print("[gRPC] channel ready")

        async def request_iter():
            now = timestamp_pb2.Timestamp()
            now.GetCurrentTime()

            yield control_pb2.ClientMessage(
                hello=control_pb2.Hello(
                    host=common_pb2.Host(
                        id=enroll_resp["host_id"],
                        hostname="smoke-host-01",
                        os=common_pb2.OsInfo(family="linux", version="6.6", platform="WSL2"),
                        agent_version="0.1.0-smoke",
                    ),
                    boot_time_iso="2026-05-08T00:00:00Z",
                    last_event_id_seen=0,
                )
            )

            ev = events_pb2.EndpointEvent(
                event_id=secrets.token_hex(8),
                event_created=now,
                event_observed=now,
                kind=events_pb2.EVENT_KIND_EVENT,
                category=[events_pb2.EVENT_CATEGORY_PROCESS],
                action="process_started",
                outcome="success",
                host_id=enroll_resp["host_id"],
                agent_id="smoke-agent",
                agent_version="0.1.0-smoke",
                process=events_pb2.ProcessEvent(
                    process=common_pb2.ProcessKey(pid=1234, start_time_ns=0),
                    name="mimikatz.exe",
                    executable="C:\\\\Users\\\\Public\\\\mimikatz.exe",
                    command_line="mimikatz.exe lsadump",
                    action=events_pb2.PROCESS_ACTION_START,
                ),
            )
            yield control_pb2.ClientMessage(
                events=control_pb2.EventBatch(events=[ev], batch_id="b1", first_seq=1, last_seq=1)
            )
            yield control_pb2.ClientMessage(
                heartbeat=control_pb2.Heartbeat(
                    ts=now,
                    metrics=control_pb2.AgentMetrics(
                        cpu_percent=0.1, memory_bytes=10_000_000, events_emitted=1
                    ),
                )
            )
            await asyncio.sleep(2)

        call = stub.HostStream(request_iter())
        try:
            async for srv_msg in call:
                kind = srv_msg.WhichOneof("payload")
                if kind == "rules":
                    print(
                        f"[gRPC] RuleSync version={srv_msg.rules.rules_version} "
                        f"yara={len(srv_msg.rules.yara)} iocs={len(srv_msg.rules.iocs)}"
                    )
                    break
                elif kind == "pong":
                    print("[gRPC] Pong")
                    break
                else:
                    print(f"[gRPC] server msg: {kind}")
                    break
        except grpc.aio.AioRpcError as exc:
            print(f"[gRPC] error: {exc.code()} {exc.details()}")
            return 1

    print("[gRPC] OK")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
