# ADR 0002 — Agent ↔ manager communication and enrollment

- **Status:** Accepted
- **Date:** 2026-05-08

## Context

Agents must:
1. Authenticate themselves to the manager strongly (an attacker on the network must not be able to spoof an agent or impersonate the manager).
2. Stream high-volume telemetry up.
3. Receive policy updates, rule syncs, and response commands (kill, scan, isolate) with low latency.
4. Survive transient disconnection without dropping events.

## Decision

### Transport

**gRPC bidirectional streaming over mTLS.** The agent maintains a single long-lived `HostStream` RPC. `ClientMessage` is sent up (events, heartbeats, command results, scan reports). `ServerMessage` is sent down (policy updates, rule sync, commands, pongs). Schemas in `proto/edr/v1/control.proto`.

### Identity and enrollment

**Per-host X.509 client certificates issued by an internal CA hosted by the manager.**

Enrollment flow:
1. Operator generates a one-time **enrollment token** in the manager UI (or via API). Token is short-lived (default 24h), single-use.
2. Agent installer is given the manager URL and the enrollment token.
3. On first run the agent generates a P-256 key pair and a CSR.
4. Agent calls `Enroll(EnrollRequest{ enrollment_token, hostname, os, agent_version, csr_pem })` over TLS (no client cert yet — enrollment endpoint accepts anonymous TLS).
5. Manager validates token, signs cert with internal CA, returns `client_cert_pem` + `ca_chain_pem` + assigned `host_id`.
6. Agent persists key + cert + assigned host_id in the agent config dir; subsequent connections use mTLS.

### Internal CA

- Single root CA per manager instance, generated on first run if absent.
- CA private key encrypted at rest in PG using a master key from `EDR_CA_MASTER_KEY` env (development default; deployments must override).
- Issued client certs: 90 day validity, rotated by agent before expiry via a `RenewCert` RPC (out of scope for ADR; will be added in M1).
- No intermediates in v1.

### Reconnection and event durability

- Agent disk-spools events when the manager is unreachable (sled-backed ring buffer, default 24h cap or 1 GiB cap, whichever first).
- On reconnect, agent replays from the spool. Events carry monotonic `(host_id, seq)`; manager dedupes by `event_id` (ULID).

## Rationale

- **mTLS over a static API key:** mTLS gives identity at the TLS layer (agents that lose their key cannot impersonate other hosts), supports rotation cleanly, and matches the operating model of every serious EDR.
- **gRPC over HTTPS+WS or long-polling:** strong typing via protobuf, single multiplexed stream, and built-in flow control. Modest setup cost is paid once.
- **One-time enrollment token over shared install secret:** each agent is bound to a token usable once; compromise of an install package does not yield a re-enrollable secret.
- **Internal CA over public CA:** no out-of-band cert provisioning; manager is the trust anchor; rotations and revocations are local operations.

## Alternatives considered

- **HTTPS POST + WebSocket commands.** Workable but requires operating two endpoints and reasoning about consistency between them.
- **OpenID Connect / mutual JWT.** Would require an IdP for agent identity; mTLS is simpler in a self-hosted PoC.
- **Pre-shared keys per host.** Rotation is brittle, identity binding is weaker than X.509.

## Consequences

- The manager runs both a REST/HTTPS service (UI + admin API on :8000) and a gRPC service (agents on :50051) with separate cert stores.
- We ship a CA management subsystem in M1 (boot, persist, rotate).
- The agent must handle clock skew gracefully (client cert validity windows; mTLS handshake fails on heavy skew). Document NTP requirement.
