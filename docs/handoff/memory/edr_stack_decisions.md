---
name: EDR stack decisions (M0)
description: Frozen technology choices for the EDR project — consult before suggesting alternatives.
type: project
originSessionId: 04069394-44f9-41e9-9017-3a82415636ec
---
Decisions locked in during M0 design phase. Don't propose alternatives without flagging this memory and the cost of the change.

**Why:** Each was chosen deliberately by the user after seeing tradeoffs. Re-litigating mid-build wastes time and breaks invariants (e.g., schema, transport).

**How to apply:** When writing code, picking libraries, or proposing changes, conform to these. If a hard blocker appears, surface it explicitly rather than silently swapping.

| Concern | Decision |
|---|---|
| Target OS (PoC) | Windows first, Linux later |
| Agent language | Rust core + small C shim where required (kernel driver C/C++, eBPF C) |
| Backend lang/framework | Python + FastAPI |
| Backend DB | PostgreSQL 16 |
| Telemetry store | OpenSearch 2.x |
| Message bus | Kafka (Redpanda in dev) |
| Stream processing | Apache Flink (Sigma streaming) |
| Frontend | React + Vite + TS + shadcn/ui + Tailwind |
| Agent ↔ backend transport | gRPC bidirectional streaming over mTLS |
| Telemetry ingest path | Kafka (queue between gRPC ingest and consumers) |
| Agent enrollment / auth | mTLS with per-host certs from internal CA; one-time enrollment token |
| Sigma execution | Real-time streaming via Flink (fallback to Python consumer if Flink slips) |
| Event/telemetry schema | ECS-aligned (Elastic Common Schema), defined in protobuf |
| Kernel-level scope | Full kernel: KMDF driver + minifilter on Windows; eBPF (CO-RE/aya) on Linux |
| Windows targets | Win10 22H2 + Win11 |
| Driver signing (PoC) | Test-signed; dev VMs with `bcdedit /set testsigning on` |
| Repo layout | Monorepo at /mnt/d/priv/code/edr; kernel sources in top-level kernel-windows/, kernel-linux/ |
| Protobuf | Source of truth in `proto/edr/v1/` — CI checks generated bindings match |
| PoC v1 scope target | Full v1: kernel driver, response actions, both OS, full UI (delivered across milestones M0–M7) |
