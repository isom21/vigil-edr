# ADR 0001 — Technology stack selection

- **Status:** Accepted
- **Date:** 2026-05-08
- **Decision drivers:** PoC velocity, production-realism (HarfangLab as reference), kernel-mode capability, schema rigor.

## Context

We are building an EDR (agent + management plane) PoC inspired by HarfangLab. The full v1 target includes a kernel driver on Windows, eBPF on Linux, response actions (kill / block / detect), YARA + Sigma + IOC rule engines, a streaming alert pipeline, and a web UI fronted by a strict REST API.

We need to commit to a stack early because schema, transport, and language choices affect every later component.

## Decision

| Concern | Choice |
| --- | --- |
| Agent language | Rust core (workspace) with C/C++ where the OS forces it (Windows KMDF driver, eBPF programs) |
| Agent target order | Windows first (Win10 22H2 + Win11), Linux second |
| Kernel scope | Full: KMDF driver + minifilter on Windows; eBPF (CO-RE via aya) on Linux |
| Driver signing for PoC | Test-signed in dev VMs (`bcdedit /set testsigning on`) |
| Manager API | Python 3.12 + FastAPI + Pydantic v2 + SQLAlchemy 2.0 (async) + Alembic |
| Manager state DB | PostgreSQL 16 |
| Telemetry / alerts store | OpenSearch 2.x (ECS-aligned indices) |
| Message bus | Kafka API; Redpanda in dev |
| Stream processing | Apache Flink (Sigma evaluation) |
| Frontend | React 18 + Vite + TypeScript + shadcn/ui + Tailwind |
| Schema source of truth | Protobuf in `proto/edr/v1/` |

## Rationale

- **Rust over C++ for the agent body:** memory safety reduces a class of agent crashes that would otherwise be catastrophic on customer endpoints. Mature gRPC, TLS, and YARA bindings (`tonic`, `rustls`, `yara-x`). C/C++ is still required where the platform mandates it (Windows kernel, eBPF).
- **Python/FastAPI for the manager:** fastest API iteration; pySigma integrates natively for rule conversion; OpenSearch + Postgres clients are mature. The manager is not on the hot ingest path for telemetry — Kafka + Flink are.
- **Kafka + Flink:** chosen over a Python-only stream consumer because the user explicitly opted for production-shape streaming. Risk: integration complexity. Mitigation: Python consumer fallback documented in ADR 0002.
- **Redpanda in dev:** Kafka-API-compatible single binary, no Zookeeper, fast startup. Drop-in replaceable with real Kafka in higher environments.
- **OpenSearch over Elasticsearch:** Apache 2.0 license; identical API surface for our needs. We pay no license complexity for a PoC.
- **Test-signed driver for PoC:** Production EV-cert signing adds weeks of process before the driver can load on a non-dev box. The PoC operates entirely in dev VMs where test-signing is enabled.
- **Protobuf as schema source of truth:** generated bindings into Rust (via `tonic-build`) and Python (via `grpcio-tools`). CI checks regenerated output matches committed bindings — drift is caught at PR time.

## Alternatives considered

- **Go agent.** Rejected: weaker eBPF/aya story, GC pauses are tolerable but Rust gives us deterministic resource use.
- **Node.js manager.** Rejected: pySigma is the de-facto Sigma compiler; reimplementing it would be wasted work.
- **ClickHouse instead of OpenSearch.** Better ingest perf but worse Sigma-tooling fit; OpenSearch is the path of least resistance for Sigma.
- **No kernel driver in PoC.** Rejected by user: full kernel scope is part of the v1 definition.

## Consequences

- Every kernel-driver iteration costs a VM reboot or driver reload. Plan for slow inner-loop in milestones M4–M5.
- Two language runtimes (Rust + Python) on the manager side (gRPC ingest is Python; agent is Rust). Schema discipline is mandatory.
- Flink is heavy infrastructure for a PoC; we keep the Python-consumer fallback warm in case Flink integration slips.
