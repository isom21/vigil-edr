# ADR 0003 — Event schema: ECS-aligned, protobuf source of truth

- **Status:** Accepted
- **Date:** 2026-05-08

## Context

Every component of the system reads or writes telemetry events: agents produce them, the gRPC ingest accepts them, Kafka transports them, the normalizer canonicalizes them, OpenSearch indexes them, Flink evaluates Sigma against them, the UI renders them, and analysts query them.

Schema drift between any two of those is catastrophic — Sigma rules silently miss matches, the UI shows blank fields, analysts lose trust.

## Decision

1. **The protobuf files in `proto/edr/v1/` are the single source of truth.** No component defines its own event shape. Bindings are generated:
   - Rust (agent): via `tonic-build` in `agent-core/build.rs`.
   - Python (backend): via `grpcio-tools` (M1) into `backend/app/proto_gen/`.
   - TypeScript (frontend): only telemetry *views* are rendered, generated as needed.
   - Flink (Sigma jobs): consume Kafka via the Python or Java protobuf bindings.

2. **Field naming follows ECS** (Elastic Common Schema). Where ECS dot-notation maps awkwardly to protobuf (`process.parent.executable`), nested protobuf messages reproduce the structure (`ProcessEvent.parent.executable`). Helpers in the normalizer flatten to ECS dot-notation before indexing in OpenSearch.

3. **One envelope, payload one-of.** `EndpointEvent` is the universal envelope. Concrete payload (process / file / image_load / thread / registry / network / scan) is selected by the `oneof payload` field. This keeps the wire format tight and gives every event a uniform header (host_id, event_id, timestamps, kind, category).

4. **Process identity is `(host_id, pid, start_time_ns)`.** PIDs are reused; start time disambiguates. Process tree assembly is performed server-side by joining `ProcessEvent.process` with `ProcessEvent.parent`.

5. **Timestamps are `google.protobuf.Timestamp` in events** (UTC, nanosecond resolution where the OS provides it). Flattened to ISO-8601 in OpenSearch.

6. **Protobuf compatibility rules:**
   - New fields are added with new field numbers; never reuse a number.
   - Fields are never deleted from the schema; deprecated fields are marked `[deprecated = true]` and left in place.
   - CI runs `buf breaking` against the previous main commit to enforce wire compatibility.

7. **Schema versioning** is communicated by the proto package (`edr.v1`). A future incompatible revision becomes `edr.v2` and the manager negotiates per-agent.

## Rationale

- **ECS over OCSF:** OCSF is cleaner taxonomically but Sigma backends and OpenSearch dashboards have first-class ECS support today. We can map ECS → OCSF later if needed.
- **Protobuf over JSON:** wire size matters at agent scale; strong typing prevents the "did the agent send this field or not?" class of bug; codegen for Rust + Python is mature.
- **Single envelope vs per-event RPCs:** one envelope per category would explode the gRPC service surface and complicate the ingest path. The `oneof` keeps switching simple.

## Consequences

- Adding a new event category is a three-step PR: (1) edit `events.proto`, (2) regenerate bindings in agent + backend, (3) extend the normalizer to write the new fields to OpenSearch. The CI gate prevents partial rollouts.
- Sigma rule writers target ECS field names. The supported subset
  of ECS fields per category is the set the normalizer writes —
  `backend/app/services/normalizer.py::to_ecs` is the source of
  truth; an out-of-tree `docs/schema/` index was never produced
  because the normalizer covers the same ground without the drift
  risk of a hand-maintained companion document.
- Telemetry retention is governed by OpenSearch ILM, not by Kafka topic retention. Kafka retention is sized for catch-up + replay (default 7d for normalized).
