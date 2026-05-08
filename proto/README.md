# Protobuf — schema source of truth

The contents of `edr/v1/` are the canonical schema for every wire format in the EDR system. Bindings for Rust and Python are generated from these files; never edit generated code, never define event shapes outside this directory.

See [ADR 0003](../docs/adr/0003-event-schema-ecs.md) for the rationale and compatibility rules.

## Files

| File | Purpose |
| --- | --- |
| `edr/v1/common.proto` | Shared types: `ProcessKey`, `Hash`, `Host`, `User`, `Severity`, `RuleAction`. |
| `edr/v1/events.proto` | `EndpointEvent` envelope and per-category payloads. |
| `edr/v1/control.proto` | `AgentService` RPCs: `HostStream` (bidi) and `Enroll`. |

## Generation

- **Rust** — generated at compile time by `agent-core/build.rs` via `tonic-build`. Output lands in `agent-core/src/proto_gen/` (gitignored).
- **Python** — M1 will add a `make proto` step using `grpcio-tools` that writes `backend/app/proto_gen/` (gitignored).
- **CI** — `buf breaking` runs against the previous main commit to enforce wire compatibility.

## Compatibility rules

- New fields use new field numbers; never reuse.
- Fields are never deleted; mark `[deprecated = true]` instead.
- Incompatible revisions become a new package (`edr.v2`).
