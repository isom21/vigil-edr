# Architecture Decision Records

ADRs document non-obvious decisions and the reasoning behind them. New ADRs are numbered sequentially and added here.

| # | Title | Status |
|---|---|---|
| [0001](0001-stack-selection.md) | Technology stack selection | Accepted (Sigma row superseded by 0005 via 0004) |
| [0002](0002-agent-comms-and-enrollment.md) | Agent ↔ manager communication and enrollment | Accepted |
| [0003](0003-event-schema-ecs.md) | Event schema: ECS-aligned, protobuf source of truth | Accepted |
| [0004](0004-sigma-scheduled-correlation.md) | Sigma evaluation via scheduled OpenSearch correlation | Superseded by 0005 |
| [0005](0005-sigma-realtime-percolator.md) | Sigma evaluation: realtime via OpenSearch percolator | Accepted |
| [0006](0006-testing-strategy.md) | Testing strategy (static / integration / smoke / mutation) | Accepted |
| [0007](0007-multi-tenancy.md) | Multi-tenancy via shared schema + row-level `tenant_id` | Accepted |
| [0008](0008-redis-ha.md) | Redis as a shared dependency, with HA pattern | Accepted |
| [0009](0009-ai-llm-trust-boundary.md) | AI / LLM features as untrusted, sandboxed advisors | Accepted |
| [0010](0010-tpm-attestation.md) | TPM-backed boot-state attestation | Accepted |

## Format

Each ADR has: status, date, context, decision, rationale, alternatives, consequences. Keep them short — pages, not chapters. If a decision is reversed, write a new ADR that supersedes the old one rather than editing in place.
