# CLAUDE.md

> **If this is your first session on this codebase, read
> [`docs/SESSION_HANDOFF.md`](docs/SESSION_HANDOFF.md) before doing
> anything else.** It tells you where the previous session left off, how
> to restore memory from `docs/handoff/memory/`, how to bring the dev
> stack back up, and what to start on next (M4: Windows kernel driver).

## Quick orientation

EDR (Endpoint Detection and Response) PoC inspired by HarfangLab. Agent
in Rust + C (Windows kernel driver / Linux eBPF), manager in Python
FastAPI + PostgreSQL + OpenSearch + Kafka, frontend in React. mTLS gRPC
between agents and the manager. ECS-aligned protobuf schema.

| What | Where |
|---|---|
| Milestone roadmap & status | [docs/SESSION_HANDOFF.md](docs/SESSION_HANDOFF.md) |
| Architecture decisions | [docs/adr/](docs/adr/) |
| Frozen tech choices | [docs/handoff/memory/edr_stack_decisions.md](docs/handoff/memory/edr_stack_decisions.md) |
| Smoke / e2e tests | [tools/smoke/](tools/smoke/) |
| First-run quickstart | [README.md](README.md) |
| Auto-memory snapshot | [docs/handoff/memory/](docs/handoff/memory/) |

## Working agreements (read once)

- **Git commits in this repo are unsigned by local config.** The user's
  global gitconfig signs everything; this repo overrides it. Don't pass
  `-c commit.gpgsign=…`. See
  [feedback_edr_repo_gpgsign.md](docs/handoff/memory/feedback_edr_repo_gpgsign.md).
- **Plan before code on ambitious work**, even in auto mode. The user
  prefers focused design questions + a written milestone plan upfront.
  See [feedback_plan_first.md](docs/handoff/memory/feedback_plan_first.md).
- **Don't propose alternatives to the frozen stack** without flagging the
  cost. See [edr_stack_decisions.md](docs/handoff/memory/edr_stack_decisions.md).
- **Default to TOTP, not YubiKey/WebAuthn**, for any security design that
  comes up. See [feedback_no_yubikey.md](docs/handoff/memory/feedback_no_yubikey.md).

## Don't be surprised by

- Python venv must live on the Linux filesystem, not under `/mnt/d/...`
  or any other slow remote mount. See SESSION_HANDOFF §4.1.
- Cargo needs `>=1.85` (edition 2024). `rust-toolchain.toml` pins
  `channel = "stable"`.
- ADR 0004 is superseded by ADR 0005 (Sigma went from scheduled to
  realtime via OpenSearch percolator).
