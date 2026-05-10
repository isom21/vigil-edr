# CLAUDE.md

Working notes for Claude when contributing to this repo. Humans should
start at [`README.md`](README.md) and [`docs/install.md`](docs/install.md).

## Quick orientation

EDR (Endpoint Detection and Response) — agent + management plane,
Apache 2.0. Agent in Rust + C (Windows kernel driver / Linux eBPF),
manager in Python FastAPI + Postgres + OpenSearch + Kafka, frontend in
React. mTLS gRPC between agents and the manager. ECS-aligned protobuf
schema.

| What | Where |
|---|---|
| Install (manager + agents) | [docs/install.md](docs/install.md) |
| Day-to-day operations | [docs/operator-guide.md](docs/operator-guide.md) |
| Threat model | [docs/threat-model.md](docs/threat-model.md) |
| RBAC + audit + tokens | [docs/rbac.md](docs/rbac.md) |
| Architecture decisions | [docs/adr/](docs/adr/) |
| Smoke / e2e tests | [tools/smoke/](tools/smoke/) |

## Working agreements

- **Plan before code on ambitious work**, even in auto mode. Open with
  focused design questions and a written plan; only start writing code
  once the user confirms direction.
- **Don't propose alternatives to the frozen stack** without flagging
  the cost. The stack choices live in
  [`docs/adr/0001-stack-selection.md`](docs/adr/0001-stack-selection.md).
- **Default to TOTP, not YubiKey/WebAuthn** for any 2FA design that
  comes up — the project targets solo-developer / small-team operations.
- **Git commits in this repo are unsigned.** The user's global
  gitconfig signs everything; this repo overrides locally. Don't pass
  `-c commit.gpgsign=…`.

## Don't be surprised by

- Python venv must live on the Linux filesystem, not under `/mnt/d/...`
  or any other slow remote mount.
- Cargo needs `>=1.85` (edition 2024). `rust-toolchain.toml` pins
  `channel = "stable"`.
- ADR 0004 is superseded by ADR 0005 (Sigma went from scheduled to
  realtime via OpenSearch percolator).
- The Linux agent's BPF programs and pinned maps live under
  `/sys/fs/bpf/edr/`; if a previous agent crashed, the next one runs
  `cleanup_or_takeover` to claim them rather than refusing to start.
- The audit log is INSERT-only at the DB role level (REVOKE UPDATE,
  DELETE, TRUNCATE) and tamper-evident via an HMAC chain keyed off
  `EDR_AUDIT_HMAC_KEY`. Don't try to "fix" rows by UPDATE; insert
  compensating rows instead.

## Optional commercial signing

Authenticode + WHQL + Microsoft Antimalware ELAM are needed to ship
to production Windows fleets without test-signing. See
[`README.md`](README.md) "What's not included" for the rationale and
[`docs/threat-model.md`](docs/threat-model.md) for what each buys.
