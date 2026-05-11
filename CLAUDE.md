# CLAUDE.md

Working notes for Claude when contributing to this repo. Humans should
start at [`README.md`](README.md) and [`docs/install.md`](docs/install.md).

## Quick orientation

Vigil — Endpoint Detection and Response, agent + management plane,
Apache 2.0. Agent in Rust + C (Windows kernel driver / Linux eBPF),
manager in Python FastAPI + Postgres + OpenSearch + Kafka, frontend
in React. mTLS gRPC between agents and the manager. ECS-aligned
protobuf schema.

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
- When working on the web UI, use the `look` tool from the `browser-eyes` MCP
  to see the current state of my browser. Call it after each visible change and whenever you suspect a console error.


## Don't be surprised by

- Python venv must live on the Linux filesystem, not under `/mnt/d/...`
  or any other slow remote mount.
- Cargo needs `>=1.85` (edition 2024). `rust-toolchain.toml` pins
  `channel = "stable"`.
- ADR 0004 is superseded by ADR 0005 (Sigma went from scheduled to
  realtime via OpenSearch percolator).
- The Linux agent's BPF programs and pinned maps live under
  `/sys/fs/bpf/vigil/`; if a previous agent crashed, the next one runs
  `cleanup_or_takeover` to claim them rather than refusing to start.
- The audit log is INSERT-only at the DB role level *and* tamper-
  evident via an HMAC chain. The role split: `audit_log` is owned by
  `vigil_audit_writer`; the manager's runtime user `vigil_manager` is non-
  superuser and has only SELECT + INSERT. Superusers bypass GRANT/
  REVOKE checks, which is why the dev docker-compose now bootstraps
  as `postgres` (the cluster superuser) and an init script creates
  `vigil_manager` separately. Setup details: `deploy/postgres-init.sql` +
  migration `c41d5b7e9f02` (M16.a fixed). The HMAC chain is keyed off
  `VIGIL_AUDIT_HMAC_KEY`; rotation requires a manager restart and
  invalidates every row written under the old key. Don't try to "fix"
  rows by UPDATE — the runtime user can't, and the verifier would
  catch it anyway. Insert compensating rows instead.

## Optional commercial signing

Authenticode + WHQL + Microsoft Antimalware ELAM are needed to ship
to production Windows fleets without test-signing. See
[`README.md`](README.md) "What's not included" for the rationale and
[`docs/threat-model.md`](docs/threat-model.md) for what each buys.
