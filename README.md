# Vigil

Endpoint Detection and Response — agent + management plane.
Open-source under Apache 2.0; production-realistic where the upstream
tooling is free, with a clearly documented set of features (driver
code-signing, WHQL attestation, Microsoft Antimalware ELAM) that need
paid signing work to ship to a real fleet.

The name is from the *Vigiles Urbani*, Rome's professional night
watch — they patrolled, spotted threats, and responded; the closest
analog Roman society had to what an EDR does.

## What it does

* **Telemetry** — process / file / network / image / registry / DNS
  events from kernel-mode collectors. Linux uses eBPF + LSM hooks;
  Windows uses a KMDF minifilter + WFP + ETW.
* **Detection** — Sigma rules via OpenSearch percolator (~1s p95
  end-to-end), IOC matching, first-time-process anomaly detection,
  agent self-protection tamper detection.
* **Response** — kill / block process / block file / quarantine file
  via response-action commands queued from the UI or REST API.
  Actions are kernel-enforced (BPF maps on Linux, IOCTL to the
  driver on Windows).
* **Self-protection** — BPF LSM (Linux) and ObRegisterCallbacks
  (Windows) reject same-box-root attempts to kill, ptrace, debug, or
  unlink the agent. Tamper-evident audit log on the manager.
* **RBAC** — admin / analyst / viewer roles, host-group scoping,
  per-user API tokens, full audit trail with HMAC chain.

## Stack

| Layer | Tech |
|---|---|
| Agent — Linux | Rust + C (eBPF / aya) |
| Agent — Windows | Rust + C (KMDF minifilter + ETW) |
| Manager API | Python + FastAPI + SQLAlchemy |
| Storage | Postgres 16 (state) + OpenSearch 2 (telemetry) |
| Stream | Kafka (Redpanda in dev) + Python workers |
| Frontend | React + Vite + TypeScript + shadcn/ui + Tailwind |
| Wire schema | Protobuf, ECS-aligned |
| Transport | mTLS gRPC bidi |

See [`docs/adr/`](docs/adr/) for the reasoning behind each choice.

## Repository layout

```
proto/             Protobuf source of truth (edr.v1)
agent-core/        Rust crate: cross-platform agent building blocks
agent-linux/       Rust binary: Linux Vigil agent
agent-windows/     Rust binary: Windows Vigil agent
kernel-windows/    KMDF C/C++ kernel driver
backend/           FastAPI manager (REST + gRPC ingest + workers)
frontend/          React + Vite + TS + shadcn/ui
deploy/            docker-compose, systemd units, installers
docs/              Install, operator, threat model, RBAC, ADRs
tools/             Smoke tests, dev helpers
```

## Get started

```bash
git clone https://github.com/isom21/vigil-edr.git
cd vigil-edr
```

Then follow [`docs/install.md`](docs/install.md) — single document
covering manager bring-up, enrollment-token generation, and Linux +
Windows agent installation.

For day-to-day operations after install, see
[`docs/operator-guide.md`](docs/operator-guide.md).

## What's not included

This release runs end-to-end on test-signed Windows drivers and
unsigned Linux binaries. Three pieces of paid signing work are needed
to ship into a production Windows fleet without test-signing or
operator escape hatches:

1. **Authenticode signing** of `vigil-agent.exe` and `vigil.sys` with an
   EV code-signing certificate.
2. **WHQL attestation** of `vigil.sys` via the Microsoft Hardware Dev
   Center portal so the driver loads on Secure Boot + HVCI hosts.
3. **Microsoft Antimalware ELAM** registration so the agent can
   subscribe to the `Microsoft-Windows-Threat-Intelligence` ETW
   provider for in-memory attack telemetry (manual map detection,
   AMSI bypass tradecraft, LSASS access patterns).

The codebase is structured so adding these is purely a build-side
change — no source modifications. The threat model
([`docs/threat-model.md`](docs/threat-model.md)) documents what each
of those buys.

## Reporting bugs and contributing

* **Bug reports / features**: open a GitHub issue.
* **Patches**: open a pull request.
* **Security**: see [`SECURITY.md`](SECURITY.md). Use GitHub's
  private vulnerability reporting via the repo's *Security* tab, or
  email `isom21@protonmail.com`.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
