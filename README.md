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

Phase-grouped feature index. Each line links to the operator runbook
section that covers day-to-day use.

**Telemetry + detection (Phase 0 / M-series)**

* **Kernel-mode telemetry** — process / file / network / image /
  registry / DNS events. Linux: eBPF + LSM hooks. Windows: KMDF
  minifilter + WFP + ETW.
* **Sigma realtime detection** — OpenSearch percolator, ~1s p95
  end-to-end ([operator-guide → Detection workflow](docs/operator-guide.md#detection-workflow)).
  ADR 0005 documents the move from scheduled to realtime.
* **Sigma rule packs** — 25-rule starter pack + 51-rule curated v2 +
  identity-attack pack shipped in `backend/rule_packs/`.
* **IOC matching, first-time-process anomaly, agent tamper detection**.
* **Response actions** — `alert` / `block` / `quarantine` (kernel-
  enforced via BPF maps on Linux, IOCTL to the driver on Windows).
* **MITRE ATT&CK + Navigator JSON** export for fleet coverage.
* **RBAC** — admin / analyst / viewer + host-group scoping. Tamper-
  evident audit log (HMAC chain + INSERT-only DB role).

**Phase 1 — alerts + identity (#1.x)**

* **Alert dedup sliding-window** + **incidents** (cross-rule grouping,
  process-tree-aware).
* **Alert routing** to Slack, PagerDuty, SMTP ([operator-guide → Notifications](docs/operator-guide.md#notifications)).
* **OIDC SSO** + **TOTP 2FA** (TOTP takes precedence — see
  [install.md → OIDC SSO](docs/install.md#oidc-sso)).
* **Live response terminal** (TerminalStream + xterm.js).
* **Network isolation** — BPF allowlist + Windows WFP.
* **Redis HA** — rate-limit / alert broker / login throttle.
* **SIEM forwarders** — syslog/CEF, Splunk HEC, Microsoft Sentinel.
* **Threat intel** — TAXII 2.1 + abuse.ch CSV + custom JSON.

**Phase 2 — detection breadth + jobs engine (#2.x)**

* **In-memory YARA scanner** (`memory_yara_v1`).
* **Sequence / behavioural rules** — multi-step YAML detections.
* **Auth-event capture** — ETW + auditd.
* **Process correlation graph** + **vulnerability assessment** (NVD).
* **Application allowlist** — per-host-group SHA-256 enforce mode.
* **Container enrichment** + **triage forensic acquisition jobs**.
* **Hunt workbench** + saved hunts (scheduler + alert-on-hit).
* **DNS sinkhole** ([operator-guide → DNS block](docs/operator-guide.md#dns-block-list)).

**Phase 3 — multi-tenancy + automation (#3.x)**

* **Multi-tenancy** — every tenant-scoped resource has a `tenant_id`
  column + RBAC gate ([operator-guide → Multi-tenancy](docs/operator-guide.md#multi-tenancy)).
* **Archive ILM + S3 cold tier**.
* **Agent rollout cohorts** + auto-rollback.
* **Dashboards** — operator-authored widget grids.
* **Playbooks** — YAML response chains ([operator-guide → Playbooks](docs/operator-guide.md#playbooks)).
* **Case sync** — Jira + ServiceNow.
* **Webhooks** — HMAC-signed outbound delivery.
* **SCIM 2.0** — IdP-provisioned users.
* **USB device control**.

**Phase 4 — AI / cloud / honeytokens (#4.x)**

* **AI LLM summary + NL→query** (Ollama by default).
* **IAM CloudTrail anomaly detection**.
* **Okta + Azure AD identity-source telemetry**.
* **Cuckoo detonation** with auto-IOC feedback.
* **Honeytoken decoys** (credential + file + registry).
* **TPM-backed boot-state attestation** (Linux active; Windows pending
  Tbsi — see [the "What's not included" section](#whats-not-included)).

**Self-protection + audit trail**

* **BPF LSM self-protection (Linux)** — kill, ptrace, /proc/<pid>/mem,
  bpffs unlink, agent_self hijack all blocked from non-self callers.
* **ObRegisterCallbacks self-protection (Windows)** — taskkill,
  Stop-Process, raw `TerminateProcess` all rejected; non-self processes
  unaffected.
* **Tamper-evident audit log** — HMAC chain + INSERT-only DB role
  (`vigil_audit_writer`); per-tenant chain verifier exposes a
  fingerprint of the active key.

## Stack

| Layer | Tech |
|---|---|
| Agent — Linux | Rust + C (eBPF / aya) |
| Agent — Windows | Rust + C (KMDF minifilter + ETW) |
| Manager API | Python + FastAPI + SQLAlchemy |
| Storage | Postgres 16 (state) + OpenSearch 2 (telemetry) + MinIO (artifact / snapshot blobs) |
| Stream | Kafka (Redpanda in dev) + Python workers |
| Cache + brokering | Redis 7 (rate limits, cross-process locks, short-lived caches, cache-invalidation pub/sub) |
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

One-liner:

```bash
git clone https://github.com/isom21/vigil-edr.git && cd vigil-edr && ./install.sh && make up
```

Or the same broken out:

```bash
git clone https://github.com/isom21/vigil-edr.git
cd vigil-edr
./install.sh
make up
```

`install.sh` handles infra, venv, dependencies, secret generation,
migrations, the first admin user, and frontend deps. It's idempotent.
`make up` starts every backend worker plus the frontend dev server
under one supervisor.

After `make up` you can sign in at <http://localhost:5173> with the
credentials `install.sh` printed.

**OIDC SSO**: bootstrap with `./install.sh --with-oidc` (or set
`VIGIL_INSTALL_WITH_OIDC=1`) to prompt for the IdP issuer + client
credentials. The sign-in page renders an SSO button when
`/api/auth/oidc/discovery` reports `enabled=true`. See
[install.md → OIDC SSO](docs/install.md#oidc-sso) for the full setup
including the Keycloak / Okta example and the TOTP-still-required
post-OIDC flow.

[`docs/install.md`](docs/install.md) covers the manual flow,
production deployment, and Linux + Windows agent enrollment. Day-to-day
operations are in [`docs/operator-guide.md`](docs/operator-guide.md).

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
