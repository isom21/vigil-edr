# Session handoff — read this first if you're a fresh Claude instance

The previous session was migrated to a new host so the user can wire a
Windows VM into the loop for M4. This document is the bridge: it tells you
where we are, what's next, what tribal knowledge applies, and how to bring
the local environment back up.

---

## 1. State at handoff

**Milestone progress:** M0–M3.5 are done and verified end-to-end on Linux.
M2.3c (Windows ETW agent) is written but uncompiled — needs the Windows
VM to actually link. The next milestone is **M4: Windows kernel driver
(KMDF + minifilter)**.

```
M0  Foundations / scaffolding ............................  done
M1  Backend core + UI shell + enrollment CA ..............  done
M2  Agent thin slice (Linux: working; Windows: skeleton) .  done
M3  Sigma pipeline ...
    M3.1 normalizer + indexer + detector workers .........  done
    M3.2 sigma_scheduler (legacy, 30-60s latency) ........  done
    M3.3 ADR 0004 ........................................  done
    M3.5 sigma_realtime via OpenSearch percolator
         (~1s end-to-end latency; replaces 3.2) ..........  done
M4  Windows kernel driver (KMDF + minifilter) ............  next
M5  Response actions (kill / block) ......................
M6  Linux agent (eBPF / aya) .............................
M7  Polish, self-protection, installers, RBAC ............
```

**Last verified pipeline:** Linux agent (Rust, /proc-poll) → gRPC mTLS →
Kafka `telemetry.raw` → normalizer → `telemetry.normalized` → {indexer,
detector, sigma_realtime} → alerts in PG + `alerts-YYYYMMDD` in OpenSearch.
Sigma realtime alert latency measured at **~1.1s** (bottleneck is the
agent's 1s `/proc` poll, not the Sigma path).

**Git history:** `git log --oneline` shows commits `M0` through `M3.5:
Sigma realtime via OpenSearch percolator`. ADRs are in
[`docs/adr/`](adr/) — read them in order; 0004 is superseded by 0005.

## 2. What's expected from a fresh instance

When the user resumes:

1. **Restore memory** — see §3 below. The repo carries a snapshot of every
   memory file the previous session wrote. Copy them into your local
   memory dir before doing anything else.
2. **Bring up the stack** — see §4. The user may already have done this;
   ask before assuming.
3. **Confirm where the user wants to go.** Default assumption: start M4.
   Don't auto-execute — see [`feedback_plan_first.md`](handoff/memory/feedback_plan_first.md).

## 3. Memory restoration

All memory files written by the previous session are mirrored into
[`handoff/memory/`](handoff/memory/). They were originally at
`/home/john/.claude/projects/-mnt-d-priv-code/memory/` on the previous
host; on the new host the path will be different (Claude Code derives the
memory dir from the project path).

**Restoration recipe:**

```bash
# Find this Claude instance's memory dir for this project. It's typically:
#   ~/.claude/projects/<flattened-cwd>/memory/
# where <flattened-cwd> is the project's working directory with / -> -.
# If unsure, write any memory once via the auto-memory system and look
# for the path it uses.

MEMORY_DIR="<resolved memory dir for this host>"
mkdir -p "$MEMORY_DIR"
cp -v docs/handoff/memory/*.md "$MEMORY_DIR/"
```

Read each file. The most important ones for picking up where the previous
session left off:

| File | Why it matters |
|---|---|
| [user_role.md](handoff/memory/user_role.md) | Tone, technical depth, what NOT to over-explain. |
| [edr_project.md](handoff/memory/edr_project.md) | Project requirements (frozen). |
| [edr_stack_decisions.md](handoff/memory/edr_stack_decisions.md) | Frozen tech choices. Don't propose alternatives without flagging. |
| [feedback_plan_first.md](handoff/memory/feedback_plan_first.md) | Plan before code on ambitious work — overrides auto-mode. |
| [feedback_edr_repo_gpgsign.md](handoff/memory/feedback_edr_repo_gpgsign.md) | This repo has gpgsign disabled locally; commit normally. |
| [feedback_no_yubikey.md](handoff/memory/feedback_no_yubikey.md) | Default to TOTP for personal-project security designs. |
| [edr_cloudlab_project.md](handoff/memory/edr_cloudlab_project.md) | Sibling project at `/mnt/d/priv/code/edr-cloudlab/` (planning docs only; no infra yet). Infomaniak Public Cloud + Tailscale. |
| [infomaniak_no_nested_virt.md](handoff/memory/infomaniak_no_nested_virt.md) | Infomaniak doesn't expose VT-x/SVM. Affects Hyper-V plans for the Windows VM if the user later moves the VM to Infomaniak. |

## 4. Bringing the stack back up on a new host

The previous instance's environment was a WSL2 Linux 6.6 box on the
user's laptop. The new host is wherever the user is now — the procedure
is the same.

### 4.1 Critical WSL2 / cloud-VM gotcha (still applies anywhere with a slow FS)

**The Python venv must NOT live on `/mnt/d/...` (or any 9P / NFS / SMB
mount).** First run was unworkably slow until we moved it to the Linux
filesystem. Recipe:

```bash
mkdir -p ~/edr-venvs
python3 -m venv ~/edr-venvs/backend
source ~/edr-venvs/backend/bin/activate
pip install -e '/path/to/edr/backend[dev]'
```

Same warning for the npm node_modules if running on a slow mount: keep
the `frontend/` checkout on the Linux fs, or symlink `node_modules` to a
Linux-fs cache dir.

### 4.2 First-run quickstart

```bash
# 1. Infra
cd /path/to/edr
make infra-up
make infra-bootstrap          # creates Kafka topics

# 2. Backend Python deps (venv on Linux fs, see 4.1)
python3 -m venv ~/edr-venvs/backend
source ~/edr-venvs/backend/bin/activate
pip install -e './backend[dev]'   # picks up psycopg[binary], pydantic[email], aiohttp etc.
cd backend && cp .env.example .env
alembic upgrade head
python -m scripts.create_admin --email admin@example.local --password 'change-me-please-12chars'
cd ..

# 3. Generate Python protobuf bindings (Rust regenerates them at build time)
make proto

# 4. Build the Linux agent
cargo build -p agent-linux --release

# 5. Frontend (only if you want the UI right away)
cd frontend && npm install && npm run dev   # http://localhost:5173
cd ..

# 6. Pipeline workers — one per shell, all from repo root:
make backend-dev          # FastAPI REST :8000
make backend-grpc         # gRPC ingest :50051
make backend-normalizer   # telemetry.raw -> telemetry.normalized
make backend-indexer      # telemetry.normalized -> OpenSearch
make backend-detector     # IOC matching
make backend-sigma        # Sigma realtime (percolator). Aggregation rules: backend-sigma-scheduled
```

### 4.3 Verification

After §4.2 the smoke tests in [`tools/smoke/`](../tools/smoke/) should all
pass. See that directory's README for the run order.

```bash
tools/smoke/00-backend-smoke.sh
PYTHONPATH=backend python tools/smoke/10-grpc-smoke.py
tools/smoke/20-agent-ioc-e2e.sh
tools/smoke/30-sigma-realtime-e2e.sh
```

## 5. Tribal knowledge / fix-once gotchas

These were debugged in the previous session and are worth knowing in
advance:

- **WSL `/mnt/d` venv** — see §4.1.
- **`psycopg[binary]`, `pydantic[email]`, `aiohttp`** — all in
  `backend/pyproject.toml` already. They were each missing in the
  original M0 commit and added during M1's first smoke. If a fresh
  install hits `ModuleNotFoundError: psycopg` or similar, re-check
  `pip install -e './backend[dev]'` ran in the right venv.
- **Email field in API/login is plain `str`, not `EmailStr`** — pydantic
  rejects `.local` / `.test` / `example.com` domains, which broke dev
  login. Don't switch back without changing dev creds first.
- **SQLAlchemy enum mapping** — use `pg_enum()` from `app/models/base.py`.
  Without `values_callable`, SA sends the Python member *name* (`ADMIN`)
  to PG, not the value (`admin`).
- **Cargo toolchain** — must be `>=1.85` (edition 2024 stabilized in
  1.85). `rust-toolchain.toml` pins `channel = "stable"`. `1.82` was the
  initial pin but couldn't compile modern crates.
- **`protoc` for Rust build** — vendored via `protoc-bin-vendored` in
  `agent-core/build.rs`. No system `protoc` install needed.
- **rustls in agents** — both `agent-linux/src/main.rs` and
  `agent-windows/src/main.rs` call
  `rustls::crypto::ring::default_provider().install_default()` early in
  `main`. rustls 0.23 stopped auto-selecting a provider.
- **aiokafka compression** — uses `gzip`, not `lz4`. `lz4` requires the
  `python-lz4` extra; `gzip` is in stdlib.
- **gRPC TLS for percolator etc.** — manager server cert is signed by
  the same internal CA that signs agent client certs (single trust
  anchor). See `services/ca.py::get_or_issue_server_cert`.
- **OpenSearch sigma-rules index** — the percolator index. The previous
  session uses `dynamic="strict"` and a 1s refresh interval. Schema is
  in `services/opensearch.py::_SIGMA_INDEX_BODY`. Field shapes mirror
  `telemetry-*` so registered Lucene queries work the same as the live
  events they percolate against.

## 6. M4 starting point (next milestone)

Per [edr_project.md](handoff/memory/edr_project.md), M4 is the **Windows
kernel driver (KMDF + minifilter)**. Per
[edr_stack_decisions.md](handoff/memory/edr_stack_decisions.md):

- Targets: Win10 22H2 + Win11
- Driver signing for the PoC: **test-signed** in dev VMs (`bcdedit /set
  testsigning on`), not production EV signing
- Source lives in `kernel-windows/` (currently empty — only stub from M0)

The user's first task on the new host is to confirm Windows VM access
works (the reason for the migration). If they haven't already wired the
new Claude instance into the VM, ask whether to:

1. Plan M4 in detail first (driver layout, callbacks, IOCTL channel,
   user-mode ↔ driver IPC, signing setup), or
2. Start with M2.3c verification — actually compile and run
   `agent-windows` on the VM. Several `ferrisetw` API calls are best-
   guess and may need touch-ups when first compiled on Windows.

Recommended order: M2.3c first (cheap to verify, validates the toolchain
+ build pipeline + agent enrollment over the network), then plan M4.

## 7. Outstanding context bits

- **`agent-windows` was never compiled.** All code is in the repo; we
  expected `ferrisetw` API specifics to need adjustment when actually
  built. See `agent-windows/src/etw.rs` callsites.
- **Scheduled Sigma still ships** as `make backend-sigma-scheduled`. We
  swapped to realtime in M3.5 but kept the scheduler for future
  aggregation rules (count-of, time-window) which the percolator can't
  evaluate — see [ADR 0005](adr/0005-sigma-realtime-percolator.md)
  trade-offs.
- **`alerts.raw` Kafka topic** is provisioned but unused since M3.5. Keep
  it; future engines may consume it.
- **`/tmp/edr-*` scripts from the previous session are gone** — they were
  the source for `tools/smoke/`. Use the in-repo ones.
- **Sibling project `edr-cloudlab/`** at `/mnt/d/priv/code/edr-cloudlab/`
  is unrelated to M4. Read its docs only if the user asks about cloud
  infra. Status: planning docs done, infra scaffolding empty.

## 8. House style summary

These are condensed from the previous session's working notes. They
reflect the user's preferences as observed:

- Production-realistic over PoC shortcuts. The user picked the harder
  option every time we offered a fork (Rust agent, mTLS, full kernel
  scope, Kafka instead of Redis, ECS schema). Don't propose
  simplifications without flagging trade-offs.
- Don't over-explain ETW, eBPF, Kafka, mTLS, Lucene, etc. The user knows
  these.
- For substantive design questions, lead with a recommendation in 2-3
  sentences, then list 2-3 alternatives with one-line trade-offs each.
  See the M3.5 conversation for the pattern.
- Commits are focused per milestone (e.g. M2.1 / M2.2 / M2.3 are
  separate). Keep that going.
- ADRs supersede via new entries (0004 → 0005), not edits in place.
