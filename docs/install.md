# Installation guide

Single source of truth for standing up Vigil end-to-end:

1. [Install the manager](#1-install-the-manager) (FastAPI + Postgres + Kafka + OpenSearch + UI)
2. [Generate an enrollment token](#2-generate-an-enrollment-token)
3. [Install the Linux agent](#3-install-the-linux-agent)
4. [Install the Windows agent](#4-install-the-windows-agent)
5. [Verify](#5-verify)

If you only need to operate an already-running deployment (triage
alerts, queue commands, decommission hosts), see
[`operator-guide.md`](operator-guide.md) instead.

## Prerequisites

| Component | Version |
|---|---|
| Docker + Docker Compose | 24.0+ |
| Rust toolchain | 1.85+ (pinned in `rust-toolchain.toml`) |
| Python | 3.12+ |
| Node | 20+ |
| Postgres (host or container) | 16 |
| OpenSearch | 2.x |
| Kafka-API broker | Redpanda recommended for dev; any modern Kafka works |

The agents add OS-specific requirements:

* **Linux agent**: kernel 5.15+ with `CONFIG_BPF_LSM=y` and BTF
  available at `/sys/kernel/security/lsm` (Ubuntu 22.04+, Debian 12+,
  RHEL/Rocky/Alma 9+ all qualify out of the box).
* **Windows agent**: Windows 10 21H2+ or Server 2019+ as the endpoint;
  the kernel driver must be either WHQL-signed (production path) or
  loaded under `bcdedit /set testsigning on` (lab path).

## 1. Install the manager

The manager runs five long-lived processes plus the supporting
infrastructure. For dev / single-host installs, `docker compose`
brings up Postgres + Redpanda + OpenSearch; the FastAPI manager and
its workers run on the host.

### 1.1 Bring up infrastructure

```bash
git clone https://github.com/isom21/vigil-edr.git
cd vigil-edr

make infra-up           # Postgres + Redpanda + OpenSearch + Flink
make infra-bootstrap    # creates Kafka topics
```

Services exposed on the host:

| Service | URL |
|---|---|
| Postgres | `localhost:5432` (user `edr`, db `edr`) |
| Redpanda Kafka | `localhost:19092` |
| Redpanda Console | http://localhost:8080 |
| OpenSearch | http://localhost:9200 |
| OpenSearch Dashboards | http://localhost:5601 |

### 1.2 Configure the backend

```bash
cd backend
python -m venv ~/edr-venvs/backend           # keep the venv on a Linux fs
source ~/edr-venvs/backend/bin/activate
pip install -e '.[dev]'

cp .env.example .env
$EDITOR .env                                  # see "Required env" below
```

Required env (`backend/.env`):

```
VIGIL_PG_DSN=postgresql+asyncpg://edr:<password>@localhost:5432/edr
VIGIL_KAFKA_BROKERS=localhost:19092
VIGIL_OPENSEARCH_URL=http://localhost:9200
VIGIL_SECRET_KEY=<generate via: openssl rand -hex 32>
VIGIL_AUDIT_HMAC_KEY=<generate via: openssl rand -hex 32>
```

`VIGIL_SECRET_KEY` signs JWTs. `VIGIL_AUDIT_HMAC_KEY` activates the
tamper-evident audit log chain. Both must be at least 16 bytes; once
set, do not rotate without a maintenance window — rotating
`VIGIL_AUDIT_HMAC_KEY` invalidates every existing audit row's HMAC.

### 1.3 Apply the database schema

```bash
alembic upgrade head
```

This is also the migration that activates the audit-log INSERT-only
privileges and the M12.f HMAC chain columns.

### 1.4 Create the first admin user

```bash
python -m scripts.create_admin \
  --email admin@example.local \
  --password 'change-me-please-12chars'
```

### 1.5 Generate the manager TLS certificate authority

The manager mints client certificates for every enrolled agent during
the REST enrollment flow. The CA itself can be either operator-supplied
(production) or auto-generated on first start (dev / lab).

For a dev / single-host install, the auto-generation is fine: the
backend will lazily create the CA in `VIGIL_CA_DIR` (default
`backend/data/ca/`) on first call to the enrollment endpoint, and
persist it there.

For production:

```bash
mkdir -p /var/lib/vigil-ca
openssl genrsa -out /var/lib/vigil-ca/ca.key 4096
openssl req -x509 -new -nodes -key /var/lib/vigil-ca/ca.key -sha256 \
  -days 3650 -subj "/CN=Vigil Manager CA" -out /var/lib/vigil-ca/ca.crt
chmod 600 /var/lib/vigil-ca/ca.key
```

Then set in `.env`:

```
VIGIL_CA_DIR=/var/lib/vigil-ca
```

### 1.6 Start the manager processes

Each in its own shell, from the repo root:

```bash
make backend-dev          # FastAPI REST API (:8000)
make backend-grpc         # gRPC ingest for agents (:50051)
make backend-normalizer   # telemetry.raw -> telemetry.normalized
make backend-indexer      # telemetry.normalized -> OpenSearch
make backend-detector     # IOC detector
make backend-sigma        # realtime Sigma percolator
make backend-anomaly      # first-time-process anomaly detector
make backend-tamper       # agent self-protection tamper alerter
make backend-silence      # agent-silence alerter
```

For long-running deployments, use a systemd unit per process or a
process supervisor (supervisord, systemd, k8s deployment). A reference
`systemd/` set of unit files lives under `deploy/`.

### 1.7 Start the UI

```bash
cd frontend
npm install
npm run dev      # http://localhost:5173 (dev)
# or for production:
npm run build && npm run preview
```

The dev server proxies `/api/*` to `localhost:8000`.

Sign in with the admin you created in 1.4.

## 2. Generate an enrollment token

Each agent needs a one-time enrollment token to bootstrap. Mint one
through the UI or the API.

### Via the UI

Sign in as an admin → **Enrollment** → **New token** → copy the
`enr_…` value (you only see it once).

### Via the API

```bash
TOKEN=$(curl -s "$MANAGER_REST/api/auth/login" -X POST \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.local","password":"<password>"}' \
  | jq -r .access_token)

curl -s "$MANAGER_REST/api/enrollment/tokens" -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"description":"prod-laptop-04","expires_in_hours":24}' \
  | jq -r .token
```

Tokens are single-use: once an agent enrolls with one, it's marked
spent. Re-enrolling the same host requires a fresh token.

## 3. Install the Linux agent

### 3.1 Build the .deb / .rpm

From the repo root, on a Linux build host with `cargo install
cargo-deb cargo-generate-rpm`:

```bash
make agent-linux-deb       # writes target/debian/vigil-agent_*.deb
make agent-linux-rpm       # writes target/generate-rpm/vigil-agent-*.rpm
```

### 3.2 Install on the endpoint

Debian / Ubuntu:

```bash
sudo apt-get install -y /tmp/vigil-agent_1.0.0-1_amd64.deb
```

RHEL / Rocky / Alma:

```bash
sudo dnf install -y /tmp/vigil-agent-1.0.0-1.x86_64.rpm
```

The package creates `/etc/vigil/agent.env` from a template, sets up
`/var/lib/vigil/` for state, and registers the systemd unit
`vigil-agent.service` (disabled by default).

### 3.3 Configure & start

```bash
sudo $EDITOR /etc/vigil/agent.env
```

Set at minimum:

```
VIGIL_MANAGER_ENDPOINT=https://manager.example.com:50051
VIGIL_MANAGER_REST=https://manager.example.com:8000
VIGIL_ENROLLMENT_TOKEN=enr_<token-from-section-2>
```

Optional:

```
VIGIL_HOSTNAME=<override>            # default: kernel's hostname
VIGIL_STATE_DIR=/var/lib/vigil         # default
VIGIL_DISABLE_SELF_PROTECTION=1      # only set if BPF LSM unavailable
VIGIL_DISABLE_FILE_HASHING=1         # cuts CPU at the cost of file IOC matching
```

Then:

```bash
sudo systemctl enable --now vigil-agent
sudo journalctl -u vigil-agent -f         # watch enrollment + first telemetry
```

The agent enrolls with the manager, receives a client certificate,
persists it in `/var/lib/vigil/identity/`, and starts streaming events
over mTLS gRPC.

## 4. Install the Windows agent

### 4.1 Build the agent + driver

On a Windows lab box (or a self-hosted runner), with the WDK 10 +
Visual Studio Build Tools installed:

```powershell
# Driver — produces vigil.sys + vigil.cat + vigil.inf
cd kernel-windows
.\build.ps1

# Agent — produces vigil-agent.exe
cd ..
cargo build -p agent-windows --release --target x86_64-pc-windows-msvc
```

For the kernel driver, you have three signing options:

* **Production**: WHQL-attested via the Microsoft Hardware Dev Center
  portal. Requires an EV code-signing certificate. The driver loads
  on Secure Boot machines without any extra steps.
* **Cross-signed**: an EV code-signing certificate + a kernel-mode
  signing flow. Works on Windows 10 1607+ but not on Server 2019+
  with HVCI.
* **Test-signing**: zero-cost lab path. The endpoint must boot with
  `bcdedit /set testsigning on`; cleartext "Test Mode" appears on the
  desktop. Use only in non-production.

### 4.2 Package & deploy

The build output ships as a ZIP:

```powershell
.\packaging\windows\make-package.ps1
# produces vigil-windows-1.0.0.zip
```

On the endpoint, elevated PowerShell:

```powershell
# Test-signing path only (skip on production):
bcdedit /set testsigning on
Restart-Computer

# Then:
Expand-Archive -Path .\vigil-windows-1.0.0.zip -DestinationPath C:\edr
cd C:\edr\vigil-windows-1.0.0
.\install-vigil.ps1
```

The installer:

1. Copies `vigil.sys` to `%SystemRoot%\System32\drivers\`.
2. Registers and starts the `edr` kernel service.
3. Installs the agent at `%ProgramFiles%\Vigil\vigil-agent.exe`.
4. Creates `%ProgramData%\Vigil\agent.env` from a template.
5. Registers the agent as a Windows service (`vigil-agent`, manual
   start by default).

### 4.3 Configure & start

```powershell
notepad %ProgramData%\Vigil\agent.env
```

Set:

```
VIGIL_MANAGER_ENDPOINT=https://manager.example.com:50051
VIGIL_MANAGER_REST=https://manager.example.com:8000
VIGIL_ENROLLMENT_TOKEN=enr_<token-from-section-2>
```

Then:

```powershell
Start-Service edr           # kernel driver
Start-Service vigil-agent     # userspace agent

# Watch the first enrollment:
Get-EventLog -LogName Application -Source 'vigil-agent' -Newest 50
```

For service start at boot, change the start type:

```powershell
Set-Service -Name vigil-agent -StartupType Automatic
```

## 5. Verify

After the agent finishes enrolling, you should see:

1. **In the UI** — Hosts → search by hostname → the row appears with
   status `online` and `last_seen_at` ticking.
2. **In OpenSearch** — `telemetry-*` index has events with that
   `host.id`. Try:
   ```
   curl -s "$OS_URL/telemetry-*/_search?q=event.kind:process_started&size=5"
   ```
3. **In `/metrics`** — agent exposes `127.0.0.1:9101/metrics` showing
   `edr_agent_bpf_*` counters incrementing on Linux.

For a structured smoke run, use the scripts under `tools/smoke/`:

```bash
tools/smoke/00-backend-smoke.sh         # REST surface
tools/smoke/10-grpc-smoke.py            # gRPC ingest
tools/smoke/20-agent-ioc-e2e.sh         # IOC detector
tools/smoke/30-sigma-realtime-e2e.sh    # Sigma percolator
tools/smoke/45-self-protection-linux.sh # BPF LSM hooks
```

For Windows-specific verification, the
`tools/smoke/46-self-protection-windows.ps1` script exercises the
driver's ObCallback handle-stripping.

## Where to go next

* [`operator-guide.md`](operator-guide.md) — daily operations: triage
  alerts, queue response actions, manage host groups, decommission.
* [`rbac.md`](rbac.md) — roles, host groups, audit log, API tokens.
* [`threat-model.md`](threat-model.md) — what the agent defends
  against and the explicit gaps.
* [`agent-update-protocol.md`](agent-update-protocol.md) — how
  agents discover updates and verify them.
* [`adr/`](adr/) — architecture decision records.
