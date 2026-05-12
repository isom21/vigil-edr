# Installation guide

The fastest path is two commands:

```bash
git clone https://github.com/isom21/vigil-edr.git
cd vigil-edr
./install.sh
make up
```

`install.sh` brings up the infra (Postgres + Redpanda + OpenSearch +
Flink), creates the backend venv, generates `backend/.env` with secure
random secrets, applies migrations, creates the first admin user,
installs frontend dependencies, and prints the URLs and admin
credentials. It's idempotent — re-running it never overwrites your
`.env` or your existing admin password.

`make up` then starts every long-running process under one supervisor
(uvicorn API, gRPC ingest, six Kafka workers, frontend dev server).
Stop it with `Ctrl-C`, or `make down` from another shell to also stop
the docker infra.

After `make up` you can sign in at <http://localhost:5173> with the
credentials install.sh printed.

The rest of this document is the manual flow — useful for production
deployments where you want explicit control over each step, or when
something in the bootstrap fails and you want to skip ahead. Each
manual step below corresponds to a step in `install.sh`, so you can
mix and match.

---

## Prerequisites

| Component | Version |
|---|---|
| Docker + Docker Compose | 24.0+ |
| Rust toolchain (agent build only) | 1.85+ (pinned in `rust-toolchain.toml`) |
| Python | 3.12+ |
| Node | 20+ |
| Postgres (host or container) | 16 |
| OpenSearch | 2.x |
| Kafka-API broker | Redpanda recommended for dev |

The agents add OS-specific requirements:

* **Linux agent**: kernel 5.15+ with `CONFIG_BPF_LSM=y` and BTF
  available at `/sys/kernel/security/lsm` (Ubuntu 22.04+, Debian 12+,
  RHEL/Rocky/Alma 9+ all qualify out of the box).
* **Windows agent**: Windows 10 21H2+ or Server 2019+; the kernel
  driver must be either WHQL-signed (production) or loaded under
  `bcdedit /set testsigning on` (lab path).

## What `install.sh` does

For transparency, here is every step the script runs. Anything below
this section is the manual equivalent.

1. **Pre-flight** — verifies docker, python 3.12+, node 20+ are on PATH.
2. **Infra** — `make infra-up`, then waits up to 120 s for Postgres to
   be `pg_isready`, then `make infra-bootstrap` to create Kafka topics.
3. **Backend venv** — creates `backend/.venv`, upgrades pip,
   `pip install -e backend[dev]` plus `honcho`.
4. **Proto bindings** — `make proto-python` generates
   `backend/app/proto_gen/` from `proto/edr/v1/*.proto`.
5. **Secrets + .env** — if `backend/.env` doesn't exist, generates
   random `VIGIL_JWT_SECRET`, `VIGIL_CA_MASTER_KEY`,
   `VIGIL_AUDIT_HMAC_KEY` (each 32 bytes hex), plus the
   `VIGIL_AUDIT_OWNER_PASSWORD` used by the M16.a (fixed) migration
   to provision `vigil_audit_writer`. `VIGIL_PG_DSN_AUDIT` is
   composed from that password so the chain verifier can connect.
   All written alongside the standard service URLs. File mode 0600.
   Existing `.env` is left alone.
6. **Migrations** — `alembic upgrade head` against the just-started DB.
7. **Admin user** — runs `python -m scripts.create_admin` with
   `VIGIL_ADMIN_EMAIL` (default `admin@vigil.local`) and
   `VIGIL_ADMIN_PASSWORD` (default: 20-char random alphanumeric,
   printed once on completion).
8. **Frontend deps** — `npm install` in `frontend/`.
9. **Marker** — writes `.vigil/installed` so `make up` knows install
   ran successfully.

To override admin credentials:

```bash
VIGIL_ADMIN_EMAIL=admin@example.com \
VIGIL_ADMIN_PASSWORD='your-strong-password' \
./install.sh
```

To skip parts:

```bash
VIGIL_INSTALL_SKIP_INFRA=1 ./install.sh      # don't touch docker
VIGIL_INSTALL_SKIP_FRONTEND=1 ./install.sh   # don't npm install
```

## Manual install (when you can't or won't use `install.sh`)

Useful when production deployments separate the manager and infra
across hosts, or when one of the steps in `install.sh` fails and you
want to retry just that piece.

### 1. Bring up infrastructure

```bash
make infra-up           # Postgres + Redpanda + OpenSearch + MinIO
make infra-bootstrap    # creates Kafka topics
```

The compose also brings up Flink jobmanager/taskmanager containers
for historical reasons (ADR 0004's scheduled-correlation engine).
ADR 0005 superseded that with an OpenSearch percolator running in
the manager process; **Flink is not on the hot path and is safe to
remove** from `deploy/docker-compose.yml` if you want a leaner dev
stack. We keep it provisioned so anyone reading the ADR history can
spin the old engine back up without re-templating compose.

Services exposed on the host:

| Service | URL |
|---|---|
| Postgres | `localhost:5432` (cluster superuser `postgres`, runtime user `vigil_manager`, db `vigil`) |
| Redpanda Kafka | `localhost:19092` |
| Redpanda Console | http://localhost:8080 |
| OpenSearch | http://localhost:9200 |
| OpenSearch Dashboards | http://localhost:5601 |

Two Postgres roles, on purpose:

- `postgres` — cluster superuser, used only for the initial schema
  bootstrap and any future operation that needs cluster-wide
  privileges. The compose creates it via `POSTGRES_USER: postgres`.
- `vigil_manager` — non-superuser runtime role the manager connects
  as. Owner of the `vigil` database; can create tables, INSERT into
  `audit_log` but not UPDATE/DELETE/TRUNCATE it. Provisioned by
  `deploy/postgres-init.sql` on first DB init.

The split is load-bearing: the M16.a audit-log INSERT-only guarantee
relies on the runtime user not being a superuser (PG superusers
bypass GRANT/REVOKE checks). Older dev installs that bootstrapped
with `POSTGRES_USER: edr` (or `POSTGRES_USER: vigil_manager`) carry
a superuser as the runtime user in the data dir and the guarantee
silently fails — `docker compose down -v` then re-run `install.sh`
to get the role split in place.

### 2. Configure the backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'

cp .env.example .env
$EDITOR .env          # see "Required env" below
```

Required env (`backend/.env`):

```
# Runtime DSN — manager connects as the non-superuser `vigil_manager`.
VIGIL_PG_DSN=postgresql+asyncpg://vigil_manager:<password>@localhost:5432/vigil
# Audit-writer DSN — verifier connects as the table-owner role.
VIGIL_PG_DSN_AUDIT=postgresql+asyncpg://vigil_audit_writer:<password>@localhost:5432/vigil
# Same password as VIGIL_PG_DSN_AUDIT — the M16.a (fixed) migration
# uses it to create / rotate the vigil_audit_writer role.
VIGIL_AUDIT_OWNER_PASSWORD=<openssl rand -base64 32>
VIGIL_KAFKA_BROKERS=localhost:19092
VIGIL_OPENSEARCH_URL=http://localhost:9200
VIGIL_JWT_SECRET=<openssl rand -hex 32>
VIGIL_AUDIT_HMAC_KEY=<openssl rand -hex 32>
VIGIL_CA_MASTER_KEY=<openssl rand -hex 32>
VIGIL_UPLOAD_TOKEN_KEY=<openssl rand -hex 32>
VIGIL_TOTP_ENCRYPTION_KEY=<python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())">
```

`VIGIL_JWT_SECRET` signs JWTs. `VIGIL_AUDIT_HMAC_KEY` activates the
tamper-evident audit log chain. Both must be at least 16 bytes; once
set, do not rotate without a maintenance window — rotating
`VIGIL_AUDIT_HMAC_KEY` invalidates every existing audit row's HMAC.

`VIGIL_UPLOAD_TOKEN_KEY` (M23.x.b) signs the per-upload grant HMACs
the manager hands to agents during job artifact upload. It's
deliberately separate from `VIGIL_JWT_SECRET` so a leak of either
doesn't compromise the other. When unset, the manager falls back to
`VIGIL_JWT_SECRET` so older dev environments keep working —
production installs should set both explicitly.

`VIGIL_TOTP_ENCRYPTION_KEY` encrypts user TOTP secrets at rest
(Fernet). Must be 32 raw bytes encoded url-safe base64 — generate
with `Fernet.generate_key()`. Rotating this key without re-enrolling
every 2FA-enabled user locks them out; if you must rotate, plan a
maintenance window where admins force-disable then re-enroll each
user via `/api/users/{id}/2fa/disable` + the standard setup flow.

<a name="crypto-secrets"></a>**Refuse-to-boot guard.** When `VIGIL_DEBUG`
is unset (production default), the manager refuses to start if any of
the five crypto secrets is missing or still at its dev default:

- `VIGIL_JWT_SECRET == "dev-only-change-me"`
- `VIGIL_CA_MASTER_KEY` starts with `"dev-only-"`
- `VIGIL_AUDIT_HMAC_KEY` is unset or empty
- `VIGIL_TOTP_ENCRYPTION_KEY` is unset or still the dev default
- `VIGIL_UPLOAD_TOKEN_KEY` is unset (silently falls back to `VIGIL_JWT_SECRET`, defeating M18's auth-path separation)

`install.sh` rotates all five; operators building from compose alone
must set them in `.env` (or the manager's process environment) before
starting. The startup error message names which secret is missing.

`VIGIL_PG_DSN_AUDIT` + `VIGIL_AUDIT_OWNER_PASSWORD` are new in M16.a
(fixed). The first time you apply migrations after upgrading,
`VIGIL_AUDIT_OWNER_PASSWORD` must be present in the env so the
migration can create the `vigil_audit_writer` role. `install.sh`
writes both for you; production operators provision the password
through their secrets manager.

### 3. Apply the database schema

```bash
alembic upgrade head
```

### 4. Create the first admin

```bash
python -m scripts.create_admin \
  --email admin@vigil.local \
  --password 'change-me-please-12chars'
```

### 5. Generate the manager TLS certificate authority

For dev / single-host installs the auto-generated CA is fine: the
backend lazily creates one in `VIGIL_CA_DIR` (default
`backend/data/ca/`) on first call to the enrollment endpoint.

For production:

```bash
mkdir -p /var/lib/vigil-ca
openssl genrsa -out /var/lib/vigil-ca/ca.key 4096
openssl req -x509 -new -nodes -key /var/lib/vigil-ca/ca.key -sha256 \
  -days 3650 -subj "/CN=Vigil Manager CA" -out /var/lib/vigil-ca/ca.crt
chmod 600 /var/lib/vigil-ca/ca.key
```

Then in `.env`:

```
VIGIL_CA_DIR=/var/lib/vigil-ca
```

### 6. Start the manager processes

`make up` runs honcho with the top-level `Procfile` (preferred). To
start individual processes by hand for debugging:

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
make frontend-dev         # React UI (:5173)
```

For long-running production deployments, use a systemd unit per
process or a process supervisor (supervisord, k8s deployment).
Reference systemd units live under `deploy/systemd/`.

## Generating an enrollment token

Each agent needs a one-time enrollment token to bootstrap.

### Via the UI

Sign in as an admin → **Enrollment** → **New token** → copy the
`enr_…` value (you only see it once).

### Via the API

```bash
TOKEN=$(curl -s "$MANAGER_REST/api/auth/login" -X POST \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@vigil.local","password":"<password>"}' \
  | jq -r .access_token)

curl -s "$MANAGER_REST/api/enrollment/tokens" -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"description":"prod-laptop-04","expires_in_hours":24}' \
  | jq -r .token
```

Tokens are single-use, enforced atomically at the DB level — both
the REST `/api/enrollment/enroll` and the gRPC `AgentService.Enroll`
paths collapse the validity check + mark-spent into a single
`UPDATE … WHERE used_at IS NULL RETURNING …`, so two agents racing
the same token can't both succeed (see C1 / `services/enrollment.py
::consume_token`). Re-enrolling the same host requires a fresh
token. The M12.e re-enrollment detector fires a HIGH alert when a
host with the same hostname re-enrolls inside
`VIGIL_REENROLLMENT_WINDOW_SECONDS` (default 3600 s), so a
compromise-then-reimage workflow shows up in the SOC console.

## Install the Linux agent

### 1. Build the .deb / .rpm

From the repo root, on a Linux build host with `cargo install
cargo-deb cargo-generate-rpm`:

```bash
make agent-linux-deb       # writes target/debian/vigil-agent_*.deb
make agent-linux-rpm       # writes target/generate-rpm/vigil-agent-*.rpm
```

### 2. Install on the endpoint

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

### 3. Configure & start

```bash
sudo $EDITOR /etc/vigil/agent.env
```

Set at minimum:

```
VIGIL_MANAGER_ENDPOINT=https://manager.example.com:50051
VIGIL_MANAGER_REST=https://manager.example.com:8000
VIGIL_ENROLLMENT_TOKEN=enr_<token>
```

Optional:

```
VIGIL_HOSTNAME=<override>
VIGIL_STATE_DIR=/var/lib/vigil
VIGIL_DISABLE_SELF_PROTECTION=1   # only if BPF LSM unavailable
VIGIL_DISABLE_FILE_HASHING=1      # cuts CPU at the cost of file IOC matching
```

Then:

```bash
sudo systemctl enable --now vigil-agent
sudo journalctl -u vigil-agent -f       # watch enrollment + first telemetry
```

## Install the Windows agent

### 1. Build the agent + driver

On a Windows lab box with the WDK 10 + Visual Studio Build Tools:

```powershell
cd kernel-windows
.\build.ps1                     # produces vigil.sys + vigil.cat + vigil.inf

cd ..
cargo build -p agent-windows --release --target x86_64-pc-windows-msvc
```

Driver signing options:

* **Production**: WHQL-attested via the Microsoft Hardware Dev Center.
  Requires an EV code-signing certificate. Loads on Secure Boot
  without further steps.
* **Cross-signed**: EV cert + kernel-mode signing flow. Works on
  Windows 10 1607+ but not on Server 2019+ with HVCI.
* **Test-signing**: zero-cost lab path. The endpoint must boot with
  `bcdedit /set testsigning on`. Use only in non-production.

### 2. Package & deploy

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
Expand-Archive -Path .\vigil-windows-1.0.0.zip -DestinationPath C:\vigil
cd C:\vigil\vigil-windows-1.0.0
.\install-vigil.ps1
```

The installer:

1. Copies `vigil.sys` to `%SystemRoot%\System32\drivers\`.
2. Registers and starts the `vigil` kernel service.
3. Installs the agent at `%ProgramFiles%\Vigil\vigil-agent.exe`.
4. Creates `%ProgramData%\Vigil\agent.env` from a template.
5. Registers the agent as a Windows service (`vigil-agent`, manual
   start by default).

### 3. Configure & start

```powershell
notepad %ProgramData%\Vigil\agent.env
```

Set:

```
VIGIL_MANAGER_ENDPOINT=https://manager.example.com:50051
VIGIL_MANAGER_REST=https://manager.example.com:8000
VIGIL_ENROLLMENT_TOKEN=enr_<token>
```

Then:

```powershell
Start-Service vigil           # kernel driver
Start-Service vigil-agent     # userspace agent
Set-Service -Name vigil-agent -StartupType Automatic   # for boot-start
```

## Verify

After the agent finishes enrolling, you should see:

1. **In the UI** — Hosts → search by hostname → row appears with
   status `online` and `last_seen_at` ticking.
2. **In OpenSearch** — `telemetry-*` index has events with that
   `host.id`:
   ```
   curl -s "$OS_URL/telemetry-*/_search?q=event.kind:process_started&size=5"
   ```
3. **In `/metrics`** — `127.0.0.1:9101/metrics` on the agent host
   shows `edr_agent_bpf_*` counters incrementing.

For a structured smoke run:

```bash
tools/smoke/00-backend-smoke.sh         # REST surface
tools/smoke/10-grpc-smoke.py            # gRPC ingest
tools/smoke/20-agent-ioc-e2e.sh         # IOC detector
tools/smoke/30-sigma-realtime-e2e.sh    # Sigma percolator
tools/smoke/45-self-protection-linux.sh # BPF LSM hooks
```

## Where to go next

* [`operator-guide.md`](operator-guide.md) — daily operations: triage
  alerts, queue response actions, manage host groups, decommission.
* [`rbac.md`](rbac.md) — roles, host groups, audit log, API tokens.
* [`threat-model.md`](threat-model.md) — what the agent defends
  against and the explicit gaps.
* [`agent-update-protocol.md`](agent-update-protocol.md) — how
  agents discover updates.
* [`adr/`](adr/) — architecture decision records.
