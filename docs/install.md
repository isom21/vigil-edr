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
VIGIL_INTEL_ENCRYPTION_KEY=<python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())">
VIGIL_NOTIFICATION_ENCRYPTION_KEY=<python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())">
```

Optional, only when OIDC SSO is enabled (`./install.sh --with-oidc`
sets these for you; see "OIDC SSO" below):

```
VIGIL_OIDC_ENABLED=true
VIGIL_OIDC_ISSUER_URL=https://keycloak.example/realms/vigil
VIGIL_OIDC_CLIENT_ID=vigil-manager
VIGIL_OIDC_CLIENT_SECRET=<value from the IdP>
```

`VIGIL_JWT_SECRET` signs JWTs. `VIGIL_AUDIT_HMAC_KEY` activates the
tamper-evident audit log chain. Both must be at least 16 bytes; once
set, do not rotate without a maintenance window — rotating
`VIGIL_AUDIT_HMAC_KEY` invalidates every existing audit row's HMAC.

If you DO rotate the audit key (and you've decided the cost of
invalidating prior chain rows is worth it), the verifier exposes a
fingerprint of the active key on every pass: the structured log
line for `audit_verifier.ok` and `audit_verifier.breaks_detected`
includes a `key_fingerprint` field, and `GET /api/audit/verify`
returns the same value in its response. Compare the fingerprint
pre- and post-restart to confirm every manager process picked up
the new key — a stale process still computing HMACs under the old
key will keep logging the old fingerprint and the chain breaks
from the rotation point will read as real tampering until that
process is bounced.

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

`VIGIL_INTEL_ENCRYPTION_KEY` (Fernet) encrypts the TAXII /
abuse.ch / custom-JSON IntelFeed credentials at rest. Same shape
and rotation cost as TOTP — rotating without re-saving each feed's
credentials locks the puller out of every feed.

`VIGIL_NOTIFICATION_ENCRYPTION_KEY` (Fernet) encrypts
NotificationChannel credentials at rest — Slack webhook URLs,
PagerDuty integration keys, SMTP passwords. Same shape and
rotation cost; rotating without re-saving each channel breaks
every alert route until the channels are reset.

<a name="crypto-secrets"></a>**Refuse-to-boot guard.** When `VIGIL_DEBUG`
is unset (production default), the manager refuses to start if any
of the seven crypto secrets (plus three OIDC fields when SSO is
enabled) is missing or still at its dev default:

- `VIGIL_JWT_SECRET == "dev-only-change-me"`
- `VIGIL_CA_MASTER_KEY` starts with `"dev-only-"`
- `VIGIL_AUDIT_HMAC_KEY` is unset or empty
- `VIGIL_TOTP_ENCRYPTION_KEY` is unset or still the dev default
- `VIGIL_INTEL_ENCRYPTION_KEY` is unset or still the dev default
- `VIGIL_NOTIFICATION_ENCRYPTION_KEY` is unset or still the dev default
- `VIGIL_UPLOAD_TOKEN_KEY` is unset (silently falls back to `VIGIL_JWT_SECRET`, defeating M18's auth-path separation)

Plus, when `VIGIL_OIDC_ENABLED=true`:

- `VIGIL_OIDC_ISSUER_URL` non-empty
- `VIGIL_OIDC_CLIENT_ID` non-empty
- `VIGIL_OIDC_CLIENT_SECRET` non-empty

`install.sh` rotates all seven; operators building from compose
alone must set them in `.env` (or the manager's process environment)
before starting. The startup error message names which secret is
missing. For OIDC, the cleanest path is `./install.sh --with-oidc`
which prompts for the three IdP-side identifiers and writes them
into `backend/.env`.

### OIDC SSO

Phase 1 #1.6 added OIDC sign-in via the standard authorization-code
flow with PKCE. By default OIDC is off and the install.sh-printed
password path is the only way in. To enable:

```bash
./install.sh --with-oidc
# (prompts for VIGIL_OIDC_ISSUER_URL, VIGIL_OIDC_CLIENT_ID,
# VIGIL_OIDC_CLIENT_SECRET; writes them into backend/.env at mode 600.)
```

The four `VIGIL_OIDC_*` env vars are checked by the same
refuse-to-boot guard described above — a half-configured OIDC
(say, issuer URL set but client secret blank) refuses to start
rather than silently letting the password fallback mask the
misconfiguration. To turn OIDC back off without rotating any
secret, set `VIGIL_OIDC_ENABLED=false` in `backend/.env` and
restart the manager; the three identifier values can remain.

Known limitation: today an OIDC sign-in for a user with TOTP
enabled bypasses the TOTP step (tracked as CODE-30). Until that
ships, disable 2FA on accounts that authenticate via OIDC, or
require 2FA inside the IdP itself.

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
start individual processes by hand for debugging, the Procfile is
the source of truth; the table below summarises every worker so
operators don't have to dig through `backend/app/workers/`:

| Worker | Module | What it does |
|---|---|---|
| API + UI | `uvicorn app.main:app` + `npm run dev` | REST API (:8000) + React UI (:5173). |
| gRPC ingest | `app.grpc.server` | mTLS ingest from agents (:50051). |
| normalizer | `app.workers.normalizer` | `telemetry.raw` → `telemetry.normalized` (ECS + tenant/hostname enrichment). |
| indexer | `app.workers.indexer` | `telemetry.normalized` → OpenSearch. |
| detector | `app.workers.detector` | IOC detector. |
| sigma (realtime) | `app.workers.sigma_realtime` | OpenSearch percolator. |
| sigma (scheduled) | `app.workers.sigma_scheduler` | 30 s-tick legacy engine (ADR 0004; aggregation use cases only). |
| anomaly | `app.workers.anomaly` | First-time-process baseline. |
| sequence_detector | `app.workers.sequence_detector` | Multi-step behavioural rules (Phase 2 #2.3). |
| tamper | `app.workers.tamper` | Agent self-protection tamper alerts. |
| silence | `app.workers.silence` | Agent-silence detector. |
| incident_grouper | `app.workers.incident_grouper` | Folds alerts into incidents (Phase 1 #1.11 / #1.12). |
| alert_router | `app.workers.alert_router` | Fans alerts out to Slack / PagerDuty / SMTP. |
| webhook_dispatcher | `app.workers.webhook_dispatcher` | Outbound HMAC-signed webhook fanout. |
| siem_forwarder | `app.workers.siem_forwarder` | syslog/CEF + Splunk HEC + Sentinel. |
| intel_ingest | `app.workers.intel_ingest` | TAXII + abuse.ch + custom JSON pullers. |
| process_chain_indexer | `app.workers.process_chain_indexer` | Builds the process-tree graph store. |
| ai_summariser | `app.workers.ai_summariser` | On alert open, asks the LLM for a 3-line summary. |
| identity_monitor | `app.workers.identity_monitor` | Okta + Azure AD anomaly detection (Phase 4 #4.3). |
| cloud_iam_monitor | `app.workers.cloud_iam_monitor` | CloudTrail role-event anomaly (Phase 4 #4.2). |
| detonation_poller | `app.workers.detonation_poller` | Cuckoo result poll → IOC backfill (Phase 4 #4.4). |
| quarantine | `app.workers.quarantine` | Quarantine + release pipeline. |
| allowlist_learner | `app.workers.allowlist_learner` | Per-host-group SHA-256 collection. |
| vuln_scanner | `app.workers.vuln_scanner` | NVD CPE matching. |
| hunt_scheduler | `app.workers.hunt_scheduler` | Cron-fires saved hunts. |
| archive_worker | `app.workers.archive_worker` | ILM rollover + S3 cold tier. |
| rollout_monitor | `app.workers.rollout_monitor` | Cohort failure rate → auto-rollback. |
| case_sync | `app.workers.case_sync` | Jira + ServiceNow bidirectional. |
| sweep_scheduler | `app.workers.sweep_scheduler` | Cron-fires recurring jobs. |
| dispatch_watchdog | `app.workers.dispatch_watchdog` | Expires stuck Commands past their deadline. |
| audit_verifier_loop | `app.workers.audit_verifier_loop` | Walks the audit_log HMAC chain on a tick. |
| playbook_executor | `app.workers.playbook_executor` | Drains `kafka.alerts.opened`, runs matching playbooks. |

For long-running production deployments, use a systemd unit per
process or a process supervisor (supervisord, k8s deployment).
Reference systemd units live under `deploy/systemd/`. See
[`operator-guide.md → Production deployment`](operator-guide.md#production-deployment)
for the externally-managed-Postgres / OpenSearch / Kafka shape.

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

### Verifying release signatures

Packages published to GitHub Releases (tag-triggered, see
`.github/workflows/release.yml`) are signed by the maintainer's
GPG key and ship alongside a `SHA256SUMS` file and a CycloneDX
1.5 SBOM (`vigil-sbom.cdx.json`).

The expected public key fingerprint is:

```
<TO_BE_FILLED_BY_MAINTAINER>
```

> **TODO (DOC-9):** the maintainer GPG fingerprint above is a
> placeholder. Until the maintainer publishes one, treat the
> verify-before-install step below as advisory and pin to a
> known-good commit SHA via `git clone --depth=1 --branch=v1.0.0`
> instead of trusting the release tarball. Tracking issue:
> <https://github.com/isom21/vigil-edr/issues>.

Import the key and verify before installing:

```bash
# Fetch + import the maintainer public key.
curl -fsSL https://github.com/isom21/vigil-edr/releases/download/v1.0.0/maintainer-pubkey.asc \
  | gpg --import

# Verify the .deb (dpkg-sig embeds a detached signature inside the .deb).
dpkg-sig --verify vigil-agent_1.0.0-1_amd64.deb

# Verify the .rpm (rpm --checksig requires the maintainer key in the rpm DB).
sudo rpm --import maintainer-pubkey.asc
rpm --checksig vigil-agent-1.0.0-1.x86_64.rpm

# Verify the SHA256SUMS file matches the artefacts you downloaded.
sha256sum --check SHA256SUMS
```

`dpkg-sig --verify` should report `GOODSIG _gpgbuilder <fingerprint>`
and `rpm --checksig` should report `digests signatures OK`. Any
other output (`BADSIG`, `NOKEY`, `NOT OK`) means the package is
either corrupted or signed by a key you haven't trusted — do not
install it.

The CycloneDX SBOM (`vigil-sbom.cdx.json`) is the merged Python
(`backend/`) + Rust (workspace) component inventory and is suitable
for ingest into compliance tooling that consumes CycloneDX 1.5.

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

Optional (run `vigil-agent --help` for the full list):

```
VIGIL_AGENT_CONFIG=/etc/vigil/agent.toml   # optional TOML config file (overrides defaults)
VIGIL_HOSTNAME=<override>                  # override the registered hostname
VIGIL_STATE_DIR=/var/lib/vigil             # agent state (default /var/lib/vigil)
VIGIL_DISABLE_EBPF=1                       # skip eBPF, use the /proc-poll fallback
VIGIL_DISABLE_SELF_PROTECTION=1            # skip BPF LSM self-protection hooks
VIGIL_DISABLE_FILE_HASHING=1               # cuts CPU at the cost of file IOC matching
VIGIL_PIN_DIR=/sys/fs/bpf/vigil            # override the bpffs pin dir
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
tools/smoke/00-backend-smoke.sh            # REST surface
tools/smoke/10-grpc-smoke.py               # gRPC ingest
tools/smoke/20-agent-ioc-e2e.sh            # IOC detector
tools/smoke/30-sigma-realtime-e2e.sh       # Sigma percolator (realtime)
tools/smoke/40-sigma-scheduled-e2e.sh      # Sigma scheduled correlation (legacy path)
tools/smoke/45-self-protection-linux.sh    # Linux BPF LSM self-protection
tools/smoke/46-self-protection-windows.ps1 # Windows driver self-protection (PowerShell, run on the Windows lab box)
tools/smoke/50-rbac-e2e.sh                 # RBAC + audit log end-to-end
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
