# EDR

Endpoint Detection and Response — agent + management plane. PoC inspired by HarfangLab.

> **Status:** M0 (foundations). No business logic yet — only scaffolding, schemas, and dev infrastructure.

## Layout

```
proto/             Protobuf source of truth (edr.v1)
agent-core/        Rust crate: cross-platform agent building blocks
agent-windows/     Rust binary: Windows EDR agent (depends on agent-core)
agent-linux/       Rust binary: Linux EDR agent (depends on agent-core)
kernel-windows/    KMDF C/C++ driver (M4)
kernel-linux/      eBPF C programs (M6)
backend/           FastAPI manager (REST + gRPC ingest)
stream/            Kafka consumers + Flink Sigma jobs
frontend/          React + Vite + TS + shadcn/ui
deploy/            docker-compose, installers
docs/adr/          Architecture decision records
tools/             Dev helpers (rule converters, etc.)
```

## Stack at a glance

- **Agent**: Rust + C (Windows kernel / eBPF). gRPC bidi over mTLS.
- **Manager**: FastAPI + PostgreSQL + OpenSearch + Kafka (Redpanda in dev) + Flink.
- **Frontend**: React + Vite + TypeScript + shadcn/ui + Tailwind.
- **Schema**: Protobuf (source of truth), ECS-aligned naming.

See [docs/adr/](docs/adr/) for the reasoning behind each choice.

## Dev environment

Prerequisites:

- Docker + Docker Compose
- Rust toolchain (pinned in `rust-toolchain.toml`)
- Python 3.12+
- Node 20+
- (For agent-windows kernel work) Windows 10/11 dev VM with `bcdedit /set testsigning on`

Bring up infrastructure:

```bash
cd deploy
docker compose up -d
./dev/bootstrap-kafka-topics.sh
```

Services exposed on the host:

| Service | URL |
| --- | --- |
| Postgres | `localhost:5432` (user `edr`, db `edr`) |
| Redpanda Kafka | `localhost:19092` |
| Redpanda Console | http://localhost:8080 |
| OpenSearch | http://localhost:9200 |
| OpenSearch Dashboards | http://localhost:5601 |
| Flink Dashboard | http://localhost:8081 |

Backend (M1+):

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env
uvicorn app.main:app --reload --port 8000
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

Agent (M2+):

```bash
# from repo root
cargo build -p agent-windows --release   # cross-compile from WSL or build on Win VM
cargo build -p agent-linux --release
```

## Milestones

| # | Scope | Status |
|---|---|---|
| M0 | Foundations: monorepo, proto schema, dev infra, ADRs | **Done** |
| M1 | Backend core + UI shell + enrollment CA | **Done** |
| M2 | Agent thin slice — Linux agent (proc-poll) verified in WSL; Windows ETW skeleton needs a Windows VM | **Done** |
| M3 | Sigma pipeline (scheduled OpenSearch correlation, see [ADR 0004](docs/adr/0004-sigma-scheduled-correlation.md)) | **Done** |
| M4 | Windows kernel driver (KMDF + minifilter) | Planned |
| M5 | Response actions (kill / block) | Planned |
| M6 | Linux agent (eBPF / aya) | Planned |
| M7 | Polish, self-protection, installers, RBAC | Planned |

## First-run quickstart

```bash
# 1. Bring up infra
make infra-up
make infra-bootstrap

# 2. Backend
cd backend
# IMPORTANT (WSL2): put the venv on the Linux fs, not /mnt/d — file I/O on the
# Windows mount is ~50x slower for venv creation and pip installs.
python -m venv ~/edr-venvs/backend
source ~/edr-venvs/backend/bin/activate
pip install -e '.[dev]'
cp .env.example .env       # edit secrets
alembic upgrade head
python -m scripts.create_admin --email admin@example.local --password 'change-me-please-12chars'
uvicorn app.main:app --reload --port 8000

# 3. Frontend (in a new terminal, from repo root)
cd frontend
npm install
npm run dev   # http://localhost:5173
```

## Running the full detection pipeline

After the quickstart, you need five processes for end-to-end detection.
Each in its own shell, from the repo root:

```bash
make backend-dev          # FastAPI REST API (:8000)
make backend-grpc         # gRPC ingest for agents (:50051)
make backend-normalizer   # telemetry.raw -> telemetry.normalized
make backend-indexer      # telemetry.normalized -> OpenSearch (telemetry-*)
make backend-detector     # IOC matching: emit alerts on filename/path/hash hits
make backend-sigma        # 30s scheduler running each enabled Sigma rule
make frontend-dev         # React UI (:5173)
```

Then enroll an agent: in the UI go to **Enrollment → Generate**, copy the
token, and on the endpoint run:

```bash
EDR_ENROLLMENT_TOKEN=enr_… \
EDR_MANAGER_ENDPOINT=https://<manager-host>:50051 \
EDR_MANAGER_REST=http://<manager-host>:8000 \
edr-agent
```

Sign in with the admin you just created. The UI proxies `/api/*` to the backend on `:8000`.

## License

Proprietary — internal PoC. No external use.
