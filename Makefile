# Top-level Makefile. Targets group operations across components.

PROTO_DIR := proto
PROTO_FILES := $(PROTO_DIR)/edr/v1/common.proto $(PROTO_DIR)/edr/v1/events.proto $(PROTO_DIR)/edr/v1/control.proto
BACKEND_GEN := backend/app/proto_gen
RUST_GEN_NOTE := agent-core regenerates Rust bindings via tonic-build at compile time; run 'cargo build -p agent-core'.
VENV_PY := backend/.venv/bin/python
VENV_HONCHO := backend/.venv/bin/honcho

.PHONY: help
help:
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage: make <target>\n\nTargets:\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# ---------------------------------------------------------------------------
# One-shot bring-up. The minimal install path is:
#
#     ./install.sh && make up
#
# install.sh is idempotent; `make install` is a thin wrapper around it.
# `make up` runs every backend worker + the frontend under honcho. Stop
# with Ctrl-C or `make down` from another shell.
# ---------------------------------------------------------------------------
.PHONY: install
install: ## One-shot manager bootstrap (infra, venv, deps, .env, migrations, admin, npm).
	./install.sh

.PHONY: up
up: ## Start every manager process (backend workers + frontend) under honcho.
	@test -f .vigil/installed || ( echo "run \`make install\` first" >&2 && exit 1 )
	@PATH="$(CURDIR)/backend/.venv/bin:$$PATH" $(VENV_HONCHO) -e backend/.env start

.PHONY: down
down: ## Stop everything started by `make up` (and the infra stack).
	-pkill -f "honcho start" 2>/dev/null || true
	cd deploy && docker compose stop

.PHONY: proto
proto: proto-python ## Regenerate all protobuf bindings (Python; Rust regenerates at cargo build time).
	@echo "$(RUST_GEN_NOTE)"

# ---------------------------------------------------------------------------
# Linux installer packaging (M7.3)
# ---------------------------------------------------------------------------
.PHONY: agent-linux-build
agent-linux-build: ## Build the Linux agent in release mode.
	cargo build -p agent-linux --release

.PHONY: agent-linux-deb
agent-linux-deb: agent-linux-build ## Build a .deb (Ubuntu 22.04+ / Debian 12+). Requires `cargo install cargo-deb`.
	cargo deb -p agent-linux --no-build
	@echo "wrote: target/debian/vigil-agent_*_amd64.deb"

.PHONY: agent-linux-rpm
agent-linux-rpm: agent-linux-build ## Build a .rpm (RHEL/Rocky/Alma 9). Requires `cargo install cargo-generate-rpm`.
	cargo generate-rpm -p agent-linux
	@echo "wrote: target/generate-rpm/vigil-agent-*.x86_64.rpm"

.PHONY: agent-linux-packages
agent-linux-packages: agent-linux-deb agent-linux-rpm ## Build .deb + .rpm in one go.

# ---------------------------------------------------------------------------
# Pre-paid prep (M18). Generate SBOMs + sign artefacts. The signing
# scripts no-op cleanly when GPG_KEY_ID isn't set so this Makefile target
# is safe to run in CI before M19's certs land.
# ---------------------------------------------------------------------------
.PHONY: sbom
sbom: ## Generate a merged CycloneDX 1.5 SBOM (Python + Rust). Override SBOM_OUT to set the path.
	bash tools/sign/sbom.sh $(SBOM_OUT)

.PHONY: sign-deb
sign-deb: ## Sign .deb artefacts with the operator's GPG key (requires GPG_KEY_ID).
	bash tools/sign/sign-deb.sh

.PHONY: sign-rpm
sign-rpm: ## Sign .rpm artefacts with the operator's GPG key (requires GPG_KEY_ID).
	bash tools/sign/sign-rpm.sh

.PHONY: release-prep
release-prep: agent-linux-packages sbom ## Build packages + SBOMs (no signing). The tag-triggered release workflow plugs in sign-deb / sign-rpm.

# ---------------------------------------------------------------------------
# Gates (M8): same checks CI runs, locally.
# ---------------------------------------------------------------------------
.PHONY: gates
gates: gate-rust gate-python gate-frontend ## Run all per-PR gates locally.

.PHONY: gate-rust
gate-rust: ## clippy + fmt + audit + deny (workspace).
	cargo fmt --all --check
	cargo clippy --workspace --all-targets --all-features --no-deps -- -D warnings
	cargo audit --deny warnings || echo "  (cargo-audit not installed: cargo install cargo-audit)"
	cargo deny check 2>/dev/null || echo "  (cargo-deny not installed: cargo install cargo-deny)"

.PHONY: gate-python
gate-python: ## ruff + pyright + pip-audit on backend.
	cd backend && ruff check app && ruff format --check app
	cd backend && pyright app || echo "  (pyright optional)"
	cd backend && pip-audit --skip-editable || echo "  (pip-audit optional)"

.PHONY: gate-frontend
gate-frontend: ## tsc + eslint + prettier + npm audit on frontend.
	cd frontend && npm run typecheck
	cd frontend && npx eslint --max-warnings=0 src
	cd frontend && npx prettier --check src
	cd frontend && npm audit --omit=dev --audit-level=high || echo "  (advisory only)"

.PHONY: test-backend
test-backend: ## Run the backend pytest suite against the dev DB (assumes VIGIL_TEST_PG_DSN or VIGIL_PG_DSN).
	cd backend && pytest -v --cov=app --cov-report=term-missing

.PHONY: proto-python
proto-python: ## Regenerate Python bindings into backend/app/proto_gen.
	@rm -rf $(BACKEND_GEN)
	@mkdir -p $(BACKEND_GEN)/edr/v1
	@touch $(BACKEND_GEN)/__init__.py $(BACKEND_GEN)/edr/__init__.py $(BACKEND_GEN)/edr/v1/__init__.py
	cd backend && python -m grpc_tools.protoc \
		-I ../$(PROTO_DIR) \
		--python_out=app/proto_gen \
		--pyi_out=app/proto_gen \
		--grpc_python_out=app/proto_gen \
		$(addprefix ../,$(PROTO_FILES))
	@# grpc_tools generates absolute imports; rewrite them under app.proto_gen.
	@find $(BACKEND_GEN) -name '*.py' -exec sed -i \
		-e 's/^from edr\./from app.proto_gen.edr./g' \
		-e 's/^import edr\./import app.proto_gen.edr./g' {} \;

.PHONY: backend-dev
backend-dev: ## Run the backend in dev mode (auto-reload). Binds 0.0.0.0 so lab VMs on the tailnet can reach it.
	cd backend && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

.PHONY: backend-grpc
backend-grpc: ## Run the gRPC ingest server.
	cd backend && python -m app.grpc.server

.PHONY: backend-normalizer
backend-normalizer: ## Run the proto -> ECS normalizer worker (telemetry.raw -> telemetry.normalized).
	cd backend && python -m app.workers.normalizer

.PHONY: backend-indexer
backend-indexer: ## Run the telemetry indexer (telemetry.normalized -> OpenSearch).
	cd backend && python -m app.workers.indexer

.PHONY: backend-detector
backend-detector: ## Run the IOC detector (telemetry.normalized -> alerts).
	cd backend && python -m app.workers.detector

.PHONY: backend-anomaly
backend-anomaly: ## M11.b — first-time-process anomaly detector.
	cd backend && python -m app.workers.anomaly

.PHONY: backend-tamper
backend-tamper: ## M12 — agent self-protection tamper alert worker.
	cd backend && python -m app.workers.tamper

.PHONY: backend-silence
backend-silence: ## M12.d — agent silence alert worker.
	cd backend && python -m app.workers.silence

.PHONY: backend-quarantine
backend-quarantine: ## M20.c — quarantine inventory tracker.
	cd backend && python -m app.workers.quarantine

.PHONY: backend-sigma
backend-sigma: ## Run the Sigma realtime worker (OpenSearch percolator). Recommended.
	cd backend && python -m app.workers.sigma_realtime

.PHONY: backend-sigma-scheduled
backend-sigma-scheduled: ## Run the legacy Sigma scheduler (30s tick). Use for aggregation rules.
	cd backend && python -m app.workers.sigma_scheduler

.PHONY: backend-migrate
backend-migrate: ## Apply the latest Alembic migration.
	cd backend && alembic upgrade head

.PHONY: backend-lint
backend-lint: ## Lint the backend.
	cd backend && ruff check . && ruff format --check .

.PHONY: frontend-dev
frontend-dev: ## Run the frontend dev server.
	cd frontend && npm run dev

.PHONY: infra-up
infra-up: ## Start dev infra (Postgres, Redpanda, OpenSearch, Flink).
	cd deploy && docker compose up -d
	@echo "waiting for services to be healthy..."
	@cd deploy && docker compose ps

.PHONY: infra-down
infra-down: ## Stop dev infra.
	cd deploy && docker compose down

.PHONY: infra-bootstrap
infra-bootstrap: ## Bootstrap Kafka topics.
	deploy/dev/bootstrap-kafka-topics.sh
