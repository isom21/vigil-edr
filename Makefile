# Top-level Makefile. Targets group operations across components.

PROTO_DIR := proto
PROTO_FILES := $(PROTO_DIR)/edr/v1/common.proto $(PROTO_DIR)/edr/v1/events.proto $(PROTO_DIR)/edr/v1/control.proto
BACKEND_GEN := backend/app/proto_gen
RUST_GEN_NOTE := agent-core regenerates Rust bindings via tonic-build at compile time; run 'cargo build -p agent-core'.

.PHONY: help
help:
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage: make <target>\n\nTargets:\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: proto
proto: proto-python ## Regenerate all protobuf bindings (Python; Rust regenerates at cargo build time).
	@echo "$(RUST_GEN_NOTE)"

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
backend-dev: ## Run the backend in dev mode (auto-reload).
	cd backend && uvicorn app.main:app --reload --port 8000

.PHONY: backend-grpc
backend-grpc: ## Run the gRPC ingest server.
	cd backend && python -m app.grpc.server

.PHONY: backend-indexer
backend-indexer: ## Run the telemetry indexer + IOC detector worker.
	cd backend && python -m app.workers.indexer

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
