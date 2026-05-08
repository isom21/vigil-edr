# Smoke tests

Black-box end-to-end checks against a running stack. They are not unit tests
— each one assumes the relevant subsystems are up and verifies real behavior
visible at the API surface.

| Script | Verifies |
|---|---|
| `00-backend-smoke.sh` | REST API: health, login, /me, rule CRUD, enrollment token, hosts, policies. |
| `10-grpc-smoke.py` | gRPC ingest path: REST enroll → mTLS HostStream → Hello + EventBatch + Heartbeat → RuleSync received. |
| `20-agent-ioc-e2e.sh` | Agent → Kafka → indexer → IOC detector → alert in PG. Spawns `/tmp/mimikatz.exe`. |
| `30-sigma-realtime-e2e.sh` | Realtime (percolator) Sigma engine. Reports wall-clock latency from process spawn → alert visible. |
| `40-sigma-scheduled-e2e.sh` | Legacy 30s-tick scheduled Sigma engine — only used to validate aggregation rules later. |

## Run order

For a clean re-validation after `make infra-up`:

```bash
# 0. One shell each, from the repo root:
make backend-dev backend-grpc \
     backend-normalizer backend-indexer \
     backend-detector backend-sigma     # backend-sigma is the realtime worker

# 1. Bootstrap admin (once per fresh DB):
cd backend
python -m scripts.create_admin --email admin@example.local --password 'change-me-please-12chars'
cd ..

# 2. Run the smokes:
tools/smoke/00-backend-smoke.sh
PYTHONPATH=backend python tools/smoke/10-grpc-smoke.py
tools/smoke/20-agent-ioc-e2e.sh
tools/smoke/30-sigma-realtime-e2e.sh
```

## Env overrides

All the bash smokes read `EMAIL`, `PASSWORD`, `BASE`, and `AGENT_BIN` from
the environment if you need to point them at a non-default admin or a
remote manager.
