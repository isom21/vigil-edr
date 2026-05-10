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
| `45-self-protection-linux.sh` | M7.1 BPF LSM self-protection on a Linux endpoint: kill, ptrace, /proc/&lt;pid&gt;/mem, bpffs unlink, state-dir unlink, bpftool detach all blocked from non-self callers; `systemctl stop` still works. Runs against a host with the agent already installed and active; pass `--state-dir` if not the default `/var/lib/edr`. |
| `46-self-protection-windows.ps1` | M7.2 driver `ObCallback` self-protection: taskkill /F, Stop-Process, and `TerminateProcess` via a stripped PROCESS_TERMINATE handle are all rejected against the agent process; `PROCESS_QUERY_LIMITED_INFORMATION` still opens (Task Manager-style inspection works); a non-self test process is still killable normally. Runs as Administrator on a host with the driver loaded and the agent active. |

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
