# Operator guide

Day-to-day operations runbook: provisioning hosts, triaging alerts,
queueing response actions, upgrading, decommissioning. For the
first-time install (manager + agents), see `install.md`.

Companion docs:

- `install.md` — first-time bring-up of manager + agents.
- `threat-model.md` — what the agent defends against and explicit gaps.
- `rbac.md` — roles, host groups, audit log, API tokens.

## Glossary

| Term | Meaning |
|---|---|
| Manager | The FastAPI backend + UI + workers running centrally. |
| Agent | The endpoint binary (`edr-agent`) running on each protected host. |
| Driver | Windows-only kernel component (`edr.sys`) the agent talks to via IOCTL. |
| Host | A single endpoint enrolled with the manager (one row in PG `hosts`). |
| Host group | A label-bucket of hosts used for RBAC scoping (M7.5). |
| Enrollment token | One-time secret minted by an admin, consumed by the agent on first run. |
| Pin path | bpffs directory (`/sys/fs/bpf/edr/`) where the Linux agent's BPF programs/links/maps are kept alive across crashes. |

## Provisioning a new endpoint

See [`install.md`](install.md) §2 (enrollment token) and §3–§5
(Linux / Windows install + verification). This guide picks up
afterwards, once the host is enrolled and visible in the UI.

## Operating

### Reading telemetry

OpenSearch dashboard: the `telemetry-*` index pattern. As of M7.7,
each doc carries `host.id`, `host.hostname`, and `host.os.family`,
so analysts can search by hostname.

Quick checks:

```bash
# Recent process_started on a host:
curl -s "$OS_URL/telemetry-*/_search?q=event.kind:process_started+AND+host.hostname:<name>&size=20"

# Outbound connects from a binary:
curl -s "$OS_URL/telemetry-*/_search?q=event.kind:network_connect+AND+process.name:curl"
```

### Triaging an alert

UI: Alerts → click the row → Alert Detail.

Move state with the buttons at the top: `new` → `investigating` →
`true_positive` (or `false_positive`). Optional comment goes in the
state-history.

Queue a response action:

- "Block process by path…" — drops every future exec of that binary.
- "Block file…" — denies open() on that path.
- "Kill PID…" — terminates a specific running pid.

Status lands on `/commands` once the agent confirms.

### Queueing commands without the UI

```bash
curl -s "$MANAGER_REST/api/hosts/$HOST_ID/commands" -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"kind":"block_process","payload":{"pattern":"/usr/local/bin/evil"}}' \
  | jq .
```

`kind` ∈ `kill_process`, `block_process`, `block_file`,
`unblock_process`, `unblock_file`. Payload is `{"pid": N}` for
`kill_process`, `{"pattern": "..."}` for the rest.

## Upgrading

### Linux

```bash
# Build the new deb, copy to endpoint:
make agent-linux-deb
scp target/debian/edr-agent_*.deb endpoint:/tmp/

# On endpoint:
apt-get install -y /tmp/edr-agent_*.deb     # postinst handles daemon-reload
systemctl restart edr-agent
journalctl -u edr-agent -f                  # watch takeover + reload
```

The takeover protocol claims any pinned BPF objects from the running
agent before the new one loads. Brief (<1s) protection gap during
restart; documented in `threat-model.md`.

### Windows

```powershell
.\edr-windows-0.1.0\install-edr.ps1   # idempotent; reuses identity material
sc.exe stop edr; sc.exe start edr
Stop-ScheduledTask -TaskName EDRAgent; Start-ScheduledTask -TaskName EDRAgent
```

The driver may need a reboot if the `.sys` is in use; the installer
will print a warning if `Copy-Item` fails on `system32\drivers\`.

## Decommissioning

### Stop the host (preserve identity for re-enrollment)

```bash
# Linux:
systemctl stop edr-agent
systemctl disable edr-agent

# Windows:
Stop-ScheduledTask -TaskName EDRAgent
sc.exe stop edr
```

### Full uninstall

```bash
# Linux:
apt-get remove -y edr-agent      # keeps state
apt-get purge -y edr-agent       # removes /var/lib/edr + /etc/edr

# Windows:
.\edr-windows-0.1.0\uninstall-edr.ps1            # keeps state + cert
.\edr-windows-0.1.0\uninstall-edr.ps1 -Purge -RemoveCert
```

### Mark the host as decommissioned in the manager

```bash
curl -s "$MANAGER_REST/api/hosts/$HOST_ID" -X PATCH \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"status":"decommissioned"}'
```

This revokes the host's mTLS cert (cert-status check happens at gRPC
connect time). Telemetry from that host_id from any future connection
is rejected.

## Troubleshooting

### Linux

| Symptom | Likely cause | Fix |
|---|---|---|
| `systemctl status edr-agent` fails with "agent.identity.using_existing" missing | Identity dir wiped; need new token | Mint enrollment token, set `EDR_ENROLLMENT_TOKEN` in `/etc/edr/agent.env`, restart. |
| `self_protection.takeover.failed` on startup | Old pins exist but agent_self map name changed across versions | `edr-agent --unpin` then start. |
| `ebpf load failed; falling back to /proc poller` | `CONFIG_BPF_LSM=y` not enabled, kernel <5.7, missing CAP_BPF | Confirm `cat /sys/kernel/security/lsm` contains `bpf`; ensure systemd unit's `AmbientCapabilities` line has `CAP_BPF`. |
| File-open events stop flowing under load | Backpressure (pre-M7.7) | Confirm normalizer is current; `make backend-normalizer` should pick up M7.7 batched-send. |
| `kill -9` from root succeeds | `EDR_DISABLE_SELF_PROTECTION=1` set, or `lsm/task_kill` failed to attach | Inspect journal for `lsm_task_kill.skipped`. |

### Windows

| Symptom | Likely cause | Fix |
|---|---|---|
| Driver fails to load with "signature invalid" | testsigning off or cert not in TrustedPublisher | `bcdedit /set testsigning on` + reboot; verify `certutil -store -enterprise Root` shows the cert. |
| `EDRKernelSession AlreadyExist` | Stale ETW session from a previous crash (pre-M7.7) | Upgrade to current; `ControlTraceA(STOP)` runs on startup. |
| Agent task starts but exits immediately | Bad `agent.env` format | Check `C:\Windows\Temp\edr-agent.err.log`. |
| `taskkill /F` succeeds against agent | Driver not loaded, or `g_ProtectedPid == 0` | `sc.exe query edr` (RUNNING) and verify the agent logged `driver.self_protection.registered`. |
| Defender races and wins our kill IOCTL | Built-in signature on the target name (e.g. `mimikatz.exe`) | Lab-only: `Set-MpPreference -DisableRealtimeMonitoring $true`. Block-path is unaffected. |

## Smoke tests

`tools/smoke/` — bash + PowerShell scripts that verify the running
stack from the operator's perspective. Reference:

| Script | Verifies |
|---|---|
| `00-backend-smoke.sh` | REST API surface (login, /me, rule CRUD, enrollment, hosts, policies). |
| `10-grpc-smoke.py` | gRPC ingest path end-to-end. |
| `20-agent-ioc-e2e.sh` | IOC detector → alert in PG. |
| `30-sigma-realtime-e2e.sh` | Realtime Sigma engine wall-clock latency. |
| `40-sigma-scheduled-e2e.sh` | Legacy scheduled Sigma (kept for aggregation). |
| `45-self-protection-linux.sh` | M7.1 BPF LSM hooks all reject same-box-root attacks. |
| `46-self-protection-windows.ps1` | M7.2 driver ObCallback strips dangerous handle access. |
| `50-rbac-e2e.sh` | M7.5 host-group scoping for hosts / alerts / commands. |

Recommended run order after a fresh dev-stack bring-up: 00 → 10 → 20 →
30 → 45 → 50 → (Windows lab) 46.
