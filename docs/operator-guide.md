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
| Agent | The endpoint binary (`vigil-agent`) running on each protected host. |
| Driver | Windows-only kernel component (`vigil.sys`) the agent talks to via IOCTL. |
| Host | A single endpoint enrolled with the manager (one row in PG `hosts`). |
| Host group | A label-bucket of hosts used for RBAC scoping (M7.5). |
| Enrollment token | One-time secret minted by an admin, consumed by the agent on first run. |
| Pin path | bpffs directory (`/sys/fs/bpf/vigil/`) where the Linux agent's BPF programs/links/maps are kept alive across crashes. |

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

### Auto-block fallback {#auto-block-fallback}

When a Sigma / IOC rule with `action=block` matches, the manager
queues both a kill-by-pid (if the event has a live pid) and a
preventive block-by-path. The block pattern is the resolved full
executable / file path from the matched event (`process.executable`
or `file.path` in ECS). The agent pushes that exact string into the
kernel-side block map, which is keyed by the full path the kernel
sees on exec / file_open. So the pattern and the lookup key match
and future invocations of the same binary return EPERM.

If the matched event only carries a basename (`process.name` /
`file.name`) — older events, or normalizers that drop the path — the
manager falls back to queueing the basename. The kernel will not
match it on future invocations (`"mimikatz.exe"` vs
`"/usr/local/bin/mimikatz.exe"`); the kill-by-pid limb is the only
effective response. The UI surfaces this as a normal "block queued"
status because the IOCTL succeeded — the kernel map row was added,
just keyed by a string that the resolver will never produce. If you
need a preventive block against a basename-only event, re-queue the
block manually with the path you actually want denied.

## Upgrading

### Linux

```bash
# Build the new deb, copy to endpoint:
make agent-linux-deb
scp target/debian/vigil-agent_*.deb endpoint:/tmp/

# On endpoint:
apt-get install -y /tmp/vigil-agent_*.deb     # postinst handles daemon-reload
systemctl restart vigil-agent
journalctl -u vigil-agent -f                  # watch takeover + reload
```

Takeover protocol (post-M7.1.b): on agent exit the
`sched_process_exit` tracepoint zeroes `agent_self[0]` from kernel
context, so the new agent finds `self_tgid() == 0` and claims via
the standard initial-load path. The "old agent's tgid written by
the new agent" trick is gone — that route was the
`bpftool map update`-based hijack the M7.1.b fix closes. If the
exit auto-clear ever fails to fire (kernel quirk), the new agent
logs `self_protection.takeover.stale_self_observed`, unlinks the
old pins, and proceeds with a fresh load. Brief (<1s) protection
gap during restart; documented in `threat-model.md`.

### Windows

```powershell
.\vigil-windows-0.1.0\install-vigil.ps1   # idempotent; reuses identity material
sc.exe stop edr; sc.exe start edr
Stop-ScheduledTask -TaskName VigilAgent; Start-ScheduledTask -TaskName VigilAgent
```

The driver may need a reboot if the `.sys` is in use; the installer
will print a warning if `Copy-Item` fails on `system32\drivers\`.

## Decommissioning

### Stop the host (preserve identity for re-enrollment)

```bash
# Linux:
systemctl stop vigil-agent
systemctl disable vigil-agent

# Windows:
Stop-ScheduledTask -TaskName VigilAgent
sc.exe stop edr
```

### Full uninstall

```bash
# Linux:
apt-get remove -y vigil-agent      # keeps state
apt-get purge -y vigil-agent       # removes /var/lib/vigil + /etc/vigil

# Windows:
.\vigil-windows-0.1.0\uninstall-vigil.ps1            # keeps state + cert
.\vigil-windows-0.1.0\uninstall-vigil.ps1 -Purge -RemoveCert
```

### Mark the host as decommissioned in the manager

```bash
curl -s "$MANAGER_REST/api/hosts/$HOST_ID" -X PATCH \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"status":"decommissioned"}'
```

This flips `Host.status` to `DECOMMISSIONED` and the manager's gRPC
service rejects every future `HostStream` open from that host id with
`UNAUTHENTICATED: host decommissioned` — verified at the
`_check_host_admission` gate in `backend/app/grpc/services.py`. The
heartbeat tick on an already-open stream catches the same flip within
~30s and aborts mid-stream. The mTLS cert itself stays
cryptographically valid until its 90-day expiry (we don't operate a
CRL), so the decommission is enforced by the manager, not by the TLS
layer. If you need the cert to stop validating outright before its
expiry — say, for a stolen-laptop scenario — rotate the internal CA
and re-issue every other agent's cert.

Cert-pinning sits at the same gate: the SHA-256 of the presented PEM
is compared against `Host.cert_fingerprint`, so a second host that
somehow ended up with the same CN can't take over the slot.

## Troubleshooting

### Linux

| Symptom | Likely cause | Fix |
|---|---|---|
| `systemctl status vigil-agent` fails with "agent.identity.using_existing" missing | Identity dir wiped; need new token | Mint enrollment token, set `VIGIL_ENROLLMENT_TOKEN` in `/etc/vigil/agent.env`, restart. |
| `self_protection.takeover.failed` on startup | Old pins exist but agent_self map name changed across versions | `vigil-agent --unpin` then start. |
| `ebpf load failed; falling back to /proc poller` | `CONFIG_BPF_LSM=y` not enabled, kernel <5.7, missing CAP_BPF | Confirm `cat /sys/kernel/security/lsm` contains `bpf`; ensure systemd unit's `AmbientCapabilities` line has `CAP_BPF`. |
| File-open events stop flowing under load | Backpressure (pre-M7.7) | Confirm normalizer is current; `make backend-normalizer` should pick up M7.7 batched-send. |
| `kill -9` from root succeeds | `VIGIL_DISABLE_SELF_PROTECTION=1` set, or `lsm/task_kill` failed to attach | Inspect journal for `lsm_task_kill.skipped`. |

### Windows

| Symptom | Likely cause | Fix |
|---|---|---|
| Driver fails to load with "signature invalid" | testsigning off or cert not in TrustedPublisher | `bcdedit /set testsigning on` + reboot; verify `certutil -store -enterprise Root` shows the cert. |
| `VigilKernelSession AlreadyExist` | Stale ETW session from a previous crash (pre-M7.7) | Upgrade to current; `ControlTraceA(STOP)` runs on startup. |
| Agent task starts but exits immediately | Bad `agent.env` format | Check `C:\Windows\Temp\vigil-agent.err.log`. |
| `taskkill /F` succeeds against agent | Driver not loaded, or `g_ProtectedPid == 0` | `sc.exe query edr` (RUNNING) and verify the agent logged `driver.self_protection.registered`. |
| Defender races and wins our kill IOCTL | Built-in signature on the target name (e.g. `mimikatz.exe`) | Lab-only: `Set-MpPreference -DisableRealtimeMonitoring $true`. Block-path is unaffected. |

### Sigma / detection pipeline

| Symptom | Likely cause | Fix |
|---|---|---|
| Same alert opens twice (or N times) after a sigma worker restart | The realtime Sigma engine doesn't dedup across Kafka offset replays. ADR 0005 acknowledges this — when the percolator worker restarts, it re-consumes the last batch of events and re-fires any matches. Expected, not a bug. | Close the duplicates manually; if a worker bounces repeatedly, fix the underlying crash rather than try to suppress the duplicates. The percolator + auto-action path is idempotent on commands (the IOC dedup map in `agent_commands` keys by `(host_id, command_kind, payload)`), so the kernel block list ends up correct even if N alerts opened. |

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
