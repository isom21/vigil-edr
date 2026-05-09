---
name: EDR lab hosts (lab-linux, lab-windows)
description: SSH-reachable lab VMs for the EDR project; topology, networking, OS, gotchas. Use these for agent runtime testing.
type: project
originSessionId: 621387c2-943d-4e98-9fe3-2fe6a8adf4f4
---
EDR project (working dir `/home/dev/custom-edr/`) has two lab VMs reachable via SSH from the dev host. Both are on the user's Tailscale tailnet.

**Hosts:**

| Name | Tailscale IP | OS | User | SSH key |
|---|---|---|---|---|
| `lab-linux` | `100.99.225.128` | Ubuntu (verify on first connect) | `ubuntu` | `~/.ssh/edr-dev.key` |
| `lab-windows` | `100.88.227.119` | **Windows Server 2022 Datacenter** (build 10.0.20348) | `Administrator` | `~/.ssh/edr-dev.key` |

The dev host itself is `dev` (`100.111.232.7`, MagicDNS `dev.taila4f9bf.ts.net`).

**Why:** The previous session had no Windows VM at all — the M2.3c (agent-windows) skeleton was never compiled. The migration to this host on 2026-05-09 was specifically to wire `lab-windows` into the loop. M4 (KMDF kernel driver) work also runs from here.

**How to apply:**
- For agent runtime testing, target `lab-windows` for Windows agent / driver work and `lab-linux` for additional Linux agent coverage.
- `~/.ssh/config` Host blocks already exist; the key on disk is `edr-dev.key` (the `.key` suffix matters — config used to point at `~/.ssh/edr-dev` and break; fixed 2026-05-09).
- Manager endpoint exposed to lab VMs: use `dev.taila4f9bf.ts.net` (MagicDNS) or `100.111.232.7` (Tailscale IPv4). The manager's gRPC server cert SAN list must include whichever you pick — see `app/grpc/server.py::_server_credentials` and the `EDR_GRPC_SAN_EXTRAS` env var.
- **Server 2022 caveats for the EDR work:** NT 10.0.20348 — same kernel family as Win11, so user-mode ETW + `windows = 0.58` work the same. Frozen-stack target is Win10 22H2 + Win11 (`edr_stack_decisions.md`); Server 2022 differs on Defender-for-Server defaults, WHQL/HVCI behavior for drivers, and absent-by-default toolchain (no winget, no Microsoft Store, no MSVC, no Rust). Treat it as good-enough for M2.3c verification but flag if M4 driver behavior diverges from a Win11 client.
- **Toolchain on `lab-windows`** (verified 2026-05-09 = blank): no rust/cargo, no MSVC `cl`/`link`, no `git`, no `winget`, no `vswhere`. PowerShell 5.1 only (no pwsh 7). C: drive ~64 GB free.
- IE Enhanced Security Configuration may interfere with web downloads on Server; prefer `Invoke-WebRequest` (PowerShell) over Edge for fetching installers.
