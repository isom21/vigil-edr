---
name: Disable Defender real-time protection for EDR tests on lab-windows
description: When verifying agent kill/block flows on lab-windows (or other Windows test VMs), temporarily turn off Defender real-time protection so it doesn't race the EDR's actions.
type: feedback
originSessionId: 621387c2-943d-4e98-9fe3-2fe6a8adf4f4
---
For end-to-end tests of EDR response actions on lab-windows (or any Windows test VM running our agent), temporarily disable Defender real-time protection before triggering kill/block flows. Re-enable after the test if you care.

**Why:** During M5.5 (auto-action verification), spawning a process renamed `mimikatz.exe` to trigger our IOC rule (action=kill) consistently failed at the agent's `ZwOpenProcess(pid, PROCESS_TERMINATE)` IOCTL with `STATUS_INVALID_CID` → `ERROR_INVALID_PARAMETER` (0x80070057). Defender on Server 2022 has a built-in signature on `mimikatz.exe` and terminates such processes within ~1s — winning the race against our gRPC-dispatched kill command. The auto-trigger plumbing was correct; the kill just had no PID left to operate on. Block-create flows (where the driver vetoes at PsCreateNotify with STATUS_ACCESS_DENIED before any signature scan happens) are not affected.

**How to apply:**
- Before kill-path tests: `Set-MpPreference -DisableRealtimeMonitoring $true` (PowerShell, admin).
- After: `Set-MpPreference -DisableRealtimeMonitoring $false`.
- Path exclusion is an alternative: `Add-MpPreference -ExclusionPath "C:\Users\administrator"` to whitelist a working directory.
- The block path (action=block, driver-side STATUS_ACCESS_DENIED at PsCreateProcessNotifyRoutineEx) does NOT need this — it runs strictly before any AV signature scan, so Defender never sees the process.
- Document the toggle in the test session and put it back when done. Don't leave Defender disabled across reboots.
