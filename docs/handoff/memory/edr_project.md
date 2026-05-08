---
name: EDR project
description: Active project at /mnt/d/priv/code/edr — HarfangLab-style EDR (agent + manager). Currently in M0 scaffolding.
type: project
originSessionId: 04069394-44f9-41e9-9017-3a82415636ec
---
EDR (Endpoint Detection and Response) PoC inspired by HarfangLab.

**Why:** User is building this as a personal project / PoC, with cloud / on-prem distinction deferred. Local install only at PoC stage. Strong API-first stance — the web UI is a thin client over the same REST API; everything UI does must be doable via API.

**How to apply:** Treat this as the active codebase when the user references "the EDR", "the agent", "the manager", "the backend" without further qualification. Working dir is `/mnt/d/priv/code/edr/`.

**Core requirements (frozen):**
- Agent installed on endpoints, manages: YARA rules, Sigma rules, IOCs (filenames, paths, hashes).
- Agent scans memory and disk; tracks parent/child process relationships; emits telemetry.
- Per-rule action mode: `detect` / `kill` / `block` (block process startup).
- Alert lifecycle: `new` → `investigating` → `false_positive | true_positive`.
- Manager fully API-driven; web UI is one consumer.
- Performance-conscious agent — minimize endpoint resource use.
- HarfangLab as reference design (not feature-parity target).

**Milestone structure (16-week target):**
- M0: foundations / scaffolding
- M1: backend core + UI shell + enrollment CA
- M2: Windows agent thin slice (user-mode only, ETW)
- M3: Sigma streaming pipeline (Flink)
- M4: Windows kernel driver (KMDF + minifilter)
- M5: response actions (kill/block)
- M6: Linux agent (eBPF)
- M7: polish, self-protection, installers, RBAC

**Top risks tracked:**
1. Windows kernel driver complexity / dev-VM iteration speed.
2. Flink + pySigma integration (fallback: Python streaming consumer).
3. mTLS PKI handling correctness.
4. Schema drift between Rust/Python (mitigated: protobuf as source of truth, CI check).
