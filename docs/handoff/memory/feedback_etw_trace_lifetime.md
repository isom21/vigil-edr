---
name: ETW kernel trace lifetime + ferrisetw 1.2 gotchas
description: When working on agent-windows ETW code, watch for the `let _ = trace` drop-pattern bug and these ferrisetw 1.2 API specifics that bit M2.3c.
type: feedback
originSessionId: 621387c2-943d-4e98-9fe3-2fe6a8adf4f4
---
When editing `agent-windows/src/etw.rs` or any other ETW/ferrisetw code in this project, three traps hit during M2.3c verification on Server 2022:

1. **`let _ = trace` drops the value immediately** — in Rust, the bare-underscore pattern matches but doesn't bind. Used at the end of a `thread::spawn(move || { let _ = trace; thread::park(); })`, the kernel session ends *before* the spawned thread parks. Use `let _trace = trace;` (named binding with leading underscore for unused-warning suppression). This was the root cause of "ETW session is running per `logman` but no events flow" in M2.3c.

2. **`ferrisetw::trace::TraceError` doesn't implement `std::error::Error`** — `?` on `start_and_process()` won't compile through an `anyhow::Result<()>` return type. Wrap with `.map_err(|e| anyhow::anyhow!("...: {e:?}"))` or similar.

3. **`EventRecord::timestamp()` was renamed to `raw_timestamp()` in ferrisetw 1.2.** Old guides will use `timestamp()`; the compiler suggests the rename.

**Why:** All three were silent-ish failures (one runtime, two compile-time). Logging "session running" + zero events almost always means the trace handle was dropped — verify the lifetime first before chasing schema/permissions.

**How to apply:**
- For any `KernelTrace` / `UserTrace` returned by ferrisetw, give the binding a real name and verify it lives for the trace's intended lifetime. Don't trust comments that say `let _ = trace; // hold reference`.
- If the agent restarts and `start_and_process()` returns `EtwNativeError(AlreadyExist)`, the prior kernel session is still in the kernel. Permanent fix is to call `ControlTraceA(..., EVENT_TRACE_CONTROL_STOP)` for the same session name on startup. Dev workaround: `logman stop EDRKernelSession -ets` before each launch.
- For diagnostic visibility, keep the `tracing::info!("etw.kernel_trace.started")` after a successful `start_and_process()` and the `tracing::debug!`/`warn!` inside `on_event` for sent/dropped batches. Run with `RUST_LOG=info,edr_agent::etw=trace` to see per-event opcodes.
- The legacy "NT Kernel Logger" session is single-instance system-wide — using a custom name (`EDRKernelSession`) lets multiple components coexist, but every distinct name is a separate session that must be stopped on agent exit.
