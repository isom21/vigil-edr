//! Minimal library surface for the Linux agent.
//!
//! The agent's production entrypoint is the `vigil-agent` binary at
//! `src/main.rs`. This library exists purely so integration tests in
//! `tests/` can `use agent_linux::…` without dragging in the binary's
//! `main()` and side-effecting `tokio::main`.
//!
//! Modules added here MUST stay free of process-startup side effects.

#![cfg(target_os = "linux")]

pub mod scanner_memory;
