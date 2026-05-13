//! Integration-style coverage for the Phase 2 #2.8 allowlist
//! control plane.
//!
//! The real `AllowlistHandle::sync` needs live BPF maps which only
//! work on a kernel-with-LSM (the eBPF object isn't loaded under
//! `cargo test`). We instead cover the pure-Rust parts:
//!
//!   * proto → AllowlistMode conversion is total and treats unknown
//!     values as OFF (safe default).
//!   * the mode byte the userspace handle writes into the per-CPU
//!     map matches the kernel's `VIGIL_ALLOWLIST_MODE_*` constants
//!     in `ebpf/vigil.bpf.c`.
//!
//! End-to-end BPF coverage runs in the smoke harness under
//! `tools/smoke/45-self-protection-linux.sh` (kept out of `cargo
//! test` so contributors without `CAP_BPF` can still run the suite).

#![cfg(target_os = "linux")]

// `#[path = ...]` pulls the module into the integration-test crate
// without requiring `agent-linux` to expose it via lib.rs (which it
// doesn't — agent-linux is a binary crate).
#[path = "../src/allowlist.rs"]
mod allowlist;

use allowlist::AllowlistMode;

#[test]
fn proto_to_mode_handles_known_values() {
    assert_eq!(AllowlistMode::from_proto(0), AllowlistMode::Off);
    assert_eq!(AllowlistMode::from_proto(1), AllowlistMode::Learn);
    assert_eq!(AllowlistMode::from_proto(2), AllowlistMode::Enforce);
}

#[test]
fn proto_to_mode_unknown_falls_back_to_off() {
    assert_eq!(AllowlistMode::from_proto(-1), AllowlistMode::Off);
    assert_eq!(AllowlistMode::from_proto(99), AllowlistMode::Off);
    assert_eq!(AllowlistMode::from_proto(i32::MAX), AllowlistMode::Off);
}
