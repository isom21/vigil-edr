//! Integration test for the Linux memory reader (Phase 2 #2.1).
//!
//! Spawns a child `sleep` process, then opens it via the
//! [`agent_linux::scanner_memory::open`] entry point and walks its
//! address space. Asserts:
//!
//!   1. The walker returns at least one readable region.
//!   2. The total bytes available across the first handful of regions
//!      is non-trivial (sleep has at least a heap + stack + a few
//!      libc-backed mappings).
//!   3. Opening pid 0 errors out instead of silently returning an
//!      empty walker.
//!
//! `/proc/<pid>/mem` needs CAP_SYS_PTRACE (or root) on kernels ≥ 4.5;
//! the test skips with a clear message when the open fails so devs
//! without those caps don't see a confusing assertion failure.

#![cfg(target_os = "linux")]

use std::process::{Child, Command};
use std::time::Duration;

fn spawn_target() -> Child {
    Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn sleep")
}

#[test]
fn reads_at_least_one_region_from_child() {
    // Bring the trait into scope so `next_region()` resolves.
    #[allow(unused_imports)]
    use agent_core::scanner::MemoryRegionReader;
    use agent_linux::scanner_memory;

    let mut child = spawn_target();
    // Let the child get past execve / dynamic linker setup so its
    // maps are stable.
    std::thread::sleep(Duration::from_millis(150));

    let pid = child.id();
    let reader_result = scanner_memory::open(pid);
    let (regions, total_bytes, skip_msg) = match reader_result {
        Ok(mut reader) => {
            let mut regions = 0usize;
            let mut total_bytes = 0u64;
            while let Ok(Some(region)) = reader.next_region() {
                regions += 1;
                total_bytes += region.bytes.len() as u64;
                if regions > 64 {
                    break;
                }
            }
            (regions, total_bytes, None)
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("Permission denied") || msg.contains("EACCES") {
                (0, 0, Some(msg))
            } else {
                let _ = child.kill();
                let _ = child.wait();
                panic!("open pid={pid}: {e}");
            }
        }
    };

    // Reap unconditionally so the child never lingers; clippy's
    // zombie_processes lint demands wait() on every code path.
    let _ = child.kill();
    let _ = child.wait();

    if let Some(msg) = skip_msg {
        eprintln!("skipping: no CAP_SYS_PTRACE ({msg})");
        return;
    }
    assert!(regions > 0, "expected ≥1 readable region from pid {pid}");
    assert!(
        total_bytes > 4096,
        "expected non-trivial bytes; got {total_bytes}"
    );
}

#[test]
fn open_invalid_pid_errors() {
    use agent_linux::scanner_memory;
    let err = match scanner_memory::open(0) {
        Ok(_) => panic!("expected pid=0 open to fail"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(
        msg.contains("/proc/0") || msg.contains("No such") || msg.contains("invalid"),
        "unexpected error: {msg}"
    );
}
