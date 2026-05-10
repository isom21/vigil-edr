// build.rs — re-runs ebpf/build.sh when the eBPF source or build script
// changes, so `cargo build` always carries a fresh edr.bpf.o.
//
// We don't fail the user-mode build if the ebpf build fails on a non-Linux
// host — the eBPF code is gated on `target_os = "linux"` anyway. On Linux
// without clang installed, the build fails with a clearer message than
// missing object would later at load time.

use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let ebpf_dir = manifest_dir.join("ebpf");
    println!("cargo:rerun-if-changed={}/edr.bpf.c", ebpf_dir.display());
    println!("cargo:rerun-if-changed={}/build.sh", ebpf_dir.display());
    // Also re-run when the output is missing — protects against the case
    // where someone deletes edr.bpf.o between builds; cargo otherwise
    // skips build.rs (only watches the listed sources) and rustc fails
    // on a stale `include_bytes!` path.
    println!("cargo:rerun-if-changed={}/edr.bpf.o", ebpf_dir.display());

    // Skip on non-Linux (kept for `cargo check` from cross-platform CI).
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }

    // Skip if explicitly disabled (useful for offline / no-clang dev
    // hosts and CI runners that just want to validate the userspace
    // Rust). When skipped we still need an `edr.bpf.o` for the
    // `include_bytes!` macro at compile time — write a 16-byte
    // ELF-magic-prefixed stub if one doesn't already exist. The aya
    // loader will reject it at runtime, but the user-space code
    // compiles cleanly, which is all CI needs.
    let object_path = ebpf_dir.join("edr.bpf.o");
    if env::var_os("EDR_SKIP_EBPF_BUILD").is_some() {
        println!("cargo:warning=EDR_SKIP_EBPF_BUILD set; not invoking ebpf/build.sh");
        ensure_stub_object(&object_path);
        return;
    }

    let status = std::process::Command::new("bash")
        .arg(ebpf_dir.join("build.sh"))
        .status();
    match status {
        Ok(s) if s.success() => {}
        Ok(s) => {
            // Build script is most often blocked by missing
            // bpftool / clang / BTF on a CI runner. Don't fail the
            // user-space build; emit a stub and warn loudly so a
            // real-deployment build still surfaces the issue (the
            // operator running `cargo build` on the target host
            // sees the warning and the resulting agent fails to
            // load BPF programs at runtime).
            println!(
                "cargo:warning=ebpf/build.sh exited {s}; writing stub edr.bpf.o (build-time only)"
            );
            ensure_stub_object(&object_path);
        }
        Err(e) => {
            println!("cargo:warning=ebpf/build.sh: failed to spawn: {e}; writing stub edr.bpf.o");
            ensure_stub_object(&object_path);
        }
    }
}

/// Write a minimal ELF stub at `path` if no file exists there. We
/// keep the existing object whenever the build script succeeded —
/// only the no-tools / build-failed paths fall through to here, and
/// only when nothing has populated the file yet.
fn ensure_stub_object(path: &std::path::Path) {
    if path.exists() {
        return;
    }
    // 16-byte placeholder; aya will refuse to load it at runtime,
    // which is intended — CI builds should not be deployed to a
    // real host.
    let stub: [u8; 16] = [0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    if let Err(e) = std::fs::write(path, stub) {
        panic!("failed to write stub edr.bpf.o at {}: {e}", path.display());
    }
}
