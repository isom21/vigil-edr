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

    // Skip if explicitly disabled (useful for offline / no-clang dev hosts).
    if env::var_os("EDR_SKIP_EBPF_BUILD").is_some() {
        println!("cargo:warning=EDR_SKIP_EBPF_BUILD set; not invoking ebpf/build.sh");
        return;
    }

    let status = std::process::Command::new("bash")
        .arg(ebpf_dir.join("build.sh"))
        .status();
    match status {
        Ok(s) if s.success() => {}
        Ok(s) => panic!("ebpf/build.sh failed: {s}"),
        Err(e) => panic!("ebpf/build.sh: failed to spawn: {e}"),
    }
}
