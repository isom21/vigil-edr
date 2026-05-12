//! Verifier-only smoke test (not a release target).
//!
//! Loads the bundled `vigil.bpf.o` and calls `.load()` on every
//! program — which is what triggers the kernel BPF verifier. Skips
//! `.attach()` so it doesn't need BPF LSM enabled in `/sys/kernel/
//! security/lsm`. Use this on a dev box with CAP_BPF (or sudo) to
//! confirm a recent change passes the verifier before you ship.
//!
//! Run with:
//!     sudo target/release/examples/verifier_check
#![cfg(target_os = "linux")]

use anyhow::Result;
use aya::programs::{Lsm, TracePoint};
use aya::{Btf, Ebpf};

#[repr(C, align(8))]
struct AlignedObject<const N: usize>([u8; N]);

static EBPF_OBJECT_ALIGNED: &AlignedObject<{ include_bytes!("../ebpf/vigil.bpf.o").len() }> =
    &AlignedObject(*include_bytes!("../ebpf/vigil.bpf.o"));
const EBPF_OBJECT: &[u8] = &EBPF_OBJECT_ALIGNED.0;

fn main() -> Result<()> {
    let mut ebpf = Ebpf::load(EBPF_OBJECT)?;
    println!("ebpf object parsed");

    // Tracepoint programs: BTF id is implicit, no extra hookup needed
    // for .load().
    for name in &[
        "handle_sched_exec",
        "handle_sched_exit",
        "handle_module_load",
    ] {
        let prog: &mut TracePoint = ebpf
            .program_mut(name)
            .ok_or_else(|| anyhow::anyhow!("missing program {name}"))?
            .try_into()?;
        prog.load()?;
        println!("  tracepoint loaded: {name}");
    }

    // LSM programs: need BTF + the hook name to compute the BTF id at
    // load time. Verifier runs here. We don't attach so this works on
    // hosts that lack BPF LSM in /sys/kernel/security/lsm — kernels
    // still verify the program; the attach is what they reject.
    let btf = Btf::from_sys_fs()?;
    for (name, hook) in &[
        ("handle_file_open", "file_open"),
        ("handle_socket_connect", "socket_connect"),
        ("handle_bprm_check", "bprm_check_security"),
    ] {
        let prog: &mut Lsm = ebpf
            .program_mut(name)
            .ok_or_else(|| anyhow::anyhow!("missing program {name}"))?
            .try_into()?;
        match prog.load(hook, &btf) {
            Ok(()) => println!("  lsm/{hook} loaded: {name}"),
            Err(e) => println!("  lsm/{hook} LOAD ERROR ({name}): {e}"),
        }
    }

    Ok(())
}
