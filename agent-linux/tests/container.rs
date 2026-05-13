//! Phase 2 #2.9 — integration test for the container cgroup parser.
//!
//! `container.rs` is a private module of the `vigil-agent` binary
//! crate (no library target), so we re-include the source file as an
//! out-of-tree module rather than reach in via `pub use`. The
//! `#[path]` attribute compiles the same `src/container.rs` once more
//! here; the parse helpers it exposes are pure functions with no
//! tokio dependency, so this binary stays cross-platform clean.

#![cfg(target_os = "linux")]

#[path = "../src/container.rs"]
#[allow(dead_code)]
mod container;

use agent_core::proto as p;

/// Per-runtime fixture: the cgroup blob `/proc/<pid>/cgroup` would
/// contain when a process is running inside the named runtime.
fn fixture(runtime: &str) -> &'static str {
    match runtime {
        "docker_v2_systemd" => {
            // cgroup v2 with systemd cgroup driver — most common
            // Docker-on-Ubuntu shape today.
            "0::/system.slice/docker-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef.scope\n"
        }
        "docker_v1_legacy" => {
            // Older cgroupv1 docker setup with the simple /docker/<id> path.
            "12:cpu,cpuacct:/docker/abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\n\
             11:memory:/docker/abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\n"
        }
        "containerd_v2_systemd" => {
            "0::/system.slice/containerd-1111111111111111111111111111111111111111111111111111111111111111.scope\n"
        }
        "crio_kubepods" => {
            // k8s with CRI-O — the runtime prefix sits inside
            // /kubepods.slice/<qos>/<pod>/.
            "0::/kubepods.slice/kubepods-burstable.slice/\
             kubepods-burstable-pod1234abcd_5678_9abc_def0_123456789abc.slice/\
             crio-fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210.scope\n"
        }
        "podman_libpod" => {
            "0::/machine.slice/libpod-feedfacecafebabefeedfacecafebabefeedfacecafebabefeedfacecafebabe.scope\n"
        }
        "bare_metal_user_slice" => "0::/user.slice/user-1000.slice/session-3.scope\n",
        "bare_metal_root_init" => "0::/init.scope\n",
        // systemd unit name that LOOKS suspicious but isn't a container id.
        "systemd_unit_decoy" => "0::/system.slice/cron.service\n",
        _ => panic!("unknown fixture: {runtime}"),
    }
}

#[test]
fn parses_docker_systemd_scope() {
    let parsed = container::parse_cgroup(fixture("docker_v2_systemd")).expect("docker parse");
    assert_eq!(parsed.runtime, p::ContainerRuntime::Docker);
    assert_eq!(parsed.id.len(), 64);
    assert!(parsed.id.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn parses_docker_legacy_v1() {
    let parsed = container::parse_cgroup(fixture("docker_v1_legacy")).expect("docker v1 parse");
    assert_eq!(parsed.runtime, p::ContainerRuntime::Docker);
}

#[test]
fn parses_containerd_systemd_scope() {
    let parsed =
        container::parse_cgroup(fixture("containerd_v2_systemd")).expect("containerd parse");
    assert_eq!(parsed.runtime, p::ContainerRuntime::Containerd);
}

#[test]
fn parses_crio_kubepods() {
    let parsed = container::parse_cgroup(fixture("crio_kubepods")).expect("crio parse");
    assert_eq!(parsed.runtime, p::ContainerRuntime::CriO);
}

#[test]
fn parses_podman_libpod_scope() {
    let parsed = container::parse_cgroup(fixture("podman_libpod")).expect("podman parse");
    assert_eq!(parsed.runtime, p::ContainerRuntime::Podman);
}

#[test]
fn ignores_bare_metal_processes() {
    assert!(container::parse_cgroup(fixture("bare_metal_user_slice")).is_none());
    assert!(container::parse_cgroup(fixture("bare_metal_root_init")).is_none());
}

#[test]
fn ignores_systemd_unit_decoys() {
    // `cron.service` is not a container id even though it sits under
    // /system.slice/ — the prefix-aware matcher must reject it.
    assert!(container::parse_cgroup(fixture("systemd_unit_decoy")).is_none());
}

#[test]
fn runtime_tokens_match_ecs_normaliser() {
    // The Python normalizer maps the proto enum onto these exact
    // strings; agent-side `runtime_token` mirrors that table so a
    // future log line includes the same value the SOC searches for.
    assert_eq!(
        container::runtime_token(p::ContainerRuntime::Docker),
        "docker"
    );
    assert_eq!(
        container::runtime_token(p::ContainerRuntime::Containerd),
        "containerd"
    );
    assert_eq!(container::runtime_token(p::ContainerRuntime::CriO), "cri_o");
    assert_eq!(
        container::runtime_token(p::ContainerRuntime::Podman),
        "podman"
    );
}
