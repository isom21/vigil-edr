//! Linux EDR agent entry point.
//!
//! Pipeline (M2):
//! 1. Load config (or env vars).
//! 2. If not enrolled: REST-enroll using config.enrollment_token, persist
//!    cert/key/host_id.
//! 3. Open gRPC HostStream over mTLS.
//! 4. Start /proc poller, send ProcessEvents to the manager.
//! 5. Heartbeat every 30s.

mod command_worker;
mod ebpf;
mod hasher;
mod proc_watcher;

use agent_core::client::ManagerClient;
use agent_core::config::AgentConfig;
use agent_core::enroll::{enroll, EnrollContext};
use agent_core::identity::{Identity, IdentityPaths};
use agent_core::proto as p;
use anyhow::{Context, Result};
use std::env;
use std::path::PathBuf;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// M9.5: agent ↔ manager wire-protocol version. Manager rejects
/// connections with a clear error when this is below its
/// minimum-supported version.
const PROTOCOL_VERSION: u32 = 1;

/// M9.5: capability flags the agent advertises in Hello so the manager
/// can surface fleet rollout state and tailor RuleSync to match. Stable
/// short tokens, comma-separated.
const CAPABILITIES: &str = "self_protect_v1,spool_v1,host_groups_v1,sigma_realtime_v1";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    // CLI: `edr-agent --unpin` removes any pinned BPF objects from a
    // previous run and exits. Useful when the operator wants to
    // permanently stop the agent and clean up bpffs (the LSM hooks
    // would otherwise refuse rm under /sys/fs/bpf/edr/* even after
    // graceful stop, since the pinned hooks survive process exit).
    let mut args = env::args().skip(1);
    if let Some(arg) = args.next() {
        if arg == "--unpin" {
            let pin_dir =
                env::var("EDR_PIN_DIR").unwrap_or_else(|_| ebpf::DEFAULT_PIN_DIR.to_string());
            let pin_dir = PathBuf::from(pin_dir);
            ebpf::Loader::cleanup_or_takeover(&pin_dir)
                .context("cleanup_or_takeover for --unpin")?;
            ebpf::unpin_all(&pin_dir).context("unpin_all")?;
            // Best-effort remove the empty subdirs.
            for sub in ["links", "progs", "maps"] {
                let _ = std::fs::remove_dir(pin_dir.join(sub));
            }
            let _ = std::fs::remove_dir(&pin_dir);
            tracing::info!(pin_dir = %pin_dir.display(), "unpin.complete");
            return Ok(());
        } else if arg == "--version" {
            println!("edr-agent {AGENT_VERSION}");
            return Ok(());
        } else if arg == "--help" {
            println!("edr-agent — EDR endpoint agent\n\nUsage:\n  edr-agent              run the agent (config from EDR_AGENT_CONFIG / env)\n  edr-agent --unpin      remove pinned BPF objects from a previous run\n  edr-agent --version    print version and exit\n  edr-agent --help       this message\n\nKey environment variables:\n  EDR_AGENT_CONFIG       path to TOML config file\n  EDR_MANAGER_ENDPOINT   gRPC URL of the manager (https://host:50051)\n  EDR_MANAGER_REST       REST URL of the manager (http://host:8000)\n  EDR_ENROLLMENT_TOKEN   one-time enrollment token (first run only)\n  EDR_STATE_DIR          state directory (default /var/lib/edr)\n  EDR_HOSTNAME           override registered hostname\n  EDR_DISABLE_EBPF=1     skip eBPF, use /proc-poll fallback\n  EDR_DISABLE_SELF_PROTECTION=1   skip M7.1 self-protection hooks\n  EDR_PIN_DIR            override bpffs pin dir (default /sys/fs/bpf/edr)\n");
            return Ok(());
        } else {
            anyhow::bail!("unknown argument: {arg} (try --help)");
        }
    }

    // Required since rustls 0.23 stopped auto-selecting a default provider.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // M7.1 self-protection: tighten ptrace/dump surface before anything
    // sensitive runs. Belt-and-braces with the lsm/ptrace_access_check
    // BPF hook installed below — this one works even when BPF LSM is
    // unavailable (older kernel, lockdown) and prevents the kernel from
    // generating core dumps that could leak our keys.
    if env::var_os("EDR_DISABLE_SELF_PROTECTION").is_none() {
        // SAFETY: prctl(PR_SET_DUMPABLE, ...) takes one int arg; the
        // remaining four longs are documented as ignored. libc::prctl is
        // variadic on Linux glibc, so we still pass placeholders.
        let r = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0u64, 0u64, 0u64, 0u64) };
        if r != 0 {
            tracing::warn!(
                errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
                "self_protection.prctl_set_dumpable.failed"
            );
        }

        // M12.a: refuse to start if the on-disk binary's SHA-256 doesn't
        // match the value recorded by the deb/rpm postinst.
        if let Err(e) = check_binary_integrity() {
            if env::var_os("EDR_DISABLE_INTEGRITY_CHECK").is_some() {
                tracing::warn!(error = %e, "agent.binary_integrity.bypassed");
            } else {
                tracing::error!(error = %e, "agent.binary_integrity.mismatch");
                return Err(anyhow::anyhow!("binary integrity check failed: {e}"));
            }
        }
    }

    let cfg = load_config()?;
    let id_paths = IdentityPaths::new(&cfg.identity_dir());

    let identity = if id_paths.enrolled() {
        tracing::info!("agent.identity.using_existing");
        Identity::load(&id_paths)?
    } else {
        let token = cfg
            .enrollment_token
            .as_ref()
            .context("not enrolled and EDR_ENROLLMENT_TOKEN / config.enrollment_token unset")?;
        let hostname = cfg.hostname_override.clone().unwrap_or_else(hostname);
        let os = os_info();
        tracing::info!(hostname = %hostname, "agent.enrolling");
        let ctx = EnrollContext {
            rest_endpoint: &cfg.rest_endpoint(),
            enrollment_token: token,
            hostname: &hostname,
            os_family: "linux",
            os_version: &os.version,
            os_platform: &os.platform,
            os_arch: &os.arch,
            agent_version: AGENT_VERSION,
        };
        enroll(&ctx, &id_paths).await?
    };

    tracing::info!(host_id = %identity.host_id, endpoint = %cfg.manager_endpoint, "agent.starting");

    let client = ManagerClient::new(identity.clone(), cfg.manager_endpoint.clone());
    // M9.2.b: attach the disk-backed spool so events that can't be
    // delivered while the manager is unreachable are persisted, not
    // dropped at the channel boundary.
    let spool_dir = cfg.resolved_state_dir().join("spool");
    let mut client = match client.with_spool(spool_dir.clone()) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, dir = %spool_dir.display(), "spool.disabled");
            ManagerClient::new(identity.clone(), cfg.manager_endpoint.clone())
        }
    };
    let send_tx = client.send_tx.clone();
    let mut commands_rx = client.take_commands_rx();

    // Initial Hello.
    let hello = p::ClientMessage {
        payload: Some(p::client_message::Payload::Hello(p::Hello {
            host: Some(p::Host {
                id: identity.host_id.clone(),
                hostname: cfg.hostname_override.clone().unwrap_or_else(hostname),
                os: Some(p::OsInfo {
                    family: "linux".into(),
                    version: os_info().version,
                    platform: os_info().platform,
                    architecture: os_info().arch,
                }),
                agent_version: AGENT_VERSION.into(),
            }),
            boot_time_iso: chrono_now_iso(),
            last_event_id_seen: 0,
            protocol_version: PROTOCOL_VERSION,
            capabilities: CAPABILITIES.into(),
        })),
    };
    let _ = send_tx.send(hello).await;

    // Heartbeat task.
    let hb_tx = send_tx.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            let now = agent_core::event::now_pb();
            let msg = p::ClientMessage {
                payload: Some(p::client_message::Payload::Heartbeat(p::Heartbeat {
                    ts: Some(now),
                    metrics: Some(p::AgentMetrics {
                        cpu_percent: 0.0,
                        memory_bytes: 0,
                        events_emitted: 0,
                        events_dropped: 0,
                        spool_bytes: 0,
                        // M9.4 self-diagnostics — populated from kernel
                        // counters in a follow-up; zeros here are the
                        // schema-stable default that older managers also
                        // accept (proto3 zero-default semantics).
                        spool_entries: 0,
                        ringbuf_drops: 0,
                        self_protection_active: 0,
                        last_event_age_seconds: 0,
                        collector_mode: 0,
                    }),
                })),
            };
            if hb_tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    // eBPF collector first (M6). On any failure (no CAP_BPF, kernel feature
    // missing, kernel version too old, etc.), fall back to the M2 /proc
    // poller so the agent still produces telemetry. EDR_DISABLE_EBPF=1
    // forces the fallback for testing the legacy path on a kernel that
    // would otherwise load the BPF object.
    let self_protect_enabled = env::var_os("EDR_DISABLE_SELF_PROTECTION").is_none();
    let pin_dir_str = env::var("EDR_PIN_DIR").unwrap_or_else(|_| ebpf::DEFAULT_PIN_DIR.to_string());
    let pin_dir = PathBuf::from(&pin_dir_str);

    // Take over (or clean up) any pinned objects from a previous run
    // *before* we Ebpf::load — otherwise stale lsm/bpf hooks can refuse
    // operations we do during normal load. cleanup_or_takeover is a
    // no-op when no pins exist.
    if self_protect_enabled && env::var_os("EDR_DISABLE_EBPF").is_none() {
        if let Err(e) = ebpf::Loader::cleanup_or_takeover(&pin_dir) {
            tracing::warn!(error = %e, "self_protection.takeover.failed");
        }
    }

    let mut ebpf_loader = if env::var_os("EDR_DISABLE_EBPF").is_some() {
        tracing::info!("ebpf disabled by EDR_DISABLE_EBPF; using /proc poller");
        None
    } else {
        match ebpf::Loader::load_and_attach() {
            Ok(l) => {
                tracing::info!("collector.mode = ebpf (kernel)");
                Some(l)
            }
            Err(e) => {
                tracing::warn!(error = ?e, "ebpf load failed; falling back to /proc poller");
                None
            }
        }
    };
    if let Some(loader) = ebpf_loader.as_mut() {
        let drain_ctx = ebpf::LoaderCtx {
            host_id: identity.host_id.clone(),
            agent_id: identity.host_id.clone(),
            agent_version: AGENT_VERSION.into(),
        };
        // M10.a: file hashing for FileEvent enrichment. Disabled by
        // env var when an operator wants the absolute lowest CPU
        // footprint.
        let hasher = if env::var_os("EDR_DISABLE_FILE_HASHING").is_some() {
            None
        } else {
            Some(hasher::Hasher::spawn())
        };
        if let Err(e) = loader.spawn_drainer(drain_ctx, send_tx.clone(), hasher) {
            tracing::error!(error = %e, "ebpf.drainer.spawn_failed");
        }

        // Wire the command worker into the kernel block lists.
        let state_dir = cfg.resolved_state_dir();
        match loader.take_block_lists() {
            Ok(blocks) => {
                let restored = command_worker::restore(&state_dir, &blocks).unwrap_or_default();
                if let Some(rx) = commands_rx.take() {
                    let send_tx2 = send_tx.clone();
                    let state_dir_for_worker = state_dir.clone();
                    tokio::spawn(async move {
                        command_worker::run(state_dir_for_worker, blocks, restored, rx, send_tx2)
                            .await;
                    });
                }
            }
            Err(e) => tracing::error!(error = %e, "ebpf.block_lists.unavailable"),
        }

        // M7.1: enable self-protection AFTER block lists are taken so
        // their MapData ownership has moved to the command worker. Other
        // maps (agent_self, protected_inodes, stats, events) are still
        // available via map_mut/map.
        if self_protect_enabled {
            match loader.enable_self_protection(&state_dir, &pin_dir) {
                Ok(paths) => {
                    tracing::info!(pin_count = paths.len(), pin_dir = %pin_dir.display(), "self_protection.ready");
                }
                Err(e) => {
                    tracing::error!(error = %e, "self_protection.enable_failed (degraded mode)");
                }
            }
        } else {
            tracing::warn!("self_protection.disabled by EDR_DISABLE_SELF_PROTECTION");
        }
    }
    if ebpf_loader.is_none() {
        let watcher_ctx = proc_watcher::WatcherCtx {
            host_id: identity.host_id.clone(),
            agent_id: identity.host_id.clone(),
            agent_version: AGENT_VERSION.into(),
        };
        let watcher_tx = send_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = proc_watcher::run(watcher_ctx, watcher_tx).await {
                tracing::error!(error = %e, "proc_watcher.exit");
            }
        });
        tracing::info!("collector.mode = proc-poll (fallback)");
    }

    // For M6.1 there's no event delivery from eBPF yet; we periodically log
    // the stats counters so an operator can confirm the kernel-side program
    // is firing. M6.2 replaces this with real event drainage. We keep the
    // loader alive for the agent's lifetime by parking it in a task that
    // owns it; on Drop the eBPF programs unload.
    if let Some(mut loader) = ebpf_loader {
        tokio::spawn(async move {
            // First read happens immediately — confirms the map is reachable.
            if let Ok(s) = loader.read_stats() {
                tracing::info!(stats = %ebpf::format_stats(&s), "ebpf.stats.initial");
            }
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                match loader.read_stats() {
                    Ok(s) => tracing::info!(stats = %ebpf::format_stats(&s), "ebpf.stats"),
                    Err(e) => tracing::warn!(error = %e, "ebpf.stats.read_failed"),
                }
            }
        });
    }

    // gRPC client run-loop (reconnects forever).
    client.run().await
}

fn load_config() -> Result<AgentConfig> {
    if let Ok(path) = env::var("EDR_AGENT_CONFIG") {
        return AgentConfig::load(&PathBuf::from(path));
    }
    // Otherwise build from env vars (convenient for dev runs).
    let manager_endpoint =
        env::var("EDR_MANAGER_ENDPOINT").unwrap_or_else(|_| "https://localhost:50051".to_string());
    let manager_rest_endpoint = env::var("EDR_MANAGER_REST").ok();
    let enrollment_token = env::var("EDR_ENROLLMENT_TOKEN").ok();
    let state_dir = env::var("EDR_STATE_DIR").ok().map(PathBuf::from);
    let hostname_override = env::var("EDR_HOSTNAME").ok();
    Ok(AgentConfig {
        manager_endpoint,
        manager_rest_endpoint,
        enrollment_token,
        state_dir,
        hostname_override,
    })
}

fn hostname() -> String {
    nix::unistd::gethostname()
        .ok()
        .and_then(|n| n.into_string().ok())
        .unwrap_or_else(|| "linux-host".to_string())
}

struct OsDetails {
    version: String,
    platform: String,
    arch: String,
}

fn os_info() -> OsDetails {
    OsDetails {
        version: read_release().unwrap_or_default(),
        platform: "Linux".into(),
        arch: std::env::consts::ARCH.into(),
    }
}

fn read_release() -> Option<String> {
    let s = std::fs::read_to_string("/etc/os-release").ok()?;
    let mut name = "".to_string();
    let mut version = "".to_string();
    for line in s.lines() {
        if let Some(v) = line.strip_prefix("PRETTY_NAME=") {
            name = v.trim_matches('"').to_string();
        } else if let Some(v) = line.strip_prefix("VERSION_ID=") {
            version = v.trim_matches('"').to_string();
        }
    }
    if name.is_empty() {
        Some(version)
    } else {
        Some(format!("{} {}", name, version))
    }
}

fn chrono_now_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("unix:{}.{:09}", dur.as_secs(), dur.subsec_nanos())
}

/// M12.a: hash `/proc/self/exe` and compare against
/// `/etc/edr/agent.sha256` recorded by postinst. Skips silently if the
/// manifest file is missing — covers operator workflows where the
/// agent was installed manually (no postinst) and the integrity check
/// is opt-in via the deb/rpm install path.
fn check_binary_integrity() -> Result<()> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let manifest_path = "/etc/edr/agent.sha256";
    let expected = match std::fs::read_to_string(manifest_path) {
        Ok(s) => s.trim().to_string(),
        Err(_) => {
            tracing::debug!(
                path = manifest_path,
                "binary_integrity.no_manifest (manual install? skipping check)"
            );
            return Ok(());
        }
    };
    if expected.is_empty() {
        return Ok(());
    }

    let mut file = std::fs::File::open("/proc/self/exe").context("open /proc/self/exe")?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).context("read /proc/self/exe")?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let actual = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    if actual.eq_ignore_ascii_case(&expected) {
        tracing::info!(
            sha256 = %&actual[..16],
            "agent.binary_integrity.ok"
        );
        Ok(())
    } else {
        anyhow::bail!(
            "binary on disk does not match manifest: expected {}, got {}",
            &expected,
            &actual
        )
    }
}
