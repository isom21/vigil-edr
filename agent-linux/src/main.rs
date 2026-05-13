//! Linux Vigil agent entry point.
//!
//! Pipeline (M2):
//! 1. Load config (or env vars).
//! 2. If not enrolled: REST-enroll using config.enrollment_token, persist
//!    cert/key/host_id.
//! 3. Open gRPC HostStream over mTLS.
//! 4. Start /proc poller, send ProcessEvents to the manager.
//! 5. Heartbeat every 30s.

mod capdrop;
mod command_worker;
mod ebpf;
mod hasher;
mod proc_watcher;
mod prom;
mod terminal;

use agent_core::client::{open_mtls_channel, ManagerClient};
use agent_core::config::AgentConfig;
use agent_core::enroll::{enroll, EnrollContext};
use agent_core::identity::{Identity, IdentityPaths};
use agent_core::integrity::IntegrityBaseline;
use agent_core::jobs::JobDispatcher;
use agent_core::jobs_handlers::register_cross_platform_handlers;
use agent_core::jobs_hunt::register_hunt_handlers;
use agent_core::jobs_sweep::make_sweep_handler;
use agent_core::proto as p;
use anyhow::{Context, Result};
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
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
const CAPABILITIES: &str =
    "self_protect_v1,spool_v1,host_groups_v1,sigma_realtime_v1,net_isolation_v1,terminal_v1";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    // CLI: `vigil-agent --unpin` removes any pinned BPF objects from a
    // previous run and exits. Useful when the operator wants to
    // permanently stop the agent and clean up bpffs (the LSM hooks
    // would otherwise refuse rm under /sys/fs/bpf/vigil/* even after
    // graceful stop, since the pinned hooks survive process exit).
    let mut args = env::args().skip(1);
    if let Some(arg) = args.next() {
        if arg == "--unpin" {
            let pin_dir =
                env::var("VIGIL_PIN_DIR").unwrap_or_else(|_| ebpf::DEFAULT_PIN_DIR.to_string());
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
            println!("vigil-agent {AGENT_VERSION}");
            return Ok(());
        } else if arg == "--help" {
            println!("vigil-agent — EDR endpoint agent\n\nUsage:\n  vigil-agent              run the agent (config from VIGIL_AGENT_CONFIG / env)\n  vigil-agent --unpin      remove pinned BPF objects from a previous run\n  vigil-agent --version    print version and exit\n  vigil-agent --help       this message\n\nKey environment variables:\n  VIGIL_AGENT_CONFIG       path to TOML config file\n  VIGIL_MANAGER_ENDPOINT   gRPC URL of the manager (https://host:50051)\n  VIGIL_MANAGER_REST       REST URL of the manager (http://host:8000)\n  VIGIL_ENROLLMENT_TOKEN   one-time enrollment token (first run only)\n  VIGIL_STATE_DIR          state directory (default /var/lib/vigil)\n  VIGIL_HOSTNAME           override registered hostname\n  VIGIL_DISABLE_EBPF=1     skip eBPF, use /proc-poll fallback\n  VIGIL_DISABLE_SELF_PROTECTION=1   skip BPF LSM self-protection hooks\n  VIGIL_PIN_DIR            override bpffs pin dir (default /sys/fs/bpf/vigil)\n");
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
    if env::var_os("VIGIL_DISABLE_SELF_PROTECTION").is_none() {
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
            if env::var_os("VIGIL_DISABLE_INTEGRITY_CHECK").is_some() {
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
            .context("not enrolled and VIGIL_ENROLLMENT_TOKEN / config.enrollment_token unset")?;
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
    let client_rules = client.rules();
    let mut commands_rx = client.take_commands_rx();

    // M14.b: agent-side Prometheus exporter snapshot. Created early so
    // the M12.a integrity watchdog (below) and the BPF stats loop
    // (later) share the same atomic counter struct. Spawned right
    // after creation so /metrics is reachable as soon as possible
    // during agent boot.
    let metrics_snap = std::sync::Arc::new(prom::MetricsSnapshot::default());
    if env::var_os("VIGIL_DISABLE_AGENT_METRICS").is_none() {
        let bind = env::var("VIGIL_AGENT_METRICS_BIND").unwrap_or_else(|_| "127.0.0.1:9101".into());
        prom::spawn(&bind, metrics_snap.clone());
    }

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

    // M12.a: runtime integrity watchdog. Captures SHA-256 baselines of
    // /proc/self/exe and the active config file at startup, then
    // periodically (5 min) re-verifies and emits an AgentTamperEvent
    // alert if either drifts. The startup gate (check_binary_integrity)
    // already ran above against the deb/rpm manifest; this is the
    // post-startup runtime check that catches an attacker who
    // overwrites the binary while the agent is paused or rotates the
    // config without going through the package manager. Disabled via
    // VIGIL_DISABLE_INTEGRITY_WATCHDOG=1.
    if env::var_os("VIGIL_DISABLE_INTEGRITY_WATCHDOG").is_none() {
        let bin_path = PathBuf::from("/proc/self/exe");
        let cfg_path = env::var("VIGIL_AGENT_CONFIG").ok().map(PathBuf::from);
        match IntegrityBaseline::capture(bin_path, cfg_path) {
            Ok(baseline) => {
                tracing::info!(
                    binary_sha256_prefix =
                        &baseline.binary_sha256[..16.min(baseline.binary_sha256.len())],
                    config_tracked = baseline.config_path.is_some(),
                    "agent.integrity_watchdog.baseline_captured"
                );
                let snap = metrics_snap.clone();
                let watchdog_tx = send_tx.clone();
                let host_id = identity.host_id.clone();
                let agent_id = identity.host_id.clone();
                let interval_secs = env::var("VIGIL_INTEGRITY_INTERVAL_SECS")
                    .ok()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(300);
                tokio::spawn(async move {
                    let mut interval =
                        tokio::time::interval(Duration::from_secs(interval_secs.max(30)));
                    // Skip the immediate-fire so we don't alert at t=0
                    // when the baseline was just taken.
                    interval.tick().await;
                    loop {
                        interval.tick().await;
                        let drift = baseline.verify();
                        if drift.is_clean() {
                            continue;
                        }
                        if let Some(d) = drift.binary {
                            tracing::error!(
                                path = %d.path.display(),
                                expected = %d.expected,
                                actual = %d.actual,
                                "agent.tamper.binary_mismatch"
                            );
                            snap.tamper_binary
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let ev = agent_core::event::agent_tamper(
                                &host_id,
                                &agent_id,
                                AGENT_VERSION,
                                p::TamperKind::BinaryMismatch,
                                &d.path.display().to_string(),
                                &d.expected,
                                &d.actual,
                                "binary hash drifted from startup baseline",
                            );
                            let _ = watchdog_tx
                                .send(p::ClientMessage {
                                    payload: Some(p::client_message::Payload::Events(
                                        p::EventBatch {
                                            events: vec![ev],
                                            batch_id: ulid::Ulid::new().to_string(),
                                            first_seq: 0,
                                            last_seq: 0,
                                        },
                                    )),
                                })
                                .await;
                        }
                        if let Some(d) = drift.config {
                            tracing::error!(
                                path = %d.path.display(),
                                expected = %d.expected,
                                actual = %d.actual,
                                "agent.tamper.config_mismatch"
                            );
                            snap.tamper_config
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let ev = agent_core::event::agent_tamper(
                                &host_id,
                                &agent_id,
                                AGENT_VERSION,
                                p::TamperKind::ConfigMismatch,
                                &d.path.display().to_string(),
                                &d.expected,
                                &d.actual,
                                "config hash drifted from startup baseline",
                            );
                            let _ = watchdog_tx
                                .send(p::ClientMessage {
                                    payload: Some(p::client_message::Payload::Events(
                                        p::EventBatch {
                                            events: vec![ev],
                                            batch_id: ulid::Ulid::new().to_string(),
                                            first_seq: 0,
                                            last_seq: 0,
                                        },
                                    )),
                                })
                                .await;
                        }
                    }
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "agent.integrity_watchdog.disabled");
            }
        }
    }

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
    // poller so the agent still produces telemetry. VIGIL_DISABLE_EBPF=1
    // forces the fallback for testing the legacy path on a kernel that
    // would otherwise load the BPF object.
    let self_protect_enabled = env::var_os("VIGIL_DISABLE_SELF_PROTECTION").is_none();
    let pin_dir_str =
        env::var("VIGIL_PIN_DIR").unwrap_or_else(|_| ebpf::DEFAULT_PIN_DIR.to_string());
    let pin_dir = PathBuf::from(&pin_dir_str);

    // Take over (or clean up) any pinned objects from a previous run
    // *before* we Ebpf::load — otherwise stale lsm/bpf hooks can refuse
    // operations we do during normal load. cleanup_or_takeover is a
    // no-op when no pins exist.
    if self_protect_enabled && env::var_os("VIGIL_DISABLE_EBPF").is_none() {
        if let Err(e) = ebpf::Loader::cleanup_or_takeover(&pin_dir) {
            tracing::warn!(error = %e, "self_protection.takeover.failed");
        }
    }

    let mut ebpf_loader = if env::var_os("VIGIL_DISABLE_EBPF").is_some() {
        tracing::info!("ebpf disabled by VIGIL_DISABLE_EBPF; using /proc poller");
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
        let hasher = if env::var_os("VIGIL_DISABLE_FILE_HASHING").is_some() {
            None
        } else {
            Some(hasher::Hasher::spawn())
        };
        if let Err(e) = loader.spawn_drainer(drain_ctx, send_tx.clone(), hasher) {
            tracing::error!(error = %e, "ebpf.drainer.spawn_failed");
        }

        // Wire the command worker into the kernel block lists.
        // Pass the pin_dir so isolation maps survive an agent restart
        // — see `Loader::take_block_lists` for the why.
        let state_dir = cfg.resolved_state_dir();
        let pin_arg = self_protect_enabled.then_some(pin_dir.as_path());
        match loader.take_block_lists(pin_arg) {
            Ok(blocks) => {
                let restored = command_worker::restore(&state_dir, &blocks).unwrap_or_default();
                if let Some(rx) = commands_rx.take() {
                    let send_tx2 = send_tx.clone();
                    let state_dir_for_worker = state_dir.clone();
                    let worker_identity = command_worker::WorkerIdentity {
                        host_id: identity.host_id.clone(),
                        agent_id: identity.host_id.clone(),
                        agent_version: AGENT_VERSION.into(),
                    };

                    // M23.d: build the JobDispatcher with the cross-
                    // platform handlers, then open a dedicated mTLS
                    // channel the worker can use for unary RPCs
                    // (RequestArtifactUpload). Keeping it separate from
                    // the bidi stream means reconnects don't tear down
                    // in-flight unary calls.
                    let job_dispatcher = Arc::new(JobDispatcher::new());
                    register_cross_platform_handlers(
                        &job_dispatcher,
                        AGENT_VERSION,
                        std::env::consts::ARCH,
                    );
                    register_hunt_handlers(&job_dispatcher, client_rules.clone());
                    // host_sweep registered last so it sees every
                    // sub-handler as supported.
                    job_dispatcher.register(make_sweep_handler(&job_dispatcher));

                    let identity_for_channel = identity.clone();
                    let endpoint_for_channel = cfg.manager_endpoint.clone();
                    tokio::spawn(async move {
                        let control_channel =
                            match open_mtls_channel(&identity_for_channel, &endpoint_for_channel)
                                .await
                            {
                                Ok(c) => c,
                                Err(e) => {
                                    tracing::error!(
                                        error = %e,
                                        "command_worker.control_channel_failed"
                                    );
                                    return;
                                }
                            };
                        command_worker::run(
                            state_dir_for_worker,
                            blocks,
                            restored,
                            worker_identity,
                            rx,
                            send_tx2,
                            job_dispatcher,
                            control_channel,
                        )
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
                    // M12.b: BPF attachment watchdog. Runs only when
                    // self-protection enabled successfully — there's
                    // nothing to watch otherwise. Periodically verifies
                    // each pinned link + map file is still present;
                    // missing files are a tamper signal (root attacker
                    // running `rm /sys/fs/bpf/vigil/...` to detach our
                    // hooks).
                    if env::var_os("VIGIL_DISABLE_BPF_WATCHDOG").is_none() {
                        spawn_bpf_watchdog(
                            pin_dir.clone(),
                            identity.host_id.clone(),
                            metrics_snap.clone(),
                            send_tx.clone(),
                        );
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "self_protection.enable_failed (degraded mode)");
                }
            }
        } else {
            tracing::warn!("self_protection.disabled by VIGIL_DISABLE_SELF_PROTECTION");
        }
    }

    // M12.c: drop unneeded Linux capabilities once init is complete.
    // BPF programs are loaded, LSM hooks attached, pin files written,
    // command worker spawned — the residual runtime needs are
    // CAP_BPF / CAP_PERFMON / CAP_KILL / a few /proc-traversal caps.
    // Everything else (CAP_SYS_BOOT, CAP_NET_RAW, CAP_SETUID, etc.) is
    // dead weight in our threat model — dropping them shrinks what an
    // exploit on the agent's userspace half (e.g. through the gRPC
    // wire path) gives the attacker.
    if env::var_os("VIGIL_DISABLE_CAPDROP").is_some() {
        tracing::warn!("capdrop.disabled by VIGIL_DISABLE_CAPDROP");
    } else {
        match capdrop::drop_to_minimum() {
            Ok(report) => {
                tracing::info!(
                    bounding_dropped = report.bounding_dropped.len(),
                    effective_kept = ?report.effective_kept,
                    no_new_privs = report.no_new_privs,
                    "capdrop.complete"
                );
            }
            Err(e) => {
                // Non-fatal: a misconfigured environment (e.g. running
                // under capsh --drop=cap_bpf already) shouldn't kill
                // the agent. The startup gate already ran; this is
                // defense-in-depth.
                tracing::warn!(error = %e, "capdrop.failed (continuing)");
            }
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

    // BPF stats reader. The metrics snapshot was set up earlier so
    // the integrity watchdog could populate tamper counters; here we
    // just feed BPF kernel counters into the same snapshot every 5s.
    if let Some(mut loader) = ebpf_loader {
        let snap = metrics_snap.clone();
        tokio::spawn(async move {
            // First read happens immediately — confirms the map is reachable.
            if let Ok(s) = loader.read_stats() {
                tracing::info!(stats = %ebpf::format_stats(&s), "ebpf.stats.initial");
                snap.update_from_bpf(&s);
            }
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                match loader.read_stats() {
                    Ok(s) => {
                        tracing::info!(stats = %ebpf::format_stats(&s), "ebpf.stats");
                        snap.update_from_bpf(&s);
                    }
                    Err(e) => tracing::warn!(error = %e, "ebpf.stats.read_failed"),
                }
            }
        });
    }

    // Phase 1 #1.4: live-response remote shell. The PTY factory is
    // platform-specific (forkpty here, ConPTY on Windows). The
    // worker awaits a terminal-open signal from the command path,
    // then dials TerminalStream against the manager and proxies
    // PTY ↔ gRPC. For now we just register the factory so the
    // capability advertisement is honest; the dispatcher in
    // command_worker reuses it.
    let _terminal_factory = terminal::factory();

    // gRPC client run-loop (reconnects forever).
    client.run().await
}

fn load_config() -> Result<AgentConfig> {
    if let Ok(path) = env::var("VIGIL_AGENT_CONFIG") {
        return AgentConfig::load(&PathBuf::from(path));
    }
    // Otherwise build from env vars (convenient for dev runs).
    let manager_endpoint = env::var("VIGIL_MANAGER_ENDPOINT")
        .unwrap_or_else(|_| "https://localhost:50051".to_string());
    let manager_rest_endpoint = env::var("VIGIL_MANAGER_REST").ok();
    let enrollment_token = env::var("VIGIL_ENROLLMENT_TOKEN").ok();
    let state_dir = env::var("VIGIL_STATE_DIR").ok().map(PathBuf::from);
    let hostname_override = env::var("VIGIL_HOSTNAME").ok();
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
/// `/etc/vigil/agent.sha256` recorded by postinst. Skips silently if the
/// manifest file is missing — covers operator workflows where the
/// agent was installed manually (no postinst) and the integrity check
/// is opt-in via the deb/rpm install path.
fn check_binary_integrity() -> Result<()> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let manifest_path = "/etc/vigil/agent.sha256";
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

/// M12.b: BPF attachment watchdog.
///
/// After self-protection succeeded, the LSM links and self-protection
/// maps live as files under `<pin_dir>/links/<hook>` and
/// `<pin_dir>/maps/<name>`. An attacker with root can bypass our
/// hooks by removing those files (which doesn't immediately detach
/// the program — the agent still holds an in-process `Link` — but it
/// strips the persistence guarantee, so a subsequent agent crash
/// leaves the kernel hookless).
///
/// We poll for missing pin files every `VIGIL_BPF_WATCHDOG_INTERVAL_SECS`
/// (default 30s) and emit AgentTamperEvent when one disappears. The
/// alarm is per-file with a one-shot suppression to avoid log/alert
/// flooding if it stays missing — re-fires only when we see it
/// reappear and disappear again.
fn spawn_bpf_watchdog(
    pin_dir: PathBuf,
    host_id: String,
    snap: std::sync::Arc<prom::MetricsSnapshot>,
    send_tx: tokio::sync::mpsc::Sender<p::ClientMessage>,
) {
    let interval_secs = env::var("VIGIL_BPF_WATCHDOG_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(30)
        .max(5);
    tokio::spawn(async move {
        // Per-target latch: true => already alerted, suppress until
        // the file reappears.
        let mut alerted_links: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut alerted_maps: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        // Skip immediate fire — pin files may still be appearing.
        interval.tick().await;
        loop {
            interval.tick().await;
            for (_prog, hook) in ebpf::EXPECTED_LSM_HOOKS.iter() {
                let path = pin_dir.join("links").join(hook);
                if path.exists() {
                    alerted_links.remove(*hook);
                    continue;
                }
                if !alerted_links.insert(hook.to_string()) {
                    continue;
                }
                tracing::error!(
                    path = %path.display(),
                    hook = %hook,
                    "agent.tamper.bpf_link_detached"
                );
                snap.tamper_bpf_detached
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let ev = agent_core::event::agent_tamper(
                    &host_id,
                    &host_id,
                    AGENT_VERSION,
                    p::TamperKind::BpfDetached,
                    &path.display().to_string(),
                    "",
                    "",
                    &format!("pinned LSM link `{hook}` missing from bpffs"),
                );
                let _ = send_tx
                    .send(p::ClientMessage {
                        payload: Some(p::client_message::Payload::Events(p::EventBatch {
                            events: vec![ev],
                            batch_id: ulid::Ulid::new().to_string(),
                            first_seq: 0,
                            last_seq: 0,
                        })),
                    })
                    .await;
            }
            for name in ebpf::EXPECTED_PINNED_MAPS.iter() {
                let path = pin_dir.join("maps").join(name);
                if path.exists() {
                    alerted_maps.remove(*name);
                    continue;
                }
                if !alerted_maps.insert(name.to_string()) {
                    continue;
                }
                tracing::error!(
                    path = %path.display(),
                    map = %name,
                    "agent.tamper.bpf_map_missing"
                );
                snap.tamper_bpf_map_missing
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let ev = agent_core::event::agent_tamper(
                    &host_id,
                    &host_id,
                    AGENT_VERSION,
                    p::TamperKind::BpfMapMissing,
                    &path.display().to_string(),
                    "",
                    "",
                    &format!("pinned map `{name}` missing from bpffs"),
                );
                let _ = send_tx
                    .send(p::ClientMessage {
                        payload: Some(p::client_message::Payload::Events(p::EventBatch {
                            events: vec![ev],
                            batch_id: ulid::Ulid::new().to_string(),
                            first_seq: 0,
                            last_seq: 0,
                        })),
                    })
                    .await;
            }
        }
    });
}
