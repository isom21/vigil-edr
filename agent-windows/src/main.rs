//! Windows Vigil agent entry point.
//!
//! Three startup modes:
//!   * **Service** (default when launched by SCM): registers the
//!     service-control-handler, runs the agent on a tokio runtime, and
//!     stops cleanly on SCM Stop / Shutdown.
//!   * **Console** (`vigil-agent --console`): foreground mode for dev /
//!     debugging. Same agent code path, no SCM glue.
//!   * **Install / uninstall** (`vigil-agent --install-service` /
//!     `vigil-agent --uninstall-service`): register with SCM and exit.
//!
//! M9.1 introduced the SCM service path, replacing the M7.4
//! scheduled-task wrapper. The agent's actual logic is in
//! `run_agent_async()` and is identical between modes.

// Phase 2 #2.8 — allowlist wire-format helpers + AllowlistMode. Kept
// cross-platform (same as `driver_wire`) so the buffer-layout unit
// tests run on Linux CI.
mod allowlist;
// Phase 3 #3.10: device control wire helpers (RegChange list builder)
// are cross-platform so the unit tests run on Linux CI. The actual
// HKLM `RegSetValueEx` call lives behind `#[cfg(windows)]` inside the
// module.
mod device_control;
#[cfg(windows)]
mod driver;
// Wire-format helpers are kept cross-platform so the buffer-layout
// unit tests can run on Linux CI (which does the bulk of `cargo test`
// for agent-windows since the rest is Windows-gated).
mod driver_wire;
#[cfg(windows)]
mod etw;
#[cfg(windows)]
mod etw_auth;
mod scanner_memory;
#[cfg(windows)]
mod service;
#[cfg(windows)]
mod terminal;

#[cfg(windows)]
use agent_core::client::open_mtls_channel;
use agent_core::client::ManagerClient;
use agent_core::config::AgentConfig;
use agent_core::enroll::{enroll, EnrollContext};
use agent_core::identity::{Identity, IdentityPaths};
#[cfg(windows)]
use agent_core::jobs::JobDispatcher;
#[cfg(windows)]
use agent_core::jobs_handlers::register_cross_platform_handlers;
#[cfg(windows)]
use agent_core::jobs_hunt::{register_hunt_handlers, register_memory_yara_handler};
#[cfg(windows)]
use agent_core::jobs_sweep::make_sweep_handler;
use agent_core::proto as p;
use anyhow::{Context, Result};
use std::env;
use std::path::PathBuf;
#[cfg(windows)]
use std::sync::Arc;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// M9.5: agent ↔ manager wire-protocol version.
const PROTOCOL_VERSION: u32 = 1;
const CAPABILITIES: &str = "self_protect_v1,spool_v1,host_groups_v1,sigma_realtime_v1,driver_v1,net_isolation_v1,terminal_v1,auth_events_v1,container_v1,memory_yara_v1,allowlist_v1,device_control_v1";

fn main() -> Result<()> {
    init_tracing();

    let _ = rustls::crypto::ring::default_provider().install_default();

    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--install-service") => {
            #[cfg(windows)]
            {
                service::install()?;
                return Ok(());
            }
            #[cfg(not(windows))]
            anyhow::bail!("--install-service is Windows-only")
        }
        Some("--uninstall-service") => {
            #[cfg(windows)]
            {
                service::uninstall()?;
                return Ok(());
            }
            #[cfg(not(windows))]
            anyhow::bail!("--uninstall-service is Windows-only")
        }
        Some("--version") => {
            println!("vigil-agent {AGENT_VERSION}");
            return Ok(());
        }
        Some("--help") => {
            print_help();
            return Ok(());
        }
        Some("--console") | None => {}
        Some(other) => anyhow::bail!("unknown argument: {other} (try --help)"),
    }

    // No-flag default + `--console`: try service mode unless --console
    // was explicit. Service mode auto-detects (returns Ok(false) when
    // not started by SCM) and falls back to console.
    #[cfg_attr(not(windows), allow(unused_variables))]
    let force_console = args.iter().any(|a| a == "--console");

    #[cfg(windows)]
    {
        if !force_console {
            match service::dispatch_if_scm_started() {
                Ok(true) => return Ok(()), // SCM owned us; service_main handled the lifecycle.
                Ok(false) => {
                    tracing::info!("not started by SCM; running in console mode");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "SCM dispatch failed; falling back to console");
                }
            }
        }
    }

    // Console mode: run the agent on a tokio runtime, no stop signal.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(run_agent_async(None))
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();
}

fn print_help() {
    println!(
        r"vigil-agent — EDR endpoint agent for Windows

Usage:
  vigil-agent                       run as a Windows service (auto-detected) or console
  vigil-agent --console             force console mode (foreground)
  vigil-agent --install-service     register the SCM service (one-time)
  vigil-agent --uninstall-service   stop + remove the SCM service
  vigil-agent --version             print version
  vigil-agent --help                this message

Environment:
  VIGIL_AGENT_CONFIG       path to TOML config file
  VIGIL_MANAGER_ENDPOINT   gRPC URL of the manager (https://host:50051)
  VIGIL_MANAGER_REST       REST URL of the manager (http://host:8000)
  VIGIL_ENROLLMENT_TOKEN   one-time enrollment token (first run only)
  VIGIL_STATE_DIR          state directory (default %ProgramData%\Vigil)
  VIGIL_HOSTNAME           override registered hostname

Logs:
  Console mode: stdout (JSON).
  Service mode: stdout is captured by SCM and ends up in
  C:\Windows\Temp\vigil-agent.log if you wire `service` to redirect.
"
    );
}

/// The actual agent body. Async because tokio drives it; takes an
/// optional shutdown receiver that the SCM service uses to stop us
/// gracefully (console mode passes None and runs until killed).
pub async fn run_agent_async(stop_rx: Option<tokio::sync::oneshot::Receiver<()>>) -> Result<()> {
    let cfg = load_config()?;
    let id_paths = IdentityPaths::new(&cfg.identity_dir());

    let identity = if id_paths.enrolled() {
        tracing::info!("agent.identity.using_existing");
        Identity::load(&id_paths)?
    } else {
        let token = cfg
            .enrollment_token
            .as_ref()
            .context("not enrolled and VIGIL_ENROLLMENT_TOKEN unset")?;
        let hostname = cfg.hostname_override.clone().unwrap_or_else(hostname);
        let os = os_info();
        tracing::info!(hostname = %hostname, "agent.enrolling");
        let ctx = EnrollContext {
            rest_endpoint: &cfg.rest_endpoint(),
            enrollment_token: token,
            hostname: &hostname,
            os_family: "windows",
            os_version: &os.version,
            os_platform: &os.platform,
            os_arch: &os.arch,
            agent_version: AGENT_VERSION,
        };
        enroll(&ctx, &id_paths).await?
    };

    tracing::info!(
        host_id = %identity.host_id,
        endpoint = %cfg.manager_endpoint,
        "agent.starting"
    );

    let client = ManagerClient::new(identity.clone(), cfg.manager_endpoint.clone());
    // M9.2.b: disk-backed spool under {state_dir}/spool.
    let spool_dir = cfg.resolved_state_dir().join("spool");
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut client = match client.with_spool(spool_dir.clone()) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, dir = %spool_dir.display(), "spool.disabled");
            ManagerClient::new(identity.clone(), cfg.manager_endpoint.clone())
        }
    };
    let send_tx = client.send_tx.clone();
    #[cfg(windows)]
    let client_rules = client.rules();
    #[cfg(windows)]
    let commands_rx = client.take_commands_rx();

    // Hello.
    let hello = p::ClientMessage {
        payload: Some(p::client_message::Payload::Hello(p::Hello {
            host: Some(p::Host {
                id: identity.host_id.clone(),
                hostname: cfg.hostname_override.clone().unwrap_or_else(hostname),
                os: Some(p::OsInfo {
                    family: "windows".into(),
                    version: os_info().version,
                    platform: os_info().platform,
                    architecture: os_info().arch,
                }),
                agent_version: AGENT_VERSION.into(),
            }),
            boot_time_iso: now_iso(),
            last_event_id_seen: 0,
            protocol_version: PROTOCOL_VERSION,
            capabilities: CAPABILITIES.into(),
        })),
    };
    let _ = send_tx.send(hello).await;

    // Heartbeat.
    let hb_tx = send_tx.clone();
    let hb_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            let now = agent_core::event::now_pb();
            let msg = p::ClientMessage {
                payload: Some(p::client_message::Payload::Heartbeat(p::Heartbeat {
                    ts: Some(now),
                    metrics: Some(p::AgentMetrics::default()),
                })),
            };
            if hb_tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    // Command-dispatch worker (M5.4) + Jobs engine (M23.d).
    #[cfg(windows)]
    if let Some(rx) = commands_rx {
        let send_tx_for_worker = send_tx.clone();
        let job_dispatcher = Arc::new(JobDispatcher::new());
        register_cross_platform_handlers(&job_dispatcher, AGENT_VERSION, std::env::consts::ARCH);
        register_hunt_handlers(&job_dispatcher, client_rules.clone());
        // Phase 2 #2.1: in-memory YARA via OpenProcess + VirtualQueryEx.
        register_memory_yara_handler(&job_dispatcher, client_rules.clone(), scanner_memory::open);
        job_dispatcher.register(make_sweep_handler(&job_dispatcher));
        let identity_for_channel = identity.clone();
        let endpoint_for_channel = cfg.manager_endpoint.clone();
        tokio::spawn(async move {
            let control_channel =
                match open_mtls_channel(&identity_for_channel, &endpoint_for_channel).await {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!(error = %e, "command_worker.control_channel_failed");
                        return;
                    }
                };
            driver::run_command_worker(rx, send_tx_for_worker, job_dispatcher, control_channel)
                .await;
        });
    }

    // Try the kernel driver first (M4.5 ring + IOCTL). Fall back to ETW.
    #[cfg(windows)]
    {
        let driver_ctx = driver::DriverCtx {
            host_id: identity.host_id.clone(),
            agent_id: identity.host_id.clone(),
            agent_version: AGENT_VERSION.into(),
        };
        match driver::start(driver_ctx, send_tx.clone()) {
            Ok(()) => {
                tracing::info!("collector.mode = driver (kernel)");
            }
            Err(driver_err) => {
                tracing::warn!(error = %driver_err, "driver unavailable; falling back to ETW");
                let etw_ctx = etw::WatcherCtx {
                    host_id: identity.host_id.clone(),
                    agent_id: identity.host_id.clone(),
                    agent_version: AGENT_VERSION.into(),
                };
                if let Err(e) = etw::start(etw_ctx, send_tx.clone()) {
                    tracing::error!(error = %e, "etw.start_failed");
                } else {
                    tracing::info!("collector.mode = etw (user-mode fallback)");
                }
            }
        }

        // Phase 2 #2.4: auth-event ETW collector runs alongside the
        // process collector regardless of driver/ETW choice — its
        // provider (Security-Auditing) is independent from the kernel-
        // session process provider.
        if env::var_os("VIGIL_DISABLE_AUTH_EVENTS").is_some() {
            tracing::info!("auth_events.disabled by VIGIL_DISABLE_AUTH_EVENTS");
        } else {
            let auth_ctx = etw_auth::WatcherCtx {
                host_id: identity.host_id.clone(),
                agent_id: identity.host_id.clone(),
                agent_version: AGENT_VERSION.into(),
            };
            if let Err(e) = etw_auth::start(auth_ctx, send_tx.clone()) {
                tracing::warn!(error = %e, "etw_auth.start_failed");
            }
        }
    }

    // Phase 1 #1.4: live-response remote shell. The PTY factory is
    // ConPTY-backed on Windows. The worker awaits a terminal-open
    // signal from the command path, then dials TerminalStream and
    // proxies PTY ↔ gRPC. For now we just register the factory so
    // the capability advertisement is honest.
    #[cfg(windows)]
    let _terminal_factory = terminal::factory();

    // Run the gRPC client until either SCM tells us to stop or the
    // client returns (which it normally doesn't — it reconnects forever).
    if let Some(stop) = stop_rx {
        tokio::select! {
            r = client.run() => r,
            _ = stop => {
                tracing::info!("agent.stop_signal_received");
                hb_handle.abort();
                Ok(())
            }
        }
    } else {
        client.run().await
    }
}

fn load_config() -> Result<AgentConfig> {
    if let Ok(path) = env::var("VIGIL_AGENT_CONFIG") {
        return AgentConfig::load(&PathBuf::from(path));
    }
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
    #[cfg(windows)]
    {
        hostname::get()
            .ok()
            .and_then(|n| n.into_string().ok())
            .unwrap_or_else(|| "windows-host".to_string())
    }
    #[cfg(not(windows))]
    {
        "windows-host-stub".into()
    }
}

struct OsDetails {
    version: String,
    platform: String,
    arch: String,
}

fn os_info() -> OsDetails {
    OsDetails {
        version: "".into(),
        platform: "Windows".into(),
        arch: std::env::consts::ARCH.into(),
    }
}

fn now_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("unix:{}.{:09}", dur.as_secs(), dur.subsec_nanos())
}
