//! Windows EDR agent entry point.
//!
//! M2 thin slice:
//! 1. Load config.
//! 2. Enroll if needed (REST).
//! 3. Connect manager via gRPC mTLS.
//! 4. Start ETW kernel-session collector (process_started events).
//! 5. Heartbeat.
//!
//! M4 swaps the user-mode ETW collector for the KMDF driver + minifilter.

#[cfg(windows)]
mod driver;
#[cfg(windows)]
mod etw;

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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    let _ = rustls::crypto::ring::default_provider().install_default();

    let cfg = load_config()?;
    let id_paths = IdentityPaths::new(&cfg.identity_dir());

    let identity = if id_paths.enrolled() {
        tracing::info!("agent.identity.using_existing");
        Identity::load(&id_paths)?
    } else {
        let token = cfg
            .enrollment_token
            .as_ref()
            .context("not enrolled and EDR_ENROLLMENT_TOKEN unset")?;
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

    tracing::info!(host_id = %identity.host_id, endpoint = %cfg.manager_endpoint, "agent.starting");

    let client = ManagerClient::new(identity.clone(), cfg.manager_endpoint.clone());
    let send_tx = client.send_tx.clone();

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
        })),
    };
    let _ = send_tx.send(hello).await;

    // Heartbeat.
    let hb_tx = send_tx.clone();
    tokio::spawn(async move {
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

    // Try the kernel driver first (M4.5 ring + IOCTL). If the device can't
    // be opened (driver not installed or not running) we fall back to the
    // user-mode ETW collector from M2.3c. On non-Windows builds (e.g.
    // cargo check from WSL), both modules are absent and we just skip.
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
    }

    client.run().await
}

fn load_config() -> Result<AgentConfig> {
    if let Ok(path) = env::var("EDR_AGENT_CONFIG") {
        return AgentConfig::load(&PathBuf::from(path));
    }
    let manager_endpoint = env::var("EDR_MANAGER_ENDPOINT")
        .unwrap_or_else(|_| "https://localhost:50051".to_string());
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
    let dur = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    format!("unix:{}.{:09}", dur.as_secs(), dur.subsec_nanos())
}
