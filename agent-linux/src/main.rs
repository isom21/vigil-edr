//! Linux EDR agent entry point.
//!
//! Pipeline (M2):
//! 1. Load config (or env vars).
//! 2. If not enrolled: REST-enroll using config.enrollment_token, persist
//!    cert/key/host_id.
//! 3. Open gRPC HostStream over mTLS.
//! 4. Start /proc poller, send ProcessEvents to the manager.
//! 5. Heartbeat every 30s.

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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .json()
        .init();

    // Required since rustls 0.23 stopped auto-selecting a default provider.
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
            .context("not enrolled and EDR_ENROLLMENT_TOKEN / config.enrollment_token unset")?;
        let hostname = cfg
            .hostname_override
            .clone()
            .unwrap_or_else(|| hostname());
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
    let send_tx = client.send_tx.clone();

    // Initial Hello.
    let hello = p::ClientMessage {
        payload: Some(p::client_message::Payload::Hello(p::Hello {
            host: Some(p::Host {
                id: identity.host_id.clone(),
                hostname: cfg
                    .hostname_override
                    .clone()
                    .unwrap_or_else(|| hostname()),
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
                    }),
                })),
            };
            if hb_tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    // /proc watcher.
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

    // gRPC client run-loop (reconnects forever).
    client.run().await
}

fn load_config() -> Result<AgentConfig> {
    if let Ok(path) = env::var("EDR_AGENT_CONFIG") {
        return AgentConfig::load(&PathBuf::from(path));
    }
    // Otherwise build from env vars (convenient for dev runs).
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
    let dur = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    format!("unix:{}.{:09}", dur.as_secs(), dur.subsec_nanos())
}
