//! gRPC HostStream client.
//!
//! Connects to the manager over mTLS, opens a long-lived bidi stream, sends
//! events from a tokio::mpsc channel, and processes server messages
//! (RuleSync, Pong, Command).

use anyhow::{anyhow, Context, Result};
use prost::Message;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint, Identity as TlsIdentity};

use crate::identity::Identity;
use crate::proto as p;
use crate::spool::SpoolQueue;

const SEND_CHANNEL_CAP: usize = 1024;

/// Cached server-pushed rule snapshot. Updated whenever a RuleSync arrives.
#[derive(Clone, Default)]
pub struct RuleCache(Arc<RwLock<Option<p::RuleSync>>>);

impl RuleCache {
    pub async fn snapshot(&self) -> Option<p::RuleSync> {
        self.0.read().await.clone()
    }

    pub async fn replace(&self, rs: p::RuleSync) {
        *self.0.write().await = Some(rs);
    }
}

pub struct ManagerClient {
    pub identity: Identity,
    pub endpoint: String,
    pub send_tx: mpsc::Sender<p::ClientMessage>,
    send_rx: Option<mpsc::Receiver<p::ClientMessage>>,
    /// Server-pushed Command messages are forwarded here. The platform-
    /// specific agent (agent-windows / agent-linux) takes the receiver via
    /// [`Self::take_commands_rx`] and runs a dispatcher.
    commands_tx: mpsc::Sender<p::Command>,
    commands_rx: Option<mpsc::Receiver<p::Command>>,
    rules: RuleCache,
    /// M9.2.b: optional disk-backed spool. When present, events that
    /// can't be delivered before the manager reconnects are persisted
    /// rather than dropped at the channel boundary; on reconnect the
    /// spool drains in seq order before live events resume.
    spool: Option<Arc<SpoolQueue>>,
}

impl ManagerClient {
    pub fn new(identity: Identity, endpoint: String) -> Self {
        let (send_tx, send_rx) = mpsc::channel(SEND_CHANNEL_CAP);
        let (commands_tx, commands_rx) = mpsc::channel(64);
        Self {
            identity,
            endpoint,
            send_tx,
            send_rx: Some(send_rx),
            commands_tx,
            commands_rx: Some(commands_rx),
            rules: RuleCache::default(),
            spool: None,
        }
    }

    /// M9.2.b: attach a disk-backed spool. `dir` is the spool directory
    /// (recommended: `{state_dir}/spool`). Idempotent; safe to call
    /// after process restart.
    pub fn with_spool(mut self, dir: PathBuf) -> Result<Self> {
        let q =
            SpoolQueue::open(&dir).with_context(|| format!("open spool at {}", dir.display()))?;
        self.spool = Some(Arc::new(q));
        Ok(self)
    }

    pub fn rules(&self) -> RuleCache {
        self.rules.clone()
    }

    /// Take the receiver end of the command channel. Call this once at
    /// startup; the platform-specific agent runs a worker that consumes
    /// commands and dispatches them to the driver / native APIs.
    pub fn take_commands_rx(&mut self) -> Option<mpsc::Receiver<p::Command>> {
        self.commands_rx.take()
    }

    /// Open the bidi stream and run forever, reconnecting on failure with
    /// simple exponential backoff. The agent feeds events via `self.send_tx`.
    pub async fn run(mut self) -> Result<()> {
        let mut send_rx = self
            .send_rx
            .take()
            .ok_or_else(|| anyhow!("ManagerClient already running"))?;
        let identity = self.identity.clone();
        let endpoint_url = self.endpoint.clone();
        let rules = self.rules.clone();
        let commands_tx = self.commands_tx.clone();
        let spool = self.spool.clone();

        let mut backoff_ms: u64 = 500;
        loop {
            match Self::run_once(
                &endpoint_url,
                &identity,
                &mut send_rx,
                &rules,
                &commands_tx,
                spool.as_deref(),
            )
            .await
            {
                Ok(()) => {
                    tracing::warn!("grpc.stream.closed_clean — reconnecting");
                    backoff_ms = 500;
                }
                Err(err) => {
                    tracing::warn!(error = %err, "grpc.stream.closed_with_error");
                }
            }

            // M9.2.b: while disconnected, anything the producer pushes
            // into send_tx accumulates in send_rx with no consumer.
            // Drain it into the spool during the backoff sleep so we
            // don't lose events to channel-cap drops. The recv()-with-
            // timeout shape means we both rate-limit the spool churn
            // and respect the backoff window.
            if let Some(q) = spool.as_deref() {
                let deadline = tokio::time::Instant::now() + Duration::from_millis(backoff_ms);
                let mut spooled = 0usize;
                while tokio::time::Instant::now() < deadline {
                    let recv_remaining =
                        deadline.saturating_duration_since(tokio::time::Instant::now());
                    match tokio::time::timeout(recv_remaining, send_rx.recv()).await {
                        Ok(Some(msg)) => {
                            let mut buf = Vec::with_capacity(msg.encoded_len());
                            if msg.encode(&mut buf).is_ok() && q.push(&buf).is_ok() {
                                spooled += 1;
                            }
                        }
                        Ok(None) => break, // send_tx all dropped
                        Err(_) => break,   // backoff window elapsed
                    }
                }
                if spooled > 0 {
                    tracing::info!(spooled, "grpc.spool.persisted_during_backoff");
                }
            } else {
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            }
            // Exponential backoff + ±25% jitter so a manager restart doesn't
            // bring the fleet back synchronously and stampede the gRPC port.
            let next = (backoff_ms.saturating_mul(2)).min(30_000);
            let jitter_window = next / 2; // ±25% of next
                                          // SAFETY: not crypto — using nanos-since-epoch as a cheap source
                                          // of per-host entropy. Two agents reconnecting on the same wall
                                          // clock tick still get different jitter from their per-process
                                          // clock skew.
            let now_nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos() as u64)
                .unwrap_or(0);
            let jitter = if jitter_window > 0 {
                (now_nanos % jitter_window) as i64 - (jitter_window / 2) as i64
            } else {
                0
            };
            backoff_ms = (next as i64 + jitter).max(100) as u64;
        }
    }

    async fn run_once(
        endpoint: &str,
        identity: &Identity,
        send_rx: &mut mpsc::Receiver<p::ClientMessage>,
        rules: &RuleCache,
        commands_tx: &mpsc::Sender<p::Command>,
        spool: Option<&SpoolQueue>,
    ) -> Result<()> {
        let channel = open_mtls_channel(identity, endpoint).await?;

        let mut stub = p::agent_service_client::AgentServiceClient::new(channel);

        // Outbound stream — drains the send_rx into gRPC.
        let (out_tx, out_rx) = mpsc::channel::<p::ClientMessage>(SEND_CHANNEL_CAP);
        let outbound = ReceiverStream::new(out_rx);

        // M9.2.b: drain any spool entries from a previous disconnect
        // *before* resuming live event delivery, so manager-side ordering
        // matches what the agent emitted. Spool entries are protobuf
        // ClientMessage payloads written verbatim.
        //
        // The drain itself is sync (the spool API is sync), but
        // forwarding into out_tx must be async (tokio mpsc). We
        // collect the bytes first, then `await` send each one. The
        // false-return-on-error path keeps unsent entries on disk.
        if let Some(q) = spool {
            let mut to_replay: Vec<Vec<u8>> = Vec::new();
            // Take a snapshot of pending entries; drain returns each
            // entry once and removes it on Ok(true). We always return
            // true here because we're owning the bytes after read.
            let _ = q.drain(|bytes| {
                to_replay.push(bytes.to_vec());
                Ok(true)
            });
            let mut replayed = 0usize;
            for bytes in &to_replay {
                let msg = match p::ClientMessage::decode(bytes.as_slice()) {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::warn!(error = %e, "grpc.spool.decode_failed_dropping");
                        continue;
                    }
                };
                if out_tx.send(msg).await.is_err() {
                    // Stream broke mid-replay; remaining bytes were
                    // already removed from disk by drain(). Re-spool
                    // them so they're not lost.
                    for leftover in &to_replay[replayed..] {
                        let _ = q.push(leftover);
                    }
                    break;
                }
                replayed += 1;
            }
            if replayed > 0 {
                tracing::info!(replayed, "grpc.spool.drained");
            }
        }

        // Forward send_rx to out_tx (so the caller's send_tx outlives the
        // stream and reconnect cycles preserve buffered events). We
        // hold a mutable borrow of send_rx for the lifetime of this
        // forward future, which lets us reuse send_rx for spool drain
        // after the select! returns.
        let forward = async {
            while let Some(msg) = send_rx.recv().await {
                if out_tx.send(msg).await.is_err() {
                    break;
                }
            }
        };

        let response = stub.host_stream(tonic::Request::new(outbound)).await?;
        let mut inbound = response.into_inner();

        let inbound_task = async {
            while let Some(srv_msg) = inbound.message().await? {
                match srv_msg.payload {
                    Some(p::server_message::Payload::Rules(rs)) => {
                        tracing::info!(
                            yara = rs.yara.len(),
                            iocs = rs.iocs.len(),
                            version = rs.rules_version,
                            "grpc.rule_sync.received"
                        );
                        rules.replace(rs).await;
                    }
                    Some(p::server_message::Payload::Pong(_)) => {
                        tracing::debug!("grpc.pong");
                    }
                    Some(p::server_message::Payload::Command(cmd)) => {
                        let cid = cmd.command_id.clone();
                        tracing::info!(command_id = %cid, "grpc.command.received");
                        // Forward to the platform-specific dispatcher. If the
                        // receiver was never taken (no dispatcher wired) the
                        // channel buffer will fill — drop on backpressure with
                        // a warning so we don't block the inbound loop.
                        if let Err(e) = commands_tx.try_send(cmd) {
                            tracing::warn!(
                                command_id = %cid,
                                error = %e,
                                "grpc.command.no_dispatcher_or_full"
                            );
                        }
                    }
                    Some(p::server_message::Payload::Policy(_)) => {
                        tracing::info!("grpc.policy_update.received");
                    }
                    None => {}
                }
            }
            Ok::<_, tonic::Status>(())
        };

        tokio::select! {
            r = inbound_task => { r.map_err(|s| anyhow!("inbound: {}", s))?; }
            _ = forward => {}
        }
        // The accumulator-during-backoff in `run()` handles spool
        // persistence; nothing to do here. `_unused = spool;` quiets
        // the parameter-unused lint while we keep the signature
        // stable for future use (e.g. mid-stream replay control).
        let _ = spool;
        Ok(())
    }
}

/// Extract the host portion of an endpoint URL to use as TLS SNI / cert
/// validation name. Handles common shapes:
///
///   - "https://manager.example.com:50051"  → "manager.example.com"
///   - "https://192.168.1.10:50051"         → "192.168.1.10"
///   - "https://[::1]:50051"                → "::1"
///   - "manager.example.com:50051"          → "manager.example.com"
///   - "https://manager.example.com"        → "manager.example.com"
///
/// Returns None if the endpoint can't be parsed into a non-empty host.
/// Callers should fall back to a safe default (e.g. "localhost") so the
/// dev-time loopback path keeps working — but in any deployment where
/// the cert is signed for a real hostname, deriving the SNI from the
/// endpoint is the only way the TLS handshake succeeds.
pub(crate) fn derive_sni(endpoint: &str) -> Option<String> {
    // Strip scheme.
    let after_scheme = endpoint
        .find("://")
        .map(|i| &endpoint[i + 3..])
        .unwrap_or(endpoint);
    // Strip path / query.
    let host_port = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    // IPv6 in brackets: "[::1]:port" → "::1".
    if let Some(rest) = host_port.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = &rest[..end];
            if !host.is_empty() {
                return Some(host.to_string());
            }
        }
        return None;
    }
    // Otherwise strip port (last colon, but only if what follows is digits
    // — a bare IPv6 without brackets like "::1" would falsely match here).
    let host = match host_port.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => h,
        _ => host_port,
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Open a single mTLS channel to the manager. Used by both the
/// bidi-stream client and the Jobs engine's unary RequestArtifactUpload
/// path (M23.c) so they share TLS config + dial settings.
///
/// The TLS SNI / cert-validation name is derived from `endpoint`'s host
/// portion. Operators don't need to configure SNI separately: whatever
/// hostname is in `manager_endpoint` is also what the manager's server
/// cert needs to be signed for. The legacy "localhost" was load-bearing
/// only in dev where the bundled cert is signed for "localhost"; in
/// production, hardcoding it prevented the cert validation from ever
/// succeeding against a real FQDN.
pub async fn open_mtls_channel(identity: &Identity, endpoint: &str) -> Result<Channel> {
    let tls_id = TlsIdentity::from_pem(&identity.client_cert_pem, &identity.client_key_pem);
    let sni = derive_sni(endpoint).unwrap_or_else(|| "localhost".to_string());
    let tls = ClientTlsConfig::new()
        .ca_certificate(tonic::transport::Certificate::from_pem(
            &identity.ca_chain_pem,
        ))
        .identity(tls_id)
        .domain_name(sni);

    Endpoint::from_shared(endpoint.to_string())?
        .tls_config(tls)?
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(60))
        .keep_alive_while_idle(true)
        .http2_keep_alive_interval(Duration::from_secs(30))
        .connect()
        .await
        .with_context(|| format!("dial {endpoint}"))
}

#[cfg(test)]
mod sni_tests {
    use super::derive_sni;

    #[test]
    fn https_with_port() {
        assert_eq!(
            derive_sni("https://manager.example.com:50051").as_deref(),
            Some("manager.example.com"),
        );
    }

    #[test]
    fn https_without_port() {
        assert_eq!(
            derive_sni("https://manager.example.com").as_deref(),
            Some("manager.example.com"),
        );
    }

    #[test]
    fn ipv4_with_port() {
        assert_eq!(
            derive_sni("https://192.168.1.10:50051").as_deref(),
            Some("192.168.1.10"),
        );
    }

    #[test]
    fn ipv6_bracketed_with_port() {
        assert_eq!(derive_sni("https://[::1]:50051").as_deref(), Some("::1"));
    }

    #[test]
    fn bare_host_with_port() {
        assert_eq!(
            derive_sni("manager.example.com:50051").as_deref(),
            Some("manager.example.com"),
        );
    }

    #[test]
    fn localhost_dev_default() {
        assert_eq!(
            derive_sni("https://localhost:50051").as_deref(),
            Some("localhost"),
        );
    }

    #[test]
    fn endpoint_with_trailing_path() {
        assert_eq!(
            derive_sni("https://manager.example.com:50051/grpc").as_deref(),
            Some("manager.example.com"),
        );
    }

    #[test]
    fn empty_returns_none() {
        assert_eq!(derive_sni(""), None);
    }

    #[test]
    fn scheme_only_returns_none() {
        assert_eq!(derive_sni("https://"), None);
    }
}
