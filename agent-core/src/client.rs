//! gRPC HostStream client.
//!
//! Connects to the manager over mTLS, opens a long-lived bidi stream, sends
//! events from a tokio::mpsc channel, and processes server messages
//! (RuleSync, Pong, Command).

use anyhow::{anyhow, Context, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint, Identity as TlsIdentity};

use crate::identity::Identity;
use crate::proto as p;

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
    rules: RuleCache,
}

impl ManagerClient {
    pub fn new(identity: Identity, endpoint: String) -> Self {
        let (send_tx, send_rx) = mpsc::channel(SEND_CHANNEL_CAP);
        Self {
            identity,
            endpoint,
            send_tx,
            send_rx: Some(send_rx),
            rules: RuleCache::default(),
        }
    }

    pub fn rules(&self) -> RuleCache {
        self.rules.clone()
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

        let mut backoff_ms: u64 = 500;
        loop {
            match Self::run_once(&endpoint_url, &identity, &mut send_rx, &rules).await {
                Ok(()) => {
                    tracing::warn!("grpc.stream.closed_clean — reconnecting");
                    backoff_ms = 500;
                }
                Err(err) => {
                    tracing::warn!(error = %err, "grpc.stream.closed_with_error");
                }
            }
            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            backoff_ms = (backoff_ms * 2).min(30_000);
        }
    }

    async fn run_once(
        endpoint: &str,
        identity: &Identity,
        send_rx: &mut mpsc::Receiver<p::ClientMessage>,
        rules: &RuleCache,
    ) -> Result<()> {
        let tls_id = TlsIdentity::from_pem(&identity.client_cert_pem, &identity.client_key_pem);
        let tls = ClientTlsConfig::new()
            .ca_certificate(tonic::transport::Certificate::from_pem(
                &identity.ca_chain_pem,
            ))
            .identity(tls_id)
            // Manager server cert is signed for "localhost" / "edr-manager" in dev.
            .domain_name("localhost");

        let channel: Channel = Endpoint::from_shared(endpoint.to_string())?
            .tls_config(tls)?
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .keep_alive_while_idle(true)
            .http2_keep_alive_interval(Duration::from_secs(30))
            .connect()
            .await
            .with_context(|| format!("dial {}", endpoint))?;

        let mut stub = p::agent_service_client::AgentServiceClient::new(channel);

        // Outbound stream — drains the send_rx into gRPC.
        let (out_tx, out_rx) = mpsc::channel::<p::ClientMessage>(SEND_CHANNEL_CAP);
        let outbound = ReceiverStream::new(out_rx);

        // Forward send_rx to out_tx (so the caller's send_tx outlives the
        // stream and reconnect cycles preserve buffered events).
        let forward = {
            let send_rx = send_rx;
            async move {
                while let Some(msg) = send_rx.recv().await {
                    if out_tx.send(msg).await.is_err() {
                        break;
                    }
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
                        tracing::info!(command_id = %cmd.command_id, "grpc.command.received");
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
        Ok(())
    }
}
