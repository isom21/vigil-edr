//! Stream-backed implementations of [`JobReporter`] and
//! [`ArtifactUploader`].
//!
//! Bridges the abstract traits in [`crate::jobs`] to the concrete
//! agent runtime — sending `ClientMessage::JobProgress` /
//! `ClientMessage::JobArtifact` on the bidi stream, calling
//! `RequestArtifactUpload` for presigned URLs, and PUTting blobs to
//! MinIO via reqwest.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
pub use tonic::transport::Channel;

use crate::jobs::{ArtifactSpec, ArtifactUploader, JobContext, JobReporter, UploadedArtifact};
use crate::proto as p;

/// JobReporter that writes JobProgress envelopes onto the existing
/// agent send channel. Cloneable: handlers can hand it off to spawned
/// subtasks.
#[derive(Clone)]
pub struct StreamJobReporter {
    run_id: String,
    send_tx: mpsc::Sender<p::ClientMessage>,
}

impl StreamJobReporter {
    pub fn new(run_id: String, send_tx: mpsc::Sender<p::ClientMessage>) -> Self {
        Self { run_id, send_tx }
    }

    async fn emit(
        &self,
        status: p::JobRunStatus,
        pct: u32,
        message: Option<String>,
        error: Option<String>,
    ) {
        let msg = p::ClientMessage {
            payload: Some(p::client_message::Payload::JobProgress(p::JobProgress {
                run_id: self.run_id.clone(),
                status: status as i32,
                progress_pct: pct,
                progress_message: message.unwrap_or_default(),
                error: error.unwrap_or_default(),
            })),
        };
        if let Err(e) = self.send_tx.send(msg).await {
            tracing::warn!(error = %e, run_id = %self.run_id, "job_reporter.send_failed");
        }
    }
}

#[async_trait]
impl JobReporter for StreamJobReporter {
    async fn started(&self) {
        self.emit(p::JobRunStatus::Running, 0, None, None).await;
    }
    async fn progress(&self, pct: u32, message: Option<String>) {
        self.emit(p::JobRunStatus::Running, pct, message, None)
            .await;
    }
    async fn failed(&self, error: String) {
        self.emit(p::JobRunStatus::Failed, 100, None, Some(error))
            .await;
    }
}

/// ArtifactUploader that does the full Request → PUT → Report cycle:
///   1. unary `RequestArtifactUpload` to get a presigned PUT URL.
///   2. HTTPS PUT the bytes to MinIO.
///   3. Emit `JobArtifactReport` on the bidi stream so the manager
///      writes a JobArtifact row.
pub struct GrpcArtifactUploader {
    run_id: String,
    grpc: tokio::sync::Mutex<p::agent_service_client::AgentServiceClient<Channel>>,
    http: reqwest::Client,
    send_tx: mpsc::Sender<p::ClientMessage>,
}

impl GrpcArtifactUploader {
    pub fn new(
        run_id: String,
        grpc_channel: Channel,
        send_tx: mpsc::Sender<p::ClientMessage>,
    ) -> Self {
        Self {
            run_id,
            grpc: tokio::sync::Mutex::new(p::agent_service_client::AgentServiceClient::new(
                grpc_channel,
            )),
            http: reqwest::Client::builder()
                .danger_accept_invalid_certs(false)
                .build()
                .expect("reqwest client"),
            send_tx,
        }
    }
}

#[async_trait]
impl ArtifactUploader for GrpcArtifactUploader {
    async fn upload(&self, spec: ArtifactSpec, body: Vec<u8>) -> Result<UploadedArtifact> {
        // Step 1: ask the manager for a presigned PUT URL.
        let req = p::ArtifactUploadRequest {
            run_id: self.run_id.clone(),
            original_filename: spec.original_filename.clone(),
            artifact_kind: spec.kind.as_str().to_string(),
            expected_size_bytes: body.len() as u64,
        };
        let grant = {
            let mut client = self.grpc.lock().await;
            client
                .request_artifact_upload(req)
                .await
                .context("request_artifact_upload rpc")?
                .into_inner()
        };

        // Step 2: PUT to MinIO. SHA-256 the bytes for the manager-side
        // metadata record.
        let mut hasher = Sha256::new();
        hasher.update(&body);
        let sha256 = hex::encode(hasher.finalize());
        let size_bytes = body.len() as u64;

        let mut put = self.http.put(&grant.url).body(body);
        for (k, v) in grant.required_headers.iter() {
            put = put.header(k, v);
        }
        let resp = put.send().await.context("PUT to MinIO")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("MinIO PUT failed: {status} {text}"));
        }

        // Step 3: tell the manager what we just uploaded.
        let metadata_json = serde_json::to_string(&spec.metadata).unwrap_or_else(|_| "{}".into());
        let report = p::JobArtifactReport {
            run_id: self.run_id.clone(),
            bucket: grant.bucket.clone(),
            object_key: grant.object_key.clone(),
            artifact_kind: spec.kind.as_str().to_string(),
            size_bytes,
            sha256: sha256.clone(),
            metadata_json,
        };
        let msg = p::ClientMessage {
            payload: Some(p::client_message::Payload::JobArtifact(report)),
        };
        if let Err(e) = self.send_tx.send(msg).await {
            tracing::warn!(error = %e, run_id = %self.run_id, "artifact.report_send_failed");
        }

        Ok(UploadedArtifact {
            bucket: grant.bucket,
            object_key: grant.object_key,
            size_bytes,
            sha256,
        })
    }
}

/// Build a [`JobContext`] for a single run. The platform agent (linux
/// or windows command worker) calls this on each Body::RunJob and
/// hands the context to `dispatcher.dispatch()`.
pub fn build_context(
    run_id: String,
    job_kind: String,
    send_tx: mpsc::Sender<p::ClientMessage>,
    grpc_channel: Channel,
) -> JobContext {
    let reporter: Arc<dyn JobReporter> =
        Arc::new(StreamJobReporter::new(run_id.clone(), send_tx.clone()));
    let uploader: Arc<dyn ArtifactUploader> = Arc::new(GrpcArtifactUploader::new(
        run_id.clone(),
        grpc_channel,
        send_tx,
    ));
    JobContext {
        run_id,
        job_kind,
        reporter,
        uploader,
    }
}
