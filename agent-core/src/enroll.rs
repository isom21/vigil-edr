//! REST enrollment client.
//!
//! The agent's first contact with the manager: posts a CSR + one-time token
//! to /api/enrollment/enroll, receives a signed client cert + CA chain back.

use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::identity::{generate_csr, persist_identity, GeneratedCsr, Identity, IdentityPaths};

#[derive(Debug, Serialize)]
struct EnrollRequest<'a> {
    enrollment_token: &'a str,
    hostname: &'a str,
    os_family: &'a str,
    os_version: &'a str,
    os_platform: &'a str,
    os_arch: &'a str,
    agent_version: &'a str,
    csr_pem: String,
}

#[derive(Debug, Deserialize)]
struct EnrollResponse {
    host_id: String,
    client_cert_pem: String,
    ca_chain_pem: String,
    cert_not_after: String,
}

pub struct EnrollContext<'a> {
    pub rest_endpoint: &'a str,
    pub enrollment_token: &'a str,
    pub hostname: &'a str,
    pub os_family: &'a str,
    pub os_version: &'a str,
    pub os_platform: &'a str,
    pub os_arch: &'a str,
    pub agent_version: &'a str,
}

pub async fn enroll(ctx: &EnrollContext<'_>, paths: &IdentityPaths) -> Result<Identity> {
    let GeneratedCsr {
        csr_pem, key_pem, ..
    } = generate_csr(ctx.hostname).context("generate CSR")?;

    let body = EnrollRequest {
        enrollment_token: ctx.enrollment_token,
        hostname: ctx.hostname,
        os_family: ctx.os_family,
        os_version: ctx.os_version,
        os_platform: ctx.os_platform,
        os_arch: ctx.os_arch,
        agent_version: ctx.agent_version,
        csr_pem,
    };

    let url = format!("{}/api/enrollment/enroll", ctx.rest_endpoint.trim_end_matches('/'));
    let client = Client::builder()
        .danger_accept_invalid_certs(true) // dev: manager TLS may use a self-signed root
        .build()?;
    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("POST {}", url))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(anyhow!("enrollment failed: {} {}", status, text));
    }

    let er: EnrollResponse = resp.json().await.context("parse enroll response")?;

    persist_identity(
        paths,
        &er.host_id,
        er.client_cert_pem.as_bytes(),
        key_pem.as_bytes(),
        er.ca_chain_pem.as_bytes(),
    )?;

    tracing::info!(
        host_id = %er.host_id,
        cert_not_after = %er.cert_not_after,
        "enrollment.success"
    );

    Identity::load(paths)
}
