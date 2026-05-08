//! Agent identity material: key + CSR generation, on-disk persistence.
//!
//! Agents own a single P-256 keypair. On first run they generate it, post
//! the CSR to the manager, and persist the issued cert + chain.

use anyhow::{anyhow, Context, Result};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// On-disk paths for the agent's identity material.
#[derive(Debug, Clone)]
pub struct IdentityPaths {
    pub host_id: PathBuf,
    pub client_cert: PathBuf,
    pub client_key: PathBuf,
    pub ca_chain: PathBuf,
}

impl IdentityPaths {
    pub fn new(dir: &Path) -> Self {
        Self {
            host_id: dir.join("host_id"),
            client_cert: dir.join("client.crt"),
            client_key: dir.join("client.key"),
            ca_chain: dir.join("ca.pem"),
        }
    }

    pub fn enrolled(&self) -> bool {
        self.host_id.exists()
            && self.client_cert.exists()
            && self.client_key.exists()
            && self.ca_chain.exists()
    }
}

/// In-memory identity loaded from disk after successful enrollment.
#[derive(Debug, Clone)]
pub struct Identity {
    pub host_id: String,
    pub client_cert_pem: Vec<u8>,
    pub client_key_pem: Vec<u8>,
    pub ca_chain_pem: Vec<u8>,
    pub fingerprint_sha256: String,
}

impl Identity {
    pub fn load(paths: &IdentityPaths) -> Result<Self> {
        let host_id = std::fs::read_to_string(&paths.host_id)
            .with_context(|| format!("read {}", paths.host_id.display()))?
            .trim()
            .to_string();
        let cert = std::fs::read(&paths.client_cert)?;
        let key = std::fs::read(&paths.client_key)?;
        let ca = std::fs::read(&paths.ca_chain)?;

        let mut hasher = Sha256::new();
        hasher.update(&cert);
        let fingerprint = hex::encode(hasher.finalize());

        Ok(Self {
            host_id,
            client_cert_pem: cert,
            client_key_pem: key,
            ca_chain_pem: ca,
            fingerprint_sha256: fingerprint,
        })
    }
}

/// Generate a fresh P-256 keypair and a CSR with CN = hostname.
pub struct GeneratedCsr {
    pub keypair: KeyPair,
    pub csr_pem: String,
    pub key_pem: String,
}

pub fn generate_csr(hostname: &str) -> Result<GeneratedCsr> {
    let keypair = KeyPair::generate()?;
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, hostname);
    params
        .distinguished_name
        .push(DnType::OrganizationalUnitName, "agents");
    let csr = params.serialize_request(&keypair)?;
    let key_pem = keypair.serialize_pem();
    Ok(GeneratedCsr {
        keypair,
        csr_pem: csr.pem()?,
        key_pem,
    })
}

/// Persist enrollment artifacts to disk with strict permissions.
pub fn persist_identity(
    paths: &IdentityPaths,
    host_id: &str,
    client_cert_pem: &[u8],
    client_key_pem: &[u8],
    ca_chain_pem: &[u8],
) -> Result<()> {
    let dir = paths
        .host_id
        .parent()
        .ok_or_else(|| anyhow!("identity dir has no parent"))?;
    std::fs::create_dir_all(dir)?;
    std::fs::write(&paths.host_id, host_id.as_bytes())?;
    std::fs::write(&paths.client_cert, client_cert_pem)?;
    std::fs::write(&paths.client_key, client_key_pem)?;
    std::fs::write(&paths.ca_chain, ca_chain_pem)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&paths.client_key, std::fs::Permissions::from_mode(0o600))?;
        std::fs::set_permissions(&paths.host_id, std::fs::Permissions::from_mode(0o644))?;
        std::fs::set_permissions(&paths.client_cert, std::fs::Permissions::from_mode(0o644))?;
        std::fs::set_permissions(&paths.ca_chain, std::fs::Permissions::from_mode(0o644))?;
    }
    Ok(())
}
