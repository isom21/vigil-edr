//! Agent on-disk configuration (manager URL, cert paths, spool dir).
//! Stub — concrete shape lands in M2 when the agent first runs.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub manager_endpoint: String,
    pub ca_cert_path: PathBuf,
    pub client_cert_path: PathBuf,
    pub client_key_path: PathBuf,
    pub spool_dir: PathBuf,
    pub max_spool_bytes: u64,
}
