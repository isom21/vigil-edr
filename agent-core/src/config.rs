//! Agent on-disk configuration.
//!
//! The agent stores its configuration plus enrollment artifacts in a single
//! directory:
//!
//!   <state_dir>/
//!     agent.toml            (this struct)
//!     identity/
//!       host_id             (UUID assigned by manager on enrollment)
//!       client.crt          (PEM)
//!       client.key          (PEM, mode 0600)
//!       ca.pem              (PEM, manager CA chain)
//!     spool/                (sled DB, M3+)

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// gRPC endpoint of the manager, e.g. "https://localhost:50051".
    pub manager_endpoint: String,

    /// Optional: REST endpoint used for enrollment ("http://localhost:8000").
    /// Falls back to manager_endpoint with the gRPC port stripped.
    pub manager_rest_endpoint: Option<String>,

    /// One-time enrollment token (string starting with "enr_"). Required on
    /// first run only; cleared after successful enrollment.
    pub enrollment_token: Option<String>,

    /// Where the agent stores identity + spool. Defaults to platform-specific
    /// locations if unset.
    #[serde(default)]
    pub state_dir: Option<PathBuf>,

    /// Logical hostname to register as (defaults to system hostname).
    #[serde(default)]
    pub hostname_override: Option<String>,
}

impl AgentConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read config {}", path.display()))?;
        let cfg: Self = toml_lite::from_str(&raw)?;
        Ok(cfg)
    }

    /// Compute the effective state directory.
    pub fn resolved_state_dir(&self) -> PathBuf {
        if let Some(p) = &self.state_dir {
            return p.clone();
        }
        if cfg!(windows) {
            PathBuf::from(
                std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string()),
            )
            .join("EDR")
        } else {
            PathBuf::from("/var/lib/edr")
        }
    }

    pub fn identity_dir(&self) -> PathBuf {
        self.resolved_state_dir().join("identity")
    }

    pub fn spool_dir(&self) -> PathBuf {
        self.resolved_state_dir().join("spool")
    }

    /// Default REST endpoint inferred from the gRPC endpoint when not set.
    pub fn rest_endpoint(&self) -> String {
        if let Some(r) = &self.manager_rest_endpoint {
            return r.clone();
        }
        // "https://host:50051" -> "http://host:8000"
        let url = self.manager_endpoint.replace(":50051", ":8000");
        url.replace("https://", "http://")
    }
}

// Tiny TOML reader to keep deps minimal — the config file we accept is a
// strict subset (KEY = "VALUE" lines, no nesting).
mod toml_lite {
    use anyhow::{anyhow, Result};

    pub fn from_str<T: serde::de::DeserializeOwned>(s: &str) -> Result<T> {
        let mut map = serde_json::Map::new();
        for (idx, raw) in s.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let (k, v) = line
                .split_once('=')
                .ok_or_else(|| anyhow!("config:{}: missing '=': {}", idx + 1, raw))?;
            let key = k.trim().to_string();
            let value = v.trim();
            let json_value: serde_json::Value =
                if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
                    serde_json::Value::String(value[1..value.len() - 1].to_string())
                } else if let Ok(b) = value.parse::<bool>() {
                    serde_json::Value::Bool(b)
                } else if let Ok(n) = value.parse::<i64>() {
                    serde_json::Value::from(n)
                } else {
                    return Err(anyhow!("config:{}: unsupported value: {}", idx + 1, raw));
                };
            map.insert(key, json_value);
        }
        Ok(T::deserialize(serde_json::Value::Object(map))?)
    }
}
