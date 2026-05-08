//! Scanner trait abstractions. Concrete implementations live per-OS.

use crate::Result;
use async_trait::async_trait;

#[async_trait]
pub trait FileScanner: Send + Sync {
    async fn scan_path(&self, path: &std::path::Path) -> Result<Vec<ScanHit>>;
}

#[async_trait]
pub trait MemoryScanner: Send + Sync {
    async fn scan_pid(&self, pid: u32) -> Result<Vec<ScanHit>>;
}

#[derive(Debug, Clone)]
pub struct ScanHit {
    pub rule_id: String,
    pub rule_name: String,
    pub detail: String,
}
