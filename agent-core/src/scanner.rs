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

/// Phase 2 #2.1 — platform-agnostic reader for a target process's
/// address space. Concrete implementations (`agent-linux::scanner_memory`,
/// `agent-windows::scanner_memory`) walk OS-specific structures
/// (`/proc/<pid>/maps` + `/proc/<pid>/mem`, `VirtualQueryEx` +
/// `ReadProcessMemory`) and yield readable, non-guard regions one
/// chunk at a time. The cross-platform [`MemoryYaraScanHandler`] in
/// `agent-core::jobs_hunt` drives the iterator and feeds each region
/// to yara-x.
///
/// Implementations MUST skip non-readable / guard / no-access pages
/// (Linux: regions whose perms lack `r`; Windows:
/// `MEM_FREE`/`MEM_RESERVE` and `PAGE_NOACCESS`/`PAGE_GUARD`). They
/// MUST NOT read mapped device memory (Linux: `/dev/...` mapped, file
/// mappings backed by special filesystems); restricting to anonymous
/// + heap + stack regions is the conservative default.
pub trait MemoryRegionReader: Send {
    /// Pull the next readable region, or `None` when the address
    /// space has been fully walked. Returning `Err` halts the scan;
    /// the handler decides whether to surface the partial results.
    fn next_region(&mut self) -> Result<Option<MemoryRegion>>;
}

/// A single readable region carved out of a target process. `addr`
/// is the kernel-reported base; `bytes` is the contents at the time
/// of the read. On Linux `name` is the maps line's pathname column
/// ("[heap]", "[stack]", "/usr/lib/foo.so"); on Windows it's an
/// `Image:<path>` or `Mapped:<size>` synthesised tag, or empty for
/// `MEM_PRIVATE` anonymous regions.
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub addr: u64,
    pub bytes: Vec<u8>,
    pub name: String,
}

/// Construct a platform reader for `pid`. The agent-linux and
/// agent-windows binaries each provide a concrete factory; agent-core
/// uses a function pointer rather than `dyn` trait so the handler
/// can call into the platform layer without taking a transitive
/// dependency on it.
pub type MemoryReaderFactory = fn(pid: u32) -> Result<Box<dyn MemoryRegionReader + Send + 'static>>;
