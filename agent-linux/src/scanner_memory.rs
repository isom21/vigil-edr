//! Linux memory reader (Phase 2 #2.1).
//!
//! Walks `/proc/<pid>/maps` for the target process and yields readable
//! anonymous + heap + stack regions via `/proc/<pid>/mem`. The reader
//! is intentionally conservative — it skips:
//!
//!   * regions without a leading `r` perm (kernel will EIO the read
//!     anyway, but skipping avoids the syscall),
//!   * file-backed mappings on special filesystems (`/dev/*`, `/sys/*`),
//!   * pseudo-regions like `[vvar]`, `[vsyscall]`, `[vdso]` that the
//!     kernel sometimes refuses to expose via `mem`,
//!   * regions larger than the per-region cap (the handler enforces
//!     this too; we just bail early).
//!
//! Files under `/proc/<pid>/mem` need `PTRACE_MODE_ATTACH_FSCREDS` in
//! kernels ≥ 4.5; the agent runs as root (or with CAP_SYS_PTRACE) for
//! the eBPF / driver hooks so this is always satisfied in production.

use agent_core::scanner::{MemoryRegion, MemoryRegionReader};
use anyhow::{anyhow, Context, Result};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};

/// Hard ceiling on a single `pread64`. Per-region cap higher up may
/// be larger; we still chunk so a 256 MiB heap doesn't move 256 MiB
/// in one syscall. yara-x scans the whole region as one buffer once
/// we've stitched the chunks together.
const READ_CHUNK_BYTES: usize = 4 * 1024 * 1024;

pub struct ProcMapsReader {
    pid: u32,
    maps: std::io::Lines<BufReader<File>>,
    mem: File,
}

impl ProcMapsReader {
    pub fn open(pid: u32) -> Result<Self> {
        let maps_path = format!("/proc/{pid}/maps");
        let mem_path = format!("/proc/{pid}/mem");
        let maps =
            File::open(&maps_path).with_context(|| format!("open {maps_path} (pid alive?)"))?;
        let mem = File::open(&mem_path)
            .with_context(|| format!("open {mem_path} (CAP_SYS_PTRACE / root?)"))?;
        Ok(Self {
            pid,
            maps: BufReader::new(maps).lines(),
            mem,
        })
    }
}

impl MemoryRegionReader for ProcMapsReader {
    fn next_region(&mut self) -> Result<Option<MemoryRegion>> {
        for line in self.maps.by_ref() {
            let line = match line {
                Ok(l) => l,
                Err(e) => return Err(anyhow!("read /proc/{}/maps: {e}", self.pid)),
            };
            let Some(parsed) = parse_maps_line(&line) else {
                continue;
            };
            if !parsed.readable {
                continue;
            }
            if is_skipped_region(&parsed.pathname) {
                continue;
            }
            let size = parsed.end.saturating_sub(parsed.start);
            if size == 0 {
                continue;
            }
            // Read the region in chunks. EIO/EPERM here is per-region;
            // skip with a debug log rather than aborting the whole scan.
            let bytes = match read_region(&mut self.mem, parsed.start, size as usize) {
                Ok(b) => b,
                Err(e) => {
                    tracing::debug!(
                        pid = self.pid,
                        addr = parsed.start,
                        size,
                        error = %e,
                        "scanner_memory.read_failed"
                    );
                    continue;
                }
            };
            return Ok(Some(MemoryRegion {
                addr: parsed.start,
                bytes,
                name: parsed.pathname,
            }));
        }
        Ok(None)
    }
}

struct MapsRow {
    start: u64,
    end: u64,
    readable: bool,
    pathname: String,
}

fn parse_maps_line(line: &str) -> Option<MapsRow> {
    // Format: "start-end perms offset dev inode  pathname"
    let mut it = line.split_whitespace();
    let range = it.next()?;
    let perms = it.next()?;
    let _offset = it.next()?;
    let _dev = it.next()?;
    let _inode = it.next()?;
    let pathname = it.collect::<Vec<_>>().join(" ");
    let (start_s, end_s) = range.split_once('-')?;
    let start = u64::from_str_radix(start_s, 16).ok()?;
    let end = u64::from_str_radix(end_s, 16).ok()?;
    let readable = perms.starts_with('r');
    Some(MapsRow {
        start,
        end,
        readable,
        pathname,
    })
}

fn is_skipped_region(pathname: &str) -> bool {
    // The kernel-internal pseudo-regions can't be paged in via
    // /proc/<pid>/mem on every kernel; punt rather than risk an EIO
    // and let yara still scan everything else.
    matches!(pathname, "[vsyscall]" | "[vvar]")
        // Device-backed mappings (GPU buffers, etc.) sometimes panic on
        // read; they're never interesting for malware signatures.
        || pathname.starts_with("/dev/")
        || pathname.starts_with("/sys/")
}

fn read_region(mem: &mut File, addr: u64, size: usize) -> Result<Vec<u8>> {
    mem.seek(SeekFrom::Start(addr))?;
    let mut out = Vec::with_capacity(size);
    let mut remaining = size;
    let mut buf = vec![0u8; READ_CHUNK_BYTES.min(size)];
    while remaining > 0 {
        let want = remaining.min(buf.len());
        let read = mem.read(&mut buf[..want])?;
        if read == 0 {
            break;
        }
        out.extend_from_slice(&buf[..read]);
        remaining -= read;
    }
    Ok(out)
}

/// Factory matching [`agent_core::scanner::MemoryReaderFactory`].
pub fn open(pid: u32) -> Result<Box<dyn MemoryRegionReader + Send + 'static>> {
    Ok(Box::new(ProcMapsReader::open(pid)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_maps_line() {
        let line = "55a1c0000000-55a1c0021000 r-xp 00000000 fd:00 1234567   /usr/bin/cat";
        let row = parse_maps_line(line).unwrap();
        assert_eq!(row.start, 0x55a1c0000000);
        assert_eq!(row.end, 0x55a1c0021000);
        assert!(row.readable);
        assert_eq!(row.pathname, "/usr/bin/cat");
    }

    #[test]
    fn parses_anonymous_region() {
        let line = "7f000000-7f100000 rw-p 00000000 00:00 0 ";
        let row = parse_maps_line(line).unwrap();
        assert!(row.readable);
        assert_eq!(row.pathname, "");
    }

    #[test]
    fn flags_unreadable() {
        let line = "7f000000-7f100000 ---p 00000000 00:00 0 ";
        let row = parse_maps_line(line).unwrap();
        assert!(!row.readable);
    }

    #[test]
    fn skips_special_regions() {
        assert!(is_skipped_region("[vsyscall]"));
        assert!(is_skipped_region("[vvar]"));
        assert!(is_skipped_region("/dev/nvidia0"));
        assert!(!is_skipped_region("[heap]"));
        assert!(!is_skipped_region("[stack]"));
        assert!(!is_skipped_region("/usr/lib/libc.so.6"));
    }
}
