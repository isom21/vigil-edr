//! On-disk spool for telemetry events when the manager is unreachable.
//!
//! M9.2 deliverable. Replaces the prior "send_rx blocks until manager
//! reconnects" behaviour, which silently dropped events past the
//! in-memory channel capacity. With the spool wired in, events that
//! can't be delivered immediately go to disk; on reconnect the spool
//! drains in order before live events resume.
//!
//! ## Layout
//!
//! ```text
//! {state_dir}/spool/
//!   00000000000000000001.bin   serialized ClientMessage (protobuf)
//!   00000000000000000002.bin
//!   ...
//! ```
//!
//! Each file holds one ClientMessage. The 20-digit decimal seq prefix
//! preserves on-disk ordering (`readdir` + `sort`). The file is created
//! atomically (write to `.tmp` then rename).
//!
//! ## Bounds
//!
//! `SpoolQueue::open_with_max_bytes` caps total disk usage; on overflow,
//! oldest files are removed (drop-oldest is the right policy for
//! streaming telemetry — recent events have higher value than ancient
//! ones, especially after a long disconnect).
//!
//! ## Threading
//!
//! The struct is a thin wrapper over std::fs ops; concurrent push +
//! drain is safe because each operation touches a unique seq file.
//! Counter increments are atomic.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};

/// Default cap: 256 MiB. Enough for ~24h of agent-emitted telemetry on
/// a busy host; configurable in production.
pub const DEFAULT_MAX_BYTES: u64 = 256 * 1024 * 1024;

/// File-backed FIFO queue. Single producer + single consumer is the
/// expected use; multiple producers serialize via the OS file lock-free
/// (each picks its own seq).
pub struct SpoolQueue {
    dir: PathBuf,
    next_seq: AtomicU64,
    max_bytes: u64,
}

impl SpoolQueue {
    /// Open or create a spool at `dir`. Loads the highest existing seq
    /// to continue numbering monotonically.
    pub fn open(dir: &Path) -> Result<Self> {
        Self::open_with_max_bytes(dir, DEFAULT_MAX_BYTES)
    }

    pub fn open_with_max_bytes(dir: &Path, max_bytes: u64) -> Result<Self> {
        fs::create_dir_all(dir).with_context(|| format!("create_dir_all {}", dir.display()))?;
        let mut highest: u64 = 0;
        for entry in fs::read_dir(dir).with_context(|| format!("read_dir {}", dir.display()))? {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            if let Some(seq) = filename_to_seq(&entry.file_name().to_string_lossy()) {
                if seq > highest {
                    highest = seq;
                }
            }
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            next_seq: AtomicU64::new(highest + 1),
            max_bytes,
        })
    }

    /// Append `bytes` as a new spool entry. Returns the seq number used.
    pub fn push(&self, bytes: &[u8]) -> Result<u64> {
        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
        let final_path = self.dir.join(format!("{seq:020}.bin"));
        let tmp_path = self.dir.join(format!("{seq:020}.tmp"));
        fs::write(&tmp_path, bytes).with_context(|| format!("write {}", tmp_path.display()))?;
        fs::rename(&tmp_path, &final_path).with_context(|| {
            format!(
                "rename {} -> {}",
                tmp_path.display(),
                final_path.display()
            )
        })?;
        self.evict_if_over_budget()?;
        Ok(seq)
    }

    /// Drain pending entries in seq order, calling `cb` for each.
    /// `cb` returns whether the entry was successfully sent; `Ok(true)`
    /// removes the file, `Ok(false)` keeps it and stops the drain
    /// (caller went offline again). Errors propagate; the failed entry
    /// stays on disk.
    pub fn drain<F>(&self, mut cb: F) -> Result<usize>
    where
        F: FnMut(&[u8]) -> Result<bool>,
    {
        let mut entries: Vec<(u64, PathBuf)> = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(seq) = filename_to_seq(&name) {
                entries.push((seq, entry.path()));
            }
        }
        entries.sort_by_key(|(s, _)| *s);

        let mut sent = 0usize;
        for (_seq, path) in entries {
            let bytes = match fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "spool.read_failed");
                    continue;
                }
            };
            match cb(&bytes) {
                Ok(true) => {
                    if let Err(e) = fs::remove_file(&path) {
                        tracing::warn!(path = %path.display(), error = %e, "spool.remove_failed");
                    }
                    sent += 1;
                }
                Ok(false) => break,
                Err(e) => {
                    tracing::warn!(error = %e, "spool.send_failed");
                    return Err(e);
                }
            }
        }
        Ok(sent)
    }

    /// Number of entries currently spooled.
    pub fn len(&self) -> usize {
        match fs::read_dir(&self.dir) {
            Ok(rd) => rd
                .flatten()
                .filter(|e| filename_to_seq(&e.file_name().to_string_lossy()).is_some())
                .count(),
            Err(_) => 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Sum of bytes across all .bin files.
    pub fn bytes_used(&self) -> u64 {
        let Ok(rd) = fs::read_dir(&self.dir) else {
            return 0;
        };
        rd.flatten()
            .filter(|e| filename_to_seq(&e.file_name().to_string_lossy()).is_some())
            .filter_map(|e| e.metadata().ok().map(|m| m.len()))
            .sum()
    }

    fn evict_if_over_budget(&self) -> io::Result<()> {
        let mut total = self.bytes_used();
        if total <= self.max_bytes {
            return Ok(());
        }
        let mut entries: Vec<(u64, PathBuf, u64)> = Vec::new();
        for entry in fs::read_dir(&self.dir)?.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(seq) = filename_to_seq(&name) {
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                entries.push((seq, entry.path(), size));
            }
        }
        entries.sort_by_key(|(s, _, _)| *s);
        for (_seq, path, size) in entries {
            if total <= self.max_bytes {
                break;
            }
            if fs::remove_file(&path).is_ok() {
                total = total.saturating_sub(size);
            }
        }
        Ok(())
    }
}

fn filename_to_seq(name: &str) -> Option<u64> {
    name.strip_suffix(".bin").and_then(|s| s.parse().ok())
}

// Backwards-compatible alias for the M0 stub.
pub use SpoolQueue as EventSpool;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn push_and_drain_preserves_order() {
        let dir = tempdir().unwrap();
        let q = SpoolQueue::open(dir.path()).unwrap();
        for i in 0..5 {
            q.push(format!("msg-{i}").as_bytes()).unwrap();
        }
        assert_eq!(q.len(), 5);

        let mut received: Vec<String> = Vec::new();
        let n = q
            .drain(|bytes| {
                received.push(String::from_utf8_lossy(bytes).into_owned());
                Ok(true)
            })
            .unwrap();
        assert_eq!(n, 5);
        assert_eq!(received, vec!["msg-0", "msg-1", "msg-2", "msg-3", "msg-4"]);
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn drain_callback_returning_false_stops_and_keeps_remainder() {
        let dir = tempdir().unwrap();
        let q = SpoolQueue::open(dir.path()).unwrap();
        for i in 0..5 {
            q.push(format!("msg-{i}").as_bytes()).unwrap();
        }
        let mut count = 0;
        q.drain(|_| {
            count += 1;
            Ok(count <= 2)
        })
        .unwrap();
        assert_eq!(q.len(), 3, "remaining 3 entries kept");
    }

    #[test]
    fn budget_evicts_oldest_first() {
        let dir = tempdir().unwrap();
        let q = SpoolQueue::open_with_max_bytes(dir.path(), 200).unwrap();
        for i in 0..10u8 {
            q.push(&[i; 30]).unwrap();
        }
        let used = q.bytes_used();
        assert!(used <= 200, "used {used} should be <= 200");
        let mut seen: Vec<u8> = Vec::new();
        q.drain(|bytes| {
            seen.push(bytes[0]);
            Ok(true)
        })
        .unwrap();
        assert!(*seen.first().unwrap() > 0, "oldest entries were evicted");
    }

    #[test]
    fn reopen_resumes_seq_numbering() {
        let dir = tempdir().unwrap();
        {
            let q = SpoolQueue::open(dir.path()).unwrap();
            q.push(b"first").unwrap();
            q.push(b"second").unwrap();
        }
        let q = SpoolQueue::open(dir.path()).unwrap();
        let seq = q.push(b"third").unwrap();
        assert_eq!(seq, 3);
    }
}
