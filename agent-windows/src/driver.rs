//! Kernel driver IPC: open `\\.\edr` and drain events via
//! `IOCTL_EDR_DRAIN_EVENTS`.
//!
//! Replaces the ferrisetw-based ETW collection from M2.3c with the kernel
//! driver's event ring (M4.5). The driver must be installed and started
//! (see `kernel-windows/install.ps1`); if the device can't be opened,
//! [`start`] returns an error and `main.rs` falls back to ETW.

#![cfg(windows)]

use agent_core::event;
use agent_core::proto as p;
use anyhow::{Context, Result};
use std::ffi::c_void;
use std::time::Duration;
use tokio::sync::mpsc;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;

// CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, function=0x801, METHOD_BUFFERED=0,
//          FILE_ANY_ACCESS=0). Must match `EDR_IOCTL_DRAIN_EVENTS` in
// `kernel-windows/edr.h`.
const IOCTL_EDR_DRAIN_EVENTS: u32 = 0x222004;

const DRAIN_BUF_BYTES: usize = 256 * 1024;
const POLL_IDLE_MS: u64 = 100;
const HEADER_BYTES: usize = 24;
const KIND_PROCESS_START: u32 = 1;

#[derive(Clone)]
pub struct DriverCtx {
    pub host_id: String,
    pub agent_id: String,
    pub agent_version: String,
}

/// Open `\\.\edr`, spawn the drain thread, return.
pub fn start(ctx: DriverCtx, tx: mpsc::Sender<p::ClientMessage>) -> Result<()> {
    let mut path: Vec<u16> = "\\\\.\\edr".encode_utf16().collect();
    path.push(0);

    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    }
    .context("CreateFileW \\\\.\\edr (driver not loaded?)")?;

    if handle.is_invalid() {
        anyhow::bail!("invalid handle for \\\\.\\edr");
    }

    tracing::info!("driver.collector.opened");
    // HANDLE wraps *mut c_void which isn't Send. Windows HANDLE values are
    // safe to use across threads — pass via usize (Send) and reconstruct
    // on the worker.
    let handle_usize = handle.0 as usize;
    std::thread::spawn(move || {
        let handle = HANDLE(handle_usize as *mut c_void);
        if let Err(e) = drain_loop(handle, ctx, tx) {
            tracing::error!(error = %e, "driver.drain_loop_failed");
        }
        unsafe {
            let _ = CloseHandle(handle);
        }
    });
    Ok(())
}

fn drain_loop(handle: HANDLE, ctx: DriverCtx, tx: mpsc::Sender<p::ClientMessage>) -> Result<()> {
    let mut buf = vec![0u8; DRAIN_BUF_BYTES];

    loop {
        let mut bytes_returned: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_EDR_DRAIN_EVENTS,
                None,
                0,
                Some(buf.as_mut_ptr() as *mut c_void),
                buf.len() as u32,
                Some(&mut bytes_returned),
                None,
            )
        };
        if ok.is_err() {
            anyhow::bail!("DeviceIoControl(IOCTL_EDR_DRAIN_EVENTS) failed: {ok:?}");
        }

        let n = bytes_returned as usize;
        if n == 0 {
            std::thread::sleep(Duration::from_millis(POLL_IDLE_MS));
            continue;
        }

        let mut off = 0;
        while off < n {
            match parse_event(&buf[off..n], &ctx) {
                Some((size, Some(msg))) => {
                    let _ = tx.try_send(msg);
                    off += size;
                }
                Some((size, None)) => {
                    off += size;
                }
                None => {
                    tracing::warn!(offset = off, len = n, "driver.parse_truncated");
                    break;
                }
            }
        }
    }
}

/// Parse one event. Returns `(bytes_consumed, optional ClientMessage)`.
/// `(n, None)` means we walked past an event we don't currently translate
/// (e.g. file events; M4.6 only translates process_start). `None` means
/// truncated/corrupt — caller should skip the rest of the batch.
fn parse_event(buf: &[u8], ctx: &DriverCtx) -> Option<(usize, Option<p::ClientMessage>)> {
    if buf.len() < HEADER_BYTES {
        return None;
    }
    let size = u32::from_le_bytes(buf[0..4].try_into().ok()?) as usize;
    let kind = u32::from_le_bytes(buf[4..8].try_into().ok()?);
    let timestamp_ns_nt = u64::from_le_bytes(buf[8..16].try_into().ok()?);
    let pid = u64::from_le_bytes(buf[16..24].try_into().ok()?);

    if size < HEADER_BYTES || size > buf.len() {
        return None;
    }

    let msg = match kind {
        KIND_PROCESS_START => build_process_start(&buf[..size], pid, timestamp_ns_nt, ctx),
        _ => None,
    };
    Some((size, msg))
}

fn build_process_start(buf: &[u8], pid: u64, ts_nt: u64, ctx: &DriverCtx) -> Option<p::ClientMessage> {
    if buf.len() < HEADER_BYTES + 8 + 2 + 2 {
        return None;
    }
    let parent_pid = u64::from_le_bytes(buf[24..32].try_into().ok()?);
    let image_len = u16::from_le_bytes(buf[32..34].try_into().ok()?) as usize;
    let cmd_len = u16::from_le_bytes(buf[34..36].try_into().ok()?) as usize;

    let strings_start = 36;
    if strings_start + image_len + cmd_len > buf.len() {
        return None;
    }

    let image = utf16_to_string(&buf[strings_start..strings_start + image_len]);
    let cmd = utf16_to_string(&buf[strings_start + image_len..strings_start + image_len + cmd_len]);

    let basename = std::path::Path::new(&image)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(&image)
        .to_string();

    let ev = event::process_started(
        &ctx.host_id,
        &ctx.agent_id,
        &ctx.agent_version,
        pid as u32,
        nt_100ns_to_unix_ns(ts_nt),
        parent_pid as u32,
        0,
        &image,
        &basename,
        &cmd,
        "",
    );

    let batch = p::EventBatch {
        events: vec![ev],
        batch_id: ulid::Ulid::new().to_string(),
        first_seq: 0,
        last_seq: 0,
    };
    Some(p::ClientMessage {
        payload: Some(p::client_message::Payload::Events(batch)),
    })
}

fn utf16_to_string(bytes: &[u8]) -> String {
    let mut chars: Vec<u16> = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks_exact(2) {
        chars.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    String::from_utf16_lossy(&chars)
}

/// NT epoch is 1601-01-01 UTC; Unix epoch is 1970-01-01 UTC. Difference is
/// 11644473600 seconds. NT timestamps are 100ns ticks; convert to ns since
/// Unix epoch.
fn nt_100ns_to_unix_ns(ts_nt: u64) -> u64 {
    const NT_TO_UNIX_SECONDS: u64 = 11_644_473_600;
    let ns_since_nt_epoch = ts_nt.saturating_mul(100);
    ns_since_nt_epoch.saturating_sub(NT_TO_UNIX_SECONDS * 1_000_000_000)
}
