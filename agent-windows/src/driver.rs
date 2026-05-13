//! Kernel driver IPC: open `\\.\Vigil` and drain events via
//! `IOCTL_VIGIL_DRAIN_EVENTS`.
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
//          FILE_ANY_ACCESS=0). Must match `VIGIL_IOCTL_DRAIN_EVENTS` in
// `kernel-windows/vigil.h`.
const IOCTL_VIGIL_DRAIN_EVENTS: u32 = 0x222004;
const IOCTL_VIGIL_KILL_PROCESS: u32 = 0x222008;
const IOCTL_VIGIL_BLOCK_ADD: u32 = 0x22200C;
const IOCTL_VIGIL_BLOCK_REMOVE: u32 = 0x222010;
// Reserved — the driver supports a CLEAR IOCTL (0x222014) but agent-windows
// doesn't currently expose it via a Command kind. Test scripts use it.
// M7.2 self-protection: agent registers its own pid so the driver's
// ObCallbacks know whose handles to filter.
const IOCTL_VIGIL_REGISTER_PROTECTED_PID: u32 = 0x222018;
// Phase 1 #1.3 network isolation. Must match
// `VIGIL_IOCTL_NETWORK_ISOLATE = CTL_CODE(FILE_DEVICE_UNKNOWN=0x22,
// 0x807, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0)` in `kernel-windows/vigil.h`.
const IOCTL_VIGIL_NETWORK_ISOLATE: u32 = 0x22201C;

const BLOCK_KIND_PROCESS: u32 = 1;
const BLOCK_KIND_FILE: u32 = 2;

const DRAIN_BUF_BYTES: usize = 256 * 1024;
const POLL_IDLE_MS: u64 = 100;
const HEADER_BYTES: usize = 24;
const KIND_PROCESS_START: u32 = 1;
const KIND_NETWORK_CONNECT: u32 = 9;

#[derive(Clone)]
pub struct DriverCtx {
    pub host_id: String,
    pub agent_id: String,
    pub agent_version: String,
}

/// Open `\\.\Vigil`, spawn the drain thread, return.
pub fn start(ctx: DriverCtx, tx: mpsc::Sender<p::ClientMessage>) -> Result<()> {
    let mut path: Vec<u16> = "\\\\.\\Vigil".encode_utf16().collect();
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
    .context("CreateFileW \\\\.\\Vigil (driver not loaded?)")?;

    if handle.is_invalid() {
        anyhow::bail!("invalid handle for \\\\.\\Vigil");
    }

    tracing::info!("driver.collector.opened");

    // M7.2: register our pid with the driver so the driver's ObCallback
    // pre-op handlers know whose handles to filter. Best-effort — older
    // drivers without M7.2 will return STATUS_INVALID_DEVICE_REQUEST and
    // that's fine; the agent still runs.
    if let Err(e) = register_protected_pid(handle) {
        tracing::warn!(error = %e, "driver.self_protection.register_failed");
    } else {
        tracing::info!(
            pid = std::process::id(),
            "driver.self_protection.registered"
        );
    }
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
                IOCTL_VIGIL_DRAIN_EVENTS,
                None,
                0,
                Some(buf.as_mut_ptr() as *mut c_void),
                buf.len() as u32,
                Some(&mut bytes_returned),
                None,
            )
        };
        if ok.is_err() {
            anyhow::bail!("DeviceIoControl(IOCTL_VIGIL_DRAIN_EVENTS) failed: {ok:?}");
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
        KIND_NETWORK_CONNECT => build_network_connect(&buf[..size], pid, ctx),
        _ => None,
    };
    Some((size, msg))
}

fn build_process_start(
    buf: &[u8],
    pid: u64,
    ts_nt: u64,
    ctx: &DriverCtx,
) -> Option<p::ClientMessage> {
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

fn build_network_connect(buf: &[u8], pid: u64, ctx: &DriverCtx) -> Option<p::ClientMessage> {
    // Layout (matches kernel-windows/vigil.h VIGIL_EVENT_NETWORK_CONNECT):
    //   header(24) + IpVersion(1) + Protocol(1) + LocalPort(2 BE) +
    //   RemotePort(2 BE) + _Reserved(2) + LocalAddr(16) + RemoteAddr(16)
    if buf.len() < 64 {
        return None;
    }
    let ip_version = buf[24];
    let protocol = buf[25];
    // Ports arrive network-byte-order (big-endian) per the kernel format.
    let local_port = u16::from_be_bytes(buf[26..28].try_into().ok()?);
    let remote_port = u16::from_be_bytes(buf[28..30].try_into().ok()?);
    let local_addr_bytes: [u8; 16] = buf[32..48].try_into().ok()?;
    let remote_addr_bytes: [u8; 16] = buf[48..64].try_into().ok()?;

    let (local_ip, remote_ip) = match ip_version {
        4 => (
            std::net::Ipv4Addr::new(
                local_addr_bytes[0],
                local_addr_bytes[1],
                local_addr_bytes[2],
                local_addr_bytes[3],
            )
            .to_string(),
            std::net::Ipv4Addr::new(
                remote_addr_bytes[0],
                remote_addr_bytes[1],
                remote_addr_bytes[2],
                remote_addr_bytes[3],
            )
            .to_string(),
        ),
        6 => (
            std::net::Ipv6Addr::from(local_addr_bytes).to_string(),
            std::net::Ipv6Addr::from(remote_addr_bytes).to_string(),
        ),
        _ => return None,
    };

    let transport = match protocol {
        6 => "tcp",
        17 => "udp",
        _ => "ip",
    };

    let ev = event::network_connect(
        &ctx.host_id,
        &ctx.agent_id,
        &ctx.agent_version,
        pid as u32,
        transport,
        &local_ip,
        local_port as u32,
        &remote_ip,
        remote_port as u32,
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

// ---- Command dispatch (M5.4) -----------------------------------------------

use windows::Win32::Foundation::GENERIC_WRITE;

/// Open `\\.\Vigil` for IOCTLs that need write access (kill, block, unblock).
/// Returns a usize-wrapped handle so the caller closes it explicitly.
fn open_edr_for_ioctl() -> Result<HANDLE> {
    let mut path: Vec<u16> = "\\\\.\\Vigil".encode_utf16().collect();
    path.push(0);
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            (GENERIC_READ | GENERIC_WRITE).0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    }
    .context("CreateFileW \\\\.\\Vigil")?;
    if handle.is_invalid() {
        anyhow::bail!("invalid handle for \\\\.\\Vigil");
    }
    Ok(handle)
}

fn ioctl(handle: HANDLE, code: u32, in_buf: &[u8]) -> Result<()> {
    let mut bytes_returned: u32 = 0;
    let ok = unsafe {
        DeviceIoControl(
            handle,
            code,
            Some(in_buf.as_ptr() as *const c_void),
            in_buf.len() as u32,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        )
    };
    if ok.is_err() {
        anyhow::bail!("DeviceIoControl(0x{:08x}) failed: {:?}", code, ok);
    }
    Ok(())
}

/// M7.2: tell the driver our pid so it knows whose handles to filter.
///
/// Semantics (M7.2.b first-claim lock):
///   * The driver ignores the buffer's ProcessId for *whose pid to
///     protect* — it always uses the IRP issuer's pid via
///     `PsGetCurrentProcessId()`. Passing our own pid here is a sanity
///     check (the driver rejects mismatches with STATUS_INVALID_PARAMETER
///     so a stale build of either side fails fast).
///   * The slot is first-claim wins. If another process already claimed
///     it, the driver returns STATUS_ACCESS_DENIED. In practice that
///     means an attacker can't redirect ObCallbacks protection to
///     themselves after the agent has registered — which is exactly the
///     bug this lock closes.
///   * The slot auto-clears via the kernel's process-creation
///     notification when the protected pid exits, so a clean agent
///     restart re-claims it without operator action.
///
/// Reuses the already-open drain handle since we don't need write
/// access for this IOCTL.
fn register_protected_pid(handle: HANDLE) -> Result<()> {
    // VIGIL_REGISTER_PID_REQ = UINT64 ProcessId.
    let pid = std::process::id() as u64;
    let buf = pid.to_le_bytes();
    ioctl(handle, IOCTL_VIGIL_REGISTER_PROTECTED_PID, &buf)
}

pub fn dispatch_kill_process(pid: u32) -> Result<()> {
    let handle = open_edr_for_ioctl()?;
    let result = (|| {
        // VIGIL_KILL_PROCESS_REQ = UINT64 ProcessId
        let buf = (pid as u64).to_le_bytes();
        ioctl(handle, IOCTL_VIGIL_KILL_PROCESS, &buf)
    })();
    unsafe {
        let _ = CloseHandle(handle);
    }
    result
}

fn block_request_buffer(kind: u32, pattern: &str) -> Vec<u8> {
    // VIGIL_BLOCK_REQ = UINT32 Kind, UINT32 PatternBytes, then UTF-16 bytes.
    let utf16: Vec<u16> = pattern.encode_utf16().collect();
    let pattern_bytes = utf16.len() * 2;
    let mut buf = Vec::with_capacity(8 + pattern_bytes);
    buf.extend_from_slice(&kind.to_le_bytes());
    buf.extend_from_slice(&(pattern_bytes as u32).to_le_bytes());
    for &c in &utf16 {
        buf.extend_from_slice(&c.to_le_bytes());
    }
    buf
}

pub fn dispatch_block(kind_str: &str, pattern: &str, add: bool) -> Result<()> {
    let kind = match kind_str {
        "process" => BLOCK_KIND_PROCESS,
        "file" => BLOCK_KIND_FILE,
        other => anyhow::bail!("unknown block kind: {other}"),
    };
    if pattern.is_empty() {
        anyhow::bail!("empty pattern");
    }
    let buf = block_request_buffer(kind, pattern);
    let handle = open_edr_for_ioctl()?;
    let code = if add {
        IOCTL_VIGIL_BLOCK_ADD
    } else {
        IOCTL_VIGIL_BLOCK_REMOVE
    };
    let result = ioctl(handle, code, &buf);
    unsafe {
        let _ = CloseHandle(handle);
    }
    result
}

/// Phase 1 #1.3: flip the driver into network-isolated mode.
///
/// While isolated the WFP ALE callouts return `FWP_ACTION_BLOCK` for
/// any outbound TCP/UDP connect whose destination isn't in `ips`.
/// Restore (`isolate=false`) returns the callouts to observation-only
/// behaviour. The driver auto-clears the allowlist on restore so a
/// future isolate starts from a clean slate.
///
/// Buffer construction lives in [`crate::driver_wire`] (non-Windows-gated)
/// so it's testable on Linux CI.
pub fn dispatch_network_isolate(isolate: bool, ips: &[String]) -> Result<()> {
    let buf = crate::driver_wire::network_isolate_request_buffer(isolate, ips);
    let handle = open_edr_for_ioctl()?;
    let result = ioctl(handle, IOCTL_VIGIL_NETWORK_ISOLATE, &buf);
    unsafe {
        let _ = CloseHandle(handle);
    }
    result
}

/// Run the command-dispatch worker. Consumes [`p::Command`] messages from
/// `rx`, executes the corresponding driver IOCTL, and sends a
/// [`p::CommandResult`] back upstream via `send_tx`. Loops until the channel
/// is closed.
pub async fn run_command_worker(
    mut rx: mpsc::Receiver<p::Command>,
    send_tx: mpsc::Sender<p::ClientMessage>,
    job_dispatcher: std::sync::Arc<agent_core::jobs::JobDispatcher>,
    control_channel: agent_core::jobs_runtime::Channel,
) {
    tracing::info!(
        kinds = ?job_dispatcher.supported_kinds(),
        "command_worker.jobs_dispatcher_ready"
    );
    while let Some(cmd) = rx.recv().await {
        let result = dispatch_one(&cmd, &job_dispatcher, &control_channel, &send_tx).await;
        let (success, error) = match &result {
            Ok(()) => (true, String::new()),
            Err(e) => (false, format!("{e:#}")),
        };
        if !success {
            tracing::warn!(command_id = %cmd.command_id, error = %error, "command.failed");
        } else {
            tracing::info!(command_id = %cmd.command_id, "command.succeeded");
        }
        let cr = p::CommandResult {
            command_id: cmd.command_id.clone(),
            success,
            error,
            payload: Vec::new(),
        };
        let msg = p::ClientMessage {
            payload: Some(p::client_message::Payload::CommandResult(cr)),
        };
        let _ = send_tx.send(msg).await;
    }
}

async fn dispatch_one(
    cmd: &p::Command,
    job_dispatcher: &std::sync::Arc<agent_core::jobs::JobDispatcher>,
    control_channel: &agent_core::jobs_runtime::Channel,
    send_tx: &mpsc::Sender<p::ClientMessage>,
) -> Result<()> {
    use p::command::Body;
    let body = cmd
        .body
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("command.body missing"))?;
    match body {
        Body::Kill(k) => {
            let pid = k.target.as_ref().map(|t| t.pid).unwrap_or(0);
            if pid == 0 {
                anyhow::bail!("kill.target.pid must be > 0");
            }
            tokio::task::spawn_blocking(move || dispatch_kill_process(pid))
                .await
                .map_err(|e| anyhow::anyhow!("join: {e}"))??;
        }
        Body::BlockProcess(b) => {
            let pat = b.pattern.clone();
            tokio::task::spawn_blocking(move || dispatch_block("process", &pat, true))
                .await
                .map_err(|e| anyhow::anyhow!("join: {e}"))??;
        }
        Body::BlockFile(b) => {
            let pat = b.pattern.clone();
            tokio::task::spawn_blocking(move || dispatch_block("file", &pat, true))
                .await
                .map_err(|e| anyhow::anyhow!("join: {e}"))??;
        }
        Body::UnblockProcess(b) => {
            let pat = b.pattern.clone();
            tokio::task::spawn_blocking(move || dispatch_block("process", &pat, false))
                .await
                .map_err(|e| anyhow::anyhow!("join: {e}"))??;
        }
        Body::UnblockFile(b) => {
            let pat = b.pattern.clone();
            tokio::task::spawn_blocking(move || dispatch_block("file", &pat, false))
                .await
                .map_err(|e| anyhow::anyhow!("join: {e}"))??;
        }
        Body::Isolate(req) => {
            let isolate = req.isolate;
            let ips = req.allowlist_ips.clone();
            tokio::task::spawn_blocking(move || dispatch_network_isolate(isolate, &ips))
                .await
                .map_err(|e| anyhow::anyhow!("join: {e}"))??;
        }
        Body::ScanFile(_)
        | Body::ScanMemory(_)
        | Body::Update(_)
        | Body::QuarantineFile(_)
        | Body::ReleaseQuarantine(_) => {
            anyhow::bail!("command kind not implemented on Windows yet");
        }
        Body::RunJob(cmd) => {
            if !job_dispatcher.supports(&cmd.job_kind) {
                anyhow::bail!(
                    "run_job: no handler for kind '{}' on windows (run_id={})",
                    cmd.job_kind,
                    cmd.run_id
                );
            }
            let params: serde_json::Value = if cmd.parameters_json.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::from_str(&cmd.parameters_json)
                    .map_err(|e| anyhow::anyhow!("parse parameters_json: {e}"))?
            };
            let ctx = agent_core::jobs_runtime::build_context(
                cmd.run_id.clone(),
                cmd.job_kind.clone(),
                send_tx.clone(),
                control_channel.clone(),
            );
            job_dispatcher.dispatch(ctx, params).await?;
        }
    }
    Ok(())
}

/// NT epoch is 1601-01-01 UTC; Unix epoch is 1970-01-01 UTC. Difference is
/// 11644473600 seconds. NT timestamps are 100ns ticks; convert to ns since
/// Unix epoch.
fn nt_100ns_to_unix_ns(ts_nt: u64) -> u64 {
    const NT_TO_UNIX_SECONDS: u64 = 11_644_473_600;
    let ns_since_nt_epoch = ts_nt.saturating_mul(100);
    ns_since_nt_epoch.saturating_sub(NT_TO_UNIX_SECONDS * 1_000_000_000)
}
