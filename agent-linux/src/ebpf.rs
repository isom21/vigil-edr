//! eBPF loader (M6).
//!
//! Loads the kernel-side programs from `agent-linux/ebpf/edr.bpf.o`,
//! attaches them, drains the shared ring buffer, and translates events
//! into protobuf [`p::ClientMessage`]s that flow into the existing gRPC
//! send channel.
//!
//! Falls back gracefully when CAP_BPF / kernel features are missing —
//! `main.rs` runs the legacy /proc poller when [`Loader::load_and_attach`]
//! errors out.
#![cfg(target_os = "linux")]

use agent_core::event;
use agent_core::proto as p;
use anyhow::{anyhow, Context, Result};
use aya::maps::{Array, MapData, RingBuf};
use aya::programs::{Lsm, TracePoint};
use aya::{Btf, Ebpf};
use std::os::fd::AsRawFd;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

// `include_bytes!` returns a `&'static [u8; N]` aligned to 1, but aya's
// ELF parser needs 8-byte alignment. We wrap the bytes in an 8-byte-aligned
// struct to force the right alignment without an allocation.
#[repr(C, align(8))]
struct AlignedObject<const N: usize>([u8; N]);
static EBPF_OBJECT_ALIGNED: &AlignedObject<{ include_bytes!("../ebpf/edr.bpf.o").len() }> =
    &AlignedObject(*include_bytes!("../ebpf/edr.bpf.o"));
const EBPF_OBJECT: &[u8] = &EBPF_OBJECT_ALIGNED.0;

const EDR_EVENT_KIND_PROCESS_START: u32 = 1;
const EDR_EVENT_KIND_PROCESS_EXIT: u32 = 2;
const EDR_EVENT_KIND_FILE_OPEN: u32 = 3;
const EDR_EVENT_KIND_NETWORK_CONNECT: u32 = 4;
const EDR_EVENT_KIND_MODULE_LOAD: u32 = 5;

const COMM_LEN: usize = 16;
const PATH_MAX: usize = 384;

/// Stat indices — must match `enum edr_stat` in `ebpf/edr.bpf.c`.
#[repr(u32)]
#[derive(Copy, Clone, Debug)]
pub enum Stat {
    ProcessExec = 0,
    ProcessExit = 1,
    FileOpen = 2,
    NetworkConnect = 3,
    ModuleLoad = 4,
    ProcessBlockHits = 5,
    FileBlockHits = 6,
    NetworkBlockHits = 7,
    KillRequests = 8,
    EventsDropped = 9,
}
const STAT_COUNT: usize = 10;

#[derive(Clone)]
pub struct LoaderCtx {
    pub host_id: String,
    pub agent_id: String,
    pub agent_version: String,
}

/// Owns the loaded eBPF object. Drop unloads everything attached.
pub struct Loader {
    ebpf: Ebpf,
}

impl Loader {
    /// Load the bundled object and attach the M6.x programs:
    /// - `tracepoint/sched/sched_process_exec` — process exec (M6.2)
    /// - `tracepoint/sched/sched_process_exit` — process exit (M6.2)
    /// - `lsm/file_open` — file open (M6.3) — only if BPF-LSM is enabled
    ///
    /// LSM hooks fail to load on kernels without `bpf` listed in
    /// `/sys/kernel/security/lsm`. We log + skip in that case so the
    /// rest of the pipeline still works.
    pub fn load_and_attach() -> Result<Self> {
        let mut ebpf = Ebpf::load(EBPF_OBJECT).context("aya::Ebpf::load(edr.bpf.o)")?;

        for (name, category, event) in [
            ("handle_sched_exec", "sched", "sched_process_exec"),
            ("handle_sched_exit", "sched", "sched_process_exit"),
            ("handle_module_load", "module", "module_load"),
        ] {
            let prog: &mut TracePoint = ebpf
                .program_mut(name)
                .ok_or_else(|| anyhow!("program {name} missing"))?
                .try_into()?;
            prog.load().with_context(|| format!("load {name}"))?;
            prog.attach(category, event)
                .with_context(|| format!("attach {category}/{event}"))?;
        }

        let mut attached =
            String::from("sched_process_exec,sched_process_exit,module_load");
        match attach_lsm(&mut ebpf, "handle_file_open", "file_open") {
            Ok(()) => attached.push_str(",lsm:file_open"),
            Err(e) => tracing::warn!(error = %e, "ebpf.lsm_file_open.skipped"),
        }
        match attach_lsm(&mut ebpf, "handle_socket_connect", "socket_connect") {
            Ok(()) => attached.push_str(",lsm:socket_connect"),
            Err(e) => tracing::warn!(error = %e, "ebpf.lsm_socket_connect.skipped"),
        }

        tracing::info!(programs = %attached, "ebpf.loaded");
        Ok(Self { ebpf })
    }

    /// Take ownership of the ring-buffer map and spawn an async drainer
    /// that translates events to protobuf and pushes them onto `send_tx`.
    pub fn spawn_drainer(&mut self, ctx: LoaderCtx, send_tx: mpsc::Sender<p::ClientMessage>) -> Result<()> {
        let map = self
            .ebpf
            .take_map("events")
            .ok_or_else(|| anyhow!("events ring map missing"))?;
        let ring = RingBuf::try_from(map)?;

        tokio::spawn(async move {
            if let Err(e) = drain_loop(ring, ctx, send_tx).await {
                tracing::error!(error = %e, "ebpf.drain_loop_failed");
            }
        });
        Ok(())
    }

    /// Read all stat counters into an array. Indices match [`Stat`].
    pub fn read_stats(&mut self) -> Result<[u64; STAT_COUNT]> {
        let map = self
            .ebpf
            .map_mut("stats")
            .ok_or_else(|| anyhow!("stats map missing"))?;
        let array: Array<&mut MapData, u64> = Array::try_from(map)?;
        let mut out = [0u64; STAT_COUNT];
        for i in 0..STAT_COUNT as u32 {
            out[i as usize] = array.get(&i, 0).unwrap_or(0);
        }
        Ok(out)
    }
}

/// LSM programs need a kernel BTF reference at load time and a separate
/// `attach()` call (no category/event tuple like tracepoints).
/// `prog_name` is the C function name (the SEC label is e.g. "lsm/file_open");
/// `hook_name` is the kernel hook (e.g. "file_open").
fn attach_lsm(ebpf: &mut Ebpf, prog_name: &str, hook_name: &str) -> Result<()> {
    let btf = Btf::from_sys_fs().context("Btf::from_sys_fs")?;
    let prog: &mut Lsm = ebpf
        .program_mut(prog_name)
        .ok_or_else(|| anyhow!("{prog_name} program missing"))?
        .try_into()?;
    prog.load(hook_name, &btf)
        .with_context(|| format!("load lsm/{hook_name}"))?;
    prog.attach()
        .with_context(|| format!("attach lsm/{hook_name}"))?;
    Ok(())
}

/// Best-effort one-line summary of all stat counters.
pub fn format_stats(stats: &[u64; STAT_COUNT]) -> String {
    format!(
        "exec={} exit={} file_open={} net_connect={} module_load={} \
         block_hits=p:{}/f:{}/n:{} kill_requests={} events_dropped={}",
        stats[Stat::ProcessExec as usize],
        stats[Stat::ProcessExit as usize],
        stats[Stat::FileOpen as usize],
        stats[Stat::NetworkConnect as usize],
        stats[Stat::ModuleLoad as usize],
        stats[Stat::ProcessBlockHits as usize],
        stats[Stat::FileBlockHits as usize],
        stats[Stat::NetworkBlockHits as usize],
        stats[Stat::KillRequests as usize],
        stats[Stat::EventsDropped as usize],
    )
}

async fn drain_loop(
    mut ring: RingBuf<MapData>,
    ctx: LoaderCtx,
    send_tx: mpsc::Sender<p::ClientMessage>,
) -> Result<()> {
    // RingBuf is edge-triggered via epoll; AsyncFd lets tokio await on it.
    // We follow aya's documented loop shape: wait, drain, clear_ready.
    let async_fd = AsyncFd::new(RingFd(ring.as_raw_fd()))
        .context("AsyncFd::new(RingBuf)")?;

    // Cap per-batch so a single ClientMessage stays under typical gRPC
    // limits (4 MiB default). 256 events × ~600 bytes each ≈ 150 KiB.
    const MAX_BATCH: usize = 256;

    loop {
        let mut guard = async_fd.readable().await?;
        let mut batch: Vec<p::EndpointEvent> = Vec::new();
        while let Some(item) = ring.next() {
            if let Some(ev) = parse_event(&item, &ctx) {
                batch.push(ev);
                if batch.len() >= MAX_BATCH {
                    flush_batch(&send_tx, &mut batch).await;
                }
            }
        }
        if !batch.is_empty() {
            flush_batch(&send_tx, &mut batch).await;
        }
        guard.clear_ready();
    }
}

async fn flush_batch(send_tx: &mpsc::Sender<p::ClientMessage>, batch: &mut Vec<p::EndpointEvent>) {
    if batch.is_empty() {
        return;
    }
    let events = std::mem::take(batch);
    let msg = p::ClientMessage {
        payload: Some(p::client_message::Payload::Events(p::EventBatch {
            events,
            batch_id: ulid::Ulid::new().to_string(),
            first_seq: 0,
            last_seq: 0,
        })),
    };
    // Use blocking send so the drainer back-pressures into the ring
    // buffer (which has its own drop counter) rather than silently
    // dropping at the channel.
    let _ = send_tx.send(msg).await;
}

struct RingFd(std::os::fd::RawFd);
impl AsRawFd for RingFd {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.0
    }
}

fn parse_event(buf: &[u8], ctx: &LoaderCtx) -> Option<p::EndpointEvent> {
    if buf.len() < 32 {
        return None;
    }
    let kind = u32::from_ne_bytes(buf[4..8].try_into().ok()?);
    let timestamp_ns = u64::from_ne_bytes(buf[8..16].try_into().ok()?);
    let pid = u32::from_ne_bytes(buf[16..20].try_into().ok()?);
    let ppid = u32::from_ne_bytes(buf[20..24].try_into().ok()?);

    match kind {
        EDR_EVENT_KIND_PROCESS_START => {
            // header(32) + comm[16] + path_len(4) + path[384]
            if buf.len() < 32 + COMM_LEN + 4 {
                return None;
            }
            let comm = read_cstr(&buf[32..32 + COMM_LEN]);
            let path_len = u32::from_ne_bytes(
                buf[32 + COMM_LEN..32 + COMM_LEN + 4].try_into().ok()?,
            ) as usize;
            let path_start = 32 + COMM_LEN + 4;
            let path = if path_len > 0 && path_start + path_len <= buf.len() && path_len <= PATH_MAX {
                String::from_utf8_lossy(&buf[path_start..path_start + path_len])
                    .trim_end_matches('\0')
                    .to_string()
            } else {
                String::new()
            };
            let basename = std::path::Path::new(&path)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(&comm)
                .to_string();
            Some(event::process_started(
                &ctx.host_id,
                &ctx.agent_id,
                &ctx.agent_version,
                pid,
                timestamp_ns,
                ppid,
                0,
                if path.is_empty() { &comm } else { &path },
                &basename,
                "",
                "",
            ))
        }
        EDR_EVENT_KIND_PROCESS_EXIT => {
            // M6.2: process exit is counted in eBPF stats but not forwarded
            // upstream — we mirror the Windows agent which only ships
            // process_start. M6.x can add an exit event if Sigma rules
            // start needing it.
            None
        }
        EDR_EVENT_KIND_MODULE_LOAD => {
            // header(32) + comm[16] + name_len(4) + name[64]
            const HDR: usize = 32;
            const NAME_MAX: usize = 64;
            if buf.len() < HDR + COMM_LEN + 4 {
                return None;
            }
            let _comm = read_cstr(&buf[HDR..HDR + COMM_LEN]);
            let name_len = u32::from_ne_bytes(
                buf[HDR + COMM_LEN..HDR + COMM_LEN + 4].try_into().ok()?,
            ) as usize;
            let name_start = HDR + COMM_LEN + 4;
            if name_len == 0 || name_len > NAME_MAX || name_start + name_len > buf.len() {
                return None;
            }
            let name = String::from_utf8_lossy(&buf[name_start..name_start + name_len])
                .trim_end_matches('\0')
                .to_string();
            let _ = (ppid, timestamp_ns);
            Some(event::kernel_module_loaded(
                &ctx.host_id,
                &ctx.agent_id,
                &ctx.agent_version,
                pid,
                &name,
            ))
        }
        EDR_EVENT_KIND_NETWORK_CONNECT => {
            // header(32) + comm[16] + family(1) + protocol(1) + src_port(2) +
            // dst_port(2) + _pad(2) + src_addr[16] + dst_addr[16]
            const HDR: usize = 32;
            const REQ: usize = HDR + COMM_LEN + 1 + 1 + 2 + 2 + 2 + 16 + 16;
            if buf.len() < REQ {
                return None;
            }
            let mut o = HDR;
            let _comm = read_cstr(&buf[o..o + COMM_LEN]);
            o += COMM_LEN;
            let family = buf[o];
            o += 1;
            let protocol = buf[o];
            o += 1;
            let src_port = u16::from_ne_bytes(buf[o..o + 2].try_into().ok()?);
            o += 2;
            let dst_port = u16::from_ne_bytes(buf[o..o + 2].try_into().ok()?);
            o += 2 + 2; // skip _pad
            let src_addr = &buf[o..o + 16];
            o += 16;
            let dst_addr = &buf[o..o + 16];
            const AF_INET: u8 = 2;
            const AF_INET6: u8 = 10;
            let (src_str, dst_str) = if family == AF_INET {
                let s = std::net::Ipv4Addr::new(src_addr[0], src_addr[1], src_addr[2], src_addr[3]);
                let d = std::net::Ipv4Addr::new(dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
                (s.to_string(), d.to_string())
            } else if family == AF_INET6 {
                let mut s = [0u8; 16];
                s.copy_from_slice(src_addr);
                let mut d = [0u8; 16];
                d.copy_from_slice(dst_addr);
                (
                    std::net::Ipv6Addr::from(s).to_string(),
                    std::net::Ipv6Addr::from(d).to_string(),
                )
            } else {
                return None;
            };
            let transport = match protocol {
                6 => "tcp",
                17 => "udp",
                1 => "icmp",
                _ => "other",
            };
            let _ = ppid;
            let _ = timestamp_ns;
            Some(event::network_connect(
                &ctx.host_id,
                &ctx.agent_id,
                &ctx.agent_version,
                pid,
                transport,
                &src_str,
                src_port as u32,
                &dst_str,
                dst_port as u32,
            ))
        }
        EDR_EVENT_KIND_FILE_OPEN => {
            // header(32) + comm[16] + open_flags(4) + path_len(4) + path[384]
            const HDR: usize = 32;
            if buf.len() < HDR + COMM_LEN + 8 {
                return None;
            }
            let comm = read_cstr(&buf[HDR..HDR + COMM_LEN]);
            let open_flags = u32::from_ne_bytes(
                buf[HDR + COMM_LEN..HDR + COMM_LEN + 4].try_into().ok()?,
            );
            let path_len = u32::from_ne_bytes(
                buf[HDR + COMM_LEN + 4..HDR + COMM_LEN + 8].try_into().ok()?,
            ) as usize;
            let path_start = HDR + COMM_LEN + 8;
            let path = if path_len > 0 && path_start + path_len <= buf.len() && path_len <= PATH_MAX {
                String::from_utf8_lossy(&buf[path_start..path_start + path_len])
                    .trim_end_matches('\0')
                    .to_string()
            } else {
                return None;
            };
            if path.is_empty() {
                return None;
            }
            let basename = std::path::Path::new(&path)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(&comm)
                .to_string();
            const O_WRONLY: u32 = 0o0000001;
            const O_RDWR: u32 = 0o0000002;
            const O_CREAT: u32 = 0o0000100;
            const O_TRUNC: u32 = 0o0001000;
            let acc = open_flags & 0o3;
            let action = if open_flags & O_CREAT != 0 {
                p::FileAction::Create
            } else if acc == O_WRONLY || acc == O_RDWR || open_flags & O_TRUNC != 0 {
                p::FileAction::Write
            } else {
                p::FileAction::Open
            };
            Some(event::file_opened(
                &ctx.host_id,
                &ctx.agent_id,
                &ctx.agent_version,
                pid,
                &path,
                &basename,
                action,
            ))
        }
        _ => None,
    }
}

fn read_cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}
