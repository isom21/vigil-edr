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
use aya::programs::TracePoint;
use aya::Ebpf;
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
    /// Load the bundled object and attach the M6.2 programs:
    /// - `tracepoint/sched/sched_process_exec` — process exec
    /// - `tracepoint/sched/sched_process_exit` — process exit
    ///
    /// LSM-attached blocking variants land in M6.6 (the kernel exposes
    /// `lsm/bprm_check_security` for that).
    pub fn load_and_attach() -> Result<Self> {
        let mut ebpf = Ebpf::load(EBPF_OBJECT).context("aya::Ebpf::load(edr.bpf.o)")?;

        for (name, category, event) in [
            ("handle_sched_exec", "sched", "sched_process_exec"),
            ("handle_sched_exit", "sched", "sched_process_exit"),
        ] {
            let prog: &mut TracePoint = ebpf
                .program_mut(name)
                .ok_or_else(|| anyhow!("program {name} missing"))?
                .try_into()?;
            prog.load().with_context(|| format!("load {name}"))?;
            prog.attach(category, event)
                .with_context(|| format!("attach {category}/{event}"))?;
        }

        tracing::info!("ebpf.loaded programs=sched_process_exec,sched_process_exit");
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
    let async_fd = AsyncFd::new(RingFd(ring.as_raw_fd()))
        .context("AsyncFd::new(RingBuf)")?;

    loop {
        // Drain everything currently available.
        while let Some(item) = ring.next() {
            handle_event(&item, &ctx, &send_tx).await;
        }
        // Wait for the kernel to wake us up when more is ready.
        let mut guard = async_fd.readable().await?;
        guard.clear_ready();
    }
}

struct RingFd(std::os::fd::RawFd);
impl AsRawFd for RingFd {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.0
    }
}

async fn handle_event(buf: &[u8], ctx: &LoaderCtx, send_tx: &mpsc::Sender<p::ClientMessage>) {
    if buf.len() < 32 {
        return;
    }
    let _size = u32::from_ne_bytes(buf[0..4].try_into().unwrap_or_default()) as usize;
    let kind = u32::from_ne_bytes(buf[4..8].try_into().unwrap_or_default());
    let timestamp_ns = u64::from_ne_bytes(buf[8..16].try_into().unwrap_or_default());
    let pid = u32::from_ne_bytes(buf[16..20].try_into().unwrap_or_default());
    let ppid = u32::from_ne_bytes(buf[20..24].try_into().unwrap_or_default());
    let _uid = u32::from_ne_bytes(buf[24..28].try_into().unwrap_or_default());
    let _gid = u32::from_ne_bytes(buf[28..32].try_into().unwrap_or_default());

    match kind {
        EDR_EVENT_KIND_PROCESS_START => {
            // header(32) + comm[16] + path_len(4) + path[384]
            if buf.len() < 32 + COMM_LEN + 4 {
                return;
            }
            let comm = read_cstr(&buf[32..32 + COMM_LEN]);
            let path_len = u32::from_ne_bytes(
                buf[32 + COMM_LEN..32 + COMM_LEN + 4].try_into().unwrap_or_default(),
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
            let ev = event::process_started(
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
            );
            let batch = p::EventBatch {
                events: vec![ev],
                batch_id: ulid::Ulid::new().to_string(),
                first_seq: 0,
                last_seq: 0,
            };
            let msg = p::ClientMessage {
                payload: Some(p::client_message::Payload::Events(batch)),
            };
            let _ = send_tx.try_send(msg);
        }
        EDR_EVENT_KIND_PROCESS_EXIT => {
            // M6.2: process exit is counted in eBPF stats but not forwarded
            // upstream — we mirror the Windows agent which only ships
            // process_start. M6.x can add an exit event if Sigma rules
            // start needing it.
        }
        _ => {}
    }
}

fn read_cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}
