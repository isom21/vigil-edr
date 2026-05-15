//! eBPF loader (M6).
//!
//! Loads the kernel-side programs from `agent-linux/ebpf/vigil.bpf.o`,
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
use aya::maps::{Array, HashMap as AyaHashMap, MapData, PerCpuArray, PerCpuValues, RingBuf};
use aya::programs::{Lsm, TracePoint};
use aya::{Btf, Ebpf};
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

// `include_bytes!` returns a `&'static [u8; N]` aligned to 1, but aya's
// ELF parser needs 8-byte alignment. We wrap the bytes in an 8-byte-aligned
// struct to force the right alignment without an allocation.
#[repr(C, align(8))]
struct AlignedObject<const N: usize>([u8; N]);
static EBPF_OBJECT_ALIGNED: &AlignedObject<{ include_bytes!("../ebpf/vigil.bpf.o").len() }> =
    &AlignedObject(*include_bytes!("../ebpf/vigil.bpf.o"));
const EBPF_OBJECT: &[u8] = &EBPF_OBJECT_ALIGNED.0;

const VIGIL_EVENT_KIND_PROCESS_START: u32 = 1;
const VIGIL_EVENT_KIND_PROCESS_EXIT: u32 = 2;
const VIGIL_EVENT_KIND_FILE_OPEN: u32 = 3;
const VIGIL_EVENT_KIND_NETWORK_CONNECT: u32 = 4;
const VIGIL_EVENT_KIND_MODULE_LOAD: u32 = 5;

const COMM_LEN: usize = 16;
const PATH_MAX: usize = 384;

/// Stat indices — must match `enum vigil_stat` in `ebpf/vigil.bpf.c`.
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
    SelfKillBlocked = 10,
    SelfPtraceBlocked = 11,
    SelfBpfBlocked = 12,
    SelfUnlinkBlocked = 13,
    LongPathBlockLookup = 14,
    LongPathTrulyTooLong = 15,
    NetworkIsolationHits = 16,
    NetworkIsolationDrops = 17,
}
const STAT_COUNT: usize = 18;

/// Default location for pinned BPF objects. The agent owns this directory;
/// installer must mount bpffs at `/sys/fs/bpf` (default on systemd) and
/// give the parent dir to root.
pub const DEFAULT_PIN_DIR: &str = "/sys/fs/bpf/vigil";

/// M7.1 self-protection LSM hooks — attached + pinned by
/// [`Loader::enable_self_protection`]. Pinning prevents an attacker
/// with momentary CAP_BPF from detaching the hooks during the window
/// between an agent crash and its restart.
pub const SELF_PROTECT_LSM_HOOKS: [(&str, &str); 6] = [
    ("handle_task_kill", "task_kill"),
    ("handle_ptrace_access_check", "ptrace_access_check"),
    ("handle_bpf_lsm", "bpf"),
    ("handle_inode_unlink", "inode_unlink"),
    ("handle_inode_rmdir", "inode_rmdir"),
    ("handle_inode_rename", "inode_rename"),
];

/// CODE-216 detection-side LSM hooks — attached by
/// [`Loader::load_and_attach`] and pinned there too when self-
/// protection is on. Pre-PR these were attached but unpinned, which
/// left them detachable via `bpftool prog detach` even though
/// `handle_bpf_lsm` blocks the syscall — an attacker who *also*
/// briefly disables BPF-LSM (or who lands code execution as PID 1)
/// could still race the detach. Pinning closes the race.
pub const DETECT_LSM_HOOKS: [(&str, &str); 3] = [
    ("handle_file_open", "file_open"),
    ("handle_socket_connect", "socket_connect"),
    ("handle_bprm_check", "bprm_check_security"),
];

/// All LSM hooks the watchdog should observe in bpffs. The first
/// element is the C function name in `ebpf/vigil.bpf.c` (and the
/// bpffs filename); the second is the kernel hook name passed to
/// `prog.load(hook, &btf)`.
///
/// Exposed publicly so the M12.b watchdog can verify that all
/// expected pin files still exist on every check. Adding a new LSM
/// hook means: (a) attach it in either [`SELF_PROTECT_LSM_HOOKS`] or
/// [`DETECT_LSM_HOOKS`], (b) re-export it from this constant,
/// (c) the watchdog picks it up automatically.
pub const EXPECTED_LSM_HOOKS: [(&str, &str); 9] = [
    SELF_PROTECT_LSM_HOOKS[0],
    SELF_PROTECT_LSM_HOOKS[1],
    SELF_PROTECT_LSM_HOOKS[2],
    SELF_PROTECT_LSM_HOOKS[3],
    SELF_PROTECT_LSM_HOOKS[4],
    SELF_PROTECT_LSM_HOOKS[5],
    DETECT_LSM_HOOKS[0],
    DETECT_LSM_HOOKS[1],
    DETECT_LSM_HOOKS[2],
];

/// Maps pinned under `<pin_dir>/maps/<name>` after
/// [`Loader::enable_self_protection`] succeeds. Exposed for the same
/// reason as [`EXPECTED_LSM_HOOKS`].
///
/// `isolation_state` and `manager_ip_allowlist` are pinned so an
/// IsolateHostCmd outlives an agent restart — the operator should not
/// have to re-issue isolation just because the agent crashed.
pub const EXPECTED_PINNED_MAPS: [&str; 4] = [
    "agent_self",
    "protected_inodes",
    "isolation_state",
    "manager_ip_allowlist",
];

#[derive(Clone)]
pub struct LoaderCtx {
    pub host_id: String,
    pub agent_id: String,
    pub agent_version: String,
}

/// Block-list keys are zero-padded 256-byte paths; matches `struct
/// vigil_block_key` in `vigil.bpf.c`.
pub const BLOCK_KEY_LEN: usize = 256;

/// Pad/truncate a path to a [`BLOCK_KEY_LEN`]-byte key.
///
/// The kernel side (Top-20 #5 fix) reads the resolved path via
/// `bpf_probe_read_kernel_str(key, 256, scratch)`, which copies up to
/// 255 chars and writes a NUL terminator at byte [255]. For the kernel
/// and userspace keys to compare equal under long paths, userspace
/// must also produce a `[max-255-chars][NUL][zeros]` shape — not a
/// raw 256-byte truncation. So we explicitly reserve byte [255] as
/// the NUL terminator and only copy up to 255 source bytes.
///
/// For paths of 255 chars or fewer this is a no-op vs the pre-fix
/// behaviour: the natural NUL plus the zero-init padding produces the
/// same bytes either way. The change matters only for paths exactly
/// 256 chars or longer, which previously bypassed the kernel hook
/// entirely (it bailed out at -ENAMETOOLONG) and so were never
/// effective block rules; the fix lets the operator block them.
pub fn block_key(path: &str) -> [u8; BLOCK_KEY_LEN] {
    let mut k = [0u8; BLOCK_KEY_LEN];
    let bytes = path.as_bytes();
    let n = bytes.len().min(BLOCK_KEY_LEN - 1);
    k[..n].copy_from_slice(&bytes[..n]);
    // k[n] is already 0 from the zero-init; serves as the NUL terminator
    // that bpf_probe_read_kernel_str writes on the kernel side.
    k
}

/// Lightweight handle the command worker uses to manipulate the kernel
/// block-list maps from a separate task without holding the full
/// [`Loader`].
#[derive(Clone)]
pub struct BlockListHandle {
    inner: Arc<Mutex<BlockListInner>>,
}

struct BlockListInner {
    process: AyaHashMap<MapData, [u8; BLOCK_KEY_LEN], u8>,
    file: AyaHashMap<MapData, [u8; BLOCK_KEY_LEN], u8>,
    isolation_state: PerCpuArray<MapData, u8>,
    allowlist: AyaHashMap<MapData, [u8; 16], u8>,
}

/// Normalise an [`IpAddr`] into the 16-byte IPv4-mapped-IPv6 form used
/// as the key in `manager_ip_allowlist`. IPv4 `a.b.c.d` becomes
/// `::ffff:a.b.c.d`; IPv6 addresses are stored as-is.
///
/// Done in userspace so we can share one key shape with the kernel hook
/// (see `handle_socket_connect` in `vigil.bpf.c`) and avoid duplicating
/// the v4-mapping logic on the BPF side.
pub fn ip_allowlist_key(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

impl BlockListHandle {
    pub fn block_process(&self, path: &str) -> Result<()> {
        let key = block_key(path);
        self.inner
            .lock()
            .unwrap()
            .process
            .insert(key, 1u8, 0)
            .with_context(|| format!("process_block insert {path}"))
    }

    pub fn unblock_process(&self, path: &str) -> Result<()> {
        let key = block_key(path);
        self.inner
            .lock()
            .unwrap()
            .process
            .remove(&key)
            .with_context(|| format!("process_block remove {path}"))
    }

    pub fn block_file(&self, path: &str) -> Result<()> {
        let key = block_key(path);
        self.inner
            .lock()
            .unwrap()
            .file
            .insert(key, 1u8, 0)
            .with_context(|| format!("file_block insert {path}"))
    }

    pub fn unblock_file(&self, path: &str) -> Result<()> {
        let key = block_key(path);
        self.inner
            .lock()
            .unwrap()
            .file
            .remove(&key)
            .with_context(|| format!("file_block remove {path}"))
    }

    /// Flip the kernel-side isolation flag. `on=true` makes every
    /// subsequent outbound TCP/UDP connect that doesn't match the
    /// allowlist return -EPERM.
    ///
    /// Per-CPU array: same value written to every CPU slot so the BPF
    /// hook reads a consistent state regardless of which CPU runs the
    /// classifier.
    pub fn set_isolation(&self, on: bool) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        let cpus =
            aya::util::nr_cpus().map_err(|(label, err)| anyhow!("nr_cpus ({label}): {err}"))?;
        let v: u8 = if on { 1 } else { 0 };
        let values = PerCpuValues::try_from(vec![v; cpus])
            .context("PerCpuValues::try_from(isolation_state)")?;
        inner
            .isolation_state
            .set(0, values, 0)
            .context("isolation_state.set(0)")
    }

    /// Insert `ip` into the manager allowlist. Subsequent connects to
    /// `ip` while isolated pass through. Idempotent — re-inserting an
    /// existing entry is a no-op at the map level.
    pub fn allow_ip(&self, ip: IpAddr) -> Result<()> {
        let key = ip_allowlist_key(ip);
        self.inner
            .lock()
            .unwrap()
            .allowlist
            .insert(key, 1u8, 0)
            .with_context(|| format!("manager_ip_allowlist insert {ip}"))
    }

    /// Remove `ip` from the allowlist. The kernel returns ENOENT for
    /// missing keys; we swallow all remove errors and let the caller
    /// re-issue if they need stronger guarantees (the command worker's
    /// `clear_allowlist` collects keys-then-removes, which can't miss).
    ///
    /// Not currently called by the command worker — it uses
    /// `clear_allowlist` + per-ip `allow_ip` to re-apply on every
    /// IsolateHostCmd. Kept here so an out-of-tree consumer (e.g. a
    /// hot-patch tool that wants to surgically pull a single IP) has a
    /// supported entry point.
    #[allow(dead_code)]
    pub fn disallow_ip(&self, ip: IpAddr) -> Result<()> {
        let key = ip_allowlist_key(ip);
        let _ = self.inner.lock().unwrap().allowlist.remove(&key);
        Ok(())
    }

    /// Drop every entry from the allowlist. Used at restore time so a
    /// fresh isolation event starts from a clean slate.
    pub fn clear_allowlist(&self) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        let keys: Vec<[u8; 16]> = inner
            .allowlist
            .keys()
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("manager_ip_allowlist keys")?;
        for k in keys {
            let _ = inner.allowlist.remove(&k);
        }
        Ok(())
    }
}

/// Phase 2 #2.12: handle on the kernel-side DNS block / sinkhole map.
///
/// Mirrors [`BlockListHandle`]'s ownership model — taken from the
/// [`Loader`] once, then shared (cheap [`Arc`]/[`Mutex`]) with the
/// DNS resync handler that lives in `dns_block.rs`. Operations are
/// whole-list replacements (resync semantics) rather than per-entry
/// add/remove; that matches the manager's wire-side contract and
/// makes correctness obvious (after [`DnsBlockHandle::replace_all`],
/// the kernel matches the supplied set).
#[derive(Clone)]
pub struct DnsBlockHandle {
    inner: Arc<Mutex<DnsBlockInner>>,
}

struct DnsBlockInner {
    map: AyaHashMap<MapData, [u8; BLOCK_KEY_LEN], u8>,
}

/// Action tag for entries in [`DnsBlockHandle`]. Wire values match
/// `VIGIL_DNS_ACTION_*` (1 = block, 2 = sinkhole) so userspace and
/// BPF agree on the encoding without a runtime translation layer.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DnsBlockAction {
    Block = 1,
    Sinkhole = 2,
}

impl DnsBlockHandle {
    /// Replace the kernel-side map with the supplied entries. Domain
    /// keys are normalised via [`crate::dns_block::normalise_dns_key`]
    /// before insert.
    ///
    /// "Remove every existing key not in the new set, then upsert
    /// every new key." An interim window where the map holds a mix of
    /// old + new is possible; we tolerate it because the alternative
    /// — taking the map atomically out of the eBPF object — would
    /// tear down every in-flight lookup, which is worse.
    pub fn replace_all(
        &self,
        entries: impl IntoIterator<Item = (String, DnsBlockAction)>,
    ) -> Result<()> {
        let new: std::collections::HashMap<[u8; BLOCK_KEY_LEN], u8> = entries
            .into_iter()
            .map(|(d, a)| (crate::dns_block::normalise_dns_key(&d), a as u8))
            .collect();
        let mut inner = self.inner.lock().unwrap();
        let existing: Vec<[u8; BLOCK_KEY_LEN]> = inner
            .map
            .keys()
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("dns_block_domains keys")?;
        for k in existing {
            if !new.contains_key(&k) {
                let _ = inner.map.remove(&k);
            }
        }
        for (k, v) in new {
            inner
                .map
                .insert(k, v, 0)
                .context("dns_block_domains insert")?;
        }
        Ok(())
    }

    /// Count of entries currently in the kernel map.
    pub fn len(&self) -> Result<usize> {
        let inner = self.inner.lock().unwrap();
        let keys: Vec<[u8; BLOCK_KEY_LEN]> = inner
            .map
            .keys()
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("dns_block_domains keys")?;
        Ok(keys.len())
    }
}

/// Owns the loaded eBPF object. Drop unloads everything attached
/// **except** programs and links that have been pinned to bpffs via
/// [`Loader::enable_self_protection`].
pub struct Loader {
    ebpf: Ebpf,
}

impl Loader {
    /// Best-effort takeover of stale pins from a previous (crashed) agent.
    ///
    /// If `pin_dir/maps/agent_self` exists, read it and decide whether
    /// the previous agent's slot is claimable. Three states:
    ///
    /// * `agent_self[0] == 0`: previous agent exited; its
    ///   `sched_process_exit` tracepoint cleared the slot. We're free
    ///   to claim it once the new programs are attached (our
    ///   `load_and_attach` path writes our tgid into the freshly-loaded
    ///   `agent_self` map; the old pinned map gets unlinked below).
    /// * `agent_self[0]` points to a live process: another vigil-agent
    ///   instance is running. Abort — running two of us is undefined.
    /// * `agent_self[0]` points to a dead tgid (kernel quirk where the
    ///   tracepoint didn't fire): we log loudly and continue. The old
    ///   pinned map will be unlinked below; the LSM hooks tied to it
    ///   stop applying because their map references go through the new
    ///   pinned object after attach.
    ///
    /// We deliberately do NOT update the old map to our tgid here.
    /// Under M7.1.b's `lsm/bpf` hardening, that UPDATE_ELEM would be
    /// blocked from any non-self caller — exactly the bypass attack
    /// we're closing.
    ///
    /// Called from `main.rs` *before* `load_and_attach()`. On any
    /// error (no old pins, kernel disallows, etc.) this is a no-op —
    /// a fresh load+attach will add new entries to the LSM stack.
    pub fn cleanup_or_takeover(pin_dir: &Path) -> Result<()> {
        if !pin_dir.exists() {
            return Ok(());
        }
        let self_pin = pin_dir.join("maps/agent_self");
        if self_pin.exists() {
            match MapData::from_pin(&self_pin) {
                Ok(map_data) => {
                    let map = aya::maps::Map::Array(map_data);
                    let arr: Array<MapData, u32> =
                        Array::try_from(map).context("Array::try_from(old agent_self)")?;
                    let old_tgid = arr.get(&0u32, 0).unwrap_or(0);
                    if old_tgid == 0 {
                        tracing::info!("self_protection.takeover.previous_slot_clear");
                    } else if Path::new(&format!("/proc/{old_tgid}/status")).exists() {
                        anyhow::bail!(
                            "agent_self[0]={old_tgid} points at a live process; \
                             another vigil-agent appears to be running. Refusing \
                             to start. Use `--unpin` to forcibly clean up if you \
                             are certain no agent is running."
                        );
                    } else {
                        tracing::warn!(
                            stale_tgid = old_tgid,
                            "self_protection.takeover.stale_self_observed; \
                             sched_process_exit auto-clear did not fire. The old \
                             pinned map will be unlinked below."
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "self_protection.takeover.open_self_failed");
                }
            }
        }
        for sub in ["links", "progs", "maps"] {
            let dir = pin_dir.join(sub);
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if let Err(e) = std::fs::remove_file(&p) {
                        tracing::warn!(path = %p.display(), error = %e, "self_protection.takeover.unpin_failed");
                    }
                }
            }
        }
        tracing::info!(pin_dir = %pin_dir.display(), "self_protection.takeover.complete");
        Ok(())
    }

    /// Load the bundled object and attach the M6.x programs:
    /// - `tracepoint/sched/sched_process_exec` — process exec (M6.2)
    /// - `tracepoint/sched/sched_process_exit` — process exit (M6.2)
    /// - `lsm/file_open` — file open (M6.3) — only if BPF-LSM is enabled
    /// - `lsm/socket_connect` — outbound connect (M6.4)
    /// - `lsm/bprm_check_security` — exec deny (M6.6)
    ///
    /// LSM hooks fail to load on kernels without `bpf` listed in
    /// `/sys/kernel/security/lsm`. We log + skip in that case so the
    /// rest of the pipeline still works.
    ///
    /// `detect_pin_dir` (CODE-216) is the bpffs links directory under
    /// which the detection LSMs (`file_open`, `socket_connect`,
    /// `bprm_check_security`) are pinned. Pinning closes the
    /// detach-via-CAP_BPF race that the kernel-side `handle_bpf_lsm`
    /// cannot cover on its own. `None` means "don't pin" — that path
    /// stays for [`VIGIL_DISABLE_SELF_PROTECTION`] and the unit-test
    /// loader, where the LSMs still attach but the kernel will release
    /// them on agent exit.
    pub fn load_and_attach(detect_pin_dir: Option<&Path>) -> Result<Self> {
        let mut ebpf = Ebpf::load(EBPF_OBJECT).context("aya::Ebpf::load(vigil.bpf.o)")?;

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

        if let Some(dir) = detect_pin_dir {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("create_dir_all {}", dir.display()))?;
        }

        let mut attached = String::from("sched_process_exec,sched_process_exit,module_load");
        for (prog_name, hook) in [
            ("handle_file_open", "file_open"),
            ("handle_socket_connect", "socket_connect"),
            ("handle_bprm_check", "bprm_check_security"),
        ] {
            match attach_lsm(&mut ebpf, prog_name, hook, detect_pin_dir) {
                Ok(_pin_path) => {
                    attached.push_str(",lsm:");
                    attached.push_str(hook);
                }
                Err(e) => tracing::warn!(error = %e, hook = %hook, "ebpf.lsm_attach.skipped"),
            }
        }

        tracing::info!(programs = %attached, "ebpf.loaded");
        Ok(Self { ebpf })
    }

    /// Take ownership of the block-list and isolation maps and wrap
    /// them in a thread-safe handle the command worker can use.
    ///
    /// If `pin_dir` is supplied, the isolation maps (`isolation_state`
    /// and `manager_ip_allowlist`) are pinned under `<pin_dir>/maps/`
    /// before take so an IsolateHostCmd survives an agent restart. The
    /// block-list maps are NOT pinned — they have their own JSON-on-disk
    /// persistence path (see `command_worker::restore`).
    ///
    /// Pinning happens here (not in `enable_self_protection`) because
    /// the maps live inside the handle after this returns and the
    /// loader can no longer reach them by name.
    pub fn take_block_lists(&mut self, pin_dir: Option<&Path>) -> Result<BlockListHandle> {
        if let Some(pdir) = pin_dir {
            let maps_dir = pdir.join("maps");
            std::fs::create_dir_all(&maps_dir)
                .with_context(|| format!("create_dir_all {}", maps_dir.display()))?;
            for name in ["isolation_state", "manager_ip_allowlist"] {
                let pin_path = maps_dir.join(name);
                if pin_path.exists() {
                    tracing::debug!(
                        path = %pin_path.display(),
                        "isolation.map_pin.path_exists_skipping"
                    );
                    continue;
                }
                if let Some(map) = self.ebpf.map_mut(name) {
                    if let Err(e) = map.pin(&pin_path) {
                        tracing::warn!(
                            map = %name,
                            error = %e,
                            "isolation.map_pin.failed"
                        );
                    }
                }
            }
        }
        let p_map = self
            .ebpf
            .take_map("process_block")
            .ok_or_else(|| anyhow!("process_block map missing"))?;
        let f_map = self
            .ebpf
            .take_map("file_block")
            .ok_or_else(|| anyhow!("file_block map missing"))?;
        let iso_map = self
            .ebpf
            .take_map("isolation_state")
            .ok_or_else(|| anyhow!("isolation_state map missing"))?;
        let allow_map = self
            .ebpf
            .take_map("manager_ip_allowlist")
            .ok_or_else(|| anyhow!("manager_ip_allowlist map missing"))?;
        Ok(BlockListHandle {
            inner: Arc::new(Mutex::new(BlockListInner {
                process: AyaHashMap::try_from(p_map)?,
                file: AyaHashMap::try_from(f_map)?,
                isolation_state: PerCpuArray::try_from(iso_map)?,
                allowlist: AyaHashMap::try_from(allow_map)?,
            })),
        })
    }

    /// Take ownership of the `dns_block_domains` map and return a
    /// thread-safe handle the DNS resync handler can use.
    ///
    /// Best-effort — older agents built against a BPF object that
    /// pre-dates Phase 2 #2.12 won't have the map, in which case we
    /// return `Ok(None)` and the caller logs + falls back to no DNS
    /// blocking. The map is NOT pinned: the resync command path
    /// resends the effective set on every reconnect, so a fresh load
    /// converges within one round-trip.
    pub fn take_dns_block(&mut self) -> Result<Option<DnsBlockHandle>> {
        let Some(map) = self.ebpf.take_map("dns_block_domains") else {
            return Ok(None);
        };
        Ok(Some(DnsBlockHandle {
            inner: Arc::new(Mutex::new(DnsBlockInner {
                map: AyaHashMap::try_from(map)?,
            })),
        }))
    }

    /// Take ownership of the ring-buffer map and spawn an async drainer
    /// that translates events to protobuf and pushes them onto `send_tx`.
    /// `hasher` (M10.a) optionally enriches FileEvent payloads with
    /// SHA-256; pass None to disable.
    pub fn spawn_drainer(
        &mut self,
        ctx: LoaderCtx,
        send_tx: mpsc::Sender<p::ClientMessage>,
        hasher: Option<crate::hasher::Hasher>,
    ) -> Result<()> {
        let map = self
            .ebpf
            .take_map("events")
            .ok_or_else(|| anyhow!("events ring map missing"))?;
        let ring = RingBuf::try_from(map)?;

        tokio::spawn(async move {
            if let Err(e) = drain_loop(ring, ctx, send_tx, hasher).await {
                tracing::error!(error = %e, "ebpf.drain_loop_failed");
            }
        });
        Ok(())
    }

    /// Attach the M7.1 self-protection LSM hooks, populate the
    /// `agent_self` and `protected_inodes` maps, and pin programs +
    /// links to `pin_dir` so they survive an agent crash.
    ///
    /// Runs after [`load_and_attach`]. Failures are logged but don't
    /// fail the whole agent — telemetry collection remains the priority.
    /// Returns the list of bpffs paths created (programs + links + maps)
    /// so the caller can record them for an optional unpin-on-exit.
    pub fn enable_self_protection(
        &mut self,
        state_dir: &Path,
        pin_dir: &Path,
    ) -> Result<Vec<PathBuf>> {
        let progs_dir = pin_dir.join("progs");
        let links_dir = pin_dir.join("links");
        let maps_dir = pin_dir.join("maps");
        for d in [pin_dir, &progs_dir, &links_dir, &maps_dir] {
            std::fs::create_dir_all(d)
                .with_context(|| format!("create_dir_all {}", d.display()))?;
        }

        // 1. agent_self[0] = our tgid. Programs key off this; until
        //    populated, every self-protection check no-ops.
        {
            let map = self
                .ebpf
                .map_mut("agent_self")
                .ok_or_else(|| anyhow!("agent_self map missing"))?;
            let mut arr: Array<&mut MapData, u32> = Array::try_from(map)?;
            arr.set(0u32, std::process::id(), 0)
                .context("agent_self.set(0, tgid)")?;
        }

        // 2. protected_inodes: state_dir + identity_dir + spool_dir +
        //    pin_dir. Used by lsm/inode_unlink/rmdir/rename to refuse
        //    operations on entries directly under these dirs.
        {
            let map = self
                .ebpf
                .map_mut("protected_inodes")
                .ok_or_else(|| anyhow!("protected_inodes map missing"))?;
            let mut hm: AyaHashMap<&mut MapData, [u8; 16], u8> = AyaHashMap::try_from(map)?;
            let candidates = [
                state_dir.to_path_buf(),
                state_dir.join("identity"),
                state_dir.join("spool"),
                pin_dir.to_path_buf(),
                progs_dir.clone(),
                links_dir.clone(),
                maps_dir.clone(),
            ];
            let mut count = 0usize;
            for p in &candidates {
                match std::fs::metadata(p) {
                    Ok(meta) => {
                        let key = inode_key(meta.dev(), meta.ino());
                        if let Err(e) = hm.insert(key, 1u8, 0) {
                            tracing::warn!(path = %p.display(), error = %e, "self_protection.protected_inode.insert_failed");
                        } else {
                            count += 1;
                        }
                    }
                    Err(e) => {
                        // state_dir may not exist on first run — best
                        // effort, agent will create it later.
                        tracing::debug!(path = %p.display(), error = %e, "self_protection.protected_inode.stat_failed");
                    }
                }
            }
            tracing::info!(count, "self_protection.protected_inodes.populated");
        }

        // 3. Attach + pin each self-protection LSM hook. We only pin
        //    links (not programs) because pinning the link is sufficient
        //    to keep the kernel attachment alive after we exit; pinning
        //    the program too is strictly redundant because the link
        //    holds a refcount on it. The detection-side LSM hooks
        //    (file_open / socket_connect / bprm_check_security) are
        //    attached + pinned earlier by `load_and_attach`.
        let mut paths: Vec<PathBuf> = Vec::new();
        let mut attached = Vec::new();
        for (prog_name, hook) in SELF_PROTECT_LSM_HOOKS {
            match attach_lsm(&mut self.ebpf, prog_name, hook, Some(&links_dir)) {
                Ok(Some(p)) => {
                    paths.push(p);
                    attached.push(hook);
                }
                Ok(None) => {
                    // Unreachable: we passed Some(&links_dir).
                    tracing::warn!(prog = %prog_name, hook = %hook, "self_protection.lsm_attach.unpinned");
                }
                Err(e) => {
                    tracing::warn!(prog = %prog_name, hook = %hook, error = %e, "self_protection.lsm_attach.failed");
                }
            }
        }
        // Record the pin paths of the detection LSMs so the watchdog's
        // EXPECTED_LSM_HOOKS scan finds them. They were pinned by
        // `load_and_attach`; we don't re-attach here.
        for (prog_name, _hook) in DETECT_LSM_HOOKS {
            let pin_path = links_dir.join(prog_name);
            if pin_path.exists() {
                paths.push(pin_path);
            }
        }

        // 4. Pin agent_self + protected_inodes so a takeover from a
        //    future crashed-then-restarted agent can find them.
        //    isolation_state + manager_ip_allowlist are pinned inside
        //    `take_block_lists` (they're taken by the handle before this
        //    point, so `self.ebpf.map(name)` would return None here);
        //    we still record their expected pin paths under `paths` so
        //    the watchdog has the full set.
        for name in EXPECTED_PINNED_MAPS {
            let pin_path = maps_dir.join(name);
            if pin_path.exists() {
                // Already pinned (either by an earlier branch of this
                // method, or by `take_block_lists` for the isolation
                // maps). Record so the watchdog watches the file but
                // don't double-pin.
                tracing::debug!(path = %pin_path.display(), "self_protection.map_pin.path_exists_skipping");
                paths.push(pin_path);
                continue;
            }
            if let Some(map) = self.ebpf.map(name) {
                if let Err(e) = map.pin(&pin_path) {
                    tracing::warn!(map = %name, error = %e, "self_protection.map_pin.failed");
                } else {
                    paths.push(pin_path);
                }
            }
        }

        tracing::info!(
            tgid = std::process::id(),
            attached = ?attached,
            pinned = paths.len(),
            "self_protection.enabled"
        );
        Ok(paths)
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

/// Attach an LSM program; optionally pin its link to bpffs.
///
/// LSM programs need a kernel BTF reference at load time and a separate
/// `attach()` call (no category/event tuple like tracepoints).
/// `prog_name` is the C function name (the SEC label is e.g. "lsm/file_open");
/// `hook_name` is the kernel hook (e.g. "file_open").
///
/// When `links_dir` is `Some`, the resulting link is pinned to
/// `<links_dir>/<prog_name>` so the kernel attachment survives the
/// agent's exit. Returns the pin path on `Some`, `None` on the
/// unpinned path. The pin filename uses `prog_name` to match the
/// smoke test's `links/handle_task_kill` convention.
fn attach_lsm(
    ebpf: &mut Ebpf,
    prog_name: &str,
    hook_name: &str,
    links_dir: Option<&Path>,
) -> Result<Option<PathBuf>> {
    let btf = Btf::from_sys_fs().context("Btf::from_sys_fs")?;
    let prog: &mut Lsm = ebpf
        .program_mut(prog_name)
        .ok_or_else(|| anyhow!("{prog_name} program missing"))?
        .try_into()?;
    prog.load(hook_name, &btf)
        .with_context(|| format!("load lsm/{hook_name}"))?;
    let link_id = prog
        .attach()
        .with_context(|| format!("attach lsm/{hook_name}"))?;
    let Some(dir) = links_dir else {
        return Ok(None);
    };
    let owned = prog
        .take_link(link_id)
        .with_context(|| format!("take_link lsm/{hook_name}"))?;
    let fd_link: aya::programs::links::FdLink = owned.into();
    let pin_path = dir.join(prog_name);
    let _pinned = fd_link
        .pin(&pin_path)
        .with_context(|| format!("pin link to {}", pin_path.display()))?;
    // _pinned is dropped here; that closes our local fd but the bpffs
    // file holds the link alive.
    Ok(Some(pin_path))
}

/// Pack `(dev, ino)` into the 16-byte little-endian layout that matches
/// `struct vigil_inode_key` in `vigil.bpf.c`: `[u32 dev | u32 _pad | u64 ino]`.
/// `userspace_dev` is the value from [`std::os::unix::fs::MetadataExt::dev`]
/// (glibc encoding); we translate to the kernel `s_dev` encoding before
/// packing so the BPF lookup matches what `BPF_CORE_READ(dir, i_sb, s_dev)`
/// produces inside the kernel.
fn inode_key(userspace_dev: u64, ino: u64) -> [u8; 16] {
    let mut k = [0u8; 16];
    let kernel_dev = userspace_dev_to_kernel(userspace_dev);
    k[0..4].copy_from_slice(&kernel_dev.to_le_bytes());
    // bytes 4..8 are padding (zero)
    k[8..16].copy_from_slice(&ino.to_le_bytes());
    k
}

/// Translate a glibc `dev_t` (the value returned by stat(2) via
/// `MetadataExt::dev`) into the kernel's `s_dev` encoding.
///
/// glibc `dev_t` (64-bit): major in bits 8..20 + 32..64; minor in
/// bits 0..8 + 12..32. Kernel `dev_t` (32-bit): `(major << 20) | minor`,
/// with `MINORBITS = 20`.
fn userspace_dev_to_kernel(dev: u64) -> u32 {
    let major = (((dev >> 8) & 0xfff) as u32) | (((dev >> 32) & !0xfff) as u32);
    let minor = ((dev & 0xff) as u32) | (((dev >> 12) & !0xff) as u32);
    (major << 20) | (minor & 0xf_ffff)
}

/// Walk `pin_dir` and `remove_file` every entry. Used by the optional
/// unpin-on-exit path; idempotent.
pub fn unpin_all(pin_dir: &Path) -> std::io::Result<()> {
    if !pin_dir.exists() {
        return Ok(());
    }
    for sub in ["links", "progs", "maps"] {
        let dir = pin_dir.join(sub);
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
    Ok(())
}

/// Best-effort one-line summary of all stat counters.
pub fn format_stats(stats: &[u64; STAT_COUNT]) -> String {
    format!(
        "exec={} exit={} file_open={} net_connect={} module_load={} \
         block_hits=p:{}/f:{}/n:{} kill_requests={} events_dropped={} \
         self_blocked=k:{}/t:{}/b:{}/u:{} long_path=l:{}/t:{} \
         isolation=h:{}/d:{}",
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
        stats[Stat::SelfKillBlocked as usize],
        stats[Stat::SelfPtraceBlocked as usize],
        stats[Stat::SelfBpfBlocked as usize],
        stats[Stat::SelfUnlinkBlocked as usize],
        stats[Stat::LongPathBlockLookup as usize],
        stats[Stat::LongPathTrulyTooLong as usize],
        stats[Stat::NetworkIsolationHits as usize],
        stats[Stat::NetworkIsolationDrops as usize],
    )
}

async fn drain_loop(
    mut ring: RingBuf<MapData>,
    ctx: LoaderCtx,
    send_tx: mpsc::Sender<p::ClientMessage>,
    hasher: Option<crate::hasher::Hasher>,
) -> Result<()> {
    // RingBuf is edge-triggered via epoll; AsyncFd lets tokio await on it.
    // We follow aya's documented loop shape: wait, drain, clear_ready.
    let async_fd = AsyncFd::new(RingFd(ring.as_raw_fd())).context("AsyncFd::new(RingBuf)")?;

    // Cap per-batch so a single ClientMessage stays under typical gRPC
    // limits (4 MiB default). 256 events × ~600 bytes each ≈ 150 KiB.
    const MAX_BATCH: usize = 256;

    loop {
        let mut guard = async_fd.readable().await?;
        let mut batch: Vec<p::EndpointEvent> = Vec::new();
        while let Some(item) = ring.next() {
            // Phase 4 #4.5: detect honeytoken hits before the parse so
            // we can fire the side-channel ClientMessage even if the
            // file event is later dropped by a downstream filter.
            check_honeytoken_hit(&item, &send_tx).await;
            if let Some(mut ev) = parse_event(&item, &ctx) {
                // M10.a: enrich FileEvent with SHA-256 (cache hit → sync,
                // miss → fire-and-forget enqueue; the next event for this
                // path will carry the hash).
                if let Some(ref h) = hasher {
                    enrich_file_hash(&mut ev, h);
                }
                // Phase 2 #2.9: container attribution for process events.
                // Cached per (pid, container_id) so a re-exec loop only
                // pays the cgroup-parse cost once per fresh container.
                enrich_process_container(&mut ev).await;
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

/// Phase 4 #4.5: inspect a raw ring-buffer item; if it's a file_open
/// against a deployed honeytoken path, emit a `HoneytokenHit`. Cheap
/// fast-path: skip entirely when no decoys are deployed.
async fn check_honeytoken_hit(buf: &[u8], send_tx: &mpsc::Sender<p::ClientMessage>) {
    if buf.len() < 32 {
        return;
    }
    let kind = match u32::from_ne_bytes(buf[4..8].try_into().unwrap_or([0u8; 4])) {
        v if v == VIGIL_EVENT_KIND_FILE_OPEN => v,
        _ => return,
    };
    let _ = kind;
    let pid = u32::from_ne_bytes(buf[16..20].try_into().unwrap_or([0u8; 4]));
    const HDR: usize = 32;
    if buf.len() < HDR + COMM_LEN + 8 {
        return;
    }
    let comm = read_cstr(&buf[HDR..HDR + COMM_LEN]);
    let Ok(plen_bytes) = buf[HDR + COMM_LEN + 4..HDR + COMM_LEN + 8].try_into() else {
        return;
    };
    let path_len = u32::from_ne_bytes(plen_bytes) as usize;
    let path_start = HDR + COMM_LEN + 8;
    if path_len == 0 || path_start + path_len > buf.len() || path_len > PATH_MAX {
        return;
    }
    let path = String::from_utf8_lossy(&buf[path_start..path_start + path_len])
        .trim_end_matches('\0')
        .to_string();
    if path.is_empty() {
        return;
    }

    // Cheap fast-path: no decoys deployed → skip the lookup entirely.
    let id_from_map = {
        let guard = crate::deception::DEPLOYED.read().ok();
        match guard {
            Some(g) if !g.is_empty() => g.lookup_path(&path).map(|s| s.to_string()),
            _ => None,
        }
    };
    let Some(id) = id_from_map else {
        return;
    };

    // Double-check the xattr is still there so a deleted-and-recreated
    // file with the same path doesn't keep firing false positives.
    let confirmed_id = crate::deception::read_xattr_id(std::path::Path::new(&path));
    if confirmed_id.as_deref() != Some(id.as_str()) {
        return;
    }

    let hit = p::HoneytokenHit {
        honeytoken_id: id,
        process_pid: pid as u64,
        process_executable: comm,
        hit_at: Some(agent_core::event::now_pb()),
    };
    let msg = p::ClientMessage {
        payload: Some(p::client_message::Payload::HoneytokenHit(hit)),
    };
    let _ = send_tx.send(msg).await;
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
        VIGIL_EVENT_KIND_PROCESS_START => {
            // header(32) + comm[16] + path_len(4) + path[384]
            if buf.len() < 32 + COMM_LEN + 4 {
                return None;
            }
            let comm = read_cstr(&buf[32..32 + COMM_LEN]);
            let path_len =
                u32::from_ne_bytes(buf[32 + COMM_LEN..32 + COMM_LEN + 4].try_into().ok()?) as usize;
            let path_start = 32 + COMM_LEN + 4;
            let path = if path_len > 0 && path_start + path_len <= buf.len() && path_len <= PATH_MAX
            {
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
                // Phase 2 #2.9: container enrichment happens post-parse
                // (enrich is async; parse_event is sync). See
                // `enrich_process_container` in spawn_drainer.
                None,
            ))
        }
        VIGIL_EVENT_KIND_PROCESS_EXIT => {
            // M6.2: process exit is counted in eBPF stats but not forwarded
            // upstream — we mirror the Windows agent which only ships
            // process_start. M6.x can add an exit event if Sigma rules
            // start needing it.
            None
        }
        VIGIL_EVENT_KIND_MODULE_LOAD => {
            // header(32) + comm[16] + name_len(4) + name[64]
            const HDR: usize = 32;
            const NAME_MAX: usize = 64;
            if buf.len() < HDR + COMM_LEN + 4 {
                return None;
            }
            let _comm = read_cstr(&buf[HDR..HDR + COMM_LEN]);
            let name_len =
                u32::from_ne_bytes(buf[HDR + COMM_LEN..HDR + COMM_LEN + 4].try_into().ok()?)
                    as usize;
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
        VIGIL_EVENT_KIND_NETWORK_CONNECT => {
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
        VIGIL_EVENT_KIND_FILE_OPEN => {
            // header(32) + comm[16] + open_flags(4) + path_len(4) + path[384]
            const HDR: usize = 32;
            if buf.len() < HDR + COMM_LEN + 8 {
                return None;
            }
            let comm = read_cstr(&buf[HDR..HDR + COMM_LEN]);
            let open_flags =
                u32::from_ne_bytes(buf[HDR + COMM_LEN..HDR + COMM_LEN + 4].try_into().ok()?);
            let path_len = u32::from_ne_bytes(
                buf[HDR + COMM_LEN + 4..HDR + COMM_LEN + 8]
                    .try_into()
                    .ok()?,
            ) as usize;
            let path_start = HDR + COMM_LEN + 8;
            let path = if path_len > 0 && path_start + path_len <= buf.len() && path_len <= PATH_MAX
            {
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

/// Phase 2 #2.9: stamp container.* onto a ProcessEvent when the pid
/// resolves to a container via the cgroup walk. Bare-metal pids are a
/// no-op. Cache lives inside `crate::container` so a re-exec storm
/// only re-reads /proc/<pid>/cgroup once per container.
async fn enrich_process_container(ev: &mut p::EndpointEvent) {
    let Some(p::endpoint_event::Payload::Process(ref mut pe)) = ev.payload else {
        return;
    };
    let Some(ref pk) = pe.process else { return };
    let Some(info) = crate::container::enrich(pk.pid).await else {
        return;
    };
    pe.container_id = info.id;
    pe.container_image = info.image;
    pe.container_runtime = info.runtime as i32;
}

/// Lookup the path in the hasher and stamp the SHA-256 onto the
/// FileEvent payload if cached. Cache miss: enqueue (background) and
/// leave the hash empty; next event for the same path benefits.
fn enrich_file_hash(ev: &mut p::EndpointEvent, hasher: &crate::hasher::Hasher) {
    if let Some(p::endpoint_event::Payload::File(ref mut fe)) = ev.payload {
        if !fe.path.is_empty() && fe.hash.is_none() {
            if let Some(hex) = hasher.lookup_or_enqueue(&fe.path) {
                fe.hash = Some(p::Hash {
                    sha256: hex,
                    md5: String::new(),
                    sha1: String::new(),
                });
            }
        }
    }
}

fn read_cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

#[cfg(test)]
mod block_key_tests {
    use super::*;

    #[test]
    fn short_path_is_zero_padded_after_natural_nul() {
        // "abc" -> [a, b, c, 0, 0, ..., 0]. Pre- and post-fix produce the
        // same shape for short paths; this test pins it so a future
        // refactor doesn't quietly drop the natural NUL.
        let k = block_key("/abc");
        assert_eq!(&k[..4], b"/abc");
        assert!(k[4..].iter().all(|&b| b == 0));
    }

    #[test]
    fn empty_path_is_all_zeros() {
        let k = block_key("");
        assert!(k.iter().all(|&b| b == 0));
    }

    #[test]
    fn path_exactly_at_limit_minus_one_keeps_terminating_nul_slot() {
        // 254 chars of content. With BLOCK_KEY_LEN=256 and the
        // 255-char effective cap, byte [254] is the last content slot
        // and byte [255] stays 0 for the kernel NUL.
        let s = "x".repeat(255);
        let k = block_key(&s);
        assert_eq!(&k[..255], s.as_bytes());
        assert_eq!(k[255], 0);
    }

    #[test]
    fn long_path_truncates_with_nul_reserved_at_255() {
        // Top-20 #5: a path of 260 chars used to fill all 256 bytes of
        // the userspace key. The kernel side reads via
        // bpf_probe_read_kernel_str(key, 256, src) which writes
        // [255 chars][NUL]. The two keys then hash differently and the
        // lookup misses. Post-fix, userspace also reserves byte [255]
        // as NUL so the two match.
        let s = "y".repeat(260);
        let k = block_key(&s);
        // First 255 bytes are content.
        assert!(k[..255].iter().all(|&b| b == b'y'));
        // Byte [255] is the reserved NUL.
        assert_eq!(k[255], 0);
    }

    #[test]
    fn two_keys_differing_only_after_255_collide_by_design() {
        // Side effect of the truncation: a path that's identical for
        // the first 255 chars but differs after now hashes to the same
        // key. Pre-fix this was also true once the path crossed 256
        // chars (and additionally bypassed the hook entirely). The
        // test pins the new behaviour so a follow-up that wants to
        // distinguish such paths knows to grow VIGIL_BLOCK_KEY_LEN.
        let prefix = "z".repeat(255);
        let a = block_key(&format!("{prefix}-evil"));
        let b = block_key(&format!("{prefix}-other"));
        assert_eq!(a, b);
    }
}

#[cfg(test)]
mod isolation_tests {
    //! Phase 1 #1.3: IPv4 → IPv4-mapped-IPv6 normalisation tests for
    //! the `manager_ip_allowlist` lookup key. The BPF hook builds the
    //! same shape on the kernel side (see `handle_socket_connect`); if
    //! the two ever drift, allowlisted IPs would silently fail to match
    //! during isolation. Pin the shape here so a refactor catches it.

    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn ipv4_maps_into_v4_mapped_v6() {
        // 10.0.0.42 → 00 00 00 00 00 00 00 00 00 00 ff ff 0a 00 00 2a
        let k = ip_allowlist_key(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42)));
        assert_eq!(&k[..10], &[0u8; 10]);
        assert_eq!(&k[10..12], &[0xff, 0xff]);
        assert_eq!(&k[12..], &[10, 0, 0, 42]);
    }

    #[test]
    fn ipv4_localhost_maps_correctly() {
        let k = ip_allowlist_key(IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(k[10], 0xff);
        assert_eq!(k[11], 0xff);
        assert_eq!(&k[12..], &[127, 0, 0, 1]);
    }

    #[test]
    fn ipv6_passes_through_unchanged() {
        // 2001:db8::1 → 20 01 0d b8 00 .. 00 01 (16 bytes, big-endian)
        let v6 = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        let k = ip_allowlist_key(IpAddr::V6(v6));
        assert_eq!(k, v6.octets());
    }

    #[test]
    fn ipv4_and_v4_mapped_v6_collide() {
        // ::ffff:10.0.0.42 should produce the same key as 10.0.0.42 so
        // the operator can specify either form in the allowlist.
        let v4 = ip_allowlist_key(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42)));
        let mapped = Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x002a);
        let v6 = ip_allowlist_key(IpAddr::V6(mapped));
        assert_eq!(v4, v6);
    }

    #[test]
    fn distinct_v4s_produce_distinct_keys() {
        let a = ip_allowlist_key(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let b = ip_allowlist_key(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_ne!(a, b);
    }
}

#[cfg(test)]
mod lsm_hook_tests {
    //! CODE-216 regression. The watchdog scans `EXPECTED_LSM_HOOKS`;
    //! pinning happens via `<links_dir>/<prog_name>`. If the list
    //! drifts away from the prog names the BPF C side actually
    //! exports, the watchdog will silently watch the wrong file
    //! again. Pin the contract here so a future hook addition can't
    //! quietly skip the watchdog.
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn expected_hooks_concatenates_self_protect_and_detect() {
        // Order matters for the watchdog's per-target latch
        // (alerted_links is keyed on the prog name); pin it.
        let combined = EXPECTED_LSM_HOOKS.to_vec();
        let from_parts: Vec<_> = SELF_PROTECT_LSM_HOOKS
            .iter()
            .copied()
            .chain(DETECT_LSM_HOOKS.iter().copied())
            .collect();
        assert_eq!(combined, from_parts);
    }

    #[test]
    fn detect_hooks_cover_file_open_socket_connect_and_bprm_check() {
        let names: HashSet<&str> = DETECT_LSM_HOOKS.iter().map(|(_, h)| *h).collect();
        assert!(names.contains("file_open"));
        assert!(names.contains("socket_connect"));
        assert!(names.contains("bprm_check_security"));
    }

    #[test]
    fn no_prog_name_collision_across_self_protect_and_detect() {
        // The watchdog uses the prog name as the bpffs filename; two
        // hooks sharing a prog name would alias their pins.
        let mut seen: HashSet<&str> = HashSet::new();
        for (prog, _) in EXPECTED_LSM_HOOKS.iter() {
            assert!(seen.insert(prog), "duplicate prog name: {prog}");
        }
    }
}
