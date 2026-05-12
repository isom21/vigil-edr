// vigil.bpf.c — kernel-side eBPF programs for the Vigil Linux agent (M6).
//
// Compiles to a single BTF-relocatable .bpf.o that the user-mode agent
// loads via aya at startup. Each function is a separate program attached
// to a kernel hook (LSM, tracepoint, kprobe, etc.); they share one ring
// buffer (`events`) and one stats array (`stats`).
//
// M6.1: tracepoint scaffolding + counter.
// M6.2: process exec/exit with full pid/ppid/comm/path payload through
//       the ring buffer.
// M6.3: file open via lsm/file_open (kernel-side path resolution +
//       open-flag-aware filtering to keep the ring volume sane).
// M6.4: outbound network connect via lsm/socket_connect (IPv4 + IPv6,
//       captures dest sockaddr and best-effort source).
// M6.x: kernel module load via tracepoint:module:module_load.
// M6.6: deny-on-match via lsm/bprm_check_security (exec) and a path
//       check inside lsm/file_open. Block lists are HASH maps keyed by
//       a 256-byte zero-padded path; userspace drives them.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

// ---------------------------------------------------------------------------
// Stats array
// ---------------------------------------------------------------------------

enum vigil_stat {
    VIGIL_STAT_PROCESS_EXEC = 0,
    VIGIL_STAT_PROCESS_EXIT,
    VIGIL_STAT_FILE_OPEN,
    VIGIL_STAT_NETWORK_CONNECT,
    VIGIL_STAT_MODULE_LOAD,
    VIGIL_STAT_PROCESS_BLOCK_HITS,
    VIGIL_STAT_FILE_BLOCK_HITS,
    VIGIL_STAT_NETWORK_BLOCK_HITS,
    VIGIL_STAT_KILL_REQUESTS,
    VIGIL_STAT_EVENTS_DROPPED,
    // M7.1 self-protection counters.
    VIGIL_STAT_SELF_KILL_BLOCKED,
    VIGIL_STAT_SELF_PTRACE_BLOCKED,
    VIGIL_STAT_SELF_BPF_BLOCKED,
    VIGIL_STAT_SELF_UNLINK_BLOCKED,
    // Top-20 #5: bumped when a >VIGIL_BLOCK_KEY_LEN path is observed at
    // a block hook. The 256-byte scratch buffer pre-fix made
    // bpf_d_path return -ENAMETOOLONG on these, which silently allowed
    // the exec/open. The fix uses a 4096-byte scratch and truncates
    // to the 256-byte lookup key; this counter surfaces how often the
    // long-path path is exercised so operators can size the buffer.
    VIGIL_STAT_LONG_PATH_BLOCK_LOOKUP,
    VIGIL_STAT_LONG_PATH_TRULY_TOO_LONG,
    VIGIL_STAT_MAX,
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, VIGIL_STAT_MAX);
} stats SEC(".maps");

static __always_inline void stat_inc(enum vigil_stat which)
{
    __u32 key = (__u32)which;
    __u64 *v = bpf_map_lookup_elem(&stats, &key);
    if (v)
        __sync_fetch_and_add(v, 1);
}

// ---------------------------------------------------------------------------
// Event ring + wire format
// ---------------------------------------------------------------------------

#define VIGIL_EVENT_KIND_PROCESS_START   1
#define VIGIL_EVENT_KIND_PROCESS_EXIT    2
#define VIGIL_EVENT_KIND_FILE_OPEN       3
#define VIGIL_EVENT_KIND_NETWORK_CONNECT 4
#define VIGIL_EVENT_KIND_MODULE_LOAD     5
// 6..8 reserved to mirror Windows numbering.

#define VIGIL_COMM_LEN 16
#define VIGIL_PATH_MAX 384   // executable path; truncated if longer

struct vigil_event_header {
    __u32 size;            // total bytes including header + payload
    __u32 kind;            // VIGIL_EVENT_KIND_*
    __u64 timestamp_ns;    // bpf_ktime_get_boot_ns()
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
};

struct vigil_event_process_start {
    struct vigil_event_header header;
    char comm[VIGIL_COMM_LEN];   // task->comm (basename, up to 15 chars)
    __u32 path_len;            // bytes of `path` in use; 0 if absent
    char path[VIGIL_PATH_MAX];   // full executable path via bpf_d_path
};

struct vigil_event_process_exit {
    struct vigil_event_header header;
    char comm[VIGIL_COMM_LEN];
    __s32 exit_code;
};

struct vigil_event_file_open {
    struct vigil_event_header header;
    char comm[VIGIL_COMM_LEN];
    __u32 open_flags;          // f_flags from struct file
    __u32 path_len;
    char path[VIGIL_PATH_MAX];
};

struct vigil_event_network_connect {
    struct vigil_event_header header;
    char comm[VIGIL_COMM_LEN];
    __u8  family;              // AF_INET or AF_INET6
    __u8  protocol;             // IPPROTO_TCP / IPPROTO_UDP / etc.
    __u16 src_port;             // host byte order, may be 0 pre-connect
    __u16 dst_port;             // host byte order
    __u16 _pad;
    __u8  src_addr[16];         // ipv4 in [0..4], rest 0; ipv6 fills 16
    __u8  dst_addr[16];
};

#define VIGIL_MODULE_NAME_MAX 64

struct vigil_event_module_load {
    struct vigil_event_header header;
    char comm[VIGIL_COMM_LEN];     // task that triggered load (modprobe, insmod, …)
    __u32 name_len;              // bytes used in `name`
    char  name[VIGIL_MODULE_NAME_MAX];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

// Block-list maps. Keys are zero-padded 256-byte paths (VIGIL_BLOCK_KEY_LEN);
// values are 1 byte (presence == "block"). BPF_F_NO_PREALLOC keeps the
// kernel from preallocating max_entries × 256 bytes up front.
#define VIGIL_BLOCK_KEY_LEN 256
#define VIGIL_BLOCK_MAX     256

struct vigil_block_key {
    char path[VIGIL_BLOCK_KEY_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct vigil_block_key);
    __type(value, __u8);
    __uint(max_entries, VIGIL_BLOCK_MAX);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} process_block SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct vigil_block_key);
    __type(value, __u8);
    __uint(max_entries, VIGIL_BLOCK_MAX);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} file_block SEC(".maps");

// Per-CPU scratch for paths produced by bpf_d_path before we copy them
// (NUL-stop) into a zero-padded lookup key. bpf_d_path writes its
// output to the *front* of the buffer but doesn't zero the tail, so
// using its raw output as a hash key would mismatch userspace's
// zero-padded keys. Reading via bpf_probe_read_kernel_str strips at
// the NUL and leaves the (zero-init) destination tail clean.
//
// Top-20 #5 fix: the scratch is 4096 bytes (≈ PATH_MAX) so bpf_d_path
// can resolve arbitrarily deep paths without returning -ENAMETOOLONG.
// Pre-fix the buffer was 256 bytes (= VIGIL_BLOCK_KEY_LEN), which made
// the LSM hook silently allow exec/open for any path longer than 256
// chars — an attacker who controls placement could rename a malicious
// binary to a long nested path and bypass the block list. The lookup
// key is still 256 bytes (VIGIL_BLOCK_KEY_LEN), built via
// bpf_probe_read_kernel_str from the front of the scratch, which
// truncates with a NUL terminator at byte 255 and leaves the rest of
// the (zero-initialized) key clean — matching what userspace's
// `block_key()` produces for an over-long path.
#define VIGIL_PATH_SCRATCH_LEN 4096

struct vigil_path_scratch {
    char path[VIGIL_PATH_SCRATCH_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct vigil_path_scratch);
    __uint(max_entries, 1);
} path_scratch SEC(".maps");

// ---------------------------------------------------------------------------
// Self-protection (M7.1)
//
// Three pieces:
//   * `agent_self`: a one-entry array holding the agent's tgid. LSM hooks
//     read this to know who they're protecting; userspace writes it on
//     load (and on takeover during agent restart).
//   * `protected_inodes`: hash of (dev, ino) tuples for the bpffs pin
//     directory and the agent's state directory. lsm/inode_unlink &c.
//     refuse to remove anything whose parent inode is in this set when
//     the caller isn't the agent.
//   * LSM hooks: task_kill, ptrace_access_check, bpf, inode_unlink,
//     inode_rmdir, inode_rename. All read agent_self; if the operation
//     targets the agent (or a protected inode) and the caller isn't the
//     agent, return -EPERM.
//
// Carve-outs:
//   * task_kill allows pid 1 (init/systemd) so `systemctl stop` works.
//   * lsm/bpf rejects BPF_PROG_DETACH, BPF_LINK_DETACH,
//     BPF_MAP_UPDATE_ELEM, and BPF_MAP_DELETE_ELEM from any non-self
//     caller when an agent has claimed the slot (self_tgid() != 0).
//     UPDATE_ELEM used to be allowed unconditionally to enable
//     restart-after-crash takeover; that made `bpftool map update id
//     <X> key 0 0 0 0 value <attacker_tgid>` a self-protection bypass
//     (the LSM hooks would then protect the attacker's tgid instead of
//     the agent's). Takeover is now driven by the auto-clear in
//     `handle_sched_exit` — when the agent's tgid exits, the
//     tracepoint zeroes agent_self, and the next agent finds
//     self_tgid() == 0 and claims via the standard initial path.
//     See `cleanup_or_takeover` in agent-linux/src/ebpf.rs.
// ---------------------------------------------------------------------------

#define VIGIL_SELF_KEY 0  // index in agent_self

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} agent_self SEC(".maps");

struct vigil_inode_key {
    __u32 dev;
    __u32 _pad;
    __u64 ino;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct vigil_inode_key);
    __type(value, __u8);
    __uint(max_entries, 32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} protected_inodes SEC(".maps");

static __always_inline __u32 self_tgid(void)
{
    __u32 zero = VIGIL_SELF_KEY;
    __u32 *p = bpf_map_lookup_elem(&agent_self, &zero);
    return p ? *p : 0;  // 0 = not set yet -> all hooks no-op
}

static __always_inline __u32 caller_tgid(void)
{
    __u64 pt = bpf_get_current_pid_tgid();
    return (__u32)(pt >> 32);
}

static __always_inline int is_protected_dir_inode(struct inode *dir)
{
    if (!dir)
        return 0;
    struct vigil_inode_key key = {};
    key.dev = (__u32)BPF_CORE_READ(dir, i_sb, s_dev);
    key.ino = BPF_CORE_READ(dir, i_ino);
    __u8 *hit = bpf_map_lookup_elem(&protected_inodes, &key);
    return hit != NULL;
}

// kill / signal delivery to the agent. We allow pid 1 (init) so the
// systemd unit can SIGTERM us during graceful shutdown; everyone else
// gets EPERM if they target our tgid.
SEC("lsm/task_kill")
int BPF_PROG(handle_task_kill, struct task_struct *p,
             struct kernel_siginfo *info, int sig, const struct cred *cred)
{
    (void)info;
    (void)sig;
    (void)cred;
    if (!p)
        return 0;
    __u32 self = self_tgid();
    if (self == 0)
        return 0;
    __u32 target_tgid = BPF_CORE_READ(p, tgid);
    if (target_tgid != self)
        return 0;
    __u32 caller = caller_tgid();
    if (caller == self || caller == 1)
        return 0;
    stat_inc(VIGIL_STAT_SELF_KILL_BLOCKED);
    return -1; // -EPERM
}

// ptrace attach + /proc/<pid>/mem read both route through this hook.
SEC("lsm/ptrace_access_check")
int BPF_PROG(handle_ptrace_access_check, struct task_struct *child, unsigned int mode)
{
    (void)mode;
    if (!child)
        return 0;
    __u32 self = self_tgid();
    if (self == 0)
        return 0;
    __u32 target_tgid = BPF_CORE_READ(child, tgid);
    if (target_tgid != self)
        return 0;
    __u32 caller = caller_tgid();
    if (caller == self)
        return 0;
    stat_inc(VIGIL_STAT_SELF_PTRACE_BLOCKED);
    return -1;
}

// `bpftool prog detach` / `bpftool link detach` / `bpftool map update`
// invocations route here. bpf_attr command numbers are part of the
// stable uapi.
#ifndef BPF_MAP_UPDATE_ELEM
#define BPF_MAP_UPDATE_ELEM 2
#endif
#ifndef BPF_MAP_DELETE_ELEM
#define BPF_MAP_DELETE_ELEM 3
#endif
#ifndef BPF_PROG_DETACH
#define BPF_PROG_DETACH 8
#endif
#ifndef BPF_LINK_DETACH
#define BPF_LINK_DETACH 34
#endif

SEC("lsm/bpf")
int BPF_PROG(handle_bpf_lsm, int cmd, union bpf_attr *attr, unsigned int size)
{
    (void)attr;
    (void)size;
    __u32 self = self_tgid();
    if (self == 0)
        return 0;
    __u32 caller = caller_tgid();
    if (caller == self)
        return 0;
    // Block four cmds from any non-self caller when an agent has
    // claimed the slot. UPDATE_ELEM + DELETE_ELEM close the
    // `bpftool map update id <X> value <attacker_tgid>` self-
    // protection bypass; DETACH closes detach-and-bypass. Other bpf()
    // commands (program load, map create, etc.) pass through — we
    // don't want to break unrelated BPF tooling on the host beyond
    // what the threat actually requires.
    if (cmd == BPF_PROG_DETACH || cmd == BPF_LINK_DETACH ||
        cmd == BPF_MAP_UPDATE_ELEM || cmd == BPF_MAP_DELETE_ELEM) {
        stat_inc(VIGIL_STAT_SELF_BPF_BLOCKED);
        return -1;
    }
    return 0;
}

// inode_unlink / rmdir: refuse to remove anything whose parent dir is
// in `protected_inodes` (the bpffs pin dir and the state dir).
SEC("lsm/inode_unlink")
int BPF_PROG(handle_inode_unlink, struct inode *dir, struct dentry *dentry)
{
    (void)dentry;
    __u32 self = self_tgid();
    if (self == 0)
        return 0;
    __u32 caller = caller_tgid();
    if (caller == self)
        return 0;
    if (is_protected_dir_inode(dir)) {
        stat_inc(VIGIL_STAT_SELF_UNLINK_BLOCKED);
        return -1;
    }
    return 0;
}

SEC("lsm/inode_rmdir")
int BPF_PROG(handle_inode_rmdir, struct inode *dir, struct dentry *dentry)
{
    (void)dentry;
    __u32 self = self_tgid();
    if (self == 0)
        return 0;
    __u32 caller = caller_tgid();
    if (caller == self)
        return 0;
    if (is_protected_dir_inode(dir)) {
        stat_inc(VIGIL_STAT_SELF_UNLINK_BLOCKED);
        return -1;
    }
    return 0;
}

// Rename can move a child OUT of a protected dir (effectively unlinking
// it from there) or move something INTO one (which would mask a
// protected child). Block if either side is a protected dir.
SEC("lsm/inode_rename")
int BPF_PROG(handle_inode_rename, struct inode *old_dir, struct dentry *old_dentry,
             struct inode *new_dir, struct dentry *new_dentry)
{
    (void)old_dentry;
    (void)new_dentry;
    __u32 self = self_tgid();
    if (self == 0)
        return 0;
    __u32 caller = caller_tgid();
    if (caller == self)
        return 0;
    if (is_protected_dir_inode(old_dir) || is_protected_dir_inode(new_dir)) {
        stat_inc(VIGIL_STAT_SELF_UNLINK_BLOCKED);
        return -1;
    }
    return 0;
}

static __always_inline void fill_header_common(struct vigil_event_header *h, __u32 kind, __u32 size)
{
    h->size = size;
    h->kind = kind;
    h->timestamp_ns = bpf_ktime_get_boot_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    h->pid = (__u32)(pid_tgid >> 32);   // tgid (the "process id" most tools mean)
    __u64 uid_gid = bpf_get_current_uid_gid();
    h->uid = (__u32)(uid_gid & 0xFFFFFFFF);
    h->gid = (__u32)(uid_gid >> 32);
    // ppid filled in by caller when it has a task ptr.
    h->ppid = 0;
}

// ---------------------------------------------------------------------------
// Process exec via tracepoint:sched:sched_process_exec
//
// Observation-only path. M6.6 adds LSM bprm_check_security on top of this
// for the block-create path (LSM hooks can return -EPERM, tracepoints
// can't).
//
// This program reads pid, ppid, uid/gid, comm and the exec'd path via
// the tracepoint's __data_loc filename field.
// ---------------------------------------------------------------------------
SEC("tracepoint/sched/sched_process_exec")
int handle_sched_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    (void)ctx;
    stat_inc(VIGIL_STAT_PROCESS_EXEC);

    struct vigil_event_process_start *e =
        bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        stat_inc(VIGIL_STAT_EVENTS_DROPPED);
        return 0;
    }
    fill_header_common(&e->header, VIGIL_EVENT_KIND_PROCESS_START, sizeof(*e));

    // ppid: walk current->real_parent->tgid via CO-RE.
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        struct task_struct *parent = BPF_CORE_READ(task, real_parent);
        if (parent) {
            e->header.ppid = BPF_CORE_READ(parent, tgid);
        }
    }

    // comm (basename of exe, max 15 chars).
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Best-effort path: tracepoint ctx carries an offset to the filename
    // string; struct trace_event_raw_sched_process_exec has __data_loc
    // filename. We read the offset+size and copy into e->path.
    e->path_len = 0;
    e->path[0] = 0;
    // __data_loc is a 32-bit field: low 16 bits = offset from ctx, high 16 bits = length.
    // The tracepoint format file (/sys/kernel/tracing/events/sched/sched_process_exec/format)
    // shows: field:__data_loc char[] filename; offset:8; size:4.
    __u32 dl = 0;
    bpf_probe_read_kernel(&dl, sizeof(dl), (void *)ctx + 8);
    __u32 off = dl & 0xFFFF;
    __u32 len = (dl >> 16) & 0xFFFF;
    if (len > VIGIL_PATH_MAX) {
        len = VIGIL_PATH_MAX;
    }
    if (len > 0) {
        long n = bpf_probe_read_kernel_str(&e->path, len, (void *)ctx + off);
        if (n > 0) {
            e->path_len = (__u32)n;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ---------------------------------------------------------------------------
// Process exit via tracepoint
//
// LSM has no "process exit" hook; sched_process_exit fires for every
// thread. We filter to thread-group leaders (pid == tgid) so we only
// emit one event per process.
// ---------------------------------------------------------------------------
SEC("tracepoint/sched/sched_process_exit")
int handle_sched_exit(struct trace_event_raw_sched_process_template *ctx)
{
    (void)ctx;

    // Filter to the thread-group leader. bpf_get_current_pid_tgid packs
    // tgid (process id) in the upper 32 and pid (thread id) in the lower
    // 32 bits; we want them equal so we only emit one exit per process.
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid & 0xFFFFFFFF);
    __u32 tgid = (__u32)(pid_tgid >> 32);
    if (pid != tgid) {
        return 0;
    }

    stat_inc(VIGIL_STAT_PROCESS_EXIT);

    // M7.1.b: when the agent's own tgid exits, clear agent_self[0].
    // Without this, lsm/bpf's new UPDATE_ELEM block would lock out
    // the next agent's takeover — caller_tgid (new agent) wouldn't
    // equal self_tgid (dead old agent), so the claim would fail.
    // Clearing on exit makes the next agent see self_tgid()==0 and
    // claim via the standard initial path. This update is a kernel-
    // side BPF map write, NOT a userspace bpf() syscall, so lsm/bpf
    // does not apply.
    __u32 self_now = self_tgid();
    if (self_now != 0 && tgid == self_now) {
        __u32 zero_key = VIGIL_SELF_KEY;
        __u32 zero_val = 0;
        bpf_map_update_elem(&agent_self, &zero_key, &zero_val, BPF_ANY);
    }

    struct vigil_event_process_exit *e =
        bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        stat_inc(VIGIL_STAT_EVENTS_DROPPED);
        return 0;
    }
    fill_header_common(&e->header, VIGIL_EVENT_KIND_PROCESS_EXIT, sizeof(*e));

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // exit_code: task->exit_code. tracepoint passes pid in ctx but we read
    // from current task for richer fields.
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->exit_code = task ? BPF_CORE_READ(task, exit_code) : 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ---------------------------------------------------------------------------
// File open via lsm/file_open
//
// Fires for every open() / openat() / execve() etc. on the kernel side.
// Volume can be ~thousands/sec on a quiet system, so we filter
// aggressively in the kernel: skip paths under /proc, /sys, /dev/pts
// (pseudo-fs traffic that's overwhelmingly uninteresting). Userspace
// can further reduce if needed.
//
// M6.6 will add deny-on-match here (LSM hooks can return -EPERM).
// ---------------------------------------------------------------------------

static __always_inline int path_starts_with(const char *path, __u32 plen,
                                            const char *prefix, __u32 prefix_len)
{
    if (plen < prefix_len)
        return 0;
    #pragma unroll
    for (__u32 i = 0; i < 32; i++) {
        if (i >= prefix_len)
            return 1;
        if (path[i] != prefix[i])
            return 0;
    }
    return 1;
}

SEC("lsm/file_open")
int BPF_PROG(handle_file_open, struct file *file)
{
    if (!file)
        return 0;

    struct vigil_event_file_open *e =
        bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        stat_inc(VIGIL_STAT_EVENTS_DROPPED);
        return 0;
    }

    fill_header_common(&e->header, VIGIL_EVENT_KIND_FILE_OPEN, sizeof(*e));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        struct task_struct *parent = BPF_CORE_READ(task, real_parent);
        if (parent)
            e->header.ppid = BPF_CORE_READ(parent, tgid);
    }

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->open_flags = BPF_CORE_READ(file, f_flags);
    e->path_len = 0;
    e->path[0] = 0;

    // bpf_d_path resolves struct path to "/abs/path"; only valid in
    // tracing/LSM hooks. Returns -errno on failure or path length on
    // success (incl. terminating NUL).
    long n = bpf_d_path(&file->f_path, e->path, sizeof(e->path));
    if (n > 0) {
        e->path_len = (__u32)n;

        const char proc_pfx[]   = "/proc/";
        const char sys_pfx[]    = "/sys/";
        const char devpts_pfx[] = "/dev/pts";
        if (path_starts_with(e->path, e->path_len, proc_pfx, sizeof(proc_pfx) - 1) ||
            path_starts_with(e->path, e->path_len, sys_pfx, sizeof(sys_pfx) - 1) ||
            path_starts_with(e->path, e->path_len, devpts_pfx, sizeof(devpts_pfx) - 1)) {
            bpf_ringbuf_discard(e, 0);
            return 0;
        }
    }

    // M6.6 file block: build a zero-padded 256-byte lookup key from
    // the resolved path and check the file_block hash.
    // bpf_probe_read_kernel_str copies up to N bytes including the NUL
    // and leaves the rest of the (zero-initialized) key untouched — so
    // it perfectly mirrors what the userspace `block_key()` produces.
    int ret = 0;
    if (e->path_len > 0 && e->path_len <= VIGIL_BLOCK_KEY_LEN) {
        struct vigil_block_key key = {};
        long m = bpf_probe_read_kernel_str(key.path, sizeof(key.path), e->path);
        if (m > 0) {
            __u8 *hit = bpf_map_lookup_elem(&file_block, &key);
            if (hit) {
                stat_inc(VIGIL_STAT_FILE_BLOCK_HITS);
                ret = -1; // -EPERM
            }
        }
    }

    stat_inc(VIGIL_STAT_FILE_OPEN);
    bpf_ringbuf_submit(e, 0);
    return ret;
}

// ---------------------------------------------------------------------------
// Process-create deny via lsm/bprm_check_security (M6.6)
//
// Fires on every execve before the new image runs. We resolve the
// would-be exec path with bpf_d_path on bprm->file and look it up in
// the process_block hash map; if present, return -EPERM and log a
// block_hit. The corresponding tracepoint:sched_process_exec fires
// only on successful exec, so a blocked process never produces a
// process_started event — that mirrors the Windows minifilter.
// ---------------------------------------------------------------------------

SEC("lsm/bprm_check_security")
int BPF_PROG(handle_bprm_check, struct linux_binprm *bprm)
{
    if (!bprm)
        return 0;

    // Per-CPU scratch holds the resolved path. 4096 bytes ≈ PATH_MAX;
    // bpf_d_path only returns -ENAMETOOLONG when the resolved path is
    // longer than the buffer, so this sizing accommodates effectively
    // every real-world filesystem path. Pre-fix (Top-20 #5) the buffer
    // was 256 bytes (= VIGIL_BLOCK_KEY_LEN); any path longer than that
    // caused bpf_d_path to return -ENAMETOOLONG and the LSM hook to
    // silently allow the exec — the long-path bypass the reviewer
    // flagged.
    __u32 zero = 0;
    struct vigil_path_scratch *scratch = bpf_map_lookup_elem(&path_scratch, &zero);
    if (!scratch)
        return 0;

    long n = bpf_d_path(&bprm->file->f_path, scratch->path, sizeof(scratch->path));
    if (n <= 0) {
        // Path didn't resolve. Either bpf_d_path returned an error or
        // (for the truly-pathological 4097+ char case) -ENAMETOOLONG.
        // Surface the latter via a stat so operators can tell from
        // the metric whether they're losing visibility into block hits.
        stat_inc(VIGIL_STAT_LONG_PATH_TRULY_TOO_LONG);
        return 0;
    }
    if (n > VIGIL_BLOCK_KEY_LEN) {
        // Path resolved but won't fit in the 256-byte key — we still
        // do the lookup against the truncated prefix, matching what
        // userspace `block_key()` writes for over-long paths.
        stat_inc(VIGIL_STAT_LONG_PATH_BLOCK_LOOKUP);
    }

    struct vigil_block_key key = {};
    long m = bpf_probe_read_kernel_str(key.path, sizeof(key.path), scratch->path);
    if (m <= 0)
        return 0;

    __u8 *hit = bpf_map_lookup_elem(&process_block, &key);
    if (hit) {
        stat_inc(VIGIL_STAT_PROCESS_BLOCK_HITS);
        return -1; // -EPERM
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Network connect via lsm/socket_connect
//
// Fires on connect(2) for INET / INET6 sockets. We grab:
//   - destination address+port from the sockaddr argument
//   - source port from sock->sk->skc_num (host order)
//   - source IP from skc_rcv_saddr / skc_v6_rcv_saddr — may still be
//     all-zero at this point because the kernel routes after the LSM
//     check. That's fine; userspace tolerates it.
//   - protocol from sk->sk_protocol
//
// We deliberately skip non-INET families (AF_UNIX, AF_NETLINK) as
// "connect" on those is not network traffic.
// ---------------------------------------------------------------------------

#define AF_INET   2
#define AF_INET6 10

SEC("lsm/socket_connect")
int BPF_PROG(handle_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    if (!sock || !address)
        return 0;

    __u16 fam = BPF_CORE_READ(address, sa_family);
    if (fam != AF_INET && fam != AF_INET6)
        return 0;

    struct vigil_event_network_connect *e =
        bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        stat_inc(VIGIL_STAT_EVENTS_DROPPED);
        return 0;
    }

    fill_header_common(&e->header, VIGIL_EVENT_KIND_NETWORK_CONNECT, sizeof(*e));
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        struct task_struct *parent = BPF_CORE_READ(task, real_parent);
        if (parent)
            e->header.ppid = BPF_CORE_READ(parent, tgid);
    }
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    e->family = (__u8)fam;
    e->_pad = 0;
    __builtin_memset(e->src_addr, 0, sizeof(e->src_addr));
    __builtin_memset(e->dst_addr, 0, sizeof(e->dst_addr));

    struct sock *sk = BPF_CORE_READ(sock, sk);
    e->protocol = sk ? BPF_CORE_READ(sk, sk_protocol) : 0;
    e->src_port = sk ? BPF_CORE_READ(sk, __sk_common.skc_num) : 0;

    if (fam == AF_INET) {
        struct sockaddr_in sin;
        bpf_probe_read_kernel(&sin, sizeof(sin), address);
        // sin_port is network order; convert to host order.
        e->dst_port = bpf_ntohs(sin.sin_port);
        __builtin_memcpy(e->dst_addr, &sin.sin_addr, 4);
        if (sk) {
            __be32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
            __builtin_memcpy(e->src_addr, &saddr, 4);
        }
    } else {  // AF_INET6
        struct sockaddr_in6 sin6;
        bpf_probe_read_kernel(&sin6, sizeof(sin6), address);
        e->dst_port = bpf_ntohs(sin6.sin6_port);
        __builtin_memcpy(e->dst_addr, &sin6.sin6_addr, 16);
        if (sk) {
            struct in6_addr s6 = BPF_CORE_READ(sk, __sk_common.skc_v6_rcv_saddr);
            __builtin_memcpy(e->src_addr, &s6, 16);
        }
    }

    stat_inc(VIGIL_STAT_NETWORK_CONNECT);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ---------------------------------------------------------------------------
// Kernel module load via tracepoint:module:module_load
//
// Format (verify on lab-linux:
// /sys/kernel/tracing/events/module/module_load/format):
//   field:unsigned int taints;        offset:8;  size:4;
//   field:__data_loc char[] name;     offset:12; size:4;
// __data_loc encodes (offset|length<<16) into the ctx.
// ---------------------------------------------------------------------------
SEC("tracepoint/module/module_load")
int handle_module_load(void *ctx)
{
    struct vigil_event_module_load *e =
        bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        stat_inc(VIGIL_STAT_EVENTS_DROPPED);
        return 0;
    }
    fill_header_common(&e->header, VIGIL_EVENT_KIND_MODULE_LOAD, sizeof(*e));
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        struct task_struct *parent = BPF_CORE_READ(task, real_parent);
        if (parent)
            e->header.ppid = BPF_CORE_READ(parent, tgid);
    }
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    e->name_len = 0;
    e->name[0] = 0;
    __u32 dl = 0;
    bpf_probe_read_kernel(&dl, sizeof(dl), (void *)ctx + 12);
    __u32 off = dl & 0xFFFF;
    __u32 len = (dl >> 16) & 0xFFFF;
    if (len > VIGIL_MODULE_NAME_MAX)
        len = VIGIL_MODULE_NAME_MAX;
    if (len > 0) {
        long n = bpf_probe_read_kernel_str(&e->name, len, (void *)ctx + off);
        if (n > 0)
            e->name_len = (__u32)n;
    }

    stat_inc(VIGIL_STAT_MODULE_LOAD);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
