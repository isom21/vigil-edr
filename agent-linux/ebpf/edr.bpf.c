// edr.bpf.c — kernel-side eBPF programs for the EDR Linux agent (M6).
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

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

// ---------------------------------------------------------------------------
// Stats array
// ---------------------------------------------------------------------------

enum edr_stat {
    EDR_STAT_PROCESS_EXEC = 0,
    EDR_STAT_PROCESS_EXIT,
    EDR_STAT_FILE_OPEN,
    EDR_STAT_NETWORK_CONNECT,
    EDR_STAT_MODULE_LOAD,
    EDR_STAT_PROCESS_BLOCK_HITS,
    EDR_STAT_FILE_BLOCK_HITS,
    EDR_STAT_NETWORK_BLOCK_HITS,
    EDR_STAT_KILL_REQUESTS,
    EDR_STAT_EVENTS_DROPPED,
    EDR_STAT_MAX,
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, EDR_STAT_MAX);
} stats SEC(".maps");

static __always_inline void stat_inc(enum edr_stat which)
{
    __u32 key = (__u32)which;
    __u64 *v = bpf_map_lookup_elem(&stats, &key);
    if (v)
        __sync_fetch_and_add(v, 1);
}

// ---------------------------------------------------------------------------
// Event ring + wire format
// ---------------------------------------------------------------------------

#define EDR_EVENT_KIND_PROCESS_START   1
#define EDR_EVENT_KIND_PROCESS_EXIT    2
#define EDR_EVENT_KIND_FILE_OPEN       3
#define EDR_EVENT_KIND_NETWORK_CONNECT 4
#define EDR_EVENT_KIND_MODULE_LOAD     5
// 6..8 reserved to mirror Windows numbering.

#define EDR_COMM_LEN 16
#define EDR_PATH_MAX 384   // executable path; truncated if longer

struct edr_event_header {
    __u32 size;            // total bytes including header + payload
    __u32 kind;            // EDR_EVENT_KIND_*
    __u64 timestamp_ns;    // bpf_ktime_get_boot_ns()
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
};

struct edr_event_process_start {
    struct edr_event_header header;
    char comm[EDR_COMM_LEN];   // task->comm (basename, up to 15 chars)
    __u32 path_len;            // bytes of `path` in use; 0 if absent
    char path[EDR_PATH_MAX];   // full executable path via bpf_d_path
};

struct edr_event_process_exit {
    struct edr_event_header header;
    char comm[EDR_COMM_LEN];
    __s32 exit_code;
};

struct edr_event_file_open {
    struct edr_event_header header;
    char comm[EDR_COMM_LEN];
    __u32 open_flags;          // f_flags from struct file
    __u32 path_len;
    char path[EDR_PATH_MAX];
};

struct edr_event_network_connect {
    struct edr_event_header header;
    char comm[EDR_COMM_LEN];
    __u8  family;              // AF_INET or AF_INET6
    __u8  protocol;             // IPPROTO_TCP / IPPROTO_UDP / etc.
    __u16 src_port;             // host byte order, may be 0 pre-connect
    __u16 dst_port;             // host byte order
    __u16 _pad;
    __u8  src_addr[16];         // ipv4 in [0..4], rest 0; ipv6 fills 16
    __u8  dst_addr[16];
};

#define EDR_MODULE_NAME_MAX 64

struct edr_event_module_load {
    struct edr_event_header header;
    char comm[EDR_COMM_LEN];     // task that triggered load (modprobe, insmod, …)
    __u32 name_len;              // bytes used in `name`
    char  name[EDR_MODULE_NAME_MAX];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline void fill_header_common(struct edr_event_header *h, __u32 kind, __u32 size)
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
    stat_inc(EDR_STAT_PROCESS_EXEC);

    struct edr_event_process_start *e =
        bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        stat_inc(EDR_STAT_EVENTS_DROPPED);
        return 0;
    }
    fill_header_common(&e->header, EDR_EVENT_KIND_PROCESS_START, sizeof(*e));

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
    if (len > EDR_PATH_MAX) {
        len = EDR_PATH_MAX;
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

    stat_inc(EDR_STAT_PROCESS_EXIT);

    struct edr_event_process_exit *e =
        bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        stat_inc(EDR_STAT_EVENTS_DROPPED);
        return 0;
    }
    fill_header_common(&e->header, EDR_EVENT_KIND_PROCESS_EXIT, sizeof(*e));

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

    struct edr_event_file_open *e =
        bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        stat_inc(EDR_STAT_EVENTS_DROPPED);
        return 0;
    }

    fill_header_common(&e->header, EDR_EVENT_KIND_FILE_OPEN, sizeof(*e));

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

    stat_inc(EDR_STAT_FILE_OPEN);
    bpf_ringbuf_submit(e, 0);
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

    struct edr_event_network_connect *e =
        bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        stat_inc(EDR_STAT_EVENTS_DROPPED);
        return 0;
    }

    fill_header_common(&e->header, EDR_EVENT_KIND_NETWORK_CONNECT, sizeof(*e));
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

    stat_inc(EDR_STAT_NETWORK_CONNECT);
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
    struct edr_event_module_load *e =
        bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        stat_inc(EDR_STAT_EVENTS_DROPPED);
        return 0;
    }
    fill_header_common(&e->header, EDR_EVENT_KIND_MODULE_LOAD, sizeof(*e));
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
    if (len > EDR_MODULE_NAME_MAX)
        len = EDR_MODULE_NAME_MAX;
    if (len > 0) {
        long n = bpf_probe_read_kernel_str(&e->name, len, (void *)ctx + off);
        if (n > 0)
            e->name_len = (__u32)n;
    }

    stat_inc(EDR_STAT_MODULE_LOAD);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
