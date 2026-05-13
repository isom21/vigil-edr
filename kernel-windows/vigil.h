// edr.h — shared types and constants between kernel driver and user-mode agent.

#pragma once

#define VIGIL_DRIVER_NAME      L"edr"
#define VIGIL_DRIVER_VERSION   L"0.1.0"

// Filter Manager altitude. PoC range; should be registered with Microsoft for
// production. 385100 sits in the FSFilter Activity Monitor range
// (380000-389999).
#define VIGIL_ALTITUDE         L"385100"

// Device names for the IPC channel.
#define VIGIL_DEVICE_NAME      L"\\Device\\edr"
#define VIGIL_SYMLINK_NAME     L"\\??\\edr"
#define VIGIL_USERMODE_PATH    L"\\\\.\\Vigil"

// IOCTL codes. Method-buffered (METHOD_BUFFERED = 0). FILE_ANY_ACCESS so an
// admin-only DACL on the device controls who can talk to us.
//
// Function code range 0x800-0xFFF is reserved for vendor use.
#define VIGIL_IOCTL_GET_STATS      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Drain up to OutputBufferLength bytes of events from the kernel ring into
// the caller-provided buffer. Returns IO bytes written. Buffer is a packed
// stream of VIGIL_EVENT_HEADER-prefixed records; walk it event-by-event using
// the Size field. If the ring is empty the IOCTL returns immediately with
// 0 bytes (M4.5 is polling; M4.5b will switch to inverted-IOCTL pending).
#define VIGIL_IOCTL_DRAIN_EVENTS   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Kill a process by PID. Input buffer is VIGIL_KILL_PROCESS_REQ. Returns
// STATUS_SUCCESS if the process is terminating; common failures are
// STATUS_INVALID_CID (no such pid) and STATUS_ACCESS_DENIED (protected
// process). The dispatch result reflects the kernel's view; the actual
// process exit completes asynchronously after the IOCTL returns.
#define VIGIL_IOCTL_KILL_PROCESS   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _VIGIL_KILL_PROCESS_REQ {
    UINT64 ProcessId;
} VIGIL_KILL_PROCESS_REQ, *PVIGIL_KILL_PROCESS_REQ;

// Block-list management. Two independent lists:
//   VIGIL_BLOCK_KIND_PROCESS — patterns matched against PsCreateNotifyInfo
//                            ImageFileName at process-create time. Match
//                            denies the create with STATUS_ACCESS_DENIED.
//   VIGIL_BLOCK_KIND_FILE    — patterns matched against the file name at
//                            IRP_MJ_CREATE pre-op. Match completes the IRP
//                            with STATUS_ACCESS_DENIED.
// Both are case-insensitive substring matches against the full path.
//
// Lists are persisted to HKLM\SYSTEM\CurrentControlSet\Services\edr
// \BlockList\{Process,File}Patterns (REG_MULTI_SZ) and reloaded on
// DriverEntry, so blocks survive driver reload.
#define VIGIL_BLOCK_KIND_PROCESS  1
#define VIGIL_BLOCK_KIND_FILE     2

#define VIGIL_IOCTL_BLOCK_ADD    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VIGIL_IOCTL_BLOCK_REMOVE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VIGIL_IOCTL_BLOCK_CLEAR  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

// M7.2 self-protection: agent registers its own pid so the driver's
// ObRegisterCallbacks pre-op handler can strip dangerous access bits
// (PROCESS_TERMINATE, PROCESS_VM_*, PROCESS_CREATE_THREAD,
// PROCESS_SUSPEND_RESUME) from any handle to the agent opened by a
// non-self user-mode caller. PID == 0 means "no protected process",
// which the driver also enters automatically when the protected pid
// exits (via PsCreateProcessNotifyRoutineEx).
#define VIGIL_IOCTL_REGISTER_PROTECTED_PID \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 4)
typedef struct _VIGIL_REGISTER_PID_REQ {
    UINT64 ProcessId;       // the agent's GetCurrentProcessId(); 0 to clear
} VIGIL_REGISTER_PID_REQ, *PVIGIL_REGISTER_PID_REQ;
#pragma pack(pop)

// Phase 1 #1.3 network isolation. When Isolate=1 the WFP ALE callouts
// (V4 + V6) flip from inspection-only to block-on-no-match: every
// outbound connect whose destination IP isn't in the supplied
// allowlist is BLOCK_RESET'd. Isolate=0 restores observation-only.
//
// Allowlist layout: IpCount × 16 bytes of IPv6 addresses, immediately
// after the header. IPv4 entries are stored as v4-mapped IPv6
// (`::ffff:a.b.c.d`) so the V4 and V6 classifiers share one allowlist
// shape. Max IpCount is bounded by the driver-side static buffer
// (`g_AllowedIps`), currently 256.
#define VIGIL_IOCTL_NETWORK_ISOLATE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define VIGIL_NETWORK_ISOLATE_MAX_IPS 256

#pragma pack(push, 4)
typedef struct _VIGIL_NETWORK_ISOLATE_REQ {
    UINT8  Isolate;            // 1 = isolate, 0 = restore
    UINT8  _Pad[3];
    UINT32 IpCount;            // count of 16-byte addresses that follow
    // followed by IpCount × 16-byte IPv6 addresses (IPv4 mapped)
} VIGIL_NETWORK_ISOLATE_REQ, *PVIGIL_NETWORK_ISOLATE_REQ;
#pragma pack(pop)

// Phase 2 #2.8 — application allowlist (learn → enforce).
//
// VIGIL_IOCTL_ALLOWLIST_SET replaces the kernel hash set with the
// supplied SHA-256 list. Input buffer is `VIGIL_ALLOWLIST_SET_REQ`
// followed by HashCount × 32 bytes. Driver clears the existing set
// before inserting the new entries (atomic swap under
// g_AllowlistLock).
//
// VIGIL_IOCTL_ALLOWLIST_MODE_SET flips the agent mode:
//   0 = off      — no enforcement, no learn shipping
//   1 = learn    — process-create notify ships the SHA-256 upstream
//                  but never denies
//   2 = enforce  — process-create notify checks against the set and
//                  denies on miss (STATUS_ACCESS_DENIED)
//
// Mode + set are split into two IOCTLs (rather than one combined
// request) so the userspace caller can flip mode without re-shipping
// the entire hash set — the operator flow toggling between learn and
// enforce only needs the mode IOCTL.
#define VIGIL_IOCTL_ALLOWLIST_SET \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VIGIL_IOCTL_ALLOWLIST_MODE_SET \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define VIGIL_ALLOWLIST_MAX_HASHES 8192

#define VIGIL_ALLOWLIST_MODE_OFF      0
#define VIGIL_ALLOWLIST_MODE_LEARN    1
#define VIGIL_ALLOWLIST_MODE_ENFORCE  2

#pragma pack(push, 4)
typedef struct _VIGIL_ALLOWLIST_SET_REQ {
    UINT32 HashCount;        // count of 32-byte SHA-256s that follow
    // followed by HashCount × 32-byte raw SHA-256 digests
} VIGIL_ALLOWLIST_SET_REQ, *PVIGIL_ALLOWLIST_SET_REQ;

typedef struct _VIGIL_ALLOWLIST_MODE_REQ {
    UINT8  Mode;             // VIGIL_ALLOWLIST_MODE_*
    UINT8  _Pad[3];
} VIGIL_ALLOWLIST_MODE_REQ, *PVIGIL_ALLOWLIST_MODE_REQ;
#pragma pack(pop)

#pragma pack(push, 4)
typedef struct _VIGIL_BLOCK_REQ {
    UINT32 Kind;            // VIGIL_BLOCK_KIND_*
    UINT32 PatternBytes;    // length of pattern in bytes (UTF-16; max 512)
    // followed by PatternBytes of UTF-16 (no null terminator required)
} VIGIL_BLOCK_REQ, *PVIGIL_BLOCK_REQ;

typedef struct _VIGIL_BLOCK_CLEAR_REQ {
    UINT32 Kind;            // VIGIL_BLOCK_KIND_*; 0 means clear both lists
} VIGIL_BLOCK_CLEAR_REQ, *PVIGIL_BLOCK_CLEAR_REQ;
#pragma pack(pop)

// Output buffer for IOCTL_VIGIL_GET_STATS. Counters monotonically increase
// from driver load and are reset on driver unload/reload.
typedef struct _VIGIL_STATS {
    UINT64 ProcessCreateCount;
    UINT64 ProcessExitCount;
    UINT64 ImageLoadCount;
    UINT64 ImageLoadKernelCount;
    UINT64 FileCreateCount;             // any IRP_MJ_CREATE the minifilter sees
    UINT64 FileCreateSucceededCount;    // post-op observed STATUS_SUCCESS
    UINT64 RegCreateKeyCount;           // RegNtPreCreateKeyEx
    UINT64 RegSetValueCount;            // RegNtPreSetValueKey
    UINT64 RegDeleteValueCount;         // RegNtPreDeleteValueKey
    UINT64 RegDeleteKeyCount;           // RegNtPreDeleteKey
    UINT64 RegOtherCount;               // every other REG_NOTIFY_CLASS
    UINT64 EventsEnqueued;              // events placed into the ring buffer
    UINT64 EventsDropped;               // ring full at enqueue time
    UINT64 EventsDrained;               // events delivered via IOCTL_DRAIN
    UINT64 NetConnectCount;             // FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6 hits
    UINT64 KillRequests;                // IOCTL_VIGIL_KILL_PROCESS calls received
    UINT64 KillSuccesses;                // ZwTerminateProcess returned NT_SUCCESS
    UINT64 ProcessBlockHits;            // process-create denied by block list
    UINT64 FileBlockHits;               // file-open denied by block list
    UINT32 ProcessBlockEntries;         // current size of process block list
    UINT32 FileBlockEntries;            // current size of file block list
    UINT64 SelfProtectHandleStripped;   // M7.2: ObCallback hits — handle access stripped
    UINT64 SelfProtectThreadStripped;   // M7.2: thread-handle ObCallback hits
    UINT64 ProtectedPid;                // M7.2: currently protected pid; 0 = none
    UINT64 NetworkIsolationBlockHits;   // Phase 1 #1.3: connect BLOCK_RESET'd by WFP while isolated
    UINT32 NetworkIsolated;             // Phase 1 #1.3: 1 = isolation active, 0 = inactive
    UINT32 NetworkAllowedIpCount;       // Phase 1 #1.3: current allowlist size
} VIGIL_STATS, *PVIGIL_STATS;

// VIGIL_EVENT_KIND_* values for VIGIL_EVENT_HEADER.Kind. Numeric, stable across
// driver versions — agent-windows depends on these tags. Reserve 0 as
// "invalid" so a zeroed buffer can't be misinterpreted as a real event.
// Prefix is _KIND_ to avoid colliding with the VIGIL_EVENT_PROCESS_START
// typedef below (the preprocessor would expand the macro mid-typedef).
#define VIGIL_EVENT_KIND_PROCESS_START      1
#define VIGIL_EVENT_KIND_PROCESS_EXIT       2
#define VIGIL_EVENT_KIND_IMAGE_LOAD         3
#define VIGIL_EVENT_KIND_FILE_CREATE        4
#define VIGIL_EVENT_KIND_REG_CREATE_KEY     5
#define VIGIL_EVENT_KIND_REG_SET_VALUE      6
#define VIGIL_EVENT_KIND_REG_DELETE_KEY     7
#define VIGIL_EVENT_KIND_REG_DELETE_VAL     8
#define VIGIL_EVENT_KIND_NETWORK_CONNECT    9   // outbound TCP/UDP, ALE_AUTH_CONNECT

// Common header. Every event in the IOCTL_DRAIN_EVENTS stream starts with
// this struct. Walk the stream by reading Size and advancing.
#pragma pack(push, 4)
typedef struct _VIGIL_EVENT_HEADER {
    UINT32 Size;                // total bytes including header + payload
    UINT32 Kind;                // VIGIL_EVENT_*
    UINT64 TimestampNs;         // KeQuerySystemTimePrecise — Windows NT epoch (1601), 100ns units
    UINT64 ProcessId;           // pid the event is "about" (subject)
} VIGIL_EVENT_HEADER, *PVIGIL_EVENT_HEADER;

// Process create. Followed by ImageNameLen bytes (UTF-16) and then
// CommandLineLen bytes (UTF-16). Both are byte counts, not char counts.
typedef struct _VIGIL_EVENT_PROCESS_START {
    VIGIL_EVENT_HEADER Header;
    UINT64 ParentProcessId;
    UINT16 ImageNameLen;        // bytes; 0 if absent
    UINT16 CommandLineLen;      // bytes; 0 if absent
    // followed by ImageName (UTF-16) + CommandLine (UTF-16)
} VIGIL_EVENT_PROCESS_START, *PVIGIL_EVENT_PROCESS_START;

// Outbound network connect. Captured at FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6
// before TLS encryption is layered on (TLS happens in user-mode SChannel
// above this), so 5-tuple metadata is reliable. The bytes themselves
// passing through here are still pre-TCP-stack — for plaintext-after-TLS
// you need the STREAM layer; for plaintext-before-TLS you need user-mode
// SChannel hooks (out of scope for the kernel driver).
//
// LocalAddr/RemoteAddr are 16 bytes for IPv6; the IPv4 case stores the 4
// address bytes in the first 4 of the 16 with the rest zeroed. Ports and
// addresses are network byte order (big-endian) as WFP delivers them.
typedef struct _VIGIL_EVENT_NETWORK_CONNECT {
    VIGIL_EVENT_HEADER Header;
    UINT8  IpVersion;           // 4 or 6
    UINT8  Protocol;            // IPPROTO_TCP=6, IPPROTO_UDP=17
    UINT16 LocalPort;           // network byte order
    UINT16 RemotePort;          // network byte order
    UINT16 _Reserved;
    UINT8  LocalAddr[16];
    UINT8  RemoteAddr[16];
} VIGIL_EVENT_NETWORK_CONNECT, *PVIGIL_EVENT_NETWORK_CONNECT;
#pragma pack(pop)
