// edr.h — shared types and constants between kernel driver and user-mode agent.

#pragma once

#define EDR_DRIVER_NAME      L"edr"
#define EDR_DRIVER_VERSION   L"0.1.0"

// Filter Manager altitude. PoC range; should be registered with Microsoft for
// production. 385100 sits in the FSFilter Activity Monitor range
// (380000-389999).
#define EDR_ALTITUDE         L"385100"

// Device names for the IPC channel.
#define EDR_DEVICE_NAME      L"\\Device\\edr"
#define EDR_SYMLINK_NAME     L"\\??\\edr"
#define EDR_USERMODE_PATH    L"\\\\.\\edr"

// IOCTL codes. Method-buffered (METHOD_BUFFERED = 0). FILE_ANY_ACCESS so an
// admin-only DACL on the device controls who can talk to us.
//
// Function code range 0x800-0xFFF is reserved for vendor use.
#define EDR_IOCTL_GET_STATS      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Drain up to OutputBufferLength bytes of events from the kernel ring into
// the caller-provided buffer. Returns IO bytes written. Buffer is a packed
// stream of EDR_EVENT_HEADER-prefixed records; walk it event-by-event using
// the Size field. If the ring is empty the IOCTL returns immediately with
// 0 bytes (M4.5 is polling; M4.5b will switch to inverted-IOCTL pending).
#define EDR_IOCTL_DRAIN_EVENTS   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Kill a process by PID. Input buffer is EDR_KILL_PROCESS_REQ. Returns
// STATUS_SUCCESS if the process is terminating; common failures are
// STATUS_INVALID_CID (no such pid) and STATUS_ACCESS_DENIED (protected
// process). The dispatch result reflects the kernel's view; the actual
// process exit completes asynchronously after the IOCTL returns.
#define EDR_IOCTL_KILL_PROCESS   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _EDR_KILL_PROCESS_REQ {
    UINT64 ProcessId;
} EDR_KILL_PROCESS_REQ, *PEDR_KILL_PROCESS_REQ;

// Block-list management. Two independent lists:
//   EDR_BLOCK_KIND_PROCESS — patterns matched against PsCreateNotifyInfo
//                            ImageFileName at process-create time. Match
//                            denies the create with STATUS_ACCESS_DENIED.
//   EDR_BLOCK_KIND_FILE    — patterns matched against the file name at
//                            IRP_MJ_CREATE pre-op. Match completes the IRP
//                            with STATUS_ACCESS_DENIED.
// Both are case-insensitive substring matches against the full path.
//
// Lists are persisted to HKLM\SYSTEM\CurrentControlSet\Services\edr
// \BlockList\{Process,File}Patterns (REG_MULTI_SZ) and reloaded on
// DriverEntry, so blocks survive driver reload.
#define EDR_BLOCK_KIND_PROCESS  1
#define EDR_BLOCK_KIND_FILE     2

#define EDR_IOCTL_BLOCK_ADD    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define EDR_IOCTL_BLOCK_REMOVE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define EDR_IOCTL_BLOCK_CLEAR  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

// M7.2 self-protection: agent registers its own pid so the driver's
// ObRegisterCallbacks pre-op handler can strip dangerous access bits
// (PROCESS_TERMINATE, PROCESS_VM_*, PROCESS_CREATE_THREAD,
// PROCESS_SUSPEND_RESUME) from any handle to the agent opened by a
// non-self user-mode caller. PID == 0 means "no protected process",
// which the driver also enters automatically when the protected pid
// exits (via PsCreateProcessNotifyRoutineEx).
#define EDR_IOCTL_REGISTER_PROTECTED_PID \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 4)
typedef struct _EDR_REGISTER_PID_REQ {
    UINT64 ProcessId;       // the agent's GetCurrentProcessId(); 0 to clear
} EDR_REGISTER_PID_REQ, *PEDR_REGISTER_PID_REQ;
#pragma pack(pop)

#pragma pack(push, 4)
typedef struct _EDR_BLOCK_REQ {
    UINT32 Kind;            // EDR_BLOCK_KIND_*
    UINT32 PatternBytes;    // length of pattern in bytes (UTF-16; max 512)
    // followed by PatternBytes of UTF-16 (no null terminator required)
} EDR_BLOCK_REQ, *PEDR_BLOCK_REQ;

typedef struct _EDR_BLOCK_CLEAR_REQ {
    UINT32 Kind;            // EDR_BLOCK_KIND_*; 0 means clear both lists
} EDR_BLOCK_CLEAR_REQ, *PEDR_BLOCK_CLEAR_REQ;
#pragma pack(pop)

// Output buffer for IOCTL_EDR_GET_STATS. Counters monotonically increase
// from driver load and are reset on driver unload/reload.
typedef struct _EDR_STATS {
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
    UINT64 KillRequests;                // IOCTL_EDR_KILL_PROCESS calls received
    UINT64 KillSuccesses;                // ZwTerminateProcess returned NT_SUCCESS
    UINT64 ProcessBlockHits;            // process-create denied by block list
    UINT64 FileBlockHits;               // file-open denied by block list
    UINT32 ProcessBlockEntries;         // current size of process block list
    UINT32 FileBlockEntries;            // current size of file block list
    UINT64 SelfProtectHandleStripped;   // M7.2: ObCallback hits — handle access stripped
    UINT64 SelfProtectThreadStripped;   // M7.2: thread-handle ObCallback hits
    UINT64 ProtectedPid;                // M7.2: currently protected pid; 0 = none
} EDR_STATS, *PEDR_STATS;

// EDR_EVENT_KIND_* values for EDR_EVENT_HEADER.Kind. Numeric, stable across
// driver versions — agent-windows depends on these tags. Reserve 0 as
// "invalid" so a zeroed buffer can't be misinterpreted as a real event.
// Prefix is _KIND_ to avoid colliding with the EDR_EVENT_PROCESS_START
// typedef below (the preprocessor would expand the macro mid-typedef).
#define EDR_EVENT_KIND_PROCESS_START      1
#define EDR_EVENT_KIND_PROCESS_EXIT       2
#define EDR_EVENT_KIND_IMAGE_LOAD         3
#define EDR_EVENT_KIND_FILE_CREATE        4
#define EDR_EVENT_KIND_REG_CREATE_KEY     5
#define EDR_EVENT_KIND_REG_SET_VALUE      6
#define EDR_EVENT_KIND_REG_DELETE_KEY     7
#define EDR_EVENT_KIND_REG_DELETE_VAL     8
#define EDR_EVENT_KIND_NETWORK_CONNECT    9   // outbound TCP/UDP, ALE_AUTH_CONNECT

// Common header. Every event in the IOCTL_DRAIN_EVENTS stream starts with
// this struct. Walk the stream by reading Size and advancing.
#pragma pack(push, 4)
typedef struct _EDR_EVENT_HEADER {
    UINT32 Size;                // total bytes including header + payload
    UINT32 Kind;                // EDR_EVENT_*
    UINT64 TimestampNs;         // KeQuerySystemTimePrecise — Windows NT epoch (1601), 100ns units
    UINT64 ProcessId;           // pid the event is "about" (subject)
} EDR_EVENT_HEADER, *PEDR_EVENT_HEADER;

// Process create. Followed by ImageNameLen bytes (UTF-16) and then
// CommandLineLen bytes (UTF-16). Both are byte counts, not char counts.
typedef struct _EDR_EVENT_PROCESS_START {
    EDR_EVENT_HEADER Header;
    UINT64 ParentProcessId;
    UINT16 ImageNameLen;        // bytes; 0 if absent
    UINT16 CommandLineLen;      // bytes; 0 if absent
    // followed by ImageName (UTF-16) + CommandLine (UTF-16)
} EDR_EVENT_PROCESS_START, *PEDR_EVENT_PROCESS_START;

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
typedef struct _EDR_EVENT_NETWORK_CONNECT {
    EDR_EVENT_HEADER Header;
    UINT8  IpVersion;           // 4 or 6
    UINT8  Protocol;            // IPPROTO_TCP=6, IPPROTO_UDP=17
    UINT16 LocalPort;           // network byte order
    UINT16 RemotePort;          // network byte order
    UINT16 _Reserved;
    UINT8  LocalAddr[16];
    UINT8  RemoteAddr[16];
} EDR_EVENT_NETWORK_CONNECT, *PEDR_EVENT_NETWORK_CONNECT;
#pragma pack(pop)
