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
} EDR_STATS, *PEDR_STATS;

// EDR_EVENT_KIND_* values for EDR_EVENT_HEADER.Kind. Numeric, stable across
// driver versions — agent-windows depends on these tags. Reserve 0 as
// "invalid" so a zeroed buffer can't be misinterpreted as a real event.
// Prefix is _KIND_ to avoid colliding with the EDR_EVENT_PROCESS_START
// typedef below (the preprocessor would expand the macro mid-typedef).
#define EDR_EVENT_KIND_PROCESS_START   1
#define EDR_EVENT_KIND_PROCESS_EXIT    2
#define EDR_EVENT_KIND_IMAGE_LOAD      3
#define EDR_EVENT_KIND_FILE_CREATE     4
#define EDR_EVENT_KIND_REG_CREATE_KEY  5
#define EDR_EVENT_KIND_REG_SET_VALUE   6
#define EDR_EVENT_KIND_REG_DELETE_KEY  7
#define EDR_EVENT_KIND_REG_DELETE_VAL  8

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
#pragma pack(pop)
