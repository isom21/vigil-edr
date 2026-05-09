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
#define EDR_IOCTL_GET_STATS  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

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
} EDR_STATS, *PEDR_STATS;
