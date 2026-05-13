// edr.c — M4.2: minifilter skeleton + process create + image load callbacks
// + control device with IOCTL_VIGIL_GET_STATS so user-mode can verify the
// callbacks are actually firing.
//
// What's here vs. what's coming:
//   M4.1 (done): minifilter registers and attaches at altitude 385100.
//   M4.2 (this): Ps* notify callbacks for process create + image load. Counters
//                exposed via a single IOCTL on \Device\edr.
//   M4.3 (next): IRP_MJ_CREATE pre/post-op replaces the current stub.
//   M4.4: registry callbacks via CmRegisterCallbackEx.
//   M4.5: inverted IOCTL channel for streaming events to the agent.

#include <fltKernel.h>
#include <ntddk.h>
#include <wdmsec.h>   // IoCreateDeviceSecure, SDDL_DEVOBJ_*

// WFP. fwpsk.h needs NDIS_SUPPORT_NDIS6=1 set before it sees the NDIS
// types (otherwise NET_BUFFER_LIST and friends are missing the IF_INDEX
// fields that fwpsk.h's structs reference, and you get a cascade of C2146
// "missing ;" errors deep in fwpsk.h). fwpsk.h before fwpmk.h.
#define NDIS_SUPPORT_NDIS6 1
#include <fwpsk.h>
#include <fwpmk.h>

#include "vigil.h"

DRIVER_INITIALIZE DriverEntry;

static FLT_PREOP_CALLBACK_STATUS VigilPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);
static FLT_POSTOP_CALLBACK_STATUS VigilPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

static NTSTATUS VigilFilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);
static NTSTATUS VigilInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);
static NTSTATUS VigilInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);
static VOID VigilInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);
static VOID VigilInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);

static VOID VigilCreateProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);
static VOID VigilLoadImageNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo);
static NTSTATUS VigilRegistryCallback(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2);

// Block-list helpers — defined further down (after the WFP block) but called
// from VigilCreateProcessNotify and VigilPreCreate which appear earlier.
static BOOLEAN VigilBlockMatch(_In_ LIST_ENTRY *list, _In_opt_ PCUNICODE_STRING name);
static NTSTATUS VigilBlockAdd(_In_ UINT32 kind, _In_reads_bytes_(patternBytes) const WCHAR *pattern, _In_ USHORT patternBytes);
static NTSTATUS VigilBlockRemove(_In_ UINT32 kind, _In_reads_bytes_(patternBytes) const WCHAR *pattern, _In_ USHORT patternBytes);
static NTSTATUS VigilBlockClear(_In_ UINT32 kind);
static NTSTATUS VigilBlockLoadFromReg(_In_ UINT32 kind);

static NTSTATUS VigilWfpInit(_In_ PDRIVER_OBJECT DriverObject);
static VOID VigilWfpCleanup(VOID);
static VOID VigilWfpClassifyV4(
    _In_ const FWPS_INCOMING_VALUES0 *inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues,
    _Inout_opt_ void *layerData,
    _In_opt_ const void *classifyContext,
    _In_ const FWPS_FILTER1 *filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0 *classifyOut);
static VOID VigilWfpClassifyV6(
    _In_ const FWPS_INCOMING_VALUES0 *inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues,
    _Inout_opt_ void *layerData,
    _In_opt_ const void *classifyContext,
    _In_ const FWPS_FILTER1 *filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0 *classifyOut);
static NTSTATUS VigilWfpNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID *filterKey,
    _Inout_ FWPS_FILTER1 *filter);

static NTSTATUS VigilDispatchCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
static NTSTATUS VigilDispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);

// M7.2 self-protection prototypes.
static OB_PREOP_CALLBACK_STATUS VigilPreOpProcess(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation);
static OB_PREOP_CALLBACK_STATUS VigilPreOpThread(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation);
static NTSTATUS VigilSelfProtectInit(VOID);
static VOID     VigilSelfProtectCleanup(VOID);

// Phase 1 #1.3 network isolation prototypes.
static NTSTATUS VigilNetworkIsolateSet(
    _In_reads_bytes_(inBytes) PVOID buffer,
    _In_ ULONG inBytes);

static PFLT_FILTER     g_FilterHandle  = NULL;
static PDEVICE_OBJECT  g_DeviceObject  = NULL;
static UNICODE_STRING  g_DeviceName    = RTL_CONSTANT_STRING(VIGIL_DEVICE_NAME);
static UNICODE_STRING  g_SymLinkName   = RTL_CONSTANT_STRING(VIGIL_SYMLINK_NAME);

// Counters — written from any IRQL <= DISPATCH_LEVEL. We use Interlocked ops
// to keep them coherent across CPUs without taking a lock.
static volatile LONG64 g_ProcessCreateCount         = 0;
static volatile LONG64 g_ProcessExitCount           = 0;
static volatile LONG64 g_ImageLoadCount             = 0;
static volatile LONG64 g_ImageLoadKernelCount       = 0;
static volatile LONG64 g_FileCreateCount            = 0;
static volatile LONG64 g_FileCreateSucceededCount   = 0;
static volatile LONG64 g_RegCreateKeyCount          = 0;
static volatile LONG64 g_RegSetValueCount           = 0;
static volatile LONG64 g_RegDeleteValueCount        = 0;
static volatile LONG64 g_RegDeleteKeyCount          = 0;
static volatile LONG64 g_RegOtherCount              = 0;
static volatile LONG64 g_EventsEnqueued             = 0;
static volatile LONG64 g_EventsDropped              = 0;
static volatile LONG64 g_EventsDrained              = 0;
static volatile LONG64 g_NetConnectCount            = 0;
static volatile LONG64 g_KillRequests               = 0;
static volatile LONG64 g_KillSuccesses              = 0;
static volatile LONG64 g_ProcessBlockHits           = 0;
static volatile LONG64 g_FileBlockHits              = 0;
// M7.2 self-protection counters and state.
static volatile LONG64 g_SelfProtectHandleStripped  = 0;
static volatile LONG64 g_SelfProtectThreadStripped  = 0;
// Currently-protected pid (the agent's). 0 means "no protected process";
// the ObCallback handlers fast-path out without touching a single
// caller's access mask. Read/written atomically with InterlockedExchange64.
static volatile LONG64 g_ProtectedPid               = 0;
// ObCallbacks registration cookie. NULL means callbacks not registered;
// any non-NULL value must be passed to ObUnRegisterCallbacks on cleanup.
static PVOID g_ObRegistrationHandle = NULL;

// Phase 1 #1.3 network isolation state. When `g_NetworkIsolated` is
// non-zero the WFP ALE classifiers (V4 + V6) check the destination
// against `g_AllowedIps`; a miss BLOCK_RESETs the connect. The 256-IP
// limit matches a typical EDR allowlist size (manager + redundant
// management plane + a few canary endpoints). Linear scan is cheap at
// the connect-rate of a normal host (~hundreds/sec under load); a hash
// table would buy negligible latency at meaningful complexity cost.
//
// Lock model: `g_NetworkIsolateLock` is a KSPIN_LOCK guarding writes
// to all three fields. The WFP classifiers (which can fire at
// DISPATCH_LEVEL) read with the lock; the IOCTL writer takes it for
// the full replace. Reads on a fast path (Isolate == 0) elide the
// lock via InterlockedCompareExchange.
typedef struct _VIGIL_IPV6_ADDR {
    UINT8 Bytes[16];
} VIGIL_IPV6_ADDR;

static volatile LONG    g_NetworkIsolated          = 0;
static VIGIL_IPV6_ADDR  g_AllowedIps[VIGIL_NETWORK_ISOLATE_MAX_IPS];
static UINT32           g_AllowedIpCount           = 0;
static KSPIN_LOCK       g_NetworkIsolateLock;
static volatile LONG64  g_NetworkIsolationBlockHits = 0;

// Block-list state. Two singly-linked lists protected by a single spinlock.
// Match cost is O(N * M) per check (N = list size, M = path length); list
// sizes are expected to be tens, not thousands. Pattern matching is
// case-insensitive substring match.
typedef struct _VIGIL_BLOCK_ENTRY {
    LIST_ENTRY List;
    USHORT Length;          // bytes (UTF-16)
    WCHAR Buffer[1];        // pattern; allocated as [Length / 2] WCHARs
} VIGIL_BLOCK_ENTRY, *PVIGIL_BLOCK_ENTRY;

static LIST_ENTRY g_ProcessBlockList;
static LIST_ENTRY g_FileBlockList;
static volatile LONG g_ProcessBlockCount = 0;
static volatile LONG g_FileBlockCount    = 0;
static KSPIN_LOCK g_BlockListLock;

// RegistryPath copy from DriverEntry, used to locate our service key for
// block-list persistence (e.g. "...\Services\edr"; we open
// "...\Services\edr\BlockList" under it).
static UNICODE_STRING g_RegistryPath = { 0 };
static PWCHAR g_RegistryPathBuf = NULL;

// Event ring buffer. Producers are kernel callbacks (IRQL <= APC_LEVEL),
// consumer is the IOCTL_VIGIL_DRAIN_EVENTS handler at PASSIVE_LEVEL — KSPIN_LOCK
// works at any IRQL, simplifying lifecycle vs. FAST_MUTEX. Size is generous
// for 1MB so a 1-2 second user-mode poll cadence covers normal loads.
#define VIGIL_RING_SIZE  (1u * 1024u * 1024u)
#define VIGIL_TAG        'rdEr'   // 'rEdr' little-endian — visible in pool tracing

static PUCHAR    g_RingBuf  = NULL;
static UINT32    g_RingHead = 0;   // next read offset
static UINT32    g_RingTail = 0;   // next write offset
static UINT32    g_RingUsed = 0;   // bytes currently in ring
static KSPIN_LOCK g_RingLock;

// Track which subsystems registered successfully so unload only undoes work
// it actually did. Without this a partial DriverEntry failure leads to
// double-unregister or unload-without-register.
static BOOLEAN g_PsNotifyCreateRegistered = FALSE;
static BOOLEAN g_PsNotifyImageRegistered  = FALSE;
static BOOLEAN g_SymLinkCreated           = FALSE;
static BOOLEAN g_RegCallbackRegistered    = FALSE;
static LARGE_INTEGER g_RegCookie          = { 0 };

// WFP state. Each field is set as the corresponding init step succeeds; the
// cleanup helper undoes only the steps that actually completed.
static HANDLE  g_WfpEngine        = NULL;
static UINT32  g_WfpCalloutIdV4   = 0;
static UINT32  g_WfpCalloutIdV6   = 0;
static UINT64  g_WfpFilterIdV4    = 0;
static UINT64  g_WfpFilterIdV6    = 0;
static BOOLEAN g_WfpSubLayerAdded = FALSE;
static BOOLEAN g_WfpFwpmCalloutV4Added = FALSE;
static BOOLEAN g_WfpFwpmCalloutV6Added = FALSE;
static BOOLEAN g_WfpInTransaction = FALSE;

// Generated GUIDs — must be unique per driver. Regenerate if forking.
//   sublayer:  {3a0b6d1f-4e2c-4f6a-9d11-37e0c4a5f001}
//   callout4:  {3a0b6d1f-4e2c-4f6a-9d11-37e0c4a5f002}
//   callout6:  {3a0b6d1f-4e2c-4f6a-9d11-37e0c4a5f003}
DEFINE_GUID(VIGIL_WFP_SUBLAYER_GUID,
    0x3a0b6d1f, 0x4e2c, 0x4f6a,
    0x9d, 0x11, 0x37, 0xe0, 0xc4, 0xa5, 0xf0, 0x01);
DEFINE_GUID(VIGIL_WFP_CALLOUT_V4_GUID,
    0x3a0b6d1f, 0x4e2c, 0x4f6a,
    0x9d, 0x11, 0x37, 0xe0, 0xc4, 0xa5, 0xf0, 0x02);
DEFINE_GUID(VIGIL_WFP_CALLOUT_V6_GUID,
    0x3a0b6d1f, 0x4e2c, 0x4f6a,
    0x9d, 0x11, 0x37, 0xe0, 0xc4, 0xa5, 0xf0, 0x03);

static const FLT_OPERATION_REGISTRATION g_Callbacks[] = {
    { IRP_MJ_CREATE,           0, VigilPreCreate, VigilPostCreate },
    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION g_FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    g_Callbacks,
    VigilFilterUnload,
    VigilInstanceSetup,
    VigilInstanceQueryTeardown,
    VigilInstanceTeardownStart,
    VigilInstanceTeardownComplete,
    NULL, NULL, NULL, NULL, NULL, NULL,
};

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    KeInitializeSpinLock(&g_RingLock);
    g_RingBuf = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, VIGIL_RING_SIZE, VIGIL_TAG);
    if (g_RingBuf == NULL) {
        DbgPrint("[EDR] ring allocation failed\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    InitializeListHead(&g_ProcessBlockList);
    InitializeListHead(&g_FileBlockList);
    KeInitializeSpinLock(&g_BlockListLock);
    KeInitializeSpinLock(&g_NetworkIsolateLock);

    // Capture our service registry path so we can persist block lists to a
    // BlockList subkey under it (created on first add). RegistryPath
    // contents are owned by the kernel; we copy.
    if (RegistryPath != NULL && RegistryPath->Buffer != NULL && RegistryPath->Length > 0) {
        g_RegistryPathBuf = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, RegistryPath->Length, VIGIL_TAG);
        if (g_RegistryPathBuf) {
            RtlCopyMemory(g_RegistryPathBuf, RegistryPath->Buffer, RegistryPath->Length);
            g_RegistryPath.Buffer = g_RegistryPathBuf;
            g_RegistryPath.Length = RegistryPath->Length;
            g_RegistryPath.MaximumLength = RegistryPath->Length;
        }
    }
    // Best-effort load of persisted block lists. Failures here are
    // non-fatal: an empty list is a valid initial state.
    (void)VigilBlockLoadFromReg(VIGIL_BLOCK_KIND_PROCESS);
    (void)VigilBlockLoadFromReg(VIGIL_BLOCK_KIND_FILE);

    NTSTATUS status = FltRegisterFilter(DriverObject, &g_FilterRegistration, &g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EDR] FltRegisterFilter failed: 0x%08x\n", status);
        ExFreePoolWithTag(g_RingBuf, VIGIL_TAG);
        g_RingBuf = NULL;
        return status;
    }

    // Control device for IOCTLs. Created exclusive so only one handle at a
    // time can issue IOCTLs (the agent).
    status = IoCreateDeviceSecure(
        DriverObject,
        0,
        &g_DeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &SDDL_DEVOBJ_SYS_ALL_ADM_ALL,
        NULL,
        &g_DeviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EDR] IoCreateDeviceSecure failed: 0x%08x\n", status);
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = VigilDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = VigilDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = VigilDispatchDeviceControl;

    status = IoCreateSymbolicLink(&g_SymLinkName, &g_DeviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EDR] IoCreateSymbolicLink failed: 0x%08x\n", status);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
        return status;
    }
    g_SymLinkCreated = TRUE;

    status = PsSetCreateProcessNotifyRoutineEx(VigilCreateProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EDR] PsSetCreateProcessNotifyRoutineEx failed: 0x%08x\n", status);
        goto fail_unwind;
    }
    g_PsNotifyCreateRegistered = TRUE;

    status = PsSetLoadImageNotifyRoutine(VigilLoadImageNotify);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EDR] PsSetLoadImageNotifyRoutine failed: 0x%08x\n", status);
        goto fail_unwind;
    }
    g_PsNotifyImageRegistered = TRUE;

    {
        UNICODE_STRING regAltitude = RTL_CONSTANT_STRING(L"385100");
        status = CmRegisterCallbackEx(
            VigilRegistryCallback,
            &regAltitude,
            DriverObject,
            NULL,
            &g_RegCookie,
            NULL);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[EDR] CmRegisterCallbackEx failed: 0x%08x\n", status);
            goto fail_unwind;
        }
        g_RegCallbackRegistered = TRUE;
    }

    status = VigilWfpInit(DriverObject);
    if (!NT_SUCCESS(status)) {
        // VigilWfpInit cleans up its own partial state on failure, but it does
        // not unregister our other subsystems — that's still fail_unwind's
        // job. Just bail.
        VigilWfpCleanup();
        goto fail_unwind;
    }

    // M7.2: register ObCallbacks for process + thread access. If this
    // fails (rare; usually a CodeIntegrity / signed-binary issue), we
    // log + continue — the rest of the driver still works without
    // self-protection.
    {
        NTSTATUS spStatus = VigilSelfProtectInit();
        if (!NT_SUCCESS(spStatus)) {
            DbgPrint("[EDR] VigilSelfProtectInit failed: 0x%08x (continuing without ObCallbacks)\n", spStatus);
        }
    }

    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EDR] FltStartFiltering failed: 0x%08x\n", status);
        goto fail_unwind;
    }

    DbgPrint("[EDR] DriverEntry OK (M4.2)\n");
    return STATUS_SUCCESS;

fail_unwind:
    VigilSelfProtectCleanup();
    VigilWfpCleanup();
    if (g_RegCallbackRegistered) {
        CmUnRegisterCallback(g_RegCookie);
        g_RegCallbackRegistered = FALSE;
    }
    if (g_PsNotifyImageRegistered) {
        PsRemoveLoadImageNotifyRoutine(VigilLoadImageNotify);
        g_PsNotifyImageRegistered = FALSE;
    }
    if (g_PsNotifyCreateRegistered) {
        PsSetCreateProcessNotifyRoutineEx(VigilCreateProcessNotify, TRUE);
        g_PsNotifyCreateRegistered = FALSE;
    }
    if (g_SymLinkCreated) {
        IoDeleteSymbolicLink(&g_SymLinkName);
        g_SymLinkCreated = FALSE;
    }
    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }
    FltUnregisterFilter(g_FilterHandle);
    g_FilterHandle = NULL;
    if (g_RingBuf) {
        ExFreePoolWithTag(g_RingBuf, VIGIL_TAG);
        g_RingBuf = NULL;
    }
    return status;
}

static NTSTATUS VigilFilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    // Unregister callbacks before deleting the device; once unregistered no
    // new callbacks can fire and any in-flight callback finishes before the
    // unregister call returns. WFP first because deleting filters quiesces
    // future classify calls, then unregistering kernel callouts drains
    // in-flight ones.
    VigilSelfProtectCleanup();
    VigilWfpCleanup();
    if (g_RegCallbackRegistered) {
        CmUnRegisterCallback(g_RegCookie);
        g_RegCallbackRegistered = FALSE;
    }
    if (g_PsNotifyImageRegistered) {
        PsRemoveLoadImageNotifyRoutine(VigilLoadImageNotify);
        g_PsNotifyImageRegistered = FALSE;
    }
    if (g_PsNotifyCreateRegistered) {
        PsSetCreateProcessNotifyRoutineEx(VigilCreateProcessNotify, TRUE);
        g_PsNotifyCreateRegistered = FALSE;
    }
    if (g_SymLinkCreated) {
        IoDeleteSymbolicLink(&g_SymLinkName);
        g_SymLinkCreated = FALSE;
    }
    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }
    if (g_FilterHandle) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
    }

    // Free block-list memory. Persisted entries stay in the registry and
    // will be reloaded on the next DriverEntry.
    KIRQL irql;
    KeAcquireSpinLock(&g_BlockListLock, &irql);
    LIST_ENTRY *lists[2] = { &g_ProcessBlockList, &g_FileBlockList };
    LIST_ENTRY freed;
    InitializeListHead(&freed);
    for (UINT32 i = 0; i < 2; ++i) {
        while (!IsListEmpty(lists[i])) {
            LIST_ENTRY *e = RemoveHeadList(lists[i]);
            InsertTailList(&freed, e);
        }
    }
    InterlockedExchange(&g_ProcessBlockCount, 0);
    InterlockedExchange(&g_FileBlockCount, 0);
    KeReleaseSpinLock(&g_BlockListLock, irql);
    while (!IsListEmpty(&freed)) {
        LIST_ENTRY *e = RemoveHeadList(&freed);
        PVIGIL_BLOCK_ENTRY entry = CONTAINING_RECORD(e, VIGIL_BLOCK_ENTRY, List);
        ExFreePoolWithTag(entry, VIGIL_TAG);
    }
    if (g_RegistryPathBuf) {
        ExFreePoolWithTag(g_RegistryPathBuf, VIGIL_TAG);
        g_RegistryPathBuf = NULL;
        RtlZeroMemory(&g_RegistryPath, sizeof(g_RegistryPath));
    }

    if (g_RingBuf) {
        ExFreePoolWithTag(g_RingBuf, VIGIL_TAG);
        g_RingBuf = NULL;
    }
    DbgPrint("[EDR] Unload\n");
    return STATUS_SUCCESS;
}

// Ring buffer push. Caller does NOT hold the lock; we acquire/release
// internally. Returns TRUE on success, FALSE if ring is full (event dropped).
static BOOLEAN VigilRingPush(_In_reads_bytes_(size) const VOID *src, _In_ UINT32 size)
{
    if (size == 0 || size > VIGIL_RING_SIZE) {
        return FALSE;
    }
    KIRQL irql;
    KeAcquireSpinLock(&g_RingLock, &irql);
    if (g_RingUsed + size > VIGIL_RING_SIZE) {
        KeReleaseSpinLock(&g_RingLock, irql);
        return FALSE;
    }
    UINT32 first = size;
    UINT32 second = 0;
    if (g_RingTail + size > VIGIL_RING_SIZE) {
        first = VIGIL_RING_SIZE - g_RingTail;
        second = size - first;
    }
    RtlCopyMemory(g_RingBuf + g_RingTail, src, first);
    if (second) {
        RtlCopyMemory(g_RingBuf, (const UCHAR *)src + first, second);
    }
    g_RingTail = (g_RingTail + size) % VIGIL_RING_SIZE;
    g_RingUsed += size;
    KeReleaseSpinLock(&g_RingLock, irql);
    return TRUE;
}

// Drain as many complete events as fit in [dst, dst+maxBytes). Returns the
// number of bytes written (0 if ring is empty or maxBytes too small for the
// next event). nEvents receives the count of events emitted.
static UINT32 VigilRingDrain(_Out_writes_bytes_(maxBytes) PVOID dst, _In_ UINT32 maxBytes, _Out_ PUINT32 nEvents)
{
    UINT32 written = 0;
    UINT32 events = 0;
    KIRQL irql;
    KeAcquireSpinLock(&g_RingLock, &irql);
    while (g_RingUsed >= sizeof(VIGIL_EVENT_HEADER)) {
        // Read the event Size field (first UINT32 of the event). Handle the
        // case where the field straddles the wrap boundary.
        UINT32 size;
        if (g_RingHead + sizeof(UINT32) <= VIGIL_RING_SIZE) {
            size = *(const UINT32 *)(g_RingBuf + g_RingHead);
        } else {
            UCHAR sb[sizeof(UINT32)];
            for (UINT32 i = 0; i < sizeof(UINT32); ++i) {
                sb[i] = g_RingBuf[(g_RingHead + i) % VIGIL_RING_SIZE];
            }
            size = *(const UINT32 *)sb;
        }
        if (size == 0 || size > g_RingUsed) {
            // corruption; bail out (shouldn't happen if push always wrote
            // a complete event)
            break;
        }
        if (written + size > maxBytes) {
            break;  // user buffer full
        }
        UINT32 first = size;
        UINT32 second = 0;
        if (g_RingHead + size > VIGIL_RING_SIZE) {
            first = VIGIL_RING_SIZE - g_RingHead;
            second = size - first;
        }
        RtlCopyMemory((UCHAR *)dst + written, g_RingBuf + g_RingHead, first);
        if (second) {
            RtlCopyMemory((UCHAR *)dst + written + first, g_RingBuf, second);
        }
        g_RingHead = (g_RingHead + size) % VIGIL_RING_SIZE;
        g_RingUsed -= size;
        written += size;
        events++;
    }
    KeReleaseSpinLock(&g_RingLock, irql);
    *nEvents = events;
    return written;
}

static NTSTATUS VigilInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);
    return STATUS_SUCCESS;
}

static NTSTATUS VigilInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

static VOID VigilInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
}

static VOID VigilInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
}

// Pre-op for IRP_MJ_CREATE. Bumps the file-create counter and consults the
// file block list (M5.2): if the file name matches a blocked pattern,
// completes the IRP with STATUS_ACCESS_DENIED so the open never reaches
// the filesystem.
//
// Volume of these callbacks is high (10s-100s of opens per second on an
// idle machine). FltGetFileNameInformation is moderately expensive; we
// only call it when the block list is non-empty.
static FLT_PREOP_CALLBACK_STATUS VigilPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);

    InterlockedIncrement64(&g_FileCreateCount);

    if (ReadAcquire(&g_FileBlockCount) > 0) {
        PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
        if (NT_SUCCESS(FltGetFileNameInformation(
                Data,
                FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                &nameInfo)))
        {
            (void)FltParseFileNameInformation(nameInfo);
            if (VigilBlockMatch(&g_FileBlockList, &nameInfo->Name)) {
                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                Data->IoStatus.Information = 0;
                FltReleaseFileNameInformation(nameInfo);
                InterlockedIncrement64(&g_FileBlockHits);
                *CompletionContext = NULL;
                return FLT_PREOP_COMPLETE;
            }
            FltReleaseFileNameInformation(nameInfo);
        }
    }

    *CompletionContext = NULL;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

// Post-op fires after the file system has handled the IRP. Data->IoStatus
// has the final status. We only count succeeded opens for now; useful as a
// signal that the FS actually executed the IRP (vs. denied / failed).
static FLT_POSTOP_CALLBACK_STATUS VigilPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    if (NT_SUCCESS(Data->IoStatus.Status) &&
        Data->IoStatus.Status != STATUS_REPARSE)
    {
        InterlockedIncrement64(&g_FileCreateSucceededCount);
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}

// Process create / exit. CreateInfo != NULL for create, == NULL for exit.
// Runs at PASSIVE_LEVEL.
static VOID VigilCreateProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo != NULL) {
        InterlockedIncrement64(&g_ProcessCreateCount);

        // Block check: if the image path matches an entry in the process
        // block list, deny the create with STATUS_ACCESS_DENIED. Setting
        // CreateInfo->CreationStatus to a non-success value causes the
        // create to fail in user-mode (CreateProcess returns the error).
        if (CreateInfo->ImageFileName != NULL &&
            VigilBlockMatch(&g_ProcessBlockList, CreateInfo->ImageFileName))
        {
            CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
            InterlockedIncrement64(&g_ProcessBlockHits);
            // Don't enqueue a process_start event since the process won't
            // actually run. We're done.
            return;
        }

        // Build a process_start event. Stack scratch keeps the kernel stack
        // bounded (max event ~1.4 KB; default kernel stack is 12-24 KB so
        // we have plenty of headroom).
        UCHAR scratch[1536];
        const UINT32 maxStringBytes = 480;  // each of imageName / cmdLine

        PVIGIL_EVENT_PROCESS_START ev = (PVIGIL_EVENT_PROCESS_START)scratch;
        UINT16 imageLen = 0, cmdLen = 0;
        if (CreateInfo->ImageFileName != NULL) {
            imageLen = (UINT16)min((UINT32)CreateInfo->ImageFileName->Length, maxStringBytes);
        }
        if (CreateInfo->CommandLine != NULL) {
            cmdLen = (UINT16)min((UINT32)CreateInfo->CommandLine->Length, maxStringBytes);
        }
        UINT32 evSize = sizeof(VIGIL_EVENT_PROCESS_START) + imageLen + cmdLen;

        LARGE_INTEGER ts;
        KeQuerySystemTimePrecise(&ts);

        ev->Header.Size = evSize;
        ev->Header.Kind = VIGIL_EVENT_KIND_PROCESS_START;
        ev->Header.TimestampNs = (UINT64)ts.QuadPart;
        ev->Header.ProcessId = (UINT64)(ULONG_PTR)ProcessId;
        ev->ParentProcessId = (UINT64)(ULONG_PTR)CreateInfo->ParentProcessId;
        ev->ImageNameLen = imageLen;
        ev->CommandLineLen = cmdLen;
        UCHAR *p = scratch + sizeof(VIGIL_EVENT_PROCESS_START);
        if (imageLen) {
            RtlCopyMemory(p, CreateInfo->ImageFileName->Buffer, imageLen);
            p += imageLen;
        }
        if (cmdLen) {
            RtlCopyMemory(p, CreateInfo->CommandLine->Buffer, cmdLen);
        }

        if (VigilRingPush(scratch, evSize)) {
            InterlockedIncrement64(&g_EventsEnqueued);
        } else {
            InterlockedIncrement64(&g_EventsDropped);
        }
    } else {
        InterlockedIncrement64(&g_ProcessExitCount);
        // M4.6 will enqueue process_exit; M4.5 only carries process_start to
        // keep the diff focused.

        // M7.2: if the protected pid is exiting, clear the slot so a
        // future process that happens to inherit this pid doesn't get
        // protected by accident. Compare-and-swap rather than blind
        // store: if the agent has already re-registered as a different
        // pid (unlikely but possible during a fast-restart race), don't
        // clobber.
        LONG64 expected = (LONG64)(LONG_PTR)ProcessId;
        InterlockedCompareExchange64(&g_ProtectedPid, 0, expected);
    }
}

// Image load. Runs at PASSIVE_LEVEL. ImageInfo->SystemModeImage is TRUE for
// drivers loading into the kernel; FALSE for user-mode image loads.
static VOID VigilLoadImageNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo)
{
    InterlockedIncrement64(&g_ImageLoadCount);
    if (ImageInfo->SystemModeImage) {
        InterlockedIncrement64(&g_ImageLoadKernelCount);
    }
    if (FullImageName != NULL) {
        DbgPrint("[EDR] image.load pid=%llu kernel=%u image=%wZ\n",
                 (ULONG64)(ULONG_PTR)ProcessId,
                 ImageInfo->SystemModeImage,
                 FullImageName);
    }
}

// ---- Block list -----------------------------------------------------------

#define VIGIL_BLOCK_PATTERN_MAX_BYTES 512

static LIST_ENTRY *VigilBlockListForKind(UINT32 kind)
{
    if (kind == VIGIL_BLOCK_KIND_PROCESS) return &g_ProcessBlockList;
    if (kind == VIGIL_BLOCK_KIND_FILE)    return &g_FileBlockList;
    return NULL;
}

static volatile LONG *VigilBlockCountForKind(UINT32 kind)
{
    if (kind == VIGIL_BLOCK_KIND_PROCESS) return &g_ProcessBlockCount;
    if (kind == VIGIL_BLOCK_KIND_FILE)    return &g_FileBlockCount;
    return NULL;
}

// Case-insensitive substring match: does `pattern` appear anywhere in
// `name`? Caller does NOT hold the spinlock — we acquire it here.
static BOOLEAN VigilBlockMatch(_In_ LIST_ENTRY *list, _In_opt_ PCUNICODE_STRING name)
{
    if (name == NULL || name->Buffer == NULL || name->Length == 0) {
        return FALSE;
    }
    BOOLEAN matched = FALSE;
    KIRQL irql;
    KeAcquireSpinLock(&g_BlockListLock, &irql);
    for (LIST_ENTRY *e = list->Flink; e != list; e = e->Flink) {
        PVIGIL_BLOCK_ENTRY entry = CONTAINING_RECORD(e, VIGIL_BLOCK_ENTRY, List);
        if (entry->Length == 0 || entry->Length > name->Length) {
            continue;
        }
        UNICODE_STRING pattern;
        pattern.Buffer = entry->Buffer;
        pattern.Length = entry->Length;
        pattern.MaximumLength = entry->Length;

        UINT32 startMax = (name->Length - entry->Length) / sizeof(WCHAR);
        for (UINT32 i = 0; i <= startMax && !matched; ++i) {
            UNICODE_STRING window;
            window.Buffer = name->Buffer + i;
            window.Length = entry->Length;
            window.MaximumLength = entry->Length;
            if (RtlEqualUnicodeString(&window, &pattern, TRUE)) {
                matched = TRUE;
            }
        }
        if (matched) break;
    }
    KeReleaseSpinLock(&g_BlockListLock, irql);
    return matched;
}

// Persist a block list to the driver's service registry key. Caller does
// NOT hold the spinlock — we copy the list under the lock, then write to
// the registry at PASSIVE_LEVEL.
//
// RegistryPath received in DriverEntry is e.g.
// "\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\edr".

static NTSTATUS VigilBlockPersist(_In_ UINT32 kind);

static NTSTATUS VigilBlockAdd(_In_ UINT32 kind, _In_reads_bytes_(patternBytes) const WCHAR *pattern, _In_ USHORT patternBytes)
{
    LIST_ENTRY *list = VigilBlockListForKind(kind);
    volatile LONG *count = VigilBlockCountForKind(kind);
    if (!list || patternBytes == 0 || patternBytes > VIGIL_BLOCK_PATTERN_MAX_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }
    SIZE_T entryBytes = FIELD_OFFSET(VIGIL_BLOCK_ENTRY, Buffer) + patternBytes;
    PVIGIL_BLOCK_ENTRY entry = (PVIGIL_BLOCK_ENTRY)ExAllocatePool2(POOL_FLAG_NON_PAGED, entryBytes, VIGIL_TAG);
    if (!entry) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    entry->Length = patternBytes;
    RtlCopyMemory(entry->Buffer, pattern, patternBytes);

    KIRQL irql;
    KeAcquireSpinLock(&g_BlockListLock, &irql);
    InsertTailList(list, &entry->List);
    KeReleaseSpinLock(&g_BlockListLock, irql);
    InterlockedIncrement(count);
    return VigilBlockPersist(kind);
}

static NTSTATUS VigilBlockRemove(_In_ UINT32 kind, _In_reads_bytes_(patternBytes) const WCHAR *pattern, _In_ USHORT patternBytes)
{
    LIST_ENTRY *list = VigilBlockListForKind(kind);
    volatile LONG *count = VigilBlockCountForKind(kind);
    if (!list || patternBytes == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    UNICODE_STRING needle;
    needle.Buffer = (PWCH)pattern;
    needle.Length = patternBytes;
    needle.MaximumLength = patternBytes;

    PVIGIL_BLOCK_ENTRY toFree = NULL;
    KIRQL irql;
    KeAcquireSpinLock(&g_BlockListLock, &irql);
    for (LIST_ENTRY *e = list->Flink; e != list; e = e->Flink) {
        PVIGIL_BLOCK_ENTRY entry = CONTAINING_RECORD(e, VIGIL_BLOCK_ENTRY, List);
        UNICODE_STRING ent;
        ent.Buffer = entry->Buffer;
        ent.Length = entry->Length;
        ent.MaximumLength = entry->Length;
        if (RtlEqualUnicodeString(&ent, &needle, TRUE)) {
            RemoveEntryList(&entry->List);
            toFree = entry;
            break;
        }
    }
    KeReleaseSpinLock(&g_BlockListLock, irql);

    if (toFree == NULL) return STATUS_NOT_FOUND;
    ExFreePoolWithTag(toFree, VIGIL_TAG);
    InterlockedDecrement(count);
    return VigilBlockPersist(kind);
}

static NTSTATUS VigilBlockClear(_In_ UINT32 kind)
{
    UINT32 kinds[2] = { 0, 0 };
    UINT32 nKinds = 0;
    if (kind == 0) {
        kinds[nKinds++] = VIGIL_BLOCK_KIND_PROCESS;
        kinds[nKinds++] = VIGIL_BLOCK_KIND_FILE;
    } else {
        kinds[nKinds++] = kind;
    }
    for (UINT32 k = 0; k < nKinds; ++k) {
        LIST_ENTRY *list = VigilBlockListForKind(kinds[k]);
        volatile LONG *count = VigilBlockCountForKind(kinds[k]);
        if (!list) continue;

        LIST_ENTRY freed;
        InitializeListHead(&freed);
        KIRQL irql;
        KeAcquireSpinLock(&g_BlockListLock, &irql);
        while (!IsListEmpty(list)) {
            LIST_ENTRY *e = RemoveHeadList(list);
            InsertTailList(&freed, e);
        }
        InterlockedExchange(count, 0);
        KeReleaseSpinLock(&g_BlockListLock, irql);

        while (!IsListEmpty(&freed)) {
            LIST_ENTRY *e = RemoveHeadList(&freed);
            PVIGIL_BLOCK_ENTRY entry = CONTAINING_RECORD(e, VIGIL_BLOCK_ENTRY, List);
            ExFreePoolWithTag(entry, VIGIL_TAG);
        }
        VigilBlockPersist(kinds[k]);
    }
    return STATUS_SUCCESS;
}

// Snapshot one list under the spinlock as a series of (Length, Buffer) pairs
// the caller can serialize at PASSIVE_LEVEL without holding the lock.
typedef struct _VIGIL_BLOCK_SNAPSHOT_ENTRY {
    USHORT Length;
    PWCHAR Buffer;          // points into a pool-allocated arena
} VIGIL_BLOCK_SNAPSHOT_ENTRY;

static NTSTATUS VigilBlockSnapshot(
    _In_ UINT32 kind,
    _Outptr_ VIGIL_BLOCK_SNAPSHOT_ENTRY **outEntries,
    _Out_ UINT32 *outCount,
    _Outptr_ PVOID *outArena)
{
    LIST_ENTRY *list = VigilBlockListForKind(kind);
    if (!list) return STATUS_INVALID_PARAMETER;

    *outEntries = NULL;
    *outCount = 0;
    *outArena = NULL;

    // Pass 1: count + total bytes (under lock)
    KIRQL irql;
    KeAcquireSpinLock(&g_BlockListLock, &irql);
    UINT32 count = 0;
    SIZE_T totalBytes = 0;
    for (LIST_ENTRY *e = list->Flink; e != list; e = e->Flink) {
        PVIGIL_BLOCK_ENTRY entry = CONTAINING_RECORD(e, VIGIL_BLOCK_ENTRY, List);
        count++;
        totalBytes += entry->Length;
    }

    if (count == 0) {
        KeReleaseSpinLock(&g_BlockListLock, irql);
        return STATUS_SUCCESS;
    }

    SIZE_T arrayBytes = count * sizeof(VIGIL_BLOCK_SNAPSHOT_ENTRY);
    VIGIL_BLOCK_SNAPSHOT_ENTRY *arr = NULL;
    PVOID arena = NULL;

    KeReleaseSpinLock(&g_BlockListLock, irql);
    arr = (VIGIL_BLOCK_SNAPSHOT_ENTRY *)ExAllocatePool2(POOL_FLAG_NON_PAGED, arrayBytes, VIGIL_TAG);
    arena = ExAllocatePool2(POOL_FLAG_NON_PAGED, totalBytes, VIGIL_TAG);
    if (!arr || !arena) {
        if (arr) ExFreePoolWithTag(arr, VIGIL_TAG);
        if (arena) ExFreePoolWithTag(arena, VIGIL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Pass 2: copy under the lock again (size could have changed; we'd
    // rather take it twice than allocate while holding the lock).
    KeAcquireSpinLock(&g_BlockListLock, &irql);
    UINT32 i = 0;
    SIZE_T off = 0;
    for (LIST_ENTRY *e = list->Flink; e != list && i < count && off < totalBytes; e = e->Flink) {
        PVIGIL_BLOCK_ENTRY entry = CONTAINING_RECORD(e, VIGIL_BLOCK_ENTRY, List);
        if (off + entry->Length > totalBytes || i >= count) break;
        RtlCopyMemory((UCHAR *)arena + off, entry->Buffer, entry->Length);
        arr[i].Length = entry->Length;
        arr[i].Buffer = (PWCHAR)((UCHAR *)arena + off);
        off += entry->Length;
        i++;
    }
    KeReleaseSpinLock(&g_BlockListLock, irql);

    *outEntries = arr;
    *outCount = i;
    *outArena = arena;
    return STATUS_SUCCESS;
}

static const WCHAR *VigilBlockRegValueName(UINT32 kind)
{
    return kind == VIGIL_BLOCK_KIND_PROCESS ? L"ProcessPatterns" :
           kind == VIGIL_BLOCK_KIND_FILE    ? L"FilePatterns"    : NULL;
}

// Open the driver's service key plus a "BlockList" subkey for persistence.
// Returns a HANDLE the caller must ZwClose. Creates the subkey if missing.
static NTSTATUS VigilOpenBlockListKey(_Out_ PHANDLE OutKey)
{
    *OutKey = NULL;
    if (g_RegistryPath.Buffer == NULL) {
        return STATUS_NOT_FOUND;
    }
    // BlockListPath = <RegistryPath>\BlockList
    UNICODE_STRING suffix = RTL_CONSTANT_STRING(L"\\BlockList");
    USHORT bytes = g_RegistryPath.Length + suffix.Length;
    PWCHAR buf = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, bytes, VIGIL_TAG);
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(buf, g_RegistryPath.Buffer, g_RegistryPath.Length);
    RtlCopyMemory((UCHAR *)buf + g_RegistryPath.Length, suffix.Buffer, suffix.Length);
    UNICODE_STRING fullPath;
    fullPath.Buffer = buf;
    fullPath.Length = bytes;
    fullPath.MaximumLength = bytes;
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &fullPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    HANDLE key;
    ULONG disposition;
    NTSTATUS status = ZwCreateKey(&key, KEY_ALL_ACCESS, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, &disposition);
    ExFreePoolWithTag(buf, VIGIL_TAG);
    if (NT_SUCCESS(status)) {
        *OutKey = key;
    }
    return status;
}

// Serialize current in-memory list of `kind` as REG_MULTI_SZ. Each pattern
// is null-terminated; the buffer ends with an extra null. Even if the list
// is empty we write a single null-terminator (a valid empty REG_MULTI_SZ).
static NTSTATUS VigilBlockPersist(_In_ UINT32 kind)
{
    VIGIL_BLOCK_SNAPSHOT_ENTRY *entries = NULL;
    UINT32 count = 0;
    PVOID arena = NULL;
    NTSTATUS status = VigilBlockSnapshot(kind, &entries, &count, &arena);
    if (!NT_SUCCESS(status)) return status;

    // Compute serialized size in bytes: sum(length + sizeof(WCHAR) for null) + final WCHAR null.
    SIZE_T outBytes = sizeof(WCHAR);   // trailing null
    for (UINT32 i = 0; i < count; ++i) {
        outBytes += entries[i].Length + sizeof(WCHAR);
    }
    PWCHAR multi = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, outBytes, VIGIL_TAG);
    if (!multi) {
        if (entries) ExFreePoolWithTag(entries, VIGIL_TAG);
        if (arena) ExFreePoolWithTag(arena, VIGIL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    UCHAR *p = (UCHAR *)multi;
    for (UINT32 i = 0; i < count; ++i) {
        RtlCopyMemory(p, entries[i].Buffer, entries[i].Length);
        p += entries[i].Length;
        *(WCHAR *)p = L'\0';
        p += sizeof(WCHAR);
    }
    *(WCHAR *)p = L'\0';

    HANDLE key = NULL;
    status = VigilOpenBlockListKey(&key);
    if (NT_SUCCESS(status)) {
        const WCHAR *valueName = VigilBlockRegValueName(kind);
        UNICODE_STRING vn;
        RtlInitUnicodeString(&vn, valueName);
        status = ZwSetValueKey(key, &vn, 0, REG_MULTI_SZ, multi, (ULONG)outBytes);
        ZwClose(key);
    }
    ExFreePoolWithTag(multi, VIGIL_TAG);
    if (entries) ExFreePoolWithTag(entries, VIGIL_TAG);
    if (arena) ExFreePoolWithTag(arena, VIGIL_TAG);
    return status;
}

// Read REG_MULTI_SZ for one kind back into the in-memory list. Called at
// DriverEntry, before the callbacks are armed.
static NTSTATUS VigilBlockLoadFromReg(_In_ UINT32 kind)
{
    HANDLE key = NULL;
    NTSTATUS status = VigilOpenBlockListKey(&key);
    if (!NT_SUCCESS(status)) return status;

    const WCHAR *valueName = VigilBlockRegValueName(kind);
    UNICODE_STRING vn;
    RtlInitUnicodeString(&vn, valueName);

    // Probe size first.
    ULONG sizeNeeded = 0;
    status = ZwQueryValueKey(key, &vn, KeyValuePartialInformation, NULL, 0, &sizeNeeded);
    if (status == STATUS_OBJECT_NAME_NOT_FOUND) {
        ZwClose(key);
        return STATUS_SUCCESS;  // empty list, nothing to load
    }
    if (status != STATUS_BUFFER_TOO_SMALL && !NT_SUCCESS(status)) {
        ZwClose(key);
        return status;
    }

    PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeNeeded, VIGIL_TAG);
    if (!info) {
        ZwClose(key);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    status = ZwQueryValueKey(key, &vn, KeyValuePartialInformation, info, sizeNeeded, &sizeNeeded);
    ZwClose(key);
    if (!NT_SUCCESS(status) || info->Type != REG_MULTI_SZ) {
        ExFreePoolWithTag(info, VIGIL_TAG);
        return NT_SUCCESS(status) ? STATUS_OBJECT_TYPE_MISMATCH : status;
    }

    // Walk REG_MULTI_SZ: a series of null-terminated WCHAR strings ending
    // with an empty string (double null overall).
    PWCHAR cur = (PWCHAR)info->Data;
    PWCHAR end = (PWCHAR)((UCHAR *)info->Data + info->DataLength);
    while (cur < end && *cur != L'\0') {
        // Find string length (in WCHARs)
        PWCHAR p = cur;
        while (p < end && *p != L'\0') p++;
        USHORT bytes = (USHORT)((p - cur) * sizeof(WCHAR));
        if (bytes > 0 && bytes <= VIGIL_BLOCK_PATTERN_MAX_BYTES) {
            (void)VigilBlockAdd(kind, cur, bytes);
        }
        cur = p + 1;  // skip null
    }
    ExFreePoolWithTag(info, VIGIL_TAG);
    return STATUS_SUCCESS;
}

// Build and ring-push a NETWORK_CONNECT event. Shared by both the V4 and V6
// classifiers; the caller has already converted addresses + ports to network
// byte order and selected the right family.
static VOID VigilEnqueueNetworkConnect(
    _In_ UINT8 ipVersion,
    _In_ UINT8 protocol,
    _In_ UINT16 localPortBe,
    _In_ UINT16 remotePortBe,
    _In_reads_bytes_(addrBytes) const VOID *localAddr,
    _In_reads_bytes_(addrBytes) const VOID *remoteAddr,
    _In_ UINT32 addrBytes,
    _In_ UINT64 processId)
{
    VIGIL_EVENT_NETWORK_CONNECT ev;
    RtlZeroMemory(&ev, sizeof(ev));
    LARGE_INTEGER ts;
    KeQuerySystemTimePrecise(&ts);

    ev.Header.Size = sizeof(VIGIL_EVENT_NETWORK_CONNECT);
    ev.Header.Kind = VIGIL_EVENT_KIND_NETWORK_CONNECT;
    ev.Header.TimestampNs = (UINT64)ts.QuadPart;
    ev.Header.ProcessId = processId;
    ev.IpVersion = ipVersion;
    ev.Protocol = protocol;
    ev.LocalPort = localPortBe;
    ev.RemotePort = remotePortBe;
    ev._Reserved = 0;

    UINT32 copyBytes = (addrBytes <= sizeof(ev.LocalAddr)) ? addrBytes : (UINT32)sizeof(ev.LocalAddr);
    RtlCopyMemory(ev.LocalAddr, localAddr, copyBytes);
    RtlCopyMemory(ev.RemoteAddr, remoteAddr, copyBytes);

    if (VigilRingPush(&ev, sizeof(ev))) {
        InterlockedIncrement64(&g_EventsEnqueued);
        InterlockedIncrement64(&g_NetConnectCount);
    } else {
        InterlockedIncrement64(&g_EventsDropped);
    }
}

// IPv4 ALE classify. WFP delivers V4 addresses + ports in HOST byte order
// at this layer. We byte-swap to network order on the way out so the wire
// format is consistent across V4 and V6 events.
static VOID VigilWfpClassifyV4(
    _In_ const FWPS_INCOMING_VALUES0 *inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues,
    _Inout_opt_ void *layerData,
    _In_opt_ const void *classifyContext,
    _In_ const FWPS_FILTER1 *filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0 *classifyOut)
{
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    // Inspection callout — leave the action alone so packets pass through.
    classifyOut->actionType = FWP_ACTION_CONTINUE;

    UINT32 localAddrHe = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32;
    UINT32 remoteAddrHe = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
    UINT16 localPortHe = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16;
    UINT16 remotePortHe = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;
    UINT8 protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint8;

    UINT64 processId = 0;
    if ((inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) != 0) {
        processId = inMetaValues->processId;
    }

    UINT32 localAddrBe = RtlUlongByteSwap(localAddrHe);
    UINT32 remoteAddrBe = RtlUlongByteSwap(remoteAddrHe);
    VigilEnqueueNetworkConnect(
        4,
        protocol,
        RtlUshortByteSwap(localPortHe),
        RtlUshortByteSwap(remotePortHe),
        &localAddrBe,
        &remoteAddrBe,
        sizeof(UINT32),
        processId);

    // Phase 1 #1.3 — enforce isolation if active. The event has already
    // been enqueued above so operators can see *what* tried to phone
    // home while isolated; we decide on the action separately.
    //
    // Fast-path: bail out if isolation is off without touching the
    // spinlock. The classifier fires per-connect on every NIC, so the
    // off-path cost has to be a single Interlocked read.
    if (InterlockedCompareExchange((volatile LONG *)&g_NetworkIsolated, 0, 0) == 0) {
        return;
    }
    // The IPv4 destination, mapped into the 16-byte v4-mapped-v6 form
    // we store in g_AllowedIps. `remoteAddrBe` is already big-endian.
    UINT8 needle[16] = {0};
    needle[10] = 0xff;
    needle[11] = 0xff;
    RtlCopyMemory(&needle[12], &remoteAddrBe, 4);

    BOOLEAN allowed = FALSE;
    KIRQL irql;
    KeAcquireSpinLock(&g_NetworkIsolateLock, &irql);
    for (UINT32 i = 0; i < g_AllowedIpCount; ++i) {
        if (RtlEqualMemory(g_AllowedIps[i].Bytes, needle, 16)) {
            allowed = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_NetworkIsolateLock, irql);

    if (!allowed) {
        classifyOut->actionType = FWP_ACTION_BLOCK;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
        InterlockedIncrement64(&g_NetworkIsolationBlockHits);
    }
}

// IPv6 ALE classify. V6 addresses are byteArray16* (already in network order
// per WFP); ports are HOST byte order at this layer.
static VOID VigilWfpClassifyV6(
    _In_ const FWPS_INCOMING_VALUES0 *inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues,
    _Inout_opt_ void *layerData,
    _In_opt_ const void *classifyContext,
    _In_ const FWPS_FILTER1 *filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0 *classifyOut)
{
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    classifyOut->actionType = FWP_ACTION_CONTINUE;

    const FWP_BYTE_ARRAY16 *localAddr = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS].value.byteArray16;
    const FWP_BYTE_ARRAY16 *remoteAddr = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS].value.byteArray16;
    UINT16 localPortHe = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT].value.uint16;
    UINT16 remotePortHe = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT].value.uint16;
    UINT8 protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL].value.uint8;

    UINT64 processId = 0;
    if ((inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) != 0) {
        processId = inMetaValues->processId;
    }

    if (localAddr == NULL || remoteAddr == NULL) {
        return;
    }
    VigilEnqueueNetworkConnect(
        6,
        protocol,
        RtlUshortByteSwap(localPortHe),
        RtlUshortByteSwap(remotePortHe),
        localAddr->byteArray16,
        remoteAddr->byteArray16,
        16,
        processId);

    // Phase 1 #1.3 isolation — same shape as V4 but the destination is
    // already a 16-byte IPv6 address. v4-mapped-v6 entries in the
    // allowlist still match IPv6 traffic that uses that form.
    if (InterlockedCompareExchange((volatile LONG *)&g_NetworkIsolated, 0, 0) == 0) {
        return;
    }
    BOOLEAN allowed = FALSE;
    KIRQL irql;
    KeAcquireSpinLock(&g_NetworkIsolateLock, &irql);
    for (UINT32 i = 0; i < g_AllowedIpCount; ++i) {
        if (RtlEqualMemory(g_AllowedIps[i].Bytes, remoteAddr->byteArray16, 16)) {
            allowed = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_NetworkIsolateLock, irql);

    if (!allowed) {
        classifyOut->actionType = FWP_ACTION_BLOCK;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
        InterlockedIncrement64(&g_NetworkIsolationBlockHits);
    }
}

// WFP callout notify. Required by FwpsCalloutRegister1 but we don't need to
// do anything at filter add/remove time — return STATUS_SUCCESS.
static NTSTATUS VigilWfpNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID *filterKey,
    _Inout_ FWPS_FILTER1 *filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

// WFP setup. Must be called from DriverEntry after the control device exists
// (FwpsCalloutRegister1 needs a device object). On any failure we tear down
// every step that succeeded — see VigilWfpCleanup.
static NTSTATUS VigilWfpInit(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    NTSTATUS status;

    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &g_WfpEngine);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EDR] FwpmEngineOpen0 failed: 0x%08x\n", status);
        return status;
    }

    status = FwpmTransactionBegin0(g_WfpEngine, 0);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EDR] FwpmTransactionBegin0 failed: 0x%08x\n", status);
        return status;
    }
    g_WfpInTransaction = TRUE;

    FWPM_SUBLAYER0 sublayer;
    RtlZeroMemory(&sublayer, sizeof(sublayer));
    sublayer.subLayerKey = VIGIL_WFP_SUBLAYER_GUID;
    sublayer.displayData.name = (wchar_t *)L"EDR Observation Sublayer";
    sublayer.displayData.description = (wchar_t *)L"EDR observation-only filters";
    sublayer.flags = 0;
    sublayer.weight = 0x100;
    status = FwpmSubLayerAdd0(g_WfpEngine, &sublayer, NULL);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EDR] FwpmSubLayerAdd0 failed: 0x%08x\n", status);
        return status;
    }
    g_WfpSubLayerAdded = TRUE;

    // Register kernel-side callouts. Must succeed before the management-side
    // FwpmCalloutAdd0 because the latter looks up the kernel callout by key.
    FWPS_CALLOUT1 calloutV4;
    RtlZeroMemory(&calloutV4, sizeof(calloutV4));
    calloutV4.calloutKey = VIGIL_WFP_CALLOUT_V4_GUID;
    calloutV4.classifyFn = VigilWfpClassifyV4;
    calloutV4.notifyFn = VigilWfpNotify;
    status = FwpsCalloutRegister1(g_DeviceObject, &calloutV4, &g_WfpCalloutIdV4);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EDR] FwpsCalloutRegister1 V4 failed: 0x%08x\n", status);
        return status;
    }

    FWPS_CALLOUT1 calloutV6;
    RtlZeroMemory(&calloutV6, sizeof(calloutV6));
    calloutV6.calloutKey = VIGIL_WFP_CALLOUT_V6_GUID;
    calloutV6.classifyFn = VigilWfpClassifyV6;
    calloutV6.notifyFn = VigilWfpNotify;
    status = FwpsCalloutRegister1(g_DeviceObject, &calloutV6, &g_WfpCalloutIdV6);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EDR] FwpsCalloutRegister1 V6 failed: 0x%08x\n", status);
        return status;
    }

    // Management-side callout entries.
    FWPM_CALLOUT0 fwpmCalloutV4;
    RtlZeroMemory(&fwpmCalloutV4, sizeof(fwpmCalloutV4));
    fwpmCalloutV4.calloutKey = VIGIL_WFP_CALLOUT_V4_GUID;
    fwpmCalloutV4.displayData.name = (wchar_t *)L"EDR ALE Auth Connect IPv4";
    fwpmCalloutV4.displayData.description = (wchar_t *)L"";
    fwpmCalloutV4.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    status = FwpmCalloutAdd0(g_WfpEngine, &fwpmCalloutV4, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EDR] FwpmCalloutAdd0 V4 failed: 0x%08x\n", status);
        return status;
    }
    g_WfpFwpmCalloutV4Added = TRUE;

    FWPM_CALLOUT0 fwpmCalloutV6;
    RtlZeroMemory(&fwpmCalloutV6, sizeof(fwpmCalloutV6));
    fwpmCalloutV6.calloutKey = VIGIL_WFP_CALLOUT_V6_GUID;
    fwpmCalloutV6.displayData.name = (wchar_t *)L"EDR ALE Auth Connect IPv6";
    fwpmCalloutV6.displayData.description = (wchar_t *)L"";
    fwpmCalloutV6.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    status = FwpmCalloutAdd0(g_WfpEngine, &fwpmCalloutV6, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EDR] FwpmCalloutAdd0 V6 failed: 0x%08x\n", status);
        return status;
    }
    g_WfpFwpmCalloutV6Added = TRUE;

    // Filters: TERMINATING action so the classifier can both inspect
    // (when isolation is off) and BLOCK (when isolation is on). The
    // classifier defaults to FWP_ACTION_CONTINUE which functionally
    // matches the pre-Phase-1 inspection-only behaviour; the actual
    // BLOCK action is only set when `g_NetworkIsolated == 1` and the
    // destination isn't in the allowlist.
    FWPM_FILTER0 filterV4;
    RtlZeroMemory(&filterV4, sizeof(filterV4));
    filterV4.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filterV4.subLayerKey = VIGIL_WFP_SUBLAYER_GUID;
    filterV4.displayData.name = (wchar_t *)L"EDR ALE Connect V4";
    filterV4.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filterV4.action.calloutKey = VIGIL_WFP_CALLOUT_V4_GUID;
    filterV4.weight.type = FWP_EMPTY;
    status = FwpmFilterAdd0(g_WfpEngine, &filterV4, NULL, &g_WfpFilterIdV4);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EDR] FwpmFilterAdd0 V4 failed: 0x%08x\n", status);
        return status;
    }

    FWPM_FILTER0 filterV6;
    RtlZeroMemory(&filterV6, sizeof(filterV6));
    filterV6.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    filterV6.subLayerKey = VIGIL_WFP_SUBLAYER_GUID;
    filterV6.displayData.name = (wchar_t *)L"EDR ALE Connect V6";
    filterV6.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filterV6.action.calloutKey = VIGIL_WFP_CALLOUT_V6_GUID;
    filterV6.weight.type = FWP_EMPTY;
    status = FwpmFilterAdd0(g_WfpEngine, &filterV6, NULL, &g_WfpFilterIdV6);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EDR] FwpmFilterAdd0 V6 failed: 0x%08x\n", status);
        return status;
    }

    status = FwpmTransactionCommit0(g_WfpEngine);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EDR] FwpmTransactionCommit0 failed: 0x%08x\n", status);
        return status;
    }
    g_WfpInTransaction = FALSE;

    DbgPrint("[EDR] WFP filters live (ALE connect v4+v6)\n");
    return STATUS_SUCCESS;
}

// Tear down WFP state. Idempotent: each `if` checks whether that step was
// completed in VigilWfpInit. Filters reference callouts so delete in this
// order: filter -> fwpm callout -> sublayer; then close engine; then
// unregister kernel callouts.
static VOID VigilWfpCleanup(VOID)
{
    if (g_WfpEngine != NULL) {
        if (g_WfpInTransaction) {
            FwpmTransactionAbort0(g_WfpEngine);
            g_WfpInTransaction = FALSE;
        }
        if (g_WfpFilterIdV4 != 0) {
            FwpmFilterDeleteById0(g_WfpEngine, g_WfpFilterIdV4);
            g_WfpFilterIdV4 = 0;
        }
        if (g_WfpFilterIdV6 != 0) {
            FwpmFilterDeleteById0(g_WfpEngine, g_WfpFilterIdV6);
            g_WfpFilterIdV6 = 0;
        }
        if (g_WfpFwpmCalloutV4Added) {
            FwpmCalloutDeleteByKey0(g_WfpEngine, &VIGIL_WFP_CALLOUT_V4_GUID);
            g_WfpFwpmCalloutV4Added = FALSE;
        }
        if (g_WfpFwpmCalloutV6Added) {
            FwpmCalloutDeleteByKey0(g_WfpEngine, &VIGIL_WFP_CALLOUT_V6_GUID);
            g_WfpFwpmCalloutV6Added = FALSE;
        }
        if (g_WfpSubLayerAdded) {
            FwpmSubLayerDeleteByKey0(g_WfpEngine, &VIGIL_WFP_SUBLAYER_GUID);
            g_WfpSubLayerAdded = FALSE;
        }
        FwpmEngineClose0(g_WfpEngine);
        g_WfpEngine = NULL;
    }
    if (g_WfpCalloutIdV4 != 0) {
        FwpsCalloutUnregisterById0(g_WfpCalloutIdV4);
        g_WfpCalloutIdV4 = 0;
    }
    if (g_WfpCalloutIdV6 != 0) {
        FwpsCalloutUnregisterById0(g_WfpCalloutIdV6);
        g_WfpCalloutIdV6 = 0;
    }
}

// Phase 1 #1.3: parse a VIGIL_NETWORK_ISOLATE_REQ + IP list and flip
// the global isolation state. The buffer layout is the
// VIGIL_NETWORK_ISOLATE_REQ header followed by `IpCount` × 16 bytes
// of IPv6 addresses (IPv4 mapped). Caller has already validated that
// `inBytes >= sizeof(VIGIL_NETWORK_ISOLATE_REQ)` and that the
// inline IP table fits in the remaining buffer.
//
// We acquire the spinlock for the duration so the WFP classifiers
// don't observe a half-updated `g_AllowedIpCount` / `g_AllowedIps`
// pair (which could let a deny-list IP slip through during the
// replace).
static NTSTATUS VigilNetworkIsolateSet(
    _In_reads_bytes_(inBytes) PVOID buffer,
    _In_ ULONG inBytes)
{
    if (buffer == NULL || inBytes < sizeof(VIGIL_NETWORK_ISOLATE_REQ)) {
        return STATUS_INVALID_PARAMETER;
    }
    PVIGIL_NETWORK_ISOLATE_REQ req = (PVIGIL_NETWORK_ISOLATE_REQ)buffer;
    if (req->IpCount > VIGIL_NETWORK_ISOLATE_MAX_IPS) {
        return STATUS_INVALID_PARAMETER;
    }
    ULONG ipsBytes = (ULONG)req->IpCount * 16u;
    if (sizeof(VIGIL_NETWORK_ISOLATE_REQ) + ipsBytes > inBytes) {
        return STATUS_INVALID_PARAMETER;
    }
    const UINT8 *ipsSrc = (const UINT8 *)buffer + sizeof(VIGIL_NETWORK_ISOLATE_REQ);

    KIRQL irql;
    KeAcquireSpinLock(&g_NetworkIsolateLock, &irql);
    if (req->IpCount > 0) {
        RtlCopyMemory(g_AllowedIps, ipsSrc, ipsBytes);
    }
    g_AllowedIpCount = req->IpCount;
    InterlockedExchange((volatile LONG *)&g_NetworkIsolated, req->Isolate ? 1 : 0);
    KeReleaseSpinLock(&g_NetworkIsolateLock, irql);

    DbgPrint(
        "[EDR] Phase 1 #1.3: network isolation %s (allowlist=%lu)\n",
        req->Isolate ? "ON" : "OFF",
        (unsigned long)req->IpCount);
    return STATUS_SUCCESS;
}

// Registry callback. Argument1 is REG_NOTIFY_CLASS encoded as PVOID. We bump
// per-class counters and always allow the operation. Like file IO, registry
// activity is high-volume so we don't DbgPrint per event.
static NTSTATUS VigilRegistryCallback(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2)
{
    UNREFERENCED_PARAMETER(CallbackContext);
    UNREFERENCED_PARAMETER(Argument2);

    REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    switch (notifyClass) {
    case RegNtPreCreateKeyEx:
        InterlockedIncrement64(&g_RegCreateKeyCount);
        break;
    case RegNtPreSetValueKey:
        InterlockedIncrement64(&g_RegSetValueCount);
        break;
    case RegNtPreDeleteValueKey:
        InterlockedIncrement64(&g_RegDeleteValueCount);
        break;
    case RegNtPreDeleteKey:
        InterlockedIncrement64(&g_RegDeleteKeyCount);
        break;
    default:
        InterlockedIncrement64(&g_RegOtherCount);
        break;
    }
    return STATUS_SUCCESS;
}

// IRP_MJ_CREATE / IRP_MJ_CLOSE: succeed unconditionally. The control device
// has no per-handle state in M4.2; that gets added in M4.5 when each handle
// owns an event-stream cursor.
static NTSTATUS VigilDispatchCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// Kill a target process. PASSIVE_LEVEL only — relies on ZwOpenProcess +
// ZwTerminateProcess which are paged. Dispatch is at PASSIVE_LEVEL so we're
// good. Termination is async (Windows doesn't unblock until ETHREAD list
// drains), but the IOCTL completes once we've delivered the kill.
static NTSTATUS VigilKillProcess(_In_ HANDLE Pid)
{
    InterlockedIncrement64(&g_KillRequests);

    if ((ULONG_PTR)Pid == 0 || (ULONG_PTR)Pid == 4) {
        // PID 0 = idle, 4 = system. Refusing to attempt either is just
        // good hygiene; ZwTerminateProcess on the system process would be
        // catastrophic if it ever succeeded.
        return STATUS_ACCESS_DENIED;
    }

    CLIENT_ID cid = { .UniqueProcess = Pid, .UniqueThread = 0 };
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    HANDLE handle = NULL;
    // PROCESS_TERMINATE = 0x0001. The user-mode header that names the
    // constant isn't visible from kernel mode; using the literal avoids
    // pulling in winnt.h.
    NTSTATUS status = ZwOpenProcess(&handle, 0x0001 /* PROCESS_TERMINATE */, &oa, &cid);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = ZwTerminateProcess(handle, STATUS_ACCESS_DENIED);
    ZwClose(handle);
    if (NT_SUCCESS(status)) {
        InterlockedIncrement64(&g_KillSuccesses);
    }
    return status;
}

static NTSTATUS VigilDispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;

    switch (sp->Parameters.DeviceIoControl.IoControlCode) {
    case VIGIL_IOCTL_GET_STATS: {
        if (sp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(VIGIL_STATS)) {
            status = STATUS_BUFFER_TOO_SMALL;
            information = sizeof(VIGIL_STATS);
            break;
        }
        PVIGIL_STATS out = (PVIGIL_STATS)Irp->AssociatedIrp.SystemBuffer;
        out->ProcessCreateCount         = (UINT64)ReadAcquire64(&g_ProcessCreateCount);
        out->ProcessExitCount           = (UINT64)ReadAcquire64(&g_ProcessExitCount);
        out->ImageLoadCount             = (UINT64)ReadAcquire64(&g_ImageLoadCount);
        out->ImageLoadKernelCount       = (UINT64)ReadAcquire64(&g_ImageLoadKernelCount);
        out->FileCreateCount            = (UINT64)ReadAcquire64(&g_FileCreateCount);
        out->FileCreateSucceededCount   = (UINT64)ReadAcquire64(&g_FileCreateSucceededCount);
        out->RegCreateKeyCount          = (UINT64)ReadAcquire64(&g_RegCreateKeyCount);
        out->RegSetValueCount           = (UINT64)ReadAcquire64(&g_RegSetValueCount);
        out->RegDeleteValueCount        = (UINT64)ReadAcquire64(&g_RegDeleteValueCount);
        out->RegDeleteKeyCount          = (UINT64)ReadAcquire64(&g_RegDeleteKeyCount);
        out->RegOtherCount              = (UINT64)ReadAcquire64(&g_RegOtherCount);
        out->EventsEnqueued             = (UINT64)ReadAcquire64(&g_EventsEnqueued);
        out->EventsDropped              = (UINT64)ReadAcquire64(&g_EventsDropped);
        out->EventsDrained              = (UINT64)ReadAcquire64(&g_EventsDrained);
        out->NetConnectCount            = (UINT64)ReadAcquire64(&g_NetConnectCount);
        out->KillRequests               = (UINT64)ReadAcquire64(&g_KillRequests);
        out->KillSuccesses              = (UINT64)ReadAcquire64(&g_KillSuccesses);
        out->ProcessBlockHits           = (UINT64)ReadAcquire64(&g_ProcessBlockHits);
        out->FileBlockHits              = (UINT64)ReadAcquire64(&g_FileBlockHits);
        out->ProcessBlockEntries        = (UINT32)ReadAcquire(&g_ProcessBlockCount);
        out->FileBlockEntries           = (UINT32)ReadAcquire(&g_FileBlockCount);
        out->SelfProtectHandleStripped  = (UINT64)ReadAcquire64(&g_SelfProtectHandleStripped);
        out->SelfProtectThreadStripped  = (UINT64)ReadAcquire64(&g_SelfProtectThreadStripped);
        out->ProtectedPid               = (UINT64)ReadAcquire64(&g_ProtectedPid);
        out->NetworkIsolationBlockHits  = (UINT64)ReadAcquire64(&g_NetworkIsolationBlockHits);
        out->NetworkIsolated            = (UINT32)ReadAcquire((volatile LONG *)&g_NetworkIsolated);
        {
            KIRQL irql;
            KeAcquireSpinLock(&g_NetworkIsolateLock, &irql);
            out->NetworkAllowedIpCount  = g_AllowedIpCount;
            KeReleaseSpinLock(&g_NetworkIsolateLock, irql);
        }
        status = STATUS_SUCCESS;
        information = sizeof(VIGIL_STATS);
        break;
    }
    case VIGIL_IOCTL_DRAIN_EVENTS: {
        ULONG outBytes = sp->Parameters.DeviceIoControl.OutputBufferLength;
        // The smallest possible event is sizeof(VIGIL_EVENT_HEADER); reject
        // truly undersized buffers so caller knows to grow.
        if (outBytes < sizeof(VIGIL_EVENT_HEADER)) {
            status = STATUS_BUFFER_TOO_SMALL;
            information = sizeof(VIGIL_EVENT_HEADER);
            break;
        }
        UINT32 nEvents = 0;
        UINT32 written = VigilRingDrain(Irp->AssociatedIrp.SystemBuffer, outBytes, &nEvents);
        if (nEvents > 0) {
            InterlockedExchangeAdd64(&g_EventsDrained, (LONG64)nEvents);
        }
        status = STATUS_SUCCESS;
        information = written;
        break;
    }
    case VIGIL_IOCTL_KILL_PROCESS: {
        if (sp->Parameters.DeviceIoControl.InputBufferLength < sizeof(VIGIL_KILL_PROCESS_REQ)) {
            status = STATUS_BUFFER_TOO_SMALL;
            information = sizeof(VIGIL_KILL_PROCESS_REQ);
            break;
        }
        PVIGIL_KILL_PROCESS_REQ req = (PVIGIL_KILL_PROCESS_REQ)Irp->AssociatedIrp.SystemBuffer;
        status = VigilKillProcess((HANDLE)(ULONG_PTR)req->ProcessId);
        information = 0;
        break;
    }
    case VIGIL_IOCTL_BLOCK_ADD:
    case VIGIL_IOCTL_BLOCK_REMOVE: {
        ULONG inLen = sp->Parameters.DeviceIoControl.InputBufferLength;
        if (inLen < sizeof(VIGIL_BLOCK_REQ)) {
            status = STATUS_BUFFER_TOO_SMALL;
            information = sizeof(VIGIL_BLOCK_REQ);
            break;
        }
        PVIGIL_BLOCK_REQ req = (PVIGIL_BLOCK_REQ)Irp->AssociatedIrp.SystemBuffer;
        if (req->PatternBytes == 0 ||
            req->PatternBytes > VIGIL_BLOCK_PATTERN_MAX_BYTES ||
            sizeof(VIGIL_BLOCK_REQ) + req->PatternBytes > inLen)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        const WCHAR *pattern = (const WCHAR *)((UCHAR *)req + sizeof(VIGIL_BLOCK_REQ));
        if (sp->Parameters.DeviceIoControl.IoControlCode == VIGIL_IOCTL_BLOCK_ADD) {
            status = VigilBlockAdd(req->Kind, pattern, (USHORT)req->PatternBytes);
        } else {
            status = VigilBlockRemove(req->Kind, pattern, (USHORT)req->PatternBytes);
        }
        information = 0;
        break;
    }
    case VIGIL_IOCTL_BLOCK_CLEAR: {
        if (sp->Parameters.DeviceIoControl.InputBufferLength < sizeof(VIGIL_BLOCK_CLEAR_REQ)) {
            status = STATUS_BUFFER_TOO_SMALL;
            information = sizeof(VIGIL_BLOCK_CLEAR_REQ);
            break;
        }
        PVIGIL_BLOCK_CLEAR_REQ req = (PVIGIL_BLOCK_CLEAR_REQ)Irp->AssociatedIrp.SystemBuffer;
        status = VigilBlockClear(req->Kind);
        information = 0;
        break;
    }
    case VIGIL_IOCTL_NETWORK_ISOLATE: {
        // Header sanity is checked here; the rest (IpCount upper
        // bound, total size vs input buffer) is in VigilNetworkIsolateSet.
        ULONG inLen = sp->Parameters.DeviceIoControl.InputBufferLength;
        if (inLen < sizeof(VIGIL_NETWORK_ISOLATE_REQ)) {
            status = STATUS_BUFFER_TOO_SMALL;
            information = sizeof(VIGIL_NETWORK_ISOLATE_REQ);
            break;
        }
        status = VigilNetworkIsolateSet(Irp->AssociatedIrp.SystemBuffer, inLen);
        information = 0;
        break;
    }
    case VIGIL_IOCTL_REGISTER_PROTECTED_PID: {
        if (sp->Parameters.DeviceIoControl.InputBufferLength < sizeof(VIGIL_REGISTER_PID_REQ)) {
            status = STATUS_BUFFER_TOO_SMALL;
            information = sizeof(VIGIL_REGISTER_PID_REQ);
            break;
        }
        PVIGIL_REGISTER_PID_REQ req = (PVIGIL_REGISTER_PID_REQ)Irp->AssociatedIrp.SystemBuffer;

        // M7.2.b first-claim lock. The pre-fix code accepted whatever
        // pid the user-mode caller supplied and stored it via a blind
        // InterlockedExchange64, so any process running as SYSTEM could
        // claim self-protection (and a second IOCTL from an attacker
        // could even switch the protected pid to *theirs*, leaving the
        // real agent unprotected and giving ObCallbacks-backed cover
        // to the attacker).
        //
        // Fix shape:
        //   1. The pid we record is the *caller's* via
        //      PsGetCurrentProcessId(), not whatever they put in the
        //      buffer. A user-mode caller cannot spoof that — the
        //      kernel knows who issued the IRP.
        //   2. The store goes through InterlockedCompareExchange64
        //      against an expected value of 0. The slot is first-claim
        //      wins; subsequent IOCTLs from anyone else are rejected
        //      with STATUS_ACCESS_DENIED.
        //   3. As an extra sanity check, if the user-mode caller did
        //      pass a non-zero ProcessId we require it to equal their
        //      actual pid. Catches programming bugs in the agent at
        //      development time without changing the protocol.
        //
        // The slot is cleared automatically when the protected process
        // exits (see VigilProcessNotify, ~L728) so a clean restart of
        // the agent re-claims the slot without operator intervention.
        ULONG64 callerPid = (ULONG64)(ULONG_PTR)PsGetCurrentProcessId();
        if (req->ProcessId != 0 && req->ProcessId != callerPid) {
            status = STATUS_INVALID_PARAMETER;
            information = 0;
            break;
        }
        LONG64 prev = InterlockedCompareExchange64(&g_ProtectedPid, (LONG64)callerPid, 0);
        if (prev != 0 && prev != (LONG64)callerPid) {
            // Slot already claimed by a different process. Don't
            // overwrite — that's the exact bug this fix closes.
            DbgPrint(
                "[EDR] M7.2.b: protected pid claim refused; slot held by %lld (caller pid=%llu)\n",
                prev,
                callerPid);
            status = STATUS_ACCESS_DENIED;
            information = 0;
            break;
        }
        DbgPrint("[EDR] M7.2: protected pid set to %llu\n", callerPid);
        status = STATUS_SUCCESS;
        information = 0;
        break;
    }
    default:
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// ---------------------------------------------------------------------------
// M7.2 self-protection: ObRegisterCallbacks for process + thread access
// ---------------------------------------------------------------------------
//
// We strip access bits that would let a non-self user-mode caller kill,
// suspend, inject into, or read the agent's memory. Read-only inspection
// rights (PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
// SYNCHRONIZE) pass through unchanged so Task Manager / Process Explorer
// still show the agent normally.
//
// Pre-op only — post-op is unused for handle filtering.
//
// Three escape hatches are kept open:
//   * Kernel-mode callers (PreviousMode == KernelMode, OperationInformation
//     ->KernelHandle) pass through unchanged. The kernel's own working-set
//     trimmer, page-fault handler, and similar use HANDLE creation against
//     all processes; blocking them would crash the system.
//   * Self-handles: when the source PID equals the protected PID, the
//     access mask is left untouched. The agent can open handles to itself
//     freely.
//   * Disabled (g_ProtectedPid == 0): fast-path returns immediately. The
//     agent clears the slot when it shuts down cleanly so the driver
//     stops protecting a dead pid that may be reused.

#define VIGIL_DENY_PROCESS_BITS \
    (0x0001u  /* PROCESS_TERMINATE              */ | \
     0x0008u  /* PROCESS_VM_OPERATION           */ | \
     0x0010u  /* PROCESS_VM_READ                */ | \
     0x0020u  /* PROCESS_VM_WRITE               */ | \
     0x0002u  /* PROCESS_CREATE_THREAD          */ | \
     0x0080u  /* PROCESS_SET_INFORMATION        */ | \
     0x0200u  /* PROCESS_SET_QUOTA              */ | \
     0x0800u  /* PROCESS_SUSPEND_RESUME         */)

#define VIGIL_DENY_THREAD_BITS \
    (0x0001u  /* THREAD_TERMINATE               */ | \
     0x0002u  /* THREAD_SUSPEND_RESUME          */ | \
     0x0008u  /* THREAD_GET_CONTEXT             */ | \
     0x0010u  /* THREAD_SET_CONTEXT             */ | \
     0x0020u  /* THREAD_QUERY_INFORMATION       */ | \
     0x0040u  /* THREAD_SET_INFORMATION         */ | \
     0x0080u  /* THREAD_SET_THREAD_TOKEN        */ | \
     0x0100u  /* THREAD_IMPERSONATE             */ | \
     0x0200u  /* THREAD_DIRECT_IMPERSONATION    */)

static OB_PREOP_CALLBACK_STATUS VigilPreOpProcess(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    // Kernel callers pass through unmodified. Includes everything the OS
    // itself does to processes (working set trim, exit handling, etc.).
    if (OperationInformation->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }
    LONG64 protectedPid = ReadAcquire64(&g_ProtectedPid);
    if (protectedPid == 0) {
        return OB_PREOP_SUCCESS;
    }

    // Object is the target process; we need to compare its pid to the
    // protected pid. PsGetProcessId returns the EPROCESS pid.
    PEPROCESS target = (PEPROCESS)OperationInformation->Object;
    if (target == NULL) {
        return OB_PREOP_SUCCESS;
    }
    HANDLE targetPid = PsGetProcessId(target);
    if ((LONG64)(LONG_PTR)targetPid != protectedPid) {
        return OB_PREOP_SUCCESS;
    }

    // Self-source: don't strip access for the protected process opening
    // handles to itself.
    HANDLE callerPid = PsGetCurrentProcessId();
    if ((LONG64)(LONG_PTR)callerPid == protectedPid) {
        return OB_PREOP_SUCCESS;
    }

    ACCESS_MASK *mask = NULL;
    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        mask = &OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
    } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        mask = &OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
    } else {
        return OB_PREOP_SUCCESS;
    }

    ACCESS_MASK before = *mask;
    ACCESS_MASK after  = before & ~(ACCESS_MASK)VIGIL_DENY_PROCESS_BITS;
    if (after != before) {
        *mask = after;
        InterlockedIncrement64(&g_SelfProtectHandleStripped);
    }
    return OB_PREOP_SUCCESS;
}

static OB_PREOP_CALLBACK_STATUS VigilPreOpThread(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }
    LONG64 protectedPid = ReadAcquire64(&g_ProtectedPid);
    if (protectedPid == 0) {
        return OB_PREOP_SUCCESS;
    }

    PETHREAD targetThread = (PETHREAD)OperationInformation->Object;
    if (targetThread == NULL) {
        return OB_PREOP_SUCCESS;
    }
    HANDLE targetPid = PsGetThreadProcessId(targetThread);
    if ((LONG64)(LONG_PTR)targetPid != protectedPid) {
        return OB_PREOP_SUCCESS;
    }

    HANDLE callerPid = PsGetCurrentProcessId();
    if ((LONG64)(LONG_PTR)callerPid == protectedPid) {
        return OB_PREOP_SUCCESS;
    }

    ACCESS_MASK *mask = NULL;
    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        mask = &OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
    } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        mask = &OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
    } else {
        return OB_PREOP_SUCCESS;
    }

    ACCESS_MASK before = *mask;
    ACCESS_MASK after  = before & ~(ACCESS_MASK)VIGIL_DENY_THREAD_BITS;
    if (after != before) {
        *mask = after;
        InterlockedIncrement64(&g_SelfProtectThreadStripped);
    }
    return OB_PREOP_SUCCESS;
}

static NTSTATUS VigilSelfProtectInit(VOID)
{
    if (g_ObRegistrationHandle != NULL) {
        return STATUS_SUCCESS;  // already up
    }

    // Two op-registrations: one for process handles, one for thread handles.
    // Both register HANDLE_CREATE + HANDLE_DUPLICATE. The pre-op handlers do
    // the actual access-mask filtering.
    static OB_OPERATION_REGISTRATION ops[2];
    RtlZeroMemory(ops, sizeof(ops));
    ops[0].ObjectType   = PsProcessType;
    ops[0].Operations   = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    ops[0].PreOperation = VigilPreOpProcess;
    ops[1].ObjectType   = PsThreadType;
    ops[1].Operations   = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    ops[1].PreOperation = VigilPreOpThread;

    // Altitude must be unique across all ObRegisterCallbacks consumers on
    // the system; reuse our minifilter base 385100 + 1 so it sits beside us
    // numerically without colliding.
    UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"385101");

    OB_CALLBACK_REGISTRATION reg;
    RtlZeroMemory(&reg, sizeof(reg));
    reg.Version                    = OB_FLT_REGISTRATION_VERSION;
    reg.OperationRegistrationCount = 2;
    reg.Altitude                   = altitude;
    reg.RegistrationContext        = NULL;
    reg.OperationRegistration      = ops;

    NTSTATUS status = ObRegisterCallbacks(&reg, &g_ObRegistrationHandle);
    if (!NT_SUCCESS(status)) {
        g_ObRegistrationHandle = NULL;
        DbgPrint("[EDR] ObRegisterCallbacks failed: 0x%08x\n", status);
        return status;
    }
    DbgPrint("[EDR] M7.2: ObCallbacks registered at altitude 385101\n");
    return STATUS_SUCCESS;
}

static VOID VigilSelfProtectCleanup(VOID)
{
    if (g_ObRegistrationHandle != NULL) {
        ObUnRegisterCallbacks(g_ObRegistrationHandle);
        g_ObRegistrationHandle = NULL;
    }
    InterlockedExchange64(&g_ProtectedPid, 0);
}
