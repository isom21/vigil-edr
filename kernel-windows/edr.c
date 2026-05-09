// edr.c — M4.2: minifilter skeleton + process create + image load callbacks
// + control device with IOCTL_EDR_GET_STATS so user-mode can verify the
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

#include "edr.h"

DRIVER_INITIALIZE DriverEntry;

static FLT_PREOP_CALLBACK_STATUS EdrPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);
static FLT_POSTOP_CALLBACK_STATUS EdrPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

static NTSTATUS EdrFilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);
static NTSTATUS EdrInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);
static NTSTATUS EdrInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);
static VOID EdrInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);
static VOID EdrInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);

static VOID EdrCreateProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);
static VOID EdrLoadImageNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo);
static NTSTATUS EdrRegistryCallback(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2);

static NTSTATUS EdrDispatchCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
static NTSTATUS EdrDispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);

static PFLT_FILTER     g_FilterHandle  = NULL;
static PDEVICE_OBJECT  g_DeviceObject  = NULL;
static UNICODE_STRING  g_DeviceName    = RTL_CONSTANT_STRING(EDR_DEVICE_NAME);
static UNICODE_STRING  g_SymLinkName   = RTL_CONSTANT_STRING(EDR_SYMLINK_NAME);

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

// Track which subsystems registered successfully so unload only undoes work
// it actually did. Without this a partial DriverEntry failure leads to
// double-unregister or unload-without-register.
static BOOLEAN g_PsNotifyCreateRegistered = FALSE;
static BOOLEAN g_PsNotifyImageRegistered  = FALSE;
static BOOLEAN g_SymLinkCreated           = FALSE;
static BOOLEAN g_RegCallbackRegistered    = FALSE;
static LARGE_INTEGER g_RegCookie          = { 0 };

static const FLT_OPERATION_REGISTRATION g_Callbacks[] = {
    { IRP_MJ_CREATE,           0, EdrPreCreate, EdrPostCreate },
    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION g_FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    g_Callbacks,
    EdrFilterUnload,
    EdrInstanceSetup,
    EdrInstanceQueryTeardown,
    EdrInstanceTeardownStart,
    EdrInstanceTeardownComplete,
    NULL, NULL, NULL, NULL, NULL, NULL,
};

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status = FltRegisterFilter(DriverObject, &g_FilterRegistration, &g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EDR] FltRegisterFilter failed: 0x%08x\n", status);
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

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = EdrDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = EdrDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = EdrDispatchDeviceControl;

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

    status = PsSetCreateProcessNotifyRoutineEx(EdrCreateProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EDR] PsSetCreateProcessNotifyRoutineEx failed: 0x%08x\n", status);
        goto fail_unwind;
    }
    g_PsNotifyCreateRegistered = TRUE;

    status = PsSetLoadImageNotifyRoutine(EdrLoadImageNotify);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EDR] PsSetLoadImageNotifyRoutine failed: 0x%08x\n", status);
        goto fail_unwind;
    }
    g_PsNotifyImageRegistered = TRUE;

    {
        UNICODE_STRING regAltitude = RTL_CONSTANT_STRING(L"385100");
        status = CmRegisterCallbackEx(
            EdrRegistryCallback,
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

    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EDR] FltStartFiltering failed: 0x%08x\n", status);
        goto fail_unwind;
    }

    DbgPrint("[EDR] DriverEntry OK (M4.2)\n");
    return STATUS_SUCCESS;

fail_unwind:
    if (g_RegCallbackRegistered) {
        CmUnRegisterCallback(g_RegCookie);
        g_RegCallbackRegistered = FALSE;
    }
    if (g_PsNotifyImageRegistered) {
        PsRemoveLoadImageNotifyRoutine(EdrLoadImageNotify);
        g_PsNotifyImageRegistered = FALSE;
    }
    if (g_PsNotifyCreateRegistered) {
        PsSetCreateProcessNotifyRoutineEx(EdrCreateProcessNotify, TRUE);
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
    return status;
}

static NTSTATUS EdrFilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    // Unregister callbacks before deleting the device; once unregistered no
    // new callbacks can fire and any in-flight callback finishes before the
    // unregister call returns.
    if (g_RegCallbackRegistered) {
        CmUnRegisterCallback(g_RegCookie);
        g_RegCallbackRegistered = FALSE;
    }
    if (g_PsNotifyImageRegistered) {
        PsRemoveLoadImageNotifyRoutine(EdrLoadImageNotify);
        g_PsNotifyImageRegistered = FALSE;
    }
    if (g_PsNotifyCreateRegistered) {
        PsSetCreateProcessNotifyRoutineEx(EdrCreateProcessNotify, TRUE);
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
    DbgPrint("[EDR] Unload\n");
    return STATUS_SUCCESS;
}

static NTSTATUS EdrInstanceSetup(
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

static NTSTATUS EdrInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

static VOID EdrInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
}

static VOID EdrInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
}

// Pre-op for IRP_MJ_CREATE. Bumps the file-create counter and asks the Filter
// Manager to call us back via EdrPostCreate so we can record the open
// outcome. We don't filter or modify the IRP in M4.3 — that's M5.
//
// Volume of these callbacks is high (10s-100s of opens per second on an
// idle machine), so we deliberately avoid DbgPrint here. M4.5 will replace
// the counter bump with an enqueue-event-for-user-mode call.
static FLT_PREOP_CALLBACK_STATUS EdrPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);

    InterlockedIncrement64(&g_FileCreateCount);
    *CompletionContext = NULL;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

// Post-op fires after the file system has handled the IRP. Data->IoStatus
// has the final status. We only count succeeded opens for now; useful as a
// signal that the FS actually executed the IRP (vs. denied / failed).
static FLT_POSTOP_CALLBACK_STATUS EdrPostCreate(
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
static VOID EdrCreateProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo != NULL) {
        InterlockedIncrement64(&g_ProcessCreateCount);
        DbgPrint("[EDR] proc.create pid=%llu parent=%llu image=%wZ\n",
                 (ULONG64)(ULONG_PTR)ProcessId,
                 (ULONG64)(ULONG_PTR)CreateInfo->ParentProcessId,
                 CreateInfo->ImageFileName);
    } else {
        InterlockedIncrement64(&g_ProcessExitCount);
        DbgPrint("[EDR] proc.exit pid=%llu\n", (ULONG64)(ULONG_PTR)ProcessId);
    }
}

// Image load. Runs at PASSIVE_LEVEL. ImageInfo->SystemModeImage is TRUE for
// drivers loading into the kernel; FALSE for user-mode image loads.
static VOID EdrLoadImageNotify(
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

// Registry callback. Argument1 is REG_NOTIFY_CLASS encoded as PVOID. We bump
// per-class counters and always allow the operation. Like file IO, registry
// activity is high-volume so we don't DbgPrint per event.
static NTSTATUS EdrRegistryCallback(
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
static NTSTATUS EdrDispatchCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS EdrDispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;

    switch (sp->Parameters.DeviceIoControl.IoControlCode) {
    case EDR_IOCTL_GET_STATS: {
        if (sp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(EDR_STATS)) {
            status = STATUS_BUFFER_TOO_SMALL;
            information = sizeof(EDR_STATS);
            break;
        }
        PEDR_STATS out = (PEDR_STATS)Irp->AssociatedIrp.SystemBuffer;
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
        status = STATUS_SUCCESS;
        information = sizeof(EDR_STATS);
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
