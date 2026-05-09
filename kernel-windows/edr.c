// edr.c — M4.1 minifilter skeleton.
//
// Goal of M4.1: register a Filter Manager minifilter that loads, stays loaded,
// and shows up in `fltmc instances` on the lab VM. No callbacks, no IPC, no
// process/image hooks yet — those land in M4.2-M4.5.

#include <fltKernel.h>
#include <ntddk.h>

#include "edr.h"

DRIVER_INITIALIZE DriverEntry;

static FLT_PREOP_CALLBACK_STATUS EdrPreOperationStub(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

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

// Module-global filter handle. Released in EdrFilterUnload.
static PFLT_FILTER g_FilterHandle = NULL;

// M4.1: a single registration entry for IRP_MJ_CREATE. The pre-op callback is
// a stub that returns "no callback" so we don't perturb file IO yet — it just
// proves the registration plumbing works. Real pre/post-op handlers land in
// M4.3.
static const FLT_OPERATION_REGISTRATION g_Callbacks[] = {
    { IRP_MJ_CREATE,           0, EdrPreOperationStub, NULL },
    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION g_FilterRegistration = {
    sizeof(FLT_REGISTRATION),     // Size
    FLT_REGISTRATION_VERSION,     // Version
    0,                            // Flags
    NULL,                         // ContextRegistration
    g_Callbacks,                  // OperationRegistration
    EdrFilterUnload,              // FilterUnloadCallback
    EdrInstanceSetup,             // InstanceSetupCallback
    EdrInstanceQueryTeardown,     // InstanceQueryTeardownCallback
    EdrInstanceTeardownStart,     // InstanceTeardownStartCallback
    EdrInstanceTeardownComplete,  // InstanceTeardownCompleteCallback
    NULL,                         // GenerateFileNameCallback
    NULL,                         // NormalizeNameComponentCallback
    NULL,                         // NormalizeContextCleanupCallback
    NULL,                         // TransactionNotificationCallback
    NULL,                         // NormalizeNameComponentExCallback
    NULL,                         // SectionNotificationCallback
};

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status = FltRegisterFilter(DriverObject, &g_FilterRegistration, &g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EDR] FltRegisterFilter failed: 0x%08x\n", status);
        return status;
    }

    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EDR] FltStartFiltering failed: 0x%08x\n", status);
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
        return status;
    }

    DbgPrint("[EDR] DriverEntry OK (M4.1 skeleton)\n");
    return STATUS_SUCCESS;
}

static NTSTATUS EdrFilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    if (g_FilterHandle != NULL) {
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
    return STATUS_SUCCESS;  // attach to every volume
}

static NTSTATUS EdrInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;  // allow detach
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

static FLT_PREOP_CALLBACK_STATUS EdrPreOperationStub(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
