// edr.h — shared types and constants between kernel driver and user-mode agent.
//
// IOCTL codes and event structures will grow as M4.x lands. M4.1 only needs
// the device name + symbolic link so user-mode can later attach.

#pragma once

#define EDR_DRIVER_NAME      L"edr"
#define EDR_DRIVER_VERSION   L"0.1.0"

// Filter Manager altitude. PoC range; should be registered with Microsoft for
// production. 385100 sits in the FSFilter Activity Monitor range
// (380000-389999).
#define EDR_ALTITUDE         L"385100"

// Device names for the IPC channel that lands in M4.5 (inverted IOCTL).
#define EDR_DEVICE_NAME      L"\\Device\\edr"
#define EDR_SYMLINK_NAME     L"\\??\\edr"
#define EDR_USERMODE_PATH    L"\\\\.\\edr"
