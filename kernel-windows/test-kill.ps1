# test-kill.ps1 - issue IOCTL_EDR_KILL_PROCESS for a target PID.
#
# Usage:
#   .\test-kill.ps1 -TargetPid 1234   kill PID 1234
#   .\test-kill.ps1 -SpawnTest        spawn a notepad, then kill it via the driver
param(
    [int]$TargetPid,
    [switch]$SpawnTest
)

$ErrorActionPreference = 'Stop'

# CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, function=0x802, METHOD_BUFFERED=0,
#          FILE_ANY_ACCESS=0).
$IOCTL_EDR_KILL_PROCESS = 0x222008

if (-not ('Edr.NativeKill' -as [type])) {
    Add-Type -Namespace Edr -Name NativeKill -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
public static extern System.IntPtr CreateFileW(
    string lpFileName, uint dwDesiredAccess, uint dwShareMode,
    System.IntPtr lpSecurityAttributes, uint dwCreationDisposition,
    uint dwFlagsAndAttributes, System.IntPtr hTemplateFile);
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
public static extern bool DeviceIoControl(
    System.IntPtr hDevice, uint dwIoControlCode,
    System.IntPtr lpInBuffer, uint nInBufferSize,
    System.IntPtr lpOutBuffer, uint nOutBufferSize,
    out uint lpBytesReturned, System.IntPtr lpOverlapped);
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
public static extern bool CloseHandle(System.IntPtr hObject);
'@
}

function Send-EdrKill {
    param([Parameter(Mandatory)][long]$Target)

    $GENERIC_RW = [uint32]3221225472
    $h = [Edr.NativeKill]::CreateFileW("\\.\edr", $GENERIC_RW, [uint32]3, [IntPtr]::Zero, [uint32]3, 0, [IntPtr]::Zero)
    if ($h -eq [IntPtr]::new(-1)) {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw ('CreateFile \\.\edr failed: ' + $err)
    }
    try {
        $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(8)
        try {
            [System.Runtime.InteropServices.Marshal]::WriteInt64($buf, $Target)
            $bytesReturned = 0
            $ok = [Edr.NativeKill]::DeviceIoControl($h, $IOCTL_EDR_KILL_PROCESS, $buf, 8, [IntPtr]::Zero, 0, [ref]$bytesReturned, [IntPtr]::Zero)
            if (-not $ok) {
                $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                throw ('DeviceIoControl(IOCTL_EDR_KILL_PROCESS, pid=' + $Target + ') failed: ' + $err)
            }
        } finally {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
        }
    } finally {
        [void][Edr.NativeKill]::CloseHandle($h)
    }
}

if ($SpawnTest) {
    Write-Host 'spawning notepad as kill target...'
    $proc = Start-Process -PassThru -FilePath notepad.exe
    Start-Sleep -Milliseconds 500
    if (-not (Get-Process -Id $proc.Id -ErrorAction SilentlyContinue)) {
        throw ('notepad exited before kill could land (pid=' + $proc.Id + ')')
    }
    Write-Host ('notepad pid=' + $proc.Id + ' alive - killing via driver IOCTL...')
    Send-EdrKill -Target $proc.Id
    Start-Sleep -Milliseconds 500
    $still = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
    if ($still) {
        Write-Host 'FAIL: process still alive'
        exit 1
    }
    Write-Host 'OK: process is gone'
    exit 0
}

if ($TargetPid) {
    Send-EdrKill -Target $TargetPid
    Write-Host ('kill IOCTL delivered for pid=' + $TargetPid)
    exit 0
}

Write-Host 'usage: .\test-kill.ps1 -TargetPid <PID> | -SpawnTest'
