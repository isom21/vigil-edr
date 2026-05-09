# test-get-stats.ps1 — open \\.\edr and read EDR_STATS via IOCTL_EDR_GET_STATS.
#
# Used during M4.2-M4.4 to confirm the kernel callbacks are firing without
# needing DebugView.
#
# Usage:
#   .\test-get-stats.ps1            print stats once
#   .\test-get-stats.ps1 -Watch     print every second until Ctrl-C
#   .\test-get-stats.ps1 -Spawn N   spawn N notepad processes between two reads
param(
    [switch]$Watch,
    [int]$Spawn = 0
)

$ErrorActionPreference = 'Stop'

# CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, function=0x800, METHOD_BUFFERED=0,
#          FILE_ANY_ACCESS=0) = 0x222000
$IOCTL_EDR_GET_STATS = 0x222000

if (-not ('Edr.Native' -as [type])) {
    Add-Type -Namespace Edr -Name Native -MemberDefinition @'
[System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
public struct EDR_STATS {
    public ulong ProcessCreateCount;
    public ulong ProcessExitCount;
    public ulong ImageLoadCount;
    public ulong ImageLoadKernelCount;
    public ulong FileCreateCount;
    public ulong FileCreateSucceededCount;
    public ulong RegCreateKeyCount;
    public ulong RegSetValueCount;
    public ulong RegDeleteValueCount;
    public ulong RegDeleteKeyCount;
    public ulong RegOtherCount;
    public ulong EventsEnqueued;
    public ulong EventsDropped;
    public ulong EventsDrained;
    public ulong NetConnectCount;
    public ulong KillRequests;
    public ulong KillSuccesses;
}

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

function Get-EdrStats {
    # PowerShell parses 0x80000000 as a signed Int32 (= -2147483648), which
    # CreateFileW's uint dwDesiredAccess parameter rejects. Cast explicitly.
    $GENERIC_READ = [uint32]2147483648  # 0x80000000
    $FILE_SHARE_READ_WRITE = [uint32]3
    $OPEN_EXISTING = [uint32]3
    $h = [Edr.Native]::CreateFileW("\\.\edr", $GENERIC_READ, $FILE_SHARE_READ_WRITE, [IntPtr]::Zero, $OPEN_EXISTING, 0, [IntPtr]::Zero)
    if ($h -eq [IntPtr]::new(-1)) {
        throw "CreateFile \\.\edr failed: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    try {
        $size = [System.Runtime.InteropServices.Marshal]::SizeOf([type][Edr.Native+EDR_STATS])
        $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size)
        try {
            $bytesReturned = 0
            $ok = [Edr.Native]::DeviceIoControl($h, $IOCTL_EDR_GET_STATS, [IntPtr]::Zero, 0, $buf, $size, [ref]$bytesReturned, [IntPtr]::Zero)
            if (-not $ok) {
                throw "DeviceIoControl failed: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
            }
            return [System.Runtime.InteropServices.Marshal]::PtrToStructure($buf, [type][Edr.Native+EDR_STATS])
        } finally {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
        }
    } finally {
        [void][Edr.Native]::CloseHandle($h)
    }
}

function Format-Stats($s) {
    @(
        (Get-Date).ToString('HH:mm:ss.fff')
        "proc=$($s.ProcessCreateCount)/$($s.ProcessExitCount)"
        "img=$($s.ImageLoadCount)k:$($s.ImageLoadKernelCount)"
        "file=$($s.FileCreateCount)/$($s.FileCreateSucceededCount)"
        "reg=c:$($s.RegCreateKeyCount)/s:$($s.RegSetValueCount)/dv:$($s.RegDeleteValueCount)/dk:$($s.RegDeleteKeyCount)/o:$($s.RegOtherCount)"
        "net.conn=$($s.NetConnectCount)"
        "kill=$($s.KillSuccesses)/$($s.KillRequests)"
        "ring=enq:$($s.EventsEnqueued)/drop:$($s.EventsDropped)/drain:$($s.EventsDrained)"
    ) -join ' '
}

if ($Spawn -gt 0) {
    Write-Host "before:"
    $before = Get-EdrStats
    Write-Host (Format-Stats $before)
    Write-Host "spawning $Spawn processes..."
    1..$Spawn | ForEach-Object {
        $p = Start-Process -PassThru -FilePath cmd.exe -ArgumentList '/c','exit'
        $p.WaitForExit()
    } | Out-Null
    Start-Sleep -Milliseconds 200
    Write-Host "after:"
    $after = Get-EdrStats
    Write-Host (Format-Stats $after)
    Write-Host ('delta: proc.create=+{0} proc.exit=+{1} img.load=+{2} img.kernel=+{3} file.create=+{4} file.create.ok=+{5} reg.create=+{6} reg.set=+{7} reg.del.val=+{8} reg.del.key=+{9} reg.other=+{10}' -f `
        ($after.ProcessCreateCount - $before.ProcessCreateCount),
        ($after.ProcessExitCount   - $before.ProcessExitCount),
        ($after.ImageLoadCount     - $before.ImageLoadCount),
        ($after.ImageLoadKernelCount - $before.ImageLoadKernelCount),
        ($after.FileCreateCount    - $before.FileCreateCount),
        ($after.FileCreateSucceededCount - $before.FileCreateSucceededCount),
        ($after.RegCreateKeyCount    - $before.RegCreateKeyCount),
        ($after.RegSetValueCount     - $before.RegSetValueCount),
        ($after.RegDeleteValueCount  - $before.RegDeleteValueCount),
        ($after.RegDeleteKeyCount    - $before.RegDeleteKeyCount),
        ($after.RegOtherCount        - $before.RegOtherCount))
    return
}

if ($Watch) {
    while ($true) {
        Write-Host (Format-Stats (Get-EdrStats))
        Start-Sleep -Seconds 1
    }
} else {
    Write-Host (Format-Stats (Get-EdrStats))
}
