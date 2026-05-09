# test-drain.ps1 — drain events from the kernel ring via IOCTL_EDR_DRAIN_EVENTS
# and pretty-print each one. Used during M4.5 to verify the ring buffer +
# event format end-to-end.
#
# Usage:
#   .\test-drain.ps1                drain once and print
#   .\test-drain.ps1 -Watch         drain every 200ms and print
#   .\test-drain.ps1 -Spawn N       spawn N cmd.exe, then drain, then print
param(
    [switch]$Watch,
    [int]$Spawn = 0
)

$ErrorActionPreference = 'Stop'

$IOCTL_EDR_DRAIN_EVENTS = 0x222004   # CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, 0x801, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0)
$BUF_SIZE = 256 * 1024               # 256 KB drain buffer

# EDR_EVENT_KIND_* values (must match edr.h)
$EVENT_KIND = @{
    1 = 'process.start'
    2 = 'process.exit'
    3 = 'image.load'
    4 = 'file.create'
    5 = 'reg.create.key'
    6 = 'reg.set.value'
    7 = 'reg.delete.key'
    8 = 'reg.delete.value'
}

if (-not ('Edr.NativeDrain' -as [type])) {
    Add-Type -Namespace Edr -Name NativeDrain -MemberDefinition @'
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

function Drain-Events {
    $GENERIC_READ = [uint32]2147483648  # 0x80000000
    $h = [Edr.NativeDrain]::CreateFileW("\\.\edr", $GENERIC_READ, [uint32]3, [IntPtr]::Zero, [uint32]3, 0, [IntPtr]::Zero)
    if ($h -eq [IntPtr]::new(-1)) { throw "CreateFile \\.\edr failed: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())" }
    try {
        $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($BUF_SIZE)
        try {
            $bytesReturned = 0
            $ok = [Edr.NativeDrain]::DeviceIoControl($h, $IOCTL_EDR_DRAIN_EVENTS, [IntPtr]::Zero, 0, $buf, $BUF_SIZE, [ref]$bytesReturned, [IntPtr]::Zero)
            if (-not $ok) { throw "DeviceIoControl failed: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())" }
            $bytes = New-Object byte[] $bytesReturned
            [System.Runtime.InteropServices.Marshal]::Copy($buf, $bytes, 0, [int]$bytesReturned)
            return ,$bytes
        } finally {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
        }
    } finally {
        [void][Edr.NativeDrain]::CloseHandle($h)
    }
}

function Decode-Events($bytes) {
    $result = New-Object System.Collections.Generic.List[object]
    $i = 0
    while ($i -lt $bytes.Length) {
        if ($i + 24 -gt $bytes.Length) { break }
        $size = [BitConverter]::ToUInt32($bytes, $i)
        $kind = [BitConverter]::ToUInt32($bytes, $i + 4)
        $tsNt = [BitConverter]::ToUInt64($bytes, $i + 8)
        $pid_ = [BitConverter]::ToUInt64($bytes, $i + 16)
        if ($size -lt 24 -or $i + $size -gt $bytes.Length) { break }
        # NT epoch: 100ns ticks since 1601-01-01 UTC
        $ts = [DateTime]::FromFileTimeUtc([long]$tsNt).ToString('HH:mm:ss.fff')
        $evt = [pscustomobject]@{
            kind = $EVENT_KIND[[int]$kind]
            ts   = $ts
            pid  = $pid_
        }
        if ($kind -eq 1) {
            # process.start
            $parent = [BitConverter]::ToUInt64($bytes, $i + 24)
            $imgLen = [BitConverter]::ToUInt16($bytes, $i + 32)
            $cmdLen = [BitConverter]::ToUInt16($bytes, $i + 34)
            $strStart = $i + 36
            $imgName = if ($imgLen -gt 0) { [System.Text.Encoding]::Unicode.GetString($bytes, $strStart, $imgLen) } else { '' }
            $cmdLine = if ($cmdLen -gt 0) { [System.Text.Encoding]::Unicode.GetString($bytes, $strStart + $imgLen, $cmdLen) } else { '' }
            $evt | Add-Member parent $parent -PassThru | Out-Null
            $evt | Add-Member image $imgName -PassThru | Out-Null
            $evt | Add-Member cmd $cmdLine -PassThru | Out-Null
        }
        $result.Add($evt) | Out-Null
        $i += $size
    }
    return $result
}

function Print-Event($e) {
    if ($e.kind -eq 'process.start') {
        "{0,-12} {1,-12} pid={2} parent={3} image={4} cmd={5}" -f $e.ts, $e.kind, $e.pid, $e.parent, $e.image, $e.cmd
    } else {
        "{0,-12} {1,-12} pid={2}" -f $e.ts, $e.kind, $e.pid
    }
}

if ($Spawn -gt 0) {
    # Drain once to flush anything pre-existing.
    [void](Drain-Events)
    Write-Host "spawning $Spawn cmd.exe processes..."
    1..$Spawn | ForEach-Object {
        $p = Start-Process -PassThru -FilePath cmd.exe -ArgumentList '/c','exit'
        $p.WaitForExit()
    } | Out-Null
    Start-Sleep -Milliseconds 250
    Write-Host "events:"
    $bytes = Drain-Events
    $events = Decode-Events $bytes
    Write-Host ("drained {0} bytes, {1} events" -f $bytes.Length, $events.Count)
    foreach ($e in $events) { Write-Host (Print-Event $e) }
    return
}

if ($Watch) {
    while ($true) {
        $bytes = Drain-Events
        $events = Decode-Events $bytes
        foreach ($e in $events) { Write-Host (Print-Event $e) }
        Start-Sleep -Milliseconds 200
    }
} else {
    $bytes = Drain-Events
    $events = Decode-Events $bytes
    Write-Host ("drained {0} bytes, {1} events" -f $bytes.Length, $events.Count)
    foreach ($e in $events) { Write-Host (Print-Event $e) }
}
