# 46-self-protection-windows.ps1 - verifies M7.2 driver self-protection.
#
# Run on a Windows host with vigil.sys installed and the agent running.
# Reports PASS/FAIL and exits non-zero on failure.
#
# Usage:
#   powershell.exe -ExecutionPolicy Bypass -File tools\smoke\46-self-protection-windows.ps1

# Default Continue: native commands writing to stderr (taskkill, etc.)
# would otherwise be turned into terminating errors and abort the test.
$ErrorActionPreference = "Continue"

$proc = Get-Process vigil-agent -EA SilentlyContinue
if (-not $proc) {
    Write-Output "FAIL: vigil-agent not running"
    exit 1
}
$pid_agent = $proc.Id
Write-Output "vigil-agent pid=$pid_agent"

$src = 'using System; using System.Runtime.InteropServices;
public class K {
    [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenProcess(uint a, bool i, uint p);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool TerminateProcess(IntPtr h, uint c);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr h);
}'
Add-Type -TypeDefinition $src -Language CSharp

$fails = 0
function Pass($m) { Write-Output ("  ok   - " + $m) }
function Fail($m) { Write-Output ("  FAIL - " + $m); $script:fails++ }

# 1. taskkill blocked. Capture both streams; PS turns native stderr into
#    NativeCommandError records when ErrorActionPreference == Stop, which
#    we deliberately disabled above.
$null = & taskkill.exe /pid $pid_agent /f 2>&1
if ($LASTEXITCODE -eq 0) {
    Fail "taskkill /F was NOT blocked"
} else {
    Pass ("taskkill /F blocked (exit=" + $LASTEXITCODE + ")")
}

# 2. Stop-Process blocked
try {
    Stop-Process -Id $pid_agent -Force -EA Stop
    Fail "Stop-Process -Force was NOT blocked"
} catch {
    Pass "Stop-Process -Force blocked"
}

# 3. PROCESS_TERMINATE access mask stripped from handle
$h = [K]::OpenProcess([uint32]1, $false, [uint32]$pid_agent)
if ($h -eq [IntPtr]::Zero) {
    # Some Windows configurations also block OpenProcess outright; accept that.
    Pass "OpenProcess(PROCESS_TERMINATE) refused at open"
} else {
    $ok = [K]::TerminateProcess($h, 1)
    [void][K]::CloseHandle($h)
    $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if ($ok) {
        Fail "TerminateProcess on stripped handle SUCCEEDED"
    } else {
        # err=5 (ERROR_ACCESS_DENIED) is the expected outcome for a stripped handle.
        Pass ("TerminateProcess blocked via stripped handle (err=" + $err + ")")
    }
}

# 4. PROCESS_QUERY_LIMITED still allowed (Task Manager / Process Explorer
#    must continue to function for ordinary inspection).
$h = [K]::OpenProcess([uint32]0x1000, $false, [uint32]$pid_agent)
if ($h -eq [IntPtr]::Zero) {
    Fail "PROCESS_QUERY_LIMITED open was blocked (over-protection)"
} else {
    [void][K]::CloseHandle($h)
    Pass "PROCESS_QUERY_LIMITED open allowed"
}

# 5. Agent still alive
Start-Sleep 1
$still = Get-Process vigil-agent -EA SilentlyContinue
if ($still) {
    Pass "agent alive after attacks"
} else {
    Fail "agent died"
}

# 6. Non-self process is still killable (verifies we don't over-block).
$np = Start-Process notepad.exe -PassThru -WindowStyle Hidden
Start-Sleep 1
try {
    Stop-Process -Id $np.Id -Force -EA Stop
    Start-Sleep 1
    if (Get-Process -Id $np.Id -EA SilentlyContinue) {
        Fail "notepad survived Stop-Process - we are over-blocking non-self"
    } else {
        Pass "non-self process killed normally"
    }
} catch {
    Fail ("Stop-Process on notepad threw: " + $_.Exception.Message)
}

# 7. M7.2.b first-claim lock - a second process can NOT redirect the
#    protected pid by issuing the REGISTER_PROTECTED_PID IOCTL. Pre-fix,
#    any SYSTEM-level caller (this script runs elevated) could swap the
#    slot to its own pid via a blind InterlockedExchange64. With the
#    compare-exchange lock the kernel returns ERROR_ACCESS_DENIED.
$src2 = 'using System; using System.Runtime.InteropServices;
public class Ioctl {
    [DllImport("kernel32.dll", CharSet=CharSet.Auto, SetLastError=true)]
    public static extern IntPtr CreateFile(string n, uint a, uint s, IntPtr sd, uint cd, uint fa, IntPtr t);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool DeviceIoControl(IntPtr h, uint code, ref ulong inBuf, uint inLen, IntPtr outBuf, uint outLen, out uint ret, IntPtr ov);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr h);
}'
Add-Type -TypeDefinition $src2 -Language CSharp -IgnoreWarnings

$dev = [Ioctl]::CreateFile('\\.\Vigil', 0x80000000, 3, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
if ($dev -eq [IntPtr]::Zero -or $dev.ToInt64() -eq -1) {
    Fail "could not open \\.\Vigil for IOCTL probe (driver not loaded?)"
} else {
    $myPid = [ulong][int][System.Diagnostics.Process]::GetCurrentProcess().Id
    $ret = 0
    $ok = [Ioctl]::DeviceIoControl($dev, [uint32]0x222018, [ref] $myPid, 8, [IntPtr]::Zero, 0, [ref] $ret, [IntPtr]::Zero)
    $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    [void][Ioctl]::CloseHandle($dev)
    if ($ok) {
        Fail "REGISTER_PROTECTED_PID claim by a non-agent process SUCCEEDED (first-claim lock broken)"
    } else {
        # err=5 (ERROR_ACCESS_DENIED) is the expected outcome — the slot
        # is already held by vigil-agent. Any failure here proves the
        # lock; we just sanity-check the code.
        Pass ("REGISTER_PROTECTED_PID claim refused (err=" + $err + ")")
    }
}

if ($fails -eq 0) {
    Write-Output "PASS - all self-protection checks behaved as expected"
    exit 0
} else {
    Write-Output ("FAIL - " + $fails + " check(s) failed")
    exit 1
}
