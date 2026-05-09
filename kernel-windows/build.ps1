# build.ps1 — hand-rolled minifilter build for M4.1.
#
# Drives cl.exe + link.exe + signtool.exe directly so we don't depend on the
# WDK Visual Studio extension being installed in VS Build Tools. Switch to a
# .vcxproj when the manual switches outgrow this script (M4.5+).
#
# Usage:
#   .\build.ps1                  build edr.sys + sign
#   .\build.ps1 -Clean           remove artifacts
#
# Prerequisites on the build host:
#   - VS Build Tools 2022 with MSVC v14.44+ at the default install path
#   - Windows SDK 10.0.26100 + WDK 10.0.26100 installed at
#     C:\Program Files (x86)\Windows Kits\10
#   - Test cert thumbprint at C:\toolchain\edr-cert-thumbprint.txt
param(
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

$sdkVer        = '10.0.26100.0'
$winKits       = 'C:\Program Files (x86)\Windows Kits\10'
$includeKm     = Join-Path $winKits "Include\$sdkVer\km"
$includeShared = Join-Path $winKits "Include\$sdkVer\shared"
$includeKmCrt  = Join-Path $winKits "Include\$sdkVer\km\crt"
$libKmX64      = Join-Path $winKits "Lib\$sdkVer\km\x64"

$vsBt          = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools'
$msvcRoot      = Join-Path $vsBt 'VC\Tools\MSVC'
$msvcVer       = (Get-ChildItem $msvcRoot | Sort-Object Name -Descending | Select-Object -First 1).Name
if (-not $msvcVer) { throw "no MSVC version under $msvcRoot" }
$msvc          = Join-Path $msvcRoot $msvcVer
$cl            = Join-Path $msvc 'bin\HostX64\x64\cl.exe'
$linkExe       = Join-Path $msvc 'bin\HostX64\x64\link.exe'
$includeMsvc   = Join-Path $msvc 'include'
$libMsvc       = Join-Path $msvc 'lib\x64'

if (-not (Test-Path $cl))      { throw "cl.exe not found at $cl" }
if (-not (Test-Path $linkExe)) { throw "link.exe not found at $linkExe" }
if (-not (Test-Path $libKmX64)){ throw "km libs not found at $libKmX64" }

# cl/link read paths from INCLUDE/LIB env vars. We set these instead of using
# /I and /LIBPATH because PowerShell's call operator doesn't reliably quote
# paths-with-spaces in those flag values, and link.exe's /LIBPATH:<path> can't
# be split into two argv entries (no space allowed after the colon).
# Order matters. The kernel CRT (km/crt) must come BEFORE the MSVC include so
# cl finds kernel-mode versions of stddef.h / intrin.h etc., not the user-mode
# ones that pull in corecrt.h.
$env:INCLUDE = ($includeKmCrt, $includeKm, $includeShared, $includeMsvc) -join ';'
$env:LIB     = ($libKmX64, $libMsvc) -join ';'
Write-Host "INCLUDE=$env:INCLUDE"
Write-Host "LIB=$env:LIB"

if ($Clean) {
    foreach ($f in @('edr.obj','edr.sys','edr.pdb','edr.exp','edr.lib','vc140.pdb')) {
        if (Test-Path $f) { Remove-Item -Force $f; Write-Host "removed $f" }
    }
    return
}

Write-Host "msvc:    $msvc"
Write-Host "kits:    $winKits"
Write-Host "sdk ver: $sdkVer"

Write-Host '--- compiling edr.c ---'
# /kernel auto-defines _KERNEL_MODE; passing /D_KERNEL_MODE again triggers
# C4117 (reserved name), promoted to error by /WX.
# /WX is on, but the WDK headers themselves trip a few "expected" warnings
# (alignment padding, nameless structs, etc.). The MSBuild WDK targets
# suppress these by default; we mirror that list here.
$wdkWarningSuppressions = @(
    '/wd4324'  # structure was padded due to alignment specifier
    '/wd4201'  # nameless struct/union
    '/wd4127'  # conditional expression is constant
    '/wd4214'  # bit field types other than int
    '/wd4115'  # named type definition in parentheses
    '/wd4204'  # non-constant aggregate initializer
    '/wd4221'  # initialization using address of automatic variable
)
$clArgs = @(
    '/nologo','/c','/Zi','/W4','/WX','/GS','/TC','/std:c17','/kernel'
    '/D_WIN64','/D_AMD64_','/DAMD64'
    '/DPOOL_NX_OPTIN=1','/DPOOL_ZERO_DOWN_LEVEL_SUPPORT=1'
    '/D_HAS_EXCEPTIONS=0'
) + $wdkWarningSuppressions + @(
    'edr.c','/Foedr.obj','/Fdedr.pdb'
)
& $cl @clArgs
if ($LASTEXITCODE -ne 0) { throw "cl failed (exit $LASTEXITCODE)" }

Write-Host '--- linking edr.sys ---'
$linkArgs = @(
    '/nologo','/OUT:edr.sys','/MACHINE:X64','/SUBSYSTEM:NATIVE,10.0'
    '/DRIVER','/ENTRY:DriverEntry','/NODEFAULTLIB'
    # /INTEGRITYCHECK sets IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY in the
    # PE header, which is required for any driver that calls
    # PsSetCreateProcessNotifyRoutineEx (otherwise that API returns
    # STATUS_ACCESS_DENIED with no other diagnostic).
    '/INTEGRITYCHECK'
    '/MERGE:_TEXT=.text','/MERGE:_PAGE=PAGE'
    '/SECTION:INIT,d','/OPT:REF','/OPT:ICF'
    'edr.obj','FltMgr.lib','ntoskrnl.lib','BufferOverflowFastFailK.lib','wdmsec.lib'
)
& $linkExe @linkArgs
if ($LASTEXITCODE -ne 0) { throw "link failed (exit $LASTEXITCODE)" }

Write-Host '--- signing edr.sys ---'
$thumbprint = (Get-Content 'C:\toolchain\edr-cert-thumbprint.txt' -ErrorAction Stop).Trim()
$signtool   = (Get-ChildItem (Join-Path $winKits 'bin') -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
               Where-Object { $_.FullName -match '\\x64\\signtool.exe$' } |
               Select-Object -First 1).FullName
if (-not $signtool) { throw "signtool.exe not found under $winKits\bin" }
& $signtool sign /v /sm /fd sha256 /sha1 $thumbprint /tr 'http://timestamp.digicert.com' /td sha256 edr.sys
if ($LASTEXITCODE -ne 0) { throw "signtool failed (exit $LASTEXITCODE)" }

Write-Host '--- verifying signature ---'
& $signtool verify /v /pa edr.sys
if ($LASTEXITCODE -ne 0) { Write-Warning "signtool verify reported issues (exit $LASTEXITCODE)" }

Write-Host '--- artifacts ---'
Get-Item 'edr.sys','edr.obj','edr.pdb' -ErrorAction SilentlyContinue | Format-Table Name, Length, LastWriteTime -AutoSize | Out-Host

Write-Host 'BUILD OK'
