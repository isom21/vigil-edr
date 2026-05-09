# install.ps1 — install / start / stop / uninstall the M4 EDR driver on lab-windows.
#
# Run from an elevated shell. The driver must be signed and either:
#   - The system has `bcdedit /set testsigning on` and the signing cert is
#     trusted (LocalMachine\Root + LocalMachine\TrustedPublisher), or
#   - The driver is signed by an attestation-signed / WHQL cert.
#
# Usage:
#   .\install.ps1 install      copies edr.sys to %windir%\system32\drivers
#                              and creates the service via SCM
#   .\install.ps1 start
#   .\install.ps1 stop
#   .\install.ps1 uninstall    stops + deletes the service + removes the .sys
#   .\install.ps1 status

$ErrorActionPreference = 'Stop'

$ServiceName = 'edr'
$Source      = Join-Path $PSScriptRoot 'edr.sys'
$Target      = "$env:windir\system32\drivers\edr.sys"

function Install-Driver {
    if (-not (Test-Path $Source)) { throw "edr.sys not found at $Source. Build first (build.bat)." }
    Copy-Item -Force $Source $Target
    Write-Host "copied -> $Target"

    # SERVICE_FILE_SYSTEM_DRIVER (type=2), SERVICE_DEMAND_START (start=3),
    # error normal (error=1), depend on FltMgr, group FSFilter Activity Monitor.
    & sc.exe create $ServiceName type= filesys start= demand error= normal `
        binPath= $Target depend= FltMgr group= "FSFilter Activity Monitor" | Out-Host
    & sc.exe description $ServiceName "EDR endpoint kernel driver (M4 PoC)" | Out-Host

    # Add the minifilter Instances\Default registry entries the FltMgr expects.
    $svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    $instKey = "$svcKey\Instances"
    $defKey  = "$svcKey\Instances\EDR Default"
    New-Item -Path $instKey -Force | Out-Null
    Set-ItemProperty -Path $instKey -Name 'DefaultInstance' -Value 'EDR Default'
    New-Item -Path $defKey -Force | Out-Null
    Set-ItemProperty -Path $defKey -Name 'Altitude' -Value '385100'
    Set-ItemProperty -Path $defKey -Name 'Flags' -Type DWord -Value 0x0
    Write-Host "registry: Instances\\EDR Default written"

    Write-Host 'install OK'
}

function Uninstall-Driver {
    & sc.exe stop $ServiceName 2>$null | Out-Null
    Start-Sleep -Seconds 1
    & sc.exe delete $ServiceName 2>$null | Out-Null
    if (Test-Path $Target) { Remove-Item -Force $Target }
    Write-Host 'uninstalled'
}

function Get-Status {
    & sc.exe query $ServiceName
    Write-Host '--- fltmc instances ---'
    & fltmc.exe instances -f $ServiceName
}

switch ($args[0]) {
    'install'   { Install-Driver }
    'uninstall' { Uninstall-Driver }
    'start'     { & sc.exe start $ServiceName }
    'stop'      { & sc.exe stop  $ServiceName }
    'status'    { Get-Status }
    default     { Write-Host "usage: install | uninstall | start | stop | status" }
}
