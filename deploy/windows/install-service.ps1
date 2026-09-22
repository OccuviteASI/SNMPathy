<#
.SYNOPSIS
    Installs SNMPathy as a Windows service (or a startup scheduled task).

.DESCRIPTION
    Creates a Python virtual environment under -InstallDir, installs SNMPathy
    from this repository, writes a default configuration, opens the firewall
    for the web UI and syslog ports, and registers SNMPathy to start at boot.

    If NSSM (https://nssm.cc) is on the PATH it is used to create a real
    Windows service with automatic restarts. Otherwise a scheduled task that
    runs at startup as SYSTEM is created instead.

    Run from an elevated PowerShell:
        powershell -ExecutionPolicy Bypass -File deploy\windows\install-service.ps1
    Uninstall:
        powershell -ExecutionPolicy Bypass -File deploy\windows\install-service.ps1 -Uninstall

.NOTES
    ping.exe is used for ICMP checks, so no extra privileges are required.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:ProgramData "SNMPathy"),
    [string]$Python = "py",
    [int]$HttpPort = 8080,
    [int]$SyslogPort = 5514,
    [string]$ServiceName = "SNMPathy",
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Please run this script from an elevated (Administrator) PowerShell."
    }
}

Assert-Admin
$nssm = Get-Command nssm -ErrorAction SilentlyContinue

if ($Uninstall) {
    if ($nssm -and (Get-Service $ServiceName -ErrorAction SilentlyContinue)) {
        & $nssm.Source stop $ServiceName | Out-Null
        & $nssm.Source remove $ServiceName confirm | Out-Null
    }
    if (Get-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $ServiceName -Confirm:$false
    }
    Get-NetFirewallRule -DisplayName "SNMPathy*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Write-Host "SNMPathy removed. Data in $InstallDir was kept; delete it manually if no longer needed."
    return
}

$repo = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$venv = Join-Path $InstallDir "venv"
$exe = Join-Path $venv "Scripts\snmpathy.exe"
$config = Join-Path $InstallDir "snmpathy.yaml"
$logDir = Join-Path $InstallDir "logs"

New-Item -ItemType Directory -Force -Path $InstallDir, $logDir | Out-Null

Write-Host "Creating virtual environment in $venv"
if ($Python -eq "py") { & py -3 -m venv $venv } else { & $Python -m venv $venv }
& (Join-Path $venv "Scripts\python.exe") -m pip install --upgrade pip | Out-Null
& (Join-Path $venv "Scripts\python.exe") -m pip install "$repo"

if (-not (Test-Path $config)) {
    & $exe init-config $config | Out-Null
    (Get-Content $config) `
        -replace '^database: .*', ("database: " + (Join-Path $InstallDir "snmpathy.db").Replace('\', '/')) `
        -replace '^http_port: .*', "http_port: $HttpPort" `
        -replace '^syslog_udp_port: .*', "syslog_udp_port: $SyslogPort" `
        -replace '^syslog_tcp_port: .*', "syslog_tcp_port: $SyslogPort" |
        Set-Content -Encoding UTF8 $config
    Write-Host "Wrote $config"
}

Write-Host "Opening firewall ports"
Get-NetFirewallRule -DisplayName "SNMPathy*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName "SNMPathy web UI" -Direction Inbound -Protocol TCP -LocalPort $HttpPort -Action Allow | Out-Null
New-NetFirewallRule -DisplayName "SNMPathy syslog UDP" -Direction Inbound -Protocol UDP -LocalPort $SyslogPort -Action Allow | Out-Null
New-NetFirewallRule -DisplayName "SNMPathy syslog TCP" -Direction Inbound -Protocol TCP -LocalPort $SyslogPort -Action Allow | Out-Null

if ($nssm) {
    Write-Host "Registering Windows service '$ServiceName' with NSSM"
    & $nssm.Source install $ServiceName $exe serve --config $config | Out-Null
    & $nssm.Source set $ServiceName AppDirectory $InstallDir | Out-Null
    & $nssm.Source set $ServiceName DisplayName "SNMPathy network monitoring" | Out-Null
    & $nssm.Source set $ServiceName Start SERVICE_AUTO_START | Out-Null
    & $nssm.Source set $ServiceName AppStdout (Join-Path $logDir "snmpathy.log") | Out-Null
    & $nssm.Source set $ServiceName AppStderr (Join-Path $logDir "snmpathy.log") | Out-Null
    & $nssm.Source set $ServiceName AppRotateFiles 1 | Out-Null
    & $nssm.Source set $ServiceName AppRotateBytes 10485760 | Out-Null
    & $nssm.Source start $ServiceName | Out-Null
} else {
    Write-Host "NSSM not found: registering a startup scheduled task instead"
    $action = New-ScheduledTaskAction -Execute $exe -Argument "serve --config `"$config`"" -WorkingDirectory $InstallDir
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $ServiceName -Action $action -Trigger $trigger -Settings $settings `
        -Principal $principal -Description "SNMPathy network monitoring" -Force | Out-Null
    Start-ScheduledTask -TaskName $ServiceName
}

Write-Host ""
Write-Host "SNMPathy is running: http://localhost:$HttpPort/"
Write-Host "Point syslog senders at this machine on UDP/TCP port $SyslogPort."
Write-Host "Configuration: $config"
