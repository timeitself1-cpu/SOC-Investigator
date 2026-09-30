<#
.SYNOPSIS
  Generates SAFE, controlled activity for the Investigator v0.3 real-world validation.

.DESCRIPTION
  Every scenario uses built-in Windows tools only. Nothing is downloaded and run,
  no malware or exploit is used, no system setting is changed. The "suspicious"
  scenarios only *look* suspicious to the detection rules (encoded command, hidden
  window, failed logons).

  RW-01  hidden, encoded PowerShell that fetches https://example.com (then discards it)
  RW-02  ordinary administrative PowerShell (read-only WMI query), hidden window
  RW-03  encoded PowerShell -> cmd.exe -> whoami.exe / PING.EXE (three generations)
  RW-04  six failed logons for a local account that does not exist (Secondary Logon)
  RW-05  is a telemetry-access scenario: see REAL_WORLD_PROCEDURE.md (no script needed)

  Run from a normal (non-elevated) PowerShell window. Note the time printed for
  each scenario; you will find the matching signal on the dashboard.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\rw_scenarios.ps1 -Scenario RW01
#>
param(
    [ValidateSet("RW01", "RW02", "RW03", "RW04", "All")]
    [string]$Scenario = "All"
)
$ErrorActionPreference = "Stop"

function Write-Stamp($name) {
    Write-Host ("[{0:u}] {1} started (host {2})" -f (Get-Date).ToUniversalTime(), $name, $env:COMPUTERNAME)
}

function ConvertTo-Encoded([string]$script) {
    [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
}

function Invoke-RW01 {
    Write-Stamp "RW-01 suspicious PowerShell"
    $s = "Write-Output 'RW-01 soc-investigator validation'; " +
         "Invoke-WebRequest -UseBasicParsing -Uri https://example.com/ | Out-Null"
    Start-Process powershell.exe -Wait -ArgumentList @(
        "-NoProfile", "-WindowStyle", "Hidden", "-EncodedCommand", (ConvertTo-Encoded $s))
}

function Invoke-RW02 {
    Write-Stamp "RW-02 administrative PowerShell"
    Start-Process powershell.exe -Wait -ArgumentList @(
        "-NoProfile", "-WindowStyle", "Hidden", "-Command",
        "Get-CimInstance -ClassName Win32_BIOS | Select-Object SerialNumber, SMBIOSBIOSVersion | ConvertTo-Json | Out-Null")
}

function Invoke-RW03 {
    Write-Stamp "RW-03 process chain"
    $s = "Start-Process -Wait -WindowStyle Hidden cmd.exe " +
         "-ArgumentList '/c whoami /all > NUL & ping -n 1 127.0.0.1 > NUL'"
    Start-Process powershell.exe -Wait -ArgumentList @("-NoProfile", "-EncodedCommand", (ConvertTo-Encoded $s))
}

function Invoke-RW04 {
    Write-Stamp "RW-04 failed logons"
    $user = "$env:COMPUTERNAME\rw_nonexistent"
    $pw = ConvertTo-SecureString "Not-A-Real-Password-RW04!" -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential($user, $pw)
    foreach ($i in 1..6) {
        try { Start-Process cmd.exe -ArgumentList "/c exit" -Credential $cred -WindowStyle Hidden } catch { }
        Start-Sleep -Seconds 2
    }
    Write-Host "Six logon attempts made for $user (expected to fail: the account does not exist)."
}

switch ($Scenario) {
    "RW01" { Invoke-RW01 }
    "RW02" { Invoke-RW02 }
    "RW03" { Invoke-RW03 }
    "RW04" { Invoke-RW04 }
    "All"  { Invoke-RW01; Start-Sleep 60; Invoke-RW02; Start-Sleep 60; Invoke-RW03; Start-Sleep 60; Invoke-RW04 }
}
