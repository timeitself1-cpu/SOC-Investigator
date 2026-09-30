<#
.SYNOPSIS
  Captures raw evidence of a v0.3 real-world validation run.

.DESCRIPTION
  Writes, into a new folder:
    sources.json      capability discovery as the investigator sees it (this account)
    signals.txt       the signals the investigator raised
    <source>.xml      raw events of the last -Hours hours from the four channels
                      (wevtutil qe ... /f:xml /e:Events), replayable with
                      `python -m investigator --backend windows-replay --replay-dir <folder>`
    host.json         OS caption and whether this shell is elevated
    reports\          copies of investigation reports saved by the dashboard

  The exports contain user names, command lines and host names. Review them before
  sharing. Nothing on the computer is changed.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\capture_evidence.ps1 -Hours 2
#>
param(
    [int]$Hours = 2,
    [string]$Out = (".\rw-evidence-" + (Get-Date -Format "yyyyMMdd-HHmmss")),
    [string]$Python = "python"
)
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$ms = $Hours * 3600000

& $Python -m investigator --backend windows sources --json | Out-File -Encoding utf8 "$Out\sources.json"
& $Python -m investigator --backend windows list | Out-File -Encoding utf8 "$Out\signals.txt"

$channels = [ordered]@{
    sysmon     = "Microsoft-Windows-Sysmon/Operational"
    security   = "Security"
    powershell = "Microsoft-Windows-PowerShell/Operational"
    defender   = "Microsoft-Windows-Windows Defender/Operational"
}
foreach ($c in $channels.GetEnumerator()) {
    $query = "*[System[TimeCreated[timediff(@SystemTime) <= $ms]]]"
    $xml = wevtutil qe $c.Value /q:$query /f:xml /e:Events 2>&1
    if ($LASTEXITCODE -ne 0) {
        "wevtutil exit $LASTEXITCODE for $($c.Value): $xml" | Out-File -Encoding utf8 "$Out\$($c.Key).error.txt"
    } else {
        $xml | Out-File -Encoding utf8 "$Out\$($c.Key).xml"
    }
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
@{
    os       = (Get-CimInstance Win32_OperatingSystem).Caption + " " + (Get-CimInstance Win32_OperatingSystem).Version
    elevated = $(if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { "yes" } else { "no" })
    role     = "Real-world validation host"
} | ConvertTo-Json | Out-File -Encoding utf8 "$Out\host.json"

$reports = Join-Path $env:LOCALAPPDATA "soc-investigator\reports"
if (Test-Path ".\reports") { $reports = ".\reports" }
if (Test-Path $reports) { Copy-Item -Recurse -Force $reports "$Out\reports" }

Write-Host "Evidence written to $Out (review before sharing: it contains usernames and command lines)."
