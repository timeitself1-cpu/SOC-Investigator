param(
    [ValidateRange(1,65535)][int]$Port = 8000,
    # fixture = demo incidents; windows-replay = synthetic Windows events; windows = this PC's event logs
    [ValidateSet("fixture", "windows-replay", "windows")][string]$Backend = "fixture",
    [ValidateSet("mock", "ollama")][string]$Llm = "mock"
)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$taskPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $taskPython)) {
    Write-Error "Create the environment first: py -3.12 -m venv .venv; .\.venv\Scripts\python.exe -m pip install -e '.[dev]'"
}
$env:SOCI_PORT = "$Port"
& $taskPython -m investigator --llm $Llm --backend $Backend serve
exit $LASTEXITCODE
