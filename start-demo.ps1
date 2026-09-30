param([ValidateRange(1,65535)][int]$Port = 8000)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$taskPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $taskPython)) {
    Write-Error "Create the environment first: py -3.12 -m venv .venv; .\.venv\Scripts\python.exe -m pip install -e '.[dev]'"
}
$env:SOCI_PORT = "$Port"
& $taskPython -m investigator --llm mock --backend fixture serve
exit $LASTEXITCODE
