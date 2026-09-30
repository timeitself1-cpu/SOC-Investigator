# v0.3.1 real-model evaluation on Windows (PowerShell). NOT RUN in the development
# environment. Prerequisite: `ollama pull qwen2.5:7b-instruct`. Run from the repo root:
#   powershell -ExecutionPolicy Bypass -File docs\validation\v0.3.1\run_ollama_eval.ps1
# Commit docs\validation\v0.3.1\ollama_after\ as-is, pass or fail.
$ErrorActionPreference = "Continue"
$Out = "docs\validation\v0.3.1\ollama_after"; New-Item -ItemType Directory -Force $Out | Out-Null
$env:SOCI_LLM = "ollama"; $env:SOCI_BACKEND = "fixture"
if (-not $env:SOCI_OLLAMA_MODEL) { $env:SOCI_OLLAMA_MODEL = "qwen2.5:7b-instruct" }
$env:SOCI_OLLAMA_TEMPERATURE = "0.0"; $env:SOCI_OLLAMA_SEED = "42"
& { "date: $((Get-Date).ToUniversalTime().ToString('o'))"; "commit: $(git rev-parse HEAD)"; ollama --version
    ollama show $env:SOCI_OLLAMA_MODEL; python -m investigator health } *> "$Out\environment.txt"
foreach ($ctx in 16384, 8192) {
  $env:SOCI_OLLAMA_NUM_CTX = "$ctx"
  python -m investigator acceptance --repeats 3 --out "$Out\acceptance_ctx$ctx" *> "$Out\acceptance_ctx$ctx.txt"
  "acceptance num_ctx=$ctx exit $LASTEXITCODE" | Tee-Object -Append "$Out\exit_codes.txt"
}
$env:SOCI_OLLAMA_NUM_CTX = "16384"
python -m investigator benchmark --repeats 3 *> "$Out\benchmark_ctx16384.txt"
"benchmark exit $LASTEXITCODE" | Tee-Object -Append "$Out\exit_codes.txt"
python -m investigator benchmark --repeats 3 --json *> "$Out\benchmark_ctx16384.json"
Get-ChildItem "$Out\acceptance_ctx*.txt" | ForEach-Object { Get-Content $_ -Tail 3 }
