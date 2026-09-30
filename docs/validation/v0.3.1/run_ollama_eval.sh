#!/bin/bash
# v0.3.1 real-model evaluation. NOT RUN in the development environment (no Ollama
# reachable there). Run on the machine that has Ollama and the model pulled:
#   ollama pull qwen2.5:7b-instruct
#   bash docs/validation/v0.3.1/run_ollama_eval.sh [python]
# Writes every report (JSON + Markdown), acceptance.json and the console output
# under docs/validation/v0.3.1/ollama_after/. Commit that folder as-is, pass or fail.
set -u
PY=${1:-python}; OUT=docs/validation/v0.3.1/ollama_after; mkdir -p $OUT
export SOCI_LLM=ollama SOCI_BACKEND=fixture SOCI_OLLAMA_MODEL=${SOCI_OLLAMA_MODEL:-qwen2.5:7b-instruct}
export SOCI_OLLAMA_TEMPERATURE=0.0 SOCI_OLLAMA_SEED=42
{ echo "date: $(date -u +%FT%TZ)"; echo "commit: $(git rev-parse HEAD 2>/dev/null)"; ollama --version 2>&1; \
  ollama show "$SOCI_OLLAMA_MODEL" 2>&1 | head -20; $PY -m investigator health 2>&1; } > $OUT/environment.txt
for ctx in 16384 8192; do
  SOCI_OLLAMA_NUM_CTX=$ctx $PY -m investigator acceptance --repeats 3 --out $OUT/acceptance_ctx$ctx \
    > $OUT/acceptance_ctx$ctx.txt 2>&1
  echo "acceptance num_ctx=$ctx exit $?" | tee -a $OUT/exit_codes.txt
done
SOCI_OLLAMA_NUM_CTX=16384 $PY -m investigator benchmark --repeats 3 > $OUT/benchmark_ctx16384.txt 2>&1
echo "benchmark exit $?" | tee -a $OUT/exit_codes.txt
SOCI_OLLAMA_NUM_CTX=16384 $PY -m investigator benchmark --repeats 3 --json > $OUT/benchmark_ctx16384.json 2>&1
tail -3 $OUT/acceptance_ctx*.txt
