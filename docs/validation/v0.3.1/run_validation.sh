#!/bin/bash
# Reproduce every v0.3.1 validation output in this folder (no Ollama needed).
# Usage: PY=.venv/bin/python TOK=<qwen2.5 tokenizer.json> docs/validation/v0.3.1/run_validation.sh <scratch-dir>
# The Qwen2.5 tokenizer.json used here came from npm @lenml/tokenizer-qwen2_5.
set -u
PY=${PY:-python}; W=${1:-/tmp/soci-v031}; V=docs/validation/v0.3.1; mkdir -p "$W"
step() { echo "== $1 (exit $2)"; }
$PY -m pytest -q -p no:cacheprovider > $V/pytest.txt 2>&1; step pytest $?
for i in 1 2 3 4 5; do $PY -m pytest -q -p no:cacheprovider 2>&1 | tail -1; done > $V/pytest_5x.txt; step pytest_5x 0
$PY -m pytest -q -p no:cacheprovider tests/test_browser_ui.py -m "" > $V/pytest_browser.txt 2>&1; step browser $?
$PY -m pytest -q -p no:cacheprovider -m integration > $V/pytest_integration_unconfigured.txt 2>&1; step integration $?
node --test tests/test_activity_dom.cjs > $V/node_dom_tests.txt 2>&1; step node_dom $?
$PY -m investigator --llm mock benchmark > $V/benchmark_mock.txt 2>&1; step benchmark_mock $?
$PY -m investigator --llm mock benchmark --json > $V/benchmark_mock.json 2>&1
for a in benign-after-investigation benign-immediately; do
  $PY -m investigator --llm mock benchmark --adversary $a > $V/benchmark_$a.txt 2>&1; step "adversary $a" $?
  $PY -m investigator --llm mock benchmark --adversary $a --json > $V/benchmark_$a.json 2>&1
done
$PY -m investigator --llm mock acceptance --out "$W/acceptance_mock" > $V/acceptance_mock.txt 2>&1; step acceptance_mock $?
$PY -m investigator --llm mock evaluate > $V/evaluate_demo.txt 2>&1; step evaluate $?
$PY docs/validation/v0.2.1/final_gate.py "$PWD" ${TOK:-} > $V/final_gate_v021_on_v031.txt 2>&1; step final_gate $?
$PY docs/validation/v0.3/replay_e2e.py > $V/replay_synthetic_e2e.txt 2>&1; step replay_e2e $?
if [ -n "${TOK:-}" ]; then
  $PY docs/validation/followup/probe_tokens.py "$PWD" "$TOK" > $V/tokens_16384_floods.txt 2>&1; step tokens_floods $?
  $PY docs/validation/v0.3.1/probe_contract_tokens.py "$PWD" "$TOK" > $V/tokens_contract.txt 2>&1; step tokens_contract $?
fi
PY=$PY bash docs/validation/v0.2.1/mutate_v021.sh "$PWD" "$W/m1" > $V/mutation_v021_rerun.txt 2>&1; step mutation_v021 $?
PY=$PY bash docs/validation/v0.3/mutate_v03.sh "$PWD" "$W/m2" > $V/mutation_v03_rerun.txt 2>&1; step mutation_v03 $?
PY=$PY bash docs/validation/v0.3.1/mutate_v031.sh "$PWD" "$W/m3" > $V/mutation_v031.txt 2>&1; step mutation_v031 $?
