#!/bin/bash
# Manual mutation checks for v0.2.1 safety guards.
# Usage: PY=.venv/bin/python docs/validation/v0.2.1/mutate_v021.sh <repo-root> <scratch-dir>
# For each guard: copy the tree, remove the guard, run its DEDICATED test(s) and
# the full default suite, report the results. The source tree is never modified,
# so "restore" is implicit (the copy is discarded).
SRC=$1; WORK=$2; PY=${PY:-python}
run() {  # name file old new dedicated-test-selector
  rm -rf $WORK; mkdir -p $WORK; cp -r $SRC/investigator $SRC/tests $SRC/pyproject.toml $WORK/
  $PY - "$WORK/$2" "$3" "$4" <<'PYEOF'
import sys; p, old, new = sys.argv[1:4]; s = open(p).read()
assert s.count(old) >= 1, f"pattern not found in {p}: {old!r}"; open(p, "w").write(s.replace(old, new, 1))
PYEOF
  [ $? -ne 0 ] && { echo "$1: MUTATION NOT APPLIED"; return; }
  ded=$(cd $WORK && $PY -m pytest -q -p no:cacheprovider "$5" 2>&1 | tail -1)
  full=$(cd $WORK && $PY -m pytest -q -p no:cacheprovider --ignore=tests/test_browser_ui.py 2>&1 | tail -1)
  echo "$1"; echo "    dedicated [$5] => $ded"; echo "    full suite => $full"
}
echo "== Previously untested guards (REVIEW_FOLLOWUP F6) =="
run "M1 remove 'benign withheld when collection incomplete' status gate" investigator/report.py \
'        if verdict == "benign":
            vr.verdict_adjusted_from = verdict
            verdict = "insufficient_evidence"
            vr.valid = False' \
'        if False:
            pass' \
"tests/test_integrity_v021.py::test_status_gate_alone_withholds_benign_when_any_collection_failed"
run "M2 remove '..' traversal check in management_parent_status" investigator/evidence.py \
'if ".." in full:' 'if False:' "tests/test_integrity_v021.py::test_dotdot_management_agent_path_is_a_masquerade"
echo "== New v0.2.1 guards =="
run "M3 benign ignores collection requirements" investigator/report.py \
"for r in requirements if not r.satisfied)" "for r in requirements if False)" \
"tests/test_integrity_v021.py::test_A_immediate_benign_without_investigation_is_rejected"
run "M4 descendant closure limited to the trigger (no descendants)" investigator/report.py \
"        added = {child for parent, child in links if parent in tree and child not in tree}" \
"        added = set()" \
"tests/test_integrity_v021.py::test_B_public_connection_by_any_descendant_blocks_benign"
run "M5 host-context injection does not affect the requirement" investigator/report.py \
"good = [c for c in hc_calls if c.result_count > 0 and not c.injection_suspected]" \
"good = [c for c in hc_calls if c.result_count > 0]" \
"tests/test_integrity_v021.py::test_E_exact_followup_bypass_host_context_injection_blocks_benign"
run "M6 server-reported overflow ignored" investigator/agent.py \
"            if resp.prompt_tokens and (resp.prompt_tokens >= 0.97 * self.settings.ollama_num_ctx" \
"            if False and (resp.prompt_tokens >= 0.97 * self.settings.ollama_num_ctx" \
"tests/test_integrity_v021.py::test_D_server_reported_context_overflow_marks_incomplete_and_blocks_benign"
run "M7 blob compaction disabled" investigator/compaction.py \
"    out = _CANDIDATE.sub(repl, text)" "    out = text" \
"tests/test_integrity_v021.py::test_D_encoded_floods_stay_within_the_conservative_token_limit"
run "M8 retrieval reverts to oldest-first" investigator/tools.py \
"    after_quota = (limit + 1) // 2" "    after_quota = 0" \
"tests/test_integrity_v021.py::test_F_post_alert_connection_survives_pre_alert_noise"
run "M9 cancellation during assessment ignored" investigator/agent.py \
"            if is_cancelled():
                # Cancellation accepted while" "            if False:
                # Cancellation accepted while" \
"tests/test_integrity_v021.py::test_cancellation_accepted_during_final_report_ends_cancelled"
run "M10 chars/token cap removed (3.0 accepted)" investigator/config.py \
"            return min(float(value), 2.0)  # type: ignore[arg-type]" "            return value" \
"tests/test_integrity_v021.py::test_chars_per_token_is_capped_at_two"
run "M11 hidden priority evidence not treated as a visibility issue" investigator/agent.py \
"            if hidden:" "            if False:" \
"tests/test_integrity_v021.py::test_D_evidence_shown_only_as_summaries_blocks_benign_without_omission"
