#!/bin/bash
# Mutation checks for the v0.3.1 reasoning contract (same method as v0.2.1/v0.3):
# copy the tree, break one guard, run its dedicated test and the full default suite.
# Usage: PY=.venv/bin/python docs/validation/v0.3.1/mutate_v031.sh <repo-root> <scratch-dir>
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
T=tests/test_reasoning_contract.py
run "C1 claim eligibility diverges from the validator (unsupported claims listed eligible)" investigator/attack.py \
"        if pred is _unavailable or not pred(evs):" "        if pred is _unavailable:" \
"$T::test_eligibility_equals_validator_acceptance_on_random_evidence_sets"
run "C2 revised draft's verdict trusted without the gates" investigator/agent.py \
"        final = assess(revised, exchange, False)" \
"        final = assess(revised, exchange, False); final.verdict = revised.verdict" \
"$T::test_revision_cannot_obtain_benign"
run "C3 revision ignores the disable setting" investigator/agent.py \
"        if reasons and self.settings.validation_revision and not is_cancelled():" \
"        if reasons and not is_cancelled():" \
"$T::test_exactly_one_revision_and_it_can_be_disabled"
run "C4 revision not triggered by rejected claims" investigator/agent.py \
"        lost = (vr.rejected_claims or" "        lost = (False or" \
"$T::test_a_rejected_claim_next_to_an_accepted_one_still_triggers_the_revision"
run "C5 cancellation during the revision ignored" investigator/agent.py \
"        if is_cancelled():
            trace.errors.append(f\"{CANCELLED} investigation cancelled during the revision" \
"        if False:
            trace.errors.append(f\"{CANCELLED} investigation cancelled during the revision" \
"$T::test_cancellation_during_revision_ends_cancelled"
run "C6 baseline failure hidden (not a failed collection)" investigator/agent.py \
"                trace.errors.append(f\"collection: baseline {tool} {call.status} ({call.error_kind})\")" \
"                pass" \
"$T::test_baseline_failure_is_a_visible_failed_collection"
run "C7 allowed values removed from the argument contract" investigator/tools.py \
"    if enum:
        text = \"one of \"" "    if False:
        text = \"one of \"" \
"$T::test_tool_catalog_exposes_allowed_values_bounds_rules_and_valid_examples"
run "C8 duplicate-request feedback removed" investigator/agent.py \
"            if c.status == \"duplicate\":
                last[\"message\"]" "            if False:
                last[\"message\"]" \
"$T::test_decide_state_has_feedback_answered_requests_checklist_and_suggestions"
run "C9 benign_administration warning removed from the report contract" investigator/agent.py \
"        if shown_warning:
            contract[\"benign_administration_is_not_eligible\"]" "        if False:
            contract[\"benign_administration_is_not_eligible\"]" \
"$T::test_report_prompt_carries_the_contract_and_the_benign_admin_warning"
run "C10 rejected claims hidden from the revision feedback" investigator/agent.py \
"                             \"claims_rejected\": f.rejected_claims," "                             \"claims_rejected\": []," \
"$T::test_revision_feedback_contains_only_application_text"
run "C11 (defect found in v0.3.1 validation) records omitted at level 4 counted as shown in full" investigator/agent.py \
"ranked[:min(keep, _SUMMARY_AFTER) if level >= 3 else keep]" "ranked[:_SUMMARY_AFTER if level >= 3 else keep]" \
"tests/test_integrity_v021.py::test_D_omitted_tree_records_are_hidden_even_when_fewer_than_the_summary_threshold"
