#!/bin/bash
# Mutation checks for v0.3 Windows/coverage guards (same method as v0.2.1).
# Usage: PY=.venv/bin/python docs/validation/v0.3/mutate_v03.sh <repo-root> <scratch-dir>
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
run "V1 unreadable sources return empty instead of raising" investigator/backends/windows.py \
"        if not answered_any and errors:
            raise errors[0]" "        pass" \
"tests/test_windows_backend.py::test_permission_denied_is_never_reported_as_no_events"
run "V2 degraded backend answers not marked partial" investigator/tools.py \
"            if ctx.pending_degraded:" "            if False:" \
"tests/test_v03_requirements.py::test_windows_limited_network_logging_blocks_benign_even_with_no_events"
run "V3 limited-source detection disabled" investigator/backends/windows.py \
"                        if any((source, i) in DEGRADE_WHEN_ABSENT for i in missing):" "                        if False:" \
"tests/test_v03_requirements.py::test_windows_limited_network_logging_blocks_benign_even_with_no_events"
run "V4 tree-network coverage not checked against the current tree" investigator/report.py \
"trig.process_guid.casefold() and tree_guids and tree_guids <= covered:" "trig.process_guid.casefold():" \
"tests/test_v03_requirements.py::test_tree_network_taken_before_the_tree_was_expanded_does_not_count"
run "V5 host signals ignored" investigator/report.py \
'satisfied=state == "clear", reason=reason,' 'satisfied=True, reason=reason,' \
"tests/test_v03_requirements.py::test_other_signal_on_the_host_blocks_benign"
run "V6 process-scoped queries include sources without process identity" investigator/backends/windows.py \
"        if q.process_guid:
            return None  # no process identity" "        if False:
            return None  # no process identity" \
"tests/test_windows_backend.py::test_process_scoped_queries_exclude_sources_without_process_identity"
run "V7 query value allowlist removed (XPath injection)" investigator/backends/windows_events.py \
"            if not pattern.fullmatch(value):" "            if False:" \
"tests/test_windows_backend.py::test_channel_query_rejects_injection_and_unknown_fields"
run "V8 non-local hosts accepted" investigator/backends/windows.py \
"        if not self._is_local(query.host):" "        if False:" \
"tests/test_windows_backend.py::test_only_the_local_computer_can_be_queried"
run "V9 no fallback-source degradation (4688 treated as complete)" investigator/backends/windows.py \
"                    if position > 0:
                        degraded = True" "                    if position > 0:
                        degraded = False" \
"tests/test_windows_backend.py::test_missing_source_raises_and_fallback_is_degraded"
run "V10 hidden priority evidence ignored" investigator/agent.py \
"                              \"priority_hidden\": len(priority - full_view)}" "                              \"priority_hidden\": 0}" \
"tests/test_integrity_v021.py::test_D_priority_evidence_that_cannot_reach_the_model_marks_incomplete_and_blocks_benign"
