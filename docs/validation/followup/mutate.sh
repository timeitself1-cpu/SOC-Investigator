#!/bin/bash
# Usage: PY=.venv/bin/python mutate.sh <source-root> <scratch-dir>
# Apply one mutation to a scratch copy, run the default suite, report whether any test failed.
SRC=$1; WORK=$2; PY=${PY:-python}
run() {  # name file python-replace-expr
  rm -rf $WORK; mkdir -p $WORK; cp -r $SRC/investigator $SRC/tests $SRC/pyproject.toml $WORK/
  $PY - "$WORK/$2" "$3" "$4" <<'PYEOF'
import sys; p, old, new = sys.argv[1:4]; s = open(p).read()
assert s.count(old) >= 1, f"pattern not found in {p}: {old!r}"; open(p, "w").write(s.replace(old, new, 1))
PYEOF
  [ $? -ne 0 ] && { echo "$1: MUTATION NOT APPLIED"; return; }
  out=$(cd $WORK && $PY -m pytest -q -x -p no:cacheprovider --ignore=tests/test_browser_ui.py 2>&1 | tail -1)
  echo "$1 => $out"
}
run "R1  drop '..' traversal check"             investigator/evidence.py 'if ".." in full:' 'if False:'
run "R1  accept any install dir (name only)"     investigator/evidence.py 'return "trusted_path" if full.startswith(MANAGEMENT_AGENT_DIRS) else "unexpected_path"' 'return "trusted_path"'
run "R1  masquerade not a tree contradiction"    investigator/report.py '"user_writable_path", "masquerade_suspect"}' '"user_writable_path"}'
run "R1b admin context anywhere on host"         investigator/report.py 'and any(_same_process(e, t) for t in triggers)' ''
run "R1  benign ignores injection flag"          investigator/report.py 'if any(e.injection_suspected for e in items):' 'if False:'
run "R2  no compaction (budget ignored)"         investigator/agent.py 'if len(text) <= budget_chars:' 'if True:'
run "R2  omitted evidence not disclosed"         investigator/agent.py 'if final_exchange is not None and final_exchange.evidence_omitted:' 'if False:'
run "R3  audit clips at 6000 again"              investigator/agent.py 'limit = self.settings.audit_max_chars' 'limit = 6000'
run "R4  host context dropped from prompt"       investigator/agent.py '"host_context": hosts,' '"host_context": [],'
run "R5  missing parent => truncated again"      investigator/tools.py 'missing_parent = next_guid' 'missing_parent = next_guid; truncated = True'
run "R6  shards.total==0 not an error"           investigator/backends/wazuh.py 'shards.get("total") == 0:' 'shards.get("total") == -1:'
run "R7  no token refresh on 401"                investigator/backends/wazuh.py 'if exc.kind == "auth" and attempt == 1:' 'if False:'
run "R8  raw exception text in tool error"       investigator/tools.py 'return record("error", f"{tool_name} failed: {kind}", error=message,' 'return record("error", f"{tool_name} failed: {kind}", error=str(exc),'
run "R9  malformed alert breaks queue"           investigator/backends/wazuh.py '                skipped += 1' '                raise'
run "R10 duplicate detection off"                investigator/tools.py 'if prior is not None:' 'if False:'
run "R10 unproductive-stop off"                  investigator/agent.py 'if unproductive >= 3:' 'if False:'
run "R11 trigger marker from telemetry"          investigator/agent.py 'ctx.store.mark_trigger(item.evidence_id)' 'pass'
run "R12 markdown '=' not escaped"               investigator/report.py '#+\-.!|=~<>])' '#+\-.!|~<>])'
run "R16 done_reason=length accepted"            investigator/agent.py 'if exchange.done_reason == "length":' 'if False:'
run "R17 rejected => incomplete again"           investigator/report.py '        if outcome == "failed":' '        if outcome in ("failed", "rejected"):'
run "R18 publish before journal"                 investigator/service.py 'journal_error = before_publish(self.journal(status=final)) if before_publish else None' 'self.status = final; journal_error = before_publish(self.journal(status=final)) if before_publish else None'
run "Gate benign allowed when incomplete"        investigator/report.py '        if verdict == "benign":
            vr.verdict_adjusted_from = verdict
            verdict = "insufficient_evidence"
            vr.valid = False' '        if False:
            pass'
