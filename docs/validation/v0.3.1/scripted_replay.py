"""Replay of the two live qwen2.5:7b runs with SCRIPTED models (not a real model).

Usage: python docs/validation/v0.3.1/scripted_replay.py <repo-root>

`ObservedQwen` repeats exactly what the live model did in
docs/validation/v0.3/live_ollama_runs/ (invented scope, duplicate loops,
benign_administration on every finding) and ignores all feedback.
`FeedbackFollower` makes the same first mistakes but reads the v0.3.1 feedback
(last_step_result, suggestions, claim contract, revision feedback).
This shows what the v0.3.1 harness does with each behaviour. It says nothing
about whether qwen2.5 will follow the contract: that is run_ollama_eval.sh.
"""
import sys

root = sys.argv[1]
sys.path.insert(0, root)
sys.path.insert(0, root + "/tests")
from investigator.evaluation.acceptance import check_acceptance, run_diagnostics  # noqa: E402
from test_reasoning_contract import FeedbackFollower, ObservedQwen, run_fixture  # noqa: E402

for model in (ObservedQwen, FeedbackFollower):
    runs = {}
    print(f"== {model.__name__}")
    for aid in ("INC-001", "INC-002", "INC-003", "INC-004", "INC-005"):
        r = run_fixture(aid, model(aid))
        d = run_diagnostics(r)
        runs[aid] = [d]
        print(f"  {aid}: verdict={d['verdict']} status={d['status']} draft={d['draft_verdict']} "
              f"proposed={d['claims_proposed']} accepted={d['claims_accepted']} "
              f"rejected_first={d['claims_rejected_first_draft']} invalid_args={d['invalid_argument_rejections']} "
              f"dups={d['duplicate_requests']} loop_stop={d['loop_stop']} "
              f"revision={d['revision_performed']}/{'changed' if d['revision_changed'] else 'same'} "
              f"unmet={[k for k, v in d['requirements_met'].items() if not v]}")
    for c in check_acceptance(runs):
        print(f"  {'PASS' if c['passed'] else 'FAIL'} [{c['alert']}] {c['criterion']}")
