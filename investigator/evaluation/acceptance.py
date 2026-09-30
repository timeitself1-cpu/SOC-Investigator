"""v0.3.1 real-model acceptance and per-run diagnostics.

``run_diagnostics`` extracts reasoning-contract behaviour from one report (what
the model proposed, what validation accepted or rejected, invalid arguments,
duplicates, loop stops, coverage, revision, prompt tokens). ``check_acceptance``
applies the amended v0.3.1 criteria, which are based on SUPPORTED BEHAVIORAL
CLAIMS, not on a particular severity:

* INC-004: verdict suspicious|likely_malicious AND the authentication attack pattern
  (``brute_force``) accepted. A confirmed compromise is never required.
* INC-002: verdict suspicious|likely_malicious AND LSASS credential-dumping behavior
  (``credential_theft`` — dumping behavior, not proven theft) accepted; no rejection
  caused by hidden enum values; no loop stop.
* No accepted or uncorrected ``benign_administration`` on non-management evidence.
* INC-005 stays benign with all requirements met.

``likely_malicious`` is never required.
"""

from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path
from typing import Any

from ..models import InvestigationReport

ESCALATED = {"suspicious", "likely_malicious"}
LOOP_STOP = "consecutive duplicate or rejected"


def run_diagnostics(report: InvestigationReport, runtime_ms: float | None = None) -> dict[str, Any]:
    v = report.validation
    first = report.revision.first_validation if report.revision and report.revision.first_validation else v
    calls = report.trace.tool_calls
    model_calls = [c for c in calls if c.initiator == "model"]
    rejected_claims = Counter(c for f in report.findings for c in f.rejected_claims)
    first_rejected = Counter(report.revision.first_rejected_claims) if report.revision else rejected_claims
    exchanges = report.trace.llm_exchanges
    return {
        "verdict": report.verdict, "status": report.status, "draft_verdict": first.draft_verdict,
        "claims_proposed": list(first.proposed_claims),
        "claims_accepted": sorted({c for f in report.findings for c in f.claims}),
        "claims_rejected_first_draft": dict(first_rejected),
        "claims_rejected_final": dict(rejected_claims),
        "techniques_proposed": list(first.proposed_attack_techniques),
        "techniques_accepted": sorted(m.technique_id for m in report.attack_techniques),
        "model_calls": len(model_calls),
        "invalid_argument_rejections": sum(c.status == "rejected" and c.error_kind == "invalid_argument"
                                           for c in model_calls),
        "duplicate_requests": sum(c.status == "duplicate" for c in model_calls),
        "loop_stop": any(LOOP_STOP in e for e in report.trace.errors),
        "requirements_met": {q.name: q.satisfied for q in report.coverage.requirements},
        "revision_performed": bool(report.revision and report.revision.performed),
        "revision_changed": bool(report.revision and report.revision.changed),
        "prompt_tokens_server_max": max((x.prompt_tokens or 0 for x in exchanges), default=0),
        "prompt_tokens_estimated_max": max((x.estimated_prompt_tokens or 0 for x in exchanges), default=0),
        "context_overflow": any(x.context_overflow_suspected for x in exchanges),
        "model_exchanges": len(exchanges),
        "runtime_ms": round(runtime_ms, 1) if runtime_ms is not None else None,
    }


def _benign_admin_uncorrected(d: dict[str, Any], alert_id: str) -> bool:
    """benign_administration accepted on a non-management case, or proposed in the
    final draft (after any revision) and left there."""
    if alert_id == "INC-005":
        return False
    return "benign_administration" in d["claims_accepted"] or \
        "benign_administration" in d["claims_rejected_final"]


def check_acceptance(runs: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """``runs``: alert_id -> list of diagnostics (one per repeat). A criterion
    passes only if it holds in every repeat."""
    results = []

    def crit(name: str, alert_id: str, ok_fn, describe) -> None:
        rows = runs.get(alert_id, [])
        oks = [ok_fn(d) for d in rows]
        results.append({"criterion": name, "alert": alert_id, "passed": bool(rows) and all(oks),
                        "repeats": len(rows), "passes": sum(oks), "observed": [describe(d) for d in rows]})

    crit("INC-004: escalated with the authentication attack pattern accepted (no loop stop)", "INC-004",
         lambda d: d["verdict"] in ESCALATED and "brute_force" in d["claims_accepted"] and not d["loop_stop"],
         lambda d: f"{d['verdict']}; accepted {d['claims_accepted']}; loop_stop={d['loop_stop']}")
    crit("INC-002: escalated with LSASS credential-dumping behavior accepted (no enum rejection, no loop stop)",
         "INC-002",
         lambda d: d["verdict"] in ESCALATED and "credential_theft" in d["claims_accepted"]
         and d["invalid_argument_rejections"] == 0 and not d["loop_stop"],
         lambda d: (f"{d['verdict']}; accepted {d['claims_accepted']}; invalid_args="
                    f"{d['invalid_argument_rejections']}; loop_stop={d['loop_stop']}"))
    for aid in ("INC-001", "INC-002", "INC-003", "INC-004"):
        if aid in runs:
            crit("benign_administration not accepted or left uncorrected on non-management evidence", aid,
                 lambda d, a=aid: not _benign_admin_uncorrected(d, a),
                 lambda d: f"proposed {d['claims_proposed']}; accepted {d['claims_accepted']}")
    crit("INC-005: remains benign with all requirements met", "INC-005",
         lambda d: d["verdict"] == "benign" and all(d["requirements_met"].values()),
         lambda d: f"{d['verdict']}; unmet {[k for k, v in d['requirements_met'].items() if not v]}")
    return results


def run_acceptance(settings, alerts: list[str], repeats: int = 1, out_dir: str | None = None) -> dict[str, Any]:
    from ..agent import build_agent
    from ..report import report_to_json, report_to_markdown
    agent, backend = build_agent(settings.model_copy(update={"backend": "fixture"}))
    runs: dict[str, list[dict[str, Any]]] = {}
    out = Path(out_dir) if out_dir else None
    if out:
        out.mkdir(parents=True, exist_ok=True)
    for rep in range(1, repeats + 1):
        for aid in alerts:
            alert = backend.get_alert(aid)
            if alert is None:
                continue
            t0 = time.perf_counter()
            report = agent.investigate(alert)
            d = run_diagnostics(report, (time.perf_counter() - t0) * 1000)
            d["repeat"] = rep
            runs.setdefault(aid, []).append(d)
            if out:
                (out / f"{aid}_r{rep}.json").write_text(report_to_json(report), encoding="utf-8")
                (out / f"{aid}_r{rep}.md").write_text(report_to_markdown(report), encoding="utf-8")
    criteria = check_acceptance(runs)
    result = {"model": agent.model.name, "settings": {"ollama_model": settings.ollama_model,
                                                      "num_ctx": settings.ollama_num_ctx,
                                                      "temperature": settings.ollama_temperature,
                                                      "seed": settings.ollama_seed},
              "repeats": repeats, "runs": runs, "criteria": criteria,
              "all_passed": all(c["passed"] for c in criteria)}
    if out:
        (out / "acceptance.json").write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    return result


def format_acceptance(result: dict[str, Any]) -> str:
    lines = [f"Acceptance (v0.3.1, behavior-based) — model={result['model']} repeats={result['repeats']}", ""]
    for c in result["criteria"]:
        lines.append(f"{'PASS' if c['passed'] else 'FAIL'}  [{c['alert']}] {c['criterion']}  "
                     f"({c['passes']}/{c['repeats']})")
        for o in c["observed"]:
            lines.append(f"        {o}")
    lines += ["", "Per-run diagnostics:"]
    for aid, rows in result["runs"].items():
        for d in rows:
            lines.append(f"  {aid} r{d['repeat']}: {d['verdict']:<21} draft={d['draft_verdict']} "
                         f"proposed={d['claims_proposed']} accepted={d['claims_accepted']} "
                         f"invalid_args={d['invalid_argument_rejections']} dups={d['duplicate_requests']} "
                         f"loop_stop={d['loop_stop']} revision={d['revision_performed']}/"
                         f"{'changed' if d['revision_changed'] else 'same'} "
                         f"tokens(server/est)={d['prompt_tokens_server_max']}/{d['prompt_tokens_estimated_max']} "
                         f"{d['runtime_ms']} ms")
    lines += ["", "ALL CRITERIA PASSED" if result["all_passed"] else "NOT ALL CRITERIA PASSED"]
    return "\n".join(lines)
