"""Independent benchmark runner with separated metrics.

Each case runs in an isolated FixtureBackend (only that case's records), so
cases cannot contaminate each other. Metrics are reported separately rather
than folded into one pass rate:

* detection   — confusion counts at two thresholds (escalation: suspicious or
                likely_malicious counts as positive; strict: likely_malicious
                only), false-positive / false-negative rates, benign-cleared rate,
                over-confidence on ambiguous cases;
* claims      — structured claims the model proposed that validation rejected
                (caught), and forbidden claims that survived into the report
                (should be 0), plus invalid evidence references;
* evidence    — recall of required source records (retrieved, and cited);
* operational — failed / incomplete / cancelled reports, model errors, repair
                attempts, harness exceptions, runtime.

This measures whatever model is configured. With the mock model it measures
the deterministic pipeline and guards, not language-model judgement.
"""

from __future__ import annotations

import json
import statistics
import time
import traceback
from pathlib import Path
from typing import Any

from ..agent import InvestigationAgent, build_agent
from ..backends.fixture import FixtureBackend
from ..config import PACKAGED_BENCHMARKS, Settings

DEFAULT_SUITE = PACKAGED_BENCHMARKS / "independent"
POSITIVE = {"suspicious", "likely_malicious"}


def _case_dirs(suite: Path) -> list[Path]:
    return sorted(p for p in suite.iterdir() if p.is_dir() and (p / "truth.json").is_file())


def score_case(report, truth: dict[str, Any], runtime_ms: float) -> dict[str, Any]:
    retrieved_refs = {e.source_ref for e in report.evidence}
    cited_ids = {eid for f in report.findings for eid in f.evidence_ids}
    cited_refs = {e.source_ref for e in report.evidence if e.evidence_id in cited_ids}
    required = list(truth.get("required_refs", []))
    claims = {c for f in report.findings for c in f.claims}
    retained_forbidden = sorted(claims & set(truth.get("forbidden_claims", [])))
    acceptable = report.verdict in truth.get("acceptable_verdicts", [])
    forbidden_verdict = report.verdict in truth.get("forbidden_verdicts", [])
    checks: dict[str, bool] = {}
    if truth.get("expect_injection_flag"):
        checks["injection_flagged"] = any(e.injection_suspected for e in report.evidence)
    if truth.get("expect_status"):
        checks["status_as_expected"] = report.status == truth["expect_status"]
    if truth.get("expect_truncation_disclosed"):
        checks["truncation_disclosed"] = report.coverage.truncated > 0 and not report.coverage.complete
    if truth.get("expect_host_context_injection_flag"):
        checks["host_context_injection_flagged"] = any(
            c.tool == "get_host_context" and c.injection_suspected for c in report.trace.tool_calls)
    label = truth["label"]
    outcome = None
    if label == "malicious":
        outcome = "TP" if report.verdict in POSITIVE else "FN"
    elif label == "benign":
        outcome = "FP" if report.verdict in POSITIVE else "TN"
    return {
        "case_id": truth["case_id"], "label": label, "verdict": report.verdict, "status": report.status,
        "confidence": round(report.confidence, 2), "acceptable": acceptable,
        "forbidden_verdict": forbidden_verdict, "outcome_escalation": outcome,
        "strict_positive": report.verdict == "likely_malicious",
        "retained_forbidden_claims": retained_forbidden,
        "proposed_rejected_claims": report.validation.rejected_claims,
        "invalid_evidence_refs": len(report.validation.invalid_evidence_refs),
        "required_refs": len(required),
        "retrieved_recall": (sum(r in retrieved_refs for r in required) / len(required)) if required else None,
        "cited_recall": (sum(r in cited_refs for r in required) / len(required)) if required else None,
        "missing_refs": [r for r in required if r not in retrieved_refs],
        "checks": checks, "checks_passed": all(checks.values()),
        "coverage": {"failed": report.coverage.failed, "truncated": report.coverage.truncated,
                     "partial": report.coverage.partial, "unknowns": len(report.coverage.unknowns)},
        "model_errors": sum(1 for x in report.trace.llm_exchanges if x.error),
        "repairs": report.model_output_repairs,
        "tool_calls": len(report.trace.tool_calls),
        "runtime_ms": round(runtime_ms, 1),
        "dimensions": truth.get("dimensions", []),
        "acceptable_verdicts": list(truth.get("acceptable_verdicts", [])),
        "forbidden_verdicts": list(truth.get("forbidden_verdicts", [])),
        "correct": acceptable and not forbidden_verdict and not retained_forbidden and all(checks.values()),
        "draft_evidence_refs": report.validation.draft_evidence_refs,
        "requirements_met": sum(q.satisfied for q in report.coverage.requirements),
        "requirements_total": len(report.coverage.requirements),
        "unmet_requirements": [q.name for q in report.coverage.requirements if not q.satisfied],
        "context_overflow": any(x.context_overflow_suspected for x in report.trace.llm_exchanges),
        "blobs_compacted": max((x.blobs_compacted for x in report.trace.llm_exchanges), default=0),
        "benign_withheld": report.validation.verdict_adjusted_from == "benign",
    }


def _rate(num: int, den: int) -> float | None:
    return round(num / den, 3) if den else None


def _policy_outcomes(rows: list[dict[str, Any]], verdict_of) -> dict[str, Any]:
    """Verdict-level outcomes for any policy (the agent, or a trivial baseline)."""
    verdicts = [(r, verdict_of(r)) for r in rows]
    mal = [(r, v) for r, v in verdicts if r["label"] == "malicious"]
    ben = [(r, v) for r, v in verdicts if r["label"] == "benign"]
    return {
        "benign_true_positive": sum(v == "benign" for _, v in ben),
        "benign_false_positive": sum(v == "benign" for r, v in verdicts if r["label"] != "benign"),
        "malicious_true_positive": sum(v in POSITIVE for _, v in mal),
        "malicious_false_negative": sum(v not in POSITIVE for _, v in mal),
        "escalated_benign": sum(v in POSITIVE for _, v in ben),
        "insufficient_evidence": sum(v == "insufficient_evidence" for _, v in verdicts),
        "acceptable_verdicts": sum(v in r["acceptable_verdicts"] and v not in r["forbidden_verdicts"]
                                   for r, v in verdicts),
    }


def _contract_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Reasoning-contract behaviour across runs (v0.3.1)."""
    from collections import Counter
    diags = [r["diagnostics"] for r in rows if "diagnostics" in r]
    proposed, rejected = Counter(), Counter()
    for d in diags:
        proposed.update(d["claims_proposed"])
        rejected.update(d["claims_rejected_first_draft"])
    return {
        "runs": len(diags),
        "claims_proposed": dict(proposed), "claims_rejected_first_draft": dict(rejected),
        "invalid_argument_rejections": sum(d["invalid_argument_rejections"] for d in diags),
        "duplicate_requests": sum(d["duplicate_requests"] for d in diags),
        "loop_stops": sum(d["loop_stop"] for d in diags),
        "revisions_performed": sum(d["revision_performed"] for d in diags),
        "revisions_changed_outcome": sum(d["revision_changed"] for d in diags),
        "max_prompt_tokens_server": max((d["prompt_tokens_server_max"] for d in diags), default=0),
        "max_prompt_tokens_estimated": max((d["prompt_tokens_estimated_max"] for d in diags), default=0),
    }


def aggregate(rows: list[dict[str, Any]], harness_errors: list[dict[str, str]]) -> dict[str, Any]:
    mal = [r for r in rows if r["label"] == "malicious"]
    ben = [r for r in rows if r["label"] == "benign"]
    amb = [r for r in rows if r["label"] == "ambiguous"]
    tp = sum(r["outcome_escalation"] == "TP" for r in mal)
    fn = sum(r["outcome_escalation"] == "FN" for r in mal)
    fp = sum(r["outcome_escalation"] == "FP" for r in ben)
    tn = sum(r["outcome_escalation"] == "TN" for r in ben)
    strict_fp = sum(r["strict_positive"] for r in ben)
    strict_tp = sum(r["strict_positive"] for r in mal)
    recalls = [r["retrieved_recall"] for r in rows if r["retrieved_recall"] is not None]
    cited = [r["cited_recall"] for r in rows if r["cited_recall"] is not None]
    draft_refs = sum(r.get("draft_evidence_refs", 0) for r in rows)
    invalid_refs = sum(r["invalid_evidence_refs"] for r in rows)
    req_total = sum(r.get("requirements_total", 0) for r in rows)
    return {
        "cases": len(rows) + len(harness_errors),
        "labels": {"malicious": len(mal), "benign": len(ben), "ambiguous": len(amb)},
        # Legacy v0.2.0 headline ("fully correct"): verdict in the case's
        # acceptable set, no forbidden claims, checks passed. The acceptable sets
        # are wide, so an always-"suspicious" policy scores almost as well; read it
        # next to the baseline comparison, never alone.
        "correct_cases": sum(r["correct"] for r in rows),
        "integrity": {
            **_policy_outcomes(rows, lambda r: r["verdict"]),
            "required_evidence_recall": round(statistics.mean(recalls), 3) if recalls else None,
            "unsupported_claims_rejected": sum(r["proposed_rejected_claims"] for r in rows),
            "retained_forbidden_claims": sum(len(r["retained_forbidden_claims"]) for r in rows),
            "invalid_evidence_refs": invalid_refs,
            "evidence_ref_validity": round(1 - invalid_refs / draft_refs, 3) if draft_refs else None,
            "coverage_requirements_met": round(sum(r.get("requirements_met", 0) for r in rows) / req_total, 3)
            if req_total else None,
            "reports_with_all_requirements_met": sum(
                r.get("requirements_total", 0) > 0 and r.get("requirements_met") == r.get("requirements_total")
                for r in rows),
            "context_overflow_reports": sum(r.get("context_overflow", False) for r in rows),
            "incomplete_reports": sum(r["status"] == "incomplete" for r in rows),
            "benign_withheld_by_gates": sum(r.get("benign_withheld", False) for r in rows),
        },
        "baseline_always_suspicious": _policy_outcomes(rows, lambda r: "suspicious"),
        "contract": _contract_metrics(rows),
        "detection": {
            "escalation_threshold": {"TP": tp, "FN": fn, "FP": fp, "TN": tn,
                                     "false_negative_rate": _rate(fn, len(mal)),
                                     "false_positive_rate": _rate(fp, len(ben))},
            "strict_threshold": {"TP": strict_tp, "FN": len(mal) - strict_tp, "FP": strict_fp,
                                 "false_negative_rate": _rate(len(mal) - strict_tp, len(mal)),
                                 "false_positive_rate": _rate(strict_fp, len(ben))},
            "benign_cleared_rate": _rate(sum(r["verdict"] == "benign" for r in ben), len(ben)),
            "forbidden_verdicts": sum(r["forbidden_verdict"] for r in rows),
            "ambiguous_overconfident": sum(not r["acceptable"] for r in amb),
        },
        "claims": {
            "retained_forbidden_claims": sum(len(r["retained_forbidden_claims"]) for r in rows),
            "proposed_then_rejected_claims": sum(r["proposed_rejected_claims"] for r in rows),
            "invalid_evidence_refs": sum(r["invalid_evidence_refs"] for r in rows),
        },
        "evidence": {
            "mean_retrieved_recall": round(statistics.mean(recalls), 3) if recalls else None,
            "mean_cited_recall": round(statistics.mean(cited), 3) if cited else None,
        },
        "safety_checks": {"failed": [(r["case_id"], k) for r in rows for k, v in r["checks"].items() if not v]},
        "operational": {
            "failed_reports": sum(r["status"] == "failed" for r in rows),
            "incomplete_reports": sum(r["status"] == "incomplete" for r in rows),
            "cancelled_reports": sum(r["status"] == "cancelled" for r in rows),
            "model_errors": sum(r["model_errors"] for r in rows),
            "repair_attempts": sum(r["repairs"] for r in rows),
            "harness_errors": len(harness_errors),
            "mean_runtime_ms": round(statistics.mean(r["runtime_ms"] for r in rows), 1) if rows else None,
        },
    }


def run_benchmark(settings: Settings, suite_dir: str | Path | None = None,
                  adversary: str | None = None, repeats: int = 1) -> dict[str, Any]:
    """Run the suite. ``adversary`` replaces the model with an evaluation-only
    benign proposer (see llm.mock.ADVERSARIES) to measure the verdict gates."""
    suite = Path(suite_dir) if suite_dir else DEFAULT_SUITE
    agent, _ = build_agent(settings.model_copy(update={"backend": "fixture"}))
    if adversary:
        from ..llm.mock import ADVERSARIES
        agent.model = ADVERSARIES[adversary]()
    rows: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    from .acceptance import run_diagnostics
    for rep in range(1, max(1, repeats) + 1):
        for case_dir in _case_dirs(suite):
            truth = json.loads((case_dir / "truth.json").read_text(encoding="utf-8"))
            try:
                backend = FixtureBackend(suite, only={case_dir.name})
                alert = backend.list_alerts()[0]
                isolated = InvestigationAgent(backend, agent.model, settings)
                t0 = time.perf_counter()
                report = isolated.investigate(alert)
                ms = (time.perf_counter() - t0) * 1000
                row = score_case(report, truth, ms)
                row["repeat"] = rep
                row["diagnostics"] = run_diagnostics(report, ms)
                rows.append(row)
            except Exception as exc:  # noqa: BLE001 - harness errors are a measured outcome
                errors.append({"case_id": truth.get("case_id", case_dir.name), "error": type(exc).__name__,
                               "trace": traceback.format_exc(limit=3)})
    return {"suite": str(suite), "model": agent.model.name, "adversary": adversary,
            "metrics": aggregate(rows, errors), "cases": rows, "harness_errors": errors}


def format_benchmark(result: dict[str, Any]) -> str:
    m = result["metrics"]
    d, c, e, o = m["detection"], m["claims"], m["evidence"], m["operational"]
    esc, strict = d["escalation_threshold"], d["strict_threshold"]
    i, b = m["integrity"], m["baseline_always_suspicious"]
    n = m["cases"]
    lines = [
        f"Benchmark: {result['suite']}  model={result['model']}",
        f"Cases: {n} (malicious {m['labels']['malicious']}, benign {m['labels']['benign']}, "
        f"ambiguous {m['labels']['ambiguous']})",
        "",
        "Agent vs trivial baseline (always answers 'suspicious'):",
        f"  {'metric':<52} {'agent':>7} {'baseline':>9} {'delta':>7}",
    ]
    for key, label, better in (
            ("acceptable_verdicts", "acceptable verdicts (legacy 'fully correct' basis)", "+"),
            ("benign_true_positive", "benign TP (benign cases closed as benign)", "+"),
            ("benign_false_positive", "benign FP (non-benign cases closed as benign)", "-"),
            ("malicious_true_positive", "malicious/suspicious TP (escalated)", "+"),
            ("malicious_false_negative", "malicious/suspicious FN (not escalated)", "-"),
            ("escalated_benign", "benign cases escalated (FP at escalation)", "-"),
            ("insufficient_evidence", "insufficient_evidence outcomes", "")):
        delta = i[key] - b[key]
        lines.append(f"  {label:<52} {i[key]:>7} {b[key]:>9} {delta:>+7}")
    margin = i["acceptable_verdicts"] - b["acceptable_verdicts"]
    if margin <= max(1, n // 10):
        lines.append(f"  !! Acceptable-verdict score is {margin:+d} case(s) versus the always-'suspicious' baseline;")
        lines.append("  !! that score does not show discrimination. Judge by benign TP/FP, escalation FP and FN.")
    lines += [
        "",
        "Integrity:",
        f"  required-evidence recall {i['required_evidence_recall']}  (cited {e['mean_cited_recall']})",
        f"  unsupported claims rejected {i['unsupported_claims_rejected']}  retained forbidden claims "
        f"{i['retained_forbidden_claims']}",
        f"  evidence refs: invalid {i['invalid_evidence_refs']}  validity {i['evidence_ref_validity']}",
        f"  coverage requirements met {i['coverage_requirements_met']}  reports with all requirements met "
        f"{i['reports_with_all_requirements_met']}/{n}",
        f"  context-overflow reports {i['context_overflow_reports']}  incomplete reports {i['incomplete_reports']}  "
        f"benign withheld by gates {i['benign_withheld_by_gates']}",
        "",
        "Detection (escalation = suspicious|likely_malicious):",
        f"  TP {esc['TP']}  FN {esc['FN']}  FP {esc['FP']}  TN {esc['TN']}   "
        f"FNR {esc['false_negative_rate']}  FPR {esc['false_positive_rate']}",
        "Detection (strict = likely_malicious only):",
        f"  TP {strict['TP']}  FN {strict['FN']}  FP {strict['FP']}   "
        f"FNR {strict['false_negative_rate']}  FPR {strict['false_positive_rate']}",
        f"  benign cleared: {d['benign_cleared_rate']}  forbidden verdicts: {d['forbidden_verdicts']}  "
        f"ambiguous over-confident: {d['ambiguous_overconfident']}",
        f"Claims: retained forbidden {c['retained_forbidden_claims']}  proposed-then-rejected "
        f"{c['proposed_then_rejected_claims']}  invalid evidence refs {c['invalid_evidence_refs']}",
        f"Operational: failed {o['failed_reports']}  incomplete {o['incomplete_reports']}  model errors "
        f"{o['model_errors']}  repairs {o['repair_attempts']}  harness errors {o['harness_errors']}  "
        f"mean runtime {o['mean_runtime_ms']} ms",
        f"Legacy headline (v0.2.0 'fully correct'; see baseline above): {m['correct_cases']}/{n}",
        "",
        "Reasoning contract (v0.3.1):",
        f"  runs {m['contract']['runs']}  invalid-argument rejections {m['contract']['invalid_argument_rejections']}  "
        f"duplicate requests {m['contract']['duplicate_requests']}  loop stops {m['contract']['loop_stops']}  "
        f"revisions {m['contract']['revisions_performed']} (changed {m['contract']['revisions_changed_outcome']})",
        f"  claims rejected in first drafts: {m['contract']['claims_rejected_first_draft'] or 'none'}",
        f"  max prompt tokens server/estimated: {m['contract']['max_prompt_tokens_server']}/"
        f"{m['contract']['max_prompt_tokens_estimated']}",
    ]
    if m["safety_checks"]["failed"]:
        lines.append(f"Safety checks failed: {m['safety_checks']['failed']}")
    lines += ["", f"{'case':<8} {'label':<10} {'verdict':<22} {'status':<11} ok  outcome  recall  req  notes"]
    for r in result["cases"]:
        notes = []
        if r["forbidden_verdict"]:
            notes.append("FORBIDDEN VERDICT")
        if r["retained_forbidden_claims"]:
            notes.append(f"forbidden claims {r['retained_forbidden_claims']}")
        if r["missing_refs"]:
            notes.append(f"missing {r['missing_refs']}")
        if r.get("benign_withheld"):
            notes.append("benign withheld")
        if r.get("context_overflow"):
            notes.append("context overflow")
        notes += [f"check:{k}" for k, v in r["checks"].items() if not v]
        rec = "-" if r["retrieved_recall"] is None else f"{r['retrieved_recall']:.2f}"
        req = f"{r.get('requirements_met', 0)}/{r.get('requirements_total', 0)}"
        lines.append(f"{r['case_id']:<8} {r['label']:<10} {r['verdict']:<22} {r['status']:<11} "
                     f"{'Y' if r['correct'] else 'N'}   {str(r['outcome_escalation'] or '-'):<7}  {rec:<6}  "
                     f"{req:<4} {'; '.join(notes)}")
    for err in result["harness_errors"]:
        lines.append(f"{err['case_id']:<8} HARNESS ERROR {err['error']}")
    return "\n".join(lines)
