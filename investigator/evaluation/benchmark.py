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
        "correct": acceptable and not forbidden_verdict and not retained_forbidden and all(checks.values()),
    }


def _rate(num: int, den: int) -> float | None:
    return round(num / den, 3) if den else None


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
    return {
        "cases": len(rows) + len(harness_errors),
        "labels": {"malicious": len(mal), "benign": len(ben), "ambiguous": len(amb)},
        "correct_cases": sum(r["correct"] for r in rows),
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


def run_benchmark(settings: Settings, suite_dir: str | Path | None = None) -> dict[str, Any]:
    suite = Path(suite_dir) if suite_dir else DEFAULT_SUITE
    agent, _ = build_agent(settings.model_copy(update={"backend": "fixture"}))
    rows: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for case_dir in _case_dirs(suite):
        truth = json.loads((case_dir / "truth.json").read_text(encoding="utf-8"))
        try:
            backend = FixtureBackend(suite, only={case_dir.name})
            alert = backend.list_alerts()[0]
            isolated = InvestigationAgent(backend, agent.model, settings)
            t0 = time.perf_counter()
            report = isolated.investigate(alert)
            rows.append(score_case(report, truth, (time.perf_counter() - t0) * 1000))
        except Exception as exc:  # noqa: BLE001 - harness errors are a measured outcome
            errors.append({"case_id": truth.get("case_id", case_dir.name), "error": type(exc).__name__,
                           "trace": traceback.format_exc(limit=3)})
    return {"suite": str(suite), "model": agent.model.name, "metrics": aggregate(rows, errors),
            "cases": rows, "harness_errors": errors}


def format_benchmark(result: dict[str, Any]) -> str:
    m = result["metrics"]
    d, c, e, o = m["detection"], m["claims"], m["evidence"], m["operational"]
    esc, strict = d["escalation_threshold"], d["strict_threshold"]
    lines = [
        f"Benchmark: {result['suite']}  model={result['model']}",
        f"Cases: {m['cases']} (malicious {m['labels']['malicious']}, benign {m['labels']['benign']}, "
        f"ambiguous {m['labels']['ambiguous']}); fully correct: {m['correct_cases']}",
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
        f"Evidence recall: retrieved {e['mean_retrieved_recall']}  cited {e['mean_cited_recall']}",
        f"Operational: failed {o['failed_reports']}  incomplete {o['incomplete_reports']}  model errors "
        f"{o['model_errors']}  repairs {o['repair_attempts']}  harness errors {o['harness_errors']}  "
        f"mean runtime {o['mean_runtime_ms']} ms",
    ]
    if m["safety_checks"]["failed"]:
        lines.append(f"Safety checks failed: {m['safety_checks']['failed']}")
    lines += ["", f"{'case':<8} {'label':<10} {'verdict':<22} {'status':<11} ok  outcome  recall  notes"]
    for r in result["cases"]:
        notes = []
        if r["forbidden_verdict"]:
            notes.append("FORBIDDEN VERDICT")
        if r["retained_forbidden_claims"]:
            notes.append(f"forbidden claims {r['retained_forbidden_claims']}")
        if r["missing_refs"]:
            notes.append(f"missing {r['missing_refs']}")
        notes += [f"check:{k}" for k, v in r["checks"].items() if not v]
        rec = "-" if r["retrieved_recall"] is None else f"{r['retrieved_recall']:.2f}"
        lines.append(f"{r['case_id']:<8} {r['label']:<10} {r['verdict']:<22} {r['status']:<11} "
                     f"{'Y' if r['correct'] else 'N'}   {str(r['outcome_escalation'] or '-'):<7}  {rec:<6}  "
                     f"{'; '.join(notes)}")
    for err in result["harness_errors"]:
        lines.append(f"{err['case_id']:<8} HARNESS ERROR {err['error']}")
    return "\n".join(lines)
