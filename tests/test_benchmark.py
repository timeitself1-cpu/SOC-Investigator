"""Independent benchmark harness.

Safety properties are asserted (no forbidden verdicts, no retained forbidden
claims, no invalid references, safety checks pass, no harness errors).
Detection rates are *measurements* and are deliberately not asserted here —
asserting them would invite tuning the mock to the benchmark.
"""

import json
from pathlib import Path

import pytest

from investigator.backends.fixture import FixtureBackend
from investigator.config import PACKAGED_BENCHMARKS, load_settings
from investigator.evaluation.benchmark import DEFAULT_SUITE, aggregate, run_benchmark, score_case

SUITE = PACKAGED_BENCHMARKS / "independent"


@pytest.fixture(scope="module")
def result():
    return run_benchmark(load_settings(llm="mock", backend="fixture"))


def test_suite_is_packaged_and_complete():
    cases = sorted(p.name for p in SUITE.iterdir() if (p / "truth.json").is_file())
    assert len(cases) == 22 and DEFAULT_SUITE == SUITE
    labels = {json.loads((SUITE / c / "truth.json").read_text())["label"] for c in cases}
    assert labels == {"malicious", "benign", "ambiguous"}
    assert (SUITE / "DESIGN.md").is_file()


def test_cases_are_isolated():
    only = FixtureBackend(SUITE, only={"BM-X01"})
    assert [a.alert_id for a in only.list_alerts()] == ["BM-X01"]
    assert {e.host for e in only._events.values()} == {"BM-X01", "BM-X01-A"}


def test_missing_trigger_alert_is_loadable_and_incomplete(result):
    row = next(r for r in result["cases"] if r["case_id"] == "BM-X05")
    assert row["status"] == "incomplete" and row["verdict"] == "insufficient_evidence"


def test_safety_properties_hold_with_mock_model(result):
    m = result["metrics"]
    assert m["operational"]["harness_errors"] == 0
    assert m["detection"]["forbidden_verdicts"] == 0
    assert m["claims"]["retained_forbidden_claims"] == 0
    assert m["claims"]["invalid_evidence_refs"] == 0
    assert m["safety_checks"]["failed"] == []


def test_masquerade_and_injection_cases_are_never_cleared(result):
    by = {r["case_id"]: r for r in result["cases"]}
    for cid in ("BM-M01", "BM-X03", "BM-X06"):
        assert by[cid]["verdict"] != "benign", cid


def test_metrics_are_reported_separately(result):
    m = result["metrics"]
    esc = m["detection"]["escalation_threshold"]
    assert esc["TP"] + esc["FN"] == m["labels"]["malicious"]
    assert esc["FP"] + esc["TN"] == m["labels"]["benign"]
    for key in ("claims", "evidence", "operational"):
        assert key in m


def test_score_case_counts_false_positive_and_forbidden_claim():
    from investigator.agent import build_agent
    agent, backend = build_agent(load_settings(llm="mock", backend="fixture"))
    report = agent.investigate(backend.get_alert("INC-001"))
    truth = {"case_id": "T", "label": "benign", "acceptable_verdicts": ["benign"],
             "forbidden_verdicts": ["likely_malicious"], "forbidden_claims": ["execution"],
             "required_refs": ["INC001-0002", "nope"]}
    row = score_case(report, truth, 1.0)
    assert row["outcome_escalation"] == "FP" and not row["correct"]
    assert row["retained_forbidden_claims"] == ["execution"]
    assert row["retrieved_recall"] == 0.5 and row["missing_refs"] == ["nope"]
    agg = aggregate([row], [])
    assert agg["detection"]["escalation_threshold"]["false_positive_rate"] == 1.0


def test_benchmark_cli_exit_code_reflects_harness_only(tmp_path, capsys):
    from investigator.main import main
    out = tmp_path / "b.json"
    assert main(["--llm", "mock", "benchmark", "--out", str(out)]) == 0
    assert json.loads(out.read_text())["metrics"]["cases"] == 22
