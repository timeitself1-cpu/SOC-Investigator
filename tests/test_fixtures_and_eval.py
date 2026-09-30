"""Fixture backend behavior and evaluator scoring."""

import pytest

from investigator.backends.base import EventQuery
from investigator.config import load_settings
from investigator.evaluation.evaluator import run_evaluation, evaluate_case, summarize


EXPECTED = ["INC-001", "INC-002", "INC-003", "INC-004", "INC-005"]


def test_all_fixture_cases_load(backend):
    ids = [a.alert_id for a in backend.list_alerts()]
    assert ids == EXPECTED


def test_each_case_has_expectations(backend):
    for aid in EXPECTED:
        exp = backend.expectations(aid)
        assert exp and "required_evidence" in exp and "acceptable_verdicts" in exp


def test_trigger_events_resolve(backend):
    for a in backend.list_alerts():
        assert backend.get_event(a.event_ref) is not None


def test_search_events_respects_window(backend):
    a = backend.get_alert("INC-001")
    from datetime import timedelta
    q = EventQuery(start=a.timestamp - timedelta(minutes=5), end=a.timestamp + timedelta(minutes=5),
                   host=a.host, limit=50)
    evs = backend.search_events(q)
    assert evs
    assert all(e.host == a.host for e in evs)


def test_search_events_limit_enforced(backend):
    from datetime import timedelta
    a = backend.get_alert("INC-004")
    q = EventQuery(start=a.timestamp - timedelta(hours=2), end=a.timestamp + timedelta(hours=2), limit=3)
    assert len(backend.search_events(q)) <= 3


def test_full_evaluation_passes(settings):
    res = run_evaluation(settings)
    s = res["summary"]
    assert s["cases"] == 5
    assert s["passed"] == 5, [c["notes"] for c in res["cases"] if not c["passed"]]
    assert s["all_evidence_refs_valid"]
    assert s["total_forbidden_claims"] == 0
    assert s["mean_evidence_recall"] >= 0.9


def test_benign_case_verdict_is_acceptable(settings):
    res = run_evaluation(settings)
    inc005 = next(c for c in res["cases"] if c["alert_id"] == "INC-005")
    assert inc005["verdict"] in ("benign", "suspicious", "insufficient_evidence")
    assert inc005["passed"]


def test_evaluator_detects_forbidden_claim(backend):
    """If a report made a forbidden claim, the evaluator must fail the case."""
    from datetime import datetime, timezone
    from investigator.evidence import EvidenceStore
    from investigator.models import DraftFinding, InvestigationTrace, ReportDraft
    from investigator.report import validate_report

    store = EvidenceStore("fixture")
    store.add(backend.get_event("INC002-0003"), "seed")
    store.add(backend.get_event("INC002-0004"), "seed")  # correlated LSASS access and dump
    real = [e.evidence_id for e in store.all()]
    draft = ReportDraft(verdict="likely_malicious", confidence=0.8, summary="s",
                        findings=[DraftFinding(title="f", description="d", evidence_ids=real,
                                               claims=["credential_theft"])])
    now = datetime.now(timezone.utc)
    report = validate_report(draft, store, backend.get_alert("INC-005"),
                             InvestigationTrace(investigation_id="x", model="m", backend="fixture", max_steps=5),
                             [], "m", "fixture", now, now)
    exp = backend.expectations("INC-005")  # forbids credential_theft
    score = evaluate_case(report, exp, 1.0)
    assert not score.passed
    assert "credential_theft" in score.forbidden_claims_present


def test_summarize_math():
    class S:  # minimal duck-typed score
        def __init__(self, passed, recall, invalid, forbidden):
            self.passed = passed; self.evidence_recall = recall
            self.invalid_evidence_refs = invalid; self.forbidden_claims_present = forbidden
    scores = [S(True, 1.0, [], []), S(False, 0.5, ["EV-9"], ["x"])]
    out = summarize(scores)
    assert out["cases"] == 2 and out["passed"] == 1
    assert out["total_invalid_evidence_refs"] == 1
    assert not out["all_evidence_refs_valid"]


def test_evaluator_requires_all_expected_mappings(settings):
    report = run_evaluation(settings)["reports"][0]
    score = evaluate_case(report, {"expected_attack": ["T1059.001", "T1003.001"]}, 1)
    assert not score.passed
    assert "T1003.001" in score.expected_attack_missing


def test_evaluator_rejects_unexpected_mappings_and_missing_indicators(settings):
    report = run_evaluation(settings)["reports"][0]
    score = evaluate_case(report, {"expected_attack": [], "required_indicators": ["missing"]}, 1)
    assert not score.passed
    assert score.unexpected_attack and score.missing_indicators == ["missing"]


def test_one_auth_failure_does_not_prove_multiple(settings):
    report = next(r for r in run_evaluation(settings)["reports"] if r.alert.alert_id == "INC-004")
    failure = next(e for e in report.evidence if e.attributes.get("auth_outcome") == "failure")
    report.evidence = [failure]
    score = evaluate_case(report, {"required_evidence": ["multiple_failed_logons"]}, 1)
    assert "multiple_failed_logons" in score.missing_evidence
