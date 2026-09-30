"""Schema validation and evidence-reference enforcement."""

import pytest
from pydantic import ValidationError

from investigator.models import Finding, ReportDraft, DraftFinding, Alert, RecommendedAction


def test_finding_requires_at_least_one_evidence_id():
    with pytest.raises(ValidationError):
        Finding(finding_id="F-001", title="t", description="d", severity="high", evidence_ids=[])


def test_finding_rejects_malformed_evidence_id():
    with pytest.raises(ValidationError):
        Finding(finding_id="F-001", title="t", description="d", severity="high", evidence_ids=["EVIL-1"])


def test_finding_accepts_valid_evidence_id():
    f = Finding(finding_id="F-001", title="t", description="d", severity="high", evidence_ids=["EV-0001"])
    assert f.evidence_ids == ["EV-0001"]


def test_verdict_is_constrained():
    with pytest.raises(ValidationError):
        ReportDraft(verdict="totally_evil", confidence=0.5, summary="x")


def test_confidence_bounds():
    with pytest.raises(ValidationError):
        ReportDraft(verdict="benign", confidence=1.5, summary="x")
    with pytest.raises(ValidationError):
        ReportDraft(verdict="benign", confidence=-0.1, summary="x")


def test_draft_finding_requires_evidence():
    with pytest.raises(ValidationError):
        DraftFinding(title="t", description="d", evidence_ids=[])


def test_recommended_action_cannot_be_executed():
    a = RecommendedAction(action="isolate host")
    assert a.executed is False
    with pytest.raises(ValidationError):
        RecommendedAction(action="isolate host", executed=True)


def test_extra_fields_forbidden():
    with pytest.raises(ValidationError):
        Alert(alert_id="A", title="t", timestamp="2026-01-01T00:00:00Z", host="h",
              severity="high", surprise="field")
