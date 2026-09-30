"""Report validation: fabricated evidence IDs and unsupported claims are dropped."""

from datetime import datetime, timezone

from investigator.config import load_settings
from investigator.evidence import EvidenceStore
from investigator.models import (
    Alert, DraftFinding, InvestigationTrace, NormalizedEvent, ReportDraft,
)
from investigator.report import validate_report, report_to_json, report_to_markdown


def _store_with(backend, refs):
    store = EvidenceStore("fixture")
    for r in refs:
        store.add(backend.get_event(r), "seed")
    return store


def _trace():
    return InvestigationTrace(investigation_id="INV-x", model="mock-analyst", backend="fixture", max_steps=12)


def _base_report(store, backend, draft):
    alert = backend.get_alert("INC-001")
    now = datetime.now(timezone.utc)
    return validate_report(draft, store, alert, _trace(), [], "mock", "fixture", now, now)


def test_fabricated_evidence_reference_is_dropped(backend):
    store = _store_with(backend, ["INC001-0002"])
    draft = ReportDraft(
        verdict="suspicious", confidence=0.6, summary="s",
        findings=[DraftFinding(title="bogus", description="d", evidence_ids=["EV-9999"], claims=[])],
    )
    report = _base_report(store, backend, draft)
    assert report.findings == []  # nothing valid remained
    assert "EV-9999" in report.validation.invalid_evidence_refs
    assert not report.validation.valid


def test_partial_fabrication_keeps_real_reference(backend):
    store = _store_with(backend, ["INC001-0002"])
    real = store.all()[0].evidence_id
    draft = ReportDraft(
        verdict="suspicious", confidence=0.6, summary="s",
        findings=[DraftFinding(title="mixed", description="d", evidence_ids=[real, "EV-9999"], claims=[])],
    )
    report = _base_report(store, backend, draft)
    assert len(report.findings) == 1
    assert report.findings[0].evidence_ids == [real]
    assert "EV-9999" in report.validation.invalid_evidence_refs


def test_unsupported_claim_is_rejected(backend):
    # Evidence is a powershell process; a credential_theft claim has no support.
    store = _store_with(backend, ["INC001-0002"])
    real = store.all()[0].evidence_id
    draft = ReportDraft(
        verdict="likely_malicious", confidence=0.8, summary="s",
        findings=[DraftFinding(title="unsupported", description="d", evidence_ids=[real],
                               claims=["credential_theft"])],
    )
    report = _base_report(store, backend, draft)
    assert report.findings[0].claims == []  # credential_theft dropped
    assert "credential_theft" in report.findings[0].rejected_claims
    assert report.validation.rejected_claims >= 1


def test_unsupported_attack_mapping_is_dropped(backend):
    store = _store_with(backend, ["INC001-0002"])
    real = store.all()[0].evidence_id
    draft = ReportDraft(
        verdict="likely_malicious", confidence=0.8, summary="s",
        findings=[DraftFinding(title="f", description="d", evidence_ids=[real], claims=["execution"],
                               attack_techniques=["T1003.001"])],  # LSASS dumping, unsupported here
    )
    report = _base_report(store, backend, draft)
    assert all(m.technique_id != "T1003.001" for m in report.attack_techniques)
    assert "T1003.001" in report.validation.dropped_attack_mappings


def test_verdict_downgraded_when_no_findings_survive(backend):
    store = _store_with(backend, ["INC001-0002"])
    draft = ReportDraft(
        verdict="likely_malicious", confidence=0.9, summary="s",
        findings=[DraftFinding(title="bogus", description="d", evidence_ids=["EV-0404"], claims=[])],
    )
    report = _base_report(store, backend, draft)
    assert report.verdict == "insufficient_evidence"
    assert report.validation.verdict_adjusted_from == "likely_malicious"


def test_supported_claim_and_attack_survive(backend):
    store = _store_with(backend, ["INC001-0002"])
    real = store.all()[0].evidence_id
    draft = ReportDraft(
        verdict="suspicious", confidence=0.6, summary="s",
        findings=[DraftFinding(title="ok", description="d", evidence_ids=[real],
                               claims=["execution", "obfuscation"], attack_techniques=["T1059.001"])],
    )
    report = _base_report(store, backend, draft)
    assert set(report.findings[0].claims) == {"execution", "obfuscation"}
    assert any(m.technique_id == "T1059.001" for m in report.attack_techniques)
    assert report.validation.valid


def test_exports_render(backend):
    store = _store_with(backend, ["INC001-0002", "INC001-0003"])
    real = store.all()[0].evidence_id
    draft = ReportDraft(verdict="suspicious", confidence=0.6, summary="s",
                        findings=[DraftFinding(title="ok", description="d", evidence_ids=[real], claims=["execution"])])
    report = _base_report(store, backend, draft)
    js = report_to_json(report)
    md = report_to_markdown(report)
    assert '"verdict": "suspicious"' in js
    assert "# Investigation" in md
    assert "no response actions were executed" in md.lower()
    assert real in md


def test_rejected_claim_cannot_survive_in_narrative_summary_or_actions(backend):
    from investigator.models import DraftAction
    store = _store_with(backend, ["INC001-0002"])
    draft = ReportDraft(
        verdict="likely_malicious", confidence=0.99, summary="Passwords were definitely stolen",
        findings=[DraftFinding(title="Passwords stolen", description="Passwords were definitely stolen", severity="critical",
                               evidence_ids=["EV-0001"], claims=["credential_theft"])],
        recommended_actions=[DraftAction(action="Reset every account", rationale="Passwords were definitely stolen")])
    report = _base_report(store, backend, draft)
    assert not report.validation.valid
    assert report.verdict == "insufficient_evidence"
    assert report.confidence <= 0.3
    assert report.findings[0].severity == "informational"
    assert "Passwords were definitely stolen" not in report.summary
    assert "Passwords were definitely stolen" not in report.findings[0].description
    assert "Passwords stolen" not in report.findings[0].title
    assert all("Passwords were definitely stolen" not in a.rationale for a in report.recommended_actions)


def test_untagged_findings_cannot_bypass_verdict_guard(backend):
    store = _store_with(backend, ["INC001-0002"])
    draft = ReportDraft(verdict="likely_malicious", confidence=1.0, summary="confirmed malware",
                        findings=[DraftFinding(title="confirmed malware", description="all accounts compromised",
                                               evidence_ids=["EV-0001"], claims=[])])
    report = _base_report(store, backend, draft)
    assert report.verdict == "insufficient_evidence"
    assert "all accounts compromised" not in report.findings[0].description


def test_rejected_attack_mapping_invalidates_validation(backend):
    store = _store_with(backend, ["INC001-0002"])
    draft = ReportDraft(verdict="suspicious", confidence=0.5, summary="assessment",
                        findings=[DraftFinding(title="process", description="a process started", evidence_ids=["EV-0001"],
                                               claims=["execution"], attack_techniques=["T9999"])])
    report = _base_report(store, backend, draft)
    assert not report.validation.valid
    assert report.validation.dropped_attack_mappings == ["T9999"]


def test_duplicate_references_do_not_create_duplicate_evidence(backend):
    store = _store_with(backend, ["INC001-0002"])
    draft = ReportDraft(verdict="suspicious", confidence=0.5, summary="assessment",
                        findings=[DraftFinding(title="process", description="a process started", evidence_ids=["EV-0001"] * 3,
                                               claims=["execution", "execution"], attack_techniques=["T1059.001"] * 3)])
    report = _base_report(store, backend, draft)
    assert report.findings[0].evidence_ids == ["EV-0001"]
    assert report.findings[0].claims == ["execution"]
    assert len(report.attack_techniques) == 1


def test_model_assessment_limitations_are_application_owned(backend):
    store = _store_with(backend, ["INC001-0002"])
    draft = ReportDraft(verdict="suspicious", confidence=0.5, summary="assessment",
                        findings=[DraftFinding(title="process", description="a process started", evidence_ids=["EV-0001"],
                                               claims=["execution"])], limitations=[])
    report = _base_report(store, backend, draft)
    assert any("structured claim prerequisites only" in line for line in report.limitations)
    assert any("analyst review" in line for line in report.limitations)


def test_partial_collection_cannot_be_completed_or_benign(backend):
    store = _store_with(backend, ["INC005-0001"])
    draft = ReportDraft(verdict="benign", confidence=0.95, summary="legitimate",
                        findings=[DraftFinding(title="admin", description="management execution", evidence_ids=["EV-0001"],
                                               claims=["benign_administration"])])
    trace = _trace()
    trace.errors.append("search failed")
    now = datetime.now(timezone.utc)
    report = validate_report(draft, store, backend.get_alert("INC-005"), trace, [], "mock", "fixture", now, now)
    assert report.status == "incomplete"
    assert report.verdict == "insufficient_evidence"
    assert report.confidence <= 0.3


def test_failed_report_generation_has_failed_status(backend):
    trace = _trace()
    trace.errors.append("final_report_failed: model output did not validate")
    now = datetime.now(timezone.utc)
    report = validate_report(ReportDraft(verdict="insufficient_evidence", confidence=0.2, summary="failed"),
                             EvidenceStore("fixture"), backend.get_alert("INC-001"), trace, [], "mock", "fixture", now, now)
    assert report.status == "failed"


def test_encoded_management_script_alone_cannot_justify_likely_malicious(backend):
    store = _store_with(backend, ["INC005-0001"])
    draft = ReportDraft(verdict="likely_malicious", confidence=0.99, summary="malware",
                        findings=[DraftFinding(title="Encoded script", description="Encoded PowerShell started", evidence_ids=["EV-0001"],
                                               claims=["execution", "obfuscation"])])
    report = _base_report(store, backend, draft)
    assert report.verdict == "suspicious"
    assert report.confidence <= 0.6
    assert report.validation.verdict_adjusted_from == "likely_malicious"


def test_markdown_exports_escape_telemetry_and_model_markup(backend):
    store = _store_with(backend, ["INC001-0002"])
    malicious = '<img src="https://attacker.example/collect"> ![track](https://attacker.example/image)'
    store.all()[0].description = malicious
    store.all()[0].source_ref = '`danger` ' + malicious
    draft = ReportDraft(verdict="suspicious", confidence=0.5, summary=malicious,
                        findings=[DraftFinding(title=malicious, description=malicious, evidence_ids=["EV-0001"],
                                               claims=["execution"])])
    report = _base_report(store, backend, draft)
    output = report_to_markdown(report)
    assert "<img" not in output
    assert "![track](" not in output
    assert "&lt;img" in output
    assert r"\!\[track\]\(" in output
    assert "ref `danger`" not in output
