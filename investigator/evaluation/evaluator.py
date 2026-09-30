"""Evaluate an InvestigationReport against a fixture case's machine-readable
expectations.

This grades the *investigation*, not the prose: required-evidence recall,
unsupported claims, evidence-reference validity, verdict acceptability,
completion, tool-call count and runtime. Required evidence is matched by the
application-derived indicators actually attached to retrieved evidence, so a
report cannot pass by describing evidence it never collected.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import timedelta
from typing import Any

from ..evidence import basename
from ..models import InvestigationReport

# Maps a human "required_evidence" label to the indicator(s) that prove it.
EVIDENCE_INDICATOR_MAP: dict[str, list[str]] = {
    "powershell_execution": ["powershell"],
    "winword_parent": ["office_parent"],
    "encoded_command": ["encoded_command"],
    "outbound_connection": ["external_destination"],
    "internal_connection": ["internal_destination"],
    "lsass_access": ["lsass_target"],
    "dump_file": ["memory_dump_file"],
    "scheduled_task_creation": ["scheduled_task"],
    "run_key_modification": ["run_key"],
    "successful_logon": ["successful_logon"],
    "external_source_ip": ["external_source"],
}


@dataclass
class CaseScore:
    alert_id: str
    passed: bool
    verdict: str
    verdict_acceptable: bool
    confidence: float
    required_evidence_total: int
    required_evidence_found: int
    evidence_recall: float
    missing_evidence: list[str] = field(default_factory=list)
    missing_indicators: list[str] = field(default_factory=list)
    forbidden_claims_present: list[str] = field(default_factory=list)
    invalid_evidence_refs: list[str] = field(default_factory=list)
    invalid_finding_refs: list[str] = field(default_factory=list)
    unexpected_attack: list[str] = field(default_factory=list)
    expected_attack_missing: list[str] = field(default_factory=list)
    completed: bool = True
    assessment_valid: bool = True
    validation_issues: list[str] = field(default_factory=list)
    tool_calls: int = 0
    successful_tool_calls: int = 0
    findings: int = 0
    runtime_ms: float = 0.0
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _present_indicators(report: InvestigationReport) -> set[str]:
    tags: set[str] = set()
    for e in report.evidence:
        tags.update(e.indicators)
    return tags


def _required_evidence_present(report: InvestigationReport, label: str, present: set[str]) -> bool:
    if label == "rundll32_execution":
        return any(e.category == "process" and basename(e.attributes.get("image")) == "rundll32.exe"
                   for e in report.evidence)
    if label == "multiple_failed_logons":
        # Evidence count alone is insufficient: duplicate or unrelated failures
        # do not establish the fixture's password-guessing sequence.
        groups: dict[tuple[str, str, str], dict[str, Any]] = {}
        for e in report.evidence:
            user, source = e.attributes.get("user"), e.attributes.get("src_ip")
            if e.category == "authentication" and e.attributes.get("auth_outcome") == "failure" and user and source:
                key = (e.host.casefold(), user.casefold(), source.casefold())
                groups.setdefault(key, {})[e.source_ref] = e.timestamp
        return any(times[i + 2] - times[i] <= timedelta(minutes=15)
                   for values in groups.values() for times in [sorted(values.values())]
                   for i in range(len(times) - 2))
    if label == "scheduled_task_creation":
        return any(e.category == "scheduled_task" for e in report.evidence)
    needed = EVIDENCE_INDICATOR_MAP.get(label, [])
    return bool(needed) and all(ind in present for ind in needed)


def evaluate_case(report: InvestigationReport, expectations: dict[str, Any], runtime_ms: float) -> CaseScore:
    required = expectations.get("required_evidence", [])
    acceptable = set(expectations.get("acceptable_verdicts", []))
    forbidden = set(expectations.get("forbidden_claims", []))
    expected_attack = set(expectations.get("expected_attack", []))
    min_tools = expectations.get("min_tool_calls", 0)

    present = _present_indicators(report)
    missing_indicators = sorted(set(expectations.get("required_indicators", [])) - present)
    found, missing = [], []
    for label in required:
        if _required_evidence_present(report, label, present):
            found.append(label)
        else:
            missing.append(label)
    recall = len(found) / len(required) if required else 1.0

    claims_present: set[str] = set()
    for f in report.findings:
        claims_present.update(f.claims)
    forbidden_hit = sorted(forbidden & claims_present)

    reported_attack = {m.technique_id for m in report.attack_techniques}
    unexpected = sorted(reported_attack - expected_attack)
    attack_missing = sorted(expected_attack - reported_attack)

    # Evidence-reference validity: every finding must cite only real evidence.
    valid_ids = {e.evidence_id for e in report.evidence}
    invalid_refs: list[str] = []
    for f in report.findings:
        invalid_refs.extend([eid for eid in f.evidence_ids if eid not in valid_ids])
    finding_ids = {f.finding_id for f in report.findings}
    invalid_finding_refs: list[str] = []
    for mapping in report.attack_techniques:
        invalid_refs.extend(eid for eid in mapping.evidence_ids if eid not in valid_ids)
        invalid_finding_refs.extend(fid for fid in mapping.finding_ids if fid not in finding_ids)
    invalid_refs.extend(report.validation.invalid_evidence_refs)

    validation = report.validation
    validation_issues = list(validation.issues)
    if not validation.valid:
        validation_issues.append("report assessment failed validation")
    if validation.rejected_claims or any(f.rejected_claims for f in report.findings):
        validation_issues.append("model draft contained rejected claims")
    if validation.dropped_findings:
        validation_issues.append("model draft contained dropped findings")
    if validation.dropped_attack_mappings:
        validation_issues.append("model draft contained unsupported ATT&CK mappings")
    if validation.verdict_adjusted_from:
        validation_issues.append("model verdict required correction")
    assessment_valid = not bool(validation_issues or invalid_refs or invalid_finding_refs)

    verdict_acceptable = report.verdict in acceptable if acceptable else True
    completed = report.status == "completed" and not report.trace.errors and not any(
        call.status in ("error", "rejected") or call.truncated for call in report.trace.tool_calls)
    tool_count = len(report.trace.tool_calls)
    successful_tools = sum(call.status == "ok" for call in report.trace.tool_calls)

    notes: list[str] = []
    passed = True
    if not verdict_acceptable:
        passed = False; notes.append(f"verdict {report.verdict} not in acceptable set {sorted(acceptable)}")
    if missing:
        passed = False; notes.append(f"missing required evidence: {missing}")
    if missing_indicators:
        passed = False; notes.append(f"missing required indicators: {missing_indicators}")
    if forbidden_hit:
        passed = False; notes.append(f"made forbidden claim(s): {forbidden_hit}")
    if invalid_refs:
        passed = False; notes.append(f"invalid evidence references: {sorted(set(invalid_refs))}")
    if invalid_finding_refs:
        passed = False; notes.append(f"invalid ATT&CK finding references: {sorted(set(invalid_finding_refs))}")
    if not assessment_valid:
        passed = False; notes.append("assessment required validation corrections or has invalid references")
    if not completed:
        passed = False; notes.append("investigation did not complete")
    if successful_tools < min_tools:
        passed = False; notes.append(f"only {successful_tools} successful tool calls (< {min_tools})")
    if attack_missing:
        passed = False; notes.append(f"missing expected ATT&CK techniques: {attack_missing}")
    if unexpected:
        passed = False; notes.append(f"unexpected ATT&CK techniques: {unexpected}")

    return CaseScore(
        alert_id=report.alert.alert_id, passed=passed, verdict=report.verdict,
        verdict_acceptable=verdict_acceptable, confidence=report.confidence,
        required_evidence_total=len(required), required_evidence_found=len(found),
        evidence_recall=round(recall, 3), missing_evidence=missing, missing_indicators=missing_indicators,
        forbidden_claims_present=forbidden_hit, invalid_evidence_refs=sorted(set(invalid_refs)),
        invalid_finding_refs=sorted(set(invalid_finding_refs)),
        unexpected_attack=unexpected, expected_attack_missing=attack_missing,
        completed=completed, assessment_valid=assessment_valid,
        validation_issues=list(dict.fromkeys(validation_issues)),
        tool_calls=tool_count, successful_tool_calls=successful_tools, findings=len(report.findings),
        runtime_ms=round(runtime_ms, 1), notes=notes,
    )


def summarize(scores: list[CaseScore]) -> dict[str, Any]:
    n = len(scores)
    passed = sum(1 for s in scores if s.passed)
    recall = sum(s.evidence_recall for s in scores) / n if n else 0.0
    invalid = sum(len(s.invalid_evidence_refs) for s in scores)
    forbidden = sum(len(s.forbidden_claims_present) for s in scores)
    return {
        "cases": n, "passed": passed, "failed": n - passed,
        "pass_rate": round(passed / n, 3) if n else 0.0,
        "mean_evidence_recall": round(recall, 3),
        "total_invalid_evidence_refs": invalid,
        "total_forbidden_claims": forbidden,
        "all_evidence_refs_valid": invalid == 0,
    }


def run_evaluation(settings) -> dict[str, Any]:
    """Run every fixture case through the agent and score it."""
    import time

    from ..agent import build_agent
    from ..backends.fixture import FixtureBackend

    agent, backend = build_agent(settings)
    if not isinstance(backend, FixtureBackend):
        raise RuntimeError("evaluation requires the fixture backend (SOCI_BACKEND=fixture)")
    scores: list[CaseScore] = []
    reports = []
    for alert in backend.list_alerts():
        exp = backend.expectations(alert.alert_id) or {}
        t0 = time.perf_counter()
        report = agent.investigate(alert)
        dt = (time.perf_counter() - t0) * 1000
        scores.append(evaluate_case(report, exp, dt))
        reports.append(report)
    return {"summary": summarize(scores), "cases": [s.to_dict() for s in scores], "reports": reports}
