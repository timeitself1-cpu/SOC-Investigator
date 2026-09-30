"""Report validation and export.

The application checks evidence identity and conservative structured claim
prerequisites. It cannot semantically verify arbitrary model-written prose or
prove malicious/benign intent. Reports explicitly retain that limitation.
"""

from __future__ import annotations

import json
import html
import re
from datetime import datetime

from . import attack
from .evidence import EvidenceStore
from .models import (
    Alert,
    AttackMapping,
    Evidence,
    Finding,
    InvestigationReport,
    InvestigationTrace,
    ProcessNode,
    RecommendedAction,
    ReportDraft,
    TimelineEntry,
    ValidationResult,
    Verdict,
)

CLAIM_VALUES = set(attack.CLAIM_RULES)
GROUNDING_LIMITATION = (
    "Automated validation checks evidence references and structured claim prerequisites only. "
    "Retained model narrative, verdict, confidence and recommendations are assessments requiring analyst review. "
    "ATT&CK mappings are behavioral hypotheses, not proof of malicious intent or successful compromise."
)


def validate_report(
    draft: ReportDraft,
    store: EvidenceStore,
    alert: Alert,
    trace: InvestigationTrace,
    process_tree: list[ProcessNode],
    model: str,
    backend: str,
    started_at: datetime,
    completed_at: datetime,
) -> InvestigationReport:
    vr = ValidationResult()
    valid_ids = store.ids()
    findings: list[Finding] = []
    all_cited: set[str] = set()
    technique_finding_ids: dict[str, set[str]] = {}
    technique_evidence: dict[str, set[str]] = {}

    for idx, df in enumerate(draft.findings, 1):
        vr.draft_evidence_refs += len(df.evidence_ids)
        real_ids = list(dict.fromkeys(eid for eid in df.evidence_ids if eid in valid_ids))
        bogus = [eid for eid in df.evidence_ids if eid not in valid_ids]
        if bogus:
            vr.invalid_evidence_refs.extend(bogus)
            vr.issues.append(f"Finding '{df.title[:40]}' referenced non-existent evidence {bogus}; dropped those refs.")
        if not real_ids:
            vr.dropped_findings += 1
            vr.issues.append(f"Finding '{df.title[:40]}' dropped: no valid evidence references remained.")
            continue
        cited_ev = [store.get(eid) for eid in real_ids]
        cited_ev = [e for e in cited_ev if e is not None]

        kept_claims = []
        for claim in dict.fromkeys(df.claims):
            if claim not in CLAIM_VALUES:
                vr.issues.append(f"Finding '{df.title[:40]}' had unknown claim '{claim}'; ignored.")
                vr.rejected_claims += 1
                continue
            ok, why = attack.claim_supported(claim, cited_ev)  # type: ignore[arg-type]
            if ok:
                kept_claims.append(claim)
            else:
                vr.rejected_claims += 1
                vr.issues.append(f"Finding '{df.title[:40]}': rejected claim ({why}).")
        rejected = [c for c in df.claims if c not in kept_claims]

        fid = f"F-{idx:03d}"
        # A rejected tag must not leave the very same allegation in prose.
        # Untagged findings also cannot bypass structured validation.
        observations_only = bool(rejected) or not kept_claims
        if observations_only:
            vr.issues.append(f"Finding '{df.title[:40]}': replaced unchecked narrative with retrieved observations.")
        description = ("Retrieved observations only; the proposed interpretation was not accepted.\n" +
                       "\n".join(f"{e.evidence_id}: {e.description}" for e in cited_ev))[:2000]
        findings.append(Finding(
            finding_id=fid,
            title="Retrieved evidence observations" if observations_only else df.title,
            description=description if observations_only else df.description,
            severity="informational" if observations_only else df.severity,
            evidence_ids=real_ids, claims=kept_claims,  # type: ignore[arg-type]
            rejected_claims=[str(c) for c in rejected],
        ))
        all_cited.update(real_ids)

        for tech in dict.fromkeys(df.attack_techniques):
            ok, why = attack.technique_supported(tech, cited_ev)  # type: ignore[arg-type]
            if ok:
                technique_finding_ids.setdefault(tech, set()).add(fid)
                technique_evidence.setdefault(tech, set()).update(real_ids)
            else:
                vr.dropped_attack_mappings.append(tech)
                vr.issues.append(f"Dropped ATT&CK {tech}: {why}.")

    attack_mappings: list[AttackMapping] = []
    for tech_id, f_ids in technique_finding_ids.items():
        tech = attack.CATALOG[tech_id]
        attack_mappings.append(AttackMapping(
            technique_id=tech_id, name=tech.name, tactic=tech.tactic,
            finding_ids=sorted(f_ids), evidence_ids=sorted(technique_evidence[tech_id]),
        ))
    attack_mappings.sort(key=lambda m: m.technique_id)

    # Referencing one real event is not enough to justify a strong verdict.
    verdict: Verdict = draft.verdict
    confidence = draft.confidence
    supported_claims = {claim for f in findings for claim in f.claims}
    if not supported_claims and verdict != "insufficient_evidence":
        vr.verdict_adjusted_from = verdict
        verdict = "insufficient_evidence"
        confidence = min(confidence, 0.3)
        vr.issues.append("Verdict downgraded to insufficient_evidence: no supported structured claims remained.")
    elif verdict == "benign" and ("benign_administration" not in supported_claims
                                  or attack.malicious_hypothesis_supported(store.all())):
        vr.verdict_adjusted_from = verdict
        verdict = "insufficient_evidence"
        confidence = min(confidence, 0.3)
        vr.issues.append("Benign verdict withheld: administrative context was absent or contradicted by correlated activity.")
    elif verdict == "likely_malicious" and not attack.malicious_hypothesis_supported(
            [e for e in store.all() if e.evidence_id in all_cited]):
        vr.verdict_adjusted_from = verdict
        verdict = "suspicious"
        confidence = min(confidence, 0.6)
        vr.issues.append("Likely-malicious verdict reduced: cited observations lacked the required correlated corroboration.")

    vr.valid = not bool(vr.issues)

    timeline = _build_timeline(store.all(), all_cited)
    recommended = [RecommendedAction(action=a.action, rationale=a.rationale, priority=a.priority)
                   for a in draft.recommended_actions]

    collection_incomplete = bool(trace.errors) or any(
        call.status in ("error", "rejected") or call.truncated for call in trace.tool_calls)
    report_failed = any(error.startswith("final_report_failed:") for error in trace.errors)
    status = "failed" if report_failed else "incomplete" if collection_incomplete else "completed"
    limitations = list(draft.limitations)
    limitations.append(GROUNDING_LIMITATION)
    if collection_incomplete:
        limitations.append("Evidence gathering was incomplete or encountered errors; see the investigation trace.")
        if verdict == "benign":
            vr.verdict_adjusted_from = verdict
            verdict = "insufficient_evidence"
            vr.valid = False
            vr.issues.append("Benign verdict withheld because evidence gathering was incomplete.")
        confidence = min(confidence, 0.5 if verdict != "insufficient_evidence" else 0.3)
    if not vr.valid:
        # Do not repeat rejected allegations through the summary or action rationale.
        summary = (f"Automated checks revised the model draft. Assessment: {verdict}. "
                   f"{len(findings)} finding(s) retained; review the observations and validation notes. "
                   "The original model output remains available in the audit trace.")
        recommended = [RecommendedAction(
            action="Review the retrieved evidence and validation notes before deciding on a response",
            rationale="The proposed report contained unsupported or unchecked interpretations.", priority="medium")]
        confidence = min(confidence, 0.6)
    else:
        summary = draft.summary
    return InvestigationReport(
        investigation_id=trace.investigation_id, status=status, alert=alert,
        verdict=verdict, confidence=confidence, summary=summary,
        findings=findings, evidence=store.all(), timeline=timeline, process_tree=process_tree,
        attack_techniques=attack_mappings, recommended_actions=recommended,
        limitations=limitations, validation=vr, trace=trace, model=model, backend=backend,
        started_at=started_at, completed_at=completed_at,
    )


def _build_timeline(evidence: list[Evidence], cited: set[str]) -> list[TimelineEntry]:
    entries = [TimelineEntry(timestamp=e.timestamp, evidence_id=e.evidence_id, host=e.host,
                             description=e.description, cited=e.evidence_id in cited)
               for e in evidence]
    entries.sort(key=lambda t: (t.timestamp, t.evidence_id))
    return entries


# --- exports ----------------------------------------------------------------


def report_to_json(report: InvestigationReport) -> str:
    return json.dumps(report.model_dump(mode="json"), indent=2)


def _markdown_text(value: str) -> str:
    """Render telemetry/model strings as text, never active Markdown or HTML."""
    text = html.escape(value, quote=True)
    return re.sub(r"([\\`*_{}\[\]()#+\-.!|])", r"\\\1", text)


def report_to_markdown(report: InvestigationReport) -> str:
    r = report
    m = _markdown_text
    L: list[str] = []
    L.append(f"# Investigation {m(r.investigation_id)}")
    L.append("")
    L.append(f"> **{m(r.notice)}**")
    L.append("")
    L.append(f"- **Alert:** {m(r.alert.alert_id)} — {m(r.alert.title)}")
    L.append(f"- **Host:** {m(r.alert.host)}")
    L.append(f"- **Verdict:** `{r.verdict}`  |  **Confidence:** {r.confidence:.2f}")
    L.append(f"- **Model:** {m(r.model)}  |  **Backend:** {m(r.backend)}  |  **Status:** {r.status}")
    L.append(f"- **Started:** {r.started_at.isoformat()}  |  **Completed:** {r.completed_at.isoformat()}")
    L.append("")
    L.append("## Summary")
    L.append("")
    L.append(m(r.summary))
    L.append("")
    if r.findings:
        L.append("## Findings")
        L.append("")
        for f in r.findings:
            L.append(f"### {f.finding_id}: {m(f.title)}  _(severity: {f.severity})_")
            L.append("")
            L.append(m(f.description))
            L.append("")
            L.append(f"- Evidence: {', '.join(f.evidence_ids)}")
            if f.claims:
                L.append(f"- Claims: {', '.join(f.claims)}")
            L.append("")
    if r.attack_techniques:
        L.append("## MITRE ATT&CK")
        L.append("")
        L.append("| Technique | Name | Tactic | Findings | Evidence |")
        L.append("| --- | --- | --- | --- | --- |")
        for m in r.attack_techniques:
            L.append(f"| {m.technique_id} | {_markdown_text(m.name)} | {_markdown_text(m.tactic)} | {', '.join(m.finding_ids)} | {', '.join(m.evidence_ids)} |")
        L.append("")
    if r.timeline:
        L.append("## Timeline")
        L.append("")
        for t in r.timeline:
            mark = "★" if t.cited else " "
            L.append(f"- `{t.timestamp.isoformat()}` [{mark}] {t.evidence_id} — {_markdown_text(t.description)}")
        L.append("")
    L.append("## Evidence")
    L.append("")
    for e in r.evidence:
        flag = " ⚠ possible-injection" if e.injection_suspected else ""
        L.append(f"- **{e.evidence_id}** ({e.category}, {_markdown_text(e.source)}, ref {_markdown_text(e.source_ref)}){flag}: {_markdown_text(e.description)}")
    L.append("")
    if r.recommended_actions:
        L.append("## Recommended Actions (not executed)")
        L.append("")
        for a in r.recommended_actions:
            L.append(f"- _[{a.priority}]_ {_markdown_text(a.action)} — {_markdown_text(a.rationale)}")
        L.append("")
    if r.limitations:
        L.append("## Limitations")
        L.append("")
        for lim in r.limitations:
            L.append(f"- {_markdown_text(lim)}")
        L.append("")
    if not r.validation.valid or r.validation.issues:
        L.append("## Validation Notes")
        L.append("")
        for issue in r.validation.issues:
            L.append(f"- {_markdown_text(issue)}")
        L.append("")
    return "\n".join(L)
