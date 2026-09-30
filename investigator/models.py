"""Strict typed data model for the investigator.

Design rule: the *application* owns evidence identity. The model only ever
proposes findings that reference evidence IDs the application assigned.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Verdict = Literal["benign", "suspicious", "likely_malicious", "insufficient_evidence"]
Severity = Literal["informational", "low", "medium", "high", "critical"]
EventCategory = Literal[
    "process",
    "network",
    "dns",
    "file",
    "registry",
    "process_access",
    "authentication",
    "scheduled_task",
    "process_termination",  # Sysmon 5
    "script",               # PowerShell script-block / module logging (4104/4103)
    "detection",            # Microsoft Defender detections (1116/1117)
    "privilege",            # Security 4672 special privileges assigned
    "other",
]

# Controlled claim vocabulary. Findings must tag what they assert using these
# values so claims can be checked mechanically (not by comparing prose).
Claim = Literal[
    "execution",
    "obfuscation",
    "office_child_process",
    "network_connection",
    "command_and_control",
    "payload_download",
    "credential_theft",
    "persistence",
    "brute_force",
    "account_compromise",
    "discovery",
    "lateral_movement",
    "privilege_escalation",
    "data_exfiltration",
    "benign_administration",
    "security_product_detection",
    "suspicious_script",
]

EVIDENCE_ID_PATTERN = r"^EV-\d{4}$"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------------------
# Telemetry (backend-normalized, untrusted)
# ---------------------------------------------------------------------------


class NormalizedEvent(Strict):
    """A single telemetry record normalized from Wazuh/Sysmon-shaped data.

    All string content is UNTRUSTED. It is data, never instructions.
    """

    event_ref: str  # backend source reference (fixture id or indexer _id)
    timestamp: datetime
    host: str
    source: str  # e.g. sysmon, windows-security
    event_id: int | None = None
    category: EventCategory = "other"
    rule_id: str | None = None
    rule_level: int | None = None
    rule_description: str | None = None
    process_guid: str | None = None
    parent_process_guid: str | None = None
    process_id: int | None = None
    image: str | None = None
    command_line: str | None = None
    parent_image: str | None = None
    parent_command_line: str | None = None
    user: str | None = None
    src_ip: str | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    dest_hostname: str | None = None
    target_image: str | None = None
    granted_access: str | None = None
    target_object: str | None = None
    details: str | None = None
    target_filename: str | None = None
    logon_type: int | None = None
    auth_outcome: Literal["success", "failure"] | None = None
    task_name: str | None = None
    task_content: str | None = None
    query_name: str | None = None
    # Windows-native fields (v0.3). All optional: other backends leave them empty.
    parent_process_id: int | None = None
    hashes: str | None = None             # Sysmon "Hashes" (e.g. SHA256=...,IMPHASH=...)
    protocol: str | None = None
    src_port: int | None = None
    provider: str | None = None           # event provider (e.g. Microsoft-Windows-Sysmon)
    channel: str | None = None            # event log channel
    record_id: int | None = None          # EventRecordID within the channel
    integrity_level: str | None = None
    logon_id: str | None = None
    # PowerShell script-block logging
    script_text: str | None = None
    script_block_id: str | None = None
    script_path: str | None = None
    # Microsoft Defender
    threat_name: str | None = None
    threat_severity: str | None = None
    action: str | None = None
    # True when process_guid was attached by application correlation (host + PID +
    # time against Sysmon process creation) rather than recorded in the event.
    process_guid_inferred: bool = False
    raw: dict[str, Any] = Field(default_factory=dict)


class HostContext(Strict):
    host: str
    os: str | None = None
    ip: str | None = None
    role: str | None = None
    owner: str | None = None
    criticality: str | None = None
    agent_status: str | None = None
    notes: str | None = None


class Alert(Strict):
    alert_id: str = Field(min_length=1, max_length=2048)
    title: str = Field(min_length=1, max_length=300)
    timestamp: datetime
    host: str
    severity: Severity
    status: str = "new"
    rule_id: str | None = None
    rule_level: int | None = None
    event_ref: str | None = None
    process_guid: str | None = None
    user: str | None = None
    source: str = "fixture"


# ---------------------------------------------------------------------------
# Evidence (application-owned identity)
# ---------------------------------------------------------------------------


class Evidence(Strict):
    evidence_id: str = Field(pattern=EVIDENCE_ID_PATTERN)
    timestamp: datetime
    host: str
    source: str
    backend: str
    source_ref: str  # event_ref in the backend: lets a human re-find the record
    event_id: int | None = None
    category: EventCategory = "other"
    process_guid: str | None = None
    parent_process_guid: str | None = None
    description: str  # application-generated normalized description
    attributes: dict[str, str] = Field(default_factory=dict)  # sanitized, bounded
    indicators: list[str] = Field(default_factory=list)  # application-derived tags
    injection_suspected: bool = False
    retrieved_by: str  # tool call id that first retrieved it
    retrieved_by_calls: list[str] = Field(default_factory=list)  # every call that returned this record
    retrieved_at: datetime = Field(default_factory=utcnow)
    raw: dict[str, Any] = Field(default_factory=dict)
    # Provenance disclosure: raw is bounded for storage; the hash identifies the
    # complete record as received so it can be re-fetched and compared.
    raw_sha256: str | None = None
    raw_truncated: bool = False
    truncated_fields: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Findings / report
# ---------------------------------------------------------------------------


class Finding(Strict):
    finding_id: str = Field(pattern=r"^F-\d{3}$")
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=2000)
    severity: Severity
    evidence_ids: list[str] = Field(min_length=1)
    claims: list[Claim] = Field(default_factory=list)
    rejected_claims: list[str] = Field(default_factory=list)

    @field_validator("evidence_ids")
    @classmethod
    def _ids_format(cls, v: list[str]) -> list[str]:
        import re

        for eid in v:
            if not re.match(EVIDENCE_ID_PATTERN, eid):
                raise ValueError(f"malformed evidence id: {eid!r}")
        return v


class AttackMapping(Strict):
    technique_id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    name: str
    tactic: str
    finding_ids: list[str] = Field(min_length=1)
    evidence_ids: list[str] = Field(min_length=1)


class RecommendedAction(Strict):
    action: str = Field(min_length=1, max_length=400)
    rationale: str = Field(default="", max_length=800)
    priority: Literal["low", "medium", "high"] = "medium"
    executed: Literal[False] = False  # the application never executes actions


class TimelineEntry(Strict):
    timestamp: datetime
    evidence_id: str
    host: str
    description: str
    cited: bool


class ProcessNode(Strict):
    process_guid: str
    image: str
    command_line: str | None = None
    user: str | None = None
    evidence_id: str | None = None  # None for inferred parent stubs
    children: list["ProcessNode"] = Field(default_factory=list)


class ToolCall(Strict):
    call_id: str
    step: int
    initiator: Literal["model", "system"]
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    status: Literal["ok", "rejected", "error", "duplicate"]
    summary: str  # human-readable activity summary
    evidence_ids: list[str] = Field(default_factory=list)
    result_count: int = 0
    truncated: bool = False
    error: str | None = None
    error_kind: str | None = None  # classified failure (timeout, tls, auth, index_missing, ...)
    scope: str | None = None  # human-readable description of what was queried
    gaps: list[str] = Field(default_factory=list)  # known unknowns this call exposed
    duplicate_of: str | None = None
    outcome: Literal["complete", "empty", "truncated", "partial", "failed", "rejected", "duplicate"] | None = None
    started_at: datetime = Field(default_factory=utcnow)
    duration_ms: float = 0.0
    # Application-resolved scope (host, process_guid, window) after defaults and
    # clamping. Collection requirements are checked against this, never against
    # the model's arguments or prose.
    target: dict[str, Any] | None = None
    partial_reason: Literal["ancestry_outside_window", "target_not_found", "source_degraded"] | None = None
    injection_suspected: bool = False  # instruction-like text in a non-evidence result (host context)


class LLMExchange(Strict):
    step: int
    purpose: Literal["decide", "final_report", "repair"]
    attempt: int
    model: str
    messages: list[dict[str, str]]
    response: str | None = None
    parsed_ok: bool = False
    error: str | None = None
    duration_ms: float = 0.0
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    # Audit disclosure. Prompts are bounded by the context budget before they
    # are sent; any clipping of the stored copy is recorded, never silent.
    prompt_chars: int = 0
    prompt_sha256: str | None = None
    response_chars: int = 0
    response_sha256: str | None = None
    clipped: bool = False
    done_reason: str | None = None
    prompt_budget_chars: int | None = None
    evidence_shown: int | None = None
    evidence_omitted: int = 0
    compaction_level: int = 0
    context_overflow_suspected: bool = False
    # Conservative pre-flight estimate (see compaction.estimate_tokens) and the
    # token room the prompt was allowed (num_ctx - num_predict - overhead).
    estimated_prompt_tokens: int | None = None
    prompt_token_limit: int | None = None
    blobs_compacted: int = 0       # encoded/high-entropy runs replaced by a bounded description
    evidence_summarized: int = 0   # items shown as one-line summaries without attributes
    priority_evidence_hidden: int = 0  # trigger/tree/suspicious items summarized or omitted


class ActivityEvent(Strict):
    at: datetime = Field(default_factory=utcnow)
    kind: Literal["info", "tool", "model", "warning", "error", "done"]
    message: str


class InvestigationTrace(Strict):
    investigation_id: str
    model: str
    backend: str
    max_steps: int
    steps_used: int = 0
    tool_calls: list[ToolCall] = Field(default_factory=list)
    llm_exchanges: list[LLMExchange] = Field(default_factory=list)
    activity: list[ActivityEvent] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class ValidationResult(Strict):
    valid: bool = True
    issues: list[str] = Field(default_factory=list)
    draft_evidence_refs: int = 0
    invalid_evidence_refs: list[str] = Field(default_factory=list)
    dropped_findings: int = 0
    rejected_claims: int = 0
    dropped_attack_mappings: list[str] = Field(default_factory=list)
    verdict_adjusted_from: Verdict | None = None


class CoverageItem(Strict):
    """One attempted collection step, stated in plain terms."""

    call_id: str
    tool: str
    initiator: Literal["model", "system"]
    scope: str
    outcome: Literal["complete", "empty", "truncated", "partial", "failed", "rejected", "duplicate"]
    result_count: int = 0
    error_kind: str | None = None
    detail: str | None = None


class CollectionRequirement(Strict):
    """A collection step that must have succeeded before benign closure is admissible.

    Evaluated by application code from the resolved tool-call records.
    """

    name: Literal["process_tree", "network_activity", "host_context", "host_signals", "model_visibility"]
    satisfied: bool
    reason: str
    call_ids: list[str] = Field(default_factory=list)


class CollectionCoverage(Strict):
    """What was queried, what failed or was truncated, and what remains unknown."""

    items: list[CoverageItem] = Field(default_factory=list)
    queried: int = 0
    failed: int = 0
    truncated: int = 0
    partial: int = 0
    rejected: int = 0
    duplicates: int = 0
    hosts_queried: list[str] = Field(default_factory=list)
    categories_queried: list[str] = Field(default_factory=list)
    backend_caveats: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    complete: bool = True
    requirements: list[CollectionRequirement] = Field(default_factory=list)


class ObservedFact(Strict):
    """An application-generated statement of what a retrieved record says.

    Facts are derived by code from retrieved telemetry, not from model prose.
    They state what was recorded, not whether it was malicious.
    """

    evidence_id: str
    timestamp: datetime
    host: str
    statement: str
    source_ref: str


class Hypothesis(Strict):
    """A model-proposed interpretation whose structured prerequisites passed.

    Passing prerequisites is not proof of intent, authorization or impact.
    """

    hypothesis_id: str
    kind: Literal["claim", "attack_technique"]
    label: str
    basis: str
    finding_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(min_length=1)
    status: Literal["prerequisites_met"] = "prerequisites_met"


class VerificationStep(Strict):
    """A concrete check an analyst can perform to confirm or refute something."""

    step: str
    reason: str
    related: list[str] = Field(default_factory=list)


class InvestigationReport(Strict):
    investigation_id: str
    status: Literal["completed", "incomplete", "failed", "cancelled"]
    alert: Alert
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str
    findings: list[Finding] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    timeline: list[TimelineEntry] = Field(default_factory=list)
    process_tree: list[ProcessNode] = Field(default_factory=list)
    attack_techniques: list[AttackMapping] = Field(default_factory=list)
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    validation: ValidationResult = Field(default_factory=ValidationResult)
    trace: InvestigationTrace
    model: str
    backend: str
    started_at: datetime
    completed_at: datetime
    notice: str = "Recommendations only — no response actions were executed."
    # Separation of what was observed, what is hypothesised, and what to check.
    observed_facts: list[ObservedFact] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    verification_steps: list[VerificationStep] = Field(default_factory=list)
    model_narrative: str | None = None  # model prose; never semantically verified
    coverage: CollectionCoverage = Field(default_factory=CollectionCoverage)
    host_context: list[HostContext] = Field(default_factory=list)  # untrusted asset metadata
    model_output_repairs: int = 0
    status_reasons: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Model-facing output schemas (what the LLM is allowed to produce)
# ---------------------------------------------------------------------------


class AgentDecision(Strict):
    """One step of the loop: call an allowlisted tool, or finish."""

    action: Literal["call_tool", "finish"]
    tool: str | None = Field(default=None, max_length=64)
    arguments: dict[str, Any] = Field(default_factory=dict)
    purpose: str = Field(default="", max_length=300)

    @model_validator(mode="after")
    def validate_action(self):
        if self.action == "call_tool" and not (self.tool and self.tool.strip()):
            raise ValueError("call_tool requires a tool name")
        if self.action == "finish" and (self.tool or self.arguments):
            raise ValueError("finish must not include a tool or arguments")
        return self


class DraftFinding(Strict):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=2000)
    severity: Severity = "medium"
    evidence_ids: list[str] = Field(min_length=1)
    claims: list[Claim] = Field(default_factory=list)
    attack_techniques: list[str] = Field(default_factory=list)


class DraftAction(Strict):
    action: str = Field(min_length=1, max_length=400)
    rationale: str = Field(default="", max_length=800)
    priority: Literal["low", "medium", "high"] = "medium"


class ReportDraft(Strict):
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str = Field(min_length=1, max_length=3000)
    findings: list[DraftFinding] = Field(default_factory=list, max_length=15)
    recommended_actions: list[DraftAction] = Field(default_factory=list, max_length=10)
    limitations: list[str] = Field(default_factory=list, max_length=10)


ProcessNode.model_rebuild()
