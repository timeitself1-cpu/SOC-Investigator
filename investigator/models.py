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
    retrieved_at: datetime = Field(default_factory=utcnow)
    raw: dict[str, Any] = Field(default_factory=dict)


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
    started_at: datetime = Field(default_factory=utcnow)
    duration_ms: float = 0.0


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


class InvestigationReport(Strict):
    investigation_id: str
    status: Literal["completed", "incomplete", "failed"]
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
