"""Conservative support checks for observed behavior and ATT&CK hypotheses.

These predicates check structured telemetry prerequisites, not intent or the
truth of model-written prose. A mapping is a hypothesis for analyst review.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
import re
from typing import Callable, Iterable

from .evidence import POWERSHELL_IMAGES, basename
from .models import Evidence

Pred = Callable[[list[Evidence]], bool]
CORRELATION_WINDOW = timedelta(minutes=15)


def _unique(evs: Iterable[Evidence]) -> list[Evidence]:
    return list({e.evidence_id: e for e in evs}.values())


def _any(evs: Iterable[Evidence], f: Callable[[Evidence], bool]) -> bool:
    return any(f(e) for e in evs)


def has_category(*cats: str) -> Pred:
    return lambda evs: _any(evs, lambda e: e.category in cats)


def has_indicator(*tags: str) -> Pred:
    return lambda evs: _any(evs, lambda e: any(t in e.indicators for t in tags))


def image_is(*names: str) -> Pred:
    names_l = {n.lower() for n in names}
    return lambda evs: _any(evs, lambda e: e.category == "process" and basename(e.attributes.get("image")) in names_l)


def count_indicator(tag: str, n: int) -> Pred:
    return lambda evs: sum(1 for e in _unique(evs) if tag in e.indicators) >= n


def _unavailable(evs: list[Evidence]) -> bool:
    """Current telemetry lacks the facts necessary to establish this claim."""
    return False


def _same_process(a: Evidence, b: Evidence) -> bool:
    # Missing GUIDs and matching executable names do not establish identity.
    return bool(a.process_guid and b.process_guid and a.host.casefold() == b.host.casefold()
                and a.process_guid.casefold() == b.process_guid.casefold())


def _lsass_dump(evs: list[Evidence]) -> bool:
    for access in evs:
        if access.category != "process_access" or "lsass_target" not in access.indicators:
            continue
        try:
            mask = int(access.attributes.get("granted_access", ""), 0)
        except ValueError:
            continue
        if not mask & 0x10:  # PROCESS_VM_READ; query-only access is insufficient.
            continue
        if any(e.category == "file" and "memory_dump_file" in e.indicators
               and _same_process(access, e) and timedelta(0) <= e.timestamp - access.timestamp <= CORRELATION_WINDOW
               for e in evs):
            return True
    return False


def _auth_key(e: Evidence) -> tuple[str, str, str] | None:
    user, source = e.attributes.get("user"), e.attributes.get("src_ip")
    if e.category != "authentication" or not user or not source or source == "-":
        return None
    return e.host.casefold(), user.casefold(), source.casefold()


def _failure_groups(evs: list[Evidence]) -> dict[tuple[str, str, str], list[Evidence]]:
    groups: dict[tuple[str, str, str], list[Evidence]] = defaultdict(list)
    for e in _unique(evs):
        key = _auth_key(e)
        if key and e.attributes.get("auth_outcome") == "failure":
            groups[key].append(e)
    return groups


def _brute_force(evs: list[Evidence]) -> bool:
    for failures in _failure_groups(evs).values():
        times = sorted(e.timestamp for e in failures)
        if any(times[i + 2] - times[i] <= CORRELATION_WINDOW for i in range(len(times) - 2)):
            return True
    return False


def _compromise_pattern(evs: list[Evidence]) -> bool:
    groups = _failure_groups(evs)
    return any(e.attributes.get("auth_outcome") == "success"
               and sum(timedelta(0) < e.timestamp - f.timestamp <= CORRELATION_WINDOW
                       for f in groups.get(_auth_key(e), [])) >= 3
               for e in evs if _auth_key(e))


def _account_discovery(evs: list[Evidence]) -> bool:
    return any(e.category == "process" and basename(e.attributes.get("image")) in {"net.exe", "net1.exe"}
               and re.match(r'^\s*(?:"[^"\r\n]*\\net1?\.exe"|\S+)\s+(?:user|group|localgroup)(?:\s|$)',
                            e.attributes.get("command_line", ""), re.IGNORECASE)
               for e in evs)


def malicious_hypothesis_supported(evs: list[Evidence]) -> bool:
    """Minimum corroboration for a likely-malicious assessment, never proof."""
    if _lsass_dump(evs) or _compromise_pattern(evs):
        return True
    for process in evs:
        if {"office_parent", "encoded_command"}.issubset(process.indicators):
            if any(e.category == "network" and "external_destination" in e.indicators
                   and _same_process(process, e)
                   and timedelta(0) <= e.timestamp - process.timestamp <= CORRELATION_WINDOW for e in evs):
                return True
    for registry in evs:
        payload = registry.attributes.get("details", "").casefold()
        if "run_key" in registry.indicators and len(payload) > 3:
            if any("scheduled_task" in e.indicators and e.host.casefold() == registry.host.casefold()
                   and payload in e.attributes.get("task_content", "").casefold()
                   and abs(e.timestamp - registry.timestamp) <= CORRELATION_WINDOW for e in evs):
                return True
    return False


@dataclass(frozen=True)
class Technique:
    technique_id: str
    name: str
    tactic: str
    support: Pred
    requirement: str


CATALOG: dict[str, Technique] = {
    t.technique_id: t
    for t in [
        Technique("T1059.001", "Command and Scripting Interpreter: PowerShell", "execution",
                  image_is(*POWERSHELL_IMAGES), "a cited PowerShell process-creation event"),
        Technique("T1027", "Obfuscated Files or Information", "defense-evasion",
                  has_indicator("encoded_command"), "a cited PowerShell process with an encoded command"),
        Technique("T1204.002", "User Execution: Malicious File", "execution",
                  _unavailable, "verified malicious-file and user-execution evidence (not available in this schema)"),
        Technique("T1105", "Ingress Tool Transfer", "command-and-control",
                  _unavailable, "verified inbound tool transfer; a connection alone is insufficient"),
        Technique("T1071.001", "Application Layer Protocol: Web Protocols", "command-and-control",
                  _unavailable, "application-layer command-and-control evidence; a web port alone is insufficient"),
        Technique("T1003.001", "OS Credential Dumping: LSASS Memory", "credential-access",
                  _lsass_dump, "LSASS memory-read access and a subsequent dump file from the same host/process within 15 minutes"),
        Technique("T1053.005", "Scheduled Task/Job: Scheduled Task", "persistence",
                  has_indicator("scheduled_task"), "a cited scheduled-task creation event"),
        Technique("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", "persistence",
                  has_indicator("run_key"), "a cited registry Run/RunOnce value modification"),
        Technique("T1110", "Brute Force", "credential-access",
                  _brute_force, "3 distinct failed logons for the same host, account and source within 15 minutes"),
        Technique("T1078", "Valid Accounts", "initial-access",
                  _compromise_pattern, "a success following 3 distinct failures for the same host, account and source within 15 minutes"),
        Technique("T1021.001", "Remote Services: Remote Desktop Protocol", "lateral-movement",
                  lambda evs: any(e.category == "authentication" and e.attributes.get("logon_type") == "10"
                                  and e.attributes.get("auth_outcome") == "success" for e in evs),
                  "a cited successful RemoteInteractive (type 10) logon; this does not prove lateral movement"),
        Technique("T1033", "System Owner/User Discovery", "discovery",
                  image_is("whoami.exe"), "a cited whoami.exe execution"),
        Technique("T1087", "Account Discovery", "discovery",
                  _account_discovery, "a cited net.exe/net1.exe user, group or localgroup command"),
    ]
}


# These are minimum prerequisites for hypotheses, not proof of attacker intent.
CLAIM_RULES: dict[str, tuple[Pred, str]] = {
    "execution": (has_category("process"), "process-creation evidence"),
    "obfuscation": (has_indicator("encoded_command"), "an encoded PowerShell command"),
    "office_child_process": (has_indicator("office_parent"), "a process-creation event with an Office parent"),
    "network_connection": (has_category("network"), "connection evidence; DNS alone is insufficient"),
    "command_and_control": (_unavailable, "confirmed command-and-control context unavailable in the current telemetry schema"),
    "payload_download": (_unavailable, "verified transfer evidence unavailable in the current telemetry schema"),
    "credential_theft": (_lsass_dump, "correlated LSASS memory-read access and a subsequent dump from the same host/process"),
    "persistence": (has_indicator("run_key", "scheduled_task"), "Run/RunOnce modification or scheduled-task creation evidence"),
    "brute_force": (_brute_force, "3 distinct failures for the same host/account/source within 15 minutes"),
    "account_compromise": (_compromise_pattern, "a success following 3 failures for the same host/account/source within 15 minutes"),
    "discovery": (has_indicator("discovery_command"), "a recognized discovery process/command"),
    "lateral_movement": (_unavailable, "correlated source-host and destination-host activity unavailable in the current schema"),
    "privilege_escalation": (_unavailable, "a verified privilege transition unavailable in the current schema"),
    "data_exfiltration": (_unavailable, "verified unauthorized outbound data transfer unavailable in the current schema"),
    "benign_administration": (has_indicator("management_agent_parent"), "a process-creation event from a recognized management agent; authorization still requires review"),
    "security_product_detection": (has_indicator("defender_detection"), "a cited Microsoft Defender detection event"),
    "suspicious_script": (has_indicator("suspicious_script_content"), "a cited PowerShell script block with download, in-memory loading, obfuscation or tampering content"),
}


def technique_supported(technique_id: str, evidence: list[Evidence]) -> tuple[bool, str]:
    tech = CATALOG.get(technique_id)
    if tech is None:
        return False, f"{technique_id} is not in the supported ATT&CK catalog"
    if tech.support(_unique(evidence)):
        return True, ""
    return False, f"{technique_id} requires {tech.requirement}"


def claim_supported(claim: str, evidence: list[Evidence]) -> tuple[bool, str]:
    rule = CLAIM_RULES.get(claim)
    if rule is None:
        return False, f"unknown claim {claim!r}"
    pred, need = rule
    return (True, "") if pred(_unique(evidence)) else (False, f"claim '{claim}' requires {need}")


# --- the model-facing claim contract (v0.3.1) ----------------------------------
#
# One source of truth next to CLAIM_RULES: the prompt shows these definitions and
# the validator applies CLAIM_RULES, so they cannot drift. Every claim asserts
# observed BEHAVIOR only. Intent (why) is never verified by the application, and
# outcome (e.g. credentials actually stolen, an account actually taken over) is not
# observable from this telemetry. Wire values are kept for report compatibility;
# the label states the behavior when the value's wording suggests more.

@dataclass(frozen=True)
class ClaimDefinition:
    label: str
    means: str
    does_not_mean: str
    typical_evidence: str


CLAIM_DEFINITIONS: dict[str, ClaimDefinition] = {
    "execution": ClaimDefinition(
        "Process execution", "A cited process-creation record shows the process ran.",
        "That the process was malicious.", "process events"),
    "obfuscation": ClaimDefinition(
        "Encoded PowerShell command", "A cited PowerShell process was started with an -EncodedCommand argument.",
        "That the decoded content is malicious; administrators also encode commands.",
        "process events with the encoded_command indicator"),
    "office_child_process": ClaimDefinition(
        "Office application started a process", "A cited process-creation record has an Office parent "
        "(Word, Excel, PowerPoint, Outlook, Access, Publisher).",
        "That a malicious document was opened or that the user intended it.",
        "process events with the office_parent indicator"),
    "network_connection": ClaimDefinition(
        "Network connection", "A cited network-connection record exists.",
        "Command-and-control, data transfer or exfiltration; DNS queries alone do not qualify.",
        "network events"),
    "credential_theft": ClaimDefinition(
        "LSASS credential-dumping BEHAVIOR", "A process opened LSASS with memory-read access and the same process "
        "wrote a dump file within 15 minutes (credential-access / dumping behavior).",
        "That credentials were actually stolen, exfiltrated or used; that outcome is not observable here.",
        "a process_access event targeting lsass.exe plus a .dmp file event from the same process"),
    "persistence": ClaimDefinition(
        "Persistence mechanism created", "A Run/RunOnce registry value was set or a scheduled task was created.",
        "That the persisted program is malicious.", "registry run_key or scheduled_task events"),
    "brute_force": ClaimDefinition(
        "Repeated failed logons (authentication attack pattern)",
        "At least 3 failed logons for the same host, account and source within 15 minutes.",
        "That the account was compromised or that any logon succeeded.", "authentication failure events"),
    "account_compromise": ClaimDefinition(
        "Successful logon after repeated failures (POSSIBLE compromise pattern)",
        "A successful logon followed at least 3 failures for the same host, account and source within 15 minutes.",
        "Confirmed account compromise or attacker control; the owner may have mistyped the password.",
        "authentication failure events plus the later success"),
    "discovery": ClaimDefinition(
        "Discovery command", "A recognized discovery command ran (whoami, systeminfo, ipconfig, net user/group).",
        "That the reconnaissance was hostile.", "process events with the discovery_command indicator"),
    "benign_administration": ClaimDefinition(
        "Launched by a recognized endpoint-management agent",
        "The alerted process's parent is Intune Management Extension or Configuration Manager running from its "
        "install directory.",
        "That an administrator or service account was used; that the activity looks routine; that no malicious "
        "intent was observed. Do NOT use it for accounts named admin/administrator/svc-*.",
        "a process event with the management_agent_parent indicator"),
    "security_product_detection": ClaimDefinition(
        "Microsoft Defender detection", "Microsoft Defender recorded a detection (1116/1117).",
        "That the threat executed or that remediation failed.", "detection events"),
    "suspicious_script": ClaimDefinition(
        "Suspicious PowerShell script content", "A logged script block contains download-cradle, in-memory loading, "
        "obfuscation or security-tampering patterns.",
        "That the script succeeded or was malicious in intent.",
        "script events with the suspicious_script_content indicator"),
}
UNAVAILABLE_CLAIMS = tuple(c for c, (pred, _) in CLAIM_RULES.items() if pred is _unavailable)
assert set(CLAIM_DEFINITIONS) | set(UNAVAILABLE_CLAIMS) == set(CLAIM_RULES), "claim contract out of sync"


def _claim_relevant(claim: str, e: Evidence) -> bool:
    """Records that can carry a claim's prerequisite (used to cite a compact subset)."""
    ind = set(e.indicators)
    return {
        "execution": e.category == "process",
        "obfuscation": "encoded_command" in ind,
        "office_child_process": "office_parent" in ind,
        "network_connection": e.category == "network",
        "credential_theft": "lsass_target" in ind or "memory_dump_file" in ind,
        "persistence": bool(ind & {"run_key", "scheduled_task"}),
        "brute_force": e.category == "authentication",
        "account_compromise": e.category == "authentication",
        "discovery": "discovery_command" in ind,
        "benign_administration": "management_agent_parent" in ind,
        "security_product_detection": "defender_detection" in ind,
        "suspicious_script": "suspicious_script_content" in ind,
    }.get(claim, False)


_TECHNIQUE_CLAIM = {"T1059.001": "execution", "T1027": "obfuscation", "T1003.001": "credential_theft",
                    "T1053.005": "persistence", "T1547.001": "persistence", "T1110": "brute_force",
                    "T1078": "account_compromise", "T1021.001": "brute_force", "T1033": "discovery",
                    "T1087": "discovery"}


def _supporting_subset(pred: Pred, evs: list[Evidence], relevant) -> list[Evidence]:
    """A compact subset of ``evs`` that still satisfies ``pred`` (so citing exactly
    these IDs passes validation). Falls back to everything when no subset does."""
    cand = [e for e in evs if relevant(e)]
    for subset in (cand[:12], cand):
        if subset and pred(subset):
            return subset
    return evs


def claim_eligibility(evidence: list[Evidence]) -> dict[str, list[str]]:
    """Claims whose structured prerequisites are met by ``evidence`` -> evidence IDs
    that satisfy them. Uses exactly the validator's predicates: a finding that cites
    these IDs and tags the claim is accepted. Says nothing about intent or outcome."""
    evs = _unique(evidence)
    out: dict[str, list[str]] = {}
    for claim, (pred, _) in CLAIM_RULES.items():
        if pred is _unavailable or not pred(evs):
            continue
        out[claim] = [e.evidence_id for e in _supporting_subset(pred, evs, lambda e, c=claim: _claim_relevant(c, e))]
    return out


def technique_eligibility(evidence: list[Evidence]) -> dict[str, list[str]]:
    evs = _unique(evidence)
    out: dict[str, list[str]] = {}
    for tid, tech in CATALOG.items():
        if tech.support is _unavailable or not tech.support(evs):
            continue
        claim = _TECHNIQUE_CLAIM.get(tid)
        relevant = (lambda e, c=claim: _claim_relevant(c, e)) if claim else (lambda e: True)
        out[tid] = [e.evidence_id for e in _supporting_subset(tech.support, evs, relevant)]
    return out


def claim_contract() -> list[dict[str, str]]:
    """Definitions shown to the model (behavior only; prerequisites from CLAIM_RULES)."""
    return [{"claim": c, "label": d.label, "means": d.means, "does_not_mean": d.does_not_mean,
             "requires": CLAIM_RULES[c][1], "typical_evidence": d.typical_evidence}
            for c, d in CLAIM_DEFINITIONS.items()]


def technique_contract() -> list[dict[str, str]]:
    return [{"technique": t.technique_id, "name": t.name, "requires": t.requirement}
            for t in CATALOG.values() if t.support is not _unavailable]
