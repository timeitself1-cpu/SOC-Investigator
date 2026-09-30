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
