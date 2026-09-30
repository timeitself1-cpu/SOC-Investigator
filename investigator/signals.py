"""Deterministic local security signals: "this deserves investigation".

A small, fixed rule set over normalized events produces investigation starting
points (``Alert``). It is intentionally not a correlation engine and never
calls a model: detection stays deterministic, investigation is agentic.

Rules (highest priority first; one signal per triggering event):

* ``defender_detection``   — Microsoft Defender detection (1116/1117).
* ``office_script``        — an Office application started a script interpreter.
* ``suspicious_chain``     — a script interpreter started a commonly abused
                             system binary (rundll32, regsvr32, mshta, …).
* ``suspicious_powershell``— PowerShell with an encoded command, a hidden window,
                             or a download/execute cradle on the command line.
* ``failed_logon_burst``   — ≥ N failed logons for one account within a window.
* ``lsass_access``         — a process opened LSASS with memory-read access (Sysmon 10).
* ``persistence``          — scheduled task created (4698) or Run/RunOnce value set (Sysmon 13).

The same signals serve as the host-level check for benign closure: an alert
cannot be closed as benign while other signals exist on the host around it.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta

from .evidence import OFFICE_IMAGES, POWERSHELL_IMAGES, _ENCODED_ARG, basename
from .models import Alert, NormalizedEvent

SCRIPT_INTERPRETERS = POWERSHELL_IMAGES | {"cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
ABUSED_BINARIES = {"rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe",
                   "installutil.exe", "msbuild.exe", "wmic.exe"}
_HIDDEN = re.compile(r"(?:^|\s)-w(?:i(?:n(?:d(?:o(?:w(?:s(?:t(?:y(?:l(?:e)?)?)?)?)?)?)?)?)?)?\s+h(?:idden)?\b", re.I)
_CRADLE = re.compile(r"downloadstring|downloadfile|net\.webclient|invoke-webrequest.+\|\s*iex|\biex\b|invoke-expression",
                     re.I)
FAILED_LOGON_THRESHOLD = 5
FAILED_LOGON_WINDOW = timedelta(minutes=10)

RULES = {
    "defender_detection": ("Microsoft Defender detection", 0),
    "lsass_access": ("LSASS memory access", 0),
    "persistence": ("Persistence mechanism created", 1),
    "office_script": ("Office application started a script interpreter", 1),
    "suspicious_chain": ("Script interpreter started a commonly abused system binary", 2),
    "suspicious_powershell": ("Suspicious PowerShell", 3),
    "failed_logon_burst": ("Repeated failed logons", 4),
}


@dataclass(frozen=True)
class Signal:
    rule: str
    title: str
    severity: str
    event: NormalizedEvent


def _alert_id(rule: str, event_ref: str) -> str:
    return "SIG-" + hashlib.sha256(f"{rule}|{event_ref}".encode()).hexdigest()[:12]


def _process_signal(ev: NormalizedEvent) -> Signal | None:
    img, parent = basename(ev.image), basename(ev.parent_image)
    cmd = ev.command_line or ""
    if parent in OFFICE_IMAGES and img in SCRIPT_INTERPRETERS:
        return Signal("office_script", f"{RULES['office_script'][0]}: {parent} → {img}", "high", ev)
    if parent in SCRIPT_INTERPRETERS and img in ABUSED_BINARIES:
        return Signal("suspicious_chain", f"{RULES['suspicious_chain'][0]}: {parent} → {img}", "high", ev)
    if img in POWERSHELL_IMAGES:
        reasons = []
        if _ENCODED_ARG.search(cmd):
            reasons.append("encoded command")
        if _HIDDEN.search(cmd):
            reasons.append("hidden window")
        if _CRADLE.search(cmd):
            reasons.append("download/execute pattern")
        if reasons:
            sev = "high" if len(reasons) > 1 or "download/execute pattern" in reasons else "medium"
            return Signal("suspicious_powershell", f"Suspicious PowerShell ({', '.join(reasons)})", sev, ev)
    return None


def _defender_signal(ev: NormalizedEvent) -> Signal:
    sev = {"severe": "critical", "high": "high", "moderate": "medium", "low": "low"}.get(
        (ev.threat_severity or "").casefold(), "high")
    return Signal("defender_detection", f"{RULES['defender_detection'][0]}: {ev.threat_name or 'unknown threat'}",
                  sev, ev)


def _failed_logon_signals(events: list[NormalizedEvent]) -> list[Signal]:
    by_account: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)
    for ev in events:
        if ev.category == "authentication" and ev.auth_outcome == "failure" and ev.user:
            by_account[(ev.host.casefold(), ev.user.casefold())].append(ev)
    out: list[Signal] = []
    for evs in by_account.values():
        evs.sort(key=lambda e: e.timestamp)
        i = 0
        while i + FAILED_LOGON_THRESHOLD - 1 < len(evs):
            window = evs[i:i + FAILED_LOGON_THRESHOLD]
            if window[-1].timestamp - window[0].timestamp <= FAILED_LOGON_WINDOW:
                trigger = window[-1]
                out.append(Signal("failed_logon_burst",
                                  f"{RULES['failed_logon_burst'][0]}: {FAILED_LOGON_THRESHOLD}+ failures for "
                                  f"{trigger.user} within {int(FAILED_LOGON_WINDOW.total_seconds() // 60)} min",
                                  "medium", trigger))
                # One signal per burst: skip past events inside this window.
                end = trigger.timestamp + FAILED_LOGON_WINDOW
                while i < len(evs) and evs[i].timestamp <= end:
                    i += 1
            else:
                i += 1
    return out


def detect(events: list[NormalizedEvent]) -> list[Signal]:
    """Apply the rules. Deterministic; one signal per triggering event."""
    chosen: dict[str, Signal] = {}
    candidates: list[Signal] = []
    detections: dict[tuple[str, str, str], NormalizedEvent] = {}
    for ev in sorted(events, key=lambda e: (e.timestamp, e.event_ref)):
        if ev.category == "detection" and ev.event_id in (1116, 1117):
            # 1116 (detected) and 1117 (action taken) describe one detection:
            # one signal, anchored on the earliest record.
            key = (ev.host.casefold(), (ev.threat_name or "").casefold(), (ev.target_filename or "").casefold())
            first = detections.get(key)
            if first is None or ev.timestamp - first.timestamp > FAILED_LOGON_WINDOW:
                detections[key] = ev
                candidates.append(_defender_signal(ev))
        elif ev.category == "process":
            sig = _process_signal(ev)
            if sig:
                candidates.append(sig)
        elif ev.category == "process_access" and basename(ev.target_image) == "lsass.exe":
            try:
                reads_memory = bool(int(ev.granted_access or "0", 0) & 0x10)
            except ValueError:
                reads_memory = False
            if reads_memory:
                candidates.append(Signal("lsass_access", f"{RULES['lsass_access'][0]} by "
                                         f"{basename(ev.image) or 'unknown process'}", "high", ev))
        elif ev.category == "scheduled_task" and ev.event_id == 4698:
            candidates.append(Signal("persistence", f"{RULES['persistence'][0]}: scheduled task "
                                     f"{ev.task_name or '?'}", "medium", ev))
        elif (ev.category == "registry" and ev.event_id == 13 and ev.target_object
              and re.search(r"\\currentversion\\run(?:once)?\\", ev.target_object, re.I)):
            candidates.append(Signal("persistence", f"{RULES['persistence'][0]}: Run key value "
                                     f"{ev.target_object.rsplit(chr(92), 1)[-1]}", "medium", ev))
    candidates += _failed_logon_signals(events)
    for sig in candidates:
        prior = chosen.get(sig.event.event_ref)
        if prior is None or RULES[sig.rule][1] < RULES[prior.rule][1]:
            chosen[sig.event.event_ref] = sig
    return sorted(chosen.values(), key=lambda s: (s.event.timestamp, s.event.event_ref), reverse=True)


def to_alert(sig: Signal) -> Alert:
    ev = sig.event
    return Alert(alert_id=_alert_id(sig.rule, ev.event_ref), title=sig.title[:300], timestamp=ev.timestamp,
                 host=ev.host, severity=sig.severity, rule_id=sig.rule, event_ref=ev.event_ref,  # type: ignore[arg-type]
                 process_guid=ev.process_guid, user=ev.user, source="windows")
