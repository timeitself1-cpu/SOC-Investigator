"""Evidence store: the single place where evidence IDs are created.

Telemetry is untrusted. Display attributes are bounded and screened for
instruction-like text; raw records are retained separately for auditing and
must never be treated as trusted instructions or rendered as HTML.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
import threading
from typing import Any

from .models import Evidence, NormalizedEvent

MAX_FIELD_CHARS = 600
MAX_COMMAND_CHARS = 1000
MAX_RAW_CHARS = 20_000

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f​-‏‪-‮⁦-⁩]")

INJECTION_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"ignore\s+(all\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions|rules|prompts?)",
        r"disregard\s+(all\s+)?(the\s+)?(previous|prior|above|your)\s+\w*\s*(instructions|rules)",
        r"\b(ai|llm|gpt|model)\s+(analyst|assistant|agent)\b",
        r"note\s+to\s+(the\s+)?(ai|assistant|analyst|model)",
        r"\byou\s+are\s+now\b",
        r"system\s+prompt",
        r"(classify|mark|report|treat)\s+(this|it|the\s+\w+)?\s*(as\s+)?(benign|safe|clean|false\s+positive)",
        r"\bverdict\s*[:=]",
        r"</?\s*state_json\s*>",
        r"^\s*(system|assistant|user)\s*:",
        r"\bcall\s+(the\s+)?tool\b",
    )
]

OFFICE_IMAGES = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe"}
POWERSHELL_IMAGES = {"powershell.exe", "pwsh.exe", "powershell_ise.exe"}
# Heuristic list of software-management agents that legitimately launch scripts.
MANAGEMENT_AGENT_IMAGES = {"agentexecutor.exe", "ccmexec.exe", "intunemanagementextension.exe"}
USER_WRITABLE_MARKERS = ("\\appdata\\", "\\users\\public\\", "\\windows\\temp\\", "\\downloads\\", "\\temp\\")
_ENCODED_ARG = re.compile(r"(?:^|\s)-(?:e|ec|enc|enco|encod|encode|encoded|encodedc\w*)\s+([A-Za-z0-9+/=]{16,})", re.IGNORECASE)


def sanitize_text(value: Any, limit: int = MAX_FIELD_CHARS) -> str:
    """Make untrusted text safe to store/display/embed: strip control chars, bound length."""
    text = "" if value is None else str(value)
    text = _CONTROL_CHARS.sub(" ", text)
    text = text.replace("\r", " ").replace("\n", " ")
    if limit < 0:
        raise ValueError("limit must be non-negative")
    if len(text) > limit:
        marker = " …[truncated]"
        text = text[:max(0, limit - len(marker))] + marker[:limit]
    return text


def looks_like_injection(text: str) -> bool:
    return any(p.search(text) for p in INJECTION_PATTERNS)


def basename(path: str | None) -> str:
    if not path:
        return ""
    return re.split(r"[\\/]", path)[-1].lower()


def is_public_ip(ip: str | None) -> bool | None:
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return addr.is_global and not addr.is_multicast


def decode_encoded_command(command_line: str | None) -> str | None:
    """Decode a PowerShell -EncodedCommand argument (UTF-16LE base64) for display.

    Decoded text remains untrusted telemetry and is sanitized like any other field.
    """
    if not command_line:
        return None
    m = _ENCODED_ARG.search(command_line)
    if not m:
        return None
    blob = m.group(1)
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
        text = raw.decode("utf-16-le", errors="replace")
    except (binascii.Error, ValueError):
        return None
    return sanitize_text(text, 500)


def derive_indicators(ev: NormalizedEvent) -> list[str]:
    """Deterministic, application-derived indicators. Not a verdict."""
    tags: list[str] = []
    img = basename(ev.image)
    parent = basename(ev.parent_image)
    if ev.category == "process" and img in POWERSHELL_IMAGES:
        tags.append("powershell")
    if ev.category == "process" and img in POWERSHELL_IMAGES and ev.command_line and _ENCODED_ARG.search(ev.command_line):
        tags.append("encoded_command")
    if ev.category == "process" and parent in OFFICE_IMAGES:
        tags.append("office_parent")
    if ev.category == "process" and parent in MANAGEMENT_AGENT_IMAGES:
        tags.append("management_agent_parent")
    if ev.category == "process_access" and basename(ev.target_image) == "lsass.exe":
        tags.append("lsass_target")
    if ev.category == "network":
        pub = is_public_ip(ev.dest_ip)
        if pub is True:
            tags.append("external_destination")
        elif pub is False:
            tags.append("internal_destination")
    if ev.category == "authentication":
        if ev.auth_outcome == "failure":
            tags.append("failed_logon")
        elif ev.auth_outcome == "success":
            tags.append("successful_logon")
        if ev.logon_type == 10:
            tags.append("remote_interactive_logon")
        if ev.src_ip and is_public_ip(ev.src_ip):
            tags.append("external_source")
    if (ev.category == "registry" and ev.event_id in (None, 13) and ev.target_object
            and re.search(r"\\microsoft\\windows\\currentversion\\run(?:once)?\\[^\\]+$",
                          ev.target_object, re.IGNORECASE)):
        tags.append("run_key")
    if ev.category == "scheduled_task" and ev.event_id in (None, 4698):
        tags.append("scheduled_task")
    haystack = " ".join(x for x in (ev.image, ev.command_line, ev.details, ev.target_filename, ev.task_content) if x).lower()
    if any(m in haystack for m in USER_WRITABLE_MARKERS):
        tags.append("user_writable_path")
    if ev.category == "process" and img in {"whoami.exe", "systeminfo.exe", "ipconfig.exe"}:
        tags.append("discovery_command")
    if ev.category == "process" and img in {"net.exe", "net1.exe"} and re.match(
            r'^\s*(?:"[^"\r\n]*\\net1?\.exe"|\S+)\s+(?:user|group|localgroup)(?:\s|$)',
            ev.command_line or "", re.IGNORECASE):
        tags.append("discovery_command")
    if ev.category == "file" and (ev.target_filename or "").lower().endswith(".dmp"):
        tags.append("memory_dump_file")
    return sorted(set(tags))


def describe_event(ev: NormalizedEvent) -> str:
    """Human-readable normalized description (built by code, not by the model)."""
    img = basename(ev.image) or "unknown process"
    if ev.category == "process":
        s = f"Process created: {img}"
        if ev.parent_image:
            s += f" (parent {basename(ev.parent_image)})"
        if ev.user:
            s += f" as {ev.user}"
        if ev.command_line:
            s += f" — cmd: {ev.command_line}"
        return s
    if ev.category == "network":
        dst = ev.dest_hostname or ev.dest_ip or "?"
        return f"Network connection from {img} to {dst} ({ev.dest_ip}:{ev.dest_port})"
    if ev.category == "dns":
        return f"DNS query by {img} for {ev.query_name}"
    if ev.category == "process_access":
        return f"Process access: {img} opened {basename(ev.target_image)} with access {ev.granted_access}"
    if ev.category == "file":
        return f"File created by {img}: {ev.target_filename}"
    if ev.category == "registry":
        return f"Registry value set by {img}: {ev.target_object} = {ev.details}"
    if ev.category == "authentication":
        outcome = {"success": "succeeded", "failure": "failed"}.get(ev.auth_outcome, "outcome unknown")
        return f"Logon {outcome} for {ev.user} from {ev.src_ip or 'unknown'} (logon type {ev.logon_type})"
    if ev.category == "scheduled_task":
        return f"Scheduled task created: {ev.task_name} by {ev.user}"
    return ev.rule_description or f"Event {ev.event_id} from {ev.source}"


def _bounded_raw(raw: dict[str, Any]) -> dict[str, Any]:
    import json

    text = json.dumps(raw, default=str)
    if len(text) <= MAX_RAW_CHARS:
        return raw
    return {"_truncated": True, "preview": text[:MAX_RAW_CHARS]}


_ATTR_FIELDS = (
    "image", "command_line", "parent_image", "parent_command_line", "user", "process_id",
    "src_ip", "dest_ip", "dest_port", "dest_hostname", "target_image", "granted_access",
    "target_object", "details", "target_filename", "logon_type", "auth_outcome",
    "task_name", "task_content", "query_name", "rule_id", "rule_level", "rule_description",
)


class EvidenceStore:
    """Owns evidence identity. IDs are sequential and assigned only here."""

    def __init__(self, backend_name: str, max_items: int = 200) -> None:
        self.backend_name = backend_name
        self.max_items = max_items
        self._items: dict[str, Evidence] = {}
        self._by_ref: dict[tuple[str, str, str], str] = {}
        self._lock = threading.Lock()

    def __contains__(self, evidence_id: object) -> bool:
        return evidence_id in self._items

    def __len__(self) -> int:
        return len(self._items)

    def get(self, evidence_id: str) -> Evidence | None:
        return self._items.get(evidence_id)

    def all(self) -> list[Evidence]:
        return list(self._items.values())

    def ids(self) -> set[str]:
        return set(self._items)

    def full(self) -> bool:
        return len(self._items) >= self.max_items

    def add(self, ev: NormalizedEvent, retrieved_by: str) -> Evidence | None:
        """Register an event as evidence. Re-retrieving the same event returns the same ID."""
        with self._lock:
            ref_key = (ev.source, ev.host, ev.event_ref)
            existing = self._by_ref.get(ref_key)
            if existing:
                return self._items[existing]
            if self.full():
                return None
            evidence_id = f"EV-{len(self._items) + 1:04d}"
            attrs: dict[str, str] = {}
            for name in _ATTR_FIELDS:
                val = getattr(ev, name)
                if val is None:
                    continue
                limit = MAX_COMMAND_CHARS if name in ("command_line", "parent_command_line", "task_content") else MAX_FIELD_CHARS
                attrs[name] = sanitize_text(val, limit)
            decoded = decode_encoded_command(ev.command_line) if basename(ev.image) in POWERSHELL_IMAGES else None
            if decoded:
                attrs["decoded_command"] = decoded
            indicators = derive_indicators(ev)
            description = sanitize_text(describe_event(ev), 700)
            # Screen original strings as well: truncation must not hide a signal.
            original = (str(getattr(ev, name) or "") for name in _ATTR_FIELDS)
            injection = (any(looks_like_injection(v) for v in original)
                         or any(looks_like_injection(v) for v in attrs.values())
                         or any(looks_like_injection(v or "") for v in
                                (ev.host, ev.source, ev.event_ref, ev.process_guid, ev.parent_process_guid)))
            if injection:
                indicators = sorted(set(indicators) | {"possible_prompt_injection"})
            item = Evidence(
                evidence_id=evidence_id,
                timestamp=ev.timestamp,
                host=sanitize_text(ev.host, 128),
                source=sanitize_text(ev.source, 64),
                backend=self.backend_name,
                source_ref=sanitize_text(ev.event_ref, 2048),
                event_id=ev.event_id,
                category=ev.category,
                process_guid=sanitize_text(ev.process_guid, 200) if ev.process_guid else None,
                parent_process_guid=sanitize_text(ev.parent_process_guid, 200) if ev.parent_process_guid else None,
                description=description,
                attributes=attrs,
                indicators=indicators,
                injection_suspected=injection,
                retrieved_by=retrieved_by,
                raw=_bounded_raw(ev.raw),
            )
            self._items[evidence_id] = item
            self._by_ref[ref_key] = evidence_id
            return item
