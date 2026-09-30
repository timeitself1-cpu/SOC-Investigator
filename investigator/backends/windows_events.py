"""Windows Event Log parsing, normalization and structured queries.

Everything here is pure Python and platform-independent, so it is unit-tested on
any OS. The only code that touches the Windows Event Log API lives in
``winevt_reader.py``.

* ``parse_event_xml`` turns one rendered event (the XML that ``EvtRender`` /
  ``wevtutil qe /f:xml`` produce) into a plain dict. Content is untrusted.
* ``normalize_windows_event`` maps supported events to ``NormalizedEvent``.
  The raw parsed event (including the original XML) is kept for provenance.
* ``ChannelQuery`` is the only way to ask a reader for events. It is built by
  application code from validated values; ``build_xpath`` renders it into the
  Windows event query XPath subset. Neither the model nor any user text can
  supply XPath: values are allowlisted by field and character set.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..models import NormalizedEvent

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
MAX_EVENT_XML_BYTES = 256 * 1024

# Supported sources: short key -> channel. Only these channels are ever queried.
Source = Literal["sysmon", "security", "powershell", "defender"]
CHANNELS: dict[str, str] = {
    "sysmon": "Microsoft-Windows-Sysmon/Operational",
    "security": "Security",
    "powershell": "Microsoft-Windows-PowerShell/Operational",
    "defender": "Microsoft-Windows-Windows Defender/Operational",
}
SOURCE_LABELS = {"sysmon": "Sysmon", "security": "Windows Security", "powershell": "PowerShell",
                 "defender": "Microsoft Defender"}
CHANNEL_TO_SOURCE = {v.casefold(): k for k, v in CHANNELS.items()}

SYSMON_CATEGORIES = {1: "process", 3: "network", 5: "process_termination", 10: "process_access", 11: "file",
                     12: "registry", 13: "registry", 14: "registry", 22: "dns"}
SECURITY_CATEGORIES = {4624: "authentication", 4625: "authentication", 4688: "process", 4672: "privilege",
                       4698: "scheduled_task"}
POWERSHELL_CATEGORIES = {4104: "script"}
DEFENDER_CATEGORIES = {1116: "detection", 1117: "detection"}
SOURCE_CATEGORIES: dict[str, dict[int, str]] = {
    "sysmon": SYSMON_CATEGORIES, "security": SECURITY_CATEGORIES,
    "powershell": POWERSHELL_CATEGORIES, "defender": DEFENDER_CATEGORIES,
}


class EventParseError(ValueError):
    pass


# --- parsing -------------------------------------------------------------------

def _windows_time(value: str | None) -> datetime | None:
    """Parse SystemTime ('2026-09-30T10:41:02.1234567Z') or Sysmon UtcTime
    ('2026-09-30 10:41:02.123'). Always UTC."""
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    m = re.match(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d+))?(.*)$", text)
    if not m:
        return None
    frac = (m.group(3) or "0")[:6].ljust(6, "0")
    tz = m.group(4) or "+00:00"
    try:
        dt = datetime.fromisoformat(f"{m.group(1)}T{m.group(2)}.{frac}{tz}")
    except ValueError:
        return None
    return dt.astimezone(timezone.utc)


def parse_event_xml(xml: str) -> dict[str, Any]:
    """Parse one rendered Windows event. Raises EventParseError if unusable."""
    if not isinstance(xml, str) or len(xml.encode("utf-8", "replace")) > MAX_EVENT_XML_BYTES:
        raise EventParseError("event XML missing or too large")
    if "<!DOCTYPE" in xml or "<!ENTITY" in xml:
        raise EventParseError("event XML must not contain DTDs or entities")
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise EventParseError("event XML is not well-formed") from exc
    if root.tag != f"{NS}Event":
        raise EventParseError("not a Windows event")
    system = root.find(f"{NS}System")
    if system is None:
        raise EventParseError("event has no System element")

    def text(tag: str) -> str | None:
        el = system.find(f"{NS}{tag}")
        return el.text if el is not None and el.text is not None else None

    provider_el = system.find(f"{NS}Provider")
    time_el = system.find(f"{NS}TimeCreated")
    exec_el = system.find(f"{NS}Execution")
    security_el = system.find(f"{NS}Security")
    try:
        event_id = int((text("EventID") or "").strip())
    except ValueError as exc:
        raise EventParseError("event has no numeric EventID") from exc
    record = text("EventRecordID")
    data: dict[str, str] = {}
    unnamed: list[str] = []
    event_data = root.find(f"{NS}EventData")
    if event_data is not None:
        for d in event_data.findall(f"{NS}Data"):
            name = d.get("Name")
            if name:
                data[name] = d.text or ""
            elif d.text:
                unnamed.append(d.text)
    user_data = root.find(f"{NS}UserData")
    if user_data is not None:  # e.g. some providers put fields under UserData/<Something>/<Field>
        for child in user_data.iter():
            if child is not user_data and len(child) == 0 and child.text:
                data.setdefault(child.tag.split("}")[-1], child.text)
    system_time = time_el.get("SystemTime") if time_el is not None else None
    return {
        "provider": provider_el.get("Name") if provider_el is not None else None,
        "event_id": event_id,
        "record_id": int(record) if record and record.strip().isdigit() else None,
        "channel": text("Channel"),
        "computer": text("Computer"),
        "system_time": system_time,
        "level": text("Level"),
        "execution_pid": int(exec_el.get("ProcessID")) if exec_el is not None
        and (exec_el.get("ProcessID") or "").isdigit() else None,
        "user_sid": security_el.get("UserID") if security_el is not None else None,
        "event_data": data,
        "unnamed_data": unnamed,
        "xml": xml,
    }


def split_events(document: str) -> list[str]:
    """Split a wevtutil export (``<Events>…</Events>`` or concatenated ``<Event>``s)
    into individual event XML strings."""
    return re.findall(r"<Event\b.*?</Event>", document, flags=re.DOTALL)


# --- normalization -------------------------------------------------------------

def _int(value: str | None) -> int | None:
    if value is None:
        return None
    v = value.strip()
    try:
        return int(v, 16) if v.lower().startswith("0x") else int(v)
    except ValueError:
        return None


def _s(value: str | None) -> str | None:
    if value is None:
        return None
    v = value.strip()
    return None if v in ("", "-") else v


def _account(domain: str | None, name: str | None) -> str | None:
    domain, name = _s(domain), _s(name)
    return f"{domain}\\{name}" if domain and name else name


def source_of(parsed: dict[str, Any]) -> str | None:
    channel = (parsed.get("channel") or "").casefold()
    if channel in CHANNEL_TO_SOURCE:
        return CHANNEL_TO_SOURCE[channel]
    provider = (parsed.get("provider") or "").casefold()
    if provider == "microsoft-windows-sysmon":
        return "sysmon"
    if provider == "microsoft-windows-security-auditing":
        return "security"
    if provider == "microsoft-windows-powershell":
        return "powershell"
    if provider == "microsoft-windows-windows defender":
        return "defender"
    return None


def event_ref_for(source: str, record_id: int | None) -> str:
    if record_id is None:
        raise EventParseError("event has no EventRecordID")
    return f"win:{source}:{record_id}"


def parse_event_ref(ref: str) -> tuple[str, int]:
    m = re.fullmatch(r"win:(sysmon|security|powershell|defender):(\d{1,20})", ref or "")
    if not m:
        raise ValueError("not a Windows event reference")
    return m.group(1), int(m.group(2))


def normalize_windows_event(parsed: dict[str, Any]) -> NormalizedEvent:
    """Map one parsed event to NormalizedEvent. Unsupported IDs become ``other``."""
    source = source_of(parsed)
    if source is None:
        raise EventParseError("event is not from a supported channel")
    eid = parsed["event_id"]
    ed: dict[str, str] = parsed["event_data"]
    category = SOURCE_CATEGORIES[source].get(eid, "other")
    ts = _windows_time(ed.get("UtcTime")) if source == "sysmon" else None
    ts = ts or _windows_time(parsed.get("system_time"))
    if ts is None:
        raise EventParseError("event has no usable timestamp")
    raw = {k: v for k, v in parsed.items()}
    f: dict[str, Any] = {
        "event_ref": event_ref_for(source, parsed.get("record_id")),
        "timestamp": ts, "host": _s(parsed.get("computer")) or "unknown",
        "source": {"sysmon": "sysmon", "security": "windows-security", "powershell": "powershell",
                   "defender": "defender"}[source],
        "event_id": eid, "category": category, "provider": parsed.get("provider"),
        "channel": parsed.get("channel"), "record_id": parsed.get("record_id"), "raw": raw,
    }
    if source == "sysmon":
        f.update(
            process_guid=_s(ed.get("ProcessGuid")), process_id=_int(ed.get("ProcessId")),
            image=_s(ed.get("Image")), command_line=_s(ed.get("CommandLine")), user=_s(ed.get("User")),
            parent_process_guid=_s(ed.get("ParentProcessGuid")), parent_process_id=_int(ed.get("ParentProcessId")),
            parent_image=_s(ed.get("ParentImage")), parent_command_line=_s(ed.get("ParentCommandLine")),
            hashes=_s(ed.get("Hashes")), integrity_level=_s(ed.get("IntegrityLevel")),
            logon_id=_s(ed.get("LogonId")),
        )
        if eid == 3:
            f.update(protocol=_s(ed.get("Protocol")), src_ip=_s(ed.get("SourceIp")),
                     src_port=_int(ed.get("SourcePort")), dest_ip=_s(ed.get("DestinationIp")),
                     dest_port=_int(ed.get("DestinationPort")), dest_hostname=_s(ed.get("DestinationHostname")))
        elif eid == 10:
            f.update(process_guid=_s(ed.get("SourceProcessGUID")), process_id=_int(ed.get("SourceProcessId")),
                     image=_s(ed.get("SourceImage")), target_image=_s(ed.get("TargetImage")),
                     granted_access=_s(ed.get("GrantedAccess")), user=_s(ed.get("SourceUser")))
        elif eid == 11:
            f.update(target_filename=_s(ed.get("TargetFilename")))
        elif eid in (12, 13, 14):
            f.update(target_object=_s(ed.get("TargetObject")), details=_s(ed.get("Details")))
        elif eid == 22:
            f.update(query_name=_s(ed.get("QueryName")), details=_s(ed.get("QueryResults")))
    elif source == "security":
        if eid in (4624, 4625):
            f.update(user=_account(ed.get("TargetDomainName"), ed.get("TargetUserName")),
                     logon_type=_int(ed.get("LogonType")), src_ip=_s(ed.get("IpAddress")),
                     src_port=_int(ed.get("IpPort")), auth_outcome="success" if eid == 4624 else "failure",
                     process_id=_int(ed.get("ProcessId")), image=_s(ed.get("ProcessName")),
                     logon_id=_s(ed.get("TargetLogonId")),
                     details=_s(ed.get("FailureReason")) or _s(ed.get("SubStatus")) or _s(ed.get("Status")))
        elif eid == 4688:
            # 4688 carries no process GUIDs: ancestry by PID alone is ambiguous
            # (PIDs are reused), so no GUID is invented here.
            f.update(image=_s(ed.get("NewProcessName")), command_line=_s(ed.get("CommandLine")),
                     process_id=_int(ed.get("NewProcessId")), parent_process_id=_int(ed.get("ProcessId")),
                     parent_image=_s(ed.get("ParentProcessName")),
                     user=_account(ed.get("TargetDomainName"), ed.get("TargetUserName"))
                     or _account(ed.get("SubjectDomainName"), ed.get("SubjectUserName")),
                     logon_id=_s(ed.get("SubjectLogonId")), integrity_level=_s(ed.get("MandatoryLabel")))
        elif eid == 4672:
            f.update(user=_account(ed.get("SubjectDomainName"), ed.get("SubjectUserName")),
                     logon_id=_s(ed.get("SubjectLogonId")),
                     details=" ".join((ed.get("PrivilegeList") or "").split()) or None)
        elif eid == 4698:
            f.update(user=_account(ed.get("SubjectDomainName"), ed.get("SubjectUserName")),
                     task_name=_s(ed.get("TaskName")), task_content=_s(ed.get("TaskContent")))
    elif source == "powershell":
        if eid == 4104:
            f.update(script_text=ed.get("ScriptBlockText") or None, script_block_id=_s(ed.get("ScriptBlockId")),
                     script_path=_s(ed.get("Path")), process_id=parsed.get("execution_pid"),
                     details=(f"part {ed.get('MessageNumber')} of {ed.get('MessageTotal')}"
                              if ed.get("MessageTotal") not in (None, "", "1") else None))
    elif source == "defender":
        if eid in (1116, 1117):
            f.update(threat_name=_s(ed.get("Threat Name")), threat_severity=_s(ed.get("Severity Name")),
                     action=_s(ed.get("Action Name")), target_filename=_s(ed.get("Path")),
                     image=_s(ed.get("Process Name")), user=_s(ed.get("Detection User")),
                     details=_s(ed.get("Category Name")))
    return NormalizedEvent(**f)


# --- structured queries --------------------------------------------------------

# EventData fields a query may filter on, per source, and the value shapes allowed.
_GUID = re.compile(r"^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$")
_ACCOUNT = re.compile(r"^[A-Za-z0-9 ._$@-]{1,104}(\\[A-Za-z0-9 ._$@-]{1,104})?$")
FILTERABLE: dict[str, dict[str, re.Pattern[str]]] = {
    "sysmon": {"ProcessGuid": _GUID, "ParentProcessGuid": _GUID, "SourceProcessGUID": _GUID, "User": _ACCOUNT,
               "ProcessId": re.compile(r"^\d{1,10}$")},
    "security": {"TargetUserName": _ACCOUNT, "SubjectUserName": _ACCOUNT},
    "powershell": {},
    "defender": {},
}


class ChannelQuery(BaseModel):
    """One bounded, application-built query against one allowlisted channel."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: Source
    event_ids: tuple[int, ...] = Field(min_length=1, max_length=16)
    start: datetime | None = None
    end: datetime | None = None
    data_equals: tuple[tuple[str, str], ...] = ()
    execution_pid: int | None = Field(default=None, ge=0, le=2**32)
    record_id: int | None = Field(default=None, ge=0)
    reverse: bool = False
    max_events: int = Field(default=51, ge=1, le=5000)

    @field_validator("event_ids")
    @classmethod
    def _ids(cls, v: tuple[int, ...]) -> tuple[int, ...]:
        if any(not (0 <= i <= 65535) for i in v):
            raise ValueError("event id out of range")
        return v

    @model_validator(mode="after")
    def _check(self) -> "ChannelQuery":
        for t in (self.start, self.end):
            if t is not None and t.tzinfo is None:
                raise ValueError("query times must be timezone-aware")
        allowed = FILTERABLE[self.source]
        for name, value in self.data_equals:
            pattern = allowed.get(name)
            if pattern is None:
                raise ValueError(f"field {name!r} is not filterable for {self.source}")
            if not pattern.fullmatch(value):
                raise ValueError(f"value for {name} has an unexpected format")
        return self

    @property
    def channel(self) -> str:
        return CHANNELS[self.source]


def _xpath_time(t: datetime) -> str:
    t = t.astimezone(timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def build_xpath(q: ChannelQuery) -> str:
    """Render a ChannelQuery as a Windows event XPath query.

    Every value is either an integer, an ISO timestamp produced here, or a string
    that passed ``FILTERABLE`` (no quotes, brackets or operators can occur).
    """
    system = ["(" + " or ".join(f"EventID={i}" for i in q.event_ids) + ")"]
    if q.start is not None or q.end is not None:
        parts = []
        if q.start is not None:
            parts.append(f"@SystemTime>='{_xpath_time(q.start)}'")
        if q.end is not None:
            parts.append(f"@SystemTime<='{_xpath_time(q.end)}'")
        system.append("TimeCreated[" + " and ".join(parts) + "]")
    if q.execution_pid is not None:
        system.append(f"Execution[@ProcessID={int(q.execution_pid)}]")
    if q.record_id is not None:
        system.append(f"EventRecordID={int(q.record_id)}")
    xpath = "*[System[" + " and ".join(system) + "]]"
    for name, value in q.data_equals:
        xpath += f" and *[EventData[Data[@Name='{name}']='{value}']]"
    return xpath


def matches(q: ChannelQuery, parsed: dict[str, Any]) -> bool:
    """Evaluate a ChannelQuery against a parsed event (same semantics as build_xpath).
    Used by the recorded-event reader so tests and replays share query semantics."""
    if parsed["event_id"] not in q.event_ids:
        return False
    t = _windows_time(parsed.get("system_time"))
    if q.start is not None and (t is None or t < q.start):
        return False
    if q.end is not None and (t is None or t > q.end):
        return False
    if q.execution_pid is not None and parsed.get("execution_pid") != q.execution_pid:
        return False
    if q.record_id is not None and parsed.get("record_id") != q.record_id:
        return False
    return all(parsed["event_data"].get(name) == value for name, value in q.data_equals)
