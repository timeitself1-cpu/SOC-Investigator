"""Normalize Wazuh-indexed Windows eventchannel documents into NormalizedEvent.

Both FixtureBackend and WazuhBackend use this, which is what makes the two
backends interchangeable from the agent's point of view. Field names follow
Wazuh's decoding of Windows eventchannel logs (`data.win.system.*`,
`data.win.eventdata.*`).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from ..models import NormalizedEvent

SYSMON_PROVIDER = "microsoft-windows-sysmon"

SYSMON_CATEGORIES = {1: "process", 3: "network", 10: "process_access", 11: "file",
                     12: "registry", 13: "registry", 14: "registry", 22: "dns"}
SECURITY_CATEGORIES = {4624: "authentication", 4625: "authentication", 4688: "process", 4698: "scheduled_task"}


def parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip().replace("Z", "+00:00")
        text = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", text)  # +0000 -> +00:00
        dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _get(d: dict[str, Any], path: str) -> Any:
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _int(v: Any) -> int | None:
    try:
        return int(str(v), 0) if isinstance(v, str) and v.lower().startswith("0x") else int(v)
    except (TypeError, ValueError):
        return None


def _s(v: Any) -> str | None:
    if v is None or v == "":
        return None
    return str(v)


def normalize_wazuh_doc(doc: dict[str, Any], event_ref: str | None = None) -> NormalizedEvent:
    """Convert a Wazuh alert/archive `_source` document into a NormalizedEvent."""
    system = _get(doc, "data.win.system") or {}
    ed = _get(doc, "data.win.eventdata") or {}
    if not isinstance(system, dict) or not isinstance(ed, dict):
        raise ValueError("Windows event system and eventdata must be objects")
    ref = event_ref or _s(doc.get("id"))
    if not ref:
        raise ValueError("telemetry event has no source identity")
    provider = str(system.get("providerName", "")).lower()
    event_id = _int(system.get("eventID"))
    is_sysmon = provider == SYSMON_PROVIDER
    if is_sysmon:
        category = SYSMON_CATEGORIES.get(event_id or -1, "other")
        source = "sysmon"
    elif "security" in str(system.get("channel", "")).lower() or provider.startswith("microsoft-windows-security"):
        category = SECURITY_CATEGORIES.get(event_id or -1, "other")
        source = "windows-security"
    else:
        category, source = "other", str(_get(doc, "decoder.name") or "wazuh")

    host = _s(_get(doc, "agent.name")) or _s(system.get("computer")) or "unknown"
    ts = doc.get("timestamp") or doc.get("@timestamp") or system.get("systemTime")

    image = _s(ed.get("image")) or _s(ed.get("newProcessName"))
    process_guid = _s(ed.get("processGuid")) or _s(ed.get("processGUID"))
    process_id = _int(ed.get("processId"))
    user = _s(ed.get("user"))
    if category == "process_access":
        image = _s(ed.get("sourceImage"))
        process_guid = _s(ed.get("sourceProcessGUID")) or _s(ed.get("sourceProcessGuid"))
        process_id = _int(ed.get("sourceProcessId"))
        user = _s(ed.get("sourceUser")) or user

    auth_outcome = None
    src_ip = _s(ed.get("sourceIp"))
    if category == "authentication":
        auth_outcome = "success" if event_id == 4624 else "failure"
        domain = _s(ed.get("targetDomainName"))
        name = _s(ed.get("targetUserName"))
        user = f"{domain}\\{name}" if domain and name else name
        src_ip = _s(ed.get("ipAddress"))
    if category == "scheduled_task":
        sub = _s(ed.get("subjectUserName"))
        dom = _s(ed.get("subjectDomainName"))
        user = f"{dom}\\{sub}" if dom and sub else sub
    if source == "windows-security" and event_id == 4688:
        # 4688's processId belongs to the creator; newProcessId identifies the
        # process represented by newProcessName. Do not conflate their PIDs.
        process_id = _int(ed.get("newProcessId"))
        name = _s(ed.get("subjectUserName"))
        domain = _s(ed.get("subjectDomainName"))
        user = f"{domain}\\{name}" if domain and name else name

    rule = doc.get("rule") or {}
    return NormalizedEvent(
        event_ref=ref,
        timestamp=parse_timestamp(ts),
        host=host,
        source=source,
        event_id=event_id,
        category=category,  # type: ignore[arg-type]
        rule_id=_s(rule.get("id")),
        rule_level=_int(rule.get("level")),
        rule_description=_s(rule.get("description")),
        process_guid=process_guid,
        parent_process_guid=_s(ed.get("parentProcessGuid")) or _s(ed.get("parentProcessGUID")),
        process_id=process_id,
        image=image,
        command_line=_s(ed.get("commandLine")),
        parent_image=_s(ed.get("parentImage")),
        parent_command_line=_s(ed.get("parentCommandLine")),
        user=user,
        src_ip=src_ip,
        dest_ip=_s(ed.get("destinationIp")),
        dest_port=_int(ed.get("destinationPort")),
        dest_hostname=_s(ed.get("destinationHostname")),
        target_image=_s(ed.get("targetImage")),
        granted_access=_s(ed.get("grantedAccess")),
        target_object=_s(ed.get("targetObject")),
        details=_s(ed.get("details")),
        target_filename=_s(ed.get("targetFilename")),
        logon_type=_int(ed.get("logonType")),
        auth_outcome=auth_outcome,  # type: ignore[arg-type]
        task_name=_s(ed.get("taskName")),
        task_content=_s(ed.get("taskContent")),
        query_name=_s(ed.get("queryName")),
        raw=doc,
    )


def event_matches_keyword(ev: NormalizedEvent, keyword: str) -> bool:
    kw = keyword.lower()
    fields = (ev.image, ev.command_line, ev.parent_image, ev.user, ev.dest_ip, ev.dest_hostname,
              ev.target_image, ev.target_object, ev.details, ev.target_filename, ev.task_name,
              ev.query_name, ev.rule_description, ev.src_ip)
    return any(f and kw in f.lower() for f in fields)
