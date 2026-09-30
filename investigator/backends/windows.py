"""WindowsEventBackend: read-only investigation backend over local Windows event logs.

Implements the same ``TelemetryBackend`` interface as the fixture and Wazuh
backends, so the investigation engine is unchanged. All operating-system access
goes through an ``EventLogReader`` (live: pywin32; tests/replay: recorded XML)
and every query is an application-built ``ChannelQuery``.

Coverage honesty (the v0.2.1 principle, applied to Windows):

* Capability discovery probes each source (Sysmon, Security, PowerShell,
  Defender) at startup and every few minutes: active / limited / not installed /
  access denied.
* A query for a category whose sources are all unavailable raises a classified
  error (``permission`` or ``source_unavailable``); the tool call fails and the
  investigation is incomplete. It never returns "no events".
* A query answered only partly (fallback source, a source limited by its
  configuration, unparseable records, a scan cap) returns an ``EventList`` with
  ``degraded=True`` and plain-text gaps; tools report it as ``partial``, which
  does not satisfy benign-closure requirements.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from pydantic import BaseModel, ValidationError

from .. import signals
from ..config import Settings
from ..errors import ClassifiedError, classify_exception
from ..models import Alert, HostContext, NormalizedEvent, utcnow
from ..backends.normalize import event_matches_keyword
from .base import EventList, EventQuery
from .windows_events import (
    CHANNELS,
    SOURCE_CATEGORIES,
    SOURCE_LABELS,
    ChannelQuery,
    EventParseError,
    normalize_windows_event,
    parse_event_ref,
    parse_event_xml,
)
from .winevt_reader import EventLogReader

SourceState = Literal["active", "limited", "not_installed", "access_denied", "error"]

# Events a healthy source records routinely; their absence over the discovery
# window means the source is configured not to record them.
EXPECTED_EVENTS: dict[str, dict[int, str]] = {
    "sysmon": {1: "process creation", 3: "network connection", 22: "DNS query"},
    "security": {4624: "successful logon", 4688: "process creation (requires 'Audit Process Creation')"},
    "powershell": {4104: "script block (requires script block logging)"},
    "defender": {},
}

# category -> ordered (source, event ids) plan. The first usable entry answers;
# later entries are fallbacks used only when earlier ones are unusable.
CATEGORY_PLAN: dict[str, list[tuple[str, tuple[int, ...]]]] = {
    "process": [("sysmon", (1,)), ("security", (4688,))],
    "network": [("sysmon", (3,))],
    "dns": [("sysmon", (22,))],
    "process_termination": [("sysmon", (5,))],
    "process_access": [("sysmon", (10,))],
    "file": [("sysmon", (11,))],
    "registry": [("sysmon", (12, 13, 14))],
    "authentication": [("security", (4624, 4625))],
    "privilege": [("security", (4672,))],
    "scheduled_task": [("security", (4698,))],
    "script": [("powershell", (4104,))],
    "detection": [("defender", (1116, 1117))],
}
# A category whose answering source is "limited" for these ids is degraded
# (results cannot be treated as complete). Others only add a known unknown.
DEGRADE_WHEN_ABSENT = {("sysmon", 1), ("sysmon", 3), ("security", 4688)}


class SourceStatus(BaseModel):
    source: str
    label: str
    channel: str
    state: SourceState
    detail: str = ""
    missing_events: list[str] = []
    missing_ids: list[int] = []

    @property
    def usable(self) -> bool:
        return self.state in ("active", "limited")


class WindowsEventBackend:
    name = "windows"

    def __init__(self, settings: Settings, reader: EventLogReader) -> None:
        self.s = settings
        self.reader = reader
        self._lock = threading.RLock()
        self._status: dict[str, SourceStatus] = {}
        self._status_at = 0.0
        self._alerts: dict[str, Alert] = {}
        self._pid_cache: dict[tuple[int, int], tuple[str | None, datetime | None]] = {}
        self.skipped_alerts = 0
        self.signal_notes: list[str] = []
        self.refresh_sources()

    # -- clock / identity --------------------------------------------------
    def now(self) -> datetime:
        clock = getattr(self.reader, "now", None)
        return clock() if callable(clock) else utcnow()

    def local_names(self) -> set[str]:
        names = {n.casefold() for n in self.reader.computer_names()}
        return names | {n.split(".")[0] for n in names}

    def primary_host(self) -> str:
        names = sorted(self.reader.computer_names(), key=len)
        return names[0] if names else "localhost"

    def _is_local(self, host: str | None) -> bool:
        if not host:
            return True
        h = host.casefold()
        return h in self.local_names() or h.split(".")[0] in self.local_names()

    # -- capability discovery ------------------------------------------------
    def refresh_sources(self) -> list[SourceStatus]:
        now = self.now()
        since = now - timedelta(days=self.s.windows_discovery_days)
        statuses: dict[str, SourceStatus] = {}
        for source, channel in CHANNELS.items():
            label = SOURCE_LABELS[source]
            probe = self.reader.probe(source)
            if probe.state != "available":
                state: SourceState = {"not_found": "not_installed", "access_denied": "access_denied"}.get(
                    probe.state, "error")  # type: ignore[assignment]
                statuses[source] = SourceStatus(source=source, label=label, channel=channel, state=state,
                                                detail=probe.detail)
                continue
            missing: dict[int, str] = {}
            try:
                for eid, what in EXPECTED_EVENTS[source].items():
                    if not self.reader.query(ChannelQuery(source=source, event_ids=(eid,), start=since, end=now,
                                                          reverse=True, max_events=1)):
                        missing[eid] = what
            except ClassifiedError as exc:
                state = "access_denied" if exc.kind == "permission" else "error"
                statuses[source] = SourceStatus(source=source, label=label, channel=channel, state=state,
                                                detail=exc.safe_message)
                continue
            detail = ""
            if missing:
                detail = (f"no {', '.join(f'{what} (event {eid})' for eid, what in missing.items())} records in "
                          f"the last {self.s.windows_discovery_days} days")
            statuses[source] = SourceStatus(source=source, label=label, channel=channel,
                                            state="limited" if missing else "active", detail=detail,
                                            missing_events=list(missing.values()), missing_ids=list(missing))
        with self._lock:
            self._status, self._status_at = statuses, time.monotonic()
        return list(statuses.values())

    def source_status(self) -> list[SourceStatus]:
        with self._lock:
            stale = time.monotonic() - self._status_at > self.s.windows_discovery_refresh_seconds
        if stale:
            self.refresh_sources()
        with self._lock:
            return list(self._status.values())

    def _state(self, source: str) -> SourceStatus:
        with self._lock:
            return self._status[source]

    def coverage_caveats(self) -> list[str]:
        out = []
        for st in self.source_status():
            if st.state != "active":
                out.append(f"{st.label} telemetry: {st.state.replace('_', ' ')}"
                           + (f" — {st.detail}" if st.detail else "") + ".")
        out.append("Only this computer's event logs are available; other hosts cannot be queried.")
        return out

    # -- queries --------------------------------------------------------------
    def _run(self, q: ChannelQuery) -> tuple[list[NormalizedEvent], int]:
        """Execute one channel query; returns (events, unparseable count)."""
        events, bad = [], 0
        for xml in self.reader.query(q):
            try:
                events.append(normalize_windows_event(parse_event_xml(xml)))
            except (EventParseError, ValueError):
                bad += 1
        return events, bad

    def _filters_for(self, source: str, ids: tuple[int, ...], q: EventQuery
                     ) -> list[tuple[tuple[int, ...], tuple[tuple[str, str], ...], int | None]] | None:
        """Translate EventQuery filters into per-id-group data filters, or None when
        the source cannot answer them (e.g. process GUIDs on non-Sysmon sources)."""
        if source == "sysmon":
            groups = []
            for gid in ids:
                data: list[tuple[str, str]] = []
                if q.process_guid:
                    data.append(("SourceProcessGUID" if gid == 10 else "ProcessGuid", q.process_guid))
                if q.parent_process_guid:
                    if gid != 1:
                        continue
                    data.append(("ParentProcessGuid", q.parent_process_guid))
                if q.user and "\\" in q.user:
                    data.append(("User", q.user))
                groups.append(((gid,), tuple(data), None))
            return groups or None
        if q.parent_process_guid:
            return None
        if source == "security":
            if q.process_guid:
                return None
            groups = []
            for gid in ids:
                data = []
                if q.user:
                    field = "TargetUserName" if gid in (4624, 4625) else "SubjectUserName"
                    data.append((field, q.user.rsplit("\\", 1)[-1]))
                groups.append(((gid,), tuple(data), None))
            return groups
        if source == "powershell" and q.process_guid:
            return [(ids, (), -1)]  # PID resolved from the GUID at query time
        if q.process_guid:
            return None  # no process identity in this source: it cannot answer a process-scoped query
        return [(ids, (), None)]

    def _pid_for_guid(self, guid: str) -> tuple[int | None, datetime | None]:
        """Sysmon process creation for a GUID -> (pid, creation time), anywhere in the log."""
        if not self._state("sysmon").usable:
            return None, None
        events, _ = self._run(ChannelQuery(source="sysmon", event_ids=(1,), data_equals=(("ProcessGuid", guid),),
                                           max_events=1))
        return (events[0].process_id, events[0].timestamp) if events else (None, None)

    def _guid_for_pid(self, pid: int, at: datetime) -> str | None:
        """Most recent Sysmon process creation with this PID before ``at`` (PIDs are reused,
        so the latest earlier creation within the lookback is the only defensible match)."""
        key = (pid, int(at.timestamp()) // 60)
        with self._lock:
            if key in self._pid_cache:
                return self._pid_cache[key][0]
        guid = None
        if self._state("sysmon").usable:
            events, _ = self._run(ChannelQuery(
                source="sysmon", event_ids=(1,), data_equals=(("ProcessId", str(pid)),),
                start=at - timedelta(hours=self.s.max_lookback_hours), end=at, reverse=True, max_events=1))
            guid = events[0].process_guid if events else None
        with self._lock:
            self._pid_cache[key] = (guid, at)
        return guid

    def search_events(self, query: EventQuery) -> EventList:
        try:
            return self._search_events(query)
        except ValidationError:
            # A value (usually model-supplied: a GUID, an account) failed the
            # ChannelQuery allowlist. Nothing was sent to the event log.
            raise ClassifiedError("invalid_argument", "A query value had an unexpected format and was not "
                                                      "sent to the event log.") from None

    def _search_events(self, query: EventQuery) -> EventList:
        if not self._is_local(query.host):
            raise ClassifiedError("source_unavailable", "Only this computer's event logs can be queried; the "
                                                        "requested host is not this computer.")
        self.source_status()
        categories = [query.category] if query.category else [c for c in CATEGORY_PLAN]
        if query.category == "other":
            return EventList([], gaps=["Events outside the supported categories are not collected from the "
                                       "Windows event logs."])
        client_side = bool(query.keyword or (query.user and "\\" not in query.user))
        per_query = self.s.windows_scan_limit if client_side else query.limit
        collected: list[NormalizedEvent] = []
        gaps: list[str] = []
        degraded = False
        errors: list[ClassifiedError] = []
        answered_any = False
        for category in categories:
            plan = CATEGORY_PLAN[category]
            answered = False
            for position, (source, ids) in enumerate(plan):
                if query.event_id is not None:
                    ids = tuple(i for i in ids if i == query.event_id)
                    if not ids:
                        continue
                st = self._state(source)
                if not st.usable:
                    if st.state == "access_denied":
                        errors.append(ClassifiedError("permission", f"{st.label} event log: access denied."))
                    else:
                        errors.append(ClassifiedError("source_unavailable", f"{st.label} is {st.state.replace('_', ' ')}."))
                    gaps.append(f"{category.replace('_', ' ')} events from {st.label} were not available "
                                f"({st.state.replace('_', ' ')}).")
                    continue
                groups = self._filters_for(source, ids, query)
                if groups is None:
                    if query.category is not None:
                        # The caller asked for this category specifically and this
                        # source cannot answer it for a process: a real gap.
                        degraded = True
                        gaps.append(f"{st.label} records cannot be filtered by process identity; they were not "
                                    f"searched for {category.replace('_', ' ')}.")
                    continue
                for gids, data, pid_marker in groups:
                    start, end, pid = query.start, query.end, None
                    if pid_marker == -1:
                        pid, created = self._pid_for_guid(query.process_guid or "")
                        if pid is None:
                            degraded = True
                            gaps.append("PowerShell events could not be tied to the requested process (no Sysmon "
                                        "process-creation record for its GUID).")
                            continue
                        if created and created > end:
                            answered = answered_any = True
                            continue  # the process did not exist yet in this window: nothing to find
                        start = max(start, created) if created else start
                    try:
                        events, bad = self._run(ChannelQuery(
                            source=source, event_ids=gids, start=start, end=end, data_equals=data,
                            execution_pid=pid, reverse=query.order == "desc", max_events=per_query))
                    except ClassifiedError as exc:
                        errors.append(exc)
                        degraded = True
                        gaps.append(f"{st.label} query failed ({exc.kind}).")
                        continue
                    answered = answered_any = True
                    if bad:
                        degraded = True
                        gaps.append(f"{bad} {st.label} record(s) could not be parsed and were skipped.")
                    if client_side and len(events) >= per_query:
                        degraded = True
                        gaps.append(f"Keyword/user filtering scanned only {per_query} {st.label} records.")
                    collected.extend(events)
                    missing = [i for i in gids if i in st.missing_ids]
                    if missing:
                        gaps.append(f"{st.label} is running but recorded no {', '.join(str(i) for i in missing)} "
                                    f"events recently; its configuration may exclude them.")
                        if any((source, i) in DEGRADE_WHEN_ABSENT for i in missing):
                            degraded = True
                if answered:
                    if position > 0:
                        degraded = True
                        gaps.append(f"{category.replace('_', ' ')} events came from a fallback source "
                                    f"({st.label}); process GUIDs and ancestry are unavailable.")
                    break
        if not answered_any and errors:
            raise errors[0]
        if query.keyword:
            collected = [e for e in collected if event_matches_keyword(e, query.keyword)]
        if query.user and "\\" not in query.user:
            want = query.user.casefold()
            collected = [e for e in collected if (e.user or "").casefold().rsplit("\\", 1)[-1] == want]
        for i, ev in enumerate(collected):
            if ev.category == "script" and not ev.process_guid and ev.process_id is not None:
                guid = self._guid_for_pid(ev.process_id, ev.timestamp)
                if guid:
                    collected[i] = ev.model_copy(update={"process_guid": guid, "process_guid_inferred": True})
        collected.sort(key=lambda e: (e.timestamp, e.event_ref), reverse=query.order == "desc")
        return EventList(collected[: query.limit], gaps=list(dict.fromkeys(gaps)), degraded=degraded)

    def get_event(self, event_ref: str) -> NormalizedEvent | None:
        try:
            source, record = parse_event_ref(event_ref)
        except ValueError:
            return None
        ids = tuple(sorted(SOURCE_CATEGORIES[source]))
        events, _ = self._run(ChannelQuery(source=source, event_ids=ids, record_id=record, max_events=1))
        ev = events[0] if events else None
        if ev is not None and ev.category == "script" and not ev.process_guid and ev.process_id is not None:
            guid = self._guid_for_pid(ev.process_id, ev.timestamp)
            if guid:
                ev = ev.model_copy(update={"process_guid": guid, "process_guid_inferred": True})
        return ev

    # -- signals ----------------------------------------------------------------
    def list_alerts(self) -> list[Alert]:
        self.source_status()
        now = self.now()
        start = now - timedelta(hours=self.s.windows_signal_lookback_hours)
        cap = self.s.windows_scan_limit
        events: list[NormalizedEvent] = []
        notes: list[str] = []
        wanted = [("process", (1,), "sysmon"), ("process", (4688,), "security"),
                  ("authentication", (4625,), "security"), ("detection", (1116, 1117), "defender"),
                  ("process_access", (10,), "sysmon"), ("registry", (13,), "sysmon"),
                  ("scheduled_task", (4698,), "security")]
        for category, ids, source in wanted:
            st = self._state(source)
            if category == "process" and source == "security" and self._state("sysmon").state == "active":
                continue  # Sysmon already covers process creation
            if not st.usable:
                note = f"{st.label} is {st.state.replace('_', ' ')}: its signals are unavailable."
                if note not in notes:
                    notes.append(note)
                continue
            try:
                got, bad = self._run(ChannelQuery(source=source, event_ids=ids, start=start, end=now, reverse=True,
                                                  max_events=cap))
            except ClassifiedError as exc:
                notes.append(f"{st.label} could not be read ({exc.kind}); its signals are unavailable.")
                continue
            if len(got) >= cap:
                notes.append(f"Only the newest {cap} {st.label} events were scanned for signals.")
            if bad:
                notes.append(f"{bad} {st.label} record(s) could not be parsed.")
            events.extend(got)
        alerts = [signals.to_alert(s) for s in signals.detect(events)][:50]
        with self._lock:
            self._alerts = {a.alert_id: a for a in alerts}
            self.signal_notes = notes
        return alerts

    def get_alert(self, alert_id: str) -> Alert | None:
        with self._lock:
            hit = self._alerts.get(alert_id)
        if hit is None:
            self.list_alerts()
            with self._lock:
                hit = self._alerts.get(alert_id)
        return hit

    # -- host context -------------------------------------------------------------
    def get_host_context(self, host: str) -> HostContext | None:
        if not self._is_local(host):
            return None
        facts = self.reader.host_facts()
        sources = "; ".join(f"{st.label}: {st.state.replace('_', ' ')}" for st in self.source_status())
        return HostContext(host=host or self.primary_host(), os=facts.get("os"),
                           role=facts.get("role") or "Local Windows endpoint (standalone investigator)",
                           criticality=facts.get("criticality"),
                           agent_status=f"investigator elevated: {facts.get('elevated', 'unknown')}",
                           notes=f"Telemetry sources — {sources}.")

    # -- diagnostics ----------------------------------------------------------------
    def probe(self, host: str | None = None) -> list[dict[str, Any]]:
        out = []
        for st in self.refresh_sources():
            out.append({"check": f"{st.label} ({st.channel})", "ok": st.state == "active",
                        "kind": None if st.state == "active" else st.state,
                        "detail": st.detail or st.state.replace("_", " ")})
        return out


def build_windows_backend(settings: Settings) -> WindowsEventBackend:
    """Live reader on Windows; recorded reader for ``windows-replay``."""
    from .winevt_reader import PyWin32Reader, RecordedEventReader
    if settings.backend == "windows-replay":
        from ..config import PACKAGED_WINDOWS_SAMPLES
        directory = settings.windows_replay_dir or PACKAGED_WINDOWS_SAMPLES
        return WindowsEventBackend(settings, RecordedEventReader.from_directory(directory))
    try:
        return WindowsEventBackend(settings, PyWin32Reader())
    except ClassifiedError:
        raise
    except Exception as exc:  # pragma: no cover - platform specific
        raise classify_exception(exc) from None
