"""Readers for the Windows Event Log.

``EventLogReader`` is the boundary between the investigator and the operating
system. It accepts only ``ChannelQuery`` objects (built by application code) and
returns rendered event XML. Two implementations:

* ``PyWin32Reader`` — the live reader. Uses the documented Windows Event Log API
  (``EvtQuery`` / ``EvtNext`` / ``EvtRender``) through pywin32. Read-only: it
  never clears, exports, subscribes to or reconfigures a channel.
  STATUS: implemented; NOT exercised in this project's CI (no Windows host).
* ``RecordedEventReader`` — events exported with ``wevtutil qe <channel> /f:xml
  /e:Events`` (or authored samples), evaluated with the same query semantics.
  Used by the unit tests and by ``SOCI_BACKEND=windows-replay``.

Failures are classified. Access denied and missing channels are reported as
such and never as "no events".
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal, Protocol

from ..errors import ClassifiedError
from .windows_events import (
    CHANNELS,
    ChannelQuery,
    EventParseError,
    _windows_time,
    build_xpath,
    matches,
    parse_event_xml,
    source_of,
    split_events,
)

ProbeState = Literal["available", "not_found", "access_denied", "error"]

ERROR_ACCESS_DENIED = 5
ERROR_NO_MORE_ITEMS = 259
ERROR_EVT_INVALID_QUERY = 15001
ERROR_EVT_CHANNEL_NOT_FOUND = 15007


@dataclass
class ChannelProbe:
    source: str
    state: ProbeState
    detail: str = ""


class EventLogReader(Protocol):
    name: str

    def query(self, q: ChannelQuery) -> list[str]:
        """Rendered XML of at most ``q.max_events`` matching events, oldest first
        (newest first when ``q.reverse``). Raises ClassifiedError."""
        ...

    def probe(self, source: str) -> ChannelProbe: ...

    def computer_names(self) -> set[str]: ...

    def host_facts(self) -> dict[str, str]: ...


def _classify_winerror(code: int | None, source: str) -> ClassifiedError:
    label = CHANNELS.get(source, source)
    if code == ERROR_ACCESS_DENIED:
        return ClassifiedError("permission", f"Access to the {label} event log was denied "
                                             "(run elevated or join the local 'Event Log Readers' group).")
    if code == ERROR_EVT_CHANNEL_NOT_FOUND:
        return ClassifiedError("source_unavailable", f"The {label} event log does not exist on this computer.")
    if code == ERROR_EVT_INVALID_QUERY:
        return ClassifiedError("internal", "The event log rejected an application-built query.")
    return ClassifiedError("unavailable", f"The {label} event log could not be read.")


class PyWin32Reader:
    """Live Windows Event Log reader (pywin32). Windows only."""

    name = "windows-eventlog"
    BATCH = 64

    def __init__(self) -> None:
        try:
            import pywintypes  # noqa: F401
            import win32evtlog  # noqa: F401
        except ImportError as exc:  # pragma: no cover - exercised on Windows only
            raise ClassifiedError("source_unavailable", "The Windows event log backend needs pywin32 "
                                  "(pip install pywin32) and must run on Windows.") from exc

    def query(self, q: ChannelQuery) -> list[str]:  # pragma: no cover - Windows only
        import pywintypes
        import win32evtlog

        flags = win32evtlog.EvtQueryChannelPath | (
            win32evtlog.EvtQueryReverseDirection if q.reverse else win32evtlog.EvtQueryForwardDirection)
        out: list[str] = []
        try:
            handle = win32evtlog.EvtQuery(q.channel, flags, build_xpath(q))
            while len(out) < q.max_events:
                try:
                    batch = win32evtlog.EvtNext(handle, min(self.BATCH, q.max_events - len(out)), -1, 0)
                except pywintypes.error as exc:
                    if exc.winerror == ERROR_NO_MORE_ITEMS:
                        break
                    raise
                if not batch:
                    break
                for event in batch:
                    out.append(win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml))
        except pywintypes.error as exc:
            raise _classify_winerror(exc.winerror, q.source) from None
        return out

    def probe(self, source: str) -> ChannelProbe:  # pragma: no cover - Windows only
        import pywintypes
        import win32evtlog

        try:
            handle = win32evtlog.EvtQuery(CHANNELS[source], win32evtlog.EvtQueryChannelPath
                                          | win32evtlog.EvtQueryReverseDirection, "*")
            try:
                win32evtlog.EvtNext(handle, 1, -1, 0)
            except pywintypes.error as exc:
                if exc.winerror != ERROR_NO_MORE_ITEMS:
                    raise
            return ChannelProbe(source, "available")
        except pywintypes.error as exc:
            err = _classify_winerror(exc.winerror, source)
            state: ProbeState = {"permission": "access_denied", "source_unavailable": "not_found"}.get(
                err.kind, "error")  # type: ignore[assignment]
            return ChannelProbe(source, state, err.safe_message)

    def computer_names(self) -> set[str]:
        import platform
        import socket
        names = {platform.node(), socket.getfqdn(), os.environ.get("COMPUTERNAME", "")}
        return {n for n in names if n}

    def host_facts(self) -> dict[str, str]:  # pragma: no cover - Windows only
        import ctypes
        import platform
        try:
            admin = bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001 - informational only
            admin = False
        return {"os": f"{platform.system()} {platform.release()} ({platform.version()})",
                "elevated": "yes" if admin else "no"}


@dataclass
class RecordedEventReader:
    """Events recorded as XML, queried with the live reader's semantics.

    ``events`` maps source key -> list of event XML strings. ``missing`` and
    ``denied`` simulate channels that do not exist or cannot be opened (a real
    denial is also what an unprivileged user sees on the live reader).
    """

    events: dict[str, list[str]] = field(default_factory=dict)
    missing: set[str] = field(default_factory=set)
    denied: set[str] = field(default_factory=set)
    facts: dict[str, str] = field(default_factory=dict)
    name: str = "recorded-eventlog"
    queries: list[ChannelQuery] = field(default_factory=list)
    _parsed: dict[str, list[tuple[dict, str]]] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        for source, xmls in self.events.items():
            rows = []
            for xml in xmls:
                try:
                    rows.append((parse_event_xml(xml), xml))
                except EventParseError:
                    rows.append(({"event_id": -1, "event_data": {}, "system_time": None}, xml))
            self._parsed[source] = rows

    @classmethod
    def from_directory(cls, directory: str | Path, **kw) -> "RecordedEventReader":
        """Load ``*.xml`` exports; each event is routed to its source by channel/provider."""
        events: dict[str, list[str]] = {}
        facts: dict[str, str] = {}
        root = Path(directory)
        if not root.is_dir():
            raise ClassifiedError("source_unavailable", "The recorded-event directory does not exist.")
        for path in sorted(root.glob("*.xml")):
            data = path.read_bytes()
            # Windows PowerShell 5.1 redirection (">") writes UTF-16 with a BOM.
            text = data.decode("utf-16") if data[:2] in (b"\xff\xfe", b"\xfe\xff") else data.decode("utf-8-sig")
            for xml in split_events(text):
                try:
                    src = source_of(parse_event_xml(xml))
                except EventParseError:
                    src = None
                if src:
                    events.setdefault(src, []).append(xml)
        meta = root / "host.json"
        if meta.is_file():
            import json
            facts = {k: str(v) for k, v in json.loads(meta.read_text(encoding="utf-8")).items()}
        missing = set(filter(None, facts.pop("missing_sources", "").split(",")))
        denied = set(filter(None, facts.pop("denied_sources", "").split(",")))
        return cls(events=events, missing=missing | kw.pop("missing", set()),
                   denied=denied | kw.pop("denied", set()), facts=facts, **kw)

    def _check(self, source: str) -> None:
        if source in self.denied:
            raise _classify_winerror(ERROR_ACCESS_DENIED, source)
        if source in self.missing:
            raise _classify_winerror(ERROR_EVT_CHANNEL_NOT_FOUND, source)

    def query(self, q: ChannelQuery) -> list[str]:
        self.queries.append(q)
        self._check(q.source)
        rows = [(p, x) for p, x in self._parsed.get(q.source, []) if p["event_id"] >= 0 and matches(q, p)]
        epoch = datetime.min.replace(tzinfo=timezone.utc)
        rows.sort(key=lambda r: (_windows_time(r[0].get("system_time")) or epoch, r[0].get("record_id") or 0),
                  reverse=q.reverse)
        return [x for _, x in rows[: q.max_events]]

    def probe(self, source: str) -> ChannelProbe:
        try:
            self._check(source)
        except ClassifiedError as exc:
            state: ProbeState = "access_denied" if exc.kind == "permission" else "not_found"
            return ChannelProbe(source, state, exc.safe_message)
        return ChannelProbe(source, "available")

    def computer_names(self) -> set[str]:
        names = {p.get("computer") for rows in self._parsed.values() for p, _ in rows if p.get("computer")}
        return {n for n in names if n}

    def host_facts(self) -> dict[str, str]:
        return dict(self.facts)

    def latest_time(self) -> datetime | None:
        times = [_windows_time(p.get("system_time")) for rows in self._parsed.values() for p, _ in rows]
        times = [t for t in times if t]
        return max(times) if times else None

    def now(self) -> datetime:
        """Replays anchor 'now' at the newest recorded event, not the wall clock."""
        latest = self.latest_time()
        return (latest + timedelta(minutes=1)) if latest else datetime.now(timezone.utc)
