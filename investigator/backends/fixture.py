"""Deterministic fixture backend.

Loads every case directory under `cases/` into ONE in-memory telemetry store,
the same way a SIEM holds data for many hosts. Events are stored as
Wazuh-shaped documents and normalized with the same code WazuhBackend uses.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import Alert, HostContext, NormalizedEvent
from .base import EventQuery
from .normalize import event_matches_keyword, normalize_wazuh_doc


class FixtureBackend:
    name = "fixture"

    def __init__(self, cases_dir: Path) -> None:
        self.cases_dir = Path(cases_dir)
        self._alerts: dict[str, Alert] = {}
        self._events: dict[str, NormalizedEvent] = {}
        self._hosts: dict[str, HostContext] = {}
        self._expectations: dict[str, dict[str, Any]] = {}
        self._load()

    # -- loading ---------------------------------------------------------
    def _load(self) -> None:
        if not self.cases_dir.is_dir():
            raise FileNotFoundError(f"cases directory not found: {self.cases_dir}")
        for case_dir in sorted(p for p in self.cases_dir.iterdir() if p.is_dir()):
            events = json.loads((case_dir / "events.json").read_text(encoding="utf-8"))
            for doc in events:
                ev = normalize_wazuh_doc(doc)
                if ev.event_ref in self._events:
                    raise ValueError(f"duplicate fixture event id {ev.event_ref}")
                self._events[ev.event_ref] = ev
            hosts_file = case_dir / "hosts.json"
            if hosts_file.exists():
                for h in json.loads(hosts_file.read_text(encoding="utf-8")):
                    ctx = HostContext.model_validate(h)
                    self._hosts[ctx.host.lower()] = ctx
            meta = json.loads((case_dir / "alert.json").read_text(encoding="utf-8"))
            trigger = self._events[meta["event_ref"]]
            alert = Alert(
                alert_id=meta["alert_id"],
                title=meta["title"],
                timestamp=trigger.timestamp,
                host=trigger.host,
                severity=meta["severity"],
                status=meta.get("status", "new"),
                rule_id=trigger.rule_id,
                rule_level=trigger.rule_level,
                event_ref=trigger.event_ref,
                process_guid=trigger.process_guid,
                user=trigger.user,
                source="fixture",
            )
            self._alerts[alert.alert_id] = alert
            exp_file = case_dir / "expectations.json"
            if exp_file.exists():
                self._expectations[alert.alert_id] = json.loads(exp_file.read_text(encoding="utf-8"))

    # -- TelemetryBackend ------------------------------------------------
    def list_alerts(self) -> list[Alert]:
        return sorted(self._alerts.values(), key=lambda a: a.alert_id)

    def get_alert(self, alert_id: str) -> Alert | None:
        return self._alerts.get(alert_id)

    def get_event(self, event_ref: str) -> NormalizedEvent | None:
        return self._events.get(event_ref)

    def search_events(self, query: EventQuery) -> list[NormalizedEvent]:
        out: list[NormalizedEvent] = []
        for ev in sorted(self._events.values(), key=lambda e: (e.timestamp, e.event_ref)):
            if not (query.start <= ev.timestamp <= query.end):
                continue
            if query.host and ev.host.lower() != query.host.lower():
                continue
            if query.category and ev.category != query.category:
                continue
            if query.event_id is not None and ev.event_id != query.event_id:
                continue
            if query.process_guid and (ev.process_guid or "").lower() != query.process_guid.lower():
                continue
            if query.parent_process_guid and (ev.parent_process_guid or "").lower() != query.parent_process_guid.lower():
                continue
            if query.keyword and not event_matches_keyword(ev, query.keyword):
                continue
            out.append(ev)
            if len(out) >= query.limit:
                break
        return out

    def get_host_context(self, host: str) -> HostContext | None:
        return self._hosts.get(host.lower())

    # -- evaluation support (not exposed to the model) ------------------
    def expectations(self, alert_id: str) -> dict[str, Any] | None:
        return self._expectations.get(alert_id)
