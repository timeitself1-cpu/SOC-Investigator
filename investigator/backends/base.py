"""Backend protocol. The investigation engine depends ONLY on this interface.

Every method is a read. There is intentionally no method that writes, acts on
a host, or executes anything. Adding a new SIEM means implementing these five
methods and returning `NormalizedEvent`s.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..models import Alert, EventCategory, HostContext, NormalizedEvent


class EventQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    start: datetime
    end: datetime
    host: str | None = None
    category: EventCategory | None = None
    event_id: int | None = None
    process_guid: str | None = None
    parent_process_guid: str | None = None
    keyword: str | None = None
    limit: int = Field(default=25, ge=1, le=51)  # tools request limit+1 to detect truncation

    @model_validator(mode="after")
    def validate_window(self) -> "EventQuery":
        if self.start.tzinfo is None or self.end.tzinfo is None:
            raise ValueError("event query timestamps must include a timezone")
        if self.start > self.end:
            raise ValueError("event query start must not be after end")
        return self


@runtime_checkable
class TelemetryBackend(Protocol):
    name: str

    def list_alerts(self) -> list[Alert]: ...

    def get_alert(self, alert_id: str) -> Alert | None: ...

    def get_event(self, event_ref: str) -> NormalizedEvent | None: ...

    def search_events(self, query: EventQuery) -> list[NormalizedEvent]: ...

    def get_host_context(self, host: str) -> HostContext | None: ...


READ_ONLY_BACKEND_METHODS = frozenset({"list_alerts", "get_alert", "get_event", "search_events", "get_host_context"})


def severity_from_level(level: int | None) -> str:
    if level is None:
        return "medium"
    if level >= 13:
        return "critical"
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    if level >= 4:
        return "low"
    return "informational"
