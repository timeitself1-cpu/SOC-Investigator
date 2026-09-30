"""Bounded, read-only investigation tools exposed to the agent.

Security model, enforced in code (not by prompting):
  * Dispatch is an explicit allowlist. A tool name not in TOOLS is rejected.
  * Every argument is validated by a Pydantic schema (extra fields forbidden).
  * Result counts and time windows are clamped to configured bounds.
  * Each invocation is recorded as a ToolCall with an application-owned id.
  * Tools only ever READ. There is no write/execute/remediate tool, by design.

Evidence identity is assigned by the EvidenceStore, never by tool arguments or
by the model.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta
from typing import Any, Callable

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .backends.base import EventQuery, TelemetryBackend
from .config import Settings
from .evidence import EvidenceStore, basename, sanitize_text
from .models import (
    Alert,
    Evidence,
    EventCategory,
    NormalizedEvent,
    ProcessNode,
    ToolCall,
    utcnow,
)


class ToolContext:
    """Per-investigation state shared by the tools."""

    def __init__(self, backend: TelemetryBackend, store: EvidenceStore, alert: Alert, settings: Settings) -> None:
        self.backend = backend
        self.store = store
        self.alert = alert
        self.settings = settings
        self._counter = 0

    def next_call_id(self) -> str:
        self._counter += 1
        return f"tc-{self._counter:03d}"


# --- argument schemas -------------------------------------------------------


class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SearchEventsArgs(_Args):
    host: str | None = Field(default=None, max_length=128)
    category: EventCategory | None = None
    event_id: int | None = Field(default=None, ge=0, le=65535)
    process_guid: str | None = Field(default=None, max_length=128)
    keyword: str | None = Field(default=None, max_length=120)
    center_evidence_id: str | None = Field(default=None, max_length=16)
    window_minutes: int | None = Field(default=None, ge=1)
    limit: int | None = Field(default=None, ge=1)


class GetProcessTreeArgs(_Args):
    process_guid: str | None = Field(default=None, max_length=128)
    evidence_id: str | None = Field(default=None, max_length=16)


class GetProcessDetailsArgs(_Args):
    process_guid: str | None = Field(default=None, max_length=128)
    evidence_id: str | None = Field(default=None, max_length=16)


class GetNetworkActivityArgs(_Args):
    host: str | None = Field(default=None, max_length=128)
    process_guid: str | None = Field(default=None, max_length=128)
    window_minutes: int | None = Field(default=None, ge=1)
    limit: int | None = Field(default=None, ge=1)


class GetRelatedEventsArgs(_Args):
    evidence_id: str = Field(max_length=16)
    window_minutes: int | None = Field(default=None, ge=1)
    limit: int | None = Field(default=None, ge=1)


class GetHostContextArgs(_Args):
    host: str | None = Field(default=None, max_length=128)


# --- tool result ------------------------------------------------------------


class ToolResult:
    def __init__(self, summary: str, evidence: list[Evidence], *, extra: dict[str, Any] | None = None,
                 truncated: bool = False, count: int | None = None) -> None:
        self.summary = summary
        self.evidence = evidence
        self.extra = extra or {}
        self.truncated = truncated
        self.count = count if count is not None else len(evidence)


class ToolError(Exception):
    pass


# --- helpers ----------------------------------------------------------------


def _clamp(value: int | None, default: int, hi: int) -> int:
    if value is None:
        return min(default, hi)
    return max(1, min(value, hi))


def _anchor_time(ctx: ToolContext, evidence_id: str | None) -> datetime:
    if evidence_id:
        ev = ctx.store.get(evidence_id)
        if ev is None:
            raise ToolError(f"unknown evidence_id {evidence_id!r}")
        return ev.timestamp
    return ctx.alert.timestamp


def _resolve_process(ctx: ToolContext, process_guid: str | None, evidence_id: str | None) -> tuple[str, str]:
    if evidence_id:
        ev = ctx.store.get(evidence_id)
        if ev is None:
            raise ToolError(f"unknown evidence_id {evidence_id!r}")
        if not ev.process_guid:
            raise ToolError(f"{evidence_id} has no associated process")
        if process_guid and process_guid.casefold() != ev.process_guid.casefold():
            raise ToolError("process_guid conflicts with evidence_id")
        return ev.process_guid, ev.host
    if process_guid:
        return process_guid, ctx.alert.host
    raise ToolError("provide process_guid or evidence_id")


def _time_bounds(ctx: ToolContext, center: datetime | None = None,
                 minutes: int | None = None) -> tuple[datetime, datetime]:
    """Evidence pivots cannot walk outside the investigation's time envelope."""
    start = ctx.alert.timestamp - timedelta(hours=ctx.settings.max_lookback_hours)
    end = ctx.alert.timestamp + timedelta(minutes=ctx.settings.max_window_minutes)
    if center is not None and minutes is not None:
        start = max(start, center - timedelta(minutes=minutes))
        end = min(end, center + timedelta(minutes=minutes))
    if start > end:
        raise ToolError("evidence timestamp is outside the investigation time bounds")
    return start, end


def _ingest(ctx: ToolContext, events: list[NormalizedEvent], call_id: str) -> tuple[list[Evidence], bool]:
    out: list[Evidence] = []
    dropped = False
    for ev in events:
        item = ctx.store.add(ev, call_id)
        if item is None:
            dropped = True
            break
        out.append(item)
    return out, dropped


# --- tool implementations ---------------------------------------------------


def tool_search_events(ctx: ToolContext, call_id: str, a: SearchEventsArgs) -> ToolResult:
    s = ctx.settings
    limit = _clamp(a.limit, s.max_results_per_tool, s.max_results_per_tool)
    if a.center_evidence_id or a.window_minutes:
        center = _anchor_time(ctx, a.center_evidence_id)
        win = _clamp(a.window_minutes, s.max_window_minutes, s.max_window_minutes)
        start, end = _time_bounds(ctx, center, win)
    else:
        start, end = _time_bounds(ctx)
    anchor = ctx.store.get(a.center_evidence_id) if a.center_evidence_id else None
    host = a.host or (anchor.host if anchor else ctx.alert.host)
    q = EventQuery(start=start, end=end, host=host, category=a.category, event_id=a.event_id,
                   process_guid=a.process_guid, keyword=a.keyword, limit=min(limit + 1, 51))
    events = ctx.backend.search_events(q)
    truncated = len(events) > limit
    events = events[:limit]
    evidence, dropped = _ingest(ctx, events, call_id)
    truncated = truncated or dropped
    scope = a.keyword or a.category or "events"
    summary = f"Searched telemetry for {scope}; retrieved {len(evidence)} event(s)"
    if truncated:
        summary += " (results capped)"
    return ToolResult(summary, evidence, truncated=truncated, count=len(evidence))


def tool_get_process_tree(ctx: ToolContext, call_id: str, a: GetProcessTreeArgs) -> ToolResult:
    guid, host = _resolve_process(ctx, a.process_guid, a.evidence_id)
    s = ctx.settings
    start, end = _time_bounds(ctx)
    limit = s.max_results_per_tool
    # Query specific GUIDs: a busy host's first 51 processes are not its tree.
    # Bound both returned evidence and ancestry requests, including corrupt cycles.
    chain: list[NormalizedEvent] = []
    seen: set[str] = set()
    next_guid: str | None = guid
    truncated = False
    while next_guid and len(chain) < min(limit, 16):
        key = next_guid.casefold()
        if key in seen:
            truncated = True
            break
        seen.add(key)
        matches = ctx.backend.search_events(EventQuery(
            start=start, end=end, host=host, category="process", process_guid=next_guid, limit=1))
        if not matches:
            truncated = bool(chain)  # the parent could be outside available telemetry
            break
        cur = matches[0]
        chain.append(cur)
        next_guid = cur.parent_process_guid
    else:
        truncated = bool(next_guid)
    chain.reverse()
    remaining = limit - len(chain)
    child_hits = ctx.backend.search_events(EventQuery(
        start=start, end=end, host=host, category="process", parent_process_guid=guid,
        limit=min(remaining + 1, 51))) if chain else []
    children = []
    for child in child_hits:
        key = (child.process_guid or child.event_ref).casefold()
        if key in seen:
            continue
        seen.add(key)
        children.append(child)
    truncated = truncated or len(child_hits) > remaining
    children = children[:remaining]
    relevant = chain + children
    evidence, dropped = _ingest(ctx, relevant, call_id)

    ev_by_guid = {e.process_guid: e for e in evidence if e.process_guid}
    nodes: list[ProcessNode] = []
    for ev in chain:
        item = ev_by_guid.get(ev.process_guid or "")
        if item is None:
            continue  # never render a claimed observed node without its evidence
        node = ProcessNode(
            process_guid=sanitize_text(ev.process_guid or "?", 128),
            image=basename(item.attributes.get("image")) or "unknown",
            command_line=item.attributes.get("command_line"),
            user=item.attributes.get("user"), evidence_id=item.evidence_id,
        )
        if nodes:
            nodes[-1].children.append(node)
        nodes.append(node)
    if nodes and chain[-1].process_guid in ev_by_guid:
        target_node = nodes[-1]
        for child in children:
            citem = ev_by_guid.get(child.process_guid or "")
            if citem is None:
                continue
            target_node.children.append(ProcessNode(
                process_guid=sanitize_text(child.process_guid or "?", 128),
                image=basename(citem.attributes.get("image")) or "unknown",
                command_line=citem.attributes.get("command_line"),
                user=citem.attributes.get("user"), evidence_id=citem.evidence_id,
            ))
    root = [nodes[0]] if nodes else []
    depth = len(chain)
    summary = f"Reconstructed process ancestry ({depth} level(s), {len(children)} child process(es))"
    if truncated or dropped:
        summary += " (partial tree: query, ancestry, or evidence bounds reached)"
    return ToolResult(summary, evidence, extra={"process_tree": [n.model_dump(mode="json") for n in root]},
                      truncated=truncated or dropped, count=len(evidence))


def tool_get_process_details(ctx: ToolContext, call_id: str, a: GetProcessDetailsArgs) -> ToolResult:
    guid, host = _resolve_process(ctx, a.process_guid, a.evidence_id)
    s = ctx.settings
    start, end = _time_bounds(ctx)
    q = EventQuery(start=start, end=end, host=host, process_guid=guid,
                   limit=min(s.max_results_per_tool + 1, 51))
    events = ctx.backend.search_events(q)
    truncated = len(events) > s.max_results_per_tool
    events = events[: s.max_results_per_tool]
    evidence, dropped = _ingest(ctx, events, call_id)
    cats = sorted({e.category for e in evidence})
    summary = f"Collected {len(evidence)} event(s) for process {guid[:16]}… covering {', '.join(cats) or 'no'} activity"
    return ToolResult(summary, evidence, truncated=truncated or dropped, count=len(evidence))


def tool_get_network_activity(ctx: ToolContext, call_id: str, a: GetNetworkActivityArgs) -> ToolResult:
    s = ctx.settings
    win = _clamp(a.window_minutes, s.max_window_minutes, s.max_window_minutes)
    limit = _clamp(a.limit, s.max_results_per_tool, s.max_results_per_tool)
    center = ctx.alert.timestamp
    start, end = _time_bounds(ctx, center, win)
    results: list[NormalizedEvent] = []
    for cat in ("network", "dns"):
        q = EventQuery(start=start, end=end,
                       host=a.host or ctx.alert.host, category=cat,  # type: ignore[arg-type]
                       process_guid=a.process_guid, limit=min(limit + 1, 51))
        results.extend(ctx.backend.search_events(q))
    results.sort(key=lambda e: e.timestamp)
    truncated = len(results) > limit
    results = results[:limit]
    evidence, dropped = _ingest(ctx, results, call_id)
    ext = sum(1 for e in evidence if "external_destination" in e.indicators)
    summary = f"Checked network activity: {len(evidence)} connection(s)/quer(ies), {ext} to external address(es)"
    return ToolResult(summary, evidence, truncated=truncated or dropped, count=len(evidence))


def tool_get_related_events(ctx: ToolContext, call_id: str, a: GetRelatedEventsArgs) -> ToolResult:
    ev = ctx.store.get(a.evidence_id)
    if ev is None:
        raise ToolError(f"unknown evidence_id {a.evidence_id!r}")
    s = ctx.settings
    win = _clamp(a.window_minutes, min(15, s.max_window_minutes), s.max_window_minutes)
    limit = _clamp(a.limit, s.max_results_per_tool, s.max_results_per_tool)
    start, end = _time_bounds(ctx, ev.timestamp, win)
    q = EventQuery(start=start, end=end,
                   host=ev.host, limit=min(limit + 1, 51))
    events = ctx.backend.search_events(q)
    truncated = len(events) > limit
    events = events[:limit]
    evidence, dropped = _ingest(ctx, events, call_id)
    summary = f"Correlated events within ±{win} minutes of {a.evidence_id}: {len(evidence)} event(s)"
    return ToolResult(summary, evidence, truncated=truncated or dropped, count=len(evidence))


def tool_get_host_context(ctx: ToolContext, call_id: str, a: GetHostContextArgs) -> ToolResult:
    host = a.host or ctx.alert.host
    hc = ctx.backend.get_host_context(host)
    if hc is None:
        return ToolResult(f"No host context found for {host}", [], extra={"host_context": None})
    return ToolResult(f"Retrieved host context for {host} ({hc.role or 'role unknown'})", [],
                      extra={"host_context": hc.model_dump(mode="json")})


# --- allowlist / dispatch ---------------------------------------------------

ToolFn = Callable[[ToolContext, str, Any], ToolResult]


class ToolSpec(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    name: str
    description: str
    args_model: type[_Args]
    fn: ToolFn


TOOLS: dict[str, ToolSpec] = {
    "search_events": ToolSpec(
        name="search_events", args_model=SearchEventsArgs, fn=tool_search_events,
        description="Search normalized telemetry by host/category/event_id/process_guid/keyword, "
                    "optionally centered on an evidence_id within a time window. "
                    "Defaults to the evidence host or alert host; provide host to pivot to another host."),
    "get_process_tree": ToolSpec(
        name="get_process_tree", args_model=GetProcessTreeArgs, fn=tool_get_process_tree,
        description="Reconstruct process ancestry and direct children for a process_guid or evidence_id."),
    "get_process_details": ToolSpec(
        name="get_process_details", args_model=GetProcessDetailsArgs, fn=tool_get_process_details,
        description="Return all events tied to one process (creation, network, file, registry, access)."),
    "get_network_activity": ToolSpec(
        name="get_network_activity", args_model=GetNetworkActivityArgs, fn=tool_get_network_activity,
        description="List network connections and DNS queries for a host/process within a window."),
    "get_related_events": ToolSpec(
        name="get_related_events", args_model=GetRelatedEventsArgs, fn=tool_get_related_events,
        description="Correlate events near a given evidence_id in time on the same host."),
    "get_host_context": ToolSpec(
        name="get_host_context", args_model=GetHostContextArgs, fn=tool_get_host_context,
        description="Retrieve asset/role/criticality context for a host. Returns no evidence."),
}

ALLOWED_TOOLS = frozenset(TOOLS)


def tool_catalog() -> list[dict[str, Any]]:
    out = []
    for spec in TOOLS.values():
        schema = spec.args_model.model_json_schema()
        props = schema.get("properties", {})
        out.append({"name": spec.name, "description": spec.description,
                    "arguments": {k: v.get("type", "any") for k, v in props.items()}})
    return out


def dispatch(ctx: ToolContext, step: int, tool_name: str, arguments: dict[str, Any],
             initiator: str = "model") -> tuple[ToolCall, ToolResult | None]:
    """Validate + run one tool. Always returns a ToolCall for the audit trail."""
    call_id = ctx.next_call_id()
    started = utcnow()
    t0 = time.perf_counter()

    def record(status: str, summary: str, *, result: ToolResult | None = None, error: str | None = None) -> ToolCall:
        return ToolCall(
            call_id=call_id, step=step, initiator=initiator, tool=tool_name,  # type: ignore[arg-type]
            arguments=arguments if isinstance(arguments, dict) else {}, status=status,  # type: ignore[arg-type]
            summary=summary, evidence_ids=[e.evidence_id for e in result.evidence] if result else [],
            result_count=result.count if result else 0, truncated=result.truncated if result else False,
            error=error, started_at=started, duration_ms=(time.perf_counter() - t0) * 1000,
        )

    if tool_name not in ALLOWED_TOOLS:
        return record("rejected", f"Rejected unknown tool {tool_name!r}",
                      error=f"tool {tool_name!r} is not in the allowlist"), None
    spec = TOOLS[tool_name]
    if not isinstance(arguments, dict):
        return record("rejected", "Rejected: arguments must be an object", error="arguments must be a JSON object"), None
    try:
        args = spec.args_model.model_validate(arguments)
    except ValidationError as exc:
        return record("rejected", f"Rejected invalid arguments for {tool_name}",
                      error="; ".join(f"{'/'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()[:5])), None
    try:
        result = spec.fn(ctx, call_id, args)
    except ToolError as exc:
        return record("error", f"{tool_name} could not complete", error=str(exc)), None
    except Exception as exc:  # defensive: never let a tool crash the loop
        return record("error", f"{tool_name} raised an error", error=f"{type(exc).__name__}: {exc}"), None
    return record("ok", result.summary, result=result), result
