"""Tool allowlisting, argument validation, bounded results, process tree."""

from investigator.config import load_settings
from investigator.evidence import EvidenceStore
from investigator.tools import ToolContext, dispatch, ALLOWED_TOOLS, TOOLS


def _process(backend, ref, guid, parent=None, host=None, minutes=0):
    from datetime import timedelta

    base = backend.get_event("INC001-0002")
    return base.model_copy(update={"event_ref": ref, "process_guid": guid,
                                  "parent_process_guid": parent, "host": host or base.host,
                                  "timestamp": base.timestamp + timedelta(minutes=minutes)})


def _ctx(backend):
    settings = load_settings(llm="mock", backend="fixture")
    alert = backend.get_alert("INC-001")
    store = EvidenceStore("fixture", max_items=settings.max_evidence)
    return ToolContext(backend, store, alert, settings), store


def test_no_remediation_or_execution_tool_exists():
    # Name tokens, not substrings: "get_powershell_activity" reads PowerShell
    # *logs*; no tool name may contain an execution or modification verb.
    banned = {"execute", "exec", "run", "shell", "invoke", "remediate", "isolate", "delete", "write", "http",
              "ssh", "query", "kill", "quarantine", "block", "disable", "set", "modify", "stop", "start"}
    for name in TOOLS:
        assert name.startswith(("get_", "search_")), f"tool {name} is not a read verb"
        assert not (set(name.split("_")) & banned), f"suspicious tool {name}"
    # exactly the nine read-only tools (v0.3 added three category-scoped readers)
    assert ALLOWED_TOOLS == {"search_events", "get_process_tree", "get_process_details",
                             "get_network_activity", "get_related_events", "get_host_context",
                             "get_logon_activity", "get_powershell_activity", "get_defender_activity"}


def test_unknown_tool_is_rejected(backend):
    ctx, _ = _ctx(backend)
    call, result = dispatch(ctx, 1, "run_shell", {"cmd": "rm -rf /"})
    assert call.status == "rejected"
    assert result is None
    assert "allowlist" in call.error


def test_invalid_arguments_rejected(backend):
    ctx, _ = _ctx(backend)
    call, result = dispatch(ctx, 1, "search_events", {"event_id": "not-an-int", "bogus": 1})
    assert call.status == "rejected"
    assert result is None


def test_extra_argument_rejected(backend):
    ctx, _ = _ctx(backend)
    call, _ = dispatch(ctx, 1, "get_host_context", {"host": "FIN-WKS-014", "injected": "x"})
    assert call.status == "rejected"


def test_search_events_bounds_results(backend):
    ctx, store = _ctx(backend)
    # An oversized limit is clamped to the configured cap, never honored verbatim.
    call, result = dispatch(ctx, 1, "search_events", {"host": "FIN-WKS-014", "limit": 999})
    assert call.status == "ok"
    assert result.count <= ctx.settings.max_results_per_tool
    # A default search is also bounded.
    call, result = dispatch(ctx, 2, "search_events", {"host": "FIN-WKS-014"})
    assert call.status == "ok"
    assert result.count <= ctx.settings.max_results_per_tool


def test_negative_limit_rejected(backend):
    ctx, _ = _ctx(backend)
    call, _ = dispatch(ctx, 1, "search_events", {"host": "FIN-WKS-014", "limit": -5})
    assert call.status == "rejected"  # ge=1 violated


def test_process_tree_reconstruction(backend):
    ctx, store = _ctx(backend)
    # seed the powershell trigger event
    ev = backend.get_event("INC001-0002")
    item = store.add(ev, "seed")
    call, result = dispatch(ctx, 1, "get_process_tree", {"evidence_id": item.evidence_id})
    assert call.status == "ok"
    tree = result.extra["process_tree"]
    assert tree, "expected a process tree"
    # root should be WINWORD; a descendant should be powershell
    def images(node):
        yield node["image"]
        for c in node["children"]:
            yield from images(c)
    all_imgs = list(images(tree[0]))
    assert any("winword" in i for i in all_imgs)
    assert any("powershell" in i for i in all_imgs)


def test_tool_errors_are_recorded_not_raised(backend):
    ctx, _ = _ctx(backend)
    call, result = dispatch(ctx, 1, "get_related_events", {"evidence_id": "EV-9999"})
    # A model reference to unknown evidence is a rejected request (model error),
    # distinct from a backend collection failure (status "error").
    assert call.status == "rejected" and call.outcome == "rejected"
    assert call.error_kind == "invalid_argument"
    assert result is None
    assert "unknown evidence_id" in call.error


def test_tree_finds_target_and_parent_after_first_51_unrelated_processes(backend):
    ctx, _ = _ctx(backend)
    events = [_process(backend, f"noise-{i}", f"noise-{i}", minutes=-10) for i in range(60)]
    events += [_process(backend, "parent", "{PARENT}", minutes=-2),
               _process(backend, "target", "{TARGET}", "{parent}", minutes=-1),
               _process(backend, "child", "{CHILD}", "{target}")]
    backend._events = {ev.event_ref: ev for ev in events}
    call, result = dispatch(ctx, 1, "get_process_tree", {"process_guid": "{target}"})
    assert call.status == "ok"
    assert {ev.source_ref for ev in result.evidence} == {"parent", "target", "child"}
    tree = result.extra["process_tree"][0]
    assert tree["process_guid"] == "{PARENT}"
    assert tree["children"][0]["children"][0]["process_guid"] == "{CHILD}"


def test_tree_respects_result_cap_and_reports_truncation(backend):
    ctx, _ = _ctx(backend)
    ctx.settings.max_results_per_tool = 2
    events = [_process(backend, "target", "target")]
    events += [_process(backend, f"child-{i}", f"child-{i}", "target") for i in range(5)]
    backend._events = {ev.event_ref: ev for ev in events}
    call, result = dispatch(ctx, 1, "get_process_tree", {"process_guid": "target"})
    assert call.status == "ok"
    assert result.count == 2
    assert call.truncated
    assert len(result.extra["process_tree"][0]["children"]) == 1


def test_tree_uses_only_process_creation_events(backend):
    ctx, _ = _ctx(backend)
    network = _process(backend, "network", "target").model_copy(update={"category": "network"})
    backend._events = {network.event_ref: network}
    call, result = dispatch(ctx, 1, "get_process_tree", {"process_guid": "target"})
    assert call.status == "ok"
    assert result.extra["process_tree"] == []


def test_tree_detects_cycles_and_bounds_ancestry_queries(backend):
    ctx, _ = _ctx(backend)
    events = [_process(backend, "one", "one", "two"), _process(backend, "two", "two", "ONE")]
    backend._events = {ev.event_ref: ev for ev in events}
    call, result = dispatch(ctx, 1, "get_process_tree", {"process_guid": "one"})
    assert call.status == "ok"
    assert call.truncated
    assert result.count == 2


def test_process_evidence_pivot_uses_its_host(backend):
    ctx, store = _ctx(backend)
    foreign = _process(backend, "foreign", "foreign-guid", host="OTHER-HOST")
    backend._events = {foreign.event_ref: foreign}
    item = store.add(foreign, "seed")
    for step, tool in enumerate(("get_process_details", "get_process_tree"), 1):
        call, result = dispatch(ctx, step, tool, {"evidence_id": item.evidence_id})
        assert call.status == "ok"
        assert result.count == 1
        assert result.evidence[0].host == "OTHER-HOST"


def test_conflicting_process_and_evidence_ids_are_rejected(backend):
    ctx, store = _ctx(backend)
    item = store.add(backend.get_event("INC001-0002"), "seed")
    call, result = dispatch(ctx, 1, "get_process_details", {"evidence_id": item.evidence_id, "process_guid": "other"})
    assert call.status == "rejected" and call.error_kind == "invalid_argument"
    assert result is None
    assert "conflicts" in call.error


def test_evidence_pivots_cannot_extend_investigation_window(backend):
    from datetime import timedelta

    ctx, store = _ctx(backend)
    anchor = _process(backend, "anchor", "anchor").model_copy(update={
        "timestamp": ctx.alert.timestamp + timedelta(minutes=ctx.settings.max_window_minutes)})
    item = store.add(anchor, "seed")
    queries = []
    backend.search_events = lambda query: queries.append(query) or []
    for step, (tool, args) in enumerate((
        ("search_events", {"center_evidence_id": item.evidence_id, "window_minutes": 999}),
        ("get_related_events", {"evidence_id": item.evidence_id, "window_minutes": 999}),
    ), 1):
        call, result = dispatch(ctx, step, tool, args)
        assert call.status == "ok"
    assert all(query.end <= anchor.timestamp for query in queries)
    assert all(query.start >= ctx.alert.timestamp - timedelta(hours=ctx.settings.max_lookback_hours) for query in queries)


def test_default_search_is_scoped_to_alert_host(backend):
    ctx, _ = _ctx(backend)
    queries = []
    backend.search_events = lambda query: queries.append(query) or []
    call, _ = dispatch(ctx, 1, "search_events", {})
    assert call.status == "ok"
    assert queries[0].host == ctx.alert.host


def test_codebase_has_no_remediation_or_os_modification_calls():
    """Static guard (v0.3): the only OS access is reading event logs. No process,
    registry, service, firewall, Defender, file-deletion or log-modifying API is used."""
    import re
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent / "investigator"
    banned = re.compile(
        r"\bsubprocess\b|os\.system|os\.popen|\bPopen\b|os\.startfile|\bwinreg\b|win32service|win32process|"
        r"win32api\.TerminateProcess|TerminateProcess|EvtClearLog|EvtExportLog|ClearEventLog|EvtSubscribe|"
        r"EvtSetChannelConfigProperty|EvtSaveChannelConfig|Set-MpPreference|Remove-Item|netsh|shutil\.rmtree")
    hits = [f"{p.relative_to(root)}:{i}" for p in root.rglob("*.py")
            for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1) if banned.search(line)]
    assert hits == []
    reader = (root / "backends" / "winevt_reader.py").read_text(encoding="utf-8")
    used = set(re.findall(r"win32evtlog\.(Evt\w+)\(", reader))
    assert used == {"EvtQuery", "EvtNext", "EvtRender"}  # read-only event log API only
