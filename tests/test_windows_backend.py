"""WindowsEventBackend: parsing, normalization, structured queries, capability
discovery, coverage honesty, signals, and end-to-end investigations.

Deterministic and platform-independent: events are Windows event XML (the
packaged synthetic samples or hand-built records) served by
RecordedEventReader, which applies the same query semantics the live reader
sends to the Event Log API. The live pywin32 reader is NOT exercised here.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from investigator.agent import InvestigationAgent, build_agent
from investigator.backends.base import EventQuery
from investigator.backends.windows import WindowsEventBackend
from investigator.backends.windows_events import (
    ChannelQuery,
    EventParseError,
    build_xpath,
    matches,
    normalize_windows_event,
    parse_event_ref,
    parse_event_xml,
    split_events,
)
from investigator.backends.winevt_reader import RecordedEventReader
from investigator.config import PACKAGED_WINDOWS_SAMPLES, load_settings
from investigator.errors import ClassifiedError
from investigator.llm.mock import BenignProposerModel, MockInvestigatorModel
from investigator.signals import detect
from investigator.tools import ToolContext, dispatch
from investigator.evidence import EvidenceStore

DEMO = PACKAGED_WINDOWS_SAMPLES
NO_SYSMON = PACKAGED_WINDOWS_SAMPLES.parent / "demo-no-sysmon"
T = datetime(2026, 9, 29, 10, 41, tzinfo=timezone.utc)


def settings(**kw):
    return load_settings(llm="mock", backend="windows-replay", **kw)


def backend(directory=DEMO, **kw) -> WindowsEventBackend:
    return WindowsEventBackend(settings(), RecordedEventReader.from_directory(directory, **kw))


def xml_of(source: str, directory=DEMO) -> list[str]:
    return split_events((Path(directory) / f"{source}.xml").read_text(encoding="utf-8"))


def first(source, event_id, directory=DEMO, pred=lambda p: True):
    for x in xml_of(source, directory):
        p = parse_event_xml(x)
        if p["event_id"] == event_id and pred(p):
            return p
    raise AssertionError(f"no {source} {event_id}")


def by_title(b, fragment):
    return next(a for a in b.list_alerts() if fragment in a.title)


# --- parsing & normalization ------------------------------------------------------

def test_sysmon_process_creation_is_normalized_with_guids_hashes_and_parent_pid():
    p = first("sysmon", 1, pred=lambda p: "EncodedCommand" in p["event_data"].get("CommandLine", "")
              and "Hidden" in p["event_data"]["CommandLine"])
    ev = normalize_windows_event(p)
    assert ev.category == "process" and ev.source == "sysmon" and ev.event_ref == f"win:sysmon:{p['record_id']}"
    assert ev.process_guid.startswith("{") and ev.parent_process_guid.startswith("{")
    assert ev.process_id == 8840 and ev.parent_process_id == 5012
    assert ev.image.endswith("powershell.exe") and ev.parent_image.endswith("explorer.exe")
    assert ev.hashes.startswith("SHA256=") and ev.user == r"DESKTOP-RW01\rwtest"
    assert ev.timestamp == T  # UtcTime (event time), not the logging time
    assert ev.raw["xml"].startswith("<Event") and ev.channel == "Microsoft-Windows-Sysmon/Operational"


def test_sysmon_network_dns_and_termination():
    net = normalize_windows_event(first("sysmon", 3, pred=lambda p: p["event_data"]["DestinationIp"] == "93.184.215.14"))
    assert (net.category, net.dest_ip, net.dest_port, net.protocol, net.dest_hostname) == \
        ("network", "93.184.215.14", 443, "tcp", "example.com")
    assert net.src_ip == "192.168.1.50" and net.src_port == 53011
    dns = normalize_windows_event(first("sysmon", 22, pred=lambda p: p["event_data"]["QueryName"] == "example.com"))
    assert dns.category == "dns" and dns.query_name == "example.com"
    end = normalize_windows_event(first("sysmon", 5))
    assert end.category == "process_termination" and end.process_guid


def test_security_events_4624_4625_4688_4672():
    fail = normalize_windows_event(first("security", 4625))
    assert (fail.category, fail.auth_outcome, fail.logon_type, fail.user) == \
        ("authentication", "failure", 2, r"DESKTOP-RW01\rw_nonexistent")
    ok = normalize_windows_event(first("security", 4624))
    assert ok.auth_outcome == "success" and ok.src_ip is None  # "-" means none
    proc = normalize_windows_event(first("security", 4688))
    assert proc.category == "process" and proc.process_guid is None  # 4688 has no GUIDs; none invented
    assert isinstance(proc.process_id, int) and isinstance(proc.parent_process_id, int)  # hex parsed
    priv = normalize_windows_event(first("security", 4672))
    assert priv.category == "privilege" and "SeTcbPrivilege" in priv.details


def test_powershell_script_block_and_defender_detection():
    sb = normalize_windows_event(first("powershell", 4104, pred=lambda p: "RW-01" in p["event_data"]["ScriptBlockText"]))
    assert sb.category == "script" and "Invoke-WebRequest" in sb.script_text and sb.process_id == 8840
    det = normalize_windows_event(first("defender", 1116))
    assert det.category == "detection" and det.threat_name == "Virus:DOS/EICAR_Test_File"
    assert det.threat_severity == "Severe" and "eicar" in det.target_filename.lower()


def test_seven_digit_system_time_and_malformed_events():
    p = first("security", 4624)
    assert p["system_time"].endswith("0Z") and len(p["system_time"].split(".")[1]) == 8  # 7 digits + Z
    assert normalize_windows_event(p).timestamp.tzinfo is not None
    with pytest.raises(EventParseError):
        parse_event_xml("<!DOCTYPE x [<!ENTITY a 'b'>]><Event/>")
    with pytest.raises(EventParseError):
        parse_event_xml("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>")
    with pytest.raises(EventParseError):
        parse_event_xml("<NotAnEvent/>")
    with pytest.raises(EventParseError):
        parse_event_xml("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>" + "x" * 300_000)


def test_event_refs_roundtrip_and_reject_garbage():
    assert parse_event_ref("win:sysmon:481328") == ("sysmon", 481328)
    for bad in ("win:system:1", "win:sysmon:abc", "wz1~x~y", "win:sysmon:1 or 1=1"):
        with pytest.raises(ValueError):
            parse_event_ref(bad)
    b = backend()
    a = by_title(b, "encoded command, hidden window")
    ev = b.get_event(a.event_ref)
    assert ev.event_ref == a.event_ref and ev.category == "process"
    assert b.get_event("win:sysmon:1") is None and b.get_event("not-a-ref") is None


# --- structured queries (the only way to reach the event log) ----------------------

def test_xpath_is_built_only_from_validated_values():
    q = ChannelQuery(source="sysmon", event_ids=(1, 3), start=T - timedelta(minutes=5), end=T,
                     data_equals=(("ProcessGuid", "{7c3a9e51-0b15-66f9-2a15-000000010015}"),))
    x = build_xpath(q)
    assert x == ("*[System[(EventID=1 or EventID=3) and TimeCreated[@SystemTime>='2026-09-29T10:36:00.000Z' "
                 "and @SystemTime<='2026-09-29T10:41:00.000Z']]] and "
                 "*[EventData[Data[@Name='ProcessGuid']='{7c3a9e51-0b15-66f9-2a15-000000010015}']]")
    assert build_xpath(ChannelQuery(source="powershell", event_ids=(4104,), execution_pid=8840)) == \
        "*[System[(EventID=4104) and Execution[@ProcessID=8840]]]"
    assert build_xpath(ChannelQuery(source="security", event_ids=(4625,), record_id=7)) == \
        "*[System[(EventID=4625) and EventRecordID=7]]"


@pytest.mark.parametrize("field,value", [
    ("ProcessGuid", "{x}' or '1'='1"), ("ProcessGuid", "not-a-guid"), ("User", "a'b"), ("User", "x]"),
    ("CommandLine", "anything"), ("ProcessId", "12 or 1=1"),
])
def test_channel_query_rejects_injection_and_unknown_fields(field, value):
    with pytest.raises(ValueError):
        ChannelQuery(source="sysmon", event_ids=(1,), data_equals=((field, value),))


def test_channel_query_bounds():
    with pytest.raises(ValueError):
        ChannelQuery(source="sysmon", event_ids=tuple(range(17)))
    with pytest.raises(ValueError):
        ChannelQuery(source="sysmon", event_ids=(1,), start=datetime(2026, 1, 1))  # naive time
    with pytest.raises(ValueError):
        ChannelQuery(source="system", event_ids=(1,))  # channel not allowlisted
    with pytest.raises(ValueError):
        ChannelQuery(source="sysmon", event_ids=(1,), max_events=5001)


def test_recorded_semantics_match_query_fields():
    p = first("sysmon", 1, pred=lambda p: p["event_data"]["ProcessId"] == "8840")
    guid = p["event_data"]["ProcessGuid"]
    assert matches(ChannelQuery(source="sysmon", event_ids=(1,), data_equals=(("ProcessGuid", guid),)), p)
    assert not matches(ChannelQuery(source="sysmon", event_ids=(3,)), p)
    assert not matches(ChannelQuery(source="sysmon", event_ids=(1,), end=T - timedelta(seconds=1)), p)
    r = RecordedEventReader.from_directory(DEMO)
    newest = r.query(ChannelQuery(source="sysmon", event_ids=(1,), reverse=True, max_events=2))
    oldest = r.query(ChannelQuery(source="sysmon", event_ids=(1,), max_events=2))
    assert len(newest) == 2 and newest != oldest
    t0 = [parse_event_xml(x)["system_time"] for x in newest]
    assert t0 == sorted(t0, reverse=True)


# --- capability discovery & coverage honesty ------------------------------------

def test_discovery_on_a_fully_instrumented_host():
    states = {s.label: s.state for s in backend().source_status()}
    assert states == {"Sysmon": "active", "Windows Security": "active", "PowerShell": "active",
                      "Microsoft Defender": "active"}


def test_discovery_reports_missing_denied_and_limited_sources():
    assert {s.label: s.state for s in backend(NO_SYSMON).source_status()}["Sysmon"] == "not_installed"
    b = backend(denied={"security"})
    sec = next(s for s in b.source_status() if s.source == "security")
    assert sec.state == "access_denied" and "Event Log Readers" in sec.detail
    # Sysmon running but configured without network (event 3) logging:
    events = {"sysmon": [x for x in xml_of("sysmon") if "<EventID>3</EventID>" not in x],
              "security": xml_of("security"), "powershell": xml_of("powershell"), "defender": xml_of("defender")}
    lim = WindowsEventBackend(settings(), RecordedEventReader(events=events))
    sysmon = next(s for s in lim.source_status() if s.source == "sysmon")
    assert sysmon.state == "limited" and 3 in sysmon.missing_ids


def test_permission_denied_is_never_reported_as_no_events():
    b = backend(denied={"sysmon"})
    with pytest.raises(ClassifiedError) as err:
        b.search_events(EventQuery(start=T - timedelta(hours=1), end=T, category="network"))
    assert err.value.kind == "permission"


def test_missing_source_raises_and_fallback_is_degraded():
    b = backend(NO_SYSMON)
    with pytest.raises(ClassifiedError) as err:
        b.search_events(EventQuery(start=T - timedelta(hours=1), end=T + timedelta(hours=1), category="network"))
    assert err.value.kind == "source_unavailable"
    got = b.search_events(EventQuery(start=T - timedelta(hours=1), end=T + timedelta(hours=1), category="process"))
    assert got and got.degraded and any("fallback source" in g for g in got.gaps)
    assert all(e.source == "windows-security" and e.process_guid is None for e in got)


def test_limited_network_logging_degrades_network_answers():
    events = {"sysmon": [x for x in xml_of("sysmon") if "<EventID>3</EventID>" not in x],
              "security": xml_of("security"), "powershell": xml_of("powershell"), "defender": xml_of("defender")}
    b = WindowsEventBackend(settings(), RecordedEventReader(events=events))
    got = b.search_events(EventQuery(start=T - timedelta(hours=1), end=T + timedelta(hours=1), category="network"))
    assert got == [] and got.degraded and any("configuration may exclude" in g for g in got.gaps)


def test_only_the_local_computer_can_be_queried():
    b = backend()
    with pytest.raises(ClassifiedError) as err:
        b.search_events(EventQuery(start=T - timedelta(hours=1), end=T, host="OTHER-PC"))
    assert err.value.kind == "source_unavailable"
    assert b.search_events(EventQuery(start=T - timedelta(minutes=1), end=T + timedelta(minutes=1),
                                      host="desktop-rw01", category="process"))
    assert b.get_host_context("OTHER-PC") is None
    hc = b.get_host_context("DESKTOP-RW01")
    assert "Sysmon: active" in hc.notes and hc.os


def test_process_scoped_queries_exclude_sources_without_process_identity():
    b = backend()
    p = first("sysmon", 1, pred=lambda p: p["event_data"]["ProcessId"] == "7512")  # G: IME PowerShell
    got = b.search_events(EventQuery(start=datetime(2026, 9, 29, tzinfo=timezone.utc),
                                     end=datetime(2026, 9, 30, tzinfo=timezone.utc),
                                     process_guid=p["event_data"]["ProcessGuid"], limit=50))
    assert got and {e.source for e in got} <= {"sysmon", "powershell"}
    assert not any(e.category == "detection" for e in got)  # Defender has no process identity


def test_powershell_script_blocks_are_tied_to_the_process_by_pid_and_time():
    b = backend()
    rw1 = first("sysmon", 1, pred=lambda p: p["event_data"]["ProcessId"] == "8840")
    got = b.search_events(EventQuery(start=T - timedelta(minutes=5), end=T + timedelta(minutes=5), category="script",
                                     process_guid=rw1["event_data"]["ProcessGuid"]))
    assert len(got) == 1 and "RW-01" in got[0].script_text
    assert got[0].process_guid == rw1["event_data"]["ProcessGuid"] and got[0].process_guid_inferred


def test_malformed_model_value_is_rejected_before_any_query():
    b = backend()
    be_alert = by_title(b, "encoded command, hidden window")
    ctx = ToolContext(b, EvidenceStore("windows"), be_alert, settings())
    before = len(b.reader.queries)
    call, _ = dispatch(ctx, 1, "search_events", {"process_guid": "{x}' or '1'='1"})
    assert call.status == "rejected" and call.error_kind == "invalid_argument"
    assert len(b.reader.queries) == before


# --- signals ----------------------------------------------------------------------------

def test_demo_signals():
    titles = sorted(a.title for a in backend().list_alerts())
    assert titles == sorted([
        "Microsoft Defender detection: Virus:DOS/EICAR_Test_File",
        "Repeated failed logons: 5+ failures for DESKTOP-RW01\\rw_nonexistent within 10 min",
        "Suspicious PowerShell (encoded command)",
        "Suspicious PowerShell (encoded command, hidden window)",
        "Suspicious PowerShell (hidden window)",
    ])


def _evs(source, event_id, directory=DEMO):
    return [normalize_windows_event(parse_event_xml(x)) for x in xml_of(source, directory)
            if parse_event_xml(x)["event_id"] == event_id]


def test_failed_logon_threshold_and_defender_dedup():
    fails = _evs("security", 4625)
    assert len(detect(fails[:4])) == 0 and len(detect(fails)) == 1
    assert len(detect(_evs("defender", 1116) + _evs("defender", 1117))) == 1


def test_persistence_lsass_chain_and_office_rules():
    base = normalize_windows_event(first("sysmon", 1, pred=lambda p: p["event_data"]["ProcessId"] == "9188"))
    office = base.model_copy(update={"parent_image": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                                     "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                                     "event_ref": "win:sysmon:1"})
    chain = base.model_copy(update={"parent_image": r"C:\Windows\System32\cmd.exe",
                                    "image": r"C:\Windows\System32\rundll32.exe", "event_ref": "win:sysmon:2"})
    lsass = base.model_copy(update={"category": "process_access", "event_id": 10, "event_ref": "win:sysmon:3",
                                    "target_image": r"C:\Windows\System32\lsass.exe", "granted_access": "0x1010"})
    query_only = lsass.model_copy(update={"granted_access": "0x1000", "event_ref": "win:sysmon:4"})
    task = base.model_copy(update={"category": "scheduled_task", "event_id": 4698, "task_name": r"\Updater",
                                   "event_ref": "win:security:5"})
    runkey = base.model_copy(update={"category": "registry", "event_id": 13, "event_ref": "win:sysmon:6",
                                     "target_object": r"HKU\S-1\Software\Microsoft\Windows\CurrentVersion\Run\x"})
    rules = {s.event.event_ref: s.rule for s in detect([office, chain, lsass, query_only, task, runkey])}
    assert rules == {"win:sysmon:1": "office_script", "win:sysmon:2": "suspicious_chain", "win:sysmon:3": "lsass_access",
                     "win:security:5": "persistence", "win:sysmon:6": "persistence"}


def test_ordinary_powershell_is_not_a_signal():
    base = normalize_windows_event(first("sysmon", 1, pred=lambda p: p["event_data"]["ProcessId"] == "8840"))
    plain = base.model_copy(update={"command_line": "powershell.exe -NoProfile -File C:\\Scripts\\report.ps1"})
    assert detect([plain]) == []


# --- end to end on Windows replay ---------------------------------------------------------

def run(title_fragment, directory=DEMO, model=None, **reader_kw):
    b = WindowsEventBackend(settings(), RecordedEventReader.from_directory(directory, **reader_kw))
    agent = InvestigationAgent(b, model or MockInvestigatorModel(), settings())
    return agent.investigate(by_title(b, title_fragment))


def unmet(r):
    return {q.name for q in r.coverage.requirements if not q.satisfied}


def test_G_windows_benign_admin_job_is_closable_with_complete_coverage():
    r = run("(hidden window)")
    assert r.verdict == "benign" and r.status == "completed", (unmet(r), r.validation.issues)
    assert unmet(r) == set()
    # Host-wide network was capped on this busy host; the tree-scoped query completed.
    tools = [(c.tool, c.outcome, (c.target or {}).get("scope")) for c in r.trace.tool_calls]
    assert ("get_network_activity", "truncated", None) in tools
    assert ("get_network_activity", "empty", "process_tree") in tools


def test_RW01_suspicious_powershell_investigation():
    r = run("encoded command, hidden window")
    assert r.verdict in ("suspicious", "likely_malicious") and r.status == "completed"
    refs = {e.source_ref for e in r.evidence}
    rw1 = first("sysmon", 1, pred=lambda p: p["event_data"]["ProcessId"] == "8840")
    net = first("sysmon", 3, pred=lambda p: p["event_data"]["DestinationIp"] == "93.184.215.14")
    sb = first("powershell", 4104, pred=lambda p: "RW-01" in p["event_data"]["ScriptBlockText"])
    assert {f"win:sysmon:{rw1['record_id']}", f"win:sysmon:{net['record_id']}",
            f"win:powershell:{sb['record_id']}"} <= refs
    assert r.validation.invalid_evidence_refs == []
    assert any("encoded" in (e.attributes.get("command_line", "") + " ".join(e.indicators)) for e in r.evidence)
    assert "host_signals" in unmet(r)  # RW-03 and RW-04 happen on the same host within the hour


def test_RW03_multi_generation_tree_is_reconstructed():
    r = run("Suspicious PowerShell (encoded command)")
    root = r.process_tree[0]
    names = []

    def walk(n, depth):
        names.append((depth, n.image))
        for c in n.children:
            walk(c, depth + 1)
    walk(root, 0)
    assert (0, "powershell.exe") in names and (1, "cmd.exe") in names
    assert (2, "whoami.exe") in names and (2, "ping.exe") in names


def test_RW04_failed_logon_investigation_uses_logon_activity():
    r = run("Repeated failed logons")
    logon_call = next(c for c in r.trace.tool_calls if c.tool == "get_logon_activity")
    assert logon_call.status == "ok" and logon_call.result_count >= 6
    assert sum("failed_logon" in e.indicators for e in r.evidence) >= 6
    assert r.verdict != "benign"


def test_RW05_missing_sysmon_is_incomplete_and_never_benign():
    r = run("hidden window", directory=NO_SYSMON)
    assert r.status == "incomplete"
    failed = [c for c in r.trace.tool_calls if c.outcome == "failed"]
    assert failed and all(c.error_kind in ("source_unavailable", "permission") for c in failed)
    assert {"process_tree", "network_activity"} <= unmet(r)
    adv = run("hidden window", directory=NO_SYSMON, model=BenignProposerModel())
    assert adv.verdict == "insufficient_evidence"


def test_access_denied_sysmon_is_incomplete_not_clean():
    b = WindowsEventBackend(settings(), RecordedEventReader.from_directory(DEMO))
    alert = by_title(b, "(hidden window)")
    b.reader.denied.add("sysmon")  # access revoked after the signal was raised
    b.refresh_sources()
    r = InvestigationAgent(b, BenignProposerModel(), settings()).investigate(alert)
    assert r.verdict == "insufficient_evidence" and r.status == "incomplete"
    assert any(c.error_kind == "permission" for c in r.trace.tool_calls)
    assert any("access denied" in c.lower() for c in r.coverage.backend_caveats)


def test_adversary_cannot_close_windows_signals_other_than_the_clean_admin_job():
    b = WindowsEventBackend(settings(), RecordedEventReader.from_directory(DEMO))
    agent = InvestigationAgent(b, BenignProposerModel(), settings())
    verdicts = {a.title: agent.investigate(a).verdict for a in b.list_alerts()}
    assert verdicts.pop("Suspicious PowerShell (hidden window)") == "benign"
    assert set(verdicts.values()) == {"insufficient_evidence"}, verdicts


def test_build_agent_wires_windows_replay():
    agent, b = build_agent(settings())
    assert b.name == "windows" and len(b.list_alerts()) == 5
    assert json.loads(json.dumps([s.model_dump() for s in b.source_status()]))
