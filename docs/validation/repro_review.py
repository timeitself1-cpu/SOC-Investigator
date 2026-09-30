"""Independent reproductions against the uploaded 'improved' source (unmodified)."""
import copy, json, sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

ROOT = Path(sys.argv[1])
sys.path.insert(0, str(ROOT))

from investigator.agent import InvestigationAgent, build_agent
from investigator.backends.base import EventQuery
from investigator.backends.fixture import FixtureBackend
from investigator.backends.normalize import normalize_wazuh_doc
from investigator.config import load_settings
from investigator.evidence import EvidenceStore
from investigator.llm.base import LLMResponse
from investigator.llm.mock import MockInvestigatorModel
from investigator.models import Alert, DraftFinding, InvestigationTrace, ReportDraft
from investigator.report import validate_report
from investigator.tools import ToolContext, dispatch

T0 = datetime(2026, 9, 29, 11, 0, tzinfo=timezone.utc)


def doc(i, ts, host, evid, ed, provider="Microsoft-Windows-Sysmon", channel="Microsoft-Windows-Sysmon/Operational", rule=None):
    return {"id": i, "timestamp": ts.isoformat(), "agent": {"name": host}, "rule": rule or {},
            "data": {"win": {"system": {"providerName": provider, "eventID": str(evid), "channel": channel},
                             "eventdata": ed}}}


class ListBackend:
    name = "fixture"

    def __init__(self, docs, alert_ref, title="t", hosts=None):
        self.events = {d["id"]: normalize_wazuh_doc(d) for d in docs}
        trig = self.events[alert_ref]
        self.alert = Alert(alert_id="X", title=title, timestamp=trig.timestamp, host=trig.host,
                           severity="high", event_ref=alert_ref, process_guid=trig.process_guid)
        self.hosts = hosts or {}
        self.queries = 0

    def list_alerts(self): return [self.alert]
    def get_alert(self, a): return self.alert if a == "X" else None
    def get_event(self, r): return self.events.get(r)
    def get_host_context(self, h): return self.hosts.get(h)

    def search_events(self, q: EventQuery):
        self.queries += 1
        fb = FixtureBackend.__new__(FixtureBackend)
        fb._events = self.events
        return FixtureBackend.search_events(fb, q)


def header(t):
    print("\n" + "=" * 8, t, "=" * 8)


S = load_settings(llm="mock", backend="fixture")

# ---------------------------------------------------------------- R1
header("R1 masquerading 'AgentExecutor.exe' in a user-writable path -> benign accepted")
H = "WS-77"
docs = [
    doc("M1", T0, H, 1, {"image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                         "commandLine": "powershell.exe -NoP -EncodedCommand " + "QQBBAEEAQQBBAEEAQQBBAEEAQQBBAA==",
                         "processGuid": "{m-1}", "parentImage": r"C:\Users\Public\AgentExecutor.exe",
                         "user": r"CORP\bob"}, rule={"id": "1", "level": 12, "description": "enc ps"}),
    doc("M2", T0 + timedelta(seconds=2), H, 3, {"image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                                                "processGuid": "{m-1}", "destinationIp": "10.9.9.9", "destinationPort": "443"}),
]
be = ListBackend(docs, "M1")
rep = InvestigationAgent(be, MockInvestigatorModel(), S).investigate(be.alert)
print("end-to-end mock verdict:", rep.verdict, rep.confidence, "status:", rep.status, "valid:", rep.validation.valid)
store = EvidenceStore("fixture")
e1 = store.add(be.events["M1"], "t"); store.add(be.events["M2"], "t")
print("indicators on masquerade process:", e1.indicators)
draft = ReportDraft(verdict="benign", confidence=0.8, summary="Routine SCCM job.",
                    findings=[DraftFinding(title="Mgmt agent", description="d", evidence_ids=[e1.evidence_id],
                                           claims=["benign_administration"])])
tr = InvestigationTrace(investigation_id="x", model="m", backend="fixture", max_steps=1)
r = validate_report(draft, store, be.alert, tr, [], "m", "fixture", T0, T0)
print("validator on model-drafted benign:", r.verdict, "valid:", r.validation.valid, "issues:", r.validation.issues)

# ---------------------------------------------------------------- R2
header("R2 get_host_context result never reaches the model or report")
agent, backend = build_agent(S)
captured = []


class Spy(MockInvestigatorModel):
    def complete(self, messages, *, temperature=None):
        captured.append(messages[-1]["content"])
        return super().complete(messages, temperature=temperature)


agent.model = Spy()
rep = agent.investigate(backend.get_alert("INC-005"))
hc = backend.get_host_context("IT-ADMIN-01")
print("host notes:", hc.notes)
print("'SCCM' / role text in any prompt after get_host_context:", any("runs scheduled inventory" in c for c in captured))
print("host context in report JSON:", "runs scheduled inventory" in rep.model_dump_json())

# ---------------------------------------------------------------- R3/R4
header("R3 prompt size is unbounded relative to num_ctx; R4 audit clipping has no structured flag")
big = []
for i in range(150):
    big.append(doc(f"B{i}", T0 + timedelta(seconds=i), "BIG-1", 1, {
        "image": r"C:\Windows\System32\cmd.exe", "commandLine": "cmd.exe /c " + ("x" * 900),
        "processGuid": f"{{b-{i}}}", "parentImage": r"C:\Windows\explorer.exe"}))
be = ListBackend(big, "B0")
ctx = ToolContext(be, EvidenceStore("fixture", 150), be.alert, S)
for d in big:
    ctx.store.add(be.events[d["id"]], "t")
tr = InvestigationTrace(investigation_id="x", model="m", backend="fixture", max_steps=12)
ag = InvestigationAgent(be, MockInvestigatorModel(), S)
if hasattr(ag, "_build_state"):
    state, meta = ag._build_state(ctx, tr, 1, "decide", ag.prompt_budget_chars())
    print(f"state chars={len(state):,} (budget {ag.prompt_budget_chars():,}) ~tokens={len(state)//3:,} "
          f"num_ctx={S.ollama_num_ctx:,} compaction={meta['level']} omitted={meta['evidence_omitted']}")
else:
    state = ag._state_block(ctx, tr, 1, "decide")
    print(f"state chars={len(state):,}  ~tokens={len(state)//4:,}  num_ctx={S.ollama_num_ctx:,}  (no budget)")
ag4, b4 = build_agent(S)
rep = ag4.investigate(b4.get_alert("INC-004"))
print("INC-004 exchanges (purpose, stored chars, clipped-in-audit):",
      [(x.purpose, len(x.messages[-1]["content"]), x.messages[-1]["content"].rstrip().endswith("[clipped]")
        or getattr(x, "clipped", False)) for x in rep.trace.llm_exchanges])
print("structured disclosure fields:", [k for k in type(rep.trace.llm_exchanges[0]).model_fields
                                        if "clip" in k or "sha" in k])

# ---------------------------------------------------------------- R5
header("R5 realistic Sysmon parentProcessGuid (parent outside retention) -> every tree 'incomplete'; benign unreachable")
tmp = Path(sys.argv[2]) / "cases_r5"
import shutil
shutil.rmtree(tmp, ignore_errors=True)
shutil.copytree(ROOT / "investigator" / "cases" if (ROOT / "investigator" / "cases").is_dir() else ROOT / "cases", tmp)
ev = json.loads((tmp / "INC005" / "events.json").read_text())
ev[0]["data"]["win"]["eventdata"]["parentProcessGuid"] = "{dddd5555-0000-0000-0005-0000000000aa}"  # AgentExecutor, long-lived, not in window
(tmp / "INC005" / "events.json").write_text(json.dumps(ev))
S5 = load_settings(llm="mock", backend="fixture", cases_dir=tmp)
agent5, b5 = build_agent(S5)
rep = agent5.investigate(b5.get_alert("INC-005"))
print("INC-005 with realistic parent GUID -> verdict:", rep.verdict, "status:", rep.status)
print("  truncated calls:", [c.tool for c in rep.trace.tool_calls if c.truncated])

# ---------------------------------------------------------------- R6
header("R6 Wazuh: nonexistent archives index returns 0 shards/0 hits and is treated as 'no activity'")
from investigator.backends.wazuh import WazuhBackend
seen = []


def handler(req: httpx.Request):
    seen.append(str(req.url))
    return httpx.Response(200, json={"took": 1, "timed_out": False, "_shards": {"total": 0, "successful": 0, "failed": 0},
                                     "hits": {"total": {"value": 0}, "hits": []}})


WS = load_settings(backend="wazuh", wazuh_indexer_url="https://idx:9200", wazuh_indexer_user="u",
                   wazuh_indexer_password="p", wazuh_events_index="wazuh-archives-*")
wb = WazuhBackend(WS, transport=httpx.MockTransport(handler))
try:
    out = wb.search_events(EventQuery(start=T0 - timedelta(hours=1), end=T0, host="H", limit=5))
    print("result:", out, "| request:", seen[-1])
except Exception as exc:
    print("raised:", type(exc).__name__, getattr(exc, "kind", ""), "| request:", seen[-1])

# ---------------------------------------------------------------- R7
header("R7 Wazuh API token cached forever; expired token (401) is not refreshed")
calls = []


def api(req: httpx.Request):
    calls.append((req.method, req.url.path))
    if req.url.path == "/security/user/authenticate":
        return httpx.Response(200, json={"data": {"token": f"tok{len(calls)}"}})
    if req.url.path == "/agents":
        if req.headers["authorization"] == "Bearer tok1" and len([c for c in calls if c[1] == "/agents"]) > 1:
            return httpx.Response(401, json={"title": "Unauthorized"})
        return httpx.Response(200, json={"data": {"affected_items": [{"name": "H", "id": "001"}]}})
    return httpx.Response(200, json={"_shards": {"total": 1, "failed": 0}, "hits": {"hits": []}})


WS2 = load_settings(backend="wazuh", wazuh_indexer_url="https://idx:9200", wazuh_indexer_user="u",
                    wazuh_indexer_password="p", wazuh_api_url="https://api:55000", wazuh_api_user="a", wazuh_api_password="b")
wb = WazuhBackend(WS2, transport=httpx.MockTransport(api))
print("first:", wb.get_host_context("H").host)
try:
    wb.get_host_context("H")
    print("second: ok")
except Exception as exc:
    print("second call after token expiry ->", type(exc).__name__, str(exc)[:120])

# ---------------------------------------------------------------- R8/R9
header("R8 raw backend exception text flows into trace/model prompt; R9 one malformed alert breaks the queue")


def bad(req: httpx.Request):
    return httpx.Response(200, json={"_shards": {"total": 1, "failed": 0}, "hits": {"hits": [
        {"_index": "wazuh-alerts-4.x-2026.09.29", "_id": "ok1", "_source": {"timestamp": T0.isoformat(), "agent": {"name": "H"}, "rule": {"level": 12}, "data": {"win": {"system": {}, "eventdata": {}}}}},
        {"_index": "wazuh-alerts-4.x-2026.09.29", "_id": "bad", "_source": {"timestamp": "not-a-time", "agent": {"name": "H"}}},
    ]}})


wb = WazuhBackend(WS, transport=httpx.MockTransport(bad))
try:
    print(len(wb.list_alerts()))
except Exception as exc:
    print("list_alerts ->", type(exc).__name__, ":", str(exc)[:100])


class Boom(ListBackend):
    def search_events(self, q):
        raise RuntimeError("OpenSearch said: {\"error\":\"...Authorization: Basic dTpw...\"}")


be = Boom(docs, "M1")
ctx = ToolContext(be, EvidenceStore("fixture"), be.alert, S)
call, _ = dispatch(ctx, 1, "search_events", {})
print("ToolCall.error (also serialized into STATE_JSON tools_called):", call.error)

# ---------------------------------------------------------------- R10
header("R10 identical repeated tool calls are re-executed until the step budget is exhausted")


class Repeat:
    name = "repeat"

    def complete(self, messages, *, temperature=None):
        if '"phase": "final_report"' in messages[-1]["content"]:
            return LLMResponse(text='{"verdict":"insufficient_evidence","confidence":0.1,"summary":"x"}', model="r")
        return LLMResponse(text='{"action":"call_tool","tool":"search_events","arguments":{"host":"WS-77"}}', model="r")


be = ListBackend(docs, "M1")
rep = InvestigationAgent(be, Repeat(), S).investigate(be.alert)
print("backend queries:", be.queries, "statuses:", sorted({c.status for c in rep.trace.tool_calls}),
      "report status:", rep.status)

# ---------------------------------------------------------------- R11
header("R11 raw telemetry key '_role' is trusted as the application's trigger marker")
d2 = copy.deepcopy(docs)
d2[1]["_role"] = "trigger"
be = ListBackend(d2, "M1")
ctx = ToolContext(be, EvidenceStore("fixture"), be.alert, S)
for d in d2:
    ctx.store.add(be.events[d["id"]], "t")
st = json.loads(InvestigationAgent(be, MockInvestigatorModel(), S)._state_block(ctx, InvestigationTrace(
    investigation_id="x", model="m", backend="fixture", max_steps=1), 1, "decide"))
print("is_trigger flags:", [(e["evidence_id"], e["is_trigger"]) for e in st["evidence"]])
