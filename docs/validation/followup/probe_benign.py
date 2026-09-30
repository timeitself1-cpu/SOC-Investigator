"""Probes of the v0.2.0 benign-verdict guard (R1/R1b follow-up)."""
import json, sys
from datetime import timedelta
sys.path.insert(0, sys.argv[1]); sys.path.insert(0, sys.argv[1] + "/tests")
from test_review_regressions import ListBackend, doc, settings, T0, PS, ENC
from investigator.agent import InvestigationAgent
from investigator.llm.base import LLMResponse

SCCM = r"C:\Program Files\Microsoft Configuration Manager\bin\x64\AgentExecutor.exe"

class Scripted:
    name = "scripted"
    def __init__(self, decisions, report):
        self.decisions, self.report = list(decisions), report
    def complete(self, messages, *, temperature=None, schema=None):
        phase = json.loads(messages[1]["content"].split("<STATE_JSON>\n",1)[1].rsplit("\n</STATE_JSON>",1)[0])["phase"]
        if phase == "decide":
            d = self.decisions.pop(0) if self.decisions else {"action": "finish", "arguments": {}}
            return LLMResponse(json.dumps(d), self.name)
        return LLMResponse(json.dumps(self.report), self.name)

BENIGN = {"verdict": "benign", "confidence": 0.8, "summary": "Routine SCCM inventory job.",
          "findings": [{"title": "SCCM job", "description": "Launched by the SCCM agent.", "severity": "informational",
                        "evidence_ids": ["EV-0001"], "claims": ["benign_administration", "execution"]}]}

def docs():
    return [
        doc("A1", T0, "WS-9", 1, {"image": PS, "commandLine": f"powershell -EncodedCommand {ENC}", "processGuid": "{p1}",
                                  "parentImage": SCCM, "parentProcessGuid": "{p0}", "user": r"NT AUTHORITY\SYSTEM"}),
        # child cmd.exe -> grandchild rundll32 in AppData, beaconing to a public IP
        doc("A2", T0 + timedelta(seconds=3), "WS-9", 1, {"image": r"C:\Windows\System32\cmd.exe", "commandLine": "cmd /c start x",
                                  "processGuid": "{p2}", "parentImage": PS, "parentProcessGuid": "{p1}"}),
        doc("A3", T0 + timedelta(seconds=4), "WS-9", 1, {"image": r"C:\Windows\System32\rundll32.exe",
                                  "commandLine": r"rundll32 C:\ProgramData\x.dll,Start", "processGuid": "{p3}",
                                  "parentImage": r"C:\Windows\System32\cmd.exe", "parentProcessGuid": "{p2}"}),
        doc("A4", T0 + timedelta(seconds=6), "WS-9", 3, {"image": r"C:\Windows\System32\rundll32.exe", "processGuid": "{p3}",
                                  "destinationIp": "93.184.216.34", "destinationPort": "443"}),
    ]

def run(label, decisions):
    be = ListBackend(docs(), "A1")
    r = InvestigationAgent(be, Scripted(decisions, BENIGN), settings()).investigate(be.alert)
    tags = sorted({t for e in r.evidence for t in e.indicators})
    print(f"{label}\n  -> verdict={r.verdict} conf={r.confidence:.2f} status={r.status} valid={r.validation.valid}"
          f" evidence={len(r.evidence)} indicators={tags}\n  unknowns={r.coverage.unknowns}\n  issues={r.validation.issues}")

run("P1 model finishes immediately (no tree, no network query) and drafts benign", [])
run("P2 model reconstructs the tree and queries host network; grandchild beacons to a public IP",
    [{"action": "call_tool", "tool": "get_process_tree", "arguments": {"evidence_id": "EV-0001"}},
     {"action": "call_tool", "tool": "get_network_activity", "arguments": {}},
     {"action": "call_tool", "tool": "get_host_context", "arguments": {}}])

from investigator.llm.mock import MockInvestigatorModel
be = ListBackend(docs(), "A1")
r = InvestigationAgent(be, MockInvestigatorModel(), settings()).investigate(be.alert)
print("P3 mock analyst on the same telemetry ->", r.verdict, f"{r.confidence:.2f}", r.status,
      "calls:", [c.tool for c in r.trace.tool_calls], "evidence:", len(r.evidence),
      "grandchild beacon retrieved:", any("external_destination" in e.indicators for e in r.evidence))
