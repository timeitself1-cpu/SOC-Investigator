import sys; root = sys.argv[1]; sys.path.insert(0, root); sys.path.insert(0, root + "/tests")
from datetime import timedelta
from test_review_regressions import ListBackend, doc, settings, T0, PS
from investigator.evidence import EvidenceStore
from investigator.tools import ToolContext, dispatch
noise = [doc(f"N{i}", T0 - timedelta(minutes=14) + timedelta(seconds=20 * i), "WS-5", 1,
             {"image": r"C:\Windows\System32\svchost.exe", "processGuid": "{n%d}" % i}) for i in range(40)]
trig = doc("T", T0, "WS-5", 1, {"image": PS, "commandLine": "powershell -nop", "processGuid": "{t}", "parentImage": r"C:\Windows\explorer.exe"})
after = doc("C2", T0 + timedelta(seconds=5), "WS-5", 3, {"image": PS, "processGuid": "{t}", "destinationIp": "93.184.216.34", "destinationPort": "443"})
be = ListBackend(noise + [trig, after], "T")
ctx = ToolContext(be, EvidenceStore("fixture"), be.alert, settings())
ctx.store.mark_trigger(ctx.store.add(be.events["T"], "seed").evidence_id)
call, res = dispatch(ctx, 1, "get_related_events", {"evidence_id": "EV-0001"})
print("get_related_events ±15min, 40 earlier noise events:", call.outcome, "retrieved", call.result_count,
      "| latest retrieved:", max(e.timestamp for e in res.evidence).time(), "| trigger at", T0.time(),
      "| post-trigger C2 connection retrieved:", any(e.category == "network" for e in res.evidence))
for sub in ("wazuh.py",):
    src = open(root + "/investigator/backends/" + sub).read()
    print("wazuh sort:", src[src.find('"sort": [{"timestamp"', src.find("def build_query")):][:46])
