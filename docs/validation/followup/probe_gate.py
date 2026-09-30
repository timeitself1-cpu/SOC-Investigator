import sys; root = sys.argv[1]; sys.path.insert(0, root); sys.path.insert(0, root + "/tests")
sys.argv = [sys.argv[0], root]
exec(open(__file__.replace("probe_gate.py", "probe_benign.py")).read().split("def run(")[0])
from investigator.evidence import management_parent_status
class Flaky(ListBackend):
    def search_events(self, q):
        raise RuntimeError("backend down")
be = Flaky(docs(), "A1")
r = InvestigationAgent(be, Scripted([{"action": "call_tool", "tool": "get_network_activity", "arguments": {}}], BENIGN),
                       settings()).investigate(be.alert)
print("benign draft + failed network query ->", r.verdict, r.status, r.coverage.failed, "failed")
print("'..' path ->", management_parent_status(r"C:\Program Files\Microsoft Configuration Manager\..\..\Users\Public\AgentExecutor.exe"))
