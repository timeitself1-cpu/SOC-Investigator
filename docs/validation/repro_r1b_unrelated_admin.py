import sys; from datetime import datetime, timezone, timedelta
sys.path.insert(0, sys.argv[1])
from investigator.backends.normalize import normalize_wazuh_doc
from investigator.evidence import EvidenceStore
from investigator.models import Alert, DraftFinding, InvestigationTrace, ReportDraft
from investigator.report import validate_report
T0=datetime(2026,9,29,11,tzinfo=timezone.utc); PS=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
def d(i,t,ed): return {"id":i,"timestamp":t.isoformat(),"agent":{"name":"WS-9"},"data":{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"1"},"eventdata":ed}}}
u=normalize_wazuh_doc(d("U1",T0,{"image":PS,"commandLine":"powershell -enc QQBBAEEAQQBBAEEAQQBBAEEA","processGuid":"{u}","parentImage":r"C:\Windows\explorer.exe"}))
a=normalize_wazuh_doc(d("A1",T0+timedelta(minutes=2),{"image":PS,"commandLine":"powershell -File inv.ps1","processGuid":"{a}","parentImage":r"C:\Program Files\Microsoft Configuration Manager\bin\x64\AgentExecutor.exe"}))
st=EvidenceStore("fixture"); t=st.add(u,"seed"); e=st.add(a,"t")
if hasattr(st, "mark_trigger"): st.mark_trigger(t.evidence_id)
alert=Alert(alert_id="X",title="t",timestamp=T0,host="WS-9",severity="high",event_ref="U1")
r=validate_report(ReportDraft(verdict="benign",confidence=0.8,summary="admin",findings=[DraftFinding(title="admin",description="d",evidence_ids=[e.evidence_id],claims=["benign_administration"])]),st,alert,InvestigationTrace(investigation_id="x",model="m",backend="fixture",max_steps=1),[],"m","fixture",T0,T0)
print("unrelated-admin whitewash -> verdict:", r.verdict, "status:", r.status, "issues:", r.validation.issues)
