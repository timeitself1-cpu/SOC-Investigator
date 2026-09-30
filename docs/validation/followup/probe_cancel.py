import sys, time, tempfile; root = sys.argv[1]; sys.path.insert(0, root)
from investigator.config import load_settings
from investigator.service import InvestigationService
from investigator.llm.mock import MockInvestigatorModel
class SlowReport(MockInvestigatorModel):
    def complete(self, messages, **kw):
        if '"phase": "final_report"' in messages[1]["content"]:
            time.sleep(1.0)
        return super().complete(messages, **kw)
svc = InvestigationService(load_settings(llm="mock", backend="fixture", reports_dir=tempfile.mkdtemp()))
svc.agent.model = SlowReport()
run = svc.start("INC-001")
while not any("Building assessment" in a.message for a in list(run.activity)):
    time.sleep(0.02)
print("cancel accepted during final-report call:", svc.cancel(run.run_id))
run.thread.join(10)
print("-> run status:", run.status, "| report status:", run.report_status, "| verdict:", run.verdict,
      "| cancel_requested:", run.cancel_event.is_set())
