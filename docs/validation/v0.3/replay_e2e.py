"""End-to-end Windows pipeline on recorded event XML (SYNTHETIC samples by default).

Usage: python docs/validation/v0.3/replay_e2e.py [replay-dir ...]

For each directory: capability discovery, signals, and an investigation of every
signal with (a) the mock analyst and (b) the evaluation-only benign proposer.
This exercises parsing -> normalization -> discovery -> signals -> tools ->
requirements -> verdict gates. It is NOT a real-Windows result.
"""
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(root))
from investigator.agent import InvestigationAgent  # noqa: E402
from investigator.backends.windows import WindowsEventBackend  # noqa: E402
from investigator.backends.winevt_reader import RecordedEventReader  # noqa: E402
from investigator.config import load_settings  # noqa: E402
from investigator.llm.mock import BenignProposerModel, MockInvestigatorModel  # noqa: E402

dirs = sys.argv[1:] or [str(root / "investigator/windows_samples/demo"),
                        str(root / "investigator/windows_samples/demo-no-sysmon")]
for d in dirs:
    s = load_settings(llm="mock", backend="windows-replay", windows_replay_dir=d)
    b = WindowsEventBackend(s, RecordedEventReader.from_directory(d))
    print(f"== {Path(d).name}: host {b.primary_host()}")
    for st in b.source_status():
        print(f"   source {st.label:<20} {st.state:<14} {st.detail}")
    alerts = b.list_alerts()
    for n in b.signal_notes:
        print(f"   note: {n}")
    for a in alerts:
        print(f"-- {a.alert_id} {a.severity:<8} {a.title}")
        for label, model in (("mock analyst", MockInvestigatorModel()), ("benign proposer", BenignProposerModel())):
            r = InvestigationAgent(b, model, s).investigate(a)
            unmet = [q.name for q in r.coverage.requirements if not q.satisfied]
            tools = ", ".join(f"{c.tool.replace('get_', '')}:{c.outcome}" for c in r.trace.tool_calls)
            print(f"   {label:<16} verdict={r.verdict:<21} status={r.status:<10} evidence={len(r.evidence):<3} "
                  f"invalid_refs={len(r.validation.invalid_evidence_refs)} unmet={unmet}")
            if label == "mock analyst":
                print(f"   {'':<16} tools: {tools}")
