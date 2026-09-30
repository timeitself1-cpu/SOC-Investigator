"""Run the independent suite against the UNMODIFIED baseline, one isolated case per temp dir."""
import json, shutil, sys, tempfile
from pathlib import Path
base, suite = Path(sys.argv[1]), Path(sys.argv[2])
sys.path.insert(0, str(base))
from investigator.agent import InvestigationAgent
from investigator.backends.fixture import FixtureBackend
from investigator.config import load_settings
from investigator.llm.mock import MockInvestigatorModel
S = load_settings(llm="mock", backend="fixture")
rows = []
for d in sorted(p for p in suite.iterdir() if (p / "truth.json").is_file()):
    truth = json.loads((d / "truth.json").read_text())
    with tempfile.TemporaryDirectory() as tmp:
        shutil.copytree(d, Path(tmp) / d.name)
        try:
            b = FixtureBackend(Path(tmp))
            r = InvestigationAgent(b, MockInvestigatorModel(), S).investigate(b.list_alerts()[0])
        except Exception as exc:
            rows.append((truth["case_id"], truth["label"], f"HARNESS ERROR {type(exc).__name__}", "", False, False, [])); continue
    claims = {c for f in r.findings for c in f.claims}
    rows.append((truth["case_id"], truth["label"], r.verdict, r.status, r.verdict in truth["acceptable_verdicts"],
                 r.verdict in truth.get("forbidden_verdicts", []), sorted(claims & set(truth.get("forbidden_claims", [])))))
for row in rows:
    print(f"{row[0]:<8} {row[1]:<10} {row[2]:<24} {row[3]:<11} acceptable={row[4]!s:<5} forbidden_verdict={row[5]!s:<5} forbidden_claims={row[6]}")
print("acceptable:", sum(r[4] for r in rows), "/", len(rows), " forbidden verdicts:", sum(r[5] for r in rows))
