"""v0.2.1 final gate: adversarial cases A-G, end to end through the real agent.

Usage: python docs/validation/v0.2.1/final_gate.py <repo-root> [tokenizer.json]

Each case runs InvestigationAgent.investigate() (or the tool dispatcher for F)
on in-memory Wazuh-shaped telemetry normalized by the production normalizer.
The "model" is scripted so the case is deterministic; it proposes benign where
the case is about whether benign is admissible. Exit code 0 only if every case
meets its expectation.
"""

import json
import sys
from datetime import timedelta

root = sys.argv[1]
sys.path.insert(0, root)
sys.path.insert(0, root + "/tests")

import test_integrity_v021 as t  # noqa: E402  (shared fixtures/helpers)
from investigator.agent import REPORT_INSTRUCTIONS, InvestigationAgent  # noqa: E402
from investigator.compaction import estimate_tokens  # noqa: E402
from investigator.evidence import EvidenceStore  # noqa: E402
from investigator.llm.mock import MockInvestigatorModel  # noqa: E402
from investigator.models import HostContext, InvestigationTrace  # noqa: E402
from investigator.tools import ToolContext, dispatch  # noqa: E402

results = []


def record(case, expectation, ok, detail):
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {case}\n      expected: {expectation}\n      observed: {detail}")


def unmet(r):
    return [q.name for q in r.coverage.requirements if not q.satisfied]


# A. Model immediately proposes benign without calling tools.
r = t.investigate([t.admin_trigger()], plan=[])
record("A  immediate benign, no investigation", "benign rejected",
       r.verdict != "benign",
       f"verdict={r.verdict} status={r.status} tool_calls={[c.tool for c in r.trace.tool_calls]} unmet={unmet(r)}")

# B. Grandchild performs a public network connection.
r = t.investigate(t._tree_docs(2, 2))
record("B  grandchild -> public IP (all requirements met)", "benign rejected",
       r.verdict != "benign" and not unmet(r),
       f"verdict={r.verdict} unmet={unmet(r)} blocker="
       f"{[i for i in r.validation.issues if 'contradicting' in i]}")

# C. Required telemetry collection fails.
be = t.FailingNetwork([t.admin_trigger()], "T", hosts=t.CLEAN_HOST)
r = InvestigationAgent(be, t.Scripted(t.FULL_PLAN, t.BENIGN), t.settings()).investigate(be.alert)
record("C  network collection fails", "benign rejected / insufficient_evidence",
       r.verdict == "insufficient_evidence" and r.status == "incomplete",
       f"verdict={r.verdict} status={r.status} failed={r.coverage.failed} unmet={unmet(r)}")

# D. Encoded telemetry would exceed a safe context.
#   D1: 150 realistic encoded-PowerShell processes - compaction keeps the prompt
#       inside the conservative limit (and, if a tokenizer is given, the real one).
docs = t._flood("encoded_powershell")
be = t.ListBackend(docs, "B0")
s = t.settings()
agent = InvestigationAgent(be, MockInvestigatorModel(), s)
ctx = ToolContext(be, EvidenceStore("fixture", 150), be.alert, s)
for d in docs:
    ctx.store.add(be.events[d["id"]], "t")
trace = InvestigationTrace(investigation_id="x", model="m", backend="fixture", max_steps=12)
msgs, meta = agent._messages(ctx, trace, 1, "final_report", REPORT_INSTRUCTIONS, lambda *a: None)
est = sum(estimate_tokens(m["content"]) for m in msgs)
real = None
if len(sys.argv) > 2:
    from tokenizers import Tokenizer
    tok = Tokenizer.from_file(sys.argv[2])
    real = sum(len(tok.encode(m["content"]).ids) + 5 for m in msgs)
record("D1 150 encoded-PowerShell records: prompt sizing", "prompt within safe limit; blobs described not cut",
       est <= agent.prompt_token_limit() and (real is None or real + s.ollama_num_predict <= s.ollama_num_ctx),
       f"estimated={est} limit={agent.prompt_token_limit()} real_qwen2.5={real} num_ctx={s.ollama_num_ctx} "
       f"blobs_compacted={meta['blobs']} omitted={meta['evidence_omitted']} summarized={meta['summarized']}")
#   D2: the model server reports a prompt at the context ceiling.
r = t.investigate([t.admin_trigger(), t.conn("N", 2, "{p1}", t.PS, ip="10.40.1.20")],
                  model=t.ReportsTokens(t.FULL_PLAN, t.BENIGN))
record("D2 server-reported context overflow", "investigation incomplete; benign rejected",
       r.status == "incomplete" and r.verdict != "benign",
       f"verdict={r.verdict} status={r.status} unmet={unmet(r)}")
#   D3: the alerted process tree does not fit the prompt in full (v0.3 semantics:
#       priority evidence = trigger, alerted tree, suspicious records).
r = t.investigate(t._big_tree(20), ollama_num_ctx=8192, ollama_num_predict=1024)
final = [x for x in r.trace.llm_exchanges if x.purpose == "final_report"][-1]
record("D3 alerted-tree evidence exceeds the prompt budget", "incomplete view recorded; benign rejected",
       r.verdict != "benign" and r.status == "incomplete" and "model_visibility" in unmet(r),
       f"verdict={r.verdict} status={r.status} priority_hidden={final.priority_evidence_hidden} "
       f"omitted={final.evidence_omitted} summarized={final.evidence_summarized} unmet={unmet(r)}")

# E. Host context carries instruction-like text (exact REVIEW_FOLLOWUP F4 bypass).
seen = []


class Spy(t.Scripted):
    def complete(self, messages, **kw):
        seen.append(messages[1]["content"])
        return super().complete(messages, **kw)


r = t.investigate([t.admin_trigger()], model=Spy([t.call("get_host_context"),
                                                  t.call("get_process_tree", evidence_id="EV-0001"),
                                                  t.call("get_network_activity")], t.BENIGN),
                  hosts={t.HOST: HostContext(host=t.HOST, os=t.INJECTED_OS)})
state = json.loads(seen[-1].split("<STATE_JSON>\n", 1)[1].rsplit("\n</STATE_JSON>", 1)[0])
record("E  injected host context", "treated as flagged data; benign prevented",
       r.verdict != "benign" and state["host_context"][0]["injection_suspected"] is True,
       f"verdict={r.verdict} host_context requirement="
       f"{[q.reason for q in r.coverage.requirements if q.name == 'host_context']} "
       f"prompt flag={state['host_context'][0]['injection_suspected']}")

# F. Pre-alert noise + critical connection five seconds after the alert.
be = t.ListBackend(t._x07_like(), "T")
ctx = ToolContext(be, EvidenceStore("fixture"), be.alert, t.settings())
ctx.store.mark_trigger(ctx.store.add(be.events["T"], "seed").evidence_id)
kept = {}
for tool, args in (("get_related_events", {"evidence_id": "EV-0001"}), ("get_network_activity", {})):
    c, res = dispatch(ctx, 1, tool, args)
    kept[tool] = (c.outcome, c.result_count, any(e.source_ref == "C2" for e in res.evidence))
record("F  40 pre-alert connections + C2 at T+5s, cap 25", "post-alert connection retained",
       all(v[2] for v in kept.values()), f"{kept}")

# G. Legitimate administrative PowerShell with complete clean evidence.
r = t.investigate([t.admin_trigger(), t.conn("N", 2, "{p1}", t.PS, ip="10.40.1.20")])
record("G  clean admin PowerShell, complete collection", "benign remains possible",
       r.verdict == "benign" and r.status == "completed" and not unmet(r),
       f"verdict={r.verdict} status={r.status} requirements="
       f"{[(q.name, q.satisfied) for q in r.coverage.requirements]}")

print(f"\nFINAL GATE: {sum(results)}/{len(results)} cases met expectations")
sys.exit(0 if all(results) else 1)
