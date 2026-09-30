"""Real Qwen2.5 token counts of the v0.3.1 prompts (decide, final_report, revision).

Usage: python docs/validation/v0.3.1/probe_contract_tokens.py <repo-root> <qwen tokenizer.json>

Runs every packaged fixture case and every independent-benchmark case through the real
agent at num_ctx 16384 and 8192, with (a) the mock analyst and (b) the scripted
"observed qwen" model from tests/test_reasoning_contract.py (forces the revision
round). Every prompt the agent sends is tokenized with the Qwen2.5 tokenizer
(+5 tokens/message for the chat template). Reports the maximum per phase and whether
prompt + num_predict fits num_ctx.
"""
import sys
from collections import defaultdict

root = sys.argv[1]
sys.path.insert(0, root)
sys.path.insert(0, root + "/tests")
from tokenizers import Tokenizer  # noqa: E402

from investigator.agent import InvestigationAgent  # noqa: E402
from investigator.backends.fixture import FixtureBackend  # noqa: E402
from investigator.config import PACKAGED_BENCHMARKS, PACKAGED_CASES, load_settings  # noqa: E402
from investigator.llm.mock import MockInvestigatorModel  # noqa: E402
from test_reasoning_contract import FeedbackFollower, ObservedQwen, state_of  # noqa: E402

tok = Tokenizer.from_file(sys.argv[2])


def ntok(messages):
    return sum(len(tok.encode(m["content"]).ids) + 5 for m in messages) + 3


class Recorder:
    def __init__(self, inner):
        self.inner, self.name, self.seen = inner, inner.name, []

    def complete(self, messages, **kw):
        self.seen.append((state_of(messages)["phase"], messages))
        return self.inner.complete(messages, **kw)


fail = False
for num_ctx in (16384, 8192):
    s = load_settings(llm="mock", backend="fixture", ollama_num_ctx=num_ctx)
    worst = defaultdict(lambda: (0, 0, ""))
    statuses = defaultdict(int)
    for suite in (PACKAGED_CASES, PACKAGED_BENCHMARKS / "independent"):
        be = FixtureBackend(suite)
        for alert in be.list_alerts():
            for label, factory in (("mock", lambda a: MockInvestigatorModel()), ("observed-qwen", ObservedQwen),
                                   ("feedback-follower", FeedbackFollower)):
                rec = Recorder(factory(alert.alert_id))
                r = InvestigationAgent(be, rec, s).investigate(alert)
                statuses[(label, r.status)] += 1
                for phase, msgs in rec.seen:
                    t, c = ntok(msgs), sum(len(m["content"]) for m in msgs)
                    if t > worst[phase][0]:
                        worst[phase] = (t, c, f"{alert.alert_id} ({label})")
    print(f"== num_ctx {num_ctx}  num_predict {s.ollama_num_predict}  prompt budget {s.ollama_num_ctx - s.ollama_num_predict}")
    for phase, (t, c, where) in sorted(worst.items()):
        ok = t + s.ollama_num_predict <= num_ctx
        fail |= not ok
        print(f"   {phase:<13} max tokens={t:>6,} chars={c:>7,} chars/token={c / t:4.2f}  "
              f"prompt+num_predict={t + s.ollama_num_predict:>6,} / {num_ctx:,} {'ok' if ok else 'OVERFLOW'}  [{where}]")
    print("   run statuses:", dict(statuses))
sys.exit(1 if fail else 0)
