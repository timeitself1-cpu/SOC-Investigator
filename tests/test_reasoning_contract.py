"""v0.3.1 reasoning-contract repair.

The contract given to the model — claim definitions and eligibility, tool argument
schemas, step feedback, collection checklist, baseline collection and one bounded
validation-feedback revision — is checked here deterministically. Two scripted
models replay the behaviour observed with qwen2.5:7b-instruct in
docs/validation/v0.3/live_ollama_runs/: one ignores all feedback, the other reads
it. They prove the mechanics; whether a real model improves is measured with
`investigator --llm ollama acceptance` (see docs/validation/v0.3.1/).
"""

from __future__ import annotations

import json
import random
import threading

import pytest
from pydantic import ValidationError

from investigator import attack
from investigator.agent import InvestigationAgent, build_agent
from investigator.backends.fixture import FixtureBackend
from investigator.config import PACKAGED_BENCHMARKS, PACKAGED_CASES, load_settings
from investigator.evaluation.acceptance import check_acceptance, run_diagnostics
from investigator.evidence import EvidenceStore
from investigator.llm.base import LLMResponse
from investigator.llm.mock import MockInvestigatorModel
from investigator.report import _markdown_text, report_to_markdown
from investigator.tools import TOOLS, ToolContext, dispatch, tool_catalog


def settings(**kw):
    return load_settings(llm="mock", backend="fixture", **kw)


def state_of(messages) -> dict:
    return json.loads(messages[1]["content"].split("<STATE_JSON>\n", 1)[1].rsplit("\n</STATE_JSON>", 1)[0])


# --- scripted models replaying the observed qwen2.5:7b behaviour -----------------

OBSERVED_DECISIONS = {
    # INC-002 (run-20201d86…): tree, details, invented scope, logons, then the same tree 4x
    "INC-002": [{"tool": "get_process_tree", "arguments": {"evidence_id": "EV-0001"}},
                {"tool": "get_process_details", "arguments": {"evidence_id": "EV-0001"}},
                {"tool": "get_network_activity", "arguments": {"scope": "process"}},
                {"tool": "get_logon_activity", "arguments": {"user": "CORP\\svc-backup"}},
                *[{"tool": "get_process_tree", "arguments": {"process_guid": "{bbbb2222-0000-0000-0002-000000000001}"}}] * 4],
    # INC-004 (run-f8f901d0…): the same logon query 4x
    "INC-004": [{"tool": "get_logon_activity", "arguments": {}}] * 4,
}


def observed_draft(state) -> dict:
    """What qwen drafted: every finding tagged benign_administration."""
    ev = [e["evidence_id"] for e in state["evidence"]]
    return {"verdict": "suspicious", "confidence": 0.6, "summary": "Activity by an administrative account.",
            "findings": [{"title": "Activity observed", "description": "Administrative account activity.",
                          "severity": "medium", "evidence_ids": ev[:9], "claims": ["benign_administration"]}],
            "limitations": ["The evidence provided does not include network or process activity."]}


class ObservedQwen:
    """Replays the observed failure modes and ignores every piece of feedback."""
    name = "scripted-observed-qwen"

    def __init__(self, alert_id):
        self.plan = [dict(d, action="call_tool") for d in OBSERVED_DECISIONS.get(alert_id, [])]
        self.prompts = []

    def complete(self, messages, *, temperature=None, schema=None):
        self.prompts.append(messages)
        state = state_of(messages)
        if state["phase"] == "decide":
            d = self.plan.pop(0) if self.plan else {"action": "finish", "arguments": {}}
            return LLMResponse(json.dumps(d), self.name)
        return LLMResponse(json.dumps(observed_draft(state)), self.name)


class FeedbackFollower(ObservedQwen):
    """Starts with the same mistakes, but reads last_step_result / suggestions during
    gathering and the claim contract during the revision."""
    name = "scripted-feedback-follower"

    def complete(self, messages, *, temperature=None, schema=None):
        self.prompts.append(messages)
        state = state_of(messages)
        if state["phase"] == "decide":
            last = state["last_step_result"]
            if last.get("status") == "rejected":
                example = next(t["example"] for t in state["available_tools"] if t["name"] == last["tool"])
                d = {"action": "call_tool", "tool": last["tool"], "arguments": example}
            elif last.get("status") == "duplicate" or not self.plan:
                nxt = state["suggested_next_steps"]
                d = ({"action": "call_tool", "tool": nxt[0]["tool"], "arguments": nxt[0]["arguments"]} if nxt
                     else {"action": "finish", "arguments": {}})
                self.plan = []
            else:
                d = self.plan.pop(0)
            return LLMResponse(json.dumps(d), self.name)
        if state["phase"] == "final_report":
            # repeats the observed claim-tagging mistake, but follows the verdict
            # guidance: benign only when benign_administration is eligible
            draft = observed_draft(state)
            if any(e["claim"] == "benign_administration" for e in state["claim_contract"]["eligible"]):
                draft["verdict"] = "benign"
            return LLMResponse(json.dumps(draft), self.name)
        # revision: tag findings only with eligible claims, citing the listed evidence
        eligible = state["claim_contract"]["eligible"]
        findings = [{"title": e["label"][:80], "description": e["means"] if "means" in e else e["label"],
                     "severity": "high", "evidence_ids": e["cite_evidence_ids"], "claims": [e["claim"]],
                     "attack_techniques": [t["technique"] for t in state["attack_contract"]["eligible"]
                                           if set(t["cite_evidence_ids"]) <= set(e["cite_evidence_ids"])]}
                    for e in eligible if e["claim"] != "execution"]
        benign = any(e["claim"] == "benign_administration" for e in eligible)
        return LLMResponse(json.dumps({"verdict": "benign" if benign else "suspicious", "confidence": 0.6,
                                       "summary": "Behavior supported by the listed evidence.",
                                       "findings": findings}), self.name)


def run_fixture(alert_id, model, **kw):
    be = FixtureBackend(PACKAGED_CASES)
    agent = InvestigationAgent(be, model, settings(**kw))
    return agent.investigate(be.get_alert(alert_id))


# --- the observed failure, reproduced, stays safe --------------------------------

@pytest.mark.parametrize("alert_id", ["INC-002", "INC-004"])
def test_observed_qwen_behaviour_is_reproduced_and_stays_safe(alert_id):
    r = run_fixture(alert_id, ObservedQwen(alert_id))
    d = run_diagnostics(r)
    assert r.verdict == "insufficient_evidence"  # every claim rejected, as in the live run
    assert "benign_administration" in d["claims_proposed"] and d["claims_accepted"] == []
    assert d["loop_stop"] and r.revision and r.revision.performed and not r.revision.changed
    if alert_id == "INC-002":
        assert d["invalid_argument_rejections"] == 1
    assert not check_acceptance({alert_id: [d]})[0]["passed"]


@pytest.mark.parametrize("alert_id,claim", [("INC-002", "credential_theft"), ("INC-004", "brute_force")])
def test_feedback_following_model_reaches_the_supported_behavior(alert_id, claim):
    r = run_fixture(alert_id, FeedbackFollower(alert_id))
    d = run_diagnostics(r)
    assert r.verdict == "suspicious"  # behavior-based; likely_malicious is not required
    assert claim in d["claims_accepted"] and not d["loop_stop"]
    assert r.revision.performed and r.revision.changed and r.revision.first_validated_verdict == "insufficient_evidence"
    assert "benign_administration" not in d["claims_accepted"]
    results = {c["criterion"]: c["passed"] for c in check_acceptance({alert_id: [d]}) if c["alert"] == alert_id}
    assert all(results.values()), results


def test_feedback_follower_keeps_the_benign_management_job_benign():
    r = run_fixture("INC-005", FeedbackFollower("INC-005"))
    assert r.verdict == "benign" and all(q.satisfied for q in r.coverage.requirements)


# --- claim contract ------------------------------------------------------------------

def test_claim_contract_is_single_source_and_behavior_only():
    contract = {c["claim"]: c for c in attack.claim_contract()}
    assert set(contract) | set(attack.UNAVAILABLE_CLAIMS) == set(attack.CLAIM_RULES)
    for c, d in contract.items():
        assert d["requires"] == attack.CLAIM_RULES[c][1] and d["does_not_mean"] and d["means"]
    assert "administrator" in contract["benign_administration"]["does_not_mean"]
    assert "not" in contract["credential_theft"]["does_not_mean"] and "BEHAVIOR" in contract["credential_theft"]["label"]
    assert "POSSIBLE" in contract["account_compromise"]["label"]


def _evidence_pools():
    pools = []
    for root in (PACKAGED_CASES, PACKAGED_BENCHMARKS / "independent"):
        be = FixtureBackend(root)
        store = EvidenceStore("fixture", max_items=1000)
        for ev in be._events.values():
            store.add(ev, "t")
        pools.append(store.all())
    return pools


def test_eligibility_equals_validator_acceptance_on_random_evidence_sets():
    rng = random.Random(31)
    for pool in _evidence_pools():
        for _ in range(300):
            subset = rng.sample(pool, rng.randint(1, min(25, len(pool))))
            eligible = attack.claim_eligibility(subset)
            accepted = {c for c in attack.CLAIM_RULES if attack.claim_supported(c, subset)[0]}
            assert set(eligible) == accepted
            by_id = {e.evidence_id: e for e in subset}
            for c, ids in eligible.items():  # citing exactly the listed IDs passes validation
                assert attack.claim_supported(c, [by_id[i] for i in ids])[0], (c, ids)
            techniques = attack.technique_eligibility(subset)
            assert set(techniques) == {t for t in attack.CATALOG if attack.technique_supported(t, subset)[0]}
            for t, ids in techniques.items():
                assert attack.technique_supported(t, [by_id[i] for i in ids])[0], (t, ids)


def test_report_prompt_carries_the_contract_and_the_benign_admin_warning():
    model = ObservedQwen("INC-002")
    run_fixture("INC-002", model)
    final = state_of(next(m for m in model.prompts if state_of(m)["phase"] == "final_report"))
    eligible = {e["claim"]: e for e in final["claim_contract"]["eligible"]}
    assert "credential_theft" in eligible and eligible["credential_theft"]["cite_evidence_ids"]
    assert "benign_administration" not in eligible
    assert "administrator" in final["claim_contract"]["benign_administration_is_not_eligible"]["does_not_mean"]
    assert "T1003.001" in {t["technique"] for t in final["attack_contract"]["eligible"]}
    text = model.prompts[-1][1]["content"]
    assert "BEHAVIOR only" in text and "intent" in text and "outcome" in text


# --- tool contract --------------------------------------------------------------------

def test_tool_catalog_exposes_allowed_values_bounds_rules_and_valid_examples():
    s = settings()
    cat = {t["name"]: t for t in tool_catalog(s)}
    assert set(cat) == set(TOOLS)
    assert cat["get_network_activity"]["arguments"]["scope"] == "one of host|process_tree (default host)"
    assert cat["get_network_activity"]["arguments"]["window_minutes"] == f"integer 1-{s.max_window_minutes} (default {s.max_window_minutes})"
    assert "one of process|network" in cat["search_events"]["arguments"]["category"]
    assert "(REQUIRED)" in cat["get_related_events"]["arguments"]["evidence_id"]
    assert "descendants" in cat["get_process_tree"]["description"].lower()
    for name, spec in TOOLS.items():
        assert set(cat[name]["arguments"]) == set(spec.args_model.model_json_schema()["properties"])
        spec.args_model.model_validate(spec.example)  # every example is a valid call


def test_every_example_call_executes_on_a_real_case():
    agent, be = build_agent(settings())
    alert = be.get_alert("INC-001")
    ctx = ToolContext(be, EvidenceStore("fixture"), alert, settings())
    ctx.store.mark_trigger(ctx.store.add(be.get_event(alert.event_ref), "seed").evidence_id)
    for name, spec in TOOLS.items():
        call, _ = dispatch(ctx, 1, name, dict(spec.example))
        assert call.status == "ok", (name, call.error)


def test_invalid_scope_is_rejected_with_the_allowed_values():
    agent, be = build_agent(settings())
    ctx = ToolContext(be, EvidenceStore("fixture"), be.get_alert("INC-001"), settings())
    call, _ = dispatch(ctx, 1, "get_network_activity", {"scope": "process"})
    assert call.status == "rejected" and "'host' or 'process_tree'" in call.error


# --- step feedback, checklist, baseline ------------------------------------------------

def test_decide_state_has_feedback_answered_requests_checklist_and_suggestions():
    model = ObservedQwen("INC-002")
    run_fixture("INC-002", model)
    decides = [state_of(m) for m in model.prompts if state_of(m)["phase"] == "decide"]
    first = decides[0]
    assert "Already collected by the harness" in first["last_step_result"]["note"]
    assert {a["tool"] for a in first["answered_requests"]} >= {"get_event", "get_host_context", "get_process_tree"}
    assert first["collection_checklist"]["process_tree"]["status"] == "met"
    assert first["collection_checklist"]["network_activity"]["status"] == "not_yet_collected"
    assert any(sg["tool"] == "get_network_activity" for sg in first["suggested_next_steps"])
    # After the first request (a duplicate of the baseline tree) the next prompt says so explicitly:
    assert decides[1]["last_step_result"]["status"] == "duplicate"
    assert "Skipped: identical to" in decides[1]["last_step_result"]["message"]
    # After the invented scope value, the rejection and the allowed values are shown:
    rejected = next(d["last_step_result"] for d in decides if d["last_step_result"].get("status") == "rejected")
    assert "'host' or 'process_tree'" in rejected["message"]
    assert "claim_contract" not in first and "claim_vocabulary" not in first


def test_auth_alert_suggestions_and_checklist():
    model = ObservedQwen("INC-004")
    run_fixture("INC-004", model)
    first = state_of(model.prompts[0])
    assert [s["tool"] for s in first["suggested_next_steps"]] == ["get_logon_activity", "get_network_activity"]
    assert first["collection_checklist"]["process_tree"]["status"] == "cannot_be_established"
    assert first["collection_checklist"]["host_context"]["status"] == "met"


class HostContextDown(FixtureBackend):
    def get_host_context(self, host):
        raise RuntimeError("asset service unavailable")


def test_baseline_failure_is_a_visible_failed_collection():
    be = HostContextDown(PACKAGED_CASES)
    r = InvestigationAgent(be, MockInvestigatorModel(), settings()).investigate(be.get_alert("INC-005"))
    base = [c for c in r.trace.tool_calls if c.initiator == "system" and c.tool == "get_host_context"]
    assert base and base[0].outcome == "failed"
    assert r.status == "incomplete" and r.verdict != "benign"
    assert any(e.startswith("collection: baseline get_host_context") for e in r.trace.errors)


def test_baseline_can_be_disabled():
    r = run_fixture("INC-005", MockInvestigatorModel(), baseline_collection=False)
    assert not any(c.initiator == "system" and c.tool != "get_event" for c in r.trace.tool_calls)


# --- revision round --------------------------------------------------------------------

def test_exactly_one_revision_and_it_can_be_disabled():
    r = run_fixture("INC-002", ObservedQwen("INC-002"))
    assert sum(x.purpose == "revision" for x in r.trace.llm_exchanges) == 1
    off = run_fixture("INC-002", ObservedQwen("INC-002"), validation_revision=False)
    assert not any(x.purpose == "revision" for x in off.trace.llm_exchanges) and off.revision is None


def test_revision_feedback_contains_only_application_text():
    model = FeedbackFollower("INC-002")
    run_fixture("INC-002", model)
    revision = next(m for m in model.prompts if state_of(m)["phase"] == "revision")
    feedback = json.dumps(state_of(revision)["validation_of_your_draft"])
    assert "comsvcs" not in feedback and "MiniDump" not in feedback and "lsass.dmp" not in feedback
    assert "rejected claim" in feedback and "benign_administration" in feedback
    findings = state_of(revision)["validation_of_your_draft"]["findings"]
    assert findings and all("benign_administration" in f["claims_rejected"] for f in findings)


def test_a_rejected_claim_next_to_an_accepted_one_still_triggers_the_revision():
    """A finding keeps one supported claim but loses another: that loss is fed back."""
    class MixedClaims(ObservedQwen):
        def complete(self, messages, **kw):
            state = state_of(messages)
            if state["phase"] in ("final_report", "revision"):
                self.prompts.append(messages)
                bf = next(e for e in state["claim_contract"]["eligible"] if e["claim"] == "brute_force")
                claims = ["brute_force"] if state["phase"] == "revision" else ["brute_force", "benign_administration"]
                return LLMResponse(json.dumps({
                    "verdict": "suspicious", "confidence": 0.6, "summary": "Repeated failures then success.",
                    "findings": [{"title": "Failures then success", "description": "Authentication pattern.",
                                  "severity": "high", "evidence_ids": bf["cite_evidence_ids"],
                                  "claims": claims}]}), self.name)
            return super().complete(messages, **kw)
    model = MixedClaims("INC-004")
    r = run_fixture("INC-004", model)
    assert r.revision and r.revision.performed
    assert "benign_administration" in r.revision.first_rejected_claims
    assert "brute_force" in r.revision.first_accepted_claims
    assert r.verdict == "suspicious" and not any(f.rejected_claims for f in r.findings)


class BenignReviser(ObservedQwen):
    """First draft has a rejected claim; the revision proposes benign."""
    def complete(self, messages, *, temperature=None, schema=None):
        state = state_of(messages)
        if state["phase"] == "revision":
            ids = [e["evidence_id"] for e in state["evidence"]]
            return LLMResponse(json.dumps({"verdict": "benign", "confidence": 0.9, "summary": "Admin.",
                                           "findings": [{"title": "Admin", "description": "d", "evidence_ids": ids,
                                                         "claims": ["benign_administration", "execution"]}]}),
                               self.name)
        return super().complete(messages, temperature=temperature, schema=schema)


@pytest.mark.parametrize("alert_id", ["INC-001", "INC-002", "INC-003", "INC-004"])
def test_revision_cannot_obtain_benign(alert_id):
    r = run_fixture(alert_id, BenignReviser(alert_id))
    assert r.revision and r.revision.performed and r.verdict != "benign"


def test_cancellation_during_revision_ends_cancelled():
    cancel = threading.Event()

    class CancelInRevision(ObservedQwen):
        def complete(self, messages, **kw):
            if state_of(messages)["phase"] == "revision":
                cancel.set()
            return super().complete(messages, **kw)
    be = FixtureBackend(PACKAGED_CASES)
    r = InvestigationAgent(be, CancelInRevision("INC-004"), settings()).investigate(
        be.get_alert("INC-004"), cancel_event=cancel)
    assert r.status == "cancelled" and r.verdict == "insufficient_evidence"


# --- exports ----------------------------------------------------------------------------

def test_markdown_escaping_keeps_quotes_readable():
    out = _markdown_text("Finding 'Process Access' \"x\" & <b> #1")
    assert "&#x27;" not in out and "&\\#" not in out and "'" in out and "&amp;" in out and "&lt;b&gt;" in out


def test_exports_show_draft_vs_accepted_revision_and_logon_category():
    r = run_fixture("INC-004", FeedbackFollower("INC-004"))
    md = report_to_markdown(r)
    assert "## Model draft vs. accepted" in md and "Validation-feedback revision" in md
    assert "benign\\_administration" in md and "intent and outcome are not verified" in md
    assert "authentication" in r.coverage.categories_queried


def test_revision_record_survives_json_roundtrip():
    from investigator.models import InvestigationReport
    r = run_fixture("INC-004", FeedbackFollower("INC-004"))
    again = InvestigationReport.model_validate_json(r.model_dump_json())
    assert again.revision.performed and again.revision.first_validation is not None
    with pytest.raises(ValidationError):
        InvestigationReport.model_validate({**json.loads(r.model_dump_json()), "revision": {"bogus": 1}})
