"""Live Ollama integration (opt-in). Verifies real model/server behaviour that
mocks cannot: tag availability, structured output, context accounting,
timeouts and an end-to-end fixture investigation. Assertions are about the
harness contract, never about the model's verdict quality (see `benchmark`)."""

import pytest

from investigator.agent import InvestigationAgent, _parse, build_agent
from investigator.errors import ClassifiedError
from investigator.llm.ollama import OllamaModel
from investigator.main import ollama_structured_probe
from investigator.models import AgentDecision

pytestmark = pytest.mark.integration


def test_configured_model_is_pulled(ollama_settings):
    ok, msg = OllamaModel(ollama_settings).health()
    assert ok, msg


def test_missing_model_tag_is_reported_not_accepted(ollama_settings):
    s = ollama_settings.model_copy(update={"ollama_model": "soci-nonexistent-model:0b"})
    ok, msg = OllamaModel(s).health()
    assert not ok and "not pulled" in msg


def test_unknown_model_chat_is_classified(ollama_settings):
    s = ollama_settings.model_copy(update={"ollama_model": "soci-nonexistent-model:0b"})
    with pytest.raises(ClassifiedError) as err:
        OllamaModel(s).complete([{"role": "user", "content": "hi"}])
    assert err.value.kind in {"not_found", "invalid_response"}


def test_structured_output_round_trip(ollama_settings):
    row = ollama_structured_probe(ollama_settings)
    assert row["ok"], row


def test_timeout_is_classified(ollama_settings):
    s = ollama_settings.model_copy(update={"ollama_timeout": 0.001})
    with pytest.raises(ClassifiedError) as err:
        OllamaModel(s).complete([{"role": "user", "content": "Write 500 words."}])
    assert err.value.kind == "timeout"


def test_small_context_budget_is_respected_and_accounted(ollama_settings):
    """With a deliberately small num_ctx the harness must compact prompts itself;
    Ollama's reported prompt tokens must not hit the context ceiling."""
    s = ollama_settings.model_copy(update={"ollama_num_ctx": 4096, "ollama_num_predict": 768, "max_steps": 3})
    agent, backend = build_agent(s)
    report = agent.investigate(backend.get_alert("INC-004"))
    for x in report.trace.llm_exchanges:
        if x.prompt_tokens is not None:
            assert x.prompt_tokens < s.ollama_num_ctx, x.prompt_tokens
        assert not x.context_overflow_suspected
    # The chars-per-token assumption held for this model/tokenizer:
    measured = [x.prompt_chars / x.prompt_tokens for x in report.trace.llm_exchanges if x.prompt_tokens]
    assert measured and min(measured) >= s.prompt_chars_per_token * 0.8, measured


def test_end_to_end_fixture_investigation_contract(ollama_settings):
    agent, backend = build_agent(ollama_settings)
    report = agent.investigate(backend.get_alert("INC-001"))
    ids = {e.evidence_id for e in report.evidence}
    assert report.evidence, "the trigger must at least be retrieved"
    for f in report.findings:
        assert set(f.evidence_ids) <= ids
    for h in report.hypotheses:
        assert set(h.evidence_ids) <= ids
    assert report.status in {"completed", "incomplete", "failed"}
    assert all(x.prompt_sha256 for x in report.trace.llm_exchanges)
    print(f"\nlive INC-001: verdict={report.verdict} status={report.status} "
          f"repairs={report.model_output_repairs} tools={len(report.trace.tool_calls)}")
