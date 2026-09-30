"""CLI failure signals and model-health checks must agree with real outcomes."""
import httpx
import pytest

from investigator.config import Settings
from investigator.llm.ollama import OllamaModel, OllamaError
from investigator.main import main


def model_with_response(payload, name="qwen2.5:7b-instruct"):
    client = httpx.Client(base_url="http://ollama.test", transport=httpx.MockTransport(
        lambda request: httpx.Response(200, json=payload)))
    return OllamaModel(Settings(ollama_model=name), client=client)


def test_health_requires_exact_model_tag():
    model = model_with_response({"models": [{"name": "qwen2.5:0.5b"}]})
    assert model.health()[0] is False


def test_health_resolves_implicit_latest():
    model = model_with_response({"models": [{"name": "qwen2.5:latest"}]}, "qwen2.5")
    assert model.health() == (True, "ok")


@pytest.mark.parametrize("payload", [[], {}, {"models": None}, {"models": [None]}])
def test_health_malformed_response_fails_cleanly(payload):
    assert model_with_response(payload).health()[0] is False


@pytest.mark.parametrize("payload", [{}, [], {"message": {"content": ""}}, {"message": None}])
def test_chat_malformed_response_has_controlled_error(payload):
    with pytest.raises(OllamaError, match="invalid chat response|empty response"):
        model_with_response(payload).complete([])


def test_health_cli_reports_model_failure(monkeypatch, capsys):
    monkeypatch.setattr(OllamaModel, "health", lambda self: (False, "model missing"))
    assert main(["--llm", "ollama", "--backend", "fixture", "health"]) == 1
    assert "ollama: FAIL" in capsys.readouterr().out


@pytest.mark.parametrize("json_output", [False, True])
def test_evaluate_exit_code_reports_failure(monkeypatch, json_output):
    import investigator.evaluation.evaluator as evaluator
    summary = {"cases": 1, "passed": 0, "failed": 1, "pass_rate": 0,
               "mean_evidence_recall": 0, "total_invalid_evidence_refs": 0,
               "total_forbidden_claims": 0}
    monkeypatch.setattr(evaluator, "run_evaluation", lambda settings: {"summary": summary, "cases": []})
    args = ["--llm", "mock", "--backend", "fixture", "evaluate"]
    assert main(args + (["--json"] if json_output else [])) == 1


def test_empty_evaluation_is_not_a_success(monkeypatch):
    import investigator.evaluation.evaluator as evaluator
    monkeypatch.setattr(evaluator, "run_evaluation", lambda settings: {
        "summary": {"cases": 0, "failed": 0}, "cases": []})
    assert main(["--llm", "mock", "--backend", "fixture", "evaluate", "--json"]) == 1


def test_zero_step_override_is_validated():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        main(["--max-steps", "0", "--llm", "mock", "list"])
