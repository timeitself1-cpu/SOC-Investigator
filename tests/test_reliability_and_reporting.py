"""Cancellation, time budget, durable history/restart recovery, graceful shutdown,
structured-output handling, collection coverage and the fact/hypothesis split."""

from __future__ import annotations

import json
import threading
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from investigator.agent import InvestigationAgent, build_agent
from investigator.app import create_app
from investigator.config import load_settings
from investigator.llm.base import LLMResponse
from investigator.llm.mock import MockInvestigatorModel
from investigator.llm.ollama import OllamaModel
from investigator.models import ReportDraft
from investigator.service import InvestigationService


def settings(**kw):
    return load_settings(llm="mock", backend="fixture", **kw)


# --- cancellation / time budget ----------------------------------------------

class CancellingModel(MockInvestigatorModel):
    """Behaves like the mock but sets the cancel flag after the second decision."""

    def __init__(self, event):
        self.event, self.n = event, 0

    def complete(self, messages, **kw):
        self.n += 1
        if self.n == 2:
            self.event.set()
        return super().complete(messages, **kw)


def test_cancelled_investigation_keeps_evidence_and_makes_no_assessment(backend):
    event = threading.Event()
    agent = InvestigationAgent(backend, CancellingModel(event), settings())
    report = agent.investigate(backend.get_alert("INC-001"), cancel_event=event)
    assert report.status == "cancelled"
    assert report.verdict == "insufficient_evidence" and report.confidence == 0.0
    assert report.evidence  # evidence gathered before cancellation is preserved
    assert not any(x.purpose == "final_report" for x in report.trace.llm_exchanges)
    assert report.model_narrative is None


def test_time_budget_stops_gathering_and_is_reported(backend, monkeypatch):
    import investigator.agent as agent_mod
    clock = iter(range(0, 10_000, 400))  # every check advances 400 s
    monkeypatch.setattr(agent_mod.time, "monotonic", lambda: next(clock))
    agent, _ = build_agent(settings(max_investigation_seconds=900))
    report = agent.investigate(backend.get_alert("INC-001"))
    assert report.status == "incomplete"
    assert any("time budget" in r for r in report.status_reasons)
    assert any("time budget" in u.lower() for u in report.coverage.unknowns)


# --- durable history / restart recovery / shutdown ---------------------------

def _wait(service, run, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and run.status == "running":
        time.sleep(0.01)
    return run


def test_completed_runs_survive_restart_and_reports_load_lazily(tmp_path):
    s = settings(reports_dir=tmp_path / "reports")
    first = InvestigationService(s)
    run = _wait(first, first.start("INC-001"))
    assert run.status == "completed"
    journal = json.loads((tmp_path / "reports" / "runs" / f"{run.run_id}.json").read_text())
    assert journal["status"] == "completed" and journal["verdict"] == run.verdict

    second = InvestigationService(s)  # simulated restart
    restored = second.get_run(run.run_id)
    assert restored is not None and restored.recovered and restored.status == "completed"
    assert restored._report is None  # not loaded until needed
    assert restored.report.investigation_id == run.report.investigation_id
    assert second.latest_run_for_alert("INC-001").run_id == run.run_id


def test_run_in_flight_at_crash_is_recorded_as_interrupted(tmp_path, monkeypatch):
    s = settings(reports_dir=tmp_path / "reports")
    first = InvestigationService(s)
    release = threading.Event()
    monkeypatch.setattr(first.agent, "investigate", lambda alert, **kw: release.wait(5) and None)
    run = first.start("INC-002")
    journal = tmp_path / "reports" / "runs" / f"{run.run_id}.json"
    assert json.loads(journal.read_text())["status"] == "running"
    # Process "crashes" here: second service starts from the on-disk journal.
    second = InvestigationService(s)
    restored = second.get_run(run.run_id)
    assert restored.status == "interrupted" and "stopped" in restored.error
    assert json.loads(journal.read_text())["status"] == "interrupted"
    release.set()


def test_reports_from_before_journals_are_restored(tmp_path):
    s = settings(reports_dir=tmp_path / "reports")
    svc = InvestigationService(s)
    run = _wait(svc, svc.start("INC-003"))
    (tmp_path / "reports" / "runs" / f"{run.run_id}.json").unlink()  # legacy: report only
    restored = InvestigationService(s).get_run(run.run_id)
    assert restored and restored.status == "completed" and restored.report is not None


def test_corrupt_journal_is_skipped_with_a_visible_note(tmp_path):
    runs = tmp_path / "reports" / "runs"
    runs.mkdir(parents=True)
    (runs / "run-deadbeef.json").write_text("{not json")
    svc = InvestigationService(settings(reports_dir=tmp_path / "reports"))
    assert any("run-deadbeef.json" in n for n in svc.recovery_notes)


def test_shutdown_cancels_cooperative_runs(tmp_path, monkeypatch):
    svc = InvestigationService(settings(reports_dir=tmp_path / "reports"))
    started = threading.Event()
    real = svc.agent.investigate

    def slow(alert, activity_hook=None, cancel_event=None):
        started.set()
        cancel_event.wait(5)  # blocks until shutdown cancels
        return real(alert, activity_hook=activity_hook, cancel_event=cancel_event)

    monkeypatch.setattr(svc.agent, "investigate", slow)
    run = svc.start("INC-001")
    assert started.wait(2)
    assert svc.shutdown(grace_seconds=5) == []
    assert run.status == "cancelled" and run.report.status == "cancelled"


def test_shutdown_records_uncooperative_runs_as_interrupted(tmp_path, monkeypatch):
    svc = InvestigationService(settings(reports_dir=tmp_path / "reports"))
    release = threading.Event()
    monkeypatch.setattr(svc.agent, "investigate", lambda alert, **kw: release.wait(5) and None)
    run = svc.start("INC-001")
    assert svc.shutdown(grace_seconds=0.05) == [run.run_id]
    data = json.loads((tmp_path / "reports" / "runs" / f"{run.run_id}.json").read_text())
    assert data["status"] == "interrupted"
    with pytest.raises(Exception):
        svc.start("INC-002")  # no new work while closing
    release.set()


def test_cancel_route_and_history_page(tmp_path, monkeypatch):
    app = create_app(settings(reports_dir=tmp_path / "reports"))
    client = TestClient(app, base_url="http://localhost")
    client.get("/healthz")
    svc = app.state.service
    release = threading.Event()

    def blocked(alert, activity_hook=None, cancel_event=None):
        cancel_event.wait(5)
        release.set()
        return MockFinishing().report(svc, alert, cancel_event)

    monkeypatch.setattr(svc.agent, "investigate", blocked)
    r = client.post("/investigate/INC-001", follow_redirects=False)
    run_id = r.headers["location"].rsplit("/", 1)[-1]
    assert client.post(f"/run/{run_id}/cancel", follow_redirects=False).status_code == 303
    assert release.wait(5)
    _wait(svc, svc.get_run(run_id))
    assert client.post(f"/run/{run_id}/cancel").status_code == 409
    assert client.post("/run/run-nope/cancel").status_code == 404
    page = client.get("/history").text
    assert run_id in page and "cancelled" in page


class MockFinishing:
    def report(self, svc, alert, cancel_event):
        agent = InvestigationAgent(svc.backend, MockInvestigatorModel(), svc.settings)
        return agent.investigate(alert, cancel_event=cancel_event)


def test_queue_degrades_gracefully_when_alert_source_fails(tmp_path, monkeypatch):
    app = create_app(settings(reports_dir=tmp_path / "reports"))
    client = TestClient(app, base_url="http://localhost")
    client.get("/healthz")

    def down():
        raise httpx.ConnectError("connection refused: https://u:p@idx")

    monkeypatch.setattr(app.state.service, "list_alerts", down)
    page = client.get("/")
    assert page.status_code == 200
    assert "could not be queried (unavailable)" in page.text and "u:p@" not in page.text


# --- structured output / Ollama ------------------------------------------------

def test_ollama_payload_bounds_output_and_sends_schema():
    s = load_settings(llm="ollama", ollama_num_predict=777)
    model = OllamaModel(s, client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200))))
    schema = ReportDraft.model_json_schema()
    payload = model.build_payload([{"role": "user", "content": "x"}], schema=schema)
    assert payload["options"]["num_predict"] == 777
    assert payload["format"] == schema
    s2 = load_settings(llm="ollama", ollama_structured_output=False)
    assert OllamaModel(s2).build_payload([], schema=schema)["format"] == "json"


def test_ollama_errors_are_classified():
    def handler(req):
        raise httpx.ReadTimeout("slow", request=req)
    model = OllamaModel(load_settings(llm="ollama"), client=httpx.Client(
        base_url="http://o", transport=httpx.MockTransport(handler)))
    with pytest.raises(Exception) as err:
        model.complete([{"role": "user", "content": "x"}])
    assert getattr(err.value, "kind", None) == "timeout"


class TruncatingModel(MockInvestigatorModel):
    """First final-report answer is cut off at num_predict; the repair succeeds."""
    supports_schema = True

    def __init__(self):
        self.seen_schema = []
        self.truncated_once = False

    def complete(self, messages, *, temperature=None, schema=None):
        self.seen_schema.append(schema is not None)
        resp = super().complete(messages, temperature=temperature)
        if '"phase": "final_report"' in messages[1]["content"] and not self.truncated_once:
            self.truncated_once = True
            return LLMResponse(text=resp.text[:40], model=self.name, meta={"done_reason": "length"})
        return resp


def test_output_cut_off_at_num_predict_is_rejected_and_repaired_visibly(backend):
    model = TruncatingModel()
    report = InvestigationAgent(backend, model, settings()).investigate(backend.get_alert("INC-001"))
    assert all(model.seen_schema)  # schema passed when the model supports it
    cut = [x for x in report.trace.llm_exchanges if x.done_reason == "length"]
    assert cut and not cut[0].parsed_ok and "cut off" in cut[0].error
    assert report.model_output_repairs >= 1
    assert report.status == "completed"


# --- coverage and fact/hypothesis separation -----------------------------------

def test_failed_collection_is_incomplete_with_reasons_and_verification(backend, monkeypatch):
    agent, be = build_agent(settings())
    real = be.search_events

    def flaky(q):
        if q.category == "network":
            raise httpx.ReadTimeout("t")
        return real(q)

    monkeypatch.setattr(be, "search_events", flaky)
    report = agent.investigate(be.get_alert("INC-001"))
    assert report.status == "incomplete"
    assert report.coverage.failed >= 1 and not report.coverage.complete
    assert any("timeout" in r for r in report.status_reasons)
    assert any(v.step.startswith("Re-run or query manually") for v in report.verification_steps)


def test_rejected_model_request_is_disclosed_but_not_a_collection_failure(backend):
    class OneBadThenMock(MockInvestigatorModel):
        def __init__(self):
            self.first = True

        def complete(self, messages, **kw):
            if self.first and '"phase": "decide"' in messages[1]["content"]:
                self.first = False
                return LLMResponse(text='{"action":"call_tool","tool":"get_related_events",'
                                        '"arguments":{"evidence_id":"EV-9999"}}', model=self.name)
            return super().complete(messages, **kw)

    report = InvestigationAgent(backend, OneBadThenMock(), settings()).investigate(backend.get_alert("INC-002"))
    assert report.coverage.rejected == 1 and report.coverage.failed == 0
    assert report.status == "completed"
    assert any("rejected before execution" in u for u in report.coverage.unknowns)


def test_facts_hypotheses_and_narrative_are_separated(backend):
    agent, _ = build_agent(settings())
    report = agent.investigate(backend.get_alert("INC-001"))
    ids = {e.evidence_id for e in report.evidence}
    assert report.observed_facts and all(f.evidence_id in ids for f in report.observed_facts)
    assert any(f.statement.startswith("Triggering event.") for f in report.observed_facts)
    assert report.hypotheses and all(set(h.evidence_ids) <= ids for h in report.hypotheses)
    kinds = {h.kind for h in report.hypotheses}
    assert kinds == {"claim", "attack_technique"}
    # The summary is application-generated; model prose is kept separately.
    assert report.summary.startswith("Assessment:")
    assert report.model_narrative and report.model_narrative not in report.summary
    assert report.verification_steps


def test_markdown_and_html_render_new_sections(backend, tmp_path):
    from investigator.report import report_to_markdown
    agent, _ = build_agent(settings())
    md = report_to_markdown(agent.investigate(backend.get_alert("INC-005")))
    for heading in ("## Observed facts", "## Hypotheses", "## Verification steps",
                    "## Model narrative (unverified)", "## Collection coverage", "## Audit disclosure"):
        assert heading in md
    app = create_app(settings(reports_dir=tmp_path / "r"))
    client = TestClient(app, base_url="http://localhost")
    run_id = client.post("/investigate/INC-005", follow_redirects=False).headers["location"].rsplit("/", 1)[-1]
    svc = app.state.service
    _wait(svc, svc.get_run(run_id))
    html = client.get(f"/report/{run_id}").text
    for marker in ('id="facts"', 'id="hypotheses"', 'id="verify"', 'id="coverage"', 'id="evidence-filters"',
                   'data-cited="yes"', "/static/report.js", "Rerun"):
        assert marker in html
    assert "script-src 'self'" in client.get(f"/report/{run_id}").headers["content-security-policy"]
