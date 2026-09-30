"""Failure-mode contract tests (always run, no live services).

Each simulated failure goes through the real WazuhBackend/OllamaModel HTTP code
and must surface as a stable error kind with no raw response text. The same
kinds are asserted against live services in tests/integration/ when enabled.
These tests verify our classification logic, NOT live service behaviour.
"""

from __future__ import annotations

import ssl
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from investigator.agent import InvestigationAgent
from investigator.backends.base import EventQuery
from investigator.backends.wazuh import WazuhBackend
from investigator.config import load_settings
from investigator.errors import ClassifiedError, classify_exception
from investigator.llm.mock import MockInvestigatorModel
from investigator.llm.ollama import OllamaModel

T0 = datetime(2026, 9, 29, 11, 0, tzinfo=timezone.utc)
Q = EventQuery(start=T0 - timedelta(hours=1), end=T0, host="H", limit=5)
SECRET_BODY = '{"error":{"type":"%s","reason":"user=admin password=hunter2 index=secret-idx"}}'


def wazuh(handler, **kw):
    s = load_settings(backend="wazuh", wazuh_indexer_url="https://idx:9200", wazuh_indexer_user="u",
                      wazuh_indexer_password="p", **kw)
    return WazuhBackend(s, transport=httpx.MockTransport(handler))


@pytest.mark.parametrize("status,etype,kind", [
    (401, "security_exception", "auth"),
    (403, "security_exception", "permission"),
    (404, "index_not_found_exception", "index_missing"),
    (404, "resource_not_found", "not_found"),
    (400, "query_shard_exception", "mapping"),
    (400, "search_phase_execution_exception", "mapping"),
    (429, "es_rejected_execution_exception", "rate_limited"),
    (503, "cluster_block_exception", "unavailable"),
])
def test_http_failures_are_classified_without_body_text(status, etype, kind):
    wb = wazuh(lambda r: httpx.Response(status, text=SECRET_BODY % etype))
    with pytest.raises(ClassifiedError) as err:
        wb.search_events(Q)
    assert err.value.kind == kind and err.value.status_code == status
    assert "hunter2" not in str(err.value) and "secret-idx" not in str(err.value)


def test_timeout_is_classified():
    def handler(r):
        raise httpx.ReadTimeout("read timed out", request=r)
    with pytest.raises(ClassifiedError) as err:
        wazuh(handler).search_events(Q)
    assert err.value.kind == "timeout"


def test_tls_verification_failure_is_classified():
    def handler(r):
        try:
            raise ssl.SSLCertVerificationError("certificate verify failed: self-signed certificate")
        except ssl.SSLError as inner:
            raise httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED]", request=r) from inner
    with pytest.raises(ClassifiedError) as err:
        wazuh(handler).search_events(Q)
    assert err.value.kind == "tls"


def test_connection_refused_is_unavailable():
    def handler(r):
        raise httpx.ConnectError("[Errno 111] Connection refused", request=r)
    with pytest.raises(ClassifiedError) as err:
        wazuh(handler).search_events(Q)
    assert err.value.kind == "unavailable"


def test_shard_failure_and_timed_out_search_are_partial_results():
    for body in ({"timed_out": True, "_shards": {"total": 3, "failed": 0}, "hits": {"hits": []}},
                 {"timed_out": False, "_shards": {"total": 3, "failed": 1}, "hits": {"hits": []}}):
        with pytest.raises(ClassifiedError) as err:
            wazuh(lambda r, b=body: httpx.Response(200, json=b)).search_events(Q)
        assert err.value.kind == "partial_results"


def test_non_json_and_unmappable_records_are_invalid_response():
    with pytest.raises(ClassifiedError) as err:
        wazuh(lambda r: httpx.Response(200, text="<html>proxy error</html>")).search_events(Q)
    assert err.value.kind == "invalid_response"
    bad_hit = {"_index": "i", "_id": "1", "_source": {"timestamp": "yesterday-ish", "agent": {"name": "H"},
                                                       "data": {"win": {"system": [], "eventdata": {}}}}}
    wb = wazuh(lambda r: httpx.Response(200, json={"_shards": {"total": 1, "failed": 0}, "hits": {"hits": [bad_hit]}}))
    with pytest.raises(ClassifiedError) as err:
        wb.search_events(Q)
    assert err.value.kind == "invalid_response"


def test_backend_failure_propagates_to_report_coverage():
    """End to end: a permission failure is visible in coverage, status and verification steps."""
    good = {"_index": "wazuh-alerts-4.x-2026.09.29", "_id": "a1", "_source": {
        "timestamp": T0.isoformat(), "agent": {"name": "H"}, "rule": {"level": 12, "description": "enc ps"},
        "data": {"win": {"system": {"providerName": "Microsoft-Windows-Sysmon", "eventID": "1"},
                         "eventdata": {"image": "C:/x/powershell.exe", "processGuid": "{g}",
                                       "commandLine": "powershell -enc QQBBAEEAQQBBAEEAQQBBAEEA"}}}}}

    def handler(r):
        body = r.content.decode()
        if '"ids"' in body:  # trigger lookup succeeds
            return httpx.Response(200, json={"_shards": {"total": 1, "failed": 0}, "hits": {"hits": [good]}})
        return httpx.Response(403, text=SECRET_BODY % "security_exception")

    from investigator.backends.wazuh import _event_ref

    wb = wazuh(handler)
    alert = wb.get_alert(_event_ref(good))
    assert alert is not None
    report = InvestigationAgent(wb, MockInvestigatorModel(), load_settings(llm="mock")).investigate(alert)
    assert report.status == "incomplete"
    assert report.coverage.failed >= 1
    assert {i.error_kind for i in report.coverage.items if i.outcome == "failed"} == {"permission"}
    assert any("permission" in r for r in report.status_reasons)
    assert "hunter2" not in report.model_dump_json()
    assert any("rule-matched" in c for c in report.coverage.backend_caveats)


def test_probe_reports_each_check_without_raising():
    def handler(r):
        if "archives" in r.url.path:
            return httpx.Response(404, text=SECRET_BODY % "index_not_found_exception")
        return httpx.Response(200, json={"_shards": {"total": 1, "failed": 0}, "hits": {"hits": [
            {"_index": "i", "_id": "1", "_source": {"timestamp": T0.isoformat(), "agent": {"name": "H"},
                                                     "data": {"win": {"eventdata": {"image": "x"}}}}}]}})
    rows = wazuh(handler, wazuh_events_index="wazuh-archives-*").probe()
    by = {r["check"]: r for r in rows}
    assert by["alerts index reachable + auth"]["ok"]
    assert not by["events (archives) index present"]["ok"]
    assert by["events (archives) index present"]["kind"] == "index_missing"


@pytest.mark.parametrize("status,kind", [(404, "not_found"), (500, "unavailable"), (401, "auth")])
def test_ollama_http_failures_are_classified(status, kind):
    m = OllamaModel(load_settings(llm="ollama"), client=httpx.Client(
        base_url="http://o", transport=httpx.MockTransport(lambda r: httpx.Response(status, text="model 'x' not found"))))
    with pytest.raises(ClassifiedError) as err:
        m.complete([{"role": "user", "content": "x"}])
    assert err.value.kind == kind


def test_classifier_never_returns_raw_text():
    exc = RuntimeError("password=hunter2 at https://user:pw@host")
    c = classify_exception(exc)
    assert c.kind == "internal" and "hunter2" not in c.safe_message and "pw@" not in c.safe_message
