"""WazuhBackend: query construction, read-only guard, normalization — all with a
mocked HTTP transport. No live Wazuh required."""

import json
from datetime import datetime, timezone

import httpx
import pytest

from investigator.backends.base import EventQuery
from investigator.backends.wazuh import WazuhBackend, WazuhConfigError, WazuhSearchError
from investigator.config import load_settings


def _settings(**over):
    base = dict(backend="wazuh", wazuh_indexer_url="https://indexer:9200",
                wazuh_indexer_user="admin", wazuh_indexer_password="secret",
                wazuh_verify_tls=False)
    base.update(over)
    return load_settings(**base)


def test_requires_credentials():
    with pytest.raises(WazuhConfigError):
        WazuhBackend(load_settings(backend="wazuh"))


def test_build_query_filters_and_bounds():
    from datetime import datetime, timezone
    q = EventQuery(start=datetime(2026, 1, 1, tzinfo=timezone.utc),
                   end=datetime(2026, 1, 2, tzinfo=timezone.utc),
                   host="H1", category="network", process_guid="{g}", keyword="powershell", limit=10)
    body = WazuhBackend.build_query(q)
    assert body["size"] == 10
    filters = body["query"]["bool"]["filter"]
    assert any("range" in f and "timestamp" in f["range"] for f in filters)
    assert {"term": {"agent.name": "H1"}} in filters
    # network category maps to sysmon event id 3
    category_filter = WazuhBackend._category_filter("network")
    assert category_filter in filters
    assert category_filter["bool"]["should"][0]["bool"]["filter"] == [
        {"term": {"data.win.system.providerName": "Microsoft-Windows-Sysmon"}},
        {"terms": {"data.win.system.eventID": ["3"]}},
    ]
    assert body["query"]["bool"]["must"] == [{"match_phrase": {"full_log": "powershell"}}]


def test_repr_hides_credentials():
    b = WazuhBackend(_settings(), transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})))
    assert "secret" not in repr(b)


def test_read_only_guard_blocks_non_allowlisted_paths():
    b = WazuhBackend(_settings(), transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})))
    with pytest.raises(PermissionError):
        b._request("indexer", "DELETE", "/wazuh-alerts-*/_doc/1")
    with pytest.raises(PermissionError):
        b._request("indexer", "POST", "/wazuh-alerts-*/_update/1")


def test_search_events_normalizes_hits():
    sysmon_hit = {
        "_id": "abc123",
        "_source": {
            "timestamp": "2026-01-01T12:00:00.000Z",
            "agent": {"name": "H1"},
            "rule": {"id": "92052", "level": 12, "description": "encoded powershell"},
            "data": {"win": {
                "system": {"providerName": "Microsoft-Windows-Sysmon", "eventID": "1", "channel": "Sysmon"},
                "eventdata": {"image": "C:/Windows/powershell.exe",
                              "commandLine": "powershell -enc AAAA", "processGuid": "{g1}",
                              "parentImage": "C:/Office/WINWORD.EXE"},
            }},
        },
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/_search")
        return httpx.Response(200, json={"hits": {"hits": [sysmon_hit]}})

    b = WazuhBackend(_settings(), transport=httpx.MockTransport(handler))
    from datetime import datetime, timezone
    events = b.search_events(EventQuery(start=datetime(2026, 1, 1, tzinfo=timezone.utc),
                                        end=datetime(2026, 1, 2, tzinfo=timezone.utc), limit=10))
    assert len(events) == 1
    ev = events[0]
    assert ev.event_ref == "abc123"
    assert ev.category == "process"
    assert ev.image.endswith("powershell.exe")
    assert ev.parent_image.endswith("WINWORD.EXE")


def test_list_alerts_maps_severity():
    hit = {
        "_id": "a1",
        "_source": {"timestamp": "2026-01-01T12:00:00Z", "agent": {"name": "H1"},
                    "rule": {"id": "1", "level": 13, "description": "critical rule"},
                    "data": {"win": {"system": {"providerName": "x", "eventID": "1"}, "eventdata": {}}}},
    }
    b = WazuhBackend(_settings(), transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"hits": {"hits": [hit]}})))
    alerts = b.list_alerts()
    assert alerts[0].severity == "critical"


def _hit(index="wazuh-alerts-2026.01.01", doc_id="shared-id", host="H1"):
    return {"_index": index, "_id": doc_id, "_source": {
        "timestamp": "2026-01-01T12:00:00Z", "agent": {"name": host},
        "rule": {"id": "1", "description": "Test alert"},
    }}


def test_index_qualified_ids_keep_distinct_evidence_and_resolve_exact_index():
    from investigator.evidence import EvidenceStore

    hits = [_hit(), _hit("wazuh-alerts-2026.01.02", host="H2")]
    requests = []

    def handler(request):
        requests.append(request)
        selected = [hits[1]] if request.url.path == "/wazuh-alerts-2026.01.02/_search" else hits
        return httpx.Response(200, json={"hits": {"hits": selected}})

    b = WazuhBackend(_settings(), transport=httpx.MockTransport(handler))
    alerts = b.list_alerts()
    assert alerts[0].alert_id != alerts[1].alert_id
    assert "/" not in alerts[1].alert_id
    resolved = b.get_event(alerts[1].event_ref)
    assert resolved.host == "H2"
    assert requests[-1].url.path == "/wazuh-alerts-2026.01.02/_search"
    assert json.loads(requests[-1].content)["query"]["ids"]["values"] == ["shared-id"]
    store = EvidenceStore("wazuh")
    assert store.add(b._to_event(hits[0]), "first").evidence_id != store.add(resolved, "second").evidence_id
    with pytest.raises(WazuhSearchError, match="Ambiguous"):
        b.get_alert("shared-id")


def test_qualified_reference_cannot_escape_configured_index_scope():
    b = WazuhBackend(_settings(), transport=httpx.MockTransport(lambda r: pytest.fail("No request expected")))
    outside = b._to_event(_hit("private-secrets"))
    with pytest.raises(ValueError, match="outside configured"):
        b.get_event(outside.event_ref)
    with pytest.raises(ValueError, match="invalid Wazuh"):
        b.get_event("wz1~!!~broken")


@pytest.mark.parametrize("metadata", [
    {"timed_out": True}, {"_shards": {"failed": 1}},
])
def test_partial_search_is_an_error_not_empty_telemetry(metadata):
    def handler(request):
        assert request.url.params["allow_partial_search_results"] == "false"
        return httpx.Response(200, json={**metadata, "hits": {"hits": []}})

    b = WazuhBackend(_settings(), transport=httpx.MockTransport(handler))
    with pytest.raises(WazuhSearchError, match="timed out or failed"):
        b.list_alerts()


def test_malformed_search_response_is_not_no_results():
    b = WazuhBackend(_settings(), transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})))
    with pytest.raises(WazuhSearchError, match="invalid search response"):
        b.list_alerts()


def test_other_category_excludes_recognized_provider_and_event_pairs():
    query = EventQuery(start=datetime(2026, 1, 1, tzinfo=timezone.utc),
                       end=datetime(2026, 1, 2, tzinfo=timezone.utc), category="other")
    category = WazuhBackend.build_query(query)["query"]["bool"]["filter"][-1]
    exclusions = category["bool"]["must_not"]
    assert len(exclusions) == 2
    assert {"terms": {"data.win.system.eventID": ["1", "3", "10", "11", "12", "13", "14", "22"]}} in exclusions[0]["bool"]["filter"]


def test_process_guid_queries_cover_decoder_capitalization_variants():
    query = EventQuery(start=datetime(2026, 1, 1, tzinfo=timezone.utc),
                       end=datetime(2026, 1, 2, tzinfo=timezone.utc), process_guid="{g}",
                       parent_process_guid="{parent}")
    filters = WazuhBackend.build_query(query)["query"]["bool"]["filter"]
    assert {"term": {"data.win.eventdata.sourceProcessGuid": "{g}"}} in filters[-2]["bool"]["should"]
    assert {"term": {"data.win.eventdata.parentProcessGUID": "{parent}"}} in filters[-1]["bool"]["should"]


def test_query_requires_ordered_aware_timestamps():
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="timezone"):
        EventQuery(start=datetime(2026, 1, 1), end=datetime(2026, 1, 2))
    with pytest.raises(ValidationError, match="must not be after"):
        EventQuery(start=datetime(2026, 1, 2, tzinfo=timezone.utc), end=datetime(2026, 1, 1, tzinfo=timezone.utc))
