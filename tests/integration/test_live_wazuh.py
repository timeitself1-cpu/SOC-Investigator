"""Live Wazuh integration (opt-in, read-only). Exercises auth, TLS, permissions,
missing archives, field mappings, timeouts and incomplete telemetry against a
real indexer. Nothing here writes to Wazuh: every request goes through the
backend's read-only allowlist."""

import os
from datetime import datetime, timedelta, timezone

import pytest

from investigator.agent import InvestigationAgent
from investigator.backends.base import EventQuery
from investigator.backends.wazuh import WazuhBackend
from investigator.errors import ClassifiedError
from investigator.llm.mock import MockInvestigatorModel
from pydantic import SecretStr

pytestmark = pytest.mark.integration


def _recent_query(**kw):
    now = datetime.now(timezone.utc)
    return EventQuery(start=now - timedelta(hours=24), end=now, limit=5, **kw)


def test_probe_alerts_index_and_auth(wazuh_settings):
    rows = WazuhBackend(wazuh_settings).probe(host=os.environ.get("SOCI_IT_WAZUH_HOST"))
    for r in rows:
        print(r)
    by = {r["check"]: r for r in rows}
    assert by["alerts index reachable + auth"]["ok"], by["alerts index reachable + auth"]


def test_wrong_password_is_auth(wazuh_settings):
    s = wazuh_settings.model_copy(update={"wazuh_indexer_password": SecretStr("definitely-wrong-password")})
    with pytest.raises(ClassifiedError) as err:
        WazuhBackend(s).search_events(_recent_query())
    assert err.value.kind == "auth"


def test_limited_user_is_permission(wazuh_settings):
    user, pw = os.environ.get("SOCI_IT_WAZUH_LIMITED_USER"), os.environ.get("SOCI_IT_WAZUH_LIMITED_PASSWORD")
    if not (user and pw):
        pytest.skip("SOCI_IT_WAZUH_LIMITED_USER/PASSWORD not set")
    s = wazuh_settings.model_copy(update={"wazuh_indexer_user": user, "wazuh_indexer_password": SecretStr(pw)})
    with pytest.raises(ClassifiedError) as err:
        WazuhBackend(s).search_events(_recent_query())
    assert err.value.kind == "permission"


def test_untrusted_certificate_is_tls(wazuh_settings):
    if os.environ.get("SOCI_IT_WAZUH_SELF_SIGNED") != "1":
        pytest.skip("SOCI_IT_WAZUH_SELF_SIGNED=1 not set")
    s = wazuh_settings.model_copy(update={"wazuh_verify_tls": True, "wazuh_ca_bundle": None})
    with pytest.raises(ClassifiedError) as err:
        WazuhBackend(s).search_events(_recent_query())
    assert err.value.kind == "tls"


def test_missing_archives_index_is_explicit(wazuh_settings):
    s = wazuh_settings.model_copy(update={"wazuh_events_index": "soci-it-nonexistent-archives-*"})
    with pytest.raises(ClassifiedError) as err:
        WazuhBackend(s).search_events(_recent_query())
    assert err.value.kind == "index_missing"


def test_timeout_is_classified(wazuh_settings):
    s = wazuh_settings.model_copy(update={"wazuh_timeout": 0.0005})
    with pytest.raises(ClassifiedError) as err:
        WazuhBackend(s).search_events(_recent_query())
    assert err.value.kind in {"timeout", "unavailable"}


def test_field_mapping_of_recent_events(wazuh_settings):
    host = os.environ.get("SOCI_IT_WAZUH_HOST")
    events = WazuhBackend(wazuh_settings).search_events(_recent_query(host=host) if host else _recent_query())
    if not events:
        pytest.skip("no events in the last 24h for the configured scope")
    for ev in events:
        assert ev.timestamp.tzinfo is not None and ev.host and ev.event_ref.startswith("wz1~")
    cats = {ev.category for ev in events}
    print(f"\ncategories seen: {sorted(cats)}")


def test_read_only_investigation_of_newest_alert(wazuh_settings):
    backend = WazuhBackend(wazuh_settings)
    alerts = backend.list_alerts()
    if not alerts:
        pytest.skip("no alerts above the configured level in the lookback window")
    report = InvestigationAgent(backend, MockInvestigatorModel(), wazuh_settings).investigate(alerts[0])
    assert report.trace.tool_calls[0].tool == "get_event"
    assert report.coverage.items and report.coverage.backend_caveats
    if wazuh_settings.wazuh_events_index == wazuh_settings.wazuh_alerts_index:
        assert any("rule-matched" in c for c in report.coverage.backend_caveats)
    print(f"\nlive alert: status={report.status} failed={report.coverage.failed} "
          f"truncated={report.coverage.truncated} unknowns={len(report.coverage.unknowns)}")
