"""Live Windows event log checks (opt-in; Windows only; read-only).

    $env:SOCI_IT_WINDOWS = "1"
    python -m pytest -m integration -v tests/integration/test_live_windows.py

They read this computer's Sysmon / Security / PowerShell / Defender channels with the
same PyWin32Reader the product uses. Nothing is written. Results depend on which
sources are installed and readable by the account running the tests; a source that is
missing or denied must be *reported* as such, never read as "no events".
"""

from datetime import timedelta

import pytest

from investigator.agent import InvestigationAgent
from investigator.backends.base import EventQuery
from investigator.backends.windows import build_windows_backend
from investigator.errors import ClassifiedError
from investigator.llm.mock import MockInvestigatorModel
from investigator.models import utcnow

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def backend(windows_settings):
    return build_windows_backend(windows_settings)


def test_every_source_has_a_classified_state(backend):
    states = {s.label: s.state for s in backend.source_status()}
    print("\nsources:", states)
    assert set(states) == {"Sysmon", "Windows Security", "PowerShell", "Microsoft Defender"}
    assert set(states.values()) <= {"active", "limited", "not_installed", "access_denied", "error"}


def test_unreadable_sources_raise_instead_of_returning_nothing(backend):
    now = utcnow()
    for st in backend.source_status():
        if st.state in ("not_installed", "access_denied") and st.source == "sysmon":
            with pytest.raises(ClassifiedError):
                backend.search_events(EventQuery(start=now - timedelta(hours=1), end=now, category="network"))


def test_recent_process_events_normalize_and_roundtrip(backend):
    now = utcnow()
    try:
        events = backend.search_events(EventQuery(start=now - timedelta(hours=24), end=now, category="process",
                                                  order="desc", limit=10))
    except ClassifiedError as exc:
        pytest.skip(f"process telemetry unavailable: {exc.kind}")
    assert events, "an active process source should have recorded something in 24h"
    ev = events[0]
    assert ev.image and ev.timestamp <= now + timedelta(minutes=5)
    again = backend.get_event(ev.event_ref)
    assert again is not None and again.event_ref == ev.event_ref


def test_signals_list_and_one_investigation_has_valid_references(backend, windows_settings):
    alerts = backend.list_alerts()
    print("\nsignals:", [a.title for a in alerts][:10], "notes:", backend.signal_notes)
    if not alerts:
        pytest.skip("no signals on this machine; run docs/validation/v0.3/rw_scenarios.ps1 first")
    report = InvestigationAgent(backend, MockInvestigatorModel(), windows_settings).investigate(alerts[0])
    ids = {e.evidence_id for e in report.evidence}
    assert report.evidence and all(set(f.evidence_ids) <= ids for f in report.findings)
    assert report.validation.invalid_evidence_refs == []
    print("verdict:", report.verdict, report.status, [(q.name, q.satisfied) for q in report.coverage.requirements])
