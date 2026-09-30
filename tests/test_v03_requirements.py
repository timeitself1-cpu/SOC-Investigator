"""v0.3 benign requirements: tree-scoped network coverage, host-level signals,
and degraded (limited) sources — each must block benign exactly when it should,
while the clean case stays closable."""

from __future__ import annotations

from datetime import timedelta

from investigator.agent import InvestigationAgent
from investigator.backends.windows import WindowsEventBackend
from investigator.backends.winevt_reader import RecordedEventReader
from investigator.llm.mock import BenignProposerModel, MockInvestigatorModel
from investigator.models import Alert

from test_integrity_v021 import (
    BENIGN, CLEAN_HOST, CMD, FULL_PLAN, HOST, PS, T0, ListBackend, Scripted, admin_trigger, call, conn,
    investigate, proc, req, settings,
)
from test_windows_backend import DEMO, by_title, xml_of
from test_windows_backend import settings as win_settings

TREE_NET_PLAN = [call("get_process_tree", evidence_id="EV-0001"),
                 call("get_network_activity", scope="process_tree"), call("get_host_context")]


def _tree_with_internal_child():
    return [admin_trigger(), proc("C1", 1, "{c1}", "{p1}", CMD, PS), conn("N1", 2, "{c1}", CMD, ip="10.40.1.20")]


def test_tree_scoped_network_satisfies_requirement_when_it_covers_the_whole_tree():
    r = investigate(_tree_with_internal_child(), plan=TREE_NET_PLAN)
    q = req(r, "network_activity")
    assert q.satisfied and "process tree" in q.reason
    assert r.verdict == "benign", r.validation.issues


def test_tree_network_taken_before_the_tree_was_expanded_does_not_count():
    plan = [call("get_network_activity", scope="process_tree"), call("get_process_tree", evidence_id="EV-0001"),
            call("get_host_context")]
    r = investigate(_tree_with_internal_child(), plan=plan)
    assert not req(r, "network_activity").satisfied and r.verdict == "insufficient_evidence"


def test_tree_scoped_network_still_sees_a_descendant_beacon():
    docs = [admin_trigger(), proc("C1", 1, "{c1}", "{p1}", CMD, PS), conn("N1", 2, "{c1}", CMD)]  # public IP
    r = investigate(docs, plan=TREE_NET_PLAN)
    assert req(r, "network_activity").satisfied and r.verdict == "insufficient_evidence"
    assert any("external_destination" in i for i in r.validation.issues)


class TwoSignals(ListBackend):
    def list_alerts(self):
        other = Alert(alert_id="X-2", title="Persistence mechanism created", timestamp=self.alert.timestamp
                      + timedelta(minutes=20), host=self.alert.host, severity="medium", event_ref="other")
        return [self.alert, other]


class SignalsUnavailable(ListBackend):
    def list_alerts(self):
        raise RuntimeError("event log unreadable")


def test_other_signal_on_the_host_blocks_benign():
    be = TwoSignals([admin_trigger()], "T", hosts=CLEAN_HOST)
    r = InvestigationAgent(be, Scripted(FULL_PLAN, BENIGN), settings()).investigate(be.alert)
    q = req(r, "host_signals")
    assert not q.satisfied and "Persistence mechanism created" in q.reason
    assert r.verdict == "insufficient_evidence"


def test_unavailable_host_signal_check_blocks_benign():
    be = SignalsUnavailable([admin_trigger()], "T", hosts=CLEAN_HOST)
    r = InvestigationAgent(be, Scripted(FULL_PLAN, BENIGN), settings()).investigate(be.alert)
    assert not req(r, "host_signals").satisfied and r.verdict == "insufficient_evidence"


def test_signal_outside_the_window_or_on_another_host_does_not_block():
    class Far(ListBackend):
        def list_alerts(self):
            far = self.alert.model_copy(update={"alert_id": "X-3", "event_ref": "far",
                                                "timestamp": self.alert.timestamp + timedelta(hours=3)})
            other_host = self.alert.model_copy(update={"alert_id": "X-4", "event_ref": "oh", "host": "OTHER"})
            return [self.alert, far, other_host]
    be = Far([admin_trigger()], "T", hosts=CLEAN_HOST)
    r = InvestigationAgent(be, Scripted(FULL_PLAN, BENIGN), settings()).investigate(be.alert)
    assert req(r, "host_signals").satisfied and r.verdict == "benign"


def test_windows_limited_network_logging_blocks_benign_even_with_no_events():
    """Sysmon runs but records no network connections: an empty answer is not a clean one."""
    events = {"sysmon": [x for x in xml_of("sysmon") if "<EventID>3</EventID>" not in x],
              "security": xml_of("security"), "powershell": xml_of("powershell"), "defender": xml_of("defender")}
    b = WindowsEventBackend(win_settings(), RecordedEventReader(events=events))
    alert = by_title(b, "(hidden window)")
    r = InvestigationAgent(b, BenignProposerModel(), win_settings()).investigate(alert)
    net = [c for c in r.trace.tool_calls if c.tool == "get_network_activity"]
    assert net and all(c.outcome in ("partial", "failed") for c in net)
    assert not req(r, "network_activity").satisfied and r.verdict == "insufficient_evidence"


def test_windows_clean_admin_job_still_closes_with_the_mock_analyst():
    b = WindowsEventBackend(win_settings(), RecordedEventReader.from_directory(DEMO))
    r = InvestigationAgent(b, MockInvestigatorModel(), win_settings()).investigate(
        by_title(b, "(hidden window)"))
    assert r.verdict == "benign" and all(q.satisfied for q in r.coverage.requirements)
