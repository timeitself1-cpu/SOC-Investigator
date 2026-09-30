"""Concurrency, retention, atomic persistence, and failure regression tests."""

import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from investigator.config import load_settings
from investigator.models import InvestigationReport, InvestigationTrace, utcnow
from investigator.service import InvestigationService, RunState, ServiceBusyError


@pytest.fixture
def service(tmp_path):
    return InvestigationService(load_settings(llm="mock", backend="fixture", reports_dir=tmp_path / "reports"))


def wait_finished(service, run):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        with service._lock:
            if run.run_id not in service._active_by_alert.values():
                return run.snapshot()
        time.sleep(0.005)
    pytest.fail("investigation did not release its active slot")


def report_for(alert, status="completed"):
    return InvestigationReport(
        investigation_id="INV-test", alert=alert, status=status, verdict="insufficient_evidence",
        confidence=0.0, summary="Test report", model="test", backend="fixture",
        started_at=utcnow(), completed_at=utcnow(),
        trace=InvestigationTrace(investigation_id="INV-test", model="test", backend="fixture", max_steps=1),
    )


def test_duplicate_requests_are_admitted_once_under_concurrency(service, monkeypatch):
    release = threading.Event()
    started = threading.Event()
    calls = []

    def investigate(alert, activity_hook):
        calls.append(alert.alert_id)
        started.set()
        assert release.wait(5)
        return report_for(alert)

    monkeypatch.setattr(service.agent, "investigate", investigate)
    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            runs = list(pool.map(service.start, ["INC-001"] * 20))
        assert started.wait(1)
        assert len({r.run_id for r in runs}) == 1
        assert calls == ["INC-001"]
    finally:
        release.set()
    assert wait_finished(service, runs[0])["status"] == "completed"


def test_capacity_is_released_after_investigation_error(service, monkeypatch):
    release = threading.Event()
    service.settings.max_concurrent_runs = 1

    def fail(alert, activity_hook):
        assert release.wait(5)
        raise RuntimeError("backend unavailable")

    monkeypatch.setattr(service.agent, "investigate", fail)
    try:
        run = service.start("INC-001")
        with pytest.raises(ServiceBusyError):
            service.start("INC-002")
    finally:
        release.set()
    snap = wait_finished(service, run)
    assert snap["status"] == "error"
    assert not snap["has_report"]
    assert "backend unavailable" in snap["error"]
    monkeypatch.setattr(service.agent, "investigate", lambda alert, **kwargs: report_for(alert))
    assert wait_finished(service, service.start("INC-002"))["status"] == "completed"


def test_thread_start_failure_does_not_leak_capacity(service, monkeypatch):
    def fail_start(self):
        raise RuntimeError("cannot create thread")

    with monkeypatch.context() as patch:
        patch.setattr(threading.Thread, "start", fail_start)
        with pytest.raises(RuntimeError, match="cannot create thread"):
            service.start("INC-001")
    assert not service._active_by_alert
    assert service.latest_run_for_alert("INC-001").snapshot()["status"] == "error"
    monkeypatch.setattr(service.agent, "investigate", lambda alert, **kwargs: report_for(alert))
    assert wait_finished(service, service.start("INC-001"))["status"] == "completed"


def test_retained_runs_are_bounded_and_files_survive_eviction(service, monkeypatch):
    service.settings.max_retained_runs = 8
    monkeypatch.setattr(service.agent, "investigate", lambda alert, **kwargs: report_for(alert))
    runs = []
    for _ in range(12):
        run = service.start("INC-001")
        assert wait_finished(service, run)["status"] == "completed"
        runs.append(run)
    assert len(service.runs) == 8
    assert service.get_run(runs[0].run_id) is None
    assert service.latest_run_for_alert("INC-001") is runs[-1]
    assert len(list(service.settings.reports_dir.glob("*.json"))) == 12


def test_persistence_uses_no_telemetry_ids_in_filename(service, monkeypatch, tmp_path):
    alert = service.get_alert("INC-001").model_copy(update={"alert_id": "../../escaped"})
    report = report_for(alert).model_copy(update={"investigation_id": "../../../outside"})
    monkeypatch.setattr(service.backend, "get_alert", lambda alert_id: alert)
    monkeypatch.setattr(service.agent, "investigate", lambda *args, **kwargs: report)
    run = service.start(alert.alert_id)
    snap = wait_finished(service, run)
    assert snap["status"] == "completed"
    expected = service.settings.reports_dir / f"{run.run_id}.json"
    assert expected.is_file()
    assert list(tmp_path.rglob("*.json")) == [expected]
    assert not list(service.settings.reports_dir.glob("*.tmp"))


def test_disk_failure_keeps_report_and_exposes_warning(service, monkeypatch):
    service.settings.reports_dir.write_text("This is a file, not a writable directory")
    monkeypatch.setattr(service.agent, "investigate", lambda alert, **kwargs: report_for(alert, "incomplete"))
    run = service.start("INC-001")
    snap = wait_finished(service, run)
    assert snap["status"] == "completed"
    assert snap["has_report"]
    assert snap["report_status"] == "incomplete"
    assert "could not be saved" in snap["persistence_error"]
    assert any(a["kind"] == "warning" for a in snap["activity"])


def test_atomic_write_failure_cleans_temporary_file(service, monkeypatch):
    from pathlib import Path

    def fail_replace(self, destination):
        raise PermissionError("cannot publish")

    monkeypatch.setattr(Path, "replace", fail_replace)
    monkeypatch.setattr(service.agent, "investigate", lambda alert, **kwargs: report_for(alert))
    run = service.start("INC-001")
    snap = wait_finished(service, run)
    assert snap["status"] == "completed"
    assert snap["persistence_error"]
    assert list(service.settings.reports_dir.iterdir()) == []


def test_status_is_published_only_after_persistence_finishes(service, monkeypatch):
    writing = threading.Event()
    release = threading.Event()

    def persist(*args):
        writing.set()
        assert release.wait(5)

    monkeypatch.setattr(service, "_persist", persist)
    monkeypatch.setattr(service.agent, "investigate", lambda alert, **kwargs: report_for(alert))
    run = service.start("INC-001")
    try:
        assert writing.wait(1)
        snap = run.snapshot()
        assert snap["status"] == "running"
        assert not snap["has_report"]
    finally:
        release.set()
    snap = wait_finished(service, run)
    assert snap["status"] == "completed"
    assert snap["has_report"]


def test_negative_snapshot_cursor_rejected(service):
    state = RunState("run-test", service.get_alert("INC-001"))
    with pytest.raises(ValueError):
        state.snapshot(-1)
