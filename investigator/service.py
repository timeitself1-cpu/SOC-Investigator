"""Bounded investigation runner for the local dashboard, with durable history.

* Every run has a journal record (``<reports_dir>/runs/<run_id>.json``) written
  atomically when the run starts and when it ends; the completed report is
  written atomically to ``<reports_dir>/<run_id>.json``.
* On startup the journal is replayed: finished runs reappear in the dashboard
  (reports are loaded lazily from disk) and runs that were still ``running``
  when the process stopped are recorded as ``interrupted`` — never silently lost.
* Cancellation is cooperative: the agent checks between steps. A model or
  backend request already in flight finishes (bounded by its own timeout).
* Shutdown cancels active runs, waits a bounded grace period, and records any
  run still in flight as interrupted.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .agent import build_agent
from .config import Settings
from .errors import safe_error
from .models import ActivityEvent, Alert, InvestigationReport
from .report import report_to_json

RUN_STATUSES = ("running", "completed", "error", "cancelled", "interrupted")


class ServiceBusyError(RuntimeError):
    """The service cannot accept another run without exceeding its bounds."""


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".tmp-", suffix=".part", delete=False) as fh:
            temporary = Path(fh.name)
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


class RunState:
    def __init__(self, run_id: str, alert: Alert, *, status: str = "running",
                 started_at: datetime | None = None) -> None:
        self.run_id = run_id
        self.alert = alert
        self.status = status  # running | completed | error | cancelled | interrupted
        self.activity: list[ActivityEvent] = []
        self._report: InvestigationReport | None = None
        self.report_path: Path | None = None
        self.report_status: str | None = None
        self.verdict: str | None = None
        self.error: str | None = None
        self.persistence_error: str | None = None
        self.started_at = started_at or datetime.now(timezone.utc)
        self.finished_at: datetime | None = None
        self.recovered = False
        self.cancel_event = threading.Event()
        self.thread: threading.Thread | None = None
        self._lock = threading.Lock()

    # -- report (lazy for recovered runs) -------------------------------
    @property
    def report(self) -> InvestigationReport | None:
        with self._lock:
            if self._report is None and self.report_path is not None and self.report_path.is_file():
                try:
                    self._report = InvestigationReport.model_validate_json(
                        self.report_path.read_text(encoding="utf-8"))
                except (OSError, ValidationError, ValueError):
                    self.error = self.error or "The saved report could not be read or no longer validates."
                    self.report_path = None
            return self._report

    @report.setter
    def report(self, value: InvestigationReport | None) -> None:
        with self._lock:
            self._report = value

    def add_activity(self, ev: ActivityEvent) -> None:
        with self._lock:
            self.activity.append(ev)

    def finish(self, report: InvestigationReport, persistence_error: str | None,
               before_publish=None) -> None:
        """Record the result; ``before_publish(journal)`` runs before the status flips,
        so a crash can never leave a durable 'running' record for a finished run."""
        final = "cancelled" if report.status == "cancelled" else "completed"
        with self._lock:
            self._report = report
            self.report_status = report.status
            self.verdict = report.verdict
            self.persistence_error = persistence_error
            self.finished_at = datetime.now(timezone.utc)
        journal_error = before_publish(self.journal(status=final)) if before_publish else None
        with self._lock:
            if journal_error and not self.persistence_error:
                self.persistence_error = journal_error
            if self.persistence_error:
                self.activity.append(ActivityEvent(kind="warning", message=self.persistence_error))
            # A finished job may have an incomplete assessment. Keep that
            # distinction in report_status rather than mislabelling the job.
            self.status = final

    def fail(self, exc: BaseException, before_publish=None) -> None:
        kind, message = safe_error(exc)
        with self._lock:
            self.error = f"Investigation failed ({kind}): {message}"
            self.activity.append(ActivityEvent(kind="error", message=self.error))
            self.finished_at = datetime.now(timezone.utc)
        if before_publish:
            before_publish(self.journal(status="error"))
        with self._lock:
            self.status = "error"

    def snapshot(self, since: int = 0) -> dict[str, Any]:
        if since < 0:
            raise ValueError("activity cursor must be nonnegative")
        report = self.report if self.recovered else None
        with self._lock:
            activity = self.activity
            if not activity and report is not None:
                activity = report.trace.activity
            acts = activity[since:]
            return {
                "run_id": self.run_id, "status": self.status, "alert_id": self.alert.alert_id,
                "activity": [{"at": a.at.isoformat(), "kind": a.kind, "message": a.message} for a in acts],
                "next_index": len(activity), "error": self.error,
                "has_report": self._report is not None or self.report_path is not None,
                "report_status": self.report_status, "persistence_error": self.persistence_error,
                "cancel_requested": self.cancel_event.is_set(), "recovered": self.recovered,
            }

    def journal(self, status: str | None = None) -> dict[str, Any]:
        with self._lock:
            return {
                "version": 1, "run_id": self.run_id, "status": status or self.status,
                "alert": self.alert.model_dump(mode="json"),
                "started_at": self.started_at.isoformat(),
                "finished_at": self.finished_at.isoformat() if self.finished_at else None,
                "report_file": self.report_path.name if self.report_path else None,
                "report_status": self.report_status, "verdict": self.verdict,
                "error": self.error, "persistence_error": self.persistence_error,
            }


class InvestigationService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.agent, self.backend = build_agent(settings)
        self.runs: dict[str, RunState] = {}
        self._by_alert: dict[str, str] = {}
        self._active_by_alert: dict[str, str] = {}
        self._lock = threading.Lock()
        self._closing = False
        self.recovery_notes: list[str] = []
        self._recover()

    # -- paths ------------------------------------------------------------
    @property
    def journal_dir(self) -> Path:
        return self.settings.reports_dir / "runs"

    def _journal_path(self, run_id: str) -> Path:
        return self.journal_dir / f"{run_id}.json"

    def _write_journal(self, run: RunState, record: dict[str, Any] | None = None) -> str | None:
        try:
            _atomic_write(self._journal_path(run.run_id), json.dumps(record or run.journal(), indent=2))
            return None
        except OSError as exc:
            return f"Run history could not be saved ({type(exc).__name__})."

    # -- recovery -----------------------------------------------------------
    def _recover(self) -> None:
        """Rebuild history from disk. Runs that were in flight become 'interrupted'."""
        reports_dir = self.settings.reports_dir
        recovered: list[RunState] = []
        seen: set[str] = set()
        if self.journal_dir.is_dir():
            for path in sorted(self.journal_dir.glob("run-*.json")):
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                    alert = Alert.model_validate(data["alert"])
                    run = RunState(str(data["run_id"]), alert, status=str(data.get("status", "error")),
                                   started_at=datetime.fromisoformat(data["started_at"]))
                except (OSError, ValueError, KeyError, TypeError, ValidationError):
                    self.recovery_notes.append(f"Unreadable run record skipped: {path.name}")
                    continue
                if run.run_id != path.stem or run.status not in RUN_STATUSES:
                    self.recovery_notes.append(f"Inconsistent run record skipped: {path.name}")
                    continue
                run.recovered = True
                run.report_status, run.verdict = data.get("report_status"), data.get("verdict")
                run.error, run.persistence_error = data.get("error"), data.get("persistence_error")
                if data.get("finished_at"):
                    run.finished_at = datetime.fromisoformat(data["finished_at"])
                report_file = data.get("report_file")
                if report_file and Path(report_file).name == report_file:
                    run.report_path = reports_dir / report_file
                if run.status == "running":
                    run.status = "interrupted"
                    run.error = "The server stopped before this investigation finished; no report was produced."
                    self._write_journal(run)
                recovered.append(run)
                seen.add(run.run_id)
        # Reports written before run journals existed (or whose journal was lost).
        if reports_dir.is_dir():
            for path in sorted(reports_dir.glob("run-*.json")):
                if path.stem in seen:
                    continue
                try:
                    report = InvestigationReport.model_validate_json(path.read_text(encoding="utf-8"))
                except (OSError, ValidationError, ValueError):
                    self.recovery_notes.append(f"Unreadable report skipped: {path.name}")
                    continue
                run = RunState(path.stem, report.alert, status="completed", started_at=report.started_at)
                run.recovered, run.report_path = True, path
                run.report_status, run.verdict, run.finished_at = report.status, report.verdict, report.completed_at
                recovered.append(run)
        recovered.sort(key=lambda r: r.started_at)
        for run in recovered[-self.settings.max_retained_runs:]:
            self.runs[run.run_id] = run
            self._by_alert[run.alert.alert_id] = run.run_id

    # -- queries ----------------------------------------------------------
    def model_status(self) -> dict[str, Any]:
        """Local model reachability for the dashboard (cached for 30 s)."""
        now = time.monotonic()
        cached = getattr(self, "_model_status", None)
        if cached and now - cached[0] < 30:
            return cached[1]
        health = getattr(self.agent.model, "health", None)
        if callable(health):
            try:
                ok, msg = health()
            except Exception as exc:  # noqa: BLE001
                ok, msg = False, safe_error(exc)[1]
            status = {"ok": ok, "detail": f"{self.agent.model.name}: {'connected' if ok else msg}"}
        else:
            status = {"ok": True, "detail": f"{self.agent.model.name} (deterministic demo model, no LLM)"}
        self._model_status = (now, status)
        return status

    def list_alerts(self) -> list[Alert]:
        return self.backend.list_alerts()

    def get_alert(self, alert_id: str) -> Alert | None:
        return self.backend.get_alert(alert_id)

    def history(self) -> list[RunState]:
        with self._lock:
            return sorted(self.runs.values(), key=lambda r: r.started_at, reverse=True)

    def get_run(self, run_id: str) -> RunState | None:
        with self._lock:
            return self.runs.get(run_id)

    def latest_run_for_alert(self, alert_id: str) -> RunState | None:
        with self._lock:
            rid = self._by_alert.get(alert_id)
            return self.runs.get(rid) if rid else None

    # -- lifecycle ----------------------------------------------------------
    def start(self, alert_id: str) -> RunState:
        with self._lock:
            if self._closing:
                raise ServiceBusyError("The server is shutting down.")
            active = self._active_by_alert.get(alert_id)
            if active:
                return self.runs[active]
            if len(self._active_by_alert) >= self.settings.max_concurrent_runs:
                raise ServiceBusyError("Investigation capacity reached; retry when a running investigation finishes.")
        # A backend lookup may involve a network call. Do not hold the service
        # lock while waiting; recheck admission after fetching the alert.
        alert = self.backend.get_alert(alert_id)
        if alert is None:
            raise KeyError(alert_id)
        with self._lock:
            active = self._active_by_alert.get(alert_id)
            if active:
                return self.runs[active]
            if len(self._active_by_alert) >= self.settings.max_concurrent_runs:
                raise ServiceBusyError("Investigation capacity reached; retry when a running investigation finishes.")
            self._prune_finished_runs()
            if len(self.runs) >= self.settings.max_retained_runs:
                raise ServiceBusyError("Run history is full of active investigations; retry later.")
            run_id = f"run-{uuid.uuid4().hex}"
            run = RunState(run_id, alert)
            self.runs[run_id] = run
            self._by_alert[alert_id] = run_id
            self._active_by_alert[alert_id] = run_id
            journal_error = self._write_journal(run)
            if journal_error:
                run.persistence_error = journal_error
            try:
                thread = threading.Thread(target=self._run, args=(run,), daemon=True,
                                          name=f"investigation-{run_id}")
                run.thread = thread
                thread.start()
            except Exception as exc:
                # Thread creation can fail too; never leak a concurrency slot.
                self._active_by_alert.pop(alert_id, None)
                run.fail(exc, before_publish=lambda record: self._write_journal(run, record))
                raise
        return run

    def cancel(self, run_id: str) -> bool:
        run = self.get_run(run_id)
        if run is None or run.status != "running":
            return False
        run.cancel_event.set()
        run.add_activity(ActivityEvent(kind="warning", message="Cancellation requested; the run stops after the request in progress "
                                                 "and ends as cancelled"))
        return True

    def shutdown(self, grace_seconds: float | None = None) -> list[str]:
        """Cancel active runs, wait up to the grace period, record stragglers as interrupted."""
        grace = self.settings.shutdown_grace_seconds if grace_seconds is None else grace_seconds
        with self._lock:
            self._closing = True
            active = [self.runs[r] for r in self._active_by_alert.values() if r in self.runs]
        for run in active:
            run.cancel_event.set()
        deadline = time.monotonic() + max(0.0, grace)
        interrupted: list[str] = []
        for run in active:
            if run.thread is not None:
                run.thread.join(max(0.0, deadline - time.monotonic()))
            # Check and flip under the run's lock: a run that finishes in this
            # window must not be re-labelled interrupted after its report was saved.
            with run._lock:
                still_running = run.status == "running"
                if still_running:
                    run.status = "interrupted"
                    run.error = "The server shut down before this investigation finished."
                    run.finished_at = datetime.now(timezone.utc)
            if still_running:
                self._write_journal(run)
                interrupted.append(run.run_id)
        return interrupted

    def _prune_finished_runs(self) -> None:
        """Evict oldest finished runs from memory (called with the lock held). Disk copies remain."""
        active = set(self._active_by_alert.values())
        for run_id in list(self.runs):
            if len(self.runs) < self.settings.max_retained_runs:
                break
            if run_id in active:
                continue
            old = self.runs.pop(run_id)
            if self._by_alert.get(old.alert.alert_id) == run_id:
                self._by_alert.pop(old.alert.alert_id, None)

    def _run(self, run: RunState) -> None:
        try:
            report = self.agent.investigate(run.alert, activity_hook=run.add_activity,
                                            cancel_event=run.cancel_event)
            persistence_error = None
            try:
                self._persist(report, run.run_id)
                run.report_path = self.settings.reports_dir / f"{run.run_id}.json"
            except OSError as exc:
                persistence_error = (
                    f"Report could not be saved to disk ({type(exc).__name__}). "
                    "Download it before this run is evicted or the server stops."
                )
            # (A late finish after a shutdown timeout still saves the report and
            # replaces the 'interrupted' journal record.)
            run.finish(report, persistence_error,
                       before_publish=lambda record: self._write_journal(run, record))
        except Exception as exc:  # keep the server alive; surface a classified error
            run.fail(exc, before_publish=lambda record: self._write_journal(run, record))
        finally:
            with self._lock:
                if self._active_by_alert.get(run.alert.alert_id) == run.run_id:
                    self._active_by_alert.pop(run.alert.alert_id, None)

    def _persist(self, report: InvestigationReport, run_id: str) -> None:
        # Only an application-generated ID names files. Alert and report IDs
        # originate in untrusted data and may contain paths or header characters.
        _atomic_write(self.settings.reports_dir / f"{run_id}.json", report_to_json(report))
