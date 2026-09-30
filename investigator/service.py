"""Bounded, in-memory investigation runner for the local dashboard.

Completed reports are also written atomically to disk. Dashboard history is
bounded and is not restored after restart; the JSON files remain available.
"""

from __future__ import annotations

import os
import tempfile
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .agent import build_agent
from .config import Settings
from .models import ActivityEvent, Alert, InvestigationReport
from .report import report_to_json


class ServiceBusyError(RuntimeError):
    """The service cannot accept another run without exceeding its bounds."""


class RunState:
    def __init__(self, run_id: str, alert: Alert) -> None:
        self.run_id = run_id
        self.alert = alert
        self.status = "running"  # running | completed | error
        self.activity: list[ActivityEvent] = []
        self.report: InvestigationReport | None = None
        self.error: str | None = None
        self.persistence_error: str | None = None
        self.started_at = datetime.now(timezone.utc)
        self._lock = threading.Lock()

    def add_activity(self, ev: ActivityEvent) -> None:
        with self._lock:
            self.activity.append(ev)

    def finish(self, report: InvestigationReport, persistence_error: str | None) -> None:
        with self._lock:
            self.report = report
            self.persistence_error = persistence_error
            if persistence_error:
                self.activity.append(ActivityEvent(kind="warning", message=persistence_error))
            # A finished job may have an incomplete assessment. Keep that
            # distinction in report_status rather than mislabelling the job.
            self.status = "completed"

    def fail(self, exc: Exception) -> None:
        with self._lock:
            self.error = f"{type(exc).__name__}: {exc}"
            self.activity.append(ActivityEvent(kind="error", message=self.error))
            self.status = "error"

    def snapshot(self, since: int = 0) -> dict[str, Any]:
        if since < 0:
            raise ValueError("activity cursor must be nonnegative")
        with self._lock:
            acts = self.activity[since:]
            return {
                "run_id": self.run_id, "status": self.status, "alert_id": self.alert.alert_id,
                "activity": [{"at": a.at.isoformat(), "kind": a.kind, "message": a.message} for a in acts],
                "next_index": len(self.activity), "error": self.error,
                "has_report": self.report is not None,
                "report_status": self.report.status if self.report else None,
                "persistence_error": self.persistence_error,
            }


class InvestigationService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.agent, self.backend = build_agent(settings)
        self.runs: dict[str, RunState] = {}
        self._by_alert: dict[str, str] = {}
        self._active_by_alert: dict[str, str] = {}
        self._lock = threading.Lock()

    def list_alerts(self) -> list[Alert]:
        return self.backend.list_alerts()

    def get_alert(self, alert_id: str) -> Alert | None:
        return self.backend.get_alert(alert_id)

    def start(self, alert_id: str) -> RunState:
        with self._lock:
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
            try:
                threading.Thread(target=self._run, args=(run,), daemon=True,
                                 name=f"investigation-{run_id}").start()
            except Exception as exc:
                # Thread creation can fail too; never leak a concurrency slot.
                self._active_by_alert.pop(alert_id, None)
                run.fail(exc)
                raise
        return run

    def _prune_finished_runs(self) -> None:
        """Evict oldest finished runs only, called with the service lock held."""
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
            report = self.agent.investigate(run.alert, activity_hook=run.add_activity)
            persistence_error = None
            try:
                self._persist(report, run.run_id)
            except OSError as exc:
                persistence_error = (
                    f"Report could not be saved to disk ({type(exc).__name__}). "
                    "Download it before this run is evicted or the server stops."
                )
            run.finish(report, persistence_error)
        except Exception as exc:  # keep the server alive; surface the error
            run.fail(exc)
        finally:
            with self._lock:
                self._active_by_alert.pop(run.alert.alert_id, None)

    def _persist(self, report: InvestigationReport, run_id: str) -> None:
        # Only an application-generated ID names files. Alert and report IDs
        # originate in untrusted data and may contain paths or header characters.
        directory = self.settings.reports_dir
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{run_id}.json"
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=directory,
                                             prefix=".report-", suffix=".tmp", delete=False) as fh:
                temporary = Path(fh.name)
                fh.write(report_to_json(report))
                fh.flush()
                os.fsync(fh.fileno())
            temporary.replace(path)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def get_run(self, run_id: str) -> RunState | None:
        with self._lock:
            return self.runs.get(run_id)

    def latest_run_for_alert(self, alert_id: str) -> RunState | None:
        with self._lock:
            rid = self._by_alert.get(alert_id)
            return self.runs.get(rid) if rid else None
