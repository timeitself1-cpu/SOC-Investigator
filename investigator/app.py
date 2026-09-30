"""FastAPI local dashboard.

Endpoints:
  GET  /                      incident queue
  POST /investigate/{alert}   start an investigation, redirect to the run view
  GET  /run/{run_id}          live investigation view (polls the activity API)
  GET  /api/run/{run_id}      JSON activity/status feed
  GET  /report/{run_id}       completed report view
  GET  /export/{run_id}.json  JSON export
  GET  /export/{run_id}.md    Markdown export
  GET  /healthz               liveness + mode info

The UI is server-rendered HTML + a little vanilla JS. No build tooling.
"""

from __future__ import annotations

import threading
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .config import Settings, load_settings
from .report import report_to_json, report_to_markdown
from .service import InvestigationService, ServiceBusyError

BASE = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE / "templates"))


def create_app(settings: Settings | None = None) -> FastAPI:
    # Importing the ASGI app must not read .env, construct backend clients, or
    # write files. Initialize at startup, with a lazy fallback for ASGI clients
    # that do not dispatch lifespan events (including a bare TestClient).
    initialization_lock = threading.RLock()

    def get_settings() -> Settings:
        nonlocal settings
        with initialization_lock:
            if settings is None:
                settings = load_settings()
                app.state.settings = settings
            return settings

    def get_service() -> InvestigationService:
        with initialization_lock:
            if app.state.service is None:
                app.state.service = InvestigationService(get_settings())
            return app.state.service

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        get_service()
        yield

    app = FastAPI(title="SOC Investigation Agent", version="0.1.0", lifespan=lifespan)
    app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")
    app.state.service = None
    app.state.settings = settings

    @app.middleware("http")
    async def local_browser_protection(request: Request, call_next):
        configured_host = get_settings().host.lower().strip("[]")
        allowed_hosts = {"localhost", "127.0.0.1", "::1", configured_host}
        try:
            hostname = request.url.hostname
            if not hostname or hostname.lower() not in allowed_hosts:
                return PlainTextResponse("Invalid Host header", status_code=400)
            if request.method not in {"GET", "HEAD", "OPTIONS"}:
                if request.headers.get("sec-fetch-site") == "cross-site":
                    return PlainTextResponse("Cross-site requests are not allowed", status_code=403)
                origin = request.headers.get("origin")
                if origin is not None:
                    parsed = urlsplit(origin)
                    port = parsed.port or (443 if parsed.scheme == "https" else 80)
                    expected_port = request.url.port or (443 if request.url.scheme == "https" else 80)
                    if (parsed.scheme != request.url.scheme or parsed.hostname != hostname
                            or port != expected_port or parsed.username is not None
                            or parsed.password is not None or parsed.path not in {"", "/"}
                            or parsed.query or parsed.fragment):
                        return PlainTextResponse("Cross-origin requests are not allowed", status_code=403)
        except ValueError:
            return PlainTextResponse("Invalid request origin", status_code=400)
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        # Telemetry and model transcripts can contain sensitive incident data.
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/healthz")
    def healthz() -> dict:
        settings, service = get_settings(), get_service()
        return {"status": "ok", "llm": settings.llm, "backend": settings.backend,
                "model": service.agent.model.name, "max_steps": settings.max_steps}

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> HTMLResponse:
        settings, service = get_settings(), get_service()
        alerts = service.list_alerts()
        rows = []
        for a in alerts:
            run = service.latest_run_for_alert(a.alert_id)
            rows.append({"alert": a, "run": run})
        return templates.TemplateResponse(request, "queue.html", {
            "rows": rows, "settings": settings, "model_name": service.agent.model.name,
        })

    @app.post("/investigate/{alert_id}")
    def investigate(alert_id: str) -> RedirectResponse:
        try:
            run = get_service().start(alert_id)
        except KeyError:
            raise HTTPException(status_code=404, detail=f"unknown alert {alert_id}")
        except ServiceBusyError as exc:
            raise HTTPException(status_code=429, detail=str(exc), headers={"Retry-After": "5"})
        return RedirectResponse(url=f"/run/{run.run_id}", status_code=303)

    @app.get("/run/{run_id}", response_class=HTMLResponse)
    def run_view(request: Request, run_id: str) -> HTMLResponse:
        run = get_service().get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="unknown run")
        return templates.TemplateResponse(request, "investigation.html", {
            "run": run, "alert": run.alert,
        })

    @app.get("/api/run/{run_id}")
    def api_run(run_id: str, since: int = Query(default=0, ge=0)) -> dict:
        run = get_service().get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="unknown run")
        return run.snapshot(since=since)

    @app.get("/report/{run_id}", response_class=HTMLResponse)
    def report_view(request: Request, run_id: str) -> HTMLResponse:
        run = get_service().get_run(run_id)
        if run is None or run.report is None:
            raise HTTPException(status_code=404, detail="report not ready")
        return templates.TemplateResponse(request, "report.html", {
            "run": run, "r": run.report,
        })

    @app.get("/export/{run_id}.json")
    def export_json(run_id: str) -> PlainTextResponse:
        run = get_service().get_run(run_id)
        if run is None or run.report is None:
            raise HTTPException(status_code=404, detail="report not ready")
        return PlainTextResponse(report_to_json(run.report), media_type="application/json",
                                 headers={"Content-Disposition": f'attachment; filename="{run.run_id}.json"'})

    @app.get("/export/{run_id}.md")
    def export_md(run_id: str) -> PlainTextResponse:
        run = get_service().get_run(run_id)
        if run is None or run.report is None:
            raise HTTPException(status_code=404, detail="report not ready")
        return PlainTextResponse(report_to_markdown(run.report), media_type="text/markdown",
                                 headers={"Content-Disposition": f'attachment; filename="{run.run_id}.md"'})

    return app


app = create_app()
