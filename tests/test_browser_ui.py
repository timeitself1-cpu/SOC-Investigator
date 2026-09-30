"""Real-browser UI checks (Chromium via Playwright). Skipped when unavailable.

Covers what the Python/JS unit tests cannot: the CSP actually lets the
external scripts run and blocks nothing needed, evidence filters and anchors
work in a real DOM, and cancel/history work through real form submissions.
Install for local runs:  pip install playwright  &&  python -m playwright install chromium
"""

from __future__ import annotations

import os
import socket
import threading
import time
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")

from investigator.app import create_app  # noqa: E402
from investigator.config import load_settings  # noqa: E402

# Tracked screenshots are only rewritten on request (SOCI_UPDATE_SCREENSHOTS=1);
# otherwise a test run must not modify committed files.
SHOTS = (Path(__file__).resolve().parent.parent / "docs" / "screenshots"
         if os.environ.get("SOCI_UPDATE_SCREENSHOTS") == "1"
         else Path(os.environ.get("TMPDIR", "/tmp")) / "soci-browser-shots")


def _chromium_path() -> str | None:
    for candidate in ("/opt/pw-browsers/chromium-1194/chrome-linux/chrome",):
        if os.path.exists(candidate):
            return candidate
    return None


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    import uvicorn

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    settings = load_settings(llm="mock", backend="fixture", port=port,
                             reports_dir=tmp_path_factory.mktemp("reports"))
    app = create_app(settings)
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    for _ in range(100):
        if srv.started:
            break
        time.sleep(0.05)
    yield app, f"http://127.0.0.1:{port}"
    srv.should_exit = True
    thread.join(5)


@pytest.fixture(scope="module")
def page():
    with playwright.sync_playwright() as p:
        try:
            # No background calls to browser vendor services; the app itself is local-only.
            args = ["--disable-background-networking", "--disable-component-update", "--no-first-run"]
            browser = (p.chromium.launch(executable_path=_chromium_path(), args=args) if _chromium_path()
                       else p.chromium.launch(args=args))
        except Exception as exc:  # noqa: BLE001
            pytest.skip(f"Chromium not available: {exc}")
        pg = browser.new_page(viewport={"width": 1200, "height": 900})
        pg.console_errors = []
        pg.on("console", lambda m: m.type == "error" and pg.console_errors.append(m.text))
        yield pg
        browser.close()


def test_investigate_watch_and_navigate_report(server, page):
    _, base = server
    page.goto(base + "/")
    page.locator("tr", has_text="INC-001").get_by_role("button", name="Investigate").click()
    page.get_by_role("link", name="View report →").wait_for(state="visible", timeout=10_000)
    assert page.locator("#activity li").count() > 3
    page.get_by_role("link", name="View report →").click()
    page.wait_for_selector("#coverage")
    for section in ("#facts", "#hypotheses", "#verify", "#coverage", "#evidence"):
        assert page.locator(section).is_visible()
    # report.js ran under the CSP: filter panel un-hidden and counting.
    assert page.locator("#evidence-filters").is_visible()
    total = page.locator("details.evidence").count()
    page.fill("#ev-q", "network connection")
    shown = page.locator("details.evidence:not([hidden])").count()
    assert 0 < shown < total
    assert f"{shown} of {total} shown" in page.inner_text("#ev-count")
    page.fill("#ev-q", "")
    page.check("#ev-cited")
    assert page.locator("details.evidence:not([hidden])").count() <= total
    # An evidence anchor clears hiding filters and opens the item.
    page.uncheck("#ev-cited")
    page.fill("#ev-q", "zzz-no-match")
    first_fact = page.locator("#facts a.tag").first
    target = first_fact.inner_text()
    first_fact.click()
    # (A string predicate via wait_for_function would need eval, which the CSP
    # correctly refuses; wait on the DOM attribute instead.)
    page.locator(f"details#{target}[open]").wait_for(state="visible", timeout=5_000)
    assert page.locator(f"details#{target}").is_visible()
    SHOTS.mkdir(parents=True, exist_ok=True)
    page.goto(page.url.split("#")[0])
    page.screenshot(path=str(SHOTS / "v2_report_inc001.png"), full_page=True)
    assert not [e for e in page.console_errors if "Content Security Policy" in e], page.console_errors


def test_cancel_and_history_through_real_forms(server, page):
    app, base = server
    service = app.state.service
    real = service.agent.investigate

    def slow(alert, activity_hook=None, cancel_event=None):
        # Cooperative: wait for cancellation, then let the real agent observe it.
        cancel_event.wait(10)
        return real(alert, activity_hook=activity_hook, cancel_event=cancel_event)

    service.agent.investigate = slow
    try:
        page.goto(base + "/")
        page.locator("tr", has_text="INC-003").get_by_role("button", name="Investigate").click()
        page.get_by_role("button", name="Cancel investigation").click()
        page.get_by_role("link", name="View report →").wait_for(state="visible", timeout=10_000)
        assert "cancelled" in page.inner_text("#reportstatus").lower()
    finally:
        service.agent.investigate = real
    page.goto(base + "/history")
    assert page.locator("td", has_text="cancelled").count() >= 1
    page.screenshot(path=str(SHOTS / "v2_history.png"), full_page=True)
    page.goto(base + "/")
    page.screenshot(path=str(SHOTS / "v2_queue.png"), full_page=True)
