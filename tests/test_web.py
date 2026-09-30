"""Web app: queue, investigation lifecycle, exports."""

import time
import importlib
import threading

import pytest

from investigator.app import create_app
from investigator.config import load_settings

fastapi_testclient = pytest.importorskip("fastapi.testclient")
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture
def client(tmp_path):
    app = create_app(load_settings(llm="mock", backend="fixture", reports_dir=tmp_path / "reports"))
    with TestClient(app, base_url="http://localhost") as client:
        yield client


def _run_to_completion(client, alert_id):
    r = client.post(f"/investigate/{alert_id}", follow_redirects=False)
    assert r.status_code == 303
    run_id = r.headers["location"].split("/")[-1]
    for _ in range(200):
        snap = client.get(f"/api/run/{run_id}").json()
        if snap["status"] != "running":
            break
        time.sleep(0.02)
    return run_id, snap


def test_healthz(client):
    data = client.get("/healthz").json()
    assert data["status"] == "ok"
    assert data["llm"] == "mock"


def test_queue_lists_incidents(client):
    html = client.get("/").text
    assert "Incident Queue" in html
    for aid in ["INC-001", "INC-002", "INC-005"]:
        assert aid in html


def test_investigation_lifecycle_and_exports(client):
    run_id, snap = _run_to_completion(client, "INC-001")
    assert snap["status"] == "completed"
    assert client.get(f"/report/{run_id}").status_code == 200
    j = client.get(f"/export/{run_id}.json")
    assert j.status_code == 200 and j.json()["verdict"] in ("suspicious", "likely_malicious")
    m = client.get(f"/export/{run_id}.md")
    assert m.status_code == 200 and "# Investigation" in m.text


def test_benign_case_renders_benign(client):
    run_id, snap = _run_to_completion(client, "INC-005")
    j = client.get(f"/export/{run_id}.json").json()
    assert j["verdict"] != "likely_malicious"


def test_unknown_endpoints_404(client):
    assert client.get("/report/nonexistent").status_code == 404
    assert client.get("/api/run/nonexistent").status_code == 404
    assert client.post("/investigate/INC-999").status_code == 404


def test_report_shows_no_execution_notice(client):
    run_id, _ = _run_to_completion(client, "INC-002")
    html = client.get(f"/report/{run_id}").text
    assert "no response actions were executed" in html.lower()


def test_import_and_factory_do_not_initialize_clients_or_read_settings(monkeypatch):
    import investigator.app as module
    import investigator.config as config
    import investigator.service as service

    def unexpected(*args, **kwargs):
        raise AssertionError("app import/factory initialized external resources")

    with monkeypatch.context() as patch:
        patch.setattr(config, "load_settings", unexpected)
        patch.setattr(service, "build_agent", unexpected)
        importlib.reload(module)
        assert module.app.state.service is None
        assert module.create_app().state.service is None
    importlib.reload(module)


def test_bare_testclient_can_initialize_lazily(tmp_path):
    app = create_app(load_settings(llm="mock", backend="fixture", reports_dir=tmp_path / "reports"))
    client = TestClient(app, base_url="http://localhost")
    assert app.state.service is None
    assert client.get("/healthz").status_code == 200
    assert app.state.service is not None
    assert not (tmp_path / "reports").exists()


def test_negative_activity_cursor_is_rejected(client):
    run_id, _ = _run_to_completion(client, "INC-001")
    assert client.get(f"/api/run/{run_id}?since=-1").status_code == 422


def test_browser_protection(client):
    assert client.get("/", headers={"Host": "attacker.example"}).status_code == 400
    assert client.post("/investigate/INC-001", headers={"Origin": "https://attacker.example"}).status_code == 403
    assert client.post("/investigate/INC-001", headers={"Origin": "null"}).status_code == 403
    assert client.post("/investigate/INC-001", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert not client.app.state.service.runs
    assert client.post("/investigate/INC-001", headers={"Origin": "http://localhost"},
                       follow_redirects=False).status_code == 303
    response = client.get("/")
    assert "script-src 'self'" in response.headers["content-security-policy"]
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_capacity_returns_retryable_response_and_duplicate_reuses_run(client, monkeypatch):
    service = client.app.state.service
    service.settings.max_concurrent_runs = 1
    release = threading.Event()
    original = service.agent.investigate

    def blocked(*args, **kwargs):
        assert release.wait(5)
        return original(*args, **kwargs)

    monkeypatch.setattr(service.agent, "investigate", blocked)
    try:
        first = client.post("/investigate/INC-001", follow_redirects=False)
        duplicate = client.post("/investigate/INC-001", follow_redirects=False)
        assert duplicate.headers["location"] == first.headers["location"]
        rejected = client.post("/investigate/INC-002", follow_redirects=False)
        assert rejected.status_code == 429
        assert rejected.headers["retry-after"] == "5"
    finally:
        release.set()
    run_id = first.headers["location"].rsplit("/", 1)[1]
    for _ in range(200):
        if service.get_run(run_id).snapshot()["status"] != "running":
            break
        time.sleep(0.01)
    assert service.get_run(run_id).snapshot()["status"] == "completed"


def test_download_filename_uses_generated_id(client):
    run_id, _ = _run_to_completion(client, "INC-001")
    run = client.app.state.service.get_run(run_id)
    run.alert.alert_id = '../../unsafe;filename="bad"\r\nInjected: yes'
    for extension in ("json", "md"):
        response = client.get(f"/export/{run_id}.{extension}")
        assert response.status_code == 200
        assert response.headers["content-disposition"] == f'attachment; filename="{run_id}.{extension}"'
        assert "injected" not in response.headers
