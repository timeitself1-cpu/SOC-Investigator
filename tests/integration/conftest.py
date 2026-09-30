"""Opt-in live integration tests.

These talk to a REAL Ollama server and/or a REAL Wazuh deployment. They are
deselected by default (`-m 'not integration'` in pyproject) and additionally
skip unless explicitly enabled:

    # PowerShell
    $env:SOCI_IT_OLLAMA = "1"               # uses SOCI_OLLAMA_URL / SOCI_OLLAMA_MODEL
    $env:SOCI_IT_WAZUH  = "1"               # uses SOCI_WAZUH_* settings (read-only)
    $env:SOCI_IT_WINDOWS = "1"              # reads THIS computer's event logs (Windows only, read-only)
    python -m pytest -m integration -v tests/integration

Optional Wazuh knobs for negative-path checks (each check skips if unset):
    SOCI_IT_WAZUH_LIMITED_USER / SOCI_IT_WAZUH_LIMITED_PASSWORD
        an indexer user WITHOUT read access to the alerts index -> expects "permission"
    SOCI_IT_WAZUH_SELF_SIGNED=1
        the indexer uses a certificate not trusted by the system store -> expects "tls"
        when verification is on and no CA bundle is given
    SOCI_IT_WAZUH_HOST=<agent name>
        a Windows agent with Sysmon forwarding, for mapping/telemetry checks

All requests are the same allowlisted read-only requests the application uses.
"""

import os

import pytest

from investigator.config import load_settings


def _enabled(var: str) -> bool:
    return os.environ.get(var, "").strip() in {"1", "true", "yes"}


@pytest.fixture(scope="session")
def ollama_settings():
    if not _enabled("SOCI_IT_OLLAMA"):
        pytest.skip("set SOCI_IT_OLLAMA=1 to run live Ollama tests")
    return load_settings(llm="ollama", backend="fixture")


@pytest.fixture(scope="session")
def wazuh_settings():
    if not _enabled("SOCI_IT_WAZUH"):
        pytest.skip("set SOCI_IT_WAZUH=1 to run live Wazuh tests")
    s = load_settings(llm="mock", backend="wazuh")
    if not (s.wazuh_indexer_url and s.wazuh_indexer_user and s.wazuh_indexer_password):
        pytest.skip("SOCI_WAZUH_INDEXER_URL/USER/PASSWORD are required")
    return s


@pytest.fixture(scope="session")
def windows_settings():
    import sys
    if not _enabled("SOCI_IT_WINDOWS"):
        pytest.skip("set SOCI_IT_WINDOWS=1 to run live Windows event log tests")
    if sys.platform != "win32":
        pytest.skip("live Windows event log tests need Windows")
    return load_settings(llm="mock", backend="windows")
