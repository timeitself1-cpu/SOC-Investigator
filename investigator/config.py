"""Configuration from environment variables and an optional local `.env` file.

Precedence: real environment variables > .env file > defaults.
Secrets are held as SecretStr and never included in logs or reprs.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, SecretStr, field_validator

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent
# Demo fixtures ship inside the package so a wheel install can run the demo.
PACKAGED_CASES = PACKAGE_DIR / "cases"
PACKAGED_BENCHMARKS = PACKAGE_DIR / "benchmarks"
# Synthetic, schema-faithful Windows event XML for the windows-replay demo/tests.
PACKAGED_WINDOWS_SAMPLES = PACKAGE_DIR / "windows_samples" / "demo"


def _is_source_checkout() -> bool:
    return (PROJECT_ROOT / "pyproject.toml").is_file() and (PROJECT_ROOT / "investigator").is_dir()


def default_reports_dir() -> Path:
    """Source checkout: ./reports. Installed package: a per-user data directory,
    never site-packages."""
    if _is_source_checkout():
        return PROJECT_ROOT / "reports"
    local = os.environ.get("LOCALAPPDATA")
    if local:
        return Path(local) / "soc-investigator" / "reports"
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "soc-investigator" / "reports"


def _read_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        values[key.strip()] = val
    return values


class Settings(BaseModel):
    # Modes
    llm: Literal["ollama", "mock"] = "ollama"
    # fixture: bundled demo incidents. windows: this computer's event logs (read-only,
    # Windows only). windows-replay: recorded Windows event XML (tests, offline
    # replay of a real machine's exports). wazuh: optional SIEM integration.
    backend: Literal["fixture", "windows", "windows-replay", "wazuh"] = "fixture"

    # Web
    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)
    max_concurrent_runs: int = Field(default=2, ge=1, le=8)
    max_retained_runs: int = Field(default=100, ge=8, le=1000)
    shutdown_grace_seconds: float = Field(default=10.0, ge=0.0, le=300.0)

    # Paths
    cases_dir: Path = PACKAGED_CASES
    reports_dir: Path = Field(default_factory=default_reports_dir)

    # Agent bounds
    max_steps: int = Field(default=12, ge=1, le=30)
    max_repair_attempts: int = Field(default=2, ge=0, le=5)
    max_evidence: int = Field(default=150, ge=10, le=1000)
    max_results_per_tool: int = Field(default=25, ge=1, le=50)
    max_window_minutes: int = Field(default=60, ge=1, le=240)
    max_lookback_hours: int = Field(default=24, ge=1, le=168)
    # Wall-clock budget for evidence gathering (the final report call is still made).
    max_investigation_seconds: int = Field(default=900, ge=10, le=7200)
    # Stored audit copies of prompts/responses are clipped only beyond this size;
    # any clipping is recorded with the original length and SHA-256.
    audit_max_chars: int = Field(default=200_000, ge=1_000, le=5_000_000)

    # Reasoning contract (v0.3.1)
    # The application collects host context and the trigger's process tree before
    # the model's first step (system-initiated, audited like the trigger seed).
    baseline_collection: bool = True
    # One bounded revision round when validation rejected claims/techniques/findings.
    validation_revision: bool = True

    # Ollama
    ollama_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "qwen2.5:7b-instruct"
    ollama_temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    ollama_num_ctx: int = Field(default=16384, ge=2048, le=131072)
    ollama_timeout: float = Field(default=180.0, gt=0)
    ollama_keep_alive: str = "10m"
    ollama_seed: int = 42
    # Output bound; the prompt budget reserves this many tokens for the answer.
    ollama_num_predict: int = Field(default=2048, ge=256, le=16384)
    # Conservative characters-per-token used to keep prompts inside num_ctx when
    # no tokenizer is available. Measured with the Qwen2.5 tokenizer, encoded /
    # hex telemetry costs 1.7-2.5 chars per token, so values above 2.0 are
    # clamped to 2.0 (an older .env with 3.0 keeps working, safely).
    prompt_chars_per_token: float = Field(default=2.0, ge=1.0, le=2.0)
    # Send the response JSON schema as Ollama's `format` (Ollama >= 0.5).
    ollama_structured_output: bool = True

    # Windows event logs (backend=windows / windows-replay)
    windows_replay_dir: Path | None = None
    windows_signal_lookback_hours: int = Field(default=24, ge=1, le=720)
    windows_scan_limit: int = Field(default=2000, ge=50, le=5000)  # events read per source per signal scan
    windows_discovery_days: int = Field(default=7, ge=1, le=90)    # "recent" window for source discovery
    windows_discovery_refresh_seconds: int = Field(default=300, ge=10, le=86400)

    # Wazuh (read-only). Credentials only from env / .env — never hardcoded.
    wazuh_indexer_url: str | None = None
    wazuh_indexer_user: str | None = None
    wazuh_indexer_password: SecretStr | None = None
    wazuh_api_url: str | None = None
    wazuh_api_user: str | None = None
    wazuh_api_password: SecretStr | None = None
    wazuh_verify_tls: bool = True
    wazuh_ca_bundle: str | None = None
    wazuh_alerts_index: str = "wazuh-alerts-*"
    wazuh_events_index: str = "wazuh-alerts-*"
    wazuh_min_alert_level: int = Field(default=10, ge=0, le=16)
    wazuh_alert_lookback_hours: int = Field(default=24, ge=1, le=168)
    wazuh_timeout: float = Field(default=30.0, gt=0, le=300)

    @field_validator("prompt_chars_per_token", mode="before")
    @classmethod
    def _cap_chars_per_token(cls, value: object) -> object:
        try:
            return min(float(value), 2.0)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return value

    def safe_dict(self) -> dict[str, object]:
        """Settings suitable for display/logging — secrets redacted."""
        data = self.model_dump(mode="json")
        for key in list(data):
            if "password" in key:
                data[key] = "***" if data[key] else None
        return data


_ENV_MAP = {name: f"SOCI_{name.upper()}" for name in Settings.model_fields}


def load_settings(env_file: Path | None = None, **overrides: object) -> Settings:
    # .env is read from the source checkout, or from the current directory for
    # an installed package.
    default_env = PROJECT_ROOT / ".env" if _is_source_checkout() else Path.cwd() / ".env"
    file_values = _read_dotenv(env_file or default_env)
    raw: dict[str, object] = {}
    for field, env_name in _ENV_MAP.items():
        if env_name in os.environ:
            raw[field] = os.environ[env_name]
        elif env_name in file_values:
            raw[field] = file_values[env_name]
    raw.update({k: v for k, v in overrides.items() if v is not None})
    for key in ("wazuh_indexer_password", "wazuh_api_password"):
        if raw.get(key) == "":
            raw[key] = None
    return Settings.model_validate(raw)
