"""Configuration from environment variables and an optional local `.env` file.

Precedence: real environment variables > .env file > defaults.
Secrets are held as SecretStr and never included in logs or reprs.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, SecretStr

PROJECT_ROOT = Path(__file__).resolve().parent.parent


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
    backend: Literal["fixture", "wazuh"] = "fixture"

    # Web
    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)
    max_concurrent_runs: int = Field(default=2, ge=1, le=8)
    max_retained_runs: int = Field(default=100, ge=8, le=1000)

    # Paths
    cases_dir: Path = PROJECT_ROOT / "cases"
    reports_dir: Path = PROJECT_ROOT / "reports"

    # Agent bounds
    max_steps: int = Field(default=12, ge=1, le=30)
    max_repair_attempts: int = Field(default=2, ge=0, le=5)
    max_evidence: int = Field(default=150, ge=10, le=1000)
    max_results_per_tool: int = Field(default=25, ge=1, le=50)
    max_window_minutes: int = Field(default=60, ge=1, le=240)
    max_lookback_hours: int = Field(default=24, ge=1, le=168)

    # Ollama
    ollama_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "qwen2.5:7b-instruct"
    ollama_temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    ollama_num_ctx: int = Field(default=16384, ge=2048, le=131072)
    ollama_timeout: float = Field(default=180.0, gt=0)
    ollama_keep_alive: str = "10m"
    ollama_seed: int = 42

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

    def safe_dict(self) -> dict[str, object]:
        """Settings suitable for display/logging — secrets redacted."""
        data = self.model_dump(mode="json")
        for key in list(data):
            if "password" in key:
                data[key] = "***" if data[key] else None
        return data


_ENV_MAP = {name: f"SOCI_{name.upper()}" for name in Settings.model_fields}


def load_settings(env_file: Path | None = None, **overrides: object) -> Settings:
    file_values = _read_dotenv(env_file or PROJECT_ROOT / ".env")
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
