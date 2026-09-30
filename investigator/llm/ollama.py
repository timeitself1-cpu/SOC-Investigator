"""Small Ollama HTTP client. No large abstraction layer.

Uses the /api/chat endpoint with format=json to require a JSON object back.
Deterministic defaults (temperature 0, fixed seed).
"""

from __future__ import annotations

import time

import httpx

from ..config import Settings
from .base import LLMResponse


class OllamaError(RuntimeError):
    pass


class OllamaModel:
    def __init__(self, settings: Settings, client: httpx.Client | None = None) -> None:
        self.s = settings
        self.name = settings.ollama_model
        self._client = client or httpx.Client(base_url=settings.ollama_url.rstrip("/"), timeout=settings.ollama_timeout)

    def complete(self, messages: list[dict[str, str]], *, temperature: float | None = None) -> LLMResponse:
        payload = {
            "model": self.s.ollama_model,
            "messages": messages,
            "stream": False,
            "format": "json",
            "keep_alive": self.s.ollama_keep_alive,
            "options": {
                "temperature": self.s.ollama_temperature if temperature is None else temperature,
                "num_ctx": self.s.ollama_num_ctx,
                "seed": self.s.ollama_seed,
            },
        }
        t0 = time.perf_counter()
        try:
            resp = self._client.post("/api/chat", json=payload)
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise OllamaError(f"Ollama returned HTTP {exc.response.status_code}") from exc
        except httpx.HTTPError as exc:
            raise OllamaError(f"Ollama request failed ({type(exc).__name__})") from exc
        try:
            data = resp.json()
            content = data["message"]["content"]
            if not isinstance(content, str) or not content.strip():
                raise ValueError("empty response")
        except (ValueError, KeyError, TypeError) as exc:
            raise OllamaError("Ollama returned an invalid chat response") from exc
        return LLMResponse(
            text=content, model=data.get("model", self.s.ollama_model),
            prompt_tokens=data.get("prompt_eval_count"), completion_tokens=data.get("eval_count"),
            duration_ms=(time.perf_counter() - t0) * 1000,
        )

    def health(self) -> tuple[bool, str]:
        try:
            resp = self._client.get("/api/tags")
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            return False, f"Ollama health request failed ({type(exc).__name__})"
        try:
            data = resp.json()
            models = [m["name"] for m in data["models"]]
            if not all(isinstance(m, str) for m in models):
                raise ValueError("invalid model name")
        except (ValueError, KeyError, TypeError) as exc:
            return False, "Ollama returned an invalid model list"
        # Different tags can have very different sizes/capabilities. A sibling
        # tag is not proof that the configured model is installed.
        expected = self.s.ollama_model
        if ":" not in expected.rsplit("/", 1)[-1]:
            expected += ":latest"
        if expected not in models and self.s.ollama_model not in models:
            return False, f"model {self.s.ollama_model!r} not pulled. Run: ollama pull {self.s.ollama_model}"
        return True, "ok"
