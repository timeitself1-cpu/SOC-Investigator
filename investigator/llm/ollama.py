"""Small Ollama HTTP client. No large abstraction layer.

Uses /api/chat with a JSON-schema `format` (Ollama >= 0.5 structured outputs)
when the caller provides a schema, otherwise `format="json"`. Output length is
bounded by `num_predict`; a response cut off at that bound is reported via
`done_reason == "length"` and treated by the agent as unusable, not repaired
silently. Errors are classified and never carry raw response text.
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from ..config import Settings
from ..errors import ClassifiedError, classify_exception, classify_http_status
from .base import LLMResponse


class OllamaError(ClassifiedError):
    pass


class OllamaModel:
    supports_schema = True

    def __init__(self, settings: Settings, client: httpx.Client | None = None) -> None:
        self.s = settings
        self.name = settings.ollama_model
        self._client = client or httpx.Client(base_url=settings.ollama_url.rstrip("/"), timeout=settings.ollama_timeout)

    def build_payload(self, messages: list[dict[str, str]], *, temperature: float | None = None,
                      schema: dict[str, Any] | None = None) -> dict[str, Any]:
        return {
            "model": self.s.ollama_model,
            "messages": messages,
            "stream": False,
            "format": schema if (schema and self.s.ollama_structured_output) else "json",
            "keep_alive": self.s.ollama_keep_alive,
            "options": {
                "temperature": self.s.ollama_temperature if temperature is None else temperature,
                "num_ctx": self.s.ollama_num_ctx,
                "num_predict": self.s.ollama_num_predict,
                "seed": self.s.ollama_seed,
            },
        }

    def complete(self, messages: list[dict[str, str]], *, temperature: float | None = None,
                 schema: dict[str, Any] | None = None) -> LLMResponse:
        payload = self.build_payload(messages, temperature=temperature, schema=schema)
        t0 = time.perf_counter()
        try:
            resp = self._client.post("/api/chat", json=payload)
        except httpx.HTTPError as exc:
            c = classify_exception(exc)
            raise OllamaError(c.kind, f"Ollama request failed: {c.safe_message}") from None
        if resp.status_code >= 400:
            kind = classify_http_status(resp.status_code, resp.text)
            if resp.status_code == 404:
                kind = "not_found"  # model not pulled
            raise OllamaError(kind, f"Ollama returned HTTP {resp.status_code}", status_code=resp.status_code)
        try:
            data = resp.json()
            content = data["message"]["content"]
            if not isinstance(content, str):
                raise ValueError("content is not text")
        except (ValueError, KeyError, TypeError):
            raise OllamaError("invalid_response", "Ollama returned an invalid chat response") from None
        done_reason = data.get("done_reason")
        if not content.strip() and done_reason != "length":
            raise OllamaError("model_output", "Ollama returned an empty response")
        return LLMResponse(
            text=content, model=data.get("model", self.s.ollama_model),
            prompt_tokens=data.get("prompt_eval_count"), completion_tokens=data.get("eval_count"),
            duration_ms=(time.perf_counter() - t0) * 1000,
            meta={"done_reason": done_reason if isinstance(done_reason, str) else None},
        )

    def health(self) -> tuple[bool, str]:
        try:
            resp = self._client.get("/api/tags")
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            c = classify_exception(exc)
            return False, f"Ollama health request failed ({c.kind}): {c.safe_message}"
        try:
            data = resp.json()
            models = [m["name"] for m in data["models"]]
            if not all(isinstance(m, str) for m in models):
                raise ValueError("invalid model name")
        except (ValueError, KeyError, TypeError):
            return False, "Ollama returned an invalid model list"
        # Different tags can have very different sizes/capabilities. A sibling
        # tag is not proof that the configured model is installed.
        expected = self.s.ollama_model
        if ":" not in expected.rsplit("/", 1)[-1]:
            expected += ":latest"
        if expected not in models and self.s.ollama_model not in models:
            return False, f"model {self.s.ollama_model!r} not pulled. Run: ollama pull {self.s.ollama_model}"
        return True, "ok"
