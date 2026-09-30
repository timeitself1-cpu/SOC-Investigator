"""LLM interface. The agent depends only on this."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class LLMResponse:
    text: str
    model: str
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    duration_ms: float = 0.0
    meta: dict = field(default_factory=dict)


class InvestigatorModel(Protocol):
    name: str

    def complete(self, messages: list[dict[str, str]], *, temperature: float | None = None) -> LLMResponse:
        """Return a completion for a list of {role, content} messages."""
        ...
