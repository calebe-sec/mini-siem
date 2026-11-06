from __future__ import annotations

from typing import Protocol


class LLMError(Exception):
    """Base class for every failure of an LLM client."""


class LLMUnavailable(LLMError):
    """The server could not be reached (Ollama is down, wrong host...)."""


class LLMTimeout(LLMError):
    """The server answered too slowly."""


class LLMClient(Protocol):
    """Anything that can turn chat messages into a JSON string constrained by a schema."""

    model: str

    def complete(self, messages: list[dict], schema: dict) -> str: ...