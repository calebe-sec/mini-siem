from __future__ import annotations

import requests

from sentinel.llm.provider import LLMError, LLMTimeout, LLMUnavailable


class OllamaClient:
    """Talks to a local Ollama server over plain HTTP (/api/chat, no streaming)."""

    def __init__(
        self,
        model: str = "qwen2.5:3b",
        host: str = "http://localhost:11434",
        connect_timeout: float = 3.0,
        read_timeout: float = 120.0,
        num_ctx: int = 4096,
        num_predict: int = 400,
        keep_alive: str = "10m",
    ) -> None:
        self.model = model
        self.host = host.rstrip("/")
        self.timeout = (connect_timeout, read_timeout)
        self.num_ctx = num_ctx          # set explicitly: the default can silently cut the prompt
        self.num_predict = num_predict  # cap the answer length (speed on CPU)
        self.keep_alive = keep_alive    # keep the model in RAM between alerts

    def is_available(self) -> bool:
        """True if the Ollama server answers and the model is installed."""
        try:
            response = requests.get(f"{self.host}/api/tags", timeout=self.timeout[0])
            response.raise_for_status()
            names = [m.get("name", "") for m in response.json().get("models", [])]
        except (requests.exceptions.RequestException, ValueError):
            return False
        return any(name == self.model or name.split(":")[0] == self.model for name in names)

    def complete(self, messages: list[dict], schema: dict) -> str:
        body = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "format": schema,
            "keep_alive": self.keep_alive,
            "options": {
                "temperature": 0,
                "num_ctx": self.num_ctx,
                "num_predict": self.num_predict,
            },
        }
        try:
            response = requests.post(f"{self.host}/api/chat", json=body, timeout=self.timeout)
            response.raise_for_status()
            return response.json()["message"]["content"]
        except requests.exceptions.ConnectionError as exc:
            raise LLMUnavailable(f"cannot reach Ollama at {self.host}") from exc
        except requests.exceptions.Timeout as exc:
            raise LLMTimeout("Ollama took too long to answer") from exc
        except requests.exceptions.HTTPError as exc:
            raise LLMError(f"Ollama returned an error: {exc}") from exc
        except (KeyError, ValueError) as exc:
            raise LLMError("unexpected Ollama response shape") from exc