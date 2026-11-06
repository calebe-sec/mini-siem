import pytest
import requests

from sentinel.llm.ollama_client import OllamaClient # type: ignore
from sentinel.llm.provider import LLMError, LLMTimeout, LLMUnavailable # type: ignore


class FakeResponse:
    def __init__(self, payload=None, status=200):
        self._payload, self.status = payload, status

    def raise_for_status(self):
        if self.status >= 400:
            raise requests.exceptions.HTTPError(f"{self.status}")

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


def patch_post(monkeypatch, result):
    seen = {}

    def fake_post(url, json=None, timeout=None):
        seen.update(url=url, body=json, timeout=timeout)
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(requests, "post", fake_post)
    return seen


def test_request_shape_and_return(monkeypatch):
    seen = patch_post(monkeypatch, FakeResponse({"message": {"content": '{"a": 1}'}}))
    out = OllamaClient().complete([{"role": "user", "content": "hi"}], {"type": "object"})
    assert out == '{"a": 1}'
    assert seen["url"].endswith("/api/chat")
    assert seen["body"]["stream"] is False
    assert seen["body"]["format"] == {"type": "object"}
    assert seen["body"]["options"]["temperature"] == 0
    assert seen["timeout"] == (3.0, 120.0)


@pytest.mark.parametrize("raised,expected", [
    (requests.exceptions.ConnectionError(), LLMUnavailable),
    (requests.exceptions.ReadTimeout(), LLMTimeout),
])
def test_network_errors_are_mapped(monkeypatch, raised, expected):
    patch_post(monkeypatch, raised)
    with pytest.raises(expected):
        OllamaClient().complete([], {})


def test_http_error_and_bad_shape(monkeypatch):
    patch_post(monkeypatch, FakeResponse({}, status=500))
    with pytest.raises(LLMError):
        OllamaClient().complete([], {})
    patch_post(monkeypatch, FakeResponse({"oops": 1}))
    with pytest.raises(LLMError):
        OllamaClient().complete([], {})