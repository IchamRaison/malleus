from __future__ import annotations

import httpx
import pytest
import time
from types import SimpleNamespace

from malleus.adapters.base import AdapterError
from malleus.adapters.nvidia import NvidiaAdapter
from malleus.adapters.ollama import OllamaAdapter
from malleus.adapters.openai_compatible import OpenAICompatibleAdapter
from malleus.runner import resolve_adapter
from malleus.schemas import AdapterType, RequestConfig, TargetConfig


def make_target(adapter: AdapterType, env_name: str) -> TargetConfig:
    return TargetConfig(
        name="target",
        adapter=adapter,
        model="model",
        base_url="https://example.test/v1",
        api_key_env=env_name,
        system_prompt="system",
    )


def test_openai_compatible_adapter_uses_env_and_extracts_text(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "token-123")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer token-123"
        assert request.url == httpx.URL("https://example.test/v1/chat/completions")
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "I cannot help with that."}}]},
        )

    adapter = OpenAICompatibleAdapter(
        make_target("openai_compatible", "OPENAI_API_KEY"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    try:
        assert adapter.generate("prompt") == "I cannot help with that."
    finally:
        adapter.close()


def test_nvidia_adapter_supports_content_blocks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NVIDIA_API_KEY", "token-456")

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {"message": {"content": [{"type": "text", "text": "Refusal "}, {"type": "text", "text": "text"}]}}
                ]
            },
        )

    adapter = NvidiaAdapter(
        make_target("nvidia", "NVIDIA_API_KEY"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    try:
        assert adapter.generate("prompt") == "Refusal text"
    finally:
        adapter.close()


def test_adapter_raises_on_missing_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(AdapterError, match="missing API key"):
        OpenAICompatibleAdapter(make_target("openai_compatible", "OPENAI_API_KEY"))



def test_adapter_extracts_reasoning_content_when_content_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "token-789")

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"choices": [{"message": {"reasoning_content": "reasoning-only text"}}]},
        )

    adapter = OpenAICompatibleAdapter(
        make_target("openai_compatible", "OPENAI_API_KEY"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    try:
        assert adapter.generate("prompt") == "reasoning-only text"
    finally:
        adapter.close()


def test_openai_compatible_adapter_retries_empty_length_response_with_larger_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "token-789")
    requested_max_tokens: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = request.read()
        import json

        body = json.loads(payload)
        requested_max_tokens.append(body["max_tokens"])
        if len(requested_max_tokens) == 1:
            return httpx.Response(
                200,
                json={"choices": [{"finish_reason": "length", "message": {"role": "assistant"}}]},
            )
        return httpx.Response(200, json={"choices": [{"message": {"content": "Recovered answer."}}]})

    target = make_target("openai_compatible", "OPENAI_API_KEY").model_copy(
        update={"request": RequestConfig(max_tokens=2048)}
    )
    adapter = OpenAICompatibleAdapter(
        target,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    try:
        assert adapter.generate("prompt") == "Recovered answer."
    finally:
        adapter.close()
    assert requested_max_tokens == [2048, 8192]


def test_openai_compatible_adapter_extracts_refusal_field(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "token-789")

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"message": {"refusal": "I cannot help with that."}}]})

    adapter = OpenAICompatibleAdapter(
        make_target("openai_compatible", "OPENAI_API_KEY"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    try:
        assert adapter.generate("prompt") == "I cannot help with that."
    finally:
        adapter.close()


def test_openai_compatible_adapter_retries_transient_http_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "token-789")
    monkeypatch.setattr("malleus.adapters.base.time.sleep", lambda _seconds: None)
    statuses: list[int] = []

    def handler(_: httpx.Request) -> httpx.Response:
        statuses.append(503 if len(statuses) == 0 else 200)
        if len(statuses) == 1:
            return httpx.Response(503, json={"error": "temporarily unavailable"})
        return httpx.Response(200, json={"choices": [{"message": {"content": "Recovered after retry."}}]})

    adapter = OpenAICompatibleAdapter(
        make_target("openai_compatible", "OPENAI_API_KEY"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    try:
        assert adapter.generate("prompt") == "Recovered after retry."
    finally:
        adapter.close()
    assert statuses == [503, 200]


def test_openai_compatible_adapter_enforces_total_request_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "token-789")

    def handler(_: httpx.Request) -> httpx.Response:
        time.sleep(1)
        return httpx.Response(200, json={"choices": [{"message": {"content": "late"}}]})

    target = make_target("openai_compatible", "OPENAI_API_KEY").model_copy(
        update={"request": RequestConfig(timeout=0.01)}
    )
    adapter = OpenAICompatibleAdapter(
        target,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    try:
        with pytest.raises(AdapterError, match="adapter request exceeded total timeout"):
            adapter.generate("prompt")
    finally:
        adapter.close()


def test_adapter_registry_resolves_current_public_names() -> None:
    assert resolve_adapter(make_target("openai_compatible", "OPENAI_API_KEY")) is OpenAICompatibleAdapter
    assert resolve_adapter(make_target("nvidia", "NVIDIA_API_KEY")) is NvidiaAdapter
    assert resolve_adapter(make_target("ollama", "")) is OllamaAdapter


def test_adapter_registry_rejects_unknown_name_with_clear_error() -> None:
    target = SimpleNamespace(adapter="missing.adapter:Factory")
    with pytest.raises(NotImplementedError, match="unknown adapter 'missing.adapter:Factory'"):
        resolve_adapter(target)  # type: ignore[arg-type]
