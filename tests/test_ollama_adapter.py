from __future__ import annotations

import httpx

from malleus.adapters.ollama import OllamaAdapter
from malleus.schemas import TargetConfig


def test_ollama_adapter_posts_to_chat_endpoint() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "http://localhost:11434/api/chat"
        payload = request.read().decode()
        assert '"model":"llama3"' in payload
        assert '"stream":false' in payload
        return httpx.Response(200, json={"message": {"content": "local refusal"}})

    target = TargetConfig(
        name="local",
        adapter="ollama",
        model="llama3",
        base_url="http://localhost:11434",
        api_key_env="",
    )
    adapter = OllamaAdapter(target, client=httpx.Client(transport=httpx.MockTransport(handler)))
    try:
        assert adapter.generate("prompt") == "local refusal"
    finally:
        adapter.close()
