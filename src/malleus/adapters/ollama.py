from __future__ import annotations

import httpx

from malleus.adapters.base import AdapterError, BaseAdapter
from malleus.schemas import TargetConfig


class OllamaAdapter(BaseAdapter):
    def __init__(self, target: TargetConfig, client: httpx.Client | None = None) -> None:
        super().__init__(target, client=client)

    def endpoint(self) -> str:
        return f"{self.target.base_url.rstrip('/')}/api/chat"

    def build_payload(self, prompt: str) -> dict[str, object]:
        return {
            "model": self.target.model,
            "messages": self.build_messages(prompt),
            "stream": False,
            "options": {
                "temperature": self.target.request.temperature,
                "top_p": self.target.request.top_p,
                "num_predict": self.target.request.max_tokens,
            },
        }

    def generate(self, prompt: str) -> str:
        response = self.client.post(self.endpoint(), json=self.build_payload(prompt))
        response.raise_for_status()
        payload = response.json()
        message = payload.get("message")
        if not isinstance(message, dict) or not isinstance(message.get("content"), str):
            raise AdapterError("ollama response message payload was missing or malformed")
        return message["content"]
