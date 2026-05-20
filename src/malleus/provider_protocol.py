from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from malleus.model_universe import ProviderSpec, provider_catalog


@dataclass(frozen=True)
class ProviderProtocolCase:
    provider_id: str
    chat_url: str
    models_url: str
    auth_header: str
    success_content: str
    error_status: int
    error_class: str


def build_provider_protocol_case(spec: ProviderSpec) -> ProviderProtocolCase:
    base = spec.base_url.rstrip("/")
    return ProviderProtocolCase(
        provider_id=spec.provider_id,
        chat_url=f"{base}/chat/completions",
        models_url=f"{base}/models",
        auth_header="Authorization",
        success_content="MALLEUS_LOCAL_OK",
        error_status=401,
        error_class="auth",
    )


def provider_protocol_cases() -> list[ProviderProtocolCase]:
    return [build_provider_protocol_case(spec) for spec in provider_catalog()]


def validate_openai_compatible_response(payload: dict[str, Any]) -> tuple[bool, str]:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        return False, "missing choices list"
    first = choices[0]
    if not isinstance(first, dict):
        return False, "choice is not an object"
    message = first.get("message")
    if not isinstance(message, dict):
        return False, "missing message object"
    content = message.get("content")
    if isinstance(content, str):
        return True, content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict) and item.get("type") in {"text", "output_text"} and isinstance(item.get("text"), str):
                parts.append(item["text"])
        if parts:
            return True, "\n".join(parts)
    return False, "missing text content"


def provider_protocol_report() -> dict[str, Any]:
    cases = provider_protocol_cases()
    return {
        "schema_version": "malleus.provider_protocol.v1",
        "provider_calls_enabled": False,
        "case_count": len(cases),
        "cases": [
            {
                "provider_id": case.provider_id,
                "chat_url": case.chat_url,
                "models_url": case.models_url,
                "auth_header": case.auth_header,
                "host": urlsplit(case.chat_url).hostname or "",
                "expected_success_content": case.success_content,
                "expected_error_status": case.error_status,
                "expected_error_class": case.error_class,
            }
            for case in cases
        ],
    }
