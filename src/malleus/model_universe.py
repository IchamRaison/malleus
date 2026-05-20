from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from malleus.target_store import derive_api_key_env


MODEL_UNIVERSE_SCHEMA_VERSION = "malleus.model_universe.v1"


@dataclass(frozen=True)
class ProviderSpec:
    provider_id: str
    label: str
    base_url: str
    api_key_env: str
    models: tuple[str, ...]
    adapter: str = "openai_compatible"
    default_max_tokens: int = 2048
    endpoint_family: str = "openai_chat_completions"
    capabilities: tuple[str, ...] = ("text",)
    supports_model_listing: bool = True
    protocol_tested: bool = True
    live_verified_by_maintainer: bool = False
    verification_notes: str = "Protocol-tested with provider-free OpenAI-compatible request/response fixtures."

    def to_cli_preset(self) -> dict[str, object]:
        return {
            "label": self.label,
            "base_url": self.base_url,
            "api_key_env": self.api_key_env,
            "models": list(self.models),
            "default_max_tokens": self.default_max_tokens,
            "endpoint_family": self.endpoint_family,
            "capabilities": list(self.capabilities),
            "supports_model_listing": self.supports_model_listing,
            "protocol_tested": self.protocol_tested,
            "live_verified_by_maintainer": self.live_verified_by_maintainer,
            "verification_notes": self.verification_notes,
        }

    def to_public_dict(self) -> dict[str, object]:
        return {
            "provider_id": self.provider_id,
            "label": self.label,
            "adapter": self.adapter,
            "base_url": self.base_url,
            "api_key_env": self.api_key_env,
            "models": list(self.models),
            "default_max_tokens": self.default_max_tokens,
            "endpoint_family": self.endpoint_family,
            "capabilities": list(self.capabilities),
            "supports_model_listing": self.supports_model_listing,
            "protocol_tested": self.protocol_tested,
            "live_verified_by_maintainer": self.live_verified_by_maintainer,
            "verification_notes": self.verification_notes,
        }


_PROVIDER_SPECS: tuple[ProviderSpec, ...] = (
    ProviderSpec(
        provider_id="openai",
        label="OpenAI",
        base_url="https://api.openai.com/v1",
        api_key_env="OPENAI_API_KEY",
        models=("gpt-5.1-mini", "gpt-5.1", "gpt-4.1-mini"),
        capabilities=("text", "vision"),
    ),
    ProviderSpec(
        provider_id="deepseek",
        label="DeepSeek",
        base_url="https://api.deepseek.com/v1",
        api_key_env="DEEPSEEK_API_KEY",
        models=("deepseek-v4-flash", "deepseek-chat", "deepseek-reasoner"),
        live_verified_by_maintainer=True,
        verification_notes="Protocol-tested locally; maintainer live smoke currently uses DeepSeek when credentials are available.",
    ),
    ProviderSpec(
        provider_id="openrouter",
        label="OpenRouter",
        base_url="https://openrouter.ai/api/v1",
        api_key_env="OPENROUTER_API_KEY",
        models=("openai/gpt-4.1-mini", "deepseek/deepseek-chat", "anthropic/claude-sonnet-4.5"),
        verification_notes="Protocol-tested locally; live verification depends on user/community credentials.",
    ),
    ProviderSpec(
        provider_id="groq",
        label="Groq",
        base_url="https://api.groq.com/openai/v1",
        api_key_env="GROQ_API_KEY",
        models=("llama-3.3-70b-versatile", "openai/gpt-oss-120b", "moonshotai/kimi-k2-instruct"),
        verification_notes="Protocol-tested locally; live verification depends on user/community credentials.",
    ),
    ProviderSpec(
        provider_id="together",
        label="Together AI",
        base_url="https://api.together.xyz/v1",
        api_key_env="TOGETHER_API_KEY",
        models=("meta-llama/Llama-3.3-70B-Instruct-Turbo", "Qwen/Qwen3-235B-A22B-Instruct-2507"),
        verification_notes="Protocol-tested locally; live verification depends on user/community credentials.",
    ),
    ProviderSpec(
        provider_id="fireworks",
        label="Fireworks AI",
        base_url="https://api.fireworks.ai/inference/v1",
        api_key_env="FIREWORKS_API_KEY",
        models=("accounts/fireworks/models/llama-v3p3-70b-instruct", "accounts/fireworks/models/deepseek-v3"),
        verification_notes="Protocol-tested locally; live verification depends on user/community credentials.",
    ),
    ProviderSpec(
        provider_id="mistral",
        label="Mistral",
        base_url="https://api.mistral.ai/v1",
        api_key_env="MISTRAL_API_KEY",
        models=("mistral-large-latest", "mistral-small-latest"),
        verification_notes="Protocol-tested locally; live verification depends on user/community credentials.",
    ),
)


def provider_catalog() -> tuple[ProviderSpec, ...]:
    return _PROVIDER_SPECS


def provider_ids(*, include_custom: bool = False) -> list[str]:
    values = [spec.provider_id for spec in _PROVIDER_SPECS]
    if include_custom:
        values.append("custom")
    return values


def provider_spec(provider_id: str) -> ProviderSpec | None:
    normalized = provider_id.strip().lower()
    for spec in _PROVIDER_SPECS:
        if spec.provider_id == normalized:
            return spec
    return None


def provider_presets_for_cli() -> dict[str, dict[str, object]]:
    return {spec.provider_id: spec.to_cli_preset() for spec in _PROVIDER_SPECS}


def infer_provider_id(base_url: str | None, provider_hint: str | None = None) -> str:
    hinted = (provider_hint or "").strip().lower()
    if hinted and hinted != "custom":
        return hinted if provider_spec(hinted) is not None else "custom"
    host = (urlsplit(base_url or "").hostname or "").lower()
    for spec in _PROVIDER_SPECS:
        spec_host = (urlsplit(spec.base_url).hostname or "").lower()
        if host == spec_host or host.endswith(f".{spec_host}"):
            return spec.provider_id
    return "custom"


def model_universe_metadata(
    *,
    provider_id: str,
    model: str,
    base_url: str,
    api_key_env: str | None = None,
) -> dict[str, object]:
    resolved_provider_id = infer_provider_id(base_url, provider_id)
    spec = provider_spec(resolved_provider_id)
    provider_label = spec.label if spec else "Custom OpenAI-compatible provider"
    models = list(spec.models) if spec else []
    return {
        "schema_version": MODEL_UNIVERSE_SCHEMA_VERSION,
        "provider_id": resolved_provider_id,
        "provider_label": provider_label,
        "adapter": spec.adapter if spec else "openai_compatible",
        "endpoint_family": spec.endpoint_family if spec else "openai_chat_completions",
        "configured_model": model,
        "model_source": "catalog" if model in models else "custom_or_discovered",
        "catalog_models": models[:25],
        "capabilities": list(spec.capabilities) if spec else ["text"],
        "api_key_env": api_key_env or (spec.api_key_env if spec else derive_api_key_env(resolved_provider_id)),
        "operational_error_policy": "Provider/auth/quota/network/runtime errors are run conditions, not model behavior findings.",
        "protocol_tested": bool(spec.protocol_tested) if spec else False,
        "live_verified_by_maintainer": bool(spec.live_verified_by_maintainer) if spec else False,
    }


def provider_compatibility_matrix() -> list[dict[str, object]]:
    return [
        {
            "provider_id": spec.provider_id,
            "label": spec.label,
            "adapter": spec.adapter,
            "endpoint_family": spec.endpoint_family,
            "protocol_tested": spec.protocol_tested,
            "live_verified_by_maintainer": spec.live_verified_by_maintainer,
            "supports_model_listing": spec.supports_model_listing,
            "api_key_env": spec.api_key_env,
            "default_models": list(spec.models),
            "notes": spec.verification_notes,
        }
        for spec in _PROVIDER_SPECS
    ]
