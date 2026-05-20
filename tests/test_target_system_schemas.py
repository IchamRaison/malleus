from __future__ import annotations

from pathlib import Path

import pytest

from malleus.datasets import load_target_config
from malleus.schemas import HarnessArtifactRef, HarnessDiff, HarnessResult, HarnessToolCall, HarnessTraceAction, TargetConfig
from malleus.target_store import add_managed_target, show_managed_target


def test_legacy_target_yaml_defaults_to_chat_completion(tmp_path: Path) -> None:
    target = tmp_path / "target.yaml"
    target.write_text(
        "name: legacy\nadapter: openai_compatible\nmodel: m\nbase_url: https://example.test/v1\napi_key_env: OPENAI_API_KEY\n",
        encoding="utf-8",
    )

    config = load_target_config(target)

    assert config.target_type == "chat_completion"
    assert config.adapter == "openai_compatible"
    assert config.model == "m"
    assert config.base_url == "https://example.test/v1"


def test_direct_chat_completion_constructor_remains_compatible() -> None:
    config = TargetConfig(
        name="direct",
        adapter="openai_compatible",
        model="m",
        base_url="https://example.test/v1",
        api_key_env="OPENAI_API_KEY",
    )

    assert config.target_type == "chat_completion"
    assert config.request.temperature == 0.0
    assert config.request.timeout == 120.0
    assert config.request.max_tokens == 256


def test_vision_model_target_uses_chat_compatible_config_shape() -> None:
    config = TargetConfig.model_validate(
        {
            "name": "vision",
            "target_type": "vision_model",
            "adapter": "openai_compatible",
            "model": "vision-model",
            "base_url": "https://example.test/v1/",
            "api_key_env": "OPENAI_API_KEY",
        }
    )

    assert config.target_type == "vision_model"
    assert config.adapter == "openai_compatible"
    assert config.base_url == "https://example.test/v1/"


def test_vision_model_target_requires_chat_compatible_config() -> None:
    with pytest.raises(ValueError, match="vision_model targets require"):
        TargetConfig.model_validate({"name": "vision", "target_type": "vision_model"})


@pytest.mark.parametrize(
    "base_url",
    [
        "https://user:pass@example.test/v1",
        "https://example.test/v1?api_key=SYNTHETIC-SK-OPENAI-SECRET",
        "https://example.test/v1?token=secret-token-value",
        "https://example.test/v1?api_key=",
    ],
)
def test_direct_chat_completion_rejects_secret_bearing_base_url(base_url: str) -> None:
    with pytest.raises(ValueError, match="base_url must not include|literal secret-like values"):
        TargetConfig.model_validate(
            {
                "name": "unsafe-chat",
                "adapter": "openai_compatible",
                "model": "m",
                "base_url": base_url,
                "api_key_env": "OPENAI_API_KEY",
            }
        )


@pytest.mark.parametrize(
    "system_prompt",
    [
        "Use Authorization: Bearer SYNTHETIC-SK-OPENAI-SECRET when calling tools.",
        "Internal token=secret-token-value must stay hidden.",
    ],
)
def test_direct_chat_completion_rejects_secret_bearing_system_prompt(system_prompt: str) -> None:
    with pytest.raises(ValueError, match="literal secret-like values are not allowed at system_prompt"):
        TargetConfig.model_validate(
            {
                "name": "unsafe-prompt",
                "adapter": "openai_compatible",
                "model": "m",
                "base_url": "https://example.test/v1",
                "api_key_env": "OPENAI_API_KEY",
                "system_prompt": system_prompt,
            }
        )


@pytest.mark.parametrize(
    "request_config",
    [
        {"timeout": 0},
        {"timeout": 600.1},
        {"max_tokens": 0},
        {"max_tokens": 32769},
        {"temperature": -0.1},
        {"temperature": 2.1},
        {"top_p": 1.1},
    ],
)
def test_request_config_rejects_invalid_runtime_values(request_config: dict[str, float | int]) -> None:
    with pytest.raises(ValueError):
        TargetConfig.model_validate(
            {
                "name": "bad-request",
                "adapter": "openai_compatible",
                "model": "m",
                "base_url": "https://example.test/v1",
                "api_key_env": "OPENAI_API_KEY",
                "request": request_config,
            }
        )


@pytest.mark.parametrize("base_url", ["not-a-url", "/tmp/socket", "ftp://example.test/v1"])
def test_direct_chat_completion_rejects_non_http_base_url(base_url: str) -> None:
    with pytest.raises(ValueError, match=r"base_url must be an http\(s\) URL"):
        TargetConfig.model_validate(
            {
                "name": "bad-url",
                "adapter": "openai_compatible",
                "model": "m",
                "base_url": base_url,
                "api_key_env": "OPENAI_API_KEY",
            }
        )


def test_managed_targets_remain_legacy_chat_compatible(tmp_path: Path) -> None:
    path = add_managed_target(
        {
            "name": "Managed Chat",
            "adapter": "openai_compatible",
            "model": "m",
            "base_url": "https://example.test/v1",
            "api_key_env": "MANAGED_CHAT_KEY",
        },
        tmp_path,
    )

    config = load_target_config(path)
    shown = show_managed_target("Managed Chat", tmp_path)

    assert config.target_type == "chat_completion"
    assert shown["adapter"] == "openai_compatible"
    assert shown["model"] == "m"


@pytest.mark.parametrize(
    ("target_type", "field_name", "config"),
    [
        (
            "rag_service",
            "rag_service",
            {"endpoint_url": "https://rag.example.test/query", "auth": {"api_key_env": "RAG_API_KEY"}, "index_name": "support"},
        ),
        (
            "tool_agent",
            "tool_agent",
            {"endpoint_url": "https://agent.example.test/run", "auth": {"bearer_token_env": "AGENT_TOKEN"}, "allowed_tools": ["search"]},
        ),
        (
            "workflow_harness",
            "workflow_harness",
            {"endpoint_url": "https://workflow.example.test/run", "workflow_id": "onboarding", "auth": {"api_key_env": "WORKFLOW_KEY"}},
        ),
        (
            "code_agent",
            "code_agent",
            {"workspace_path": "tests/fixtures/workspace", "command_env": {"GIT_TOKEN": "CODE_AGENT_GIT_TOKEN"}, "allowed_actions": ["diff"]},
        ),
    ],
)
def test_system_target_types_validate(target_type: str, field_name: str, config: dict[str, object]) -> None:
    target = TargetConfig.model_validate({"name": f"{target_type}-target", "target_type": target_type, field_name: config})

    assert target.target_type == target_type
    assert getattr(target, field_name) is not None
    assert target.adapter is None
    assert target.model is None
    assert target.base_url is None


def test_system_target_type_requires_matching_config() -> None:
    with pytest.raises(ValueError, match="rag_service targets require 'rag_service' config"):
        TargetConfig.model_validate({"name": "missing", "target_type": "rag_service"})


@pytest.mark.parametrize(
    ("target_type", "field_name", "config"),
    [
        ("rag_service", "rag_service", {"endpoint_url": "https://rag.example.test/query?api_key=SYNTHETIC-SK-OPENAI-SECRET"}),
        ("tool_agent", "tool_agent", {"endpoint_url": "https://agent.example.test/run", "auth": {"api_key_env": "sk_test_secret"}}),
        ("workflow_harness", "workflow_harness", {"endpoint_url": "https://workflow.example.test/run", "workflow_id": "wf", "metadata": {"token": "Bearer secret-token"}}),
        ("code_agent", "code_agent", {"workspace_path": "tests/fixtures/workspace", "command_env": {"TOKEN": "sk_test_secret"}}),
    ],
)
def test_system_target_configs_reject_literal_secrets(target_type: str, field_name: str, config: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="secret|environment variable name"):
        TargetConfig.model_validate({"name": "unsafe", "target_type": target_type, field_name: config})


@pytest.mark.parametrize(
    ("target_type", "field_name", "config"),
    [
        ("rag_service", "rag_service", {"endpoint_url": "https://user:pass@rag.example.test/query"}),
        ("tool_agent", "tool_agent", {"endpoint_url": "https://agent.example.test/run?key=SYNTHETIC-SK-OPENAI-SECRET"}),
        ("workflow_harness", "workflow_harness", {"endpoint_url": "https://workflow.example.test/run?password=secret-value", "workflow_id": "wf"}),
        ("workflow_harness", "workflow_harness", {"endpoint_url": "https://workflow.example.test/run?password=", "workflow_id": "wf"}),
    ],
)
def test_system_endpoint_urls_reject_embedded_credentials(target_type: str, field_name: str, config: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="endpoint_url must not include|literal secret-like values"):
        TargetConfig.model_validate({"name": "unsafe-system", "target_type": target_type, field_name: config})


def test_harness_result_contract_supports_common_system_outputs() -> None:
    result = HarnessResult(
        target_type="tool_agent",
        status="ok",
        output_text="completed safely",
        retrievals=[{"source_id": "doc-1", "redacted_preview": "approved source", "score": 0.92}],
        tool_calls=[HarnessToolCall(tool_name="search", arguments={"query": "policy"}, result_preview="redacted result")],
        traces=[HarnessTraceAction(action_type="plan", summary="selected safe route")],
        actions=[HarnessTraceAction(action_type="tool", summary="called search")],
        diffs=[HarnessDiff(path="src/app.py", change_type="modified", redacted_diff="@@ redacted @@")],
        artifacts=[HarnessArtifactRef(artifact_id="a1", artifact_type="trace", path="artifacts/trace.json", sha256="abc123")],
        latency_seconds=1.25,
        metadata={"run_mode": "schema_only"},
    )

    assert result.output_text == "completed safely"
    assert result.retrievals[0].source_id == "doc-1"
    assert result.tool_calls[0].tool_name == "search"
    assert result.diffs[0].path == "src/app.py"
    assert result.artifacts[0].redaction_status == "redacted"


def test_harness_result_metadata_rejects_raw_or_secret_fields() -> None:
    with pytest.raises(ValueError, match="raw evidence fields"):
        HarnessResult(target_type="rag_service", metadata={"payload": "raw text"})

    with pytest.raises(ValueError, match="literal secret-like values"):
        HarnessResult(target_type="rag_service", metadata={"safe_label": "Bearer secret-token"})
