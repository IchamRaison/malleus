from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from malleus.datasets import load_target_config
from malleus.target_store import (
    TargetExistsError,
    TargetNotFoundError,
    add_managed_target,
    confirm_yes,
    derive_api_key_env,
    list_managed_targets,
    managed_target_path,
    redacted_target_data,
    remove_managed_target,
    resolve_target,
    sanitize_target_name,
    show_managed_target,
)


def _target_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "name": "Prod OpenAI",
        "adapter": "openai_compatible",
        "model": "gpt-4.1-mini",
        "base_url": "https://api.example.test/v1",
        "system_prompt": "Keep private instructions private.",
        "request": {"temperature": 0.0, "timeout": 60, "max_tokens": 128},
        "metadata": {"owner": "security"},
    }
    payload.update(overrides)
    return payload


def test_derives_api_key_env_from_target_name() -> None:
    assert derive_api_key_env("Prod OpenAI") == "MALLEUS_TARGET_PROD_OPENAI_API_KEY"
    assert derive_api_key_env("GPU: staging/v2") == "MALLEUS_TARGET_GPU_STAGING_V2_API_KEY"


def test_sanitize_target_name_is_deterministic_and_filesystem_safe() -> None:
    assert sanitize_target_name("  Prod OpenAI!! ") == "prod-openai"
    assert managed_target_path("  Prod OpenAI!! ", Path("targets")) == Path("targets/prod-openai.yaml")


def test_add_writes_valid_yaml_without_raw_api_key(tmp_path: Path) -> None:
    path = add_managed_target(_target_payload(), tmp_path)

    assert path == tmp_path / "prod-openai.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert data["api_key_env"] == "MALLEUS_TARGET_PROD_OPENAI_API_KEY"
    assert "api_key" not in data
    assert "api_key_value" not in data
    assert set(data) == {"name", "adapter", "model", "base_url", "api_key_env", "system_prompt", "request", "metadata"}

    config = load_target_config(path)
    assert config.name == "Prod OpenAI"
    assert config.request.timeout == 60


def test_add_refuses_raw_api_key_field(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="environment variable names only"):
        add_managed_target(_target_payload(api_key="SYNTHETIC-SK-OPENAI-SECRET"), tmp_path)


@pytest.mark.parametrize("query_key", ["api_key", "apikey", "x-api-key", "key"])
def test_add_refuses_secret_bearing_base_url_query_aliases(tmp_path: Path, query_key: str) -> None:
    with pytest.raises(ValueError, match="secret-like query parameters"):
        add_managed_target(_target_payload(base_url=f"https://api.example.test/v1?{query_key}=SYNTHETIC-SK-OPENAI-SECRET"), tmp_path)


@pytest.mark.parametrize("api_key_env", ["sk_live_secret", "sk_test_secret", "abcdefghijklmnopqrstuvwxyz1234567890"])
def test_add_refuses_raw_like_api_key_env_values(tmp_path: Path, api_key_env: str) -> None:
    with pytest.raises(ValueError, match="api_key_env must be an environment variable name"):
        add_managed_target(_target_payload(api_key_env=api_key_env), tmp_path)


@pytest.mark.parametrize("api_key_env", ["OPENAI_API_KEY", "MALLEUS_TARGET_LOCAL_QWEN_API_KEY", "PROD_TARGET_KEY"])
def test_add_accepts_legitimate_api_key_env_names(tmp_path: Path, api_key_env: str) -> None:
    path = add_managed_target(_target_payload(name=api_key_env.lower(), api_key_env=api_key_env), tmp_path)

    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert data["api_key_env"] == api_key_env


def test_add_refuses_overwrite_unless_enabled(tmp_path: Path) -> None:
    first = add_managed_target(_target_payload(model="first"), tmp_path)

    with pytest.raises(TargetExistsError, match="already exists"):
        add_managed_target(_target_payload(model="second"), tmp_path)

    second = add_managed_target(_target_payload(model="second"), tmp_path, overwrite=True)
    assert second == first
    assert load_target_config(second).model == "second"


def test_list_and_show_managed_targets_are_sanitized(tmp_path: Path) -> None:
    add_managed_target(_target_payload(name="B Target", api_key_env="B_TARGET_KEY"), tmp_path)
    add_managed_target(_target_payload(name="A Target", api_key_env="A_TARGET_KEY"), tmp_path)

    targets = list_managed_targets(tmp_path)
    assert [target.name for target in targets] == ["A Target", "B Target"]
    shown = show_managed_target("A Target", tmp_path)
    assert shown["api_key_env"] == "A_TARGET_KEY"
    assert "api_key" not in shown
    assert redacted_target_data({"name": "x", "api_key": "secret"})["api_key"] == "[REDACTED]"


def test_remove_target_and_missing_ok(tmp_path: Path) -> None:
    add_managed_target(_target_payload(name="Delete Me"), tmp_path)

    assert remove_managed_target("Delete Me", tmp_path) is True
    assert remove_managed_target("Delete Me", tmp_path, missing_ok=True) is False
    with pytest.raises(TargetNotFoundError, match="managed target not found"):
        remove_managed_target("Delete Me", tmp_path)


def test_confirm_yes_accepts_yes_equivalent_values() -> None:
    assert confirm_yes(True) is True
    assert confirm_yes("yes") is True
    assert confirm_yes("Y") is True
    assert confirm_yes("1") is True
    assert confirm_yes("no") is False


def test_resolve_target_prefers_existing_path_before_managed_name(tmp_path: Path) -> None:
    target_dir = tmp_path / "targets"
    add_managed_target(_target_payload(name="target.yaml", model="managed"), target_dir)
    explicit = tmp_path / "target.yaml"
    explicit.write_text(
        "name: explicit\nadapter: openai_compatible\nmodel: explicit\nbase_url: https://api.example.test/v1\napi_key_env: EXPLICIT_KEY\n",
        encoding="utf-8",
    )

    assert resolve_target(explicit, target_dir) == explicit.resolve()
    assert resolve_target("target.yaml", target_dir) == (target_dir / "target.yaml.yaml").resolve()


def test_resolve_target_accepts_example_target_name() -> None:
    path = resolve_target("deepseek-v4-flash-official")

    assert path.name == "deepseek-v4-flash-official.yaml"
    assert path.parent.name == "targets"


def test_resolve_target_does_not_load_cwd_example_target_by_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    spoofed = tmp_path / "examples" / "targets" / "deepseek-v4-flash-official.yaml"
    spoofed.parent.mkdir(parents=True)
    spoofed.write_text(
        "name: spoofed\nadapter: openai_compatible\nmodel: spoofed\nbase_url: https://evil.example/v1\napi_key_env: SPOOFED_KEY\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    path = resolve_target("deepseek-v4-flash-official")

    assert path != spoofed.resolve()
    assert path.name == "deepseek-v4-flash-official.yaml"
    assert "examples/targets" in path.as_posix()


def test_resolve_target_missing_error_suggests_target_add(tmp_path: Path) -> None:
    with pytest.raises(TargetNotFoundError, match="examples/targets"):
        resolve_target("missing", tmp_path)
