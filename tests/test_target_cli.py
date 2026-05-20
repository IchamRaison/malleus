from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from malleus.cli import app


SECRET = "SYNTHETIC-SK-OPENAI-SECRET"


def test_target_help_lists_managed_commands() -> None:
    result = CliRunner().invoke(app, ["target", "--help"], env={"COLUMNS": "200"})

    assert result.exit_code == 0
    assert "Manage reusable target model configurations" in result.output
    assert "init" in result.output
    assert "add" in result.output
    assert "list" in result.output
    assert "show" in result.output
    assert "remove" in result.output
    assert "test" in result.output
    assert "doctor" in result.output
    assert "universe" in result.output


def test_target_init_deepseek_preset_writes_explicit_target(tmp_path: Path) -> None:
    target_path = tmp_path / "deepseek.yaml"

    result = CliRunner().invoke(
        app,
        [
            "target",
            "init",
            "--provider",
            "deepseek",
            "--non-interactive",
            "--out",
            str(target_path),
            "--env-file",
            str(tmp_path / "missing.env"),
        ],
        env={},
    )

    assert result.exit_code == 0, result.output
    assert "Target saved: deepseek-deepseek-v4-flash" in result.output
    assert "Credential not found yet. Add DEEPSEEK_API_KEY" in result.output
    assert f"Next: malleus target doctor {target_path} --live-check" in result.output
    data = target_path.read_text(encoding="utf-8")
    assert "adapter: openai_compatible" in data
    assert "model: deepseek-v4-flash" in data
    assert "base_url: https://api.deepseek.com/v1" in data
    assert "api_key_env: DEEPSEEK_API_KEY" in data
    assert "timeout: 180.0" in data
    assert "max_tokens: 2048" in data
    assert "model_universe:" in data
    assert "provider_id: deepseek" in data
    assert "operational_error_policy:" in data
    assert SECRET not in data


def test_target_init_can_store_api_key_in_env_file_without_printing_secret(tmp_path: Path) -> None:
    target_path = tmp_path / "deepseek.yaml"
    env_file = tmp_path / ".env"

    result = CliRunner().invoke(
        app,
        [
            "target",
            "init",
            "--provider",
            "deepseek",
            "--model",
            "deepseek-reasoner",
            "--out",
            str(target_path),
            "--save-api-key",
            "--env-file",
            str(env_file),
            "--non-interactive",
        ],
        input=f"{SECRET}\n",
    )

    assert result.exit_code == 0, result.output
    assert "API key saved" in result.output
    assert "DEEPSEEK_API_KEY" in result.output
    assert SECRET not in result.output
    assert "DEEPSEEK_API_KEY=" in env_file.read_text(encoding="utf-8")
    assert SECRET in env_file.read_text(encoding="utf-8")
    assert SECRET not in target_path.read_text(encoding="utf-8")


def test_target_init_interactive_selects_suggested_model(tmp_path: Path) -> None:
    config_dir = tmp_path / "targets"

    result = CliRunner().invoke(
        app,
        ["target", "init", "--config-dir", str(config_dir), "--env-file", str(tmp_path / "missing.env"), "--no-save-api-key"],
        input="deepseek\n2\n",
        env={},
    )

    assert result.exit_code == 0, result.output
    target_path = config_dir / "deepseek-deepseek-chat.yaml"
    assert target_path.exists()
    assert f"Next: malleus target doctor deepseek-deepseek-chat --config-dir {config_dir} --live-check" in result.output
    assert "model: deepseek-chat" in target_path.read_text(encoding="utf-8")


def test_target_init_can_discover_models_and_select_by_number(monkeypatch, tmp_path: Path) -> None:
    config_dir = tmp_path / "targets"

    def fake_discover(base_url: str, api_key: str | None, *, timeout: float):
        assert base_url == "https://api.deepseek.com/v1"
        assert api_key == SECRET
        return ["deepseek-live-a", "deepseek-live-b"], None

    monkeypatch.setattr("malleus.cli._discover_provider_models", fake_discover)
    result = CliRunner().invoke(
        app,
        [
            "target",
            "init",
            "--config-dir",
            str(config_dir),
            "--env-file",
            str(tmp_path / ".env"),
            "--save-api-key",
        ],
        input=f"2\n{SECRET}\n2\n",
        env={},
    )

    assert result.exit_code == 0, result.output
    assert "Discovered 2 models from provider." in result.output
    assert "Target saved: deepseek-deepseek-live-b" in result.output
    target_path = config_dir / "deepseek-deepseek-live-b.yaml"
    assert target_path.exists()
    assert "model: deepseek-live-b" in target_path.read_text(encoding="utf-8")
    assert SECRET not in target_path.read_text(encoding="utf-8")


def test_target_universe_lists_builtin_providers_without_gemini() -> None:
    result = CliRunner().invoke(app, ["target", "universe"])

    assert result.exit_code == 0, result.output
    assert "Malleus model universe" in result.output
    assert "deepseek: DeepSeek" in result.output
    assert "live-verified" in result.output
    assert "protocol-tested" in result.output
    assert "openai: OpenAI" in result.output
    assert "gemini" not in result.output.lower()


def test_target_universe_json_includes_provider_compatibility_matrix() -> None:
    result = CliRunner().invoke(app, ["target", "universe", "--json"])

    assert result.exit_code == 0, result.output
    assert '"compatibility_matrix"' in result.output
    assert '"protocol_report"' in result.output
    assert '"provider_calls_enabled": false' in result.output


def test_target_add_list_show_remove_flow(tmp_path: Path) -> None:
    runner = CliRunner()
    config_dir = tmp_path / "targets"

    add_result = runner.invoke(
        app,
        [
            "target",
            "add",
            "--name",
            "Prod Target",
            "--model",
            "gpt-4.1-mini",
            "--base-url",
            "https://api.example.test/v1",
            "--adapter",
            "openai_compatible",
            "--api-key-env",
            "PROD_TARGET_KEY",
            "--timeout",
            "12.5",
            "--max-tokens",
            "64",
            "--temperature",
            "0.2",
            "--top-p",
            "0.9",
            "--config-dir",
            str(config_dir),
        ],
    )

    assert add_result.exit_code == 0, add_result.output
    assert "Managed target saved: Prod Target" in add_result.output
    assert (config_dir / "prod-target.yaml").exists()

    list_result = runner.invoke(app, ["target", "list", "--config-dir", str(config_dir)])
    assert list_result.exit_code == 0, list_result.output
    assert "Prod Target" in list_result.output
    assert SECRET not in list_result.output

    show_result = runner.invoke(app, ["target", "show", "Prod Target", "--config-dir", str(config_dir)])
    assert show_result.exit_code == 0, show_result.output
    assert "adapter: openai_compatible" in show_result.output
    assert "model: gpt-4.1-mini" in show_result.output
    assert "base_url: https://api.example.test/v1" in show_result.output
    assert "api_key_env: PROD_TARGET_KEY" in show_result.output
    assert "timeout: 12.5" in show_result.output
    assert "max_tokens: 64" in show_result.output
    assert "temperature: 0.2" in show_result.output
    assert "top_p: 0.9" in show_result.output
    assert SECRET not in show_result.output
    assert "user:" not in show_result.output

    missing_yes = runner.invoke(app, ["target", "remove", "Prod Target", "--config-dir", str(config_dir)])
    assert missing_yes.exit_code == 1
    assert "without --yes" in missing_yes.output
    assert (config_dir / "prod-target.yaml").exists()

    remove_result = runner.invoke(app, ["target", "remove", "Prod Target", "--config-dir", str(config_dir), "--yes"])
    assert remove_result.exit_code == 0, remove_result.output
    assert "Managed target removed: Prod Target" in remove_result.output
    assert not (config_dir / "prod-target.yaml").exists()


def test_target_add_rejects_secret_bearing_base_url(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        app,
        [
            "target",
            "add",
            "--name",
            "Unsafe",
            "--model",
            "m",
            "--base-url",
            f"https://user:{SECRET}@api.example.test/v1?api_key={SECRET}",
            "--config-dir",
            str(tmp_path / "targets"),
        ],
    )

    assert result.exit_code == 1
    assert "base_url must not include username or password credentials" in result.output
    assert SECRET not in result.output


def test_target_add_rejects_raw_like_api_key_env(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        app,
        [
            "target",
            "add",
            "--name",
            "Unsafe Env",
            "--model",
            "m",
            "--api-key-env",
            "sk_test_secret",
            "--config-dir",
            str(tmp_path / "targets"),
        ],
    )

    assert result.exit_code == 1
    assert "api_key_env must be an environment variable name" in result.output
    assert "sk_test_secret" not in result.output


def test_target_add_defaults_to_openai_base_url(tmp_path: Path) -> None:
    runner = CliRunner()
    config_dir = tmp_path / "targets"

    add_result = runner.invoke(
        app,
        [
            "target",
            "add",
            "--name",
            "Default URL",
            "--model",
            "gpt-4.1-mini",
            "--config-dir",
            str(config_dir),
        ],
    )

    assert add_result.exit_code == 0, add_result.output
    show_result = runner.invoke(app, ["target", "show", "Default URL", "--config-dir", str(config_dir)])
    assert show_result.exit_code == 0, show_result.output
    assert "base_url: https://api.openai.com/v1" in show_result.output


def test_target_add_requires_overwrite_for_existing_name(tmp_path: Path) -> None:
    runner = CliRunner()
    config_dir = tmp_path / "targets"

    def add_args(model: str) -> list[str]:
        return [
            "target",
            "add",
            "--name",
            "Replace Me",
            "--model",
            model,
            "--base-url",
            "https://api.example.test/v1",
            "--config-dir",
            str(config_dir),
        ]

    first = runner.invoke(app, add_args("first"))
    assert first.exit_code == 0, first.output

    second = runner.invoke(app, add_args("second"))
    assert second.exit_code == 1
    assert "already exists" in second.output

    overwritten = runner.invoke(app, [*add_args("second"), "--overwrite"])
    assert overwritten.exit_code == 0, overwritten.output
    show_result = runner.invoke(app, ["target", "show", "Replace Me", "--config-dir", str(config_dir)])
    assert "model: second" in show_result.output


def test_target_test_without_allowance_skips_provider_call(monkeypatch, tmp_path: Path) -> None:
    runner = CliRunner()
    target = tmp_path / "target.yaml"
    target.write_text(
        "name: local\nadapter: openai_compatible\nmodel: m\nbase_url: https://example.test/v1\napi_key_env: SAFE_KEY\n",
        encoding="utf-8",
    )

    def fail_preflight(*args, **kwargs):
        raise AssertionError("provider preflight must not run without explicit allowance")

    monkeypatch.setattr("malleus.cli.run_target_preflight", fail_preflight)
    result = runner.invoke(app, ["target", "test", str(target)])

    assert result.exit_code == 0, result.output
    assert "config: ok" in result.output
    assert "auth: env var configured (SAFE_KEY)" in result.output
    assert "network: skipped" in result.output
    assert "provider: skipped" in result.output


def test_target_test_missing_reference_reports_config_error(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, ["target", "test", "missing", "--config-dir", str(tmp_path / "targets")])

    assert result.exit_code == 1
    assert "config: failed" in result.output
    assert "target not found: missing" in result.output


def test_target_doctor_supports_model_targets_without_provider_probe(tmp_path: Path) -> None:
    target = tmp_path / "target.yaml"
    target.write_text(
        "name: deepseek\nadapter: openai_compatible\nmodel: deepseek-v4-flash\nbase_url: https://api.deepseek.com/v1\napi_key_env: DEEPSEEK_API_KEY\nrequest:\n  timeout: 180\n  max_tokens: 2048\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "doctor"

    result = CliRunner().invoke(app, ["target", "doctor", str(target), "--out-dir", str(out_dir)], env={"DEEPSEEK_API_KEY": "present"})

    assert result.exit_code == 0, result.output
    assert "Malleus target doctor" in result.output
    assert "Status: ready" in result.output
    assert "Type: chat_completion" in result.output
    assert "Provider: DeepSeek" in result.output
    assert "Model universe:" in result.output
    assert "[skip] provider_preflight: live provider check skipped" in result.output
    assert (out_dir / "target-doctor.json").exists()
    assert (out_dir / "target-doctor.md").exists()


def test_target_doctor_accepts_live_check_alias(monkeypatch, tmp_path: Path) -> None:
    target = tmp_path / "target.yaml"
    target.write_text(
        "name: deepseek\nadapter: openai_compatible\nmodel: deepseek-v4-flash\nbase_url: https://api.deepseek.com/v1\napi_key_env: DEEPSEEK_API_KEY\n",
        encoding="utf-8",
    )

    class FakePreflight:
        ok = True
        text_status = "passed"
        text_ready = True

    monkeypatch.setattr("malleus.cli.run_target_preflight", lambda *args, **kwargs: FakePreflight())
    result = CliRunner().invoke(app, ["target", "doctor", str(target), "--live-check"], env={"DEEPSEEK_API_KEY": "present"})

    assert result.exit_code == 0, result.output
    assert "[ok] provider_preflight: text probe status: passed" in result.output


def test_target_doctor_prints_failed_live_probe_details(monkeypatch, tmp_path: Path) -> None:
    target = tmp_path / "target.yaml"
    target.write_text(
        "name: deepseek\nadapter: openai_compatible\nmodel: deepseek-v4-flash\nbase_url: https://api.deepseek.com/v1\napi_key_env: DEEPSEEK_API_KEY\n",
        encoding="utf-8",
    )

    class FakeSummary:
        redacted_excerpt = "model does not support this request"

    class FakeTextProbe:
        name = "text"
        status = "preflight_failed"
        status_code = 400
        reason = "HTTP 400 from target"
        response_summary = FakeSummary()

    class FakePreflight:
        ok = False
        text_status = "preflight_failed"
        text_ready = False
        probes = [FakeTextProbe()]

    monkeypatch.setattr("malleus.cli.run_target_preflight", lambda *args, **kwargs: FakePreflight())
    result = CliRunner().invoke(app, ["target", "doctor", str(target), "--live-check"], env={"DEEPSEEK_API_KEY": "present"})

    assert result.exit_code == 1
    assert "[fail] provider_probe_text: text probe status: preflight_failed - HTTP 400" in result.output
    assert "model does not support this request" in result.output


def test_target_doctor_lists_available_models_when_configured_model_is_missing(monkeypatch, tmp_path: Path) -> None:
    target = tmp_path / "target.yaml"
    target.write_text(
        "name: deepseek\nadapter: openai_compatible\nmodel: missing-model\nbase_url: https://api.deepseek.com/v1\napi_key_env: DEEPSEEK_API_KEY\n",
        encoding="utf-8",
    )

    class FakeModelsProbe:
        name = "models"
        ok = True
        metadata = {"target_model_found": False, "model_ids": ["deepseek-live-a", "deepseek-live-b"]}

    class FakePreflight:
        ok = True
        text_status = "passed"
        text_ready = True
        probes = [FakeModelsProbe()]

    monkeypatch.setattr("malleus.cli.run_target_preflight", lambda *args, **kwargs: FakePreflight())
    result = CliRunner().invoke(app, ["target", "doctor", str(target), "--live-check"], env={"DEEPSEEK_API_KEY": "present"})

    assert result.exit_code == 0, result.output
    assert "[warn] model_catalog" in result.output
    assert "deepseek-live-a, deepseek-live-b" in result.output


def test_target_test_system_rag_target_does_not_require_base_url(monkeypatch, tmp_path: Path) -> None:
    target = tmp_path / "rag-target.yaml"
    target.write_text(
        """name: rag-target
target_type: rag_service
rag_service:
  endpoint_url: http://127.0.0.1:8765/rag
  auth:
    api_key_env: RAG_SERVICE_KEY
""",
        encoding="utf-8",
    )

    def fail_preflight(*args, **kwargs):
        raise AssertionError("provider preflight must not run for system targets")

    monkeypatch.setattr("malleus.cli.run_target_preflight", fail_preflight)
    result = CliRunner().invoke(app, ["target", "test", str(target)])

    assert result.exit_code == 0, result.output
    assert "config: ok" in result.output
    assert "target_type: rag_service" in result.output
    assert "endpoint: http://127.0.0.1:8765/" in result.output
    assert "auth: env var configured (RAG_SERVICE_KEY)" in result.output
    assert "auth_present: false" in result.output
    assert "target_preflight: skipped" in result.output
    assert "Traceback" not in result.output


def test_target_test_system_code_agent_reports_workspace(tmp_path: Path) -> None:
    target = tmp_path / "code-agent-target.yaml"
    target.write_text(
        """name: code-agent-target
target_type: code_agent
code_agent:
  workspace_path: tests/fixtures/workspace
  command_env:
    GIT_TOKEN: CODE_AGENT_TOKEN
""",
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["target", "test", str(target), "--allow-provider-call"])

    assert result.exit_code == 0, result.output
    assert "target_type: code_agent" in result.output
    assert "workspace: tests/fixtures/workspace" in result.output
    assert "auth: env var configured (CODE_AGENT_TOKEN)" in result.output
    assert "target_preflight: skipped - system targets are exercised by matching live benchmark commands" in result.output
