from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from malleus.cli import app


def _write_target(tmp_path: Path) -> Path:
    target = tmp_path / "target.yaml"
    target.write_text(
        "name: t\nadapter: openai_compatible\nmodel: m\nbase_url: https://example.test/v1\napi_key_env: OPENAI_API_KEY\n",
        encoding="utf-8",
    )
    return target


@pytest.fixture
def no_provider_calls(monkeypatch):
    class ExplodingAdapter:
        def __init__(self, *args, **kwargs):
            raise AssertionError("assessment CLI tests must not instantiate provider adapters")

    monkeypatch.setitem(__import__("malleus.runner").runner.ADAPTERS, "openai_compatible", ExplodingAdapter)
    monkeypatch.setitem(__import__("malleus.runner").runner.ADAPTERS, "nvidia", ExplodingAdapter)
    monkeypatch.setitem(__import__("malleus.runner").runner.ADAPTERS, "ollama", ExplodingAdapter)


@pytest.fixture
def assessment_seam(monkeypatch):
    captured: dict[str, object] = {}

    def fake_run_assessment(**kwargs):
        captured.update(kwargs)
        out_dir = kwargs["out_dir"]
        assert isinstance(out_dir, Path)
        out_dir.mkdir(parents=True, exist_ok=True)
        manifest = {
            "schema_version": "malleus.assessment_manifest.v1",
            "run_id": "assessment-cli-test",
            "target_path": str(kwargs["target_path"]),
            "profile": kwargs["profile"],
            "packs": kwargs["packs"],
            "mode": kwargs["mode"],
            "provider_calls_enabled": kwargs["provider_calls_enabled"],
        }
        manifest_path = out_dir / "assessment-manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return {
            "run_id": "assessment-cli-test",
            "mode": kwargs["mode"],
            "manifest_path": str(manifest_path),
            "output_dir": str(out_dir),
        }

    monkeypatch.setattr("malleus.cli.run_assessment", fake_run_assessment, raising=False)
    return captured


def test_assess_defaults_to_dry_run_and_writes_manifest(
    assessment_seam: dict[str, object], no_provider_calls, tmp_path: Path
) -> None:
    runner = CliRunner()
    target = _write_target(tmp_path)
    out = tmp_path / "assessment"

    result = runner.invoke(
        app,
        ["assess", "--target", str(target), "--profile", "chatbot", "--packs", "core", "--out-dir", str(out)],
    )

    assert result.exit_code == 0
    assert "Assessment complete" in result.output
    assert assessment_seam["target_path"] == target
    assert assessment_seam["profile"] == "chatbot"
    assert assessment_seam["packs"] == ["core"]
    assert assessment_seam["mode"] == "dry_run"
    assert assessment_seam["out_dir"] == out
    assert assessment_seam["compare_targets"] == []
    assert assessment_seam["regression_pack"] is None
    assert assessment_seam["policy_path"] is None
    assert assessment_seam["baseline_path"] is None
    assert assessment_seam["include_experimental"] is False
    assert assessment_seam["limit"] is None
    assert assessment_seam["case_ids"] == []
    assert assessment_seam["provider_calls_enabled"] is False
    assert json.loads((out / "assessment-manifest.json").read_text(encoding="utf-8"))["mode"] == "dry_run"


def test_version_command_reports_package_metadata() -> None:
    result = CliRunner().invoke(app, ["version"])

    assert result.exit_code == 0
    assert result.output.strip().startswith("malleus-evals ")
    assert result.output.strip() != "malleus-evals unknown"


@pytest.mark.parametrize(
    ("pack_expression", "expected_packs"),
    [
        ("core,rag,tools,artifact", ["core", "rag", "tools", "artifact"]),
        ("default", ["default"]),
        ("all", ["all"]),
    ],
)
def test_assess_parses_pack_expression_and_aliases(
    assessment_seam: dict[str, object], no_provider_calls, tmp_path: Path, pack_expression: str, expected_packs: list[str]
) -> None:
    target = _write_target(tmp_path)
    result = CliRunner().invoke(
        app,
        [
            "assess",
            "--target",
            str(target),
            "--profile",
            "rag-agent",
            "--packs",
            pack_expression,
            "--out-dir",
            str(tmp_path / "out"),
        ],
    )

    assert result.exit_code == 0
    assert assessment_seam["packs"] == expected_packs


def test_assess_passes_compare_regression_policy_baseline_filter_and_json_options(
    assessment_seam: dict[str, object], no_provider_calls, tmp_path: Path
) -> None:
    target = _write_target(tmp_path)
    compare_a = tmp_path / "compare-a.yaml"
    compare_b = tmp_path / "compare-b.yaml"
    regression_pack = tmp_path / "regression.yaml"
    policy = tmp_path / "policy.yaml"
    baseline = tmp_path / "baseline.json"
    for path in [compare_a, compare_b, regression_pack, policy]:
        path.write_text("name: fixture\n", encoding="utf-8")
    baseline.write_text("{}", encoding="utf-8")
    out = tmp_path / "out"

    result = CliRunner().invoke(
        app,
        [
            "assess",
            "--target",
            str(target),
            "--profile",
            "tool-agent",
            "--packs",
            "core,tools",
            "--mode",
            "dry_run",
            "--out-dir",
            str(out),
            "--compare-target",
            str(compare_a),
            "--compare-target",
            str(compare_b),
            "--regression-pack",
            str(regression_pack),
            "--policy",
            str(policy),
            "--baseline",
            str(baseline),
            "--include-experimental",
            "--limit",
            "3",
            "--case-id",
            "core:ib-do-001",
            "--case-id",
            "tools:t-001",
            "--allow-live-provider",
            "--json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["run_id"] == "assessment-cli-test"
    assert payload["mode"] == "dry_run"
    assert assessment_seam["compare_targets"] == [compare_a, compare_b]
    assert assessment_seam["regression_pack"] == regression_pack
    assert assessment_seam["policy_path"] == policy
    assert assessment_seam["baseline_path"] == baseline
    assert assessment_seam["include_experimental"] is True
    assert assessment_seam["limit"] == 3
    assert assessment_seam["case_ids"] == ["core:ib-do-001", "tools:t-001"]
    assert assessment_seam["allow_live_provider"] is True


@pytest.mark.parametrize(
    ("args", "expected_message"),
    [
        (["--profile", "unknown-profile", "--packs", "core", "--mode", "dry_run"], "unknown profile"),
        (["--profile", "chatbot", "--packs", "unknown-pack", "--mode", "dry_run"], "unknown pack"),
        (["--profile", "chatbot", "--packs", "core", "--mode", "unsafe_mode"], "unknown mode"),
    ],
)
def test_assess_rejects_unknown_profile_pack_and_mode(
    assessment_seam: dict[str, object], no_provider_calls, tmp_path: Path, args: list[str], expected_message: str
) -> None:
    target = _write_target(tmp_path)
    result = CliRunner().invoke(app, ["assess", "--target", str(target), "--out-dir", str(tmp_path / "out"), *args])

    assert result.exit_code != 0
    assert expected_message in result.output.lower()
    assert assessment_seam == {}


def test_assess_live_provider_without_cli_and_env_gates_writes_scaffold_then_fails_closed(
    assessment_seam: dict[str, object], no_provider_calls, monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("MALLEUS_ALLOW_PROVIDER_CALLS", raising=False)
    out = tmp_path / "out"
    result = CliRunner().invoke(
        app,
        [
            "assess",
            "--target",
            str(_write_target(tmp_path)),
            "--profile",
            "chatbot",
            "--packs",
            "core",
            "--mode",
            "live_provider",
            "--out-dir",
            str(out),
        ],
    )

    assert result.exit_code != 0
    assert "fail-closed" in result.output
    assert "Provider calls enabled: false" in result.output
    assert assessment_seam["mode"] == "live_provider"
    assert assessment_seam["allow_live_provider"] is False
    assert assessment_seam["provider_calls_enabled"] is False
    assert (out / "assessment-manifest.json").exists()


def test_assess_live_provider_with_cli_gate_but_missing_env_writes_scaffold_then_fails_closed(
    assessment_seam: dict[str, object], no_provider_calls, monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("MALLEUS_ALLOW_PROVIDER_CALLS", raising=False)
    result = CliRunner().invoke(
        app,
        [
            "assess",
            "--target",
            str(_write_target(tmp_path)),
            "--profile",
            "chatbot",
            "--packs",
            "core",
            "--mode",
            "live_provider",
            "--out-dir",
            str(tmp_path / "out"),
            "--allow-live-provider",
        ],
    )

    assert result.exit_code != 0
    assert "fail-closed" in result.output
    assert assessment_seam["mode"] == "live_provider"
    assert assessment_seam["allow_live_provider"] is True
    assert assessment_seam["provider_calls_enabled"] is False


def test_assess_live_provider_with_both_gates_still_fails_closed(
    assessment_seam: dict[str, object], no_provider_calls, monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("MALLEUS_ALLOW_PROVIDER_CALLS", "1")
    target = _write_target(tmp_path)
    result = CliRunner().invoke(
        app,
        [
            "assess",
            "--target",
            str(target),
            "--profile",
            "chatbot",
            "--packs",
            "core",
            "--mode",
            "live_provider",
            "--out-dir",
            str(tmp_path / "out"),
            "--allow-live-provider",
        ],
    )

    assert result.exit_code != 0
    assert "fail-closed" in result.output
    assert assessment_seam["mode"] == "live_provider"
    assert assessment_seam["allow_live_provider"] is True
    assert assessment_seam["provider_calls_enabled"] is False
