from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from malleus.assessment import run_assessment
from malleus.assessment_schemas import AssessmentMode
from malleus.cli import app


def _write_target(tmp_path: Path) -> Path:
    target = tmp_path / "target.yaml"
    target.write_text(
        "name: t\nadapter: openai_compatible\nmodel: m\nbase_url: https://example.test/v1\napi_key_env: OPENAI_API_KEY\n",
        encoding="utf-8",
    )
    return target


def test_assessment_productization_does_not_rewrite_or_call_classic_runner_scope() -> None:
    assessment_sources = [
        Path("src/malleus/assessment.py"),
        Path("src/malleus/assessment_catalog.py"),
        Path("src/malleus/assessment_reporting.py"),
        Path("src/malleus/assessment_scoring.py"),
        Path("src/malleus/assessment_compare_gate.py"),
    ]

    for source_path in assessment_sources:
        source = source_path.read_text(encoding="utf-8")
        assert "from malleus.runner import" not in source
        assert "import malleus.runner" not in source
        assert "run_benchmark(" not in source


@pytest.fixture
def poison_provider_paths(monkeypatch):
    class ExplodingAdapter:
        def __init__(self, *args, **kwargs):
            raise AssertionError("assessment must not instantiate provider adapters")

        def generate(self, prompt: str) -> str:
            raise AssertionError("assessment must not call provider adapters")

        def close(self) -> None:
            raise AssertionError("assessment must not manage provider adapters")

    def explode_run_benchmark(*args, **kwargs):
        raise AssertionError("assessment must not call live run_benchmark")

    runner_module = __import__("malleus.runner").runner
    monkeypatch.setitem(runner_module.ADAPTERS, "openai_compatible", ExplodingAdapter)
    monkeypatch.setitem(runner_module.ADAPTERS, "nvidia", ExplodingAdapter)
    monkeypatch.setitem(runner_module.ADAPTERS, "ollama", ExplodingAdapter)
    monkeypatch.setattr(runner_module, "run_benchmark", explode_run_benchmark)


@pytest.mark.parametrize("mode", [mode.value for mode in AssessmentMode])
def test_assessment_manifests_record_provider_and_network_disabled(
    poison_provider_paths, tmp_path: Path, mode: str
) -> None:
    out_dir = tmp_path / mode

    result = run_assessment(
        target_path=_write_target(tmp_path),
        profile="chatbot",
        packs=["core"],
        mode=mode,
        out_dir=out_dir,
        compare_targets=[],
        regression_pack=None,
        policy_path=None,
        baseline_path=None,
        include_experimental=False,
        limit=None,
        case_ids=[],
        allow_live_provider=True,
        provider_calls_enabled=True,
    )

    manifest = json.loads((out_dir / "assessment-manifest.json").read_text(encoding="utf-8"))
    raw = json.loads((out_dir / "raw" / "core" / "planning-metadata.json").read_text(encoding="utf-8"))
    assert result["provider_calls_enabled"] is False
    assert result["network_enabled"] is False
    assert manifest["provider_calls_enabled"] is False
    assert manifest["network_enabled"] is False
    assert manifest["provider_guardrails"] == {
        "adapter_instantiation": "disabled",
        "live_provider_behavior": "fail_closed",
        "network_enabled": False,
        "provider_calls_enabled": False,
    }
    assert any("provider and network calls are disabled" in caveat for caveat in manifest["caveats"])
    assert raw["provider_calls_enabled"] is False
    assert raw["network_enabled"] is False
    assert raw["provider_calls_made"] is False


def test_live_provider_assessment_fails_closed_without_model_behavior_evidence(
    poison_provider_paths, tmp_path: Path
) -> None:
    out_dir = tmp_path / "live"

    result = run_assessment(
        target_path=_write_target(tmp_path),
        profile="chatbot",
        packs=["core"],
        mode="live_provider",
        out_dir=out_dir,
        compare_targets=[],
        regression_pack=None,
        policy_path=None,
        baseline_path=None,
        include_experimental=False,
        limit=None,
        case_ids=[],
        allow_live_provider=True,
        provider_calls_enabled=True,
    )

    assert result["live_provider_fail_closed"] is True
    assert result["provider_calls_requested"] is True
    assert result["provider_calls_enabled"] is False
    raw = json.loads((out_dir / "raw" / "core" / "planning-metadata.json").read_text(encoding="utf-8"))
    risk_report = json.loads((out_dir / "risk-report.json").read_text(encoding="utf-8"))
    core_pack = next(pack for pack in risk_report["packs"] if pack["id"] == "core")

    assert raw["status"] == "requires_live_provider"
    assert raw["evidence_strength"] == "planning_only"
    assert raw["provider_calls_enabled"] is False
    assert raw["network_enabled"] is False
    assert "model_behavior" not in raw["evidence_strength"]
    assert any("fail-closed scaffold" in note for note in raw["workflow_notes"])
    assert core_pack["applicability"] == "requires_live_provider"
    assert core_pack["score_use"] == "not_tested"
    assert core_pack["evidence_strengths"] == ["planning_only"]
    assert "model_behavior" not in core_pack["evidence_strengths"]


def test_assess_live_provider_cli_exits_nonzero_and_writes_fail_closed_artifacts(
    poison_provider_paths, monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("MALLEUS_ALLOW_PROVIDER_CALLS", "1")
    out_dir = tmp_path / "cli-live"

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
            str(out_dir),
            "--allow-live-provider",
        ],
    )

    assert result.exit_code != 0
    assert "fail-closed" in result.output
    assert "Provider calls enabled: false" in result.output
    assert "Network enabled: false" in result.output
    manifest = json.loads((out_dir / "assessment-manifest.json").read_text(encoding="utf-8"))
    raw = json.loads((out_dir / "raw" / "core" / "planning-metadata.json").read_text(encoding="utf-8"))
    assert manifest["provider_calls_enabled"] is False
    assert manifest["network_enabled"] is False
    assert raw["evidence_strength"] == "planning_only"
    assert raw["provider_calls_enabled"] is False
