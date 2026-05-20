from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from malleus.assessment import run_assessment
from malleus.cli import app


FORBIDDEN_PUBLIC_PATTERNS = [
    r"Bearer\s+",
    r"/home/",
    r"raw_prompt",
    r"raw_response",
    r"<\s*script",
    r"javascript\s*:",
    r"https?://",
    r"\bsk-[A-Za-z0-9]",
]


def _write_target(tmp_path: Path, *, name: str, model: str, adapter: str = "openai_compatible") -> Path:
    path = tmp_path / f"{name}.yaml"
    path.write_text(
        f"name: {name}\nadapter: {adapter}\nmodel: {model}\nbase_url: https://example.test/v1\napi_key_env: OPENAI_API_KEY\n",
        encoding="utf-8",
    )
    return path


def _run_assessment(tmp_path: Path, **overrides: object) -> tuple[Path, dict[str, object]]:
    out_dir = tmp_path / "assessment"
    kwargs = {
        "target_path": _write_target(tmp_path, name="primary", model="model-a"),
        "profile": "model-selection",
        "packs": ["comparison"],
        "mode": "dry_run",
        "out_dir": out_dir,
        "compare_targets": [_write_target(tmp_path, name="secondary", model="model-b", adapter="ollama")],
        "regression_pack": None,
        "policy_path": None,
        "baseline_path": None,
        "include_experimental": False,
        "limit": None,
        "case_ids": [],
        "allow_live_provider": False,
        "provider_calls_enabled": False,
    }
    kwargs.update(overrides)
    result = run_assessment(**kwargs)  # type: ignore[arg-type]
    return out_dir, result


def _artifact_texts(out_dir: Path) -> dict[str, str]:
    paths = [
        "model-comparison/comparison-summary.md",
        "model-comparison/comparison.json",
        "model-comparison/leaderboard.html",
        "model-comparison/per-model-strengths-weaknesses.md",
        "model-comparison/shared-failures.md",
        "model-comparison/model-specific-risks.md",
        "gate/gate-summary.json",
        "gate/gate-summary.md",
        "gate/gate-results.sarif",
        "gate/gate-results.junit.xml",
    ]
    return {path: (out_dir / path).read_text(encoding="utf-8") for path in paths}


def test_compare_target_writes_provider_free_comparison_artifacts(tmp_path: Path) -> None:
    out_dir, result = _run_assessment(tmp_path)

    texts = _artifact_texts(out_dir)
    comparison = json.loads(texts["model-comparison/comparison.json"])
    assert result["model_comparison"] is not None
    assert comparison["schema_version"] == "malleus.assessment_model_comparison.v1"
    assert comparison["provider_calls_enabled"] is False
    assert comparison["network_enabled"] is False
    assert [entry["target_role"] for entry in comparison["models"]] == ["primary", "compare"]
    assert {entry["model"] for entry in comparison["models"]} == {"model-a", "model-b"}
    assert all(entry["assessment_output"] == "provider_free_composed_from_current_risk_report" for entry in comparison["models"])
    assert all(entry["provider_calls_enabled"] is False for entry in comparison["models"])
    assert "Provider calls enabled: false" in texts["model-comparison/comparison-summary.md"]
    assert "model-b" in texts["model-comparison/leaderboard.html"]


def test_comparison_and_gate_artifacts_are_static_and_sanitized(tmp_path: Path) -> None:
    hostile_target = _write_target(tmp_path, name="hostile", model="bad<script>alert(1)</script> SYNTHETIC-SK-OPENAI-SECRET")
    out_dir, _result = _run_assessment(tmp_path, compare_targets=[hostile_target])

    for relative_path, text in _artifact_texts(out_dir).items():
        lowered = text.lower()
        for pattern in FORBIDDEN_PUBLIC_PATTERNS:
            assert re.search(pattern, lowered, flags=re.IGNORECASE) is None, f"{relative_path} leaked {pattern}"

    html = (out_dir / "model-comparison" / "leaderboard.html").read_text(encoding="utf-8")
    lowered = html.lower()
    assert "<script" not in lowered
    assert "<iframe" not in lowered
    assert "javascript:" not in lowered
    assert "http://" not in lowered
    assert "https://" not in lowered
    assert re.search(r"\son[a-z]+\s*=", lowered) is None


def test_assessment_gate_warns_for_non_blocking_coverage_gaps_and_exports_ci_formats(tmp_path: Path) -> None:
    out_dir, result = _run_assessment(tmp_path, profile="rag-agent", packs=["rag"], compare_targets=[])

    gate = json.loads((out_dir / "gate" / "gate-summary.json").read_text(encoding="utf-8"))
    assert result["assessment_gate"]["status"] == "WARN"  # type: ignore[index]
    assert gate["schema_version"] == "malleus.assessment_gate.v1"
    assert gate["status"] == "WARN"
    assert gate["ci_exit_code"] == 0
    assert "coverage_gaps_present" in gate["warnings"]
    assert "regression_pack_missing_for_findings" in gate["warnings"]
    assert gate["summary"]["coverage_gaps"] == 1
    assert (out_dir / "gate" / "gate-summary.md").exists()
    assert (out_dir / "gate" / "gate-results.sarif").exists()
    assert "testsuite" in (out_dir / "gate" / "gate-results.junit.xml").read_text(encoding="utf-8")


def test_assessment_gate_validates_configured_regression_pack(tmp_path: Path) -> None:
    regression_pack = tmp_path / "regression-pack.yaml"
    regression_pack.write_text(
        """schema_version: malleus.regression_pack.v1
generated_at: '2026-04-28T00:00:00+00:00'
generated_from: findings.json
provider_calls_enabled: false
network_enabled: false
replay_mode: provider_free_required
cases:
  - id: reg-1
    source_finding_id: mf-1
    source_finding_sha256: abc
    severity: high
    source_type: run_report
    surface: prompt
    technique: role_bypass
    expected_boundary: instruction_boundary
    affected_target: {}
    replay_mode: provider_free_required
    replay_command: malleus replay mf-1 --report findings.json --dry-run
    case_ids: []
    scenario_ids: []
    evidence_refs:
      - evidence_id: e1
        artifact_path: report.json
        artifact_type: run_report_json
        redaction_status: redacted
    expected_fixed_behavior: Fix the boundary.
    tags: [regression]
metadata: {}
""",
        encoding="utf-8",
    )
    out_dir, _result = _run_assessment(tmp_path, profile="rag-agent", packs=["rag"], compare_targets=[], regression_pack=regression_pack)

    gate = json.loads((out_dir / "gate" / "gate-summary.json").read_text(encoding="utf-8"))

    assert gate["summary"]["regression_pack_configured"] is True
    assert gate["summary"]["regression_pack_status"] == "pass"
    assert gate["summary"]["regression_cases"] == 1
    assert "regression_pack_missing_for_findings" not in gate["warnings"]


def test_assessment_gate_fails_closed_on_invalid_regression_pack(tmp_path: Path) -> None:
    regression_pack = tmp_path / "regression-pack.yaml"
    regression_pack.write_text("schema_version: malleus.regression_pack.v1\nprovider_calls_enabled: true\ncases: []\n", encoding="utf-8")
    out_dir, result = _run_assessment(tmp_path, profile="rag-agent", packs=["rag"], compare_targets=[], regression_pack=regression_pack)

    gate = json.loads((out_dir / "gate" / "gate-summary.json").read_text(encoding="utf-8"))

    assert result["assessment_gate"]["status"] == "ERROR"  # type: ignore[index]
    assert gate["status"] == "ERROR"
    assert gate["ci_exit_code"] == 1
    assert any(reason.startswith("regression_pack_invalid") or reason.startswith("invalid_regression_pack") for reason in gate["reasons"])


def test_invalid_policy_fails_closed_with_error_and_no_pass(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("max_blocking_findings: nope\n", encoding="utf-8")
    out_dir, result = _run_assessment(tmp_path, policy_path=policy, compare_targets=[])

    gate = json.loads((out_dir / "gate" / "gate-summary.json").read_text(encoding="utf-8"))
    assert result["assessment_gate"]["status"] == "ERROR"  # type: ignore[index]
    assert gate["status"] == "ERROR"
    assert gate["ci_exit_code"] == 1
    assert gate["reasons"]
    assert all("PASS" not in value for value in gate["reasons"])


def test_stale_or_incompatible_baseline_fails_closed(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"schema_version": "malleus.assessment_gate_baseline.v0", "profile": "model-selection"}), encoding="utf-8")
    out_dir, _result = _run_assessment(tmp_path, baseline_path=baseline, compare_targets=[])

    gate = json.loads((out_dir / "gate" / "gate-summary.json").read_text(encoding="utf-8"))
    assert gate["status"] == "ERROR"
    assert gate["ci_exit_code"] == 1
    assert "stale_or_incompatible_baseline" in gate["reasons"]


@pytest.fixture
def no_provider_calls(monkeypatch):
    class ExplodingAdapter:
        def __init__(self, *args, **kwargs):
            raise AssertionError("assessment compare must not instantiate provider adapters")

    runner_module = __import__("malleus.runner").runner
    monkeypatch.setitem(runner_module.ADAPTERS, "openai_compatible", ExplodingAdapter)
    monkeypatch.setitem(runner_module.ADAPTERS, "nvidia", ExplodingAdapter)
    monkeypatch.setitem(runner_module.ADAPTERS, "ollama", ExplodingAdapter)


def test_assess_cli_compare_target_smoke_writes_expected_artifacts(no_provider_calls, tmp_path: Path) -> None:
    out_dir = tmp_path / "cli-out"
    result = CliRunner().invoke(
        app,
        [
            "assess",
            "--target",
            str(_write_target(tmp_path, name="cli-primary", model="model-a")),
            "--compare-target",
            str(_write_target(tmp_path, name="cli-compare", model="model-b", adapter="ollama")),
            "--profile",
            "model-selection",
            "--mode",
            "dry_run",
            "--out-dir",
            str(out_dir),
        ],
    )

    assert result.exit_code == 0
    assert (out_dir / "model-comparison" / "comparison-summary.md").exists()
    assert (out_dir / "model-comparison" / "comparison.json").exists()
    assert (out_dir / "model-comparison" / "leaderboard.html").exists()
    assert (out_dir / "gate" / "gate-summary.json").exists()
