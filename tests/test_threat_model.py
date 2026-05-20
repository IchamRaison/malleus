from __future__ import annotations

from pathlib import Path

import yaml
from typer.testing import CliRunner

from malleus.cli import app
from malleus.coverage import build_coverage_report, write_coverage_report
from malleus.threat_model import SUPPORTED_PROFILES, compare_threat_model_coverage, init_threat_model, load_threat_model, write_threat_model


def test_threat_model_profiles_are_supported_and_deterministic(tmp_path: Path) -> None:
    assert set(SUPPORTED_PROFILES) == {"chat-model", "rag-agent", "tool-agent", "coding-agent", "multi-agent", "regulated-rag"}
    first = write_threat_model(init_threat_model("rag-agent"), tmp_path / "first.yaml")
    second = write_threat_model(init_threat_model("rag-agent"), tmp_path / "second.yaml")

    assert first.read_text(encoding="utf-8") == second.read_text(encoding="utf-8")
    payload = yaml.safe_load(first.read_text(encoding="utf-8"))
    assert payload["profile"] == "rag-agent"
    assert payload["metadata"]["provider_calls_enabled"] is False
    assert payload["recommended_packs"]
    assert payload["missing_coverage"]
    assert payload["gate_policy_template"]["fail_on_missing_required_cells"] is True
    assert payload["evidence_bundle_plan"]["redaction_required"] is True


def test_threat_model_status_summarizes_profile_without_model_calls(tmp_path: Path) -> None:
    path = write_threat_model(init_threat_model("tool-agent"), tmp_path / "model.yaml")
    result = CliRunner().invoke(app, ["threat-model", "status", "--model", str(path)])

    assert result.exit_code == 0, result.output
    assert "Profile: tool-agent" in result.output
    assert "Recommended packs:" in result.output
    assert "Required surfaces:" in result.output
    assert "Gate policy template:" in result.output
    assert "Missing/known coverage:" in result.output


def test_threat_model_coverage_marks_missing_cells_as_gaps(tmp_path: Path) -> None:
    coverage = build_coverage_report("datasets/benchmark_packs/smoke-v1.yaml")
    coverage_path, _, _ = write_coverage_report(coverage, tmp_path / "coverage")
    model_path = write_threat_model(init_threat_model("rag-agent"), tmp_path / "threat-model.yaml")

    model = load_threat_model(model_path)
    result = compare_threat_model_coverage(model, coverage)

    assert result.status == "gaps_present"
    assert result.missing_required_cells > 0
    assert any(cell.source_surface == "rag_context" for cell in result.missing_coverage)

    cli_result = CliRunner().invoke(app, ["threat-model", "coverage", "--model", str(model_path), "--coverage", str(coverage_path)])
    assert cli_result.exit_code == 1
    assert "Status: gaps_present" in cli_result.output
    assert "Missing coverage:" in cli_result.output


def test_threat_model_coverage_passes_only_when_required_cells_are_covered(tmp_path: Path) -> None:
    coverage = build_coverage_report("datasets/benchmark_packs/smoke-v1.yaml")
    model = init_threat_model("chat-model")

    result = compare_threat_model_coverage(model, coverage)

    assert result.status == "covered"
    assert result.covered_required_cells == result.total_required_cells
    assert result.missing_required_cells == 0


def test_threat_model_init_cli_writes_yaml(tmp_path: Path) -> None:
    out = tmp_path / "threat-model.yaml"
    result = CliRunner().invoke(app, ["threat-model", "init", "--profile", "rag-agent", "--out", str(out)])

    assert result.exit_code == 0, result.output
    assert out.exists()
    payload = yaml.safe_load(out.read_text(encoding="utf-8"))
    assert payload["profile"] == "rag-agent"
    assert payload["schema_version"] == "malleus.threat_model.v1"


def test_invalid_profile_fails_cleanly(tmp_path: Path) -> None:
    out = tmp_path / "bad.yaml"
    result = CliRunner().invoke(app, ["threat-model", "init", "--profile", "unknown", "--out", str(out)])

    assert result.exit_code == 1
    assert "unsupported threat-model profile" in result.output
