from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from typer.testing import CliRunner

from malleus.benchmark_suite import build_benchmark_suite_plan, run_benchmark_suite
from malleus.cli import app


def test_benchmark_suite_plan_selects_compatible_target_packs(tmp_path: Path) -> None:
    target = _tool_target(tmp_path)
    matrix = _matrix(tmp_path)

    report = build_benchmark_suite_plan(target, matrix)

    assert report.target_type == "tool_agent"
    assert [pack.pack_id for pack in report.packs] == ["agentic-injection-v1", "self-modification-v1"]
    assert report.status_counts == {"selected": 2}


def test_benchmark_suite_dry_run_writes_report(tmp_path: Path) -> None:
    target = _tool_target(tmp_path)
    matrix = _matrix(tmp_path)
    out = tmp_path / "suite"

    report = run_benchmark_suite(target, matrix, out, dry_run=True)

    assert report.dry_run is True
    payload = json.loads((out / "benchmark-suite-report.json").read_text(encoding="utf-8"))
    assert payload["packs"][0]["pack_id"] == "agentic-injection-v1"
    assert (out / "benchmark-suite-report.md").exists()


def test_benchmark_suite_runs_selected_packs_with_runner(tmp_path: Path) -> None:
    target = _tool_target(tmp_path)
    matrix = _matrix(tmp_path)
    calls: list[str] = []

    def runner(**kwargs):
        calls.append(kwargs["pack_id"])
        row = _row(kwargs["pack_id"])
        return SimpleNamespace(rows=[row]), None, None

    report = run_benchmark_suite(target, matrix, tmp_path / "suite", yes=True, runner=runner)

    assert calls == ["agentic-injection-v1", "self-modification-v1"]
    assert report.status_counts == {"passed": 2}
    payload = json.loads((tmp_path / "suite" / "benchmark-suite-report.json").read_text(encoding="utf-8"))
    assert len(payload["rows"]) == 2
    assert payload["packs"][0]["output_dir"] == "surfaces/agentic-injection-v1"


def test_benchmark_suite_cli_runs_without_yes_for_live_execution(monkeypatch, tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    def fake_run_benchmark_suite(*args, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(target_name="target", target_type="tool_agent", packs=[], dry_run=False, status_counts={})

    monkeypatch.setattr("malleus.cli.run_benchmark_suite", fake_run_benchmark_suite)
    result = CliRunner().invoke(app, ["benchmark", "suite", "--target", str(_tool_target(tmp_path)), "--matrix", str(_matrix(tmp_path)), "--out-dir", str(tmp_path / "suite")])

    assert result.exit_code == 0, result.output
    assert captured["yes"] is True


def test_benchmark_suite_cli_dry_run(tmp_path: Path) -> None:
    out = tmp_path / "suite"
    result = CliRunner().invoke(app, ["benchmark", "suite", "--target", str(_tool_target(tmp_path)), "--matrix", str(_matrix(tmp_path)), "--out-dir", str(out), "--dry-run"])

    assert result.exit_code == 0, result.output
    assert "Benchmark suite written" in result.output
    assert (out / "benchmark-suite-report.json").exists()


def _tool_target(tmp_path: Path) -> Path:
    target = tmp_path / "target.yaml"
    target.write_text(
        """name: local-tool-agent
target_type: tool_agent
tool_agent:
  endpoint_url: http://127.0.0.1:8765/tool-agent
  auth:
    api_key_env: MALLEUS_TOOL_AGENT_KEY
""",
        encoding="utf-8",
    )
    return target


def _matrix(tmp_path: Path) -> Path:
    matrix = tmp_path / "matrix.yaml"
    matrix.write_text(
        """schema_version: malleus.release_matrix.v1
id: suite-test
version: 1.0.0
mode_boundaries:
  - mode: live_provider
    evidence_level: live_model_required
    provider_calls_enabled: true
packs:
  - id: smoke-v1
    path: datasets/benchmark_packs/smoke-v1.yaml
    evidence_level: live_model_required
    target_types: [chat_completion]
  - id: agentic-injection-v1
    path: datasets/agentic/agentic_injection_v1.yaml
    evidence_level: live_model_required
    target_types: [tool_agent]
  - id: self-modification-v1
    path: tests/fixtures/self_modification
    evidence_level: live_model_required
    target_types: [tool_agent, workflow_harness]
selected_mutation_profiles: []
deep_mutation_profiles: []
gates: []
""",
        encoding="utf-8",
    )
    return matrix


def _row(pack_id: str):
    class Row:
        def model_dump(self, mode: str = "json"):
            return {
                "row_id": f"pack:{pack_id}",
                "status": "passed",
                "metadata": {"reason_codes": [], "report_json": f"{pack_id}/report.json"},
            }

    return Row()
