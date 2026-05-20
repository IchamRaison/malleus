from __future__ import annotations

import json
from pathlib import Path

import yaml
from typer.testing import CliRunner

from malleus.benchmark_workflow import load_benchmark_panel, summarize_benchmark_reports, write_benchmark_plan
from malleus.cli import app


def test_benchmark_panel_fixture_has_public_model_range() -> None:
    panel = load_benchmark_panel("tests/fixtures/models/panel.yaml")

    assert len(panel.models) == 6
    assert all(model.target for model in panel.models)
    assert {model.publisher for model in panel.models} >= {"NVIDIA", "Meta", "Qwen"}


def test_benchmark_plan_writes_provider_free_commands(tmp_path: Path) -> None:
    plan, json_path, markdown_path = write_benchmark_plan("tests/fixtures/models/panel.yaml", tmp_path / "plan", dry_run=True)

    assert json_path.exists()
    assert markdown_path.exists()
    assert plan.provider_calls_enabled is False
    assert all(step.provider_calls_enabled is False for step in plan.steps)
    commands = [" ".join(step.command) for step in plan.steps]
    assert any("malleus run" in command and "--dry-run" in command for command in commands)
    assert any("malleus mutate-run" in command and "--dry-run" in command for command in commands)
    assert any("malleus agent-lab" in command and "--dry-run" in command for command in commands)
    assert any("malleus campaign run" in command and "--dry-run" in command for command in commands)
    assert any("malleus coverage build" in command for command in commands)
    assert any("malleus evidence-bundle" in command and "--audit-mode" in command for command in commands)
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["provider_calls_enabled"] is False


def test_benchmark_plan_generates_model_specific_target_configs(tmp_path: Path) -> None:
    panel = load_benchmark_panel("tests/fixtures/models/panel.yaml")
    plan, _, markdown_path = write_benchmark_plan("tests/fixtures/models/panel.yaml", tmp_path / "plan", dry_run=True)
    smoke_steps = [step for step in plan.steps if step.id.endswith("-smoke")]

    assert len(smoke_steps) == len(panel.models)
    target_paths = [Path(step.command[step.command.index("--target") + 1]) for step in smoke_steps]
    assert len(set(target_paths)) == len(panel.models)
    for target_path, model in zip(target_paths, panel.models, strict=True):
        target = yaml.safe_load(target_path.read_text(encoding="utf-8"))
        assert target["model"] == model.model
        assert target["name"].startswith("benchmark-")
    text = markdown_path.read_text(encoding="utf-8")
    assert "--run-report" in text
    assert "--mutation-report" in text
    assert "--agent-report" in text


def test_benchmark_plan_cli_rejects_live_provider_mode(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        app,
        ["benchmark", "plan", "--models", "tests/fixtures/models/panel.yaml", "--out-dir", str(tmp_path / "plan"), "--no-dry-run"],
    )

    assert result.exit_code == 1
    assert "provider-free dry-run" in result.output


def test_benchmark_plan_cli_writes_planned_commands(tmp_path: Path) -> None:
    out = tmp_path / "plan"
    result = CliRunner().invoke(app, ["benchmark", "plan", "--models", "tests/fixtures/models/panel.yaml", "--out-dir", str(out), "--dry-run"])

    assert result.exit_code == 0, result.output
    assert (out / "benchmark-plan.json").exists()
    assert (out / "benchmark-plan.md").exists()
    assert "Provider calls enabled: false" in result.output
    assert "malleus mutate-run" in (out / "benchmark-plan.md").read_text(encoding="utf-8")


def test_benchmark_summarize_writes_leaderboard_and_case_studies(tmp_path: Path) -> None:
    out = tmp_path / "summary"
    summary, json_path, markdown_path = summarize_benchmark_reports("tests/fixtures/benchmark_reports", out)

    assert json_path.exists()
    assert markdown_path.exists()
    assert len(summary.leaderboard) == 3
    assert summary.leaderboard[0].model == "fixture/model-a"
    assert summary.leaderboard[0].risk_card == "model-a/model-risk-card.md"
    assert any("LLM01 Prompt Injection" in row.taxonomy_coverage_hints for row in summary.leaderboard)
    assert len(summary.case_studies) == 3
    for relpath in summary.case_studies:
        text = (out / relpath).read_text(encoding="utf-8")
        assert "This template is sanitized" in text
        assert "raw model output" in text
        assert "system prompt" not in text.lower()


def test_benchmark_summarize_cli_does_not_edit_readme_by_default(tmp_path: Path) -> None:
    readme = tmp_path / "README.md"
    readme.write_text("# Existing\n", encoding="utf-8")
    out = tmp_path / "summary"
    result = CliRunner().invoke(app, ["benchmark", "summarize", "--reports", "tests/fixtures/benchmark_reports", "--out-dir", str(out)])

    assert result.exit_code == 0, result.output
    assert (out / "leaderboard.json").exists()
    assert (out / "leaderboard.md").exists()
    assert readme.read_text(encoding="utf-8") == "# Existing\n"
    assert "README block written" not in result.output


def test_benchmark_summarize_cli_explicit_readme_write_is_bounded(tmp_path: Path) -> None:
    readme = tmp_path / "README.md"
    readme.write_text("# Existing\n", encoding="utf-8")
    result = CliRunner().invoke(
        app,
        [
            "benchmark",
            "summarize",
            "--reports",
            "tests/fixtures/benchmark_reports",
            "--out-dir",
            str(tmp_path / "summary"),
            "--write-readme",
            str(readme),
        ],
    )

    assert result.exit_code == 0, result.output
    text = readme.read_text(encoding="utf-8")
    assert "<!-- malleus-benchmark:start -->" in text
    assert "<!-- malleus-benchmark:end -->" in text
    assert "fixture/model-a" in text


def test_benchmark_outputs_redact_unsafe_ids_and_quote_markdown_commands(tmp_path: Path) -> None:
    target = tmp_path / "target with spaces.yaml"
    target.write_text(
        "name: t\nadapter: openai_compatible\nmodel: base/model\nbase_url: https://example.test/v1\napi_key_env: OPENAI_API_KEY\n",
        encoding="utf-8",
    )
    panel = tmp_path / "panel.yaml"
    models = "\n".join(
        f"  - name: m{index}\n    publisher: P\n    model: provider/model-{index}\n    target: {str(target)!r}"
        for index in range(1, 6)
    )
    panel.write_text(f"name: p\nversion: 1\nmodels:\n{models}\n", encoding="utf-8")
    _, _, markdown_path = write_benchmark_plan(panel, tmp_path / "plan", dry_run=True)
    markdown = markdown_path.read_text(encoding="utf-8")
    assert "'" in markdown

    reports = tmp_path / "reports"
    report_dir = reports / "model"
    report_dir.mkdir(parents=True)
    (report_dir / "report.json").write_text(
        json.dumps(
            {
                "target_model": "system_prompt=SECRET_MODEL",
                "metadata": {"publisher": "developer_message=SECRET_PUBLISHER"},
                "summary": {"score_total": 0, "max_score_total": 100, "passed_items": 0, "total_items": 1},
                "datasets": [
                    {
                        "case_results": [
                            {
                                "case_id": "exfiltrate_secret token=CASESECRET",
                                "severity": "high",
                                "objective": "system_prompt token=OBJECTIVESECRET",
                                "passed": False,
                                "metadata": {"owasp": "LLM01 Prompt Injection"},
                            }
                        ],
                        "group_results": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    summary, json_path, markdown_path = summarize_benchmark_reports(reports, tmp_path / "summary")
    output = json_path.read_text(encoding="utf-8") + markdown_path.read_text(encoding="utf-8")
    for relpath in summary.case_studies:
        output += (tmp_path / "summary" / relpath).read_text(encoding="utf-8")
    assert "SECRET" not in output
    assert "system_prompt" not in output.lower()
    assert "exfiltrate_secret" not in output.lower()
