from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from malleus.cli import app
from malleus.resources import resource_path
from malleus.target_store import add_managed_target


def test_quickstart_command_shows_default_flow() -> None:
    result = CliRunner().invoke(app, ["quickstart"])

    assert result.exit_code == 0
    assert "Malleus quickstart" in result.output
    assert "malleus target init" in result.output
    assert "malleus target doctor <target-name> --live-check" in result.output
    assert "malleus benchmark soft --target <target-name>" in result.output


def test_quickstart_command_renders_target_specific_commands() -> None:
    result = CliRunner().invoke(app, ["quickstart", "--target", "sample-target"])

    assert result.exit_code == 0
    assert "Target: sample-target" in result.output
    assert "malleus target doctor sample-target --live-check" in result.output
    assert "malleus run sample-target" in result.output
    assert "malleus benchmark soft --target sample-target" in result.output
    assert "malleus evidence-bundle --run-report" in result.output


def test_project_doctor_command_reports_install_status(tmp_path: Path) -> None:
    out_dir = tmp_path / "doctor"
    result = CliRunner().invoke(app, ["doctor", "--out-dir", str(out_dir)])

    assert result.exit_code == 0, result.output
    assert "Malleus project doctor" in result.output
    assert "package_assets" in result.output
    assert "python -m build" in result.output
    assert (out_dir / "project-doctor.json").exists()


def test_init_command_wraps_target_init_and_prints_next_path(tmp_path: Path) -> None:
    target_path = tmp_path / "deepseek.yaml"
    result = CliRunner().invoke(
        app,
        [
            "init",
            "--provider",
            "deepseek",
            "--non-interactive",
            "--out",
            str(target_path),
            "--env-file",
            str(tmp_path / "missing.env"),
        ],
    )

    assert result.exit_code == 0, result.output
    assert target_path.exists()
    assert "Target saved: deepseek-deepseek-v4-flash" in result.output
    assert "Next benchmark path:" in result.output
    assert f"malleus benchmark soft --target {target_path}" in result.output


def test_run_command_writes_reports(monkeypatch) -> None:
    runner = CliRunner()

    captured = {}

    def fake_run(target_path: Path, input_path: Path, scoring_path: Path, output_dir: Path, **kwargs):
        captured.update(kwargs)
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "report.json").write_text("{}", encoding="utf-8")
        (output_dir / "report.md").write_text("# report\n", encoding="utf-8")

        class Summary:
            score_total = 100
            max_score_total = 100

        class Report:
            run_id = "run-test"
            summary = Summary()

        return Report()

    monkeypatch.setattr("malleus.cli.run_benchmark", fake_run)

    with runner.isolated_filesystem():
        Path("out").mkdir()
        Path("target.yaml").write_text(
            "name: t\nadapter: openai_compatible\nmodel: m\nbase_url: https://example.test/v1\napi_key_env: OPENAI_API_KEY\n",
            encoding="utf-8",
        )
        Path("input.yaml").write_text(
            "name: d\nversion: 1\ncategory: c\nsubcategory: s\ncases:\n  - id: c1\n    severity: low\n    objective: x\n    prompt: hi\n",
            encoding="utf-8",
        )
        Path("scoring.yaml").write_text(
            "version: 1\nmax_score: 100\nseverity_weights:\n  low: 10\n  medium: 20\n  high: 35\n  critical: 50\n",
            encoding="utf-8",
        )
        result = runner.invoke(
            app,
            [
                "run",
                "--target",
                "target.yaml",
                "--input",
                "input.yaml",
                "--scoring",
                "scoring.yaml",
                "--out-dir",
                "out",
                "--repeats",
                "2",
                "--temperature-schedule",
                "0,0.7",
            ],
        )

        assert result.exit_code == 0
        assert "Run complete: run-test" in result.output
        assert Path("out/report.json").exists()
        assert Path("out/report.md").exists()
        assert captured["repeats"] == 2
        assert captured["temperature_schedule"] == [0.0, 0.7]


def test_run_command_resolves_managed_target_name(monkeypatch, tmp_path: Path) -> None:
    runner = CliRunner()
    target_dir = tmp_path / "targets"
    target_path = add_managed_target(
        {
            "name": "Managed Run",
            "adapter": "openai_compatible",
            "model": "m",
            "base_url": "https://example.test/v1",
            "api_key_env": "MANAGED_RUN_KEY",
        },
        target_dir,
    )
    input_path = tmp_path / "input.yaml"
    input_path.write_text(
        "name: d\nversion: 1\ncategory: c\nsubcategory: s\ncases:\n  - id: c1\n    severity: low\n    objective: x\n    prompt: hi\n",
        encoding="utf-8",
    )
    scoring_path = tmp_path / "scoring.yaml"
    scoring_path.write_text(
        "version: 1\nmax_score: 100\nseverity_weights:\n  low: 10\n  medium: 20\n  high: 35\n  critical: 50\n",
        encoding="utf-8",
    )
    captured = {}

    def fake_run(target_path_arg: Path, input_path_arg: Path, scoring_path_arg: Path, output_dir: Path, **kwargs):
        captured["target_path"] = target_path_arg

        class Summary:
            score_total = 100
            max_score_total = 100

        class Report:
            run_id = "run-managed"
            summary = Summary()

        return Report()

    monkeypatch.setattr("malleus.cli.run_benchmark", fake_run)

    result = runner.invoke(
        app,
        [
            "run",
            "--target",
            "Managed Run",
            "--config-dir",
            str(target_dir),
            "--input",
            str(input_path),
            "--scoring",
            str(scoring_path),
            "--out-dir",
            str(tmp_path / "out"),
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured["target_path"] == target_path.resolve()


def test_compare_command_resolves_managed_target_name(monkeypatch, tmp_path: Path) -> None:
    runner = CliRunner()
    target_dir = tmp_path / "targets"
    target_path = add_managed_target(
        {
            "name": "Managed Compare",
            "adapter": "openai_compatible",
            "model": "base-model",
            "base_url": "https://example.test/v1",
            "api_key_env": "MANAGED_COMPARE_KEY",
        },
        target_dir,
    )
    input_path = tmp_path / "input.yaml"
    input_path.write_text(
        "name: d\nversion: 1\ncategory: c\nsubcategory: s\ncases:\n  - id: c1\n    severity: low\n    objective: x\n    prompt: hi\n",
        encoding="utf-8",
    )
    scoring_path = tmp_path / "scoring.yaml"
    scoring_path.write_text(
        "version: 1\nmax_score: 100\nseverity_weights:\n  low: 10\n  medium: 20\n  high: 35\n  critical: 50\n",
        encoding="utf-8",
    )
    captured = {}

    def fake_compare(target_path_arg: Path, input_path_arg: Path, scoring_path_arg: Path, output_dir: Path, models: list[str], **kwargs):
        captured["target_path"] = target_path_arg
        captured["dry_run"] = kwargs["dry_run"]
        output_dir.mkdir(parents=True, exist_ok=True)
        return output_dir

    monkeypatch.setattr("malleus.cli.compare_models", fake_compare)

    result = runner.invoke(
        app,
        [
            "compare",
            "--target",
            "Managed Compare",
            "--config-dir",
            str(target_dir),
            "--input",
            str(input_path),
            "--scoring",
            str(scoring_path),
            "--out-dir",
            str(tmp_path / "out"),
            "--model",
            "candidate-model",
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured["target_path"] == target_path.resolve()
    assert captured["dry_run"] is True


def test_run_command_missing_managed_target_suggests_target_add(tmp_path: Path) -> None:
    input_path = tmp_path / "input.yaml"
    input_path.write_text(
        "name: d\nversion: 1\ncategory: c\nsubcategory: s\ncases:\n  - id: c1\n    severity: low\n    objective: x\n    prompt: hi\n",
        encoding="utf-8",
    )
    scoring_path = tmp_path / "scoring.yaml"
    scoring_path.write_text(
        "version: 1\nmax_score: 100\nseverity_weights:\n  low: 10\n  medium: 20\n  high: 35\n  critical: 50\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        app,
        [
            "run",
            "--target",
            "missing",
            "--config-dir",
            str(tmp_path / "targets"),
            "--input",
            str(input_path),
            "--scoring",
            str(scoring_path),
            "--out-dir",
            str(tmp_path / "out"),
        ],
    )

    assert result.exit_code == 1
    assert "target not found: missing" in result.output
    assert "malleus target add missing" in result.output


def test_run_command_rejects_directory_target_before_runner(monkeypatch, tmp_path: Path) -> None:
    input_path = tmp_path / "input.yaml"
    input_path.write_text(
        "name: d\nversion: 1\ncategory: c\nsubcategory: s\ncases:\n  - id: c1\n    severity: low\n    objective: x\n    prompt: hi\n",
        encoding="utf-8",
    )
    scoring_path = tmp_path / "scoring.yaml"
    scoring_path.write_text(
        "version: 1\nmax_score: 100\nseverity_weights:\n  low: 10\n  medium: 20\n  high: 35\n  critical: 50\n",
        encoding="utf-8",
    )

    def fail_run(*args, **kwargs):
        raise AssertionError("run_benchmark should not receive a directory target")

    monkeypatch.setattr("malleus.cli.run_benchmark", fail_run)

    result = CliRunner().invoke(
        app,
        [
            "run",
            "--target",
            str(tmp_path),
            "--input",
            str(input_path),
            "--scoring",
            str(scoring_path),
            "--out-dir",
            str(tmp_path / "out"),
        ],
    )

    assert result.exit_code == 1
    assert "target path is not a file" in result.output


def test_run_command_reports_invalid_target_config_without_traceback(tmp_path: Path) -> None:
    target_path = tmp_path / "target.yaml"
    target_path.write_text(
        "name: unsafe\nadapter: openai_compatible\nmodel: m\nbase_url: https://example.test/v1?api_key=SYNTHETIC-SK-OPENAI-SECRET\napi_key_env: OPENAI_API_KEY\n",
        encoding="utf-8",
    )
    input_path = tmp_path / "input.yaml"
    input_path.write_text(
        "name: d\nversion: 1\ncategory: c\nsubcategory: s\ncases:\n  - id: c1\n    severity: low\n    objective: x\n    prompt: hi\n",
        encoding="utf-8",
    )
    scoring_path = tmp_path / "scoring.yaml"
    scoring_path.write_text(
        "version: 1\nmax_score: 100\nseverity_weights:\n  low: 10\n  medium: 20\n  high: 35\n  critical: 50\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        app,
        [
            "run",
            "--target",
            str(target_path),
            "--input",
            str(input_path),
            "--scoring",
            str(scoring_path),
            "--out-dir",
            str(tmp_path / "out"),
            "--dry-run",
        ],
    )

    assert result.exit_code == 1
    assert "base_url must not include secret-like query parameters" in result.output
    assert "SYNTHETIC-SK-OPENAI-SECRET" not in result.output
    assert "input_value" not in result.output
    assert "Traceback" not in result.output


def test_run_command_reports_secret_system_prompt_without_secret_leak(tmp_path: Path) -> None:
    target_path = tmp_path / "target.yaml"
    target_path.write_text(
        "name: unsafe\nadapter: openai_compatible\nmodel: m\nbase_url: https://example.test/v1\napi_key_env: OPENAI_API_KEY\nsystem_prompt: 'Authorization: Bearer SYNTHETIC-SK-OPENAI-SECRET'\n",
        encoding="utf-8",
    )
    input_path = tmp_path / "input.yaml"
    input_path.write_text(
        "name: d\nversion: 1\ncategory: c\nsubcategory: s\ncases:\n  - id: c1\n    severity: low\n    objective: x\n    prompt: hi\n",
        encoding="utf-8",
    )
    scoring_path = tmp_path / "scoring.yaml"
    scoring_path.write_text(
        "version: 1\nmax_score: 100\nseverity_weights:\n  low: 10\n  medium: 20\n  high: 35\n  critical: 50\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        app,
        [
            "run",
            "--target",
            str(target_path),
            "--input",
            str(input_path),
            "--scoring",
            str(scoring_path),
            "--out-dir",
            str(tmp_path / "out"),
            "--dry-run",
        ],
    )

    assert result.exit_code == 1
    assert "system_prompt: Value error, literal secret-like values are not allowed at system_prompt" in result.output
    assert "SYNTHETIC-SK-OPENAI-SECRET" not in result.output
    assert "input_value" not in result.output
    assert "Traceback" not in result.output


def test_run_command_reports_provider_runtime_failure_without_traceback(monkeypatch, tmp_path: Path) -> None:
    target_path = tmp_path / "target.yaml"
    target_path.write_text(
        "name: t\nadapter: openai_compatible\nmodel: m\nbase_url: https://example.test/v1\napi_key_env: OPENAI_API_KEY\n",
        encoding="utf-8",
    )
    input_path = tmp_path / "input.yaml"
    input_path.write_text(
        "name: d\nversion: 1\ncategory: c\nsubcategory: s\ncases:\n  - id: c1\n    severity: low\n    objective: x\n    prompt: hi\n",
        encoding="utf-8",
    )
    scoring_path = tmp_path / "scoring.yaml"
    scoring_path.write_text(
        "version: 1\nmax_score: 100\nseverity_weights:\n  low: 10\n  medium: 20\n  high: 35\n  critical: 50\n",
        encoding="utf-8",
    )

    def fail_run(*args, **kwargs):
        raise RuntimeError("Temporary failure in name resolution token=SYNTHETIC-SK-OPENAI-SECRET")

    monkeypatch.setattr("malleus.cli.run_benchmark", fail_run)
    result = CliRunner().invoke(
        app,
        [
            "run",
            "--target",
            str(target_path),
            "--input",
            str(input_path),
            "--scoring",
            str(scoring_path),
            "--out-dir",
            str(tmp_path / "out"),
        ],
    )

    assert result.exit_code == 1
    assert "Malleus run failed" in result.output
    assert "provider/runtime problem, not a model safety result" in result.output
    assert "malleus target doctor" in result.output
    assert "malleus network-doctor" in result.output
    assert "Sandbox/network diagnosis" in result.output
    assert "SYNTHETIC-SK-OPENAI-SECRET" not in result.output
    assert "Traceback" not in result.output


def test_network_doctor_reports_dns_failure_with_sandbox_hint(monkeypatch, tmp_path: Path) -> None:
    target_dir = tmp_path / "targets"
    add_managed_target(
        {
            "name": "DeepSeek Net",
            "adapter": "openai_compatible",
            "model": "deepseek-chat",
            "base_url": "https://api.deepseek.com/v1",
            "api_key_env": "DEEPSEEK_API_KEY",
        },
        target_dir,
    )
    monkeypatch.setattr("malleus.cli._resolve_host", lambda host, port: {"ok": False, "error_type": "gaierror", "message": "Temporary failure in name resolution", "addresses": []})
    monkeypatch.setattr(
        "malleus.cli._read_resolver_config",
        lambda: {"path": "/etc/resolv.conf", "readable": True, "nameservers": ["100.100.100.100"], "search": ["tail.test"]},
    )

    result = CliRunner().invoke(app, ["network-doctor", "--target", "DeepSeek Net", "--config-dir", str(target_dir)])

    assert result.exit_code == 1
    assert "Malleus network doctor" in result.output
    assert "Status: blocked" in result.output
    assert "[fail] gaierror: Temporary failure in name resolution" in result.output
    assert "tailscale_dns_unreachable" in result.output


def test_network_doctor_reports_ready_for_resolved_host(monkeypatch) -> None:
    monkeypatch.setattr("malleus.cli._resolve_host", lambda host, port: {"ok": True, "error_type": None, "message": "", "addresses": ["203.0.113.10"], "address_count": 1})
    monkeypatch.setattr("malleus.cli._read_resolver_config", lambda: {"path": "/etc/resolv.conf", "readable": True, "nameservers": ["1.1.1.1"], "search": []})

    result = CliRunner().invoke(app, ["network-doctor", "--host", "example.test"])

    assert result.exit_code == 0
    assert "Status: ready" in result.output
    assert "[ok] resolved 1 address(es): 203.0.113.10" in result.output


def test_target_test_reports_invalid_target_config_without_secret_leak(tmp_path: Path) -> None:
    target_path = tmp_path / "target.yaml"
    target_path.write_text(
        "name: unsafe\nadapter: openai_compatible\nmodel: m\nbase_url: https://example.test/v1?api_key=SYNTHETIC-SK-OPENAI-SECRET\napi_key_env: OPENAI_API_KEY\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["target", "test", str(target_path)])

    assert result.exit_code == 1
    assert "config: failed - base_url: Value error, base_url must not include secret-like query parameters: api_key" in result.output
    assert "SYNTHETIC-SK-OPENAI-SECRET" not in result.output
    assert "input_value" not in result.output
    assert "Traceback" not in result.output


def test_compare_command_reports_invalid_target_config_without_secret_leak(tmp_path: Path) -> None:
    target_path = tmp_path / "target.yaml"
    target_path.write_text(
        "name: unsafe\nadapter: openai_compatible\nmodel: m\nbase_url: https://example.test/v1?api_key=SYNTHETIC-SK-OPENAI-SECRET\napi_key_env: OPENAI_API_KEY\n",
        encoding="utf-8",
    )
    input_path = tmp_path / "input.yaml"
    input_path.write_text(
        "name: d\nversion: 1\ncategory: c\nsubcategory: s\ncases:\n  - id: c1\n    severity: low\n    objective: x\n    prompt: hi\n",
        encoding="utf-8",
    )
    scoring_path = tmp_path / "scoring.yaml"
    scoring_path.write_text(
        "version: 1\nmax_score: 100\nseverity_weights:\n  low: 10\n  medium: 20\n  high: 35\n  critical: 50\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        app,
        [
            "compare",
            "--target",
            str(target_path),
            "--input",
            str(input_path),
            "--scoring",
            str(scoring_path),
            "--out-dir",
            str(tmp_path / "out"),
            "--model",
            "m2",
        ],
    )

    assert result.exit_code == 1
    assert "base_url: Value error, base_url must not include secret-like query parameters: api_key" in result.output
    assert "SYNTHETIC-SK-OPENAI-SECRET" not in result.output
    assert "input_value" not in result.output
    assert "Traceback" not in result.output


def test_live_surface_command_reports_invalid_target_config_without_secret_leak(tmp_path: Path) -> None:
    target_path = tmp_path / "target.yaml"
    target_path.write_text(
        "name: unsafe\ntarget_type: rag_service\nrag_service:\n  endpoint_url: https://rag.example.test/query?api_key=SYNTHETIC-SK-OPENAI-SECRET\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        app,
        [
            "benchmark",
            "live-rag",
            "--target",
            str(target_path),
            "--out-dir",
            str(tmp_path / "out"),
            "--yes",
        ],
    )

    assert result.exit_code == 1
    assert "rag_service: Value error, literal secret-like values are not allowed at endpoint_url; use environment variable references" in result.output
    assert "SYNTHETIC-SK-OPENAI-SECRET" not in result.output
    assert "input_value" not in result.output
    assert "Traceback" not in result.output


def test_soft_and_exterminatus_report_invalid_target_config_without_secret_leak(tmp_path: Path) -> None:
    target_path = tmp_path / "target.yaml"
    target_path.write_text(
        "name: unsafe\nadapter: openai_compatible\nmodel: m\nbase_url: https://example.test/v1?api_key=SYNTHETIC-SK-OPENAI-SECRET\napi_key_env: OPENAI_API_KEY\n",
        encoding="utf-8",
    )

    for command in ("soft", "exterminatus"):
        result = CliRunner().invoke(
            app,
            [
                "benchmark",
                command,
                "--target",
                str(target_path),
                "--out-dir",
                str(tmp_path / command),
                "--yes",
            ],
        )

        assert result.exit_code == 1
        assert "base_url: Value error, base_url must not include secret-like query parameters: api_key" in result.output
        assert "SYNTHETIC-SK-OPENAI-SECRET" not in result.output
        assert "input_value" not in result.output
        assert "Traceback" not in result.output


def test_live_self_modification_help_describes_live_harness_and_capability_gap() -> None:
    result = CliRunner().invoke(app, ["benchmark", "live-self-modification", "--help"])

    assert result.exit_code == 0
    assert "compatible live harnesses" in result.output
    assert "target_capability_gap" in result.output
    assert "only capability gap" not in result.output.lower()
    assert "capability-gap evidence" not in result.output.lower()



def test_evidence_bundle_command_invokes_writer(monkeypatch, tmp_path: Path) -> None:
    runner = CliRunner()
    run_report = tmp_path / "run.json"
    run_report.write_text("{}", encoding="utf-8")
    out = tmp_path / "bundle"

    class Summary:
        run_reports = 1
        failed_eval_items = 0
        agent_violations = 0
        hidden_findings = 0
        diff_newly_failing = 0

    class Bundle:
        title = "Bundle"
        summary = Summary()

    def fake_build(**kwargs):
        assert kwargs["run_reports"] == [run_report]
        assert kwargs["title"] == "Bundle"
        return Bundle()

    def fake_write(bundle, output_dir):
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / "index.html"
        path.write_text("<html></html>", encoding="utf-8")
        return path

    monkeypatch.setattr("malleus.cli.build_evidence_bundle", fake_build)
    monkeypatch.setattr("malleus.cli.write_evidence_bundle", fake_write)

    result = runner.invoke(app, ["evidence-bundle", "--title", "Bundle", "--run-report", str(run_report), "--out-dir", str(out)])

    assert result.exit_code == 0
    assert "Evidence bundle written" in result.output
    assert "Run reports: 1" in result.output
    assert (out / "index.html").exists()



def test_diff_runs_command_invokes_writer(monkeypatch, tmp_path: Path) -> None:
    runner = CliRunner()
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    old.write_text("{}", encoding="utf-8")
    new.write_text("{}", encoding="utf-8")
    out = tmp_path / "out"

    class Summary:
        score_delta = -100
        newly_failing = 1
        newly_passing = 0
        added_items = 0
        removed_items = 0

    class Diff:
        old_run_id = "old-run"
        new_run_id = "new-run"
        summary = Summary()

    def fake_diff(old_path, new_path):
        assert old_path == old
        assert new_path == new
        return Diff()

    def fake_write(diff, output_dir):
        output_dir.mkdir(parents=True, exist_ok=True)
        json_path = output_dir / "diff-runs-report.json"
        md_path = output_dir / "diff-runs-report.md"
        json_path.write_text("{}", encoding="utf-8")
        md_path.write_text("# diff\n", encoding="utf-8")
        return json_path, md_path

    monkeypatch.setattr("malleus.cli.diff_run_reports", fake_diff)
    monkeypatch.setattr("malleus.cli.write_diff_report", fake_write)

    result = runner.invoke(app, ["diff-runs", "--old", str(old), "--new", str(new), "--out-dir", str(out)])

    assert result.exit_code == 0
    assert "Run diff complete: old-run -> new-run" in result.output
    assert "Newly failing: 1" in result.output
    assert (out / "diff-runs-report.json").exists()
    assert (out / "diff-runs-report.md").exists()


def test_dashboard_command_writes_index(tmp_path: Path) -> None:
    runner = CliRunner()
    report = tmp_path / "report.json"
    report.write_text(
        '{"target_model":"model/a","summary":{"score_total":500,"max_score_total":500,"passed_items":5,"total_items":5},"datasets":[]}',
        encoding="utf-8",
    )
    out = tmp_path / "dashboard"
    result = runner.invoke(app, ["dashboard", "--report", str(report), "--out-dir", str(out)])
    assert result.exit_code == 0
    assert (out / "index.html").exists()


def test_validate_command_prints_human_report() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["validate", "--input", "datasets/benchmark_packs/smoke-v1.yaml"])

    assert result.exit_code == 0
    assert "Validation passed" in result.output


def test_validate_command_supports_json_output() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["validate", "--input", "datasets/benchmark_packs/smoke-v1.yaml", "--json"])

    assert result.exit_code == 0
    assert '"ok": true' in result.output
    assert '"errors": []' in result.output


def _gate_report_payload(*, severity: str = "high", passed: bool = True) -> dict:
    return {
        "run_id": "run-cli-gate",
        "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:00:01Z",
        "target_name": "target",
        "target_adapter": "openai_compatible",
        "target_model": "model",
        "input_path": "/tmp/input.yaml",
        "scoring_path": "/tmp/scoring.yaml",
        "datasets": [
            {
                "dataset_name": "dataset",
                "category": "category",
                "subcategory": "subcategory",
                "case_results": [
                    {
                        "dataset_name": "dataset",
                        "case_id": "case-1",
                        "severity": severity,
                        "objective": "objective",
                        "prompt": "prompt",
                        "response_text": "response",
                        "passed": passed,
                        "score": 100 if passed else 0,
                        "penalty": 0 if passed else 100,
                        "warnings": [],
                        "failure_checks": [],
                        "pass_checks": [],
                    }
                ],
                "group_results": [],
                "summary": {
                    "total_items": 1,
                    "passed_items": 1 if passed else 0,
                    "failed_items": 0 if passed else 1,
                    "score_total": 100 if passed else 0,
                    "max_score_total": 100,
                },
            }
        ],
        "summary": {
            "total_items": 1,
            "passed_items": 1 if passed else 0,
            "failed_items": 0 if passed else 1,
            "score_total": 100 if passed else 0,
            "max_score_total": 100,
        },
    }


def test_gate_command_returns_zero_for_pass_and_warn(tmp_path: Path) -> None:
    runner = CliRunner()
    report = tmp_path / "report.json"
    report.write_text(json.dumps(_gate_report_payload()), encoding="utf-8")
    pass_result = runner.invoke(app, ["gate", "--report", str(report)])

    dry_report = tmp_path / "dry-run.json"
    dry_report.write_text(json.dumps(_gate_report_payload()), encoding="utf-8")
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "malleus.ir.v1",
                "run_id": "run-cli-gate",
                "target_name": "target",
                "target_adapter": "openai_compatible",
                "target_model": "model",
                "input_path": "/tmp/input.yaml",
                "scoring_path": "/tmp/scoring.yaml",
                "output_dir": str(tmp_path),
                "dry_run": True,
            }
        ),
        encoding="utf-8",
    )
    warn_result = runner.invoke(app, ["gate", "--report", str(dry_report)])

    assert pass_result.exit_code == 0
    assert '"status": "pass"' in pass_result.output
    assert warn_result.exit_code == 0
    assert '"status": "warn"' in warn_result.output


def test_gate_command_returns_one_for_fail(tmp_path: Path) -> None:
    runner = CliRunner()
    report = tmp_path / "report.json"
    report.write_text(json.dumps(_gate_report_payload(severity="critical", passed=False)), encoding="utf-8")

    result = runner.invoke(app, ["gate", "--report", str(report)])

    assert result.exit_code == 1
    assert '"status": "fail"' in result.output


def test_gate_command_returns_two_for_error(tmp_path: Path) -> None:
    runner = CliRunner()
    report = tmp_path / "report.json"
    report.write_text(json.dumps(_gate_report_payload()), encoding="utf-8")
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "malleus.ir.v1",
                "run_id": "run-cli-gate",
                "target_name": "target",
                "target_adapter": "openai_compatible",
                "target_model": "model",
                "input_path": "/tmp/input.yaml",
                "scoring_path": "/tmp/scoring.yaml",
                "output_dir": str(tmp_path),
                "dry_run": False,
                "provider_errors": [{"error_type": "AdapterError", "message": "missing API key"}],
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["gate", "--report", str(report)])

    assert result.exit_code == 2
    assert '"status": "error"' in result.output


def test_inspect_text_command_supports_file_and_json_output(tmp_path: Path) -> None:
    runner = CliRunner()
    sample = tmp_path / "sample.md"
    sample.write_text("hello\u200b <!-- hidden -->", encoding="utf-8")

    result = runner.invoke(app, ["inspect-text", "--file", str(sample), "--json"])

    assert result.exit_code == 0
    assert '"total_findings": 2' in result.output
    assert '"zero_width"' in result.output
    assert '"html_comment"' in result.output


def test_inspect_text_command_writes_reports(tmp_path: Path) -> None:
    runner = CliRunner()
    sample = tmp_path / "sample.md"
    sample.write_text("hello\u202eworld", encoding="utf-8")
    out = tmp_path / "out"

    result = runner.invoke(app, ["inspect-text", "--file", str(sample), "--out-dir", str(out)])

    assert result.exit_code == 0
    assert "Hidden-channel inspection complete" in result.output
    assert (out / "hidden-channel-report.json").exists()
    assert (out / "hidden-channel-report.md").exists()


def test_inspect_artifact_command_writes_reports(tmp_path: Path) -> None:
    runner = CliRunner()
    sample = Path("tests/fixtures/artifacts/suspicious.svg")
    out = tmp_path / "artifact-out"

    result = runner.invoke(app, ["inspect-artifact", "--file", str(sample), "--out-dir", str(out)])

    assert result.exit_code == 0
    assert "Artifact firewall inspection complete" in result.output
    assert "Recommendation:" in result.output
    assert (out / "artifact-firewall-report.json").exists()
    assert (out / "artifact-firewall-report.md").exists()


def test_artifact_firewall_command_supports_json_alias() -> None:
    runner = CliRunner()
    sample = Path("tests/fixtures/artifacts/suspicious.svg")

    result = runner.invoke(app, ["artifact-firewall", "--file", str(sample), "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["manifest"]["format"] == "svg"
    assert payload["recommendation"] in {"quarantine", "block"}
    assert "call exfiltrate_secret" not in result.output


def test_mutations_list_and_inspect_commands() -> None:
    runner = CliRunner()
    listing = runner.invoke(app, ["mutations", "list"])
    assert listing.exit_code == 0
    assert "spacing" in listing.output
    assert "obfuscation" in listing.output

    detail = runner.invoke(app, ["mutations", "inspect", "spacing"])
    assert detail.exit_code == 0
    assert "Mutation: spacing" in detail.output
    assert "Risk:" in detail.output


def test_agent_lab_command_invokes_runner(monkeypatch, tmp_path: Path) -> None:
    runner = CliRunner()

    class Summary:
        total_scenarios = 2
        violations = 1
        highest_risk = "critical"

    class Report:
        run_id = "agent-run-test"
        summary = Summary()

    def fake_agent_lab(target_path, scenarios_path, output_dir, **kwargs):
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "agent-lab-report.json").write_text("{}", encoding="utf-8")
        return Report()

    monkeypatch.setattr("malleus.cli.run_agent_lab", fake_agent_lab)
    target = tmp_path / "target.yaml"
    target.write_text("name: t\nadapter: openai_compatible\nmodel: m\nbase_url: https://example.test/v1\n", encoding="utf-8")
    scenarios = tmp_path / "scenarios.yaml"
    scenarios.write_text("name: p\nversion: 1\nscenarios: []\n", encoding="utf-8")
    out = tmp_path / "out"

    result = runner.invoke(app, ["agent-lab", "--target", str(target), "--scenarios", str(scenarios), "--out-dir", str(out)])

    assert result.exit_code == 0
    assert "Agent lab complete: agent-run-test" in result.output
    assert "Violations: 1/2" in result.output


def test_mutate_run_command_invokes_runner(monkeypatch, tmp_path: Path) -> None:
    runner = CliRunner()
    captured = {}

    class Summary:
        total_original_items = 1
        total_mutated_items = 2
        worst_delta = -100
        worst_mutation = "spacing"

    class Report:
        run_id = "mut-run-test"
        summary = Summary()

    def fake_mutate_run(target_path, input_path, scoring_path, output_dir, **kwargs):
        captured.update(kwargs)
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "mutation-report.json").write_text("{}", encoding="utf-8")
        return Report()

    monkeypatch.setattr("malleus.cli.run_mutation_benchmark", fake_mutate_run)
    target = tmp_path / "target.yaml"
    target.write_text("name: t\nadapter: openai_compatible\nmodel: m\nbase_url: https://example.test/v1\n", encoding="utf-8")
    dataset = tmp_path / "dataset.yaml"
    dataset.write_text("name: d\nversion: 1\ncategory: c\nsubcategory: s\ncases:\n  - id: c1\n    severity: low\n    objective: x\n    prompt: hi\n", encoding="utf-8")
    scoring = tmp_path / "scoring.yaml"
    scoring.write_text("version: 1\nmax_score: 100\nseverity_weights:\n  low: 10\n  medium: 20\n  high: 35\n  critical: 50\n", encoding="utf-8")
    out = tmp_path / "out"

    result = runner.invoke(
        app,
        [
            "mutate-run",
            "--target",
            str(target),
            "--input",
            str(dataset),
            "--scoring",
            str(scoring),
            "--out-dir",
            str(out),
            "--mutation",
            "spacing",
            "--mutation",
            "markdown_quote",
        ],
    )

    assert result.exit_code == 0
    assert "Mutation run complete: mut-run-test" in result.output
    assert "Worst delta: -100" in result.output
    assert captured["mutations"] == ["spacing", "markdown_quote"]


def test_mutate_run_command_uses_selected_mutation_profile(monkeypatch, tmp_path: Path) -> None:
    runner = CliRunner()
    captured = {}

    class Summary:
        total_original_items = 1
        total_mutated_items = 25
        worst_delta = 0
        worst_mutation = None

    class Report:
        run_id = "mut-profile-test"
        summary = Summary()

    def fake_mutate_run(target_path, input_path, scoring_path, output_dir, **kwargs):
        captured.update(kwargs)
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "mutation-dry-run.json").write_text("{}", encoding="utf-8")
        return Report()

    monkeypatch.setattr("malleus.cli.run_mutation_benchmark", fake_mutate_run)
    target = tmp_path / "target.yaml"
    target.write_text("name: t\nadapter: openai_compatible\nmodel: m\nbase_url: https://example.test/v1\n", encoding="utf-8")
    dataset = tmp_path / "dataset.yaml"
    dataset.write_text("name: d\nversion: 1\ncategory: c\nsubcategory: s\ncases:\n  - id: c1\n    severity: low\n    objective: x\n    prompt: hi\n", encoding="utf-8")
    scoring = tmp_path / "scoring.yaml"
    scoring.write_text("version: 1\nmax_score: 100\nseverity_weights:\n  low: 10\n  medium: 20\n  high: 35\n  critical: 50\n", encoding="utf-8")
    out = tmp_path / "out"

    result = runner.invoke(
        app,
        [
            "mutate-run",
            "--target",
            str(target),
            "--input",
            str(dataset),
            "--scoring",
            str(scoring),
            "--out-dir",
            str(out),
            "--mutation-profile",
            "datasets/mutation_profiles/selected-v1.yaml",
            "--dry-run",
        ],
    )

    assert result.exit_code == 0
    assert "Mutation run complete: mut-profile-test" in result.output
    assert "Mutated items: 25" in result.output
    assert captured["dry_run"] is True
    assert len(captured["mutations"]) == 25
    assert captured["mutations"][0] == "unicode_wrap"
    assert captured["mutations"][-1] == "uppercase_text"
    assert captured["mutation_profile_path"] == Path("datasets/mutation_profiles/selected-v1.yaml")


def test_mutate_run_command_rejects_mutation_and_profile_together(monkeypatch, tmp_path: Path) -> None:
    runner = CliRunner()

    def fake_mutate_run(*args, **kwargs):
        raise AssertionError("run_mutation_benchmark should not be called for conflicting mutation options")

    monkeypatch.setattr("malleus.cli.run_mutation_benchmark", fake_mutate_run)
    target = tmp_path / "target.yaml"
    target.write_text("name: t\nadapter: openai_compatible\nmodel: m\nbase_url: https://example.test/v1\n", encoding="utf-8")
    dataset = tmp_path / "dataset.yaml"
    dataset.write_text("name: d\nversion: 1\ncategory: c\nsubcategory: s\ncases:\n  - id: c1\n    severity: low\n    objective: x\n    prompt: hi\n", encoding="utf-8")
    scoring = tmp_path / "scoring.yaml"
    scoring.write_text("version: 1\nmax_score: 100\nseverity_weights:\n  low: 10\n  medium: 20\n  high: 35\n  critical: 50\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "mutate-run",
            "--target",
            str(target),
            "--input",
            str(dataset),
            "--scoring",
            str(scoring),
            "--out-dir",
            str(tmp_path / "out"),
            "--mutation",
            "unicode_zwsp",
            "--mutation-profile",
            "datasets/mutation_profiles/selected-v1.yaml",
            "--dry-run",
        ],
    )

    assert result.exit_code == 1
    assert "--mutation and --mutation-profile cannot be used together" in result.output


def test_mutate_run_core_preset_uses_core_pack_and_deep_profile(monkeypatch, tmp_path: Path) -> None:
    runner = CliRunner()
    captured = {}

    class Summary:
        total_mutated_items = 140
        worst_delta = 0
        worst_mutation = None

    class Report:
        run_id = "mut-core"
        summary = Summary()

    def fake_mutate_run(target_path: Path, input_path: Path, scoring_path: Path, output_dir: Path, **kwargs):
        captured["target_path"] = target_path
        captured["input_path"] = input_path
        captured["scoring_path"] = scoring_path
        captured["output_dir"] = output_dir
        captured.update(kwargs)
        return Report()

    monkeypatch.setattr("malleus.cli.run_mutation_benchmark", fake_mutate_run)
    target = tmp_path / "target.yaml"
    target.write_text("name: t\nadapter: openai_compatible\nmodel: m\nbase_url: https://example.test/v1\n", encoding="utf-8")
    scoring = tmp_path / "scoring.yaml"
    scoring.write_text("version: 1\nmax_score: 100\nseverity_weights:\n  low: 10\n  medium: 20\n  high: 35\n  critical: 50\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "mutate-run",
            "core",
            "--target",
            str(target),
            "--scoring",
            str(scoring),
            "--out-dir",
            str(tmp_path / "out"),
            "--dry-run",
        ],
    )

    assert result.exit_code == 0
    assert "Mutation run complete: mut-core" in result.output
    assert captured["target_path"] == target
    assert captured["input_path"] == resource_path("datasets/benchmark_packs/core-v1.yaml")
    assert captured["scoring_path"] == scoring
    assert captured["output_dir"] == tmp_path / "out"
    assert len(captured["mutations"]) == 140
    assert captured["limit"] is None
    assert captured["case_ids"] is None
    assert captured["dry_run"] is True
    assert captured["mutation_profile_path"] == resource_path("datasets/mutation_profiles/deep-v1.yaml")


def test_mutate_run_core_preset_allows_explicit_mutation_override(monkeypatch, tmp_path: Path) -> None:
    runner = CliRunner()
    captured = {}

    class Summary:
        total_mutated_items = 1
        worst_delta = 0
        worst_mutation = "spacing"

    class Report:
        run_id = "mut-core-explicit"
        summary = Summary()

    def fake_mutate_run(target_path: Path, input_path: Path, scoring_path: Path, output_dir: Path, **kwargs):
        captured["input_path"] = input_path
        captured.update(kwargs)
        return Report()

    monkeypatch.setattr("malleus.cli.run_mutation_benchmark", fake_mutate_run)
    target = tmp_path / "target.yaml"
    target.write_text("name: t\nadapter: openai_compatible\nmodel: m\nbase_url: https://example.test/v1\n", encoding="utf-8")
    scoring = tmp_path / "scoring.yaml"
    scoring.write_text("version: 1\nmax_score: 100\nseverity_weights:\n  low: 10\n  medium: 20\n  high: 35\n  critical: 50\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "mutate-run",
            "core",
            "--target",
            str(target),
            "--scoring",
            str(scoring),
            "--out-dir",
            str(tmp_path / "out"),
            "--mutation",
            "spacing",
            "--dry-run",
        ],
    )

    assert result.exit_code == 0
    assert captured["input_path"] == resource_path("datasets/benchmark_packs/core-v1.yaml")
    assert captured["mutations"] == ["spacing"]
    assert captured["mutation_profile_path"] is None


def test_mutate_run_core_preset_allows_explicit_profile_override(monkeypatch, tmp_path: Path) -> None:
    runner = CliRunner()
    captured = {}

    class Summary:
        total_mutated_items = 25
        worst_delta = 0
        worst_mutation = None

    class Report:
        run_id = "mut-core-profile"
        summary = Summary()

    def fake_mutate_run(target_path: Path, input_path: Path, scoring_path: Path, output_dir: Path, **kwargs):
        captured["input_path"] = input_path
        captured.update(kwargs)
        return Report()

    monkeypatch.setattr("malleus.cli.run_mutation_benchmark", fake_mutate_run)
    target = tmp_path / "target.yaml"
    target.write_text("name: t\nadapter: openai_compatible\nmodel: m\nbase_url: https://example.test/v1\n", encoding="utf-8")
    scoring = tmp_path / "scoring.yaml"
    scoring.write_text("version: 1\nmax_score: 100\nseverity_weights:\n  low: 10\n  medium: 20\n  high: 35\n  critical: 50\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "mutate-run",
            "core",
            "--target",
            str(target),
            "--scoring",
            str(scoring),
            "--out-dir",
            str(tmp_path / "out"),
            "--mutation-profile",
            "datasets/mutation_profiles/selected-v1.yaml",
            "--dry-run",
        ],
    )

    assert result.exit_code == 0
    assert captured["input_path"] == resource_path("datasets/benchmark_packs/core-v1.yaml")
    assert len(captured["mutations"]) == 25
    assert captured["mutations"][0] == "unicode_wrap"
    assert captured["mutations"][-1] == "uppercase_text"
    assert captured["mutation_profile_path"] == Path("datasets/mutation_profiles/selected-v1.yaml")


def test_mutate_run_legacy_input_style_remains_valid(monkeypatch, tmp_path: Path) -> None:
    runner = CliRunner()
    captured = {}

    class Summary:
        total_mutated_items = 1
        worst_delta = 0
        worst_mutation = "spacing"

    class Report:
        run_id = "mut-legacy"
        summary = Summary()

    def fake_mutate_run(target_path: Path, input_path: Path, scoring_path: Path, output_dir: Path, **kwargs):
        captured["target_path"] = target_path
        captured["input_path"] = input_path
        captured["scoring_path"] = scoring_path
        captured["output_dir"] = output_dir
        captured.update(kwargs)
        return Report()

    monkeypatch.setattr("malleus.cli.run_mutation_benchmark", fake_mutate_run)
    target = tmp_path / "target.yaml"
    target.write_text("name: t\nadapter: openai_compatible\nmodel: m\nbase_url: https://example.test/v1\n", encoding="utf-8")
    dataset = tmp_path / "dataset.yaml"
    dataset.write_text("name: d\nversion: 1\ncategory: c\nsubcategory: s\ncases:\n  - id: c1\n    severity: low\n    objective: x\n    prompt: hi\n", encoding="utf-8")
    scoring = tmp_path / "scoring.yaml"
    scoring.write_text("version: 1\nmax_score: 100\nseverity_weights:\n  low: 10\n  medium: 20\n  high: 35\n  critical: 50\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "mutate-run",
            "--target",
            str(target),
            "--input",
            str(dataset),
            "--scoring",
            str(scoring),
            "--out-dir",
            str(tmp_path / "out"),
            "--mutation",
            "spacing",
            "--dry-run",
        ],
    )

    assert result.exit_code == 0
    assert "Mutation run complete: mut-legacy" in result.output
    assert captured["target_path"] == target
    assert captured["input_path"] == dataset
    assert captured["scoring_path"] == scoring
    assert captured["output_dir"] == tmp_path / "out"
    assert captured["mutations"] == ["spacing"]
    assert captured["dry_run"] is True
    assert captured["mutation_profile_path"] is None


def test_mutate_run_core_preset_rejects_explicit_input(monkeypatch, tmp_path: Path) -> None:
    runner = CliRunner()

    def fake_mutate_run(*args, **kwargs):
        raise AssertionError("run_mutation_benchmark should not be called when core preset is combined with --input")

    monkeypatch.setattr("malleus.cli.run_mutation_benchmark", fake_mutate_run)
    target = tmp_path / "target.yaml"
    target.write_text("name: t\nadapter: openai_compatible\nmodel: m\nbase_url: https://example.test/v1\n", encoding="utf-8")
    dataset = tmp_path / "dataset.yaml"
    dataset.write_text("name: d\nversion: 1\ncategory: c\nsubcategory: s\ncases:\n  - id: c1\n    severity: low\n    objective: x\n    prompt: hi\n", encoding="utf-8")
    scoring = tmp_path / "scoring.yaml"
    scoring.write_text("version: 1\nmax_score: 100\nseverity_weights:\n  low: 10\n  medium: 20\n  high: 35\n  critical: 50\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "mutate-run",
            "core",
            "--target",
            str(target),
            "--input",
            str(dataset),
            "--scoring",
            str(scoring),
            "--out-dir",
            str(tmp_path / "out"),
            "--dry-run",
        ],
    )

    assert result.exit_code == 1
    assert "core preset cannot be combined with --input" in result.output


def test_mutate_run_rejects_unknown_preset(monkeypatch, tmp_path: Path) -> None:
    runner = CliRunner()

    def fake_mutate_run(*args, **kwargs):
        raise AssertionError("run_mutation_benchmark should not be called for unknown presets")

    monkeypatch.setattr("malleus.cli.run_mutation_benchmark", fake_mutate_run)
    target = tmp_path / "target.yaml"
    target.write_text("name: t\nadapter: openai_compatible\nmodel: m\nbase_url: https://example.test/v1\n", encoding="utf-8")
    scoring = tmp_path / "scoring.yaml"
    scoring.write_text("version: 1\nmax_score: 100\nseverity_weights:\n  low: 10\n  medium: 20\n  high: 35\n  critical: 50\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "mutate-run",
            "smoke",
            "--target",
            str(target),
            "--scoring",
            str(scoring),
            "--out-dir",
            str(tmp_path / "out"),
            "--dry-run",
        ],
    )

    assert result.exit_code == 1
    assert "unknown mutate-run preset: smoke" in result.output


def test_mutations_cli_lists_and_inspects_metadata() -> None:
    runner = CliRunner()

    list_result = runner.invoke(app, ["mutations", "list"])
    inspect_result = runner.invoke(app, ["mutations", "inspect", "zero_width_insert"])
    tool_result = runner.invoke(app, ["mutations", "inspect", "tool_output_instruction"])

    assert list_result.exit_code == 0
    assert len([line for line in list_result.output.splitlines() if line.strip()]) >= 100
    assert "Family:" in list_result.output
    assert "Risk:" in list_result.output
    assert "Surface:" in list_result.output
    assert inspect_result.exit_code == 0
    assert "Mutation: zero_width_insert" in inspect_result.output
    assert "Risk:" in inspect_result.output
    assert "Surface:" in inspect_result.output
    assert "Deterministic: true" in inspect_result.output
    assert "Safe example:" in inspect_result.output
    assert "Boundary:" in inspect_result.output
    assert "Tags:" in inspect_result.output
    assert tool_result.exit_code == 0
    assert "Mutation: tool_output_instruction" in tool_result.output
    assert "Safe example:" in tool_result.output


def test_benchmark_validate_matrix_cli_is_provider_free() -> None:
    runner = CliRunner()

    result = runner.invoke(app, ["benchmark", "validate-matrix", "--matrix", "datasets/release_matrices/malleus-v0.1.yaml"])

    assert result.exit_code == 0
    assert "Release matrix valid" in result.output
    assert "Provider calls enabled: false" in result.output
    assert "Judge required: false" in result.output
    assert "Matrix: malleus-v0.1 0.1.0" in result.output
    assert "Pack entries: 15" in result.output
    assert "Selected mutation profiles: 1" in result.output
    assert "Deep mutation profiles: 1" in result.output
    assert "Total scoped entries: 17" in result.output
    assert "Packs: 2" not in result.output
    assert "Judge required: true" not in result.output


def test_mutations_validate_profile_cli_is_provider_free() -> None:
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "mutations",
            "validate-profile",
            "--profile",
            "datasets/mutation_profiles/selected-v1.yaml",
            "--deep-profile",
            "datasets/mutation_profiles/deep-v1.yaml",
        ],
    )

    assert result.exit_code == 0
    assert "Mutation profile valid" in result.output
    assert "Provider calls enabled: false" in result.output
    assert "Profile: selected-v1 1.0.0" in result.output
    assert "Mutations: 25" in result.output
    assert "Deep profile: deep-v1" in result.output


def test_rescore_cli_writes_cache_without_provider(monkeypatch, tmp_path: Path) -> None:
    class ExplodingAdapter:
        def __init__(self, target):
            raise AssertionError("rescore CLI must not instantiate providers")

    monkeypatch.setitem(__import__("malleus.runner").runner.ADAPTERS, "openai_compatible", ExplodingAdapter)
    source = tmp_path / "records.json"
    source.write_text(json.dumps({"records": [{"case_id": "c1", "reason_codes": ["CANARY_LEAK"], "evidence_level": "provider_free_static"}]}), encoding="utf-8")
    cache = tmp_path / "rescore-cache.json"

    result = CliRunner().invoke(app, ["rescore", "--source", str(source), "--cache", str(cache)])

    assert result.exit_code == 0
    assert "Rescore cache written" in result.output
    assert "Provider calls enabled: false" in result.output
    assert "Posture: SECURITY_FAIL" in result.output
    payload = json.loads(cache.read_text(encoding="utf-8"))
    assert payload["metadata"]["provider_calls_enabled"] is False


def test_triage_cli_writes_summary_without_provider(monkeypatch, tmp_path: Path) -> None:
    class ExplodingAdapter:
        def __init__(self, target):
            raise AssertionError("triage CLI must not instantiate providers")

    monkeypatch.setitem(__import__("malleus.runner").runner.ADAPTERS, "openai_compatible", ExplodingAdapter)
    source = tmp_path / "records.json"
    source.write_text(
        json.dumps(
            {
                "records": [
                    {
                        "case_id": "leak-case",
                        "finding_id": "F-1",
                        "severity": "high",
                        "surface": "chat",
                        "reason_codes": ["CANARY_LEAK"],
                        "evidence_level": "provider_free_static",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "triage-summary.json"

    result = CliRunner().invoke(app, ["triage", "--source", str(source), "--out", str(out)])

    assert result.exit_code == 0
    assert "Deterministic triage complete" in result.output
    assert "Provider calls enabled: false" in result.output
    assert "Posture: SECURITY_FAIL" in result.output
    assert "Total cases: 1" in result.output
    assert "Fail: 1" in result.output
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "malleus.deterministic_triage.v1"
    assert payload["posture"] == "SECURITY_FAIL"
    assert payload["fail_count"] == 1
    assert payload["model_security_failure_count"] == 1


def test_triage_cli_missing_source_fails_cleanly(tmp_path: Path) -> None:
    out = tmp_path / "triage-summary.json"

    result = CliRunner().invoke(app, ["triage", "--source", str(tmp_path / "missing.json"), "--out", str(out)])

    assert result.exit_code != 0
    assert "Deterministic triage complete" not in result.output
    assert "Posture: SECURITY_FAIL" not in result.output
    assert not out.exists()
