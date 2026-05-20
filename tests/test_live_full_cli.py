from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from malleus.cli import app
from malleus.live_full import run_live_full_matrix
from malleus.live_preflight import LivePreflightReport, SafeTargetEndpoint
from malleus.runner import run_benchmark as real_run_benchmark
from malleus.target_store import add_managed_target
from malleus.utils.redact import REDACTION_MARKER, scan_public_artifact_text


MATRIX = "datasets/release_matrices/malleus-v0.1.yaml"
SELECTED_PROFILE = "datasets/mutation_profiles/selected-v1.yaml"
DEEP_PROFILE = "datasets/mutation_profiles/deep-v1.yaml"


def _block_provider_calls(*args, **kwargs):
    raise RuntimeError("test blocks live provider execution")


def _block_mutation_provider_calls(*args, **kwargs):
    raise RuntimeError("test blocks live mutation provider execution")


@pytest.fixture(autouse=True)
def block_real_provider_paths(monkeypatch):
    monkeypatch.setattr("malleus.live_full.run_benchmark", _block_provider_calls)
    monkeypatch.setattr("malleus.live_full.run_mutation_benchmark", _block_mutation_provider_calls)


def test_live_full_help_lists_strict_options() -> None:
    result = CliRunner().invoke(app, ["benchmark", "live-full", "--help"], env={"COLUMNS": "200"})

    assert result.exit_code == 0
    assert "deep mutation profile rows" in result.output
    assert "Target model YAML config" in result.output
    assert "Provider request timeout" not in result.output
    assert "currently sequential" not in result.output
    assert ("later execution" + " tasks") not in result.output
    assert ("live-full " + "planning") not in result.output


def test_live_full_requires_core_options(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, ["benchmark", "live-full", "--out-dir", str(tmp_path / "out")])

    assert result.exit_code != 0
    assert "Missing option" in result.output


def test_live_full_rejects_missing_no_dry_run(tmp_path: Path) -> None:
    target = _target(tmp_path)

    result = CliRunner().invoke(
        app,
        ["benchmark", "live-full", "--target", str(target), "--matrix", MATRIX, "--mutation-profile", SELECTED_PROFILE, "--out-dir", str(tmp_path / "out")],
    )

    assert result.exit_code == 1
    assert "dry-run cannot be full-live evidence" in result.output


def test_live_full_runs_without_yes_before_preflight(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    preflight_called = False

    def preflight_runs(*args, **kwargs):
        nonlocal preflight_called
        preflight_called = True
        return _preflight(text_ready=True)

    monkeypatch.setattr("malleus.live_full.run_target_preflight", preflight_runs)

    result = CliRunner().invoke(
        app,
        ["benchmark", "live-full", "--target", str(target), "--matrix", MATRIX, "--mutation-profile", SELECTED_PROFILE, "--out-dir", str(tmp_path / "out"), "--no-dry-run"],
    )

    assert result.exit_code == 0, result.output
    assert preflight_called is True


def test_run_live_full_matrix_runs_without_yes_before_preflight(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    preflight_called = False

    def preflight_runs(*args, **kwargs):
        nonlocal preflight_called
        preflight_called = True
        return _preflight(text_ready=True)

    monkeypatch.setattr("malleus.live_full.run_target_preflight", preflight_runs)

    run_live_full_matrix(
        target_path=target,
        matrix_path=MATRIX,
        mutation_profile_path=SELECTED_PROFILE,
        out_dir=tmp_path / "out",
        dry_run=False,
        yes=False,
    )

    assert preflight_called is True


def test_live_full_writes_skeleton_with_monkeypatched_preflight(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True, timeout=kwargs["timeout"], retries=kwargs["max_retries"]))
    out = tmp_path / "out"

    result = CliRunner().invoke(
        app,
        [
            "benchmark",
            "live-full",
            "--target",
            str(target),
            "--matrix",
            MATRIX,
            "--mutation-profile",
            SELECTED_PROFILE,
            "--out-dir",
            str(out),
            "--no-dry-run",
            "--yes",
            "--concurrency",
            "2",
            "--request-timeout",
            "7.5",
            "--max-retries",
            "3",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Live-full evidence matrix written" in result.output
    payload = json.loads((out / "live-full-evidence.json").read_text(encoding="utf-8"))
    assert payload["schema_version"] == "malleus.live_evidence_matrix.v1"
    assert payload["metadata"]["dry_run"] is False
    assert payload["metadata"]["provider_calls_enabled"] is True
    assert payload["metadata"]["concurrency"] == 2
    assert payload["metadata"]["request_timeout"] == 7.5
    assert payload["metadata"]["max_retries"] == 3
    assert payload["metadata"]["preflight"]["text_ready"] is True
    assert all(row["dry_run"] is False for row in payload["rows"])
    assert all(row["status"] for row in payload["rows"])
    assert all(row["live_model_calls"] == 0 for row in payload["rows"])
    assert (out / "live-full-evidence.md").exists()


def test_live_full_resolves_managed_target_name(monkeypatch, tmp_path: Path) -> None:
    target_dir = tmp_path / "targets"
    add_managed_target(
        {
            "name": "Managed Live Full",
            "adapter": "openai_compatible",
            "model": "m",
            "base_url": "https://example.test/v1",
            "api_key_env": "MANAGED_LIVE_FULL_KEY",
        },
        target_dir,
    )
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True))
    out = tmp_path / "managed-live-full"

    result = CliRunner().invoke(
        app,
        [
            "benchmark",
            "live-full",
            "--target",
            "Managed Live Full",
            "--config-dir",
            str(target_dir),
            "--matrix",
            MATRIX,
            "--mutation-profile",
            SELECTED_PROFILE,
            "--out-dir",
            str(out),
            "--no-dry-run",
            "--yes",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads((out / "live-full-evidence.json").read_text(encoding="utf-8"))
    assert payload["rows"][0]["target"]["name"] == "Managed Live Full"


def test_live_full_skeleton_rejects_secret_bearing_target_base_url(monkeypatch, tmp_path: Path) -> None:
    raw_url = "http://user:pass@127.0.0.1:8080/v1?api_key=secret"
    target = _target(tmp_path, base_url=raw_url)
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True))
    out = tmp_path / "sanitized"

    result = CliRunner().invoke(
        app,
        ["benchmark", "live-full", "--target", str(target), "--matrix", MATRIX, "--mutation-profile", SELECTED_PROFILE, "--out-dir", str(out), "--no-dry-run", "--yes"],
    )

    assert result.exit_code == 1
    assert "base_url must not include username or password credentials" in result.output
    assert "user:pass" not in result.output
    assert "api_key=secret" not in result.output


def test_live_full_skeleton_sanitizes_target_metadata_paths(monkeypatch, tmp_path: Path) -> None:
    raw_secret = "private-metadata-token"
    raw_path = "/home/alice/private/malleus-target.yaml"
    target = _target(tmp_path, metadata={"owner": "security", "secret_note": raw_secret, "nested": {"path": raw_path, "enabled": True, "count": 2}})
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True))
    out = tmp_path / "metadata-sanitized"

    result = CliRunner().invoke(
        app,
        ["benchmark", "live-full", "--target", str(target), "--matrix", MATRIX, "--mutation-profile", SELECTED_PROFILE, "--out-dir", str(out), "--no-dry-run", "--yes"],
    )

    assert result.exit_code == 0, result.output
    json_text = (out / "live-full-evidence.json").read_text(encoding="utf-8")
    markdown_text = (out / "live-full-evidence.md").read_text(encoding="utf-8")
    combined = json_text + markdown_text
    assert "security" in combined
    assert raw_secret in combined
    assert raw_path not in combined
    assert REDACTION_MARKER in combined
    payload = json.loads(json_text)
    row_metadata = payload["rows"][0]["target"]["metadata"]
    assert row_metadata["owner"] == "security"
    assert row_metadata["nested"]["enabled"] is True
    assert row_metadata["nested"]["count"] == 2
    scan = scan_public_artifact_text(combined)
    assert scan.passed, scan.findings


def test_live_full_skeleton_sanitizes_target_name_model_and_command(monkeypatch, tmp_path: Path) -> None:
    raw_name_secret = "token=SYNTHETIC-SK-OPENAI-SECRET"
    raw_model_secret = "SYNTHETIC-SK-OPENAI-SECRET"
    raw_command_secret = "api_key=SYNTHETIC-SK-OPENAI-SECRET"
    target = tmp_path / f"target-{raw_command_secret}.yaml"
    target.write_text(
        f"name: live target {raw_name_secret}\nadapter: openai_compatible\nmodel: model-{raw_model_secret}\nbase_url: https://example.test/v1\napi_key_env: MISSING_LIVE_FULL_KEY\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True))
    out = tmp_path / "secret-command-sanitized"

    result = CliRunner().invoke(
        app,
        ["benchmark", "live-full", "--target", str(target), "--matrix", MATRIX, "--mutation-profile", SELECTED_PROFILE, "--out-dir", str(out), "--no-dry-run", "--yes"],
    )

    assert result.exit_code == 0, result.output
    json_text = (out / "live-full-evidence.json").read_text(encoding="utf-8")
    payload = json.loads(json_text)
    combined = json_text + (out / "live-full-evidence.md").read_text(encoding="utf-8")
    assert raw_name_secret not in combined
    assert raw_model_secret not in combined
    assert raw_command_secret not in combined
    assert REDACTION_MARKER in combined
    assert payload["rows"][0]["target"]["name"] != f"live target {raw_name_secret}"
    assert payload["rows"][0]["target"]["model"] != f"model-{raw_model_secret}"
    assert raw_command_secret not in payload["rows"][0]["command"]
    scan = scan_public_artifact_text(combined)
    assert scan.passed, scan.findings


def test_live_full_skeleton_sanitizes_preflight_target_and_model(monkeypatch, tmp_path: Path) -> None:
    raw_preflight_name = "preflight token=SYNTHETIC-SK-OPENAI-SECRET"
    raw_preflight_model = "model-SYNTHETIC-SK-PREFLIGHTMODEL123456"
    target = _target(tmp_path)

    def preflight_with_secret_labels(target, **kwargs):
        return LivePreflightReport(
            target_name=raw_preflight_name,
            adapter="openai_compatible",
            model=raw_preflight_model,
            endpoint=SafeTargetEndpoint(scheme="https", host="example.test", path_hint="/v1"),
            text_status="passed",
            text_ready=True,
            visual_status="not_supported",
            ok=True,
            probes=[],
            metadata={"timeout_seconds": kwargs["timeout"], "max_retries": kwargs["max_retries"]},
        )

    monkeypatch.setattr("malleus.live_full.run_target_preflight", preflight_with_secret_labels)
    out = tmp_path / "preflight-sanitized"

    result = CliRunner().invoke(
        app,
        ["benchmark", "live-full", "--target", str(target), "--matrix", MATRIX, "--mutation-profile", SELECTED_PROFILE, "--out-dir", str(out), "--no-dry-run", "--yes", "--request-timeout", "9", "--max-retries", "2"],
    )

    assert result.exit_code == 0, result.output
    json_text = (out / "live-full-evidence.json").read_text(encoding="utf-8")
    combined = json_text + (out / "live-full-evidence.md").read_text(encoding="utf-8")
    payload = json.loads(json_text)
    preflight = payload["metadata"]["preflight"]
    assert raw_preflight_name not in combined
    assert raw_preflight_model not in combined
    assert preflight["target_name"] != raw_preflight_name
    assert preflight["model"] != raw_preflight_model
    assert preflight["text_ready"] is True
    assert preflight["visual_status"] == "not_supported"
    assert preflight["endpoint"]["host"] == "example.test"
    assert preflight["metadata"] == {"timeout_seconds": 9.0, "max_retries": 2}
    assert REDACTION_MARKER in combined
    scan = scan_public_artifact_text(combined)
    assert scan.passed, scan.findings


def test_live_full_cli_exits_nonzero_for_classic_dry_run_artifacts(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)

    def fake_dry_run(target_path, input_path, scoring_path, output_dir, **kwargs):
        return real_run_benchmark(target_path, input_path, scoring_path, output_dir, dry_run=True)

    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True))
    monkeypatch.setattr("malleus.live_full.run_benchmark", fake_dry_run)
    out = tmp_path / "dry-masquerade"

    result = CliRunner().invoke(
        app,
        ["benchmark", "live-full", "--target", str(target), "--matrix", MATRIX, "--mutation-profile", SELECTED_PROFILE, "--out-dir", str(out), "--no-dry-run", "--yes"],
    )

    assert result.exit_code == 1
    assert "dry-run/non-live artifacts" in result.output
    payload = json.loads((out / "live-full-evidence.json").read_text(encoding="utf-8"))
    rows = {row["row_id"]: row for row in payload["rows"]}
    assert rows["pack:smoke-v1"]["metadata"]["invalid_live_artifact"] is True
    assert rows["pack:core-v1"]["metadata"]["invalid_live_artifact"] is True


def test_live_full_invalid_numeric_options(tmp_path: Path) -> None:
    target = _target(tmp_path)

    result = CliRunner().invoke(
        app,
        [
            "benchmark",
            "live-full",
            "--target",
            str(target),
            "--matrix",
            MATRIX,
            "--mutation-profile",
            SELECTED_PROFILE,
            "--out-dir",
            str(tmp_path / "out"),
            "--no-dry-run",
            "--concurrency",
            "0",
        ],
    )

    assert result.exit_code != 0
    assert "0" in result.output


def test_live_full_selected_and_deep_row_behavior(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True))
    runner = CliRunner()

    default_out = tmp_path / "default"
    default_result = runner.invoke(
        app,
        ["benchmark", "live-full", "--target", str(target), "--matrix", MATRIX, "--mutation-profile", SELECTED_PROFILE, "--deep-mutation-profile", DEEP_PROFILE, "--out-dir", str(default_out), "--no-dry-run", "--yes"],
    )
    assert default_result.exit_code == 0, default_result.output
    default_rows = {row["row_id"]: row for row in json.loads((default_out / "live-full-evidence.json").read_text(encoding="utf-8"))["rows"]}
    assert default_rows["mutation-profile:selected-v1"]["status"] == "provider_error"
    assert default_rows["mutation-profile:deep-v1"]["status"] == "skipped_by_operator"
    assert default_rows["mutation-profile:deep-v1"]["live_model_calls"] == 0

    deep_out = tmp_path / "deep"
    deep_result = runner.invoke(
        app,
        [
            "benchmark",
            "live-full",
            "--target",
            str(target),
            "--matrix",
            MATRIX,
            "--mutation-profile",
            SELECTED_PROFILE,
            "--deep-mutation-profile",
            DEEP_PROFILE,
            "--include-deep-mutations",
            "--out-dir",
            str(deep_out),
            "--no-dry-run",
            "--yes",
        ],
    )
    assert deep_result.exit_code == 0, deep_result.output
    deep_rows = {row["row_id"]: row for row in json.loads((deep_out / "live-full-evidence.json").read_text(encoding="utf-8"))["rows"]}
    assert deep_rows["mutation-profile:deep-v1"]["status"] == "provider_error"
    assert deep_rows["mutation-profile:deep-v1"]["status"] != "skipped_by_flag"
    assert "malleus benchmark live-full" in deep_rows["pack:smoke-v1"]["command"]
    assert "--include-deep-mutations" in deep_rows["pack:smoke-v1"]["command"]


def test_run_command_remains_live_by_default(monkeypatch, tmp_path: Path) -> None:
    captured = {}

    def fake_run(target_path: Path, input_path: Path, scoring_path: Path, output_dir: Path, **kwargs):
        captured.update(kwargs)

        class Summary:
            score_total = 0
            max_score_total = 0

        class Report:
            run_id = "run-live-default"
            summary = Summary()

        return Report()

    monkeypatch.setattr("malleus.cli.run_benchmark", fake_run)
    result = CliRunner().invoke(app, ["run", "--target", str(_target(tmp_path)), "--input", _dataset(tmp_path), "--scoring", _scoring(tmp_path), "--out-dir", str(tmp_path / "run")])

    assert result.exit_code == 0, result.output
    assert captured["dry_run"] is False


def test_compare_command_remains_dry_by_default(monkeypatch, tmp_path: Path) -> None:
    captured = {}

    def fake_compare(target_path: Path, input_path: Path, scoring_path: Path, output_dir: Path, models: list[str], **kwargs):
        captured.update(kwargs)
        output_dir.mkdir(parents=True, exist_ok=True)
        return output_dir

    monkeypatch.setattr("malleus.cli.compare_models", fake_compare)
    result = CliRunner().invoke(
        app,
        ["compare", "--target", str(_target(tmp_path)), "--input", _dataset(tmp_path), "--scoring", _scoring(tmp_path), "--out-dir", str(tmp_path / "cmp"), "--model", "model-a"],
    )

    assert result.exit_code == 0, result.output
    assert captured["dry_run"] is True


def _target(tmp_path: Path, *, base_url: str = "https://example.test/v1", metadata: dict | None = None) -> Path:
    target = tmp_path / "target.yaml"
    metadata_yaml = ""
    if metadata:
        metadata_yaml = "metadata:\n"
        for key, value in metadata.items():
            if isinstance(value, dict):
                metadata_yaml += f"  {key}:\n"
                for nested_key, nested_value in value.items():
                    metadata_yaml += f"    {nested_key}: {nested_value}\n"
            else:
                metadata_yaml += f"  {key}: {value}\n"
    target.write_text(f"name: t\nadapter: openai_compatible\nmodel: m\nbase_url: {base_url}\napi_key_env: MISSING_LIVE_FULL_KEY\n{metadata_yaml}", encoding="utf-8")
    return target


def _dataset(tmp_path: Path) -> str:
    dataset = tmp_path / "dataset.yaml"
    dataset.write_text("name: d\nversion: 1\ncategory: c\nsubcategory: s\ncases:\n  - id: c1\n    severity: low\n    objective: x\n    prompt: hi\n", encoding="utf-8")
    return str(dataset)


def _scoring(tmp_path: Path) -> str:
    scoring = tmp_path / "scoring.yaml"
    scoring.write_text("version: 1\nmax_score: 100\nseverity_weights:\n  low: 10\n  medium: 20\n  high: 35\n  critical: 50\n", encoding="utf-8")
    return str(scoring)


def _preflight(*, text_ready: bool, timeout: float = 120.0, retries: int = 1) -> LivePreflightReport:
    return LivePreflightReport(
        target_name="t",
        adapter="openai_compatible",
        model="m",
        endpoint=SafeTargetEndpoint(scheme="https", host="example.test", path_hint="/v1"),
        text_status="passed" if text_ready else "preflight_failed",
        text_ready=text_ready,
        visual_status="not_supported",
        ok=text_ready,
        probes=[],
        metadata={"timeout_seconds": timeout, "max_retries": retries},
    )
