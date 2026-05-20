from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from malleus.cli import app
from malleus.ir import ArtifactRef
from malleus.live_evidence import LiveEvidenceRow
from malleus.live_full import run_exterminatus_benchmark, run_soft_benchmark
from malleus.live_preflight import LivePreflightReport, SafeTargetEndpoint
from malleus.target_store import add_managed_target


def _provider_error(*args, **kwargs):
    raise RuntimeError("soft mode test provider unavailable")


@pytest.fixture(autouse=True)
def block_real_live_runners(monkeypatch):
    monkeypatch.setattr("malleus.live_full.run_benchmark", _provider_error)
    monkeypatch.setattr("malleus.live_full.run_mutation_benchmark", _provider_error)
    monkeypatch.setattr("malleus.live_full.run_rag_live", _provider_error)
    monkeypatch.setattr("malleus.live_full.run_agent_lab", _provider_error)
    monkeypatch.setattr("malleus.live_full.run_hidden_artifact_live", _provider_error)
    monkeypatch.setattr("malleus.live_full.run_ui_action_live", _provider_error)
    monkeypatch.setattr("malleus.live_full.run_campaign_live", _provider_error)
    monkeypatch.setattr("malleus.live_full.run_visual_live", _provider_error)


def test_benchmark_soft_help_documents_serious_live_mode() -> None:
    result = CliRunner().invoke(app, ["benchmark", "soft", "--help"], env={"COLUMNS": "220"})

    assert result.exit_code == 0
    assert "serious/default live soft benchmark" in result.output
    assert "--yes" not in result.output
    assert "--mutation-profile" not in result.output


def test_benchmark_help_lists_exterminatus_soberly() -> None:
    result = CliRunner().invoke(app, ["benchmark", "--help"], env={"COLUMNS": "220"})

    assert result.exit_code == 0
    assert "exterminatus" in result.output
    assert "Run exhaustive/full live benchmark mode" in result.output


def test_benchmark_exterminatus_help_documents_exhaustive_confirmation() -> None:
    result = CliRunner().invoke(app, ["benchmark", "exterminatus", "--help"], env={"COLUMNS": "240"})

    assert result.exit_code == 0
    assert "exhaustive/full live benchmark mode" in result.output
    assert "--yes" not in result.output
    assert "--deep-mutation-profile" not in result.output


def test_benchmark_soft_requires_target_and_out_dir_only(tmp_path: Path) -> None:
    runner = CliRunner()

    missing_options = runner.invoke(app, ["benchmark", "soft"])
    assert missing_options.exit_code != 0
    assert "Missing option" in missing_options.output


def test_benchmark_soft_writes_mode_marker_and_uses_selected_profile(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True, visual_ready=False))
    out = tmp_path / "soft-out"

    result = CliRunner().invoke(app, ["benchmark", "soft", "--target", str(target), "--out-dir", str(out), "--yes", "--request-timeout", "3", "--max-retries", "0"])

    assert result.exit_code == 0, result.output
    assert "Mode: soft" in result.output
    assert "Deep mutations included: false" in result.output
    assert (out / "live-full-evidence.json").exists()
    assert (out / "FULL_BENCHMARK_MATRIX.json").exists()
    assert not (out / "LIVE_VS_STATIC.md").exists()
    assert (out / "SOFT_BENCHMARK_MODE.json").exists()
    assert (out / "SOFT_BENCHMARK_MODE.md").exists()

    skeleton = json.loads((out / "live-full-evidence.json").read_text(encoding="utf-8"))
    assert skeleton["metadata"]["benchmark_mode"] == "soft"
    assert skeleton["metadata"]["dry_run"] is False
    assert skeleton["metadata"]["provider_calls_enabled"] is True
    assert skeleton["metadata"]["operator_confirmed"] is True
    assert skeleton["metadata"]["include_deep_mutations"] is False
    assert "malleus benchmark soft" in skeleton["rows"][0]["command"]
    assert "--no-dry-run" not in skeleton["rows"][0]["command"]
    assert "--include-deep-mutations" not in skeleton["rows"][0]["command"]
    assert "--deep-mutation-profile" not in skeleton["rows"][0]["command"]

    rows = {row["row_id"]: row for row in skeleton["rows"]}
    assert rows["mutation-profile:selected-v1"]["status"] == "provider_error"
    assert rows["mutation-profile:deep-v1"]["status"] == "skipped_by_operator"
    assert rows["mutation-profile:deep-v1"]["live_model_calls"] == 0
    assert rows["pack:visual-ocr-matrix"]["status"] == "provider_capability_gap"
    assert rows["pack:visual-ocr-matrix"]["live_model_calls"] == 0
    assert rows["pack:challenge-v1"]["status"] == "provider_error"
    assert rows["pack:challenge-v1"]["evidence_level"] == "live_text_model"
    assert rows["pack:calibration-v1"]["status"] == "provider_error"
    assert rows["pack:calibration-v1"]["evidence_level"] == "live_text_model"

    matrix = json.loads((out / "FULL_BENCHMARK_MATRIX.json").read_text(encoding="utf-8"))
    assert matrix["benchmark_mode"] == "soft"
    assert matrix["include_deep_mutations"] is False
    assert matrix["provider_calls_enabled"] is True

    marker = json.loads((out / "SOFT_BENCHMARK_MODE.json").read_text(encoding="utf-8"))
    assert marker["benchmark_mode"] == "soft"
    assert marker["mode"] == "soft"
    assert marker["dry_run"] is False
    assert marker["provider_calls_enabled"] is True
    assert marker["operator_confirmed"] is True
    assert marker["include_deep_mutations"] is False
    assert marker["visual_requires_preflight_support"] is True
    assert marker["browser_automation"] is False
    assert "cannot satisfy live model behavior evidence" in marker["live_vs_static_contract"]


def test_soft_system_target_marks_mutations_as_target_capability_gap(monkeypatch, tmp_path: Path) -> None:
    target = tmp_path / "rag-target.yaml"
    target.write_text(
        """name: rag-target
target_type: rag_service
rag_service:
  endpoint_url: http://127.0.0.1:9/rag
  auth: {}
""",
        encoding="utf-8",
    )
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True, visual_ready=False))
    out = tmp_path / "soft-rag-out"

    result = CliRunner().invoke(app, ["benchmark", "soft", "--target", str(target), "--out-dir", str(out), "--yes", "--request-timeout", "3", "--max-retries", "0"])

    assert result.exit_code == 0, result.output
    rows = {row["row_id"]: row for row in json.loads((out / "live-full-evidence.json").read_text(encoding="utf-8"))["rows"]}
    mutation_row = rows["mutation-profile:selected-v1"]
    assert mutation_row["status"] == "target_capability_gap"
    assert mutation_row["evidence_level"] == "scaffold_static"
    assert mutation_row["live_model_calls"] == 0
    assert mutation_row["metadata"]["actual_target_type"] == "rag_service"
    assert mutation_row["metadata"]["mutation_model_calls_attempted"] is False
    for row_id in ("pack:artifact-hidden-channel-v1", "pack:campaign-v1"):
        assert rows[row_id]["status"] == "target_capability_gap"
        assert rows[row_id]["evidence_level"] == "scaffold_static"
        assert rows[row_id]["live_model_calls"] == 0
        assert rows[row_id]["metadata"]["actual_target_type"] == "rag_service"
    matrix_rows = {row["row_id"]: row for row in json.loads((out / "FULL_BENCHMARK_MATRIX.json").read_text(encoding="utf-8"))["rows"]}
    assert matrix_rows["mutation-profile:selected-v1"]["evidence_type"] == "coverage_boundary_evidence"
    assert matrix_rows["pack:artifact-hidden-channel-v1"]["evidence_type"] == "coverage_boundary_evidence"
    assert matrix_rows["pack:campaign-v1"]["evidence_type"] == "coverage_boundary_evidence"


def test_benchmark_exterminatus_runs_without_confirmation(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True, visual_ready=False))

    result = CliRunner().invoke(app, ["benchmark", "exterminatus", "--target", str(target), "--out-dir", str(tmp_path / "out")])

    assert result.exit_code == 0, result.output
    assert "Mode: exterminatus" in result.output


def test_benchmark_exterminatus_writes_exhaustive_metadata_and_deep_rows(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True, visual_ready=False))
    out = tmp_path / "exterminatus-out"

    result = CliRunner().invoke(app, ["benchmark", "exterminatus", "--target", str(target), "--out-dir", str(out), "--yes", "--request-timeout", "3", "--max-retries", "0"])

    assert result.exit_code == 0, result.output
    assert "Mode: exterminatus" in result.output
    assert "Exhaustive: true" in result.output
    assert "Deep mutations included: true" in result.output
    assert "Unsupported/deferred surfaces explicit: true" in result.output
    assert (out / "EXTERMINATUS_BENCHMARK_MODE.json").exists()
    assert (out / "EXTERMINATUS_BENCHMARK_MODE.md").exists()

    skeleton = json.loads((out / "live-full-evidence.json").read_text(encoding="utf-8"))
    assert skeleton["metadata"]["benchmark_mode"] == "exterminatus"
    assert skeleton["metadata"]["exhaustive"] is True
    assert skeleton["metadata"]["dry_run"] is False
    assert skeleton["metadata"]["provider_calls_enabled"] is True
    assert skeleton["metadata"]["operator_confirmed"] is True
    assert skeleton["metadata"]["include_deep_mutations"] is True
    assert skeleton["metadata"]["unsupported_surfaces_explicit"] is True
    assert skeleton["metadata"]["deferred_surfaces_explicit"] is True
    assert "cannot satisfy live model behavior evidence" in skeleton["metadata"]["live_vs_static_contract"]
    assert "malleus benchmark exterminatus" in skeleton["rows"][0]["command"]
    assert "--deep-mutation-profile" in skeleton["rows"][0]["command"]
    assert "--include-deep-mutations" not in skeleton["rows"][0]["command"]

    rows = {row["row_id"]: row for row in skeleton["rows"]}
    assert rows["mutation-profile:selected-v1"]["status"] == "provider_error"
    assert rows["mutation-profile:deep-v1"]["status"] == "provider_error"
    assert rows["mutation-profile:deep-v1"]["status"] != "skipped_by_flag"
    assert rows["pack:visual-ocr-matrix"]["status"] == "provider_capability_gap"
    assert rows["pack:visual-ocr-matrix"]["live_model_calls"] == 0
    assert rows["pack:challenge-v1"]["status"] == "provider_error"
    assert rows["pack:challenge-v1"]["evidence_level"] == "live_text_model"
    assert rows["pack:calibration-v1"]["status"] == "provider_error"
    assert rows["pack:calibration-v1"]["evidence_level"] == "live_text_model"

    matrix = json.loads((out / "FULL_BENCHMARK_MATRIX.json").read_text(encoding="utf-8"))
    assert matrix["benchmark_mode"] == "exterminatus"
    assert matrix["exhaustive"] is True
    assert matrix["include_deep_mutations"] is True
    assert matrix["unsupported_surfaces_explicit"] is True
    assert matrix["deferred_surfaces_explicit"] is True

    marker = json.loads((out / "EXTERMINATUS_BENCHMARK_MODE.json").read_text(encoding="utf-8"))
    assert marker["benchmark_mode"] == "exterminatus"
    assert marker["mode"] == "exhaustive_live_full"
    assert marker["exhaustive"] is True
    assert marker["include_deep_mutations"] is True
    assert marker["deep_mutation_profile"] == "deep-v1"
    assert marker["deep_mutation_profile_path"] == "datasets/mutation_profiles/deep-v1.yaml"
    assert marker["unsupported_surfaces_explicit"] is True
    assert marker["deferred_surfaces_explicit"] is True

    command_log = (out / "COMMAND_LOG.md").read_text(encoding="utf-8")
    assert "malleus benchmark exterminatus" in command_log
    assert "--include-deep-mutations" not in command_log


def test_benchmark_soft_resolves_managed_target_name(monkeypatch, tmp_path: Path) -> None:
    target_dir = tmp_path / "targets"
    add_managed_target(
        {
            "name": "Managed Soft",
            "adapter": "openai_compatible",
            "model": "m",
            "base_url": "https://example.test/v1",
            "api_key_env": "MANAGED_SOFT_KEY",
        },
        target_dir,
    )
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True, visual_ready=False))
    out = tmp_path / "managed-soft"

    result = CliRunner().invoke(
        app,
        [
            "benchmark",
            "soft",
            "--target",
            "Managed Soft",
            "--config-dir",
            str(target_dir),
            "--out-dir",
            str(out),
            "--yes",
        ],
    )

    assert result.exit_code == 0, result.output
    skeleton = json.loads((out / "live-full-evidence.json").read_text(encoding="utf-8"))
    assert skeleton["metadata"]["benchmark_mode"] == "soft"
    assert skeleton["rows"][0]["target"]["name"] == "Managed Soft"


def test_benchmark_exterminatus_resolves_managed_target_name(monkeypatch, tmp_path: Path) -> None:
    target_dir = tmp_path / "targets"
    add_managed_target(
        {
            "name": "Managed Exterminatus",
            "adapter": "openai_compatible",
            "model": "m",
            "base_url": "https://example.test/v1",
            "api_key_env": "MANAGED_EXTERMINATUS_KEY",
        },
        target_dir,
    )
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True, visual_ready=False))
    out = tmp_path / "managed-exterminatus"

    result = CliRunner().invoke(
        app,
        [
            "benchmark",
            "exterminatus",
            "--target",
            "Managed Exterminatus",
            "--config-dir",
            str(target_dir),
            "--out-dir",
            str(out),
            "--yes",
        ],
    )

    assert result.exit_code == 0, result.output
    skeleton = json.loads((out / "live-full-evidence.json").read_text(encoding="utf-8"))
    assert skeleton["metadata"]["benchmark_mode"] == "exterminatus"
    assert skeleton["metadata"]["include_deep_mutations"] is True
    assert skeleton["rows"][0]["target"]["name"] == "Managed Exterminatus"


def test_benchmark_exterminatus_marker_uses_custom_deep_profile_metadata(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    dataset = _dataset(tmp_path)
    selected = _mutation_profile(tmp_path, "selected-v1")
    custom_deep = _mutation_profile(tmp_path, "custom-deep-v1", deep=True)
    matrix = _release_matrix(tmp_path, dataset=dataset, selected=selected, deep=custom_deep, deep_id="custom-deep-v1")
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True, visual_ready=False))
    out = tmp_path / "custom-deep-out"

    result = CliRunner().invoke(
        app,
        [
            "benchmark",
            "exterminatus",
            "--target",
            str(target),
            "--matrix",
            str(matrix),
            "--mutation-profile",
            str(selected),
            "--deep-mutation-profile",
            str(custom_deep),
            "--out-dir",
            str(out),
            "--yes",
        ],
    )

    assert result.exit_code == 0, result.output
    skeleton = json.loads((out / "live-full-evidence.json").read_text(encoding="utf-8"))
    marker = json.loads((out / "EXTERMINATUS_BENCHMARK_MODE.json").read_text(encoding="utf-8"))
    custom_deep_path = custom_deep.name

    assert skeleton["metadata"]["deep_mutation_profile"] == "custom-deep-v1"
    assert skeleton["metadata"]["deep_mutation_profile_path"] == custom_deep_path
    assert marker["deep_mutation_profile"] == "custom-deep-v1"
    assert marker["deep_mutation_profile_path"] == custom_deep_path
    assert marker["deep_mutation_profile"] != "deep-v1"


def test_benchmark_soft_provider_errors_are_not_model_failures(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True, visual_ready=False))
    out = tmp_path / "provider-errors"

    result = CliRunner().invoke(app, ["benchmark", "soft", "--target", str(target), "--out-dir", str(out), "--yes"])

    assert result.exit_code == 0, result.output
    matrix = json.loads((out / "FULL_BENCHMARK_MATRIX.json").read_text(encoding="utf-8"))
    rows = {row["row_id"]: row for row in matrix["rows"]}
    smoke = rows["pack:smoke-v1"]
    assert smoke["status"] == "provider_error"
    assert smoke["provider_error"] is True
    assert smoke["fail"] is False
    assert "provider_error" in (out / "PROVIDER_ERRORS.md").read_text(encoding="utf-8")
    assert "pack:smoke-v1" not in (out / "MODEL_FAILURES.md").read_text(encoding="utf-8")


def test_benchmark_soft_checkpoint_metadata_survives_interruption(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    out = tmp_path / "soft-interrupted"
    run_count = 0

    def provider_error_then_interrupt(*args, **kwargs):
        nonlocal run_count
        run_count += 1
        if run_count == 1:
            raise RuntimeError("soft provider unavailable")
        raise KeyboardInterrupt("operator timeout")

    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True, visual_ready=False))
    monkeypatch.setattr("malleus.live_full.run_benchmark", provider_error_then_interrupt)

    with pytest.raises(KeyboardInterrupt):
        run_soft_benchmark(target_path=target, out_dir=out, yes=True)

    checkpoint = json.loads((out / "live-full-checkpoint.json").read_text(encoding="utf-8"))
    assert checkpoint["metadata"]["benchmark_mode"] == "soft"
    assert checkpoint["metadata"]["include_deep_mutations"] is False
    assert checkpoint["metadata"]["partial"] is True
    rows = {row["row_id"]: row for row in checkpoint["rows"]}
    assert rows["pack:smoke-v1"]["status"] == "provider_error"
    assert rows["pack:core-v1"]["metadata"]["checkpoint_status"] == "not_run"
    assert rows["mutation-profile:deep-v1"]["metadata"]["checkpoint_status"] == "not_run"


def test_benchmark_exterminatus_checkpoint_metadata_survives_interruption(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    out = tmp_path / "exterminatus-interrupted"
    run_count = 0

    def provider_error_then_interrupt(*args, **kwargs):
        nonlocal run_count
        run_count += 1
        if run_count == 1:
            raise RuntimeError("exterminatus provider unavailable")
        raise KeyboardInterrupt("operator timeout")

    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True, visual_ready=False))
    monkeypatch.setattr("malleus.live_full.run_benchmark", provider_error_then_interrupt)

    with pytest.raises(KeyboardInterrupt):
        run_exterminatus_benchmark(target_path=target, out_dir=out, yes=True)

    checkpoint = json.loads((out / "live-full-checkpoint.json").read_text(encoding="utf-8"))
    assert checkpoint["metadata"]["benchmark_mode"] == "exterminatus"
    assert checkpoint["metadata"]["exhaustive"] is True
    assert checkpoint["metadata"]["include_deep_mutations"] is True
    assert checkpoint["metadata"]["deep_mutation_profile"] == "deep-v1"
    assert checkpoint["metadata"]["partial"] is True
    rows = {row["row_id"]: row for row in checkpoint["rows"]}
    assert rows["pack:smoke-v1"]["status"] == "provider_error"
    assert rows["pack:core-v1"]["metadata"]["checkpoint_status"] == "not_run"
    assert rows["mutation-profile:deep-v1"]["metadata"]["checkpoint_status"] == "not_run"


def test_benchmark_live_full_behavior_still_defaults_to_live_full_metadata(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True, visual_ready=False))
    out = tmp_path / "live-full"

    result = CliRunner().invoke(
        app,
        [
            "benchmark",
            "live-full",
            "--target",
            str(target),
            "--matrix",
            "datasets/release_matrices/malleus-v0.1.yaml",
            "--mutation-profile",
            "datasets/mutation_profiles/selected-v1.yaml",
            "--out-dir",
            str(out),
            "--no-dry-run",
            "--yes",
        ],
    )

    assert result.exit_code == 0, result.output
    skeleton = json.loads((out / "live-full-evidence.json").read_text(encoding="utf-8"))
    matrix = json.loads((out / "FULL_BENCHMARK_MATRIX.json").read_text(encoding="utf-8"))
    assert skeleton["metadata"]["benchmark_mode"] == "live-full"
    assert matrix["benchmark_mode"] == "live-full"
    assert not (out / "SOFT_BENCHMARK_MODE.json").exists()


def test_benchmark_soft_text_only_chat_target_reports_live_calls_and_honest_gaps(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    out = tmp_path / "text-only-live-soft"

    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True, visual_ready=False))

    def fake_live_row(subject, *args, **kwargs):
        row_id = f"pack:{subject.id}" if hasattr(subject, "path") else f"mutation-profile:{subject.id}"
        return LiveEvidenceRow(
            row_id=row_id,
            run_id=kwargs["run_id"],
            case_id=subject.id,
            surface_id=row_id,
            timestamp=kwargs["timestamp"],
            command=kwargs["command"],
            git_commit="0" * 40,
            target=kwargs["target"],
            status="passed",
            evidence_level="live_text_model",
            dry_run=False,
            provider_calls_enabled=True,
            live_model_calls=2,
            artifacts=[ArtifactRef(path=f"{subject.id}.json", kind="json", relative_path=f"{subject.id}.json", redaction_status="redacted")],
            metadata={"completed_live_model_calls": 2, "deterministic_scoring": True},
        )

    monkeypatch.setattr("malleus.live_full._run_classic_pack_row", fake_live_row)
    monkeypatch.setattr("malleus.live_full._run_hidden_artifact_pack_row", fake_live_row)
    monkeypatch.setattr("malleus.live_full._run_campaign_pack_row", fake_live_row)
    monkeypatch.setattr("malleus.live_full._run_challenge_pack_row", fake_live_row)
    monkeypatch.setattr("malleus.live_full._run_mutation_profile_row", fake_live_row)

    result = CliRunner().invoke(app, ["benchmark", "soft", "--target", str(target), "--out-dir", str(out), "--yes"])

    assert result.exit_code == 0, result.output
    matrix = json.loads((out / "FULL_BENCHMARK_MATRIX.json").read_text(encoding="utf-8"))
    rows = {row["row_id"]: row for row in matrix["rows"]}

    assert not any(row["status"] in {"not_supported", "not_implemented"} for row in rows.values())
    assert rows["pack:rag-v1"]["surface_name"] == "RAG retrieval and citation security"
    assert rows["pack:code-agent-v1"]["surface_name"] == "Code-agent sandbox and workspace security"
    assert rows["pack:ui-browser-v1"]["status"] == "target_capability_gap"
    assert rows["pack:ui-browser-v1"]["live_model_calls"] == 0
    assert rows["pack:ui-browser-v1"]["metadata"]["required_target_types"] == ["browser_agent"]
    forbidden_tokens = {"provider_free_static", "provider_free_dry_run"}
    assert not any(token in json.dumps(row, sort_keys=True) for row in rows.values() for token in forbidden_tokens)

    for row_id in ["pack:artifact-hidden-channel-v1", "pack:campaign-v1", "pack:challenge-v1", "pack:calibration-v1"]:
        assert rows[row_id]["status"] == "passed"
        assert rows[row_id]["live_model_calls"] > 0
        assert rows[row_id]["evidence_level"] == "live_text_model"

    assert rows["pack:visual-ocr-matrix"]["status"] == "provider_capability_gap"
    assert rows["pack:visual-ocr-matrix"]["evidence_type"] == "multimodal_model_evidence"
    assert rows["pack:visual-ocr-matrix"]["live_evidence_category"] == "multimodal_model_evidence"
    assert rows["pack:visual-ocr-matrix"]["evidence_type"] != "chat_model_evidence"
    assert rows["pack:visual-ocr-matrix"]["live_model_calls"] == 0
    for row_id in ["pack:code-agent-v1", "pack:plugin-workflow-v1", "pack:self-modification-v1"]:
        assert rows[row_id]["status"] == "target_capability_gap"
        assert rows[row_id]["live_model_calls"] == 0

    summary = (out / "FULL_BENCHMARK_SUMMARY.md").read_text(encoding="utf-8")
    assert "System `target_capability_gap` rows are coverage outcomes, not model failures." in summary
    assert "RAG retrieval and citation security" in summary
    matrix_text = (out / "FULL_BENCHMARK_MATRIX.json").read_text(encoding="utf-8")
    for artifact_text in (matrix_text, summary):
        assert "provider_free_static" not in artifact_text
        assert "provider_free_dry_run" not in artifact_text
        assert "not_supported" not in artifact_text
        assert "not_implemented" not in artifact_text


def test_readme_documents_live_benchmark_modes() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")

    assert "### Live benchmark wrappers" in readme
    assert "`malleus benchmark soft` is the serious/default live benchmark wrapper" in readme
    assert "`malleus benchmark exterminatus` is the expanded live wrapper for the implemented Malleus benchmark surfaces" in readme
    assert "it is not a universal security proof" in readme
    assert "includes the selected profile and deep mutation profile by default" in readme
    assert "`malleus benchmark live-full` command remains available for explicit matrix/profile orchestration" in readme
    assert "live-full-checkpoint.json" in readme
    assert "partial progress/recovery artifacts" in readme
    assert "Successful runs may also retain these checkpoint files as a final non-partial progress snapshot" in readme
    assert "provider/server errors remain separate operational outcomes" in readme


def _target(tmp_path: Path) -> Path:
    target = tmp_path / "target.yaml"
    target.write_text("name: t\nadapter: openai_compatible\nmodel: m\nbase_url: https://example.test/v1\napi_key_env: MISSING_SOFT_KEY\n", encoding="utf-8")
    return target


def _dataset(tmp_path: Path) -> Path:
    dataset = tmp_path / "dataset.yaml"
    dataset.write_text(
        "name: smoke\nversion: 1\ncategory: c\nsubcategory: s\ncases:\n  - id: c1\n    severity: low\n    objective: refuse unsafe request\n    prompt: unsafe request\n",
        encoding="utf-8",
    )
    return dataset


def _mutation_profile(tmp_path: Path, profile_id: str, *, deep: bool = False) -> Path:
    profile = tmp_path / f"{profile_id}.yaml"
    profile.write_text(
        f"schema_version: malleus.mutation_profile.v1\nid: {profile_id}\nname: {profile_id}\nversion: 1.0.0\ndeep: {str(deep).lower()}\nmutations:\n  - unicode_wrap\n",
        encoding="utf-8",
    )
    return profile


def _release_matrix(tmp_path: Path, *, dataset: Path, selected: Path, deep: Path, deep_id: str) -> Path:
    matrix = tmp_path / "matrix.yaml"
    matrix.write_text(
        f"""schema_version: malleus.release_matrix.v1
id: custom-matrix
version: 1.0.0
mode_boundaries:
  - mode: live_provider
    evidence_level: live_model_required
    provider_calls_enabled: true
packs:
  - id: smoke-v1
    path: {dataset}
    evidence_level: live_model_required
    status: available
    live_model_evidence: true
    scaffold_only: false
selected_mutation_profiles:
  - id: selected-v1
    path: {selected}
    status: available
    default: true
    mutation_count: 1
    evidence_level: live_model_required
deep_mutation_profiles:
  - id: {deep_id}
    path: {deep}
    status: available
    default: false
    mutation_count: 1
    evidence_level: live_model_required
gates: []
""",
        encoding="utf-8",
    )
    return matrix


def _preflight(*, text_ready: bool, visual_ready: bool) -> LivePreflightReport:
    return LivePreflightReport(
        target_name="t",
        adapter="openai_compatible",
        model="m",
        endpoint=SafeTargetEndpoint(scheme="https", host="example.test", path_hint="/v1"),
        text_status="passed" if text_ready else "preflight_failed",
        text_ready=text_ready,
        visual_status="passed" if visual_ready else "not_supported",
        ok=text_ready,
        probes=[],
    )
