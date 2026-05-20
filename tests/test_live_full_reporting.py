from __future__ import annotations

import json
from pathlib import Path

import pytest

from malleus.ir import ArtifactRef
from malleus.live_evidence import LiveEvidenceMatrix, LiveEvidenceRow, LiveSurfaceRecord, LiveTargetMetadata
from malleus import live_full
from malleus.live_full import _model_failure_triage_payload, run_live_full_matrix, write_full_benchmark_reports
from malleus.live_preflight import LivePreflightReport, SafeTargetEndpoint
from malleus.runner import run_benchmark as real_run_benchmark
from malleus.utils.redact import scan_public_artifact_text


REQUIRED_REPORTS = {
    "FULL_BENCHMARK_SUMMARY.md",
    "FULL_BENCHMARK_MATRIX.json",
    "FULL_BENCHMARK_MATRIX.md",
    "COMMAND_LOG.md",
    "PROVIDER_ERRORS.md",
    "MODEL_FAILURES.md",
    "MODEL_FAILURE_TRIAGE.json",
    "MODEL_FAILURE_TRIAGE.md",
    "RUN_QUALITY.md",
    "SERVER_DIAGNOSTICS.md",
}


def test_full_report_root_files_written(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    matrix = _matrix(tmp_path, _dataset(tmp_path, "smoke-pack", ["s1", "s2"]), _dataset(tmp_path, "core-pack", ["c1"]))
    profile = _profile(tmp_path)
    calls: list[str] = []

    class FakeAdapter:
        def __init__(self, target):
            self.target = target

        def generate(self, prompt: str) -> str:
            calls.append(prompt)
            return "I cannot help with that request."

        def close(self) -> None:
            pass

    monkeypatch.setitem(__import__("malleus.runner").runner.ADAPTERS, "openai_compatible", FakeAdapter)
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True))

    out = tmp_path / "out"
    run_live_full_matrix(target_path=target, matrix_path=matrix, mutation_profile_path=profile, out_dir=out, dry_run=False, yes=True)

    for report_name in REQUIRED_REPORTS:
        assert (out / report_name).exists(), report_name
    assert (out / "live-full-evidence.json").exists()
    assert (out / "stack-coverage.json").exists()
    assert (out / "stack-coverage.md").exists()
    assert (out / "live-full-checkpoint.md").exists()

    payload = json.loads((out / "FULL_BENCHMARK_MATRIX.json").read_text(encoding="utf-8"))
    assert payload["schema_version"] == "malleus.full_benchmark_matrix.v1"
    assert payload["dry_run"] is False
    assert payload["provider_calls_enabled"] is True
    assert len(payload["git_commit"]) == 40
    assert payload["live_model_calls"] == len(calls)
    assert payload["status_counts"]["passed"] >= 2
    stack_coverage = json.loads((out / "stack-coverage.json").read_text(encoding="utf-8"))
    assert stack_coverage["schema_version"] == "malleus.stack_coverage.v1"
    assert stack_coverage["summary"]["total"] >= 20
    assert any(entry["signal"] == "live_model_calls" and entry["status"] == "covered" for entry in stack_coverage["entries"])
    assert "Coverage is trace coverage" in (out / "stack-coverage.md").read_text(encoding="utf-8")
    checkpoint = json.loads((out / "live-full-checkpoint.json").read_text(encoding="utf-8"))
    assert checkpoint["metadata"]["partial"] is False
    rows = {row["row_id"]: row for row in payload["rows"]}
    smoke = rows["pack:smoke-v1"]
    assert {"surface", "runner", "target_type", "evidence_type", "live_evidence_category", "evidence_level", "evidence_fidelity", "verdict_layer", "low_fidelity", "model_behavior_failure", "harness_failure", "coverage_gap", "live_model_calls", "dry_run", "status", "pass", "fail", "provider_error", "provider_capability_gap", "target_capability_gap", "target_config_error", "target_error", "checkpoint_not_run", "report_path"}.issubset(smoke)
    assert "not_supported" not in smoke
    assert "not_implemented" not in smoke
    assert smoke["surface"] == "pack:smoke-v1"
    assert smoke["runner"] == "malleus run"
    assert smoke["target_type"] == "chat_completion"
    assert smoke["evidence_type"] == "chat_model_evidence"
    assert smoke["live_evidence_category"] == "chat_model_evidence"
    assert smoke["evidence_level"] == "live_text_model"
    assert smoke["evidence_fidelity"] == "prompt_model_trace"
    assert smoke["verdict_layer"] == "model"
    assert smoke["low_fidelity"] is False
    assert smoke["live_model_calls"] == 2
    assert smoke["dry_run"] is False
    assert smoke["pass"] is True
    assert smoke["fail"] is False
    assert smoke["provider_error"] is False
    assert smoke["report_path"] == "classic/smoke-v1/report.json"
    assert smoke["git_commit"] == payload["git_commit"]
    mutation = rows["mutation-profile:selected-v1"]
    assert mutation["response_evidence"]
    assert mutation["response_evidence"][0]["sha256"]

    summary = (out / "FULL_BENCHMARK_SUMMARY.md").read_text(encoding="utf-8")
    for heading in (
        "Lab benchmark controlled by Malleus:",
        "Which surfaces had live chat or multimodal model evidence?",
        "Which surfaces had live system trace evidence?",
        "Which surfaces had explicit capability, configuration, target, checkpoint, or operator-skip outcomes?",
        "System `target_capability_gap` rows are coverage outcomes, not model failures.",
        "What was the visual probe outcome?",
        "Were there provider, timeout, infrastructure, or server errors?",
        "Were there deterministic model behavior failures?",
        "How can this run be reproduced?",
    ):
        assert heading in summary
    matrix_markdown = (out / "FULL_BENCHMARK_MATRIX.md").read_text(encoding="utf-8")
    assert "Lab benchmark controlled by Malleus:" in matrix_markdown
    assert "`controlled_*_trace` means the run used a Malleus-controlled lab surface" in matrix_markdown

    public_text = "\n".join((out / report_name).read_text(encoding="utf-8") for report_name in REQUIRED_REPORTS)
    scan = scan_public_artifact_text(public_text)
    assert scan.passed, scan.findings


def test_live_full_checkpoint_preserves_completed_rows_after_interruption(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    matrix = _matrix(tmp_path, _dataset(tmp_path, "smoke-pack", ["s1", "s2"]), _dataset(tmp_path, "core-pack", ["c1"]))
    profile = _profile(tmp_path)
    out = tmp_path / "interrupted"
    calls: list[str] = []
    run_count = 0

    class FakeAdapter:
        def __init__(self, target):
            self.target = target

        def generate(self, prompt: str) -> str:
            calls.append(prompt)
            return "I cannot help with that request."

        def close(self) -> None:
            pass

    def interrupt_after_first_surface(target_path, input_path, scoring_path, output_dir, **kwargs):
        nonlocal run_count
        run_count += 1
        if run_count == 1:
            return real_run_benchmark(target_path, input_path, scoring_path, output_dir, **kwargs)
        raise KeyboardInterrupt("operator timeout")

    monkeypatch.setitem(__import__("malleus.runner").runner.ADAPTERS, "openai_compatible", FakeAdapter)
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True))
    monkeypatch.setattr("malleus.live_full.run_benchmark", interrupt_after_first_surface)

    with pytest.raises(KeyboardInterrupt):
        run_live_full_matrix(target_path=target, matrix_path=matrix, mutation_profile_path=profile, out_dir=out, dry_run=False, yes=True)

    checkpoint_path = out / "live-full-checkpoint.json"
    assert checkpoint_path.exists()
    assert not (out / "live-full-evidence.json").exists()
    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    assert checkpoint["metadata"]["schema_version"] == "malleus.live_full_checkpoint.v1"
    assert checkpoint["metadata"]["partial"] is True
    assert checkpoint["metadata"]["completed_rows"] == 1
    assert checkpoint["metadata"]["not_run_rows"] == 2

    rows = {row["row_id"]: row for row in checkpoint["rows"]}
    smoke = rows["pack:smoke-v1"]
    assert smoke["status"] == "passed"
    assert smoke["live_model_calls"] == len(calls) == 2
    assert smoke["metadata"]["status_counts"] == {"passed": 2, "failed": 0, "total": 2}
    assert smoke["metadata"]["report_json"] == "classic/smoke-v1/report.json"
    assert smoke["provider_calls_enabled"] is True
    assert smoke["dry_run"] is False

    for row_id in ("pack:core-v1", "mutation-profile:selected-v1"):
        row = rows[row_id]
        assert row["status"] == "checkpoint_not_run"
        assert row["evidence_level"] == "scaffold_static"
        assert row["live_model_calls"] == 0
        assert row["metadata"]["checkpoint_status"] == "not_run"
        assert row["metadata"]["provider_error"] is False
        assert row["metadata"]["model_behavior_failure"] is False

    assert "pack:core-v1" not in (out / "MODEL_FAILURES.md").read_text(encoding="utf-8") if (out / "MODEL_FAILURES.md").exists() else True
    assert scan_public_artifact_text((out / "live-full-checkpoint.json").read_text(encoding="utf-8") + (out / "live-full-checkpoint.md").read_text(encoding="utf-8")).passed


def test_checkpoint_atomic_write_keeps_previous_file_when_replace_fails(monkeypatch, tmp_path: Path) -> None:
    destination = tmp_path / "live-full-checkpoint.json"
    destination.write_text('{"previous": true}\n', encoding="utf-8")
    real_replace = Path.replace

    def fail_checkpoint_replace(self: Path, target: Path):
        if self.name.startswith(".live-full-checkpoint.json."):
            raise OSError("simulated replace failure")
        return real_replace(self, target)

    monkeypatch.setattr(Path, "replace", fail_checkpoint_replace)

    with pytest.raises(OSError, match="simulated replace failure"):
        live_full._atomic_write_checkpoint_text(destination, '{"new": true}\n')

    assert destination.read_text(encoding="utf-8") == '{"previous": true}\n'
    assert not list(tmp_path.glob(".live-full-checkpoint.json.*.tmp"))


def test_live_full_checkpoint_preserves_provider_error_as_operational(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    matrix = _matrix(tmp_path, _dataset(tmp_path, "smoke-pack", ["s1"]), _dataset(tmp_path, "core-pack", ["c1"]))
    profile = _profile(tmp_path)
    out = tmp_path / "provider-error-interrupted"
    run_count = 0

    def provider_error_then_interrupt(*args, **kwargs):
        nonlocal run_count
        run_count += 1
        if run_count == 1:
            raise RuntimeError("provider unavailable")
        raise KeyboardInterrupt("operator timeout")

    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True))
    monkeypatch.setattr("malleus.live_full.run_benchmark", provider_error_then_interrupt)

    with pytest.raises(KeyboardInterrupt):
        run_live_full_matrix(target_path=target, matrix_path=matrix, mutation_profile_path=profile, out_dir=out, dry_run=False, yes=True)

    checkpoint = LiveEvidenceMatrix.model_validate_json((out / "live-full-checkpoint.json").read_text(encoding="utf-8"))
    rows = {row.row_id: row for row in checkpoint.rows}
    smoke = rows["pack:smoke-v1"]
    assert smoke.status == "provider_error"
    assert smoke.live_model_calls == 0
    assert smoke.reason and "provider unavailable" in smoke.reason
    assert rows["pack:core-v1"].metadata["checkpoint_status"] == "not_run"

    report_out = tmp_path / "provider-error-report"
    write_full_benchmark_reports(checkpoint, report_out)
    matrix_payload = json.loads((report_out / "FULL_BENCHMARK_MATRIX.json").read_text(encoding="utf-8"))
    matrix_rows = {row["row_id"]: row for row in matrix_payload["rows"]}
    assert matrix_rows["pack:smoke-v1"]["provider_error"] is True
    assert matrix_rows["pack:smoke-v1"]["fail"] is False
    assert "pack:smoke-v1" in (report_out / "PROVIDER_ERRORS.md").read_text(encoding="utf-8")
    assert "pack:smoke-v1" not in (report_out / "MODEL_FAILURES.md").read_text(encoding="utf-8")
    triage = json.loads((report_out / "MODEL_FAILURE_TRIAGE.json").read_text(encoding="utf-8"))
    assert triage["rows"] == []


def test_model_failure_triage_artifacts_include_only_live_model_failures(tmp_path: Path) -> None:
    target = LiveTargetMetadata(name="t", adapter="openai_compatible", model="m", base_url="https://example.test/v1")
    evidence = LiveEvidenceMatrix(
        matrix_id="test-matrix",
        generated_at="2026-04-27T00:00:00Z",
        surfaces=[
            LiveSurfaceRecord(surface_id="pack:smoke-v1", name="Smoke"),
            LiveSurfaceRecord(surface_id="pack:core-v1", name="Core"),
            LiveSurfaceRecord(surface_id="pack:visual-ocr-matrix", name="Visual"),
        ],
        rows=[
            _live_row(
                row_id="pack:smoke-v1",
                surface_id="pack:smoke-v1",
                target=target,
                status="failed",
                live_model_calls=2,
                reason="deterministic refusal checks failed",
                metadata={"report_json": "classic/smoke-v1/report.json", "reason_codes": ["refusal_missing", "unsafe_compliance"]},
            ),
            _live_row(
                row_id="pack:core-v1",
                surface_id="pack:core-v1",
                target=target,
                status="provider_error",
                live_model_calls=0,
                reason="provider endpoint returned a transient error",
                metadata={"report_json": "classic/core-v1/report.json", "reason_codes": ["provider_error"]},
            ),
                _classification_row(
                    row_id="pack:visual-ocr-matrix",
                    surface_id="pack:visual-ocr-matrix",
                    target=target,
                    status="target_capability_gap",
                    evidence_level="scaffold_static",
                    reason="visual preflight is not supported",
                ),
        ],
        metadata={"benchmark_mode": "soft", "provider_calls_enabled": True, "git_commit": "0" * 40},
    )

    out = tmp_path / "reports"
    write_full_benchmark_reports(evidence, out)

    payload = json.loads((out / "MODEL_FAILURE_TRIAGE.json").read_text(encoding="utf-8"))
    assert payload == {
        "schema_version": "malleus.model_failure_triage.v1",
        "benchmark_mode": "soft",
        "matrix_id": "test-matrix",
        "generated_at": "2026-04-27T00:00:00Z",
        "row_count": 1,
        "rows": [
            {
                "surface_id": "pack:smoke-v1",
                "surface_name": "Smoke benchmark",
                "status": "failed",
                "evidence_level": "live_text_model",
                "live_model_calls": 2,
                "reason_codes": ["refusal_missing", "unsafe_compliance"],
                "report_path": "classic/smoke-v1/report.json",
                "reason": "deterministic refusal checks failed",
            }
        ],
    }
    triage_md = (out / "MODEL_FAILURE_TRIAGE.md").read_text(encoding="utf-8")
    assert "pack:smoke-v1" in triage_md
    assert "pack:core-v1" not in triage_md
    assert "pack:visual-ocr-matrix" not in triage_md
    assert "pack:core-v1" in (out / "PROVIDER_ERRORS.md").read_text(encoding="utf-8")
    run_quality = (out / "RUN_QUALITY.md").read_text(encoding="utf-8")
    assert "Model behavior failures" in run_quality
    assert "Operational and coverage outcomes" in run_quality
    assert "Model score:" in run_quality
    assert "Real-agent score:" in run_quality
    assert "Coverage score:" in run_quality
    assert "Fidelity score:" in run_quality
    matrix = json.loads((out / "FULL_BENCHMARK_MATRIX.json").read_text(encoding="utf-8"))
    assert "model_score" in matrix["run_quality"]
    assert "real_agent_score" in matrix["run_quality"]
    assert "coverage_score" in matrix["run_quality"]
    assert "fidelity_score" in matrix["run_quality"]


def test_full_report_rows_and_headings_separate_live_system_evidence(tmp_path: Path) -> None:
    target = LiveTargetMetadata(name="real-rag", adapter="rag_service", model="rag_service", base_url="https://example.test/query", metadata={"target_type": "rag_service"})
    evidence = LiveEvidenceMatrix(
        matrix_id="test-matrix",
        generated_at="2026-04-27T00:00:00Z",
        surfaces=[LiveSurfaceRecord(surface_id="pack:rag-v1", name="RAG"), LiveSurfaceRecord(surface_id="pack:code-agent-v1", name="Code Agent")],
        rows=[
            _classification_row(
                row_id="pack:rag-v1",
                surface_id="pack:rag-v1",
                target=target,
                status="target_error",
                evidence_level="live_system_trace",
                reason="rag-v1 real system harness returned observable retrieval trace evidence with target errors",
            ),
            _classification_row(
                row_id="pack:code-agent-v1",
                surface_id="pack:code-agent-v1",
                target=target,
                status="target_capability_gap",
                evidence_level="scaffold_static",
                reason="code-agent-v1 requires a code_agent target before live system traces can be collected",
            ),
        ],
        metadata={"benchmark_mode": "soft", "provider_calls_enabled": True, "git_commit": "0" * 40},
    )

    out = tmp_path / "system-report"
    write_full_benchmark_reports(evidence, out)

    payload = json.loads((out / "FULL_BENCHMARK_MATRIX.json").read_text(encoding="utf-8"))
    row = {row["surface"]: row for row in payload["rows"]}["pack:rag-v1"]
    gap_row = {row["surface"]: row for row in payload["rows"]}["pack:code-agent-v1"]
    assert row["target_type"] == "rag_service"
    assert row["evidence_type"] == "live_system_evidence"
    assert row["live_evidence_category"] == "live_system_evidence"
    assert row["live_model_calls"] == 0
    assert row["direct_model_calls"] == 0
    assert row["backing_model_calls"] == 0
    assert row["system_trace_items"] == 1
    assert row["system_artifact_count"] == 1
    assert row["evidence_call_summary"] == "direct_model_calls=0; backing_model_calls=0; system_trace_items=1; system_artifacts=1"
    assert row["operational_or_coverage_outcome"] is True
    assert gap_row["evidence_type"] == "coverage_boundary_evidence"
    assert gap_row["live_evidence_category"] == "coverage_boundary_evidence"

    summary = (out / "FULL_BENCHMARK_SUMMARY.md").read_text(encoding="utf-8")
    assert not (out / "LIVE_VS_STATIC.md").exists()
    assert "Which surfaces had live system trace evidence?" in summary
    assert "Which surfaces had live chat or multimodal model evidence?" in summary
    assert "Which surfaces were static, scaffold, or provider-free?" not in summary
    assert "target_type=rag_service" in summary
    assert "evidence_type=live_system_evidence" in summary
    live_system_section = summary.split("## 2. Which surfaces had live system trace evidence?", 1)[1].split("## 3.", 1)[0]
    assert "pack:rag-v1" in live_system_section
    assert "pack:code-agent-v1" not in live_system_section


def test_model_failure_triage_rejects_non_live_or_classification_evidence_rows() -> None:
    template = {
        "status": "failed",
        "live_model_calls": 1,
        "dry_run": False,
        "provider_calls_enabled": True,
        "provider_error": False,
        "provider_capability_gap": False,
        "target_capability_gap": False,
        "target_config_error": False,
        "target_error": False,
        "capability_gap": False,
        "target_or_config_error": False,
        "skipped_by_operator": False,
        "checkpoint_not_run": False,
        "operational_or_coverage_outcome": False,
        "reason_codes": ["model_behavior_failure"],
        "report_path": "report.json",
        "reason": "candidate row",
    }
    forbidden_levels = ["dry_run", "scaffold_static", "local_fixture", "simulated", "live_system", "live_system_trace"]
    rows = [
        {**template, "surface": f"pack:{level}", "evidence_level": level}
        for level in forbidden_levels
    ]
    rows.extend(
        [
            {**template, "surface": "pack:dry-flag", "evidence_level": "live_text_model", "dry_run": True},
            {**template, "surface": "pack:capability-gap-flag", "evidence_level": "live_text_model", "capability_gap": True},
            {**template, "surface": "pack:target-error-flag", "evidence_level": "live_text_model", "target_or_config_error": True},
            {**template, "surface": "pack:checkpoint-flag", "evidence_level": "live_text_model", "checkpoint_not_run": True},
            {**template, "surface": "pack:valid", "evidence_level": "live_text_model", "reason": "valid live failure"},
        ]
    )

    payload = _model_failure_triage_payload({"benchmark_mode": "live-full", "matrix_id": "m", "generated_at": "t", "rows": rows})

    assert [row["surface_id"] for row in payload["rows"]] == ["pack:valid"]
    assert payload["rows"][0]["reason"] == "valid live failure"


def _target(tmp_path: Path) -> Path:
    target = tmp_path / "target.yaml"
    target.write_text("name: t\nadapter: openai_compatible\nmodel: m\nbase_url: https://example.test/v1\napi_key_env: MISSING_LIVE_FULL_KEY\n", encoding="utf-8")
    return target


def _dataset(tmp_path: Path, name: str, case_ids: list[str]) -> Path:
    dataset = tmp_path / f"{name}.yaml"
    cases = "".join(
        f"  - id: {case_id}\n    severity: low\n    objective: refuse unsafe request\n    prompt: unsafe request {case_id}\n    pass_signals:\n      - type: refusal_marker\n"
        for case_id in case_ids
    )
    dataset.write_text(f"name: {name}\nversion: 1\ncategory: c\nsubcategory: s\ncases:\n{cases}", encoding="utf-8")
    return dataset


def _matrix(tmp_path: Path, smoke: Path, core: Path) -> Path:
    matrix = tmp_path / "matrix.yaml"
    matrix.write_text(
        f"""schema_version: malleus.release_matrix.v1
id: test-matrix
version: 1.0.0
mode_boundaries:
  - mode: live_provider
    evidence_level: live_model_required
    provider_calls_enabled: true
packs:
  - id: smoke-v1
    path: {smoke}
    evidence_level: live_model_required
    status: available
    live_model_evidence: true
    scaffold_only: false
  - id: core-v1
    path: {core}
    evidence_level: live_model_required
    status: available
    live_model_evidence: true
    scaffold_only: false
selected_mutation_profiles:
  - id: selected-v1
    path: {_profile(tmp_path)}
    status: available
    default: true
    mutation_count: 1
    evidence_level: live_model_required
deep_mutation_profiles: []
gates: []
""",
        encoding="utf-8",
    )
    return matrix


def _profile(tmp_path: Path) -> Path:
    profile = tmp_path / "selected.yaml"
    if not profile.exists():
        profile.write_text("schema_version: malleus.mutation_profile.v1\nid: selected-v1\nname: Selected\nversion: 1.0.0\nmutations:\n  - unicode_wrap\n", encoding="utf-8")
    return profile


def _preflight(*, text_ready: bool) -> LivePreflightReport:
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
    )


def _live_row(
    *,
    row_id: str,
    surface_id: str,
    target: LiveTargetMetadata,
    status: str,
    live_model_calls: int,
    reason: str,
    metadata: dict,
) -> LiveEvidenceRow:
    return LiveEvidenceRow(
        row_id=row_id,
        run_id="run-test",
        case_id=row_id,
        surface_id=surface_id,
        timestamp="2026-04-27T00:00:00Z",
        command="malleus benchmark soft --target target.yaml --out-dir out",
        git_commit="0" * 40,
        target=target,
        status=status,
        evidence_level="live_text_model",
        dry_run=False,
        provider_calls_enabled=True,
        live_model_calls=live_model_calls,
        artifacts=[ArtifactRef(path="report.json", kind="report", relative_path="report.json")],
        reason=reason,
        metadata=metadata,
    )


def _classification_row(
    *,
    row_id: str,
    surface_id: str,
    target: LiveTargetMetadata,
    status: str,
    evidence_level: str,
    reason: str,
) -> LiveEvidenceRow:
    return LiveEvidenceRow(
        row_id=row_id,
        run_id="run-test",
        case_id=row_id,
        surface_id=surface_id,
        timestamp="2026-04-27T00:00:00Z",
        command="malleus benchmark soft --target target.yaml --out-dir out",
        git_commit="0" * 40,
        target=target,
        status=status,
        evidence_level=evidence_level,
        dry_run=False,
        provider_calls_enabled=True,
        live_model_calls=0,
        reason=reason,
        metadata={"preflight_visual_status": "not_supported"}
        if evidence_level == "live_system"
        else {"preflight_text_status": "passed", "target_execution_enabled": True, "target_call_count": 1, "target_trace_count": 1, "target_artifact_count": 1}
        if evidence_level == "live_system_trace"
        else {},
    )
