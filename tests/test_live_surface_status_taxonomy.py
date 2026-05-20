from __future__ import annotations

import json
from pathlib import Path

import pytest

from malleus.ir import ArtifactRef
from malleus.live_evidence import LiveEvidenceMatrix, LiveEvidenceRow, LiveSurfaceRecord, LiveTargetMetadata
from malleus.live_full import _aggregate_matrix_payload, write_full_benchmark_reports


def _target() -> LiveTargetMetadata:
    return LiveTargetMetadata(name="system-target", adapter="openai_compatible", model="model-a", base_url="https://example.test/v1")


def _row(**overrides) -> LiveEvidenceRow:
    values = {
        "row_id": "row-1",
        "run_id": "run-1",
        "case_id": "case-1",
        "surface_id": "pack:system",
        "timestamp": "2026-04-27T00:00:00Z",
        "command": "malleus benchmark soft --target target.yaml --out-dir out",
        "git_commit": "0" * 40,
        "target": _target(),
        "status": "target_error",
        "evidence_level": "live_system",
        "dry_run": False,
        "provider_calls_enabled": True,
        "live_model_calls": 0,
        "artifacts": [],
        "reason": "Target endpoint failed before model behavior scoring.",
        "metadata": {"target_execution_enabled": True, "target_trace_count": 1},
    }
    values.update(overrides)
    return LiveEvidenceRow(**values)


def _matrix(*rows: LiveEvidenceRow) -> LiveEvidenceMatrix:
    return LiveEvidenceMatrix(
        matrix_id="taxonomy-matrix",
        generated_at="2026-04-27T00:00:00Z",
        surfaces=[LiveSurfaceRecord(surface_id=row.surface_id, name=row.surface_id) for row in rows],
        rows=list(rows),
        metadata={"benchmark_mode": "soft", "provider_calls_enabled": True, "git_commit": "0" * 40},
    )


def test_final_canonical_rows_reject_legacy_status_and_evidence_level(tmp_path: Path) -> None:
    legacy_status = _row(status="not_supported", evidence_level="scaffold_static", provider_calls_enabled=False, metadata={}, reason="legacy fixture value")
    with pytest.raises(ValueError, match="legacy status not_supported"):
        _aggregate_matrix_payload(_matrix(legacy_status), tmp_path)

    legacy_evidence = _row(status="skipped_by_operator", evidence_level="not_implemented", provider_calls_enabled=False, metadata={}, reason="legacy fixture value")
    with pytest.raises(ValueError, match="legacy evidence_level not_implemented"):
        _aggregate_matrix_payload(_matrix(legacy_evidence), tmp_path)


def test_target_and_capability_rows_are_reported_but_not_model_failures(tmp_path: Path) -> None:
    rows = [
        _row(row_id="provider-gap", surface_id="pack:provider-gap", status="provider_capability_gap", evidence_level="scaffold_static", provider_calls_enabled=False, metadata={"provider_free_classification": True}, reason="No provider-backed runner exists for this surface."),
        _row(row_id="target-gap", surface_id="pack:target-gap", status="target_capability_gap", evidence_level="scaffold_static", metadata={"preflight_visual_status": "not_supported"}, reason="Target preflight reported image input unavailable."),
        _row(row_id="target-config", surface_id="pack:target-config", status="target_config_error", evidence_level="live_system", metadata={"target_execution_enabled": True, "target_trace_count": 1}, reason="Target config omitted a required endpoint."),
        _row(row_id="target-error", surface_id="pack:target-error", status="target_error", evidence_level="live_system_trace", metadata={"target_execution_enabled": True, "target_trace_count": 1}, artifacts=[ArtifactRef(path="trace.json", kind="trace", artifact_type="system_trace", relative_path="trace.json")], reason="Target execution failed before behavior scoring."),
        _row(row_id="checkpoint", surface_id="pack:checkpoint", status="checkpoint_not_run", evidence_level="scaffold_static", provider_calls_enabled=False, metadata={"checkpoint_status": "not_run"}, reason="Surface was not reached before checkpoint."),
    ]

    out = tmp_path / "reports"
    write_full_benchmark_reports(_matrix(*rows), out)

    payload = json.loads((out / "FULL_BENCHMARK_MATRIX.json").read_text(encoding="utf-8"))
    by_id = {row["row_id"]: row for row in payload["rows"]}
    assert by_id["target-gap"]["target_capability_gap"] is True
    assert by_id["target-config"]["target_config_error"] is True
    assert by_id["target-error"]["target_error"] is True
    assert by_id["checkpoint"]["checkpoint_not_run"] is True
    assert all("not_supported" not in row and "not_implemented" not in row for row in payload["rows"])
    assert "pack:target-error" not in (out / "MODEL_FAILURES.md").read_text(encoding="utf-8")
    assert json.loads((out / "MODEL_FAILURE_TRIAGE.json").read_text(encoding="utf-8"))["rows"] == []
