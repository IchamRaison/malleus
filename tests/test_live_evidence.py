from __future__ import annotations

import pytest

from malleus.ir import ArtifactRef
from malleus.live_evidence import (
    LiveEvidenceMatrix,
    LiveEvidenceRow,
    LiveSurfaceRecord,
    LiveTargetMetadata,
    summarize_response,
)
from malleus.utils.redact import sha256_text


def _target() -> LiveTargetMetadata:
    return LiveTargetMetadata(name="openai-smoke", adapter="openai_compatible", model="model-a", base_url="https://example.test/v1")


def _artifact(**overrides) -> ArtifactRef:
    values = {
        "path": "report.json",
        "kind": "json",
        "artifact_type": "run_report_json",
        "relative_path": "report.json",
        "sha256": "1" * 64,
        "redaction_status": "redacted",
    }
    values.update(overrides)
    return ArtifactRef(**values)


def _live_row(**overrides) -> LiveEvidenceRow:
    values = {
        "row_id": "row-1",
        "run_id": "run-1",
        "case_id": "case-1",
        "surface_id": "chat",
        "timestamp": "2026-04-26T00:00:00Z",
        "command": "malleus run --target examples/targets/openai.yaml --input datasets/benchmark_packs/smoke-v1.yaml",
        "git_commit": "abc1234",
        "target": _target(),
        "status": "passed",
        "evidence_level": "live_text_model",
        "dry_run": False,
        "provider_calls_enabled": True,
        "live_model_calls": 1,
        "report_mode": "live_provider",
        "artifacts": [_artifact()],
    }
    values.update(overrides)
    return LiveEvidenceRow(**values)


def test_valid_live_row_accepted() -> None:
    row = _live_row(response_summary=summarize_response("safe response"))

    assert row.status == "passed"
    assert row.evidence_level == "live_text_model"
    assert row.live_model_calls == 1
    assert row.response_summary is not None


def test_valid_non_live_classification_accepted_with_reason() -> None:
    row = _live_row(
        status="not_supported",
        evidence_level="not_supported",
        provider_calls_enabled=False,
        live_model_calls=0,
        artifacts=[],
        reason="Target does not expose image input for this surface.",
    )

    assert row.status == "not_supported"
    assert row.reason


def test_live_system_target_outcomes_require_system_evidence_and_reason() -> None:
    row = _live_row(
        status="target_config_error",
        evidence_level="live_system",
        live_model_calls=0,
        artifacts=[],
        reason="Target config omitted the required workflow endpoint.",
        metadata={"target_execution_enabled": True, "target_trace_count": 1},
    )

    assert row.status == "target_config_error"
    assert row.evidence_level == "live_system"

    with pytest.raises(ValueError, match="observed target call, trace, or target artifact count"):
        _live_row(
            status="target_error",
            evidence_level="live_system",
            live_model_calls=0,
            artifacts=[],
            reason="Target execution failed before behavior scoring.",
            metadata={"target_execution_enabled": True},
        )

    with pytest.raises(ValueError, match="explicit reason"):
        _live_row(
            status="target_error",
            evidence_level="live_system",
            live_model_calls=0,
            artifacts=[],
            reason="",
            metadata={"target_execution_enabled": True, "target_trace_count": 1},
        )


def test_capability_and_checkpoint_statuses_validate_without_model_failures() -> None:
    provider_gap = _live_row(
        status="provider_capability_gap",
        evidence_level="scaffold_static",
        provider_calls_enabled=False,
        live_model_calls=0,
        artifacts=[],
        reason="Release matrix surface has no provider-backed live runner yet.",
    )
    target_gap = _live_row(
        status="target_capability_gap",
        evidence_level="scaffold_static",
        live_model_calls=0,
        artifacts=[],
        reason="Target preflight reported image input unavailable.",
        metadata={"preflight_visual_status": "not_supported"},
    )
    checkpoint = _live_row(
        status="checkpoint_not_run",
        evidence_level="scaffold_static",
        provider_calls_enabled=False,
        live_model_calls=0,
        artifacts=[],
        reason="Surface was not reached before checkpoint.",
    )

    assert provider_gap.live_model_calls == 0
    assert target_gap.evidence_level == "scaffold_static"
    assert checkpoint.status == "checkpoint_not_run"


def test_live_system_trace_rejects_preflight_only_metadata() -> None:
    with pytest.raises(ValueError, match="observed target call, trace, or target artifact count"):
        _live_row(
            status="passed",
            evidence_level="live_system_trace",
            live_model_calls=0,
            artifacts=[],
            reason="Preflight passed but no target execution happened.",
            metadata={"preflight_text_status": "passed"},
        )

    with pytest.raises(ValueError, match="observed target call, trace, or target artifact count"):
        _live_row(
            status="provider_error",
            evidence_level="live_system_trace",
            live_model_calls=0,
            artifacts=[],
            reason="Provider preflight failed before target execution.",
            metadata={"preflight_text_status": "provider_error"},
        )


def test_dry_run_rejected() -> None:
    with pytest.raises(ValueError, match="dry_run=true"):
        _live_row(dry_run=True)

    with pytest.raises(ValueError, match="dry_run report mode|dry_run.*cannot"):
        _live_row(report_mode="dry_run")

    with pytest.raises(ValueError, match="dry-run/scaffold/fixture artifacts"):
        _live_row(artifacts=[_artifact(path="dry-run.json", relative_path="dry-run.json")])

    with pytest.raises(ValueError, match="fixture artifacts"):
        _live_row(artifacts=[_artifact(path="self-modification-workflow-fixture.json", relative_path="self-modification-workflow-fixture.json")])


def test_scaffold_only_rejected_as_live() -> None:
    with pytest.raises(ValueError, match="scaffold report mode|scaffold.*cannot"):
        _live_row(report_mode="scaffold")

    with pytest.raises(ValueError, match="scaffold-only artifacts"):
        _live_row(artifacts=[_artifact(metadata={"evidence_level": "scaffold_only"})])

    with pytest.raises(ValueError, match="manifest-only"):
        _live_row(artifacts=[_artifact(kind="manifest", artifact_type="run_manifest", path="manifest.json", relative_path="manifest.json")])


def test_provider_disabled_rejected_for_live() -> None:
    with pytest.raises(ValueError, match="provider_calls_enabled=true"):
        _live_row(provider_calls_enabled=False)


def test_zero_live_calls_rejected_for_live_status() -> None:
    with pytest.raises(ValueError, match="live_model_calls > 0"):
        _live_row(live_model_calls=0)

    with pytest.raises(ValueError, match="live_model_calls > 0"):
        _live_row(live_model_calls=None)


def test_non_live_status_without_reason_rejected() -> None:
    with pytest.raises(ValueError, match="explicit reason"):
        _live_row(
            status="not_implemented",
            evidence_level="not_implemented",
            provider_calls_enabled=False,
            live_model_calls=0,
            artifacts=[],
            reason="",
        )


def test_response_summary_uses_hash_and_redacted_excerpt_without_raw_text() -> None:
    raw = "token: SYNTHETIC-SK-OPENAI-SECRET at /home/alice/private/report.txt"
    summary = summarize_response(raw, excerpt_limit=200)
    payload = summary.model_dump()

    assert summary.sha256 == sha256_text(raw)
    assert summary.length == len(raw)
    assert "SYNTHETIC-SK-OPENAI-SECRET" not in summary.redacted_excerpt
    assert "/home/alice" not in summary.redacted_excerpt
    assert "[REDACTED]" in summary.redacted_excerpt
    assert "raw" not in payload


def test_matrix_requires_each_row_fields_and_non_live_reasons() -> None:
    surface = LiveSurfaceRecord(surface_id="chat", name="Chat", category="core", modality="text")
    live_row = _live_row(row_id="row-live")
    non_live_row = _live_row(
        row_id="row-non-live",
        status="skipped_by_flag",
        evidence_level="scaffold_static",
        provider_calls_enabled=False,
        live_model_calls=0,
        artifacts=[],
        reason="Operator disabled this optional surface.",
    )

    matrix = LiveEvidenceMatrix(matrix_id="matrix-1", generated_at="2026-04-26T00:00:00Z", surfaces=[surface], rows=[live_row, non_live_row])
    assert [row.row_id for row in matrix.rows] == ["row-live", "row-non-live"]

    with pytest.raises(ValueError, match="Field required"):
        LiveEvidenceRow.model_validate({"row_id": "incomplete"})

    with pytest.raises(ValueError, match="explicit reason"):
        _live_row(
            row_id="row-bad",
            status="skipped_by_flag",
            evidence_level="scaffold_static",
            provider_calls_enabled=False,
            live_model_calls=0,
            artifacts=[],
            reason=None,
        )

    with pytest.raises(ValueError, match="unknown surface"):
        LiveEvidenceMatrix(matrix_id="matrix-bad", generated_at="2026-04-26T00:00:00Z", surfaces=[surface], rows=[_live_row(surface_id="unknown")])
