from __future__ import annotations

from pathlib import Path

import pytest

from malleus.datasets import load_mutation_profile, load_release_matrix, load_target_config
from malleus.live_evidence import LiveEvidenceRow
from malleus.live_full import build_live_full_matrix
from malleus.live_preflight import LivePreflightReport, SafeTargetEndpoint


REPO_ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = REPO_ROOT / "datasets" / "release_matrices" / "malleus-v0.1.yaml"
SELECTED_PROFILE_PATH = REPO_ROOT / "datasets" / "mutation_profiles" / "selected-v1.yaml"
DEEP_PROFILE_PATH = REPO_ROOT / "datasets" / "mutation_profiles" / "deep-v1.yaml"
LIVE_CHAT_PACK_IDS = {
    "challenge-v1",
    "calibration-v1",
}
REAL_SYSTEM_TARGET_REQUIRED_PACK_IDS = {
    "code-agent-v1",
    "plugin-workflow-v1",
    "self-modification-v1",
}


def test_live_full_represents_every_release_matrix_surface(tmp_path: Path) -> None:
    matrix = load_release_matrix(MATRIX_PATH)
    evidence = _build_matrix(tmp_path)

    surface_ids = {surface.surface_id for surface in evidence.surfaces}
    row_ids = {row.row_id for row in evidence.rows}
    expected_pack_ids = {f"pack:{pack.id}" for pack in matrix.packs}

    assert expected_pack_ids.issubset(surface_ids)
    assert expected_pack_ids.issubset(row_ids)
    assert "mutation-profile:selected-v1" in row_ids
    assert "mutation-profile:deep-v1" in row_ids
    assert len(row_ids) == len(matrix.packs) + 2


def test_challenge_and_calibration_are_live_chat_routes_not_provider_free(tmp_path: Path) -> None:
    evidence = _build_matrix(tmp_path)
    rows = {row.row_id: row for row in evidence.rows}

    for pack_id in LIVE_CHAT_PACK_IDS:
        row = rows[f"pack:{pack_id}"]
        assert row.status == "target_error"
        assert row.status != "passed"
        assert row.evidence_level == "scaffold_static"
        assert row.dry_run is False
        assert row.live_model_calls == 0
        assert row.reason
        assert "provider-free" not in row.reason
        assert "static" not in row.reason
        assert "provider_free_classification" not in row.metadata
        assert "static_matrix_evidence_level" not in row.metadata

    assert "text preflight did not pass" in (rows["pack:challenge-v1"].reason or "")
    assert "text preflight did not pass" in (rows["pack:calibration-v1"].reason or "")

    for pack_id in REAL_SYSTEM_TARGET_REQUIRED_PACK_IDS:
        row = rows[f"pack:{pack_id}"]
        assert row.status == "target_capability_gap"
        assert row.evidence_level == "scaffold_static"
        assert row.live_model_calls == 0
        assert row.metadata["target_execution_enabled"] is False
        assert row.metadata["target_trace_count"] == 0
        assert row.metadata["actual_target_type"] == "chat_completion"
        assert any(fragment in (row.reason or "") for fragment in ("requires target_type=", "requires a compatible"))


def test_non_live_classification_rows_cannot_be_live_passes(tmp_path: Path) -> None:
    evidence = _build_matrix(tmp_path)

    for row in evidence.rows:
        assert "provider_free_classification" not in row.metadata
        if row.row_id in {f"pack:{pack_id}" for pack_id in LIVE_CHAT_PACK_IDS}:
            assert row.evidence_level == "scaffold_static"
            assert row.status == "target_error"
            assert row.live_model_calls == 0

    with pytest.raises(ValueError, match="passed/failed live rows require live_model_calls > 0"):
        LiveEvidenceRow(
            row_id="pack:code-agent-v1",
            run_id="run",
            case_id="code-agent-v1",
            surface_id="pack:code-agent-v1",
            timestamp="2026-04-27T00:00:00+00:00",
            command="malleus benchmark live-full --no-dry-run",
            git_commit="unknown",
            target=evidence.rows[0].target,
            status="passed",
            evidence_level="live_text_model",
            dry_run=False,
            provider_calls_enabled=True,
            live_model_calls=0,
        )


def _build_matrix(tmp_path: Path):
    target_path = _target(tmp_path)
    target = load_target_config(target_path)
    matrix = load_release_matrix(MATRIX_PATH)
    selected_profile = load_mutation_profile(SELECTED_PROFILE_PATH)
    deep_profile = load_mutation_profile(DEEP_PROFILE_PATH)
    return build_live_full_matrix(
        target_path=target_path,
        matrix_path=MATRIX_PATH,
        out_dir=tmp_path / "out",
        target=target,
        matrix=matrix,
        selected_profile=selected_profile,
        deep_profile=deep_profile,
        preflight=_preflight(),
        include_deep_mutations=False,
        yes=True,
        concurrency=1,
        request_timeout=30.0,
        max_retries=0,
        command="malleus benchmark live-full --no-dry-run",
    )


def _target(tmp_path: Path) -> Path:
    target = tmp_path / "target.yaml"
    target.write_text(
        "name: classification-target\nadapter: openai_compatible\nmodel: fake-model\nbase_url: https://example.test/v1\napi_key_env: MISSING_CLASSIFICATION_KEY\n",
        encoding="utf-8",
    )
    return target


def _preflight() -> LivePreflightReport:
    return LivePreflightReport(
        target_name="classification-target",
        adapter="openai_compatible",
        model="fake-model",
        endpoint=SafeTargetEndpoint(scheme="https", host="example.test", path_hint="/v1"),
        text_status="preflight_failed",
        text_ready=False,
        visual_status="not_supported",
        ok=False,
        probes=[],
    )
