from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from malleus.datasets import (
    load_benchmark_pack,
    load_mutation_profile,
    load_release_matrix,
    validate_mutation_profile_pair,
    validate_release_matrix_references,
)
from malleus.schemas import MUTATION_PROFILE_SCHEMA_VERSION, RELEASE_MATRIX_SCHEMA_VERSION


REPO_ROOT = Path(__file__).resolve().parents[1]
CANONICAL_MATRIX = REPO_ROOT / "datasets/release_matrices/malleus-v0.1.yaml"
EXPECTED_CANONICAL_PACK_IDS = {
    "smoke-v1",
    "core-v1",
    "rag-v1",
    "agentic-injection-v1",
    "artifact-hidden-channel-v1",
    "visual-ocr-matrix",
    "code-agent-v1",
    "plugin-workflow-v1",
    "memory-agent-v1",
    "multi-agent-v1",
    "ui-browser-v1",
    "campaign-v1",
    "self-modification-v1",
    "challenge-v1",
    "calibration-v1",
}
EXPECTED_BENCHMARK_PACK_PATHS = {
    "datasets/benchmark_packs/smoke-v1.yaml",
    "datasets/benchmark_packs/core-v1.yaml",
}
EXPECTED_NON_PACK_MATRIX_PATHS = {
    "tests/fixtures/rag/security-fixture.yaml",
    "datasets/agentic/agentic_injection_v1.yaml",
    "tests/fixtures/hidden_channels/artifact-hidden-catalog.yaml",
    "src/malleus/visual_lab.py",
    "tests/fixtures/code_agent",
    "tests/fixtures/workflows/plugin-workflow-v1.yaml",
    "tests/fixtures/memory/memory-agent-v1.yaml",
    "tests/fixtures/multi_agent/multi-agent-v1.yaml",
    "tests/fixtures/ui_harness/local-product.yaml",
    "tests/fixtures/campaigns/agentic-extreme.yaml",
    "tests/fixtures/self_modification",
    "tests/fixtures/challenges",
    "datasets/calibration/calibration-v1.yaml",
}
FORBIDDEN_CANONICAL_TOKENS = {
    "provider_free_static",
    "provider_free_dry_run",
    "provider-free-static-release",
    "calibration_control",
    "static_or_scaffold_evidence",
    "provider_free_or_classification_evidence",
}


def _matrix_reference_path(source_path: str) -> Path:
    return (REPO_ROOT / source_path).resolve()


def _has_non_hidden_file(path: Path) -> bool:
    return any(item.is_file() and not item.name.startswith(".") for item in path.rglob("*"))


def _matrix_yaml(**overrides: object) -> str:
    data = {
        "schema_version": RELEASE_MATRIX_SCHEMA_VERSION,
        "id": "fixture-v0.1",
        "version": "0.1.0",
        "mode_boundaries": [
            {
                "mode": "dry_run",
                "evidence_level": "provider_free_static",
                "provider_calls_enabled": False,
            }
        ],
        "packs": [
            {
                "id": "smoke-v1",
                "path": "datasets/benchmark_packs/smoke-v1.yaml",
                "evidence_level": "live_model_required",
                "live_model_evidence": True,
            }
        ],
        "selected_mutation_profiles": [
            {
                "id": "selected-v1",
                "path": "datasets/mutation_profiles/selected-v1.yaml",
                "evidence_level": "scaffold_only",
                "status": "planned",
            }
        ],
        "deep_mutation_profiles": [
            {
                "id": "deep-v1",
                "path": "datasets/mutation_profiles/deep-v1.yaml",
                "evidence_level": "optional_deep_test",
                "status": "planned",
            }
        ],
        "gates": [
            {
                "id": "fixture-gate",
                "description": "Fixture gate",
                "pack_ids": ["smoke-v1"],
                "mutation_profile_refs": ["selected-v1"],
                "evidence_level": "provider_free_static",
            }
        ],
        "notes": ["Fixture matrix."],
    }
    data.update(overrides)

    return yaml.safe_dump(data, sort_keys=False)


def _write_matrix(tmp_path: Path, **overrides: object) -> Path:
    matrix = tmp_path / "matrix.yaml"
    matrix.write_text(_matrix_yaml(**overrides), encoding="utf-8")
    return matrix


def test_canonical_release_matrix_loads_with_identity_and_profiles() -> None:
    matrix = load_release_matrix(CANONICAL_MATRIX)
    matrix_text = CANONICAL_MATRIX.read_text(encoding="utf-8")

    assert matrix.schema_version == RELEASE_MATRIX_SCHEMA_VERSION
    assert matrix.id == "malleus-v0.1"
    assert matrix.version == "0.1.0"
    assert matrix.source_path == str(CANONICAL_MATRIX.resolve())
    assert {pack.id for pack in matrix.packs} == EXPECTED_CANONICAL_PACK_IDS
    assert {profile.id for profile in matrix.selected_mutation_profiles} == {"selected-v1"}
    assert {profile.id for profile in matrix.deep_mutation_profiles} == {"deep-v1"}
    assert len(matrix.packs) + len(matrix.selected_mutation_profiles) + len(matrix.deep_mutation_profiles) == 17
    assert "ui-browser-scaffold-v1" not in {pack.id for pack in matrix.packs}
    assert all("ui-browser-scaffold-v1" not in gate.pack_ids for gate in matrix.gates)
    assert not (FORBIDDEN_CANONICAL_TOKENS & set(matrix_text.split()))
    for forbidden_token in FORBIDDEN_CANONICAL_TOKENS:
        assert forbidden_token not in matrix_text

    evidence_by_pack = {pack.id: pack.evidence_level for pack in matrix.packs}
    assert all(evidence_level == "live_model_required" for evidence_level in evidence_by_pack.values())
    packs_by_id = {pack.id: pack for pack in matrix.packs}
    assert packs_by_id["rag-v1"].surface_name == "RAG retrieval and citation security"
    assert packs_by_id["code-agent-v1"].surface_name == "Code-agent sandbox and workspace security"
    assert all(pack.surface_name and "-v1" not in pack.surface_name for pack in matrix.packs)
    assert packs_by_id["smoke-v1"].target_types == ["chat_completion"]
    assert packs_by_id["smoke-v1"].live_evidence_category == "chat_model_evidence"
    assert packs_by_id["smoke-v1"].real_system_evidence is False
    assert packs_by_id["core-v1"].target_types == ["chat_completion"]
    assert packs_by_id["core-v1"].live_evidence_category == "chat_model_evidence"
    for pack_id in {"artifact-hidden-channel-v1", "campaign-v1", "challenge-v1", "calibration-v1"}:
        assert packs_by_id[pack_id].live_model_evidence is True
        assert packs_by_id[pack_id].target_types == ["chat_completion"]
        assert packs_by_id[pack_id].live_evidence_category == "chat_model_evidence"
        assert packs_by_id[pack_id].real_system_evidence is False

    visual_matrix = packs_by_id["visual-ocr-matrix"]
    assert visual_matrix.live_model_evidence is True
    assert visual_matrix.target_types == ["vision_model"]
    assert visual_matrix.live_evidence_category == "multimodal_model_evidence"
    assert visual_matrix.real_system_evidence is False
    assert "provider_capability_gap" in visual_matrix.notes
    assert "text-only chat" in visual_matrix.notes

    expected_system_metadata = {
        "rag-v1": ["rag_service"],
        "agentic-injection-v1": ["tool_agent"],
        "plugin-workflow-v1": ["workflow_harness"],
        "code-agent-v1": ["code_agent"],
        "memory-agent-v1": ["memory_agent"],
        "multi-agent-v1": ["multi_agent"],
        "ui-browser-v1": ["browser_agent"],
    }
    for pack_id, target_types in expected_system_metadata.items():
        pack = packs_by_id[pack_id]
        assert pack.evidence_level == "live_model_required"
        assert pack.live_model_evidence is True
        assert pack.target_types == target_types
        assert pack.live_evidence_category == "live_system_evidence"
        assert pack.real_system_evidence is True
        if pack_id in {"memory-agent-v1", "multi-agent-v1", "ui-browser-v1"}:
            assert "observable" in pack.notes
        else:
            assert pack.static_evidence_separate

    self_modification = packs_by_id["self-modification-v1"]
    assert self_modification.evidence_level == "live_model_required"
    assert self_modification.live_model_evidence is True
    assert self_modification.target_types == ["tool_agent", "workflow_harness", "code_agent", "memory_agent", "multi_agent"]
    assert self_modification.live_evidence_category == "live_system_evidence"
    assert self_modification.real_system_evidence is True
    assert "target capability gap" in self_modification.notes
    assert "tool_agent" in self_modification.notes
    assert "workflow_harness" in self_modification.notes
    assert "code_agent" in self_modification.notes
    assert "memory_agent" in self_modification.notes
    assert "multi_agent" in self_modification.notes
    assert "chat text" in self_modification.notes

    [selected_profile_ref] = matrix.selected_mutation_profiles
    assert selected_profile_ref.status == "available"
    assert selected_profile_ref.profile_name == "Selected mutation robustness profile"
    assert selected_profile_ref.default is True
    assert selected_profile_ref.mutation_count == 25
    assert selected_profile_ref.path == "datasets/mutation_profiles/selected-v1.yaml"
    assert selected_profile_ref.target_types == ["chat_completion"]
    assert selected_profile_ref.live_evidence_category == "chat_model_evidence"
    assert selected_profile_ref.real_system_evidence is False

    [deep_profile_ref] = matrix.deep_mutation_profiles
    assert deep_profile_ref.status == "available_optional"
    assert deep_profile_ref.profile_name == "Deep mutation robustness profile"
    assert deep_profile_ref.default is False
    assert deep_profile_ref.optional is True
    assert deep_profile_ref.path == "datasets/mutation_profiles/deep-v1.yaml"

    selected_profile = load_mutation_profile(REPO_ROOT / selected_profile_ref.path)
    deep_profile = load_mutation_profile(REPO_ROOT / deep_profile_ref.path)
    assert len(selected_profile.mutations) == 25
    validate_mutation_profile_pair(selected_profile, deep_profile)
    assert any(boundary.mode == "live_provider" and boundary.evidence_level == "live_model_required" for boundary in matrix.mode_boundaries)
    assert {gate.id for gate in matrix.gates} == {"live-model-release"}
    [live_gate] = matrix.gates
    assert set(live_gate.pack_ids) == EXPECTED_CANONICAL_PACK_IDS
    assert live_gate.evidence_level == "live_model_required"


def test_release_matrix_optional_target_metadata_is_backward_compatible(tmp_path: Path) -> None:
    matrix = load_release_matrix(_write_matrix(tmp_path))
    [pack] = matrix.packs
    [profile] = matrix.selected_mutation_profiles

    assert pack.target_types == []
    assert pack.live_evidence_category is None
    assert pack.real_system_evidence is False
    assert pack.static_evidence_separate == ""
    assert profile.target_types == []
    assert profile.live_evidence_category is None
    assert profile.real_system_evidence is False


def test_release_matrix_rejects_invalid_target_metadata(tmp_path: Path) -> None:
    path = _write_matrix(
        tmp_path,
        packs=[
            {
                "id": "bad-target-type",
                "path": "datasets/benchmark_packs/smoke-v1.yaml",
                "evidence_level": "live_model_required",
                "live_model_evidence": True,
                "target_types": ["browser_ui"],
                "live_evidence_category": "chat_model_evidence",
            }
        ],
    )

    with pytest.raises(Exception, match="browser_ui"):
        load_release_matrix(path)


def test_release_matrix_rejects_real_system_category_mismatch(tmp_path: Path) -> None:
    path = _write_matrix(
        tmp_path,
        packs=[
            {
                "id": "bad-category",
                "path": "datasets/benchmark_packs/smoke-v1.yaml",
                "evidence_level": "live_model_required",
                "live_model_evidence": True,
                "target_types": ["rag_service"],
                "live_evidence_category": "chat_model_evidence",
                "real_system_evidence": True,
            }
        ],
    )

    with pytest.raises(Exception, match="real system evidence entries must use live_system_evidence category"):
        load_release_matrix(path)


def test_canonical_release_matrix_system_notes_do_not_claim_model_only_evidence() -> None:
    matrix = load_release_matrix(CANONICAL_MATRIX)
    packs_by_id = {pack.id: pack for pack in matrix.packs}

    for pack_id in {"rag-v1", "agentic-injection-v1", "plugin-workflow-v1", "code-agent-v1", "self-modification-v1"}:
        note_text = f"{packs_by_id[pack_id].notes} {packs_by_id[pack_id].static_evidence_separate}".lower()
        assert "completed live model responses" not in note_text
        assert "model-only" not in note_text or "separate" in note_text
        assert "static" not in note_text or "separate" in note_text or pack_id == "self-modification-v1"


def test_release_matrix_rejects_empty_matrix(tmp_path: Path) -> None:
    path = _write_matrix(tmp_path, packs=[])

    with pytest.raises(Exception, match="at least 1"):
        load_release_matrix(path)


def test_release_matrix_rejects_duplicate_pack_ids(tmp_path: Path) -> None:
    path = _write_matrix(
        tmp_path,
        packs=[
            {
                "id": "smoke-v1",
                "path": "datasets/benchmark_packs/smoke-v1.yaml",
                "evidence_level": "live_model_required",
                "live_model_evidence": True,
            },
            {
                "id": "smoke-v1",
                "path": "datasets/benchmark_packs/core-v1.yaml",
                "evidence_level": "live_model_required",
                "live_model_evidence": True,
            },
        ],
    )

    with pytest.raises(Exception, match="duplicate pack id: smoke-v1"):
        load_release_matrix(path)


def test_release_matrix_rejects_missing_required_fields(tmp_path: Path) -> None:
    path = tmp_path / "matrix.yaml"
    path.write_text("schema_version: malleus.release_matrix.v1\nid: missing-fields\n", encoding="utf-8")

    with pytest.raises(Exception, match="Field required"):
        load_release_matrix(path)


def test_release_matrix_rejects_wrong_evidence_level(tmp_path: Path) -> None:
    path = _write_matrix(
        tmp_path,
        packs=[
            {
                "id": "smoke-v1",
                "path": "datasets/benchmark_packs/smoke-v1.yaml",
                "evidence_level": "model_behavior",
            }
        ],
    )

    with pytest.raises(Exception, match="unsupported release matrix evidence level: model_behavior"):
        load_release_matrix(path)


def test_release_matrix_rejects_missing_pack_reference(tmp_path: Path) -> None:
    path = _write_matrix(
        tmp_path,
        gates=[
            {
                "id": "missing-pack-gate",
                "description": "Missing pack ref",
                "pack_ids": ["missing-pack"],
                "evidence_level": "provider_free_static",
            }
        ],
    )

    with pytest.raises(Exception, match="gate missing-pack-gate references unknown pack: missing-pack"):
        load_release_matrix(path)


def test_release_matrix_rejects_missing_mutation_profile_reference(tmp_path: Path) -> None:
    path = _write_matrix(
        tmp_path,
        gates=[
            {
                "id": "missing-profile-gate",
                "description": "Missing profile ref",
                "mutation_profile_refs": ["missing-profile"],
                "evidence_level": "provider_free_static",
            }
        ],
    )

    with pytest.raises(Exception, match="gate missing-profile-gate references unknown mutation profile: missing-profile"):
        load_release_matrix(path)


def test_release_matrix_rejects_scaffold_only_masquerading_as_live_evidence(tmp_path: Path) -> None:
    path = _write_matrix(
        tmp_path,
        packs=[
            {
                "id": "scaffold-pack",
                "path": "datasets/benchmark_packs/scaffold.yaml",
                "evidence_level": "live_model_required",
                "live_model_evidence": True,
                "scaffold_only": True,
            }
        ],
    )

    with pytest.raises(Exception, match="scaffold-only entries cannot be listed as live model evidence"):
        load_release_matrix(path)


def test_release_matrix_strict_references_accept_canonical_matrix() -> None:
    matrix = validate_release_matrix_references(CANONICAL_MATRIX)

    assert matrix.id == "malleus-v0.1"


def test_release_matrix_references_existing_sources() -> None:
    matrix = validate_release_matrix_references(CANONICAL_MATRIX)
    matrix_paths = [pack.path for pack in matrix.packs]
    profile_paths = [profile.path for profile in [*matrix.selected_mutation_profiles, *matrix.deep_mutation_profiles]]
    benchmark_pack_paths = {path for path in matrix_paths if Path(path).parts[:2] == ("datasets", "benchmark_packs")}

    assert set(matrix_paths) == EXPECTED_BENCHMARK_PACK_PATHS | EXPECTED_NON_PACK_MATRIX_PATHS
    assert {pack.path for pack in matrix.packs if pack.id == "visual-ocr-matrix"} == {"src/malleus/visual_lab.py"}
    assert not (REPO_ROOT / "datasets/benchmark_packs/visual-ocr-matrix.yaml").exists()

    for source_path in [*matrix_paths, *profile_paths]:
        resolved = _matrix_reference_path(source_path)
        assert resolved.exists(), f"matrix reference does not exist: {source_path}"
        if resolved.is_dir():
            assert _has_non_hidden_file(resolved), f"matrix directory has no non-hidden files: {source_path}"

    assert benchmark_pack_paths == EXPECTED_BENCHMARK_PACK_PATHS
    loaded_pack_paths = {load_benchmark_pack(_matrix_reference_path(path)).source_path for path in benchmark_pack_paths}
    assert loaded_pack_paths == {str(_matrix_reference_path(path)) for path in EXPECTED_BENCHMARK_PACK_PATHS}


def test_release_matrix_strict_references_reject_missing_path(tmp_path: Path) -> None:
    path = _write_matrix(
        tmp_path,
        packs=[
            {
                "id": "missing-path",
                "path": "does/not/exist.yaml",
                "evidence_level": "provider_free_static",
            }
        ],
        gates=[],
    )

    with pytest.raises(Exception, match="release matrix path does not exist: does/not/exist.yaml"):
        validate_release_matrix_references(path)


def test_release_matrix_strict_references_reject_profile_pair_mismatch(tmp_path: Path) -> None:
    selected_path = tmp_path / "selected.yaml"
    deep_path = tmp_path / "deep.yaml"
    selected_path.write_text(
        yaml.safe_dump(
            {
                "schema_version": MUTATION_PROFILE_SCHEMA_VERSION,
                "id": "selected-fixture",
                "version": "1.0.0",
                "name": "Selected fixture",
                "default": True,
                "mutations": ["unicode_wrap"],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    deep_path.write_text(
        yaml.safe_dump(
            {
                "schema_version": MUTATION_PROFILE_SCHEMA_VERSION,
                "id": "deep-fixture",
                "version": "1.0.0",
                "name": "Deep fixture",
                "deep": True,
                "mutations": ["backtick_wrap"],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    path = _write_matrix(
        tmp_path,
        selected_mutation_profiles=[
            {
                "id": "selected-fixture",
                "path": "selected.yaml",
                "evidence_level": "live_model_required",
                "status": "available",
                "default": True,
            }
        ],
        deep_mutation_profiles=[
            {
                "id": "deep-fixture",
                "path": "deep.yaml",
                "evidence_level": "optional_deep_test",
                "status": "available_optional",
                "optional": True,
            }
        ],
        gates=[],
    )

    with pytest.raises(Exception, match="selected mutation profile selected-fixture is not a subset of deep-fixture: unicode_wrap"):
        validate_release_matrix_references(path)
