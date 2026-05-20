from __future__ import annotations

import json
from pathlib import Path

from malleus.assessment import run_assessment


def _write_target(tmp_path: Path) -> Path:
    target = tmp_path / "target.yaml"
    target.write_text(
        "name: t\nadapter: openai_compatible\nmodel: m\nbase_url: https://example.test/v1\napi_key_env: OPENAI_API_KEY\n",
        encoding="utf-8",
    )
    return target


def test_assessment_dry_run_writes_raw_pack_refs_and_planning_evidence(tmp_path: Path) -> None:
    out_dir = tmp_path / "assessment"

    result = run_assessment(
        target_path=_write_target(tmp_path),
        profile="rag-agent",
        packs=["core", "rag"],
        mode="dry_run",
        out_dir=out_dir,
        compare_targets=[],
        regression_pack=None,
        policy_path=None,
        baseline_path=None,
        include_experimental=False,
        limit=None,
        case_ids=[],
        allow_live_provider=False,
        provider_calls_enabled=False,
    )

    assert result["raw_refs"] == {
        "core": "raw/core/planning-metadata.json",
        "rag": "raw/rag/planning-metadata.json",
    }
    for relative_ref in result["raw_refs"].values():
        assert (out_dir / relative_ref).exists()
        assert not Path(relative_ref).is_absolute()

    risk_report = json.loads((out_dir / "risk-report.json").read_text(encoding="utf-8"))
    manifest = json.loads((out_dir / "assessment-manifest.json").read_text(encoding="utf-8"))
    packs = {pack["id"]: pack for pack in risk_report["packs"]}
    assert packs["core"]["applicability"] == "applicable"
    assert packs["core"]["evidence_strengths"] == ["planning_only"]
    assert packs["core"]["score"]["score_declaration"]["reason"] == "planning_only_not_primary_evidence"
    assert packs["core"]["score"]["raw_ref"] == "raw/core/planning-metadata.json"
    assert packs["core"]["description"]
    assert packs["core"]["surfaces"]
    assert packs["core"]["techniques"]
    assert packs["core"]["required_inputs"]
    assert packs["core"]["expected_artifacts"]
    assert packs["core"]["scoring_dimensions"]
    assert packs["core"]["finding_categories"]
    assert packs["core"]["remediation_themes"]
    assert packs["rag"]["applicability"] == "requires_fixture"
    assert packs["rag"]["score_use"] == "not_tested"

    evidence_paths = {ref["artifact_path"] for ref in risk_report["evidence_refs"]}
    assert {"raw/core/planning-metadata.json", "raw/rag/planning-metadata.json"} <= evidence_paths
    assert risk_report["scores"]["coverage_confidence"]["gap_pack_ids"] == ["rag"]
    assert (out_dir / "remediation" / "patches").is_dir()
    assert (out_dir / "remediation" / "patches" / "README.md").exists()
    assert manifest["target_config_path"] == "target.yaml"
    assert len(manifest["target_config_sha256"]) == 64
    assert manifest["requested_packs"] == ["core", "rag"]
    assert manifest["selected_packs"] == ["core", "rag"]
    assert manifest["command_summary"]["entrypoint"] == "malleus assess"
    assert manifest["command_summary"]["case_filter_count"] == 0
    assert manifest["schema_versions"]["raw_pack"] == "malleus.assessment_raw_pack.v1"
    assert manifest["provider_calls_enabled"] is False
    assert manifest["network_enabled"] is False
    assert manifest["browser_enabled"] is False
    assert manifest["git_commit"]
    assert "raw/<pack-id>/planning-metadata.json" in manifest["raw_artifact_mapping"]
    assert "remediation/patches/README.md" in manifest["remediation_patch_mapping"]

    raw_core = json.loads((out_dir / "raw" / "core" / "planning-metadata.json").read_text(encoding="utf-8"))
    assert raw_core["pack"]["surfaces"]
    assert raw_core["pack"]["required_inputs"]
    assert raw_core["pack"]["remediation_themes"]


def test_assessment_local_fixture_missing_fixture_is_coverage_gap_not_success(tmp_path: Path) -> None:
    out_dir = tmp_path / "assessment"

    run_assessment(
        target_path=_write_target(tmp_path),
        profile="rag-agent",
        packs=["rag", "taxonomy"],
        mode="local_fixture",
        out_dir=out_dir,
        compare_targets=[],
        regression_pack=None,
        policy_path=None,
        baseline_path=None,
        include_experimental=False,
        limit=None,
        case_ids=[],
        allow_live_provider=False,
        provider_calls_enabled=False,
    )

    risk_report = json.loads((out_dir / "risk-report.json").read_text(encoding="utf-8"))
    packs = {pack["id"]: pack for pack in risk_report["packs"]}
    assert packs["rag"]["applicability"] == "requires_fixture"
    assert packs["rag"]["score_use"] == "not_tested"
    assert packs["rag"]["score"]["score_declaration"]["score_use"] == "coverage_gap"
    assert packs["rag"]["score"]["score_declaration"]["reason"] == "requires_fixture"
    assert packs["taxonomy"]["applicability"] == "applicable"
    assert packs["taxonomy"]["evidence_strengths"] == ["static_analysis"]
    assert risk_report["scores"]["primary_score"]["possible"] == 0
