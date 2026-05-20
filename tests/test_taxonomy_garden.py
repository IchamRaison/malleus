from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from malleus.cli import app
from malleus.scenario_generator import generate_defensive_scenario
from malleus.taxonomy_garden import TaxonomyCoverageCell, diff_taxonomy_snapshots, write_taxonomy_snapshot
from malleus.utils.redact import scan_public_artifact_text


def _public_text(out: Path) -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in sorted(out.iterdir()) if path.suffix in {".json", ".md"})


def test_taxonomy_snapshot_cli_writes_expected_artifacts_and_safe_dimensions(tmp_path: Path) -> None:
    scenario_out = tmp_path / "scenario"
    generate_defensive_scenario(
        profile="rag-agent",
        surface="rag_context",
        technique="tool_output_instruction",
        boundary="agent_policy_boundary",
        out_dir=scenario_out,
    )
    out = tmp_path / "taxonomy"

    result = CliRunner().invoke(
        app,
        [
            "taxonomy",
            "snapshot",
            "--input",
            "datasets/benchmark_packs/smoke-v1.yaml",
            "--input",
            "datasets/benchmark_packs/core-v1.yaml",
            "--scenario-coverage",
            str(scenario_out / "coverage-preview.json"),
            "--out-dir",
            str(out),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Taxonomy snapshot written" in result.output
    assert "Provider calls enabled: false" in result.output
    assert {"taxonomy-snapshot.json", "taxonomy-snapshot.md", "dataset-snapshot.json", "coverage-snapshot.json"}.issubset({path.name for path in out.iterdir()})

    snapshot = json.loads((out / "taxonomy-snapshot.json").read_text(encoding="utf-8"))
    dataset = json.loads((out / "dataset-snapshot.json").read_text(encoding="utf-8"))
    coverage = json.loads((out / "coverage-snapshot.json").read_text(encoding="utf-8"))
    public_text = _public_text(out)

    assert snapshot["schema_version"] == "malleus.taxonomy_garden.v1"
    assert "prompt" in snapshot["attack_surfaces"]
    assert "direct_override" in snapshot["techniques"]
    assert "instruction_boundary" in snapshot["boundaries"]
    assert snapshot["severity_rationales"]
    assert snapshot["scoring_signals"]
    assert snapshot["reviewer_status"]["draft_review_required"] >= 1
    assert snapshot["scenario_maturity"]["draft_review_required"] >= 1
    assert all(item["scenario_maturity"] == "benchmark_pack" for item in dataset["items"] if item["dataset_name"])
    assert coverage["schema_version"] == "malleus.taxonomy_garden.coverage_snapshot.v1"
    assert "prompt:" not in public_text.lower()
    assert "/home/" not in public_text
    assert scan_public_artifact_text(public_text).passed


def test_taxonomy_diff_reports_exact_added_visual_cell_without_unrelated_churn(tmp_path: Path) -> None:
    base_out = tmp_path / "base"
    new_out = tmp_path / "new"
    base, _ = write_taxonomy_snapshot(["datasets/benchmark_packs/smoke-v1.yaml"], base_out)
    changed = base.model_copy(deep=True)
    changed.coverage_cells.append(
        TaxonomyCoverageCell(
            cell_id="coverage:visual/ocr_metadata/untrusted_visual_surface",
            source_surface="visual",
            technique="ocr_metadata",
            expected_boundary="untrusted_visual_surface",
            status="covered",
            item_count=1,
            evidence_refs=1,
            taxonomy_refs=["visual_lab", "ocr_metadata"],
            coverage_tags=["visual", "local_fixture"],
            reviewer_status="covered",
            scenario_maturity="coverage_evidence",
        )
    )
    new_out.mkdir()
    new_path = new_out / "taxonomy-snapshot.json"
    new_path.write_text(changed.model_dump_json(indent=2), encoding="utf-8")

    report = diff_taxonomy_snapshots(base_out / "taxonomy-snapshot.json", new_path)

    assert report.summary.added_cells == 1
    assert report.summary.removed_cells == 0
    assert report.summary.changed_cells == 0
    assert [item.cell_id for item in report.added] == ["coverage:visual/ocr_metadata/untrusted_visual_surface"]


def test_taxonomy_diff_cli_writes_json_and_markdown(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    diff_out = tmp_path / "diff"
    write_taxonomy_snapshot(["datasets/benchmark_packs/smoke-v1.yaml"], first)
    write_taxonomy_snapshot(["datasets/benchmark_packs/core-v1.yaml"], second)

    result = CliRunner().invoke(
        app,
        [
            "taxonomy",
            "diff",
            "--old",
            str(first / "taxonomy-snapshot.json"),
            "--new",
            str(second / "taxonomy-snapshot.json"),
            "--out-dir",
            str(diff_out),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Taxonomy diff written" in result.output
    payload = json.loads((diff_out / "taxonomy-diff.json").read_text(encoding="utf-8"))
    assert payload["schema_version"] == "malleus.taxonomy_garden.diff.v1"
    assert (diff_out / "taxonomy-diff.md").exists()
