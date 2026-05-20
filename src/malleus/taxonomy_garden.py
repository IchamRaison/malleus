from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from malleus.coverage import CoverageReport, build_coverage_report, load_coverage_report
from malleus.datasets import load_input_datasets
from malleus.scenario_generator import REVIEW_STATUS_DRAFT
from malleus.utils.redact import redacted_preview, sha256_text

TAXONOMY_GARDEN_SCHEMA_VERSION = "malleus.taxonomy_garden.v1"
TAXONOMY_DIFF_SCHEMA_VERSION = "malleus.taxonomy_garden.diff.v1"


class TaxonomyDatasetItem(BaseModel):
    item_id: str
    item_type: Literal["case", "group"]
    dataset_name: str
    severity: str
    attack_surface: str
    technique: str
    boundary: str
    severity_rationale: str
    scoring_signals: list[str] = Field(default_factory=list)
    patch_recommendations: list[str] = Field(default_factory=list)
    false_positive_notes: list[str] = Field(default_factory=list)
    reviewer_status: str = "dataset_reviewed"
    scenario_maturity: str = "benchmark_pack"
    source_path: str
    objective_sha256: str
    objective_length: int
    objective_preview: str


class TaxonomyCoverageCell(BaseModel):
    cell_id: str
    source_surface: str
    technique: str
    expected_boundary: str
    status: str
    item_count: int = 0
    finding_count: int = 0
    gate_count: int = 0
    evidence_refs: int = 0
    taxonomy_refs: list[str] = Field(default_factory=list)
    coverage_tags: list[str] = Field(default_factory=list)
    reviewer_status: str = "unreviewed"
    scenario_maturity: str = "unknown"


class TaxonomyScenarioCell(BaseModel):
    cell_id: str
    dimension: str
    value: str
    total_items: int = 0
    covered_items: int = 0
    reviewer_status: str = REVIEW_STATUS_DRAFT
    scenario_maturity: str = "draft_review_required"


class TaxonomySnapshotSummary(BaseModel):
    dataset_items: int = 0
    coverage_cells: int = 0
    scenario_cells: int = 0
    attack_surfaces: int = 0
    techniques: int = 0
    boundaries: int = 0


class TaxonomyGardenSnapshot(BaseModel):
    schema_version: str = TAXONOMY_GARDEN_SCHEMA_VERSION
    generated_at: str
    input_paths: list[str] = Field(default_factory=list)
    attack_surfaces: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    boundaries: list[str] = Field(default_factory=list)
    severity_rationales: list[str] = Field(default_factory=list)
    scoring_signals: list[str] = Field(default_factory=list)
    patch_recommendations: list[str] = Field(default_factory=list)
    false_positive_notes: list[str] = Field(default_factory=list)
    reviewer_status: dict[str, int] = Field(default_factory=dict)
    scenario_maturity: dict[str, int] = Field(default_factory=dict)
    dataset_items: list[TaxonomyDatasetItem] = Field(default_factory=list)
    coverage_cells: list[TaxonomyCoverageCell] = Field(default_factory=list)
    scenario_cells: list[TaxonomyScenarioCell] = Field(default_factory=list)
    summary: TaxonomySnapshotSummary = Field(default_factory=TaxonomySnapshotSummary)
    metadata: dict[str, Any] = Field(default_factory=dict)


class TaxonomyCellDelta(BaseModel):
    cell_id: str
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None
    changed_fields: list[str] = Field(default_factory=list)


class TaxonomyDiffSummary(BaseModel):
    added_cells: int = 0
    removed_cells: int = 0
    changed_cells: int = 0


class TaxonomyDiffReport(BaseModel):
    schema_version: str = TAXONOMY_DIFF_SCHEMA_VERSION
    generated_at: str
    old_snapshot: str
    new_snapshot: str
    added: list[TaxonomyCellDelta] = Field(default_factory=list)
    removed: list[TaxonomyCellDelta] = Field(default_factory=list)
    changed: list[TaxonomyCellDelta] = Field(default_factory=list)
    summary: TaxonomyDiffSummary = Field(default_factory=TaxonomyDiffSummary)


def _safe_path(path: str | Path) -> str:
    candidate = Path(path)
    try:
        return candidate.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return candidate.name


def _metadata_text(metadata: dict[str, Any], *keys: str, default: str) -> str:
    for key in keys:
        value = metadata.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return default


def _metadata_list(metadata: dict[str, Any], *keys: str) -> list[str]:
    values: set[str] = set()
    for key in keys:
        value = metadata.get(key)
        if isinstance(value, list):
            values.update(str(item).strip() for item in value if str(item).strip())
        elif isinstance(value, str) and value.strip():
            values.add(value.strip())
    return sorted(values)


def _signal_names(item: Any) -> list[str]:
    names: set[str] = set()
    for signal in list(getattr(item, "failure_signals", []) or []) + list(getattr(item, "pass_signals", []) or []):
        label = signal.type
        if signal.pattern:
            label = f"{signal.type}:{sha256_text(signal.pattern)[:12]}"
        names.add(label)
    output_constraints = getattr(item, "output_constraints", None)
    if output_constraints is not None:
        names.add(f"output:{output_constraints.mode}")
    return sorted(names)


def _dataset_items(input_paths: list[str | Path]) -> list[TaxonomyDatasetItem]:
    rows: list[TaxonomyDatasetItem] = []
    for input_path in input_paths:
        for dataset in load_input_datasets(input_path):
            source = _safe_path(dataset.source_path or input_path)
            for item_type, items in (("case", dataset.cases or []), ("group", dataset.groups or [])):
                for item in items:
                    metadata = dict(item.metadata)
                    boundary = _metadata_text(metadata, "malleus_boundary", "expected_boundary", "violated_boundary", default=dataset.category)
                    technique = _metadata_text(metadata, "malleus_technique", "technique", "tactic", default=dataset.subcategory)
                    maps_to = metadata.get("maps_to")
                    if isinstance(maps_to, str) and "/" in maps_to:
                        left, right = maps_to.split("/", 1)
                        boundary = left.strip() or boundary
                        technique = right.strip() or technique
                    surface = _metadata_text(metadata, "malleus_surface", "source_surface", "attack_surface", "surface", default="dataset")
                    objective = getattr(item, "objective", "")
                    rows.append(
                        TaxonomyDatasetItem(
                            item_id=item.id,
                            item_type=item_type,
                            dataset_name=dataset.name,
                            severity=item.severity,
                            attack_surface=surface,
                            technique=technique,
                            boundary=boundary,
                            severity_rationale=_metadata_text(metadata, "severity_rationale", "risk_rationale", default=f"severity={item.severity}"),
                            scoring_signals=_signal_names(item),
                            patch_recommendations=_metadata_list(metadata, "patch_recommendations", "patch_recommendation", "remediation"),
                            false_positive_notes=_metadata_list(metadata, "false_positive_notes", "false_positive_note"),
                            reviewer_status=_metadata_text(metadata, "review_status", default="dataset_reviewed"),
                            scenario_maturity=_metadata_text(metadata, "scenario_maturity", default="benchmark_pack"),
                            source_path=source,
                            objective_sha256=sha256_text(objective),
                            objective_length=len(objective),
                            objective_preview=redacted_preview(objective, limit=120),
                        )
                    )
    return sorted(rows, key=lambda item: (item.dataset_name, item.item_id, item.item_type))


def _coverage_cell_id(surface: str, technique: str, boundary: str) -> str:
    return f"coverage:{surface}/{technique}/{boundary}"


def _snapshot_coverage_cells(report: CoverageReport) -> list[TaxonomyCoverageCell]:
    rows: list[TaxonomyCoverageCell] = []
    for cell in report.cells:
        reviewer = str(cell.metadata.get("review_status") or ("covered" if cell.status == "covered" else "needs_review"))
        maturity = str(cell.metadata.get("scenario_maturity") or ("coverage_evidence" if cell.status == "covered" else "coverage_gap"))
        rows.append(
            TaxonomyCoverageCell(
                cell_id=_coverage_cell_id(cell.source_surface, cell.technique, cell.expected_boundary),
                source_surface=cell.source_surface,
                technique=cell.technique,
                expected_boundary=cell.expected_boundary,
                status=cell.status,
                item_count=cell.item_count,
                finding_count=cell.finding_count,
                gate_count=cell.gate_count,
                evidence_refs=len(cell.evidence_refs),
                taxonomy_refs=sorted(set(cell.taxonomy_refs)),
                coverage_tags=sorted(set(cell.coverage_tags)),
                reviewer_status=reviewer,
                scenario_maturity=maturity,
            )
        )
    return sorted(rows, key=lambda item: item.cell_id)


def _load_json(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"JSON artifact must contain an object: {path}")
    return data


def _scenario_cells(paths: list[str | Path]) -> list[TaxonomyScenarioCell]:
    rows: list[TaxonomyScenarioCell] = []
    for path in paths:
        data = _load_json(path)
        status = str(data.get("review_status") or REVIEW_STATUS_DRAFT)
        scenario_id = str(data.get("scenario_id") or Path(path).stem)
        cells = data.get("cells") if isinstance(data.get("cells"), list) else []
        for index, cell in enumerate(cells):
            if not isinstance(cell, dict):
                continue
            dimension = str(cell.get("dimension") or "scenario_cell")
            value = str(cell.get("value") or f"cell-{index + 1}")
            rows.append(
                TaxonomyScenarioCell(
                    cell_id=f"scenario:{scenario_id}:{dimension}:{value}",
                    dimension=dimension,
                    value=value,
                    total_items=int(cell.get("total_items") or 0),
                    covered_items=int(cell.get("covered_items") or 0),
                    reviewer_status=status,
                    scenario_maturity=status,
                )
            )
    return sorted(rows, key=lambda item: item.cell_id)


def _count(values: list[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def build_taxonomy_snapshot(
    input_paths: list[str | Path],
    *,
    coverage_paths: list[str | Path] | None = None,
    scenario_coverage_paths: list[str | Path] | None = None,
) -> tuple[TaxonomyGardenSnapshot, dict[str, Any], CoverageReport]:
    if not input_paths:
        raise ValueError("at least one --input path is required")
    dataset_items = _dataset_items(input_paths)
    coverage_report = build_coverage_report(input_paths[0])
    coverage_cells = _snapshot_coverage_cells(coverage_report)
    for coverage_path in coverage_paths or []:
        coverage_cells.extend(_snapshot_coverage_cells(load_coverage_report(coverage_path)))
    coverage_cells = sorted({cell.cell_id: cell for cell in coverage_cells}.values(), key=lambda item: item.cell_id)
    scenario_cells = _scenario_cells(list(scenario_coverage_paths or []))

    attack_surfaces = sorted({item.attack_surface for item in dataset_items} | {cell.source_surface for cell in coverage_cells})
    techniques = sorted({item.technique for item in dataset_items} | {cell.technique for cell in coverage_cells})
    boundaries = sorted({item.boundary for item in dataset_items} | {cell.expected_boundary for cell in coverage_cells})
    severity_rationales = sorted({item.severity_rationale for item in dataset_items})
    scoring_signals = sorted({signal for item in dataset_items for signal in item.scoring_signals})
    patch_recommendations = sorted({value for item in dataset_items for value in item.patch_recommendations})
    false_positive_notes = sorted({value for item in dataset_items for value in item.false_positive_notes})
    reviewer_values = [item.reviewer_status for item in dataset_items] + [cell.reviewer_status for cell in coverage_cells] + [cell.reviewer_status for cell in scenario_cells]
    maturity_values = [item.scenario_maturity for item in dataset_items] + [cell.scenario_maturity for cell in coverage_cells] + [cell.scenario_maturity for cell in scenario_cells]

    snapshot = TaxonomyGardenSnapshot(
        generated_at=datetime.now(UTC).isoformat(),
        input_paths=[_safe_path(input_path) for input_path in input_paths],
        attack_surfaces=attack_surfaces,
        techniques=techniques,
        boundaries=boundaries,
        severity_rationales=severity_rationales,
        scoring_signals=scoring_signals,
        patch_recommendations=patch_recommendations,
        false_positive_notes=false_positive_notes,
        reviewer_status=_count(reviewer_values),
        scenario_maturity=_count(maturity_values),
        dataset_items=dataset_items,
        coverage_cells=coverage_cells,
        scenario_cells=scenario_cells,
        summary=TaxonomySnapshotSummary(
            dataset_items=len(dataset_items),
            coverage_cells=len(coverage_cells),
            scenario_cells=len(scenario_cells),
            attack_surfaces=len(attack_surfaces),
            techniques=len(techniques),
            boundaries=len(boundaries),
        ),
        metadata={"provider_calls_enabled": False, "raw_payloads_included": False, "benchmark_pack_mutation_enabled": False},
    )
    dataset_snapshot = {
        "schema_version": "malleus.taxonomy_garden.dataset_snapshot.v1",
        "generated_at": snapshot.generated_at,
        "input_paths": snapshot.input_paths,
        "items": [item.model_dump(mode="json") for item in dataset_items],
        "summary": {"items": len(dataset_items)},
    }
    return snapshot, dataset_snapshot, coverage_report


def _md(value: object) -> str:
    return str(value).replace("|", r"\|").replace("`", r"\`").replace("\n", " ")


def render_taxonomy_snapshot_markdown(snapshot: TaxonomyGardenSnapshot) -> str:
    lines = [
        "# Taxonomy garden snapshot",
        "",
        f"- Dataset items: {snapshot.summary.dataset_items}",
        f"- Coverage cells: {snapshot.summary.coverage_cells}",
        f"- Scenario cells: {snapshot.summary.scenario_cells}",
        f"- Reviewer status: {', '.join(f'{key}={value}' for key, value in snapshot.reviewer_status.items()) or 'none'}",
        f"- Scenario maturity: {', '.join(f'{key}={value}' for key, value in snapshot.scenario_maturity.items()) or 'none'}",
        "",
        "## Coverage cells",
        "",
        "| Cell | Status | Evidence | Reviewer | Maturity |",
        "|---|---|---:|---|---|",
    ]
    for cell in snapshot.coverage_cells:
        lines.append(f"| `{_md(cell.cell_id)}` | {_md(cell.status)} | {cell.evidence_refs} | {_md(cell.reviewer_status)} | {_md(cell.scenario_maturity)} |")
    lines.extend(["", "## Scenario draft cells", ""])
    if not snapshot.scenario_cells:
        lines.append("No scenario draft cells supplied.")
    for cell in snapshot.scenario_cells:
        lines.append(f"- `{_md(cell.cell_id)}` covered `{cell.covered_items}/{cell.total_items}` reviewer `{_md(cell.reviewer_status)}`")
    return "\n".join(lines).rstrip() + "\n"


def write_taxonomy_snapshot(
    input_paths: list[str | Path],
    out_dir: str | Path,
    *,
    coverage_paths: list[str | Path] | None = None,
    scenario_coverage_paths: list[str | Path] | None = None,
) -> tuple[TaxonomyGardenSnapshot, dict[str, Path]]:
    destination = Path(out_dir)
    destination.mkdir(parents=True, exist_ok=True)
    snapshot, dataset_snapshot, coverage_report = build_taxonomy_snapshot(input_paths, coverage_paths=coverage_paths, scenario_coverage_paths=scenario_coverage_paths)
    coverage_snapshot = {
        "schema_version": "malleus.taxonomy_garden.coverage_snapshot.v1",
        "generated_at": snapshot.generated_at,
        "summary": coverage_report.summary.model_dump(mode="json"),
        "cells": [cell.model_dump(mode="json") for cell in snapshot.coverage_cells],
    }
    paths = {
        "taxonomy_json": destination / "taxonomy-snapshot.json",
        "taxonomy_markdown": destination / "taxonomy-snapshot.md",
        "dataset_json": destination / "dataset-snapshot.json",
        "coverage_json": destination / "coverage-snapshot.json",
    }
    paths["taxonomy_json"].write_text(snapshot.model_dump_json(indent=2), encoding="utf-8")
    paths["taxonomy_markdown"].write_text(render_taxonomy_snapshot_markdown(snapshot), encoding="utf-8")
    paths["dataset_json"].write_text(json.dumps(dataset_snapshot, indent=2, sort_keys=True), encoding="utf-8")
    paths["coverage_json"].write_text(json.dumps(coverage_snapshot, indent=2, sort_keys=True), encoding="utf-8")
    return snapshot, paths


def _snapshot_cell_index(snapshot: TaxonomyGardenSnapshot) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for cell in snapshot.coverage_cells:
        rows[cell.cell_id] = cell.model_dump(mode="json")
    for cell in snapshot.scenario_cells:
        rows[cell.cell_id] = cell.model_dump(mode="json")
    return rows


def load_taxonomy_snapshot(path: str | Path) -> TaxonomyGardenSnapshot:
    return TaxonomyGardenSnapshot.model_validate_json(Path(path).read_text(encoding="utf-8"))


def diff_taxonomy_snapshots(old_path: str | Path, new_path: str | Path) -> TaxonomyDiffReport:
    old = load_taxonomy_snapshot(old_path)
    new = load_taxonomy_snapshot(new_path)
    old_cells = _snapshot_cell_index(old)
    new_cells = _snapshot_cell_index(new)
    added = [TaxonomyCellDelta(cell_id=cell_id, after=new_cells[cell_id]) for cell_id in sorted(set(new_cells) - set(old_cells))]
    removed = [TaxonomyCellDelta(cell_id=cell_id, before=old_cells[cell_id]) for cell_id in sorted(set(old_cells) - set(new_cells))]
    changed: list[TaxonomyCellDelta] = []
    for cell_id in sorted(set(old_cells) & set(new_cells)):
        before = old_cells[cell_id]
        after = new_cells[cell_id]
        fields = sorted(key for key in set(before) | set(after) if before.get(key) != after.get(key))
        if fields:
            changed.append(TaxonomyCellDelta(cell_id=cell_id, before=before, after=after, changed_fields=fields))
    return TaxonomyDiffReport(
        generated_at=datetime.now(UTC).isoformat(),
        old_snapshot=_safe_path(old_path),
        new_snapshot=_safe_path(new_path),
        added=added,
        removed=removed,
        changed=changed,
        summary=TaxonomyDiffSummary(added_cells=len(added), removed_cells=len(removed), changed_cells=len(changed)),
    )


def render_taxonomy_diff_markdown(report: TaxonomyDiffReport) -> str:
    lines = [
        "# Taxonomy garden diff",
        "",
        f"- Added cells: {report.summary.added_cells}",
        f"- Removed cells: {report.summary.removed_cells}",
        f"- Changed cells: {report.summary.changed_cells}",
    ]
    for title, rows in (("Added", report.added), ("Removed", report.removed), ("Changed", report.changed)):
        lines.extend(["", f"## {title}", ""])
        if not rows:
            lines.append("None.")
        for row in rows:
            suffix = f" fields={', '.join(row.changed_fields)}" if row.changed_fields else ""
            lines.append(f"- `{_md(row.cell_id)}`{suffix}")
    return "\n".join(lines).rstrip() + "\n"


def write_taxonomy_diff(old_path: str | Path, new_path: str | Path, out_dir: str | Path) -> tuple[TaxonomyDiffReport, Path, Path]:
    destination = Path(out_dir)
    destination.mkdir(parents=True, exist_ok=True)
    report = diff_taxonomy_snapshots(old_path, new_path)
    json_path = destination / "taxonomy-diff.json"
    markdown_path = destination / "taxonomy-diff.md"
    json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    markdown_path.write_text(render_taxonomy_diff_markdown(report), encoding="utf-8")
    return report, json_path, markdown_path
