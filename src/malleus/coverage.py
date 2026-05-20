from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from html import escape
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from malleus.agent_lab.loader import load_agent_scenarios
from malleus.campaign_runner import load_campaign
from malleus.datasets import load_input_datasets
from malleus.findings import FINDINGS_SCHEMA_VERSION, FindingsBundle, load_or_collect_findings
from malleus.mutations import mutation_names

COVERAGE_SCHEMA_VERSION = "malleus.coverage.v1"
CoverageStatus = Literal["covered", "missing", "partial"]

_SPACE_RE = re.compile(r"\s+")
_SECRET_RE = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b|\b(?:api[_-]?key|secret|token|password)\s*[:=]\s*[^\s`|<>]+", re.IGNORECASE)


class CoverageEvidenceRef(BaseModel):
    evidence_id: str
    source_type: str
    source_path: str
    item_id: str | None = None
    detail: str = ""


class CoverageCell(BaseModel):
    source_surface: str
    technique: str
    expected_boundary: str
    status: CoverageStatus = "missing"
    evidence_refs: list[CoverageEvidenceRef] = Field(default_factory=list)
    item_count: int = 0
    finding_count: int = 0
    gate_count: int = 0
    taxonomy_refs: list[str] = Field(default_factory=list)
    coverage_tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    missing_reason: str | None = None


class CoverageSummary(BaseModel):
    total_cells: int = 0
    covered_cells: int = 0
    partial_cells: int = 0
    missing_cells: int = 0
    evidence_refs: int = 0


class CoverageReport(BaseModel):
    schema_version: str = COVERAGE_SCHEMA_VERSION
    generated_at: str
    input_path: str
    cells: list[CoverageCell] = Field(default_factory=list)
    summary: CoverageSummary
    metadata: dict[str, Any] = Field(default_factory=dict)


def _safe_text(value: object) -> str:
    text = _SPACE_RE.sub(" ", str(value)).strip()
    return _SECRET_RE.sub("[REDACTED]", text)


def _md_safe(value: object) -> str:
    return _safe_text(value).replace("&", "&amp;").replace("<", "&lt;").replace("\r", " ").replace("\n", " ").replace("|", r"\|").replace("`", r"\`").replace("#", r"\#")


def _html_safe(value: object) -> str:
    return escape(_safe_text(value))


def _norm(value: object, fallback: str) -> str:
    text = _safe_text(value)
    return text if text else fallback


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists() or not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _load_required_json(path: str | Path, report_label: str) -> dict[str, Any]:
    candidate = Path(path)
    if not candidate.exists():
        raise ValueError(f"{report_label} not found: {candidate}")
    if not candidate.is_file():
        raise ValueError(f"{report_label} must be a JSON file, got directory: {candidate}")
    try:
        data = json.loads(candidate.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{report_label} is not valid JSON: {candidate}: {exc.msg}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{report_label} must contain a JSON object: {candidate}")
    return data


def _taxonomy_path() -> Path:
    return Path(__file__).resolve().parents[2] / "docs" / "taxonomy.md"


def _taxonomy_cells(path: Path | None = None) -> dict[tuple[str, str, str], CoverageCell]:
    taxonomy = path or _taxonomy_path()
    cells: dict[tuple[str, str, str], CoverageCell] = {}
    current: str | None = None
    for line in taxonomy.read_text(encoding="utf-8").splitlines():
        if line.startswith("## ") and "mutation styles" not in line:
            current = line.removeprefix("## ").strip()
            continue
        if current and line.startswith("- "):
            technique = line.removeprefix("- ").strip()
            key = ("dataset", technique, current)
            cells[key] = CoverageCell(
                source_surface="dataset",
                technique=technique,
                expected_boundary=current,
                taxonomy_refs=[current, technique],
                missing_reason="No evidence supplied for taxonomy baseline cell.",
            )
    for mutation in mutation_names():
        key = ("mutation", mutation, "mutation_robustness")
        cells[key] = CoverageCell(
            source_surface="mutation",
            technique=mutation,
            expected_boundary="mutation_robustness",
            taxonomy_refs=["mutation styles", mutation],
            missing_reason="No mutation report evidence supplied for mutation baseline cell.",
        )
    return cells


def _upsert_cell(
    cells: dict[tuple[str, str, str], CoverageCell],
    *,
    source_surface: str,
    technique: str,
    expected_boundary: str,
    evidence: CoverageEvidenceRef | None,
    taxonomy_refs: list[str] | None = None,
    coverage_tags: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
    finding: bool = False,
    gate: bool = False,
) -> None:
    surface = _norm(source_surface, "unknown_surface")
    tech = _norm(technique, "unknown_technique")
    boundary = _norm(expected_boundary, "unknown_boundary")
    key = (surface, tech, boundary)
    cell = cells.get(key)
    if cell is None:
        cell = CoverageCell(source_surface=surface, technique=tech, expected_boundary=boundary, taxonomy_refs=list(taxonomy_refs or []))
        cells[key] = cell
    for ref in taxonomy_refs or []:
        if ref and ref not in cell.taxonomy_refs:
            cell.taxonomy_refs.append(ref)
    for tag in coverage_tags or []:
        safe_tag = _norm(tag, "")
        if safe_tag and safe_tag not in cell.coverage_tags:
            cell.coverage_tags.append(safe_tag)
    if metadata:
        cell.metadata.update({str(key): value for key, value in metadata.items() if value is not None})
    if evidence is None:
        cell.status = "partial" if cell.status == "missing" else cell.status
        cell.missing_reason = cell.missing_reason or "Only partial metadata was available for this cell."
        return
    cell.evidence_refs.append(evidence)
    cell.item_count += 1
    if finding:
        cell.finding_count += 1
    if gate:
        cell.gate_count += 1
    cell.status = "covered"
    cell.missing_reason = None


def _mapped_boundary_and_technique(dataset_category: str, dataset_subcategory: str, metadata: dict[str, Any]) -> tuple[str, str]:
    if metadata.get("malleus_boundary") or metadata.get("malleus_technique"):
        return _norm(metadata.get("malleus_boundary") or dataset_category, dataset_category), _norm(metadata.get("malleus_technique") or dataset_subcategory, dataset_subcategory)
    maps_to = str(metadata.get("maps_to") or "")
    if "/" in maps_to:
        left, right = maps_to.split("/", 1)
        return _norm(left, dataset_category), _norm(right, dataset_subcategory)
    return _norm(metadata.get("expected_boundary") or metadata.get("violated_boundary") or dataset_category, dataset_category), _norm(metadata.get("technique") or metadata.get("tactic") or dataset_subcategory, dataset_subcategory)


def _metadata_scalar(metadata: dict[str, Any], key: str) -> str | None:
    value = metadata.get(key)
    return value if isinstance(value, str) and value.strip() else None


def _add_datasets(cells: dict[tuple[str, str, str], CoverageCell], input_path: str | Path) -> int:
    count = 0
    for dataset in load_input_datasets(input_path):
        dataset_ref = str(dataset.source_path or input_path)
        dataset_key = ("dataset", dataset.subcategory, dataset.category)
        cells.setdefault(
            dataset_key,
            CoverageCell(source_surface="dataset", technique=dataset.subcategory, expected_boundary=dataset.category, taxonomy_refs=[dataset.category, dataset.subcategory], missing_reason="Dataset has no item evidence."),
        )
        items = list(dataset.cases or []) + list(dataset.groups or [])
        for item in items:
            metadata = dict(item.metadata)
            boundary, technique = _mapped_boundary_and_technique(dataset.category, dataset.subcategory, metadata)
            surface = _norm(_metadata_scalar(metadata, "malleus_surface") or metadata.get("source_surface") or metadata.get("attack_surface") or metadata.get("surface") or "dataset", "dataset")
            _upsert_cell(
                cells,
                source_surface=surface,
                technique=technique,
                expected_boundary=boundary,
                evidence=CoverageEvidenceRef(evidence_id=f"dataset:{dataset.name}:{item.id}", source_type="dataset", source_path=dataset_ref, item_id=item.id, detail=f"severity={item.severity}"),
                taxonomy_refs=[boundary, technique],
            )
            if surface != "dataset":
                _upsert_cell(
                    cells,
                    source_surface="dataset",
                    technique=technique,
                    expected_boundary=boundary,
                    evidence=CoverageEvidenceRef(evidence_id=f"dataset-baseline:{dataset.name}:{item.id}", source_type="dataset", source_path=dataset_ref, item_id=item.id, detail=f"surface={surface}"),
                    taxonomy_refs=[boundary, technique],
                )
            count += 1
    return count


def _add_campaigns(cells: dict[tuple[str, str, str], CoverageCell], campaign_paths: list[str | Path] | None) -> int:
    count = 0
    for path in campaign_paths or []:
        campaign = load_campaign(path)
        for step in campaign.steps:
            metadata = dict(campaign.metadata) | dict(step.metadata)
            surface = _norm(_metadata_scalar(metadata, "malleus_surface") or step.surface, step.surface)
            technique = _norm(_metadata_scalar(metadata, "malleus_technique") or step.tactic, step.tactic)
            boundary = _norm(_metadata_scalar(metadata, "malleus_boundary") or "campaign_policy_boundary", "campaign_policy_boundary")
            _upsert_cell(
                cells,
                source_surface=surface,
                technique=technique,
                expected_boundary=boundary,
                evidence=CoverageEvidenceRef(evidence_id=f"campaign:{campaign.id}:{step.id}", source_type="campaign_spec", source_path=str(path), item_id=step.id, detail=f"order={step.order}"),
                taxonomy_refs=["campaign", surface, technique, boundary],
            )
            count += 1
    return count


def _add_agent_scenarios(cells: dict[tuple[str, str, str], CoverageCell], scenario_paths: list[str | Path] | None) -> int:
    count = 0
    for path in scenario_paths or []:
        pack = load_agent_scenarios(path)
        for scenario in pack.scenarios:
            metadata = dict(pack.metadata) | dict(scenario.metadata)
            surface = _norm(_metadata_scalar(metadata, "malleus_surface") or scenario.attack_surface, scenario.attack_surface)
            technique = _norm(_metadata_scalar(metadata, "malleus_technique") or "agent_policy", "agent_policy")
            boundary = _norm(_metadata_scalar(metadata, "malleus_boundary") or "agent_policy_boundary", "agent_policy_boundary")
            _upsert_cell(
                cells,
                source_surface=surface,
                technique=technique,
                expected_boundary=boundary,
                evidence=CoverageEvidenceRef(evidence_id=f"agent-scenario:{pack.name}:{scenario.id}", source_type="agent_scenario", source_path=str(path), item_id=scenario.id, detail=f"severity={scenario.severity}"),
                taxonomy_refs=["agent_lab", surface, technique, boundary],
            )
            count += 1
    return count


def _add_finding_bundle(cells: dict[tuple[str, str, str], CoverageCell], bundle: FindingsBundle, source: str) -> int:
    count = 0
    for finding in bundle.findings:
        _upsert_cell(
            cells,
            source_surface=finding.attack_surface,
            technique=finding.technique,
            expected_boundary=finding.violated_boundary,
            evidence=CoverageEvidenceRef(evidence_id=f"finding:{finding.finding_id}", source_type=f"finding:{finding.source_type}", source_path=source, item_id=finding.finding_id, detail=f"severity={finding.severity}"),
            taxonomy_refs=finding.taxonomy_refs,
            finding=True,
        )
        count += 1
    return count


def _add_report_artifacts(cells: dict[tuple[str, str, str], CoverageCell], report_paths: list[str | Path] | None) -> tuple[int, int]:
    finding_count = 0
    gate_count = 0
    for report in report_paths or []:
        path = Path(report)
        directory = path if path.is_dir() else path.parent
        findings_path = directory / "findings.json" if path.is_dir() else path
        findings_data = _load_json(findings_path)
        if findings_data and findings_data.get("schema_version") == FINDINGS_SCHEMA_VERSION:
            bundle = FindingsBundle.model_validate(findings_data)
        else:
            bundle = load_or_collect_findings(report)
        finding_count += _add_finding_bundle(cells, bundle, str(report))
        gate_data = _load_json(directory / "risk-summary.json")
        if gate_data is not None:
            status = str(gate_data.get("status") or "unknown")
            _upsert_cell(
                cells,
                source_surface="policy_gate",
                technique=status,
                expected_boundary="deployment_gate",
                evidence=CoverageEvidenceRef(evidence_id=f"gate:{directory.name}:{status}", source_type="gate", source_path=str(directory / "risk-summary.json"), detail=status),
                taxonomy_refs=["gate", "policy"],
                gate=True,
            )
            gate_count += 1
    return finding_count, gate_count


def _json_items(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _coverage_tags(*values: Any) -> list[str]:
    tags: set[str] = set()
    for value in values:
        if isinstance(value, list):
            tags.update(str(item) for item in value if str(item))
        elif value:
            tags.add(str(value))
    return sorted(tags)


def _evidence(path: str | Path, source_type: str, item_id: str, detail: str = "") -> CoverageEvidenceRef:
    return CoverageEvidenceRef(evidence_id=f"{source_type}:{item_id}", source_type=source_type, source_path=str(path), item_id=item_id, detail=detail)


def _add_mutation_reports(cells: dict[tuple[str, str, str], CoverageCell], report_paths: list[str | Path] | None) -> int:
    count = 0
    for path in report_paths or []:
        data = _load_required_json(path, "mutation report")
        mode = str(data.get("report_mode") or data.get("mode") or "unknown")
        for item in _json_items(data.get("planned_mutations")):
            name = _norm(item.get("name"), "mutation")
            family = _norm(item.get("family"), "mutation")
            surface = _norm(item.get("surface"), "mutation")
            boundary = _norm(item.get("boundary"), "mutation_robustness")
            _upsert_cell(cells, source_surface=surface, technique=name, expected_boundary=boundary, evidence=_evidence(path, "mutation_report", name, f"mode={mode} family={family}"), taxonomy_refs=["mutation", family, surface, boundary], coverage_tags=_coverage_tags(item.get("coverage_tags"), item.get("tags"), family, mode), metadata={"report_mode": mode, "family": family})
            count += 1
        for index, item in enumerate(_json_items(data.get("case_results"))):
            mutation = _norm(item.get("mutation"), f"mutation-{index + 1}")
            surface = _norm(item.get("surface"), "mutation")
            boundary = _norm(item.get("boundary"), "mutation_robustness")
            family = _norm(item.get("family"), "mutation")
            is_finding = bool(item.get("original_passed") and not item.get("mutated_passed")) or int(item.get("delta") or 0) < 0
            _upsert_cell(cells, source_surface=surface, technique=mutation, expected_boundary=boundary, evidence=_evidence(path, "mutation_case", f"{mutation}:{index}", f"delta={item.get('delta')} mode={mode}"), taxonomy_refs=["mutation", family, surface, boundary], coverage_tags=_coverage_tags(item.get("coverage_tags"), item.get("tags"), family, mode), metadata={"report_mode": mode, "family": family}, finding=is_finding)
            count += 1
    return count


def _add_hidden_reports(cells: dict[tuple[str, str, str], CoverageCell], report_paths: list[str | Path] | None) -> int:
    count = 0
    for path in report_paths or []:
        data = _load_required_json(path, "hidden-channel report")
        for index, item in enumerate(_json_items(data.get("findings"))):
            kind = _norm(item.get("kind"), f"hidden-{index + 1}")
            _upsert_cell(cells, source_surface="hidden_channel", technique=kind, expected_boundary="artifact_visibility", evidence=_evidence(path, "hidden_channel_report", kind, f"severity={item.get('severity', 'unknown')}"), taxonomy_refs=["hidden_channel", kind], coverage_tags=["hidden_channel", kind], finding=True)
            count += 1
    return count


def _add_artifact_reports(cells: dict[tuple[str, str, str], CoverageCell], report_paths: list[str | Path] | None) -> int:
    count = 0
    for path in report_paths or []:
        data = _load_required_json(path, "artifact report")
        for index, item in enumerate(_json_items(data.get("findings"))):
            kind = _norm(item.get("kind"), f"artifact-{index + 1}")
            _upsert_cell(cells, source_surface="artifact", technique=kind, expected_boundary="artifact_ingestion", evidence=_evidence(path, "artifact_report", kind, f"severity={item.get('severity', 'unknown')}"), taxonomy_refs=["artifact_firewall", kind], coverage_tags=["artifact", "artifact_firewall", kind], finding=True)
            count += 1
        for index, surface in enumerate(_json_items(data.get("surfaces"))):
            label = _norm(surface.get("kind") or surface.get("name") or surface.get("surface_name"), f"surface-{index + 1}")
            _upsert_cell(cells, source_surface="artifact", technique=label, expected_boundary="artifact_channel", evidence=_evidence(path, "artifact_surface", label), taxonomy_refs=["artifact_firewall", label], coverage_tags=["artifact", "artifact_channel", label])
            count += 1
    return count


def _add_rag_reports(cells: dict[tuple[str, str, str], CoverageCell], report_paths: list[str | Path] | None) -> int:
    count = 0
    for path in report_paths or []:
        data = _load_required_json(path, "RAG report")
        mode = str(data.get("mode") or "local_fixture")
        for index, result in enumerate(_json_items(data.get("results"))):
            detections = _json_items(result.get("detections"))
            tags = _coverage_tags(result.get("coverage_tags"), mode, "rag")
            if not detections:
                _upsert_cell(cells, source_surface="rag_context", technique="rag_query_pass", expected_boundary="rag_tenant_context_boundary", evidence=_evidence(path, "rag_report", str(result.get("query_id") or index), f"mode={mode}"), taxonomy_refs=["rag_security", "rag_query"], coverage_tags=tags, metadata={"mode": mode})
                count += 1
            for detection in detections:
                code = _norm(detection.get("code"), "rag_detection")
                _upsert_cell(cells, source_surface="rag_context", technique=code, expected_boundary="rag_tenant_context_boundary", evidence=_evidence(path, "rag_detection", f"{result.get('query_id') or index}:{code}", f"mode={mode} severity={detection.get('severity', 'unknown')}"), taxonomy_refs=["rag_security", code], coverage_tags=_coverage_tags(tags, code), metadata={"mode": mode}, finding=True)
                count += 1
    return count


def _add_campaign_reports(cells: dict[tuple[str, str, str], CoverageCell], report_paths: list[str | Path] | None) -> int:
    count = 0
    for path in report_paths or []:
        data = _load_required_json(path, "campaign report")
        mode = str(data.get("mode") or "simulated")
        for index, step in enumerate(_json_items(data.get("steps"))):
            step_id = str(step.get("step_id") or f"step-{index + 1}")
            surface = _norm(step.get("surface"), "campaign")
            technique = _norm(step.get("tactic"), "campaign_step")
            gate = step.get("gate") if isinstance(step.get("gate"), dict) else {}
            failed = gate.get("status") == "fail" or step.get("policy_action") in {"block", "quarantine"} or step.get("hidden_channel_recommendation") in {"block", "quarantine"}
            _upsert_cell(cells, source_surface=surface, technique=technique, expected_boundary="campaign_policy_boundary", evidence=_evidence(path, "campaign_report", step_id, f"mode={mode} gate={gate.get('status', 'unknown')}"), taxonomy_refs=["campaign", surface, technique], coverage_tags=_coverage_tags(step.get("coverage_tags"), mode), metadata={"mode": mode}, finding=failed)
            count += 1
    return count


def _add_visual_reports(cells: dict[tuple[str, str, str], CoverageCell], report_paths: list[str | Path] | None) -> int:
    count = 0
    for path in report_paths or []:
        data = _load_required_json(path, "visual report")
        mode = str(data.get("mode") or "local_fixture")
        for index, result in enumerate(_json_items(data.get("results"))):
            scenario = _norm(result.get("scenario_id"), f"visual-{index + 1}")
            family = _norm(result.get("family"), "visual_lab")
            gate = _norm(result.get("gate_recommendation"), "unknown")
            finding_count = len(_json_items(result.get("visual_lab_findings"))) + len(_json_items(result.get("artifact_firewall_findings")))
            _upsert_cell(cells, source_surface=family, technique=scenario, expected_boundary="untrusted_visual_artifact_boundary", evidence=_evidence(path, "visual_report", scenario, f"mode={mode} gate={gate}"), taxonomy_refs=["visual_lab", family, scenario], coverage_tags=_coverage_tags(result.get("coverage_tags"), mode, gate), metadata={"mode": mode, "gate": gate}, finding=finding_count > 0)
            count += 1
        for index, surface in enumerate(_json_items(data.get("untrusted_surfaces"))):
            label = _norm(surface.get("surface_type") or surface.get("surface_id"), f"visual-surface-{index + 1}")
            _upsert_cell(cells, source_surface="visual", technique=label, expected_boundary="untrusted_visual_surface", evidence=_evidence(path, "visual_surface", label, f"mode={mode}"), taxonomy_refs=["visual_lab", label], coverage_tags=_coverage_tags(label, mode, surface.get("extraction_mode")), metadata={"mode": mode})
            count += 1
    return count


def _add_safety_reports(cells: dict[tuple[str, str, str], CoverageCell], report_paths: list[str | Path] | None) -> int:
    count = 0
    for path in report_paths or []:
        data = _load_required_json(path, "safety report")
        mode = str(data.get("mode") or "dry_run")
        for item in _json_items(data.get("unsafe_regions")):
            config = _norm(item.get("config_id"), "unsafe_region")
            _upsert_cell(cells, source_surface="safety_tuner", technique=config, expected_boundary="unsafe_decoding_region", evidence=_evidence(path, "safety_unsafe_region", config, f"mode={mode} risk={item.get('risk_score', 'unknown')}"), taxonomy_refs=["safety_tuner", "unsafe_region"], coverage_tags=_coverage_tags(item.get("reasons"), mode, data.get("strategy")), metadata={"mode": mode, "strategy": data.get("strategy")}, finding=True)
            count += 1
        for item in _json_items(data.get("configurations")):
            config = _norm(item.get("config_id"), "configuration")
            _upsert_cell(cells, source_surface="decoding_parameters", technique=config, expected_boundary="safety_risk_surface", evidence=_evidence(path, "safety_configuration", config, f"mode={mode} rank={item.get('rank', 'unknown')}"), taxonomy_refs=["safety_tuner", "risk_surface"], coverage_tags=_coverage_tags(mode, data.get("strategy")), metadata={"mode": mode, "strategy": data.get("strategy")})
            count += 1
    return count


def _add_anomaly_reports(cells: dict[tuple[str, str, str], CoverageCell], report_paths: list[str | Path] | None) -> int:
    count = 0
    for path in report_paths or []:
        data = _load_required_json(path, "anomaly report")
        summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
        labels = summary.get("labels") if isinstance(summary.get("labels"), list) else []
        for label in labels or [data.get("gate_recommendation") or "none"]:
            technique = _norm(label, "anomalous_output")
            high_risk = data.get("gate_recommendation") in {"quarantine", "block"}
            _upsert_cell(cells, source_surface="output_integrity", technique=technique, expected_boundary="transcript_boundary", evidence=_evidence(path, "anomaly_report", technique, f"gate={data.get('gate_recommendation', 'none')}"), taxonomy_refs=["anomaly", technique], coverage_tags=_coverage_tags("anomaly", labels, data.get("gate_recommendation")), metadata={"gate_recommendation": data.get("gate_recommendation")}, finding=bool(high_risk))
            count += 1
    return count


def _finalize(cells: dict[tuple[str, str, str], CoverageCell]) -> list[CoverageCell]:
    finalized: list[CoverageCell] = []
    for cell in cells.values():
        if cell.status == "missing" and not cell.missing_reason:
            cell.missing_reason = "No evidence refs were supplied for this source surface, technique, and boundary."
        if cell.status == "covered" and not cell.evidence_refs:
            cell.status = "partial"
            cell.missing_reason = "Coverage was inferred from incomplete metadata and has no evidence refs."
        finalized.append(cell)
    return sorted(finalized, key=lambda item: (item.expected_boundary, item.technique, item.source_surface))


def build_coverage_report(
    input_path: str | Path,
    *,
    report_paths: list[str | Path] | None = None,
    campaign_paths: list[str | Path] | None = None,
    agent_scenario_paths: list[str | Path] | None = None,
    mutation_reports: list[str | Path] | None = None,
    hidden_reports: list[str | Path] | None = None,
    artifact_reports: list[str | Path] | None = None,
    rag_reports: list[str | Path] | None = None,
    campaign_reports: list[str | Path] | None = None,
    visual_reports: list[str | Path] | None = None,
    safety_reports: list[str | Path] | None = None,
    anomaly_reports: list[str | Path] | None = None,
) -> CoverageReport:
    cells = _taxonomy_cells()
    dataset_items = _add_datasets(cells, input_path)
    campaign_items = _add_campaigns(cells, campaign_paths)
    agent_items = _add_agent_scenarios(cells, agent_scenario_paths)
    finding_items, gate_items = _add_report_artifacts(cells, report_paths)
    mutation_items = _add_mutation_reports(cells, mutation_reports)
    hidden_items = _add_hidden_reports(cells, hidden_reports)
    artifact_items = _add_artifact_reports(cells, artifact_reports)
    rag_items = _add_rag_reports(cells, rag_reports)
    campaign_report_items = _add_campaign_reports(cells, campaign_reports)
    visual_items = _add_visual_reports(cells, visual_reports)
    safety_items = _add_safety_reports(cells, safety_reports)
    anomaly_items = _add_anomaly_reports(cells, anomaly_reports)
    finalized = _finalize(cells)
    summary = CoverageSummary(
        total_cells=len(finalized),
        covered_cells=sum(1 for cell in finalized if cell.status == "covered"),
        partial_cells=sum(1 for cell in finalized if cell.status == "partial"),
        missing_cells=sum(1 for cell in finalized if cell.status == "missing"),
        evidence_refs=sum(len(cell.evidence_refs) for cell in finalized),
    )
    return CoverageReport(
        generated_at=datetime.now(UTC).isoformat(),
        input_path=str(input_path),
        cells=finalized,
        summary=summary,
        metadata={
            "dataset_items": dataset_items,
            "campaign_items": campaign_items,
            "agent_scenario_items": agent_items,
            "finding_items": finding_items,
            "gate_items": gate_items,
            "mutation_report_items": mutation_items,
            "hidden_report_items": hidden_items,
            "artifact_report_items": artifact_items,
            "rag_report_items": rag_items,
            "campaign_report_items": campaign_report_items,
            "visual_report_items": visual_items,
            "safety_report_items": safety_items,
            "anomaly_report_items": anomaly_items,
            "status_semantics": "missing and partial cells are explicit gaps and are not counted as covered",
        },
    )


def render_coverage_markdown(report: CoverageReport) -> str:
    lines = [
        "# Malleus Attack-Surface Coverage",
        "",
        f"- Input: {_md_safe(report.input_path)}",
        f"- Covered cells: {report.summary.covered_cells}/{report.summary.total_cells}",
        f"- Partial cells: {report.summary.partial_cells}",
        f"- Missing cells: {report.summary.missing_cells}",
        "",
        "| Source surface | Technique | Expected boundary | Status | Evidence | Findings | Gates |",
        "|---|---|---|---|---:|---:|---:|",
    ]
    for cell in report.cells:
        lines.append(
            f"| {_md_safe(cell.source_surface)} | {_md_safe(cell.technique)} | {_md_safe(cell.expected_boundary)} | {_md_safe(cell.status)} | {len(cell.evidence_refs)} | {cell.finding_count} | {cell.gate_count} |"
        )
    missing = [cell for cell in report.cells if cell.status != "covered"]
    lines.extend(["", "## Explicit gaps", ""])
    if not missing:
        lines.append("No missing or partial cells.")
    for cell in missing:
        lines.append(f"- **{_md_safe(cell.status)}** `{_md_safe(cell.source_surface)} / {_md_safe(cell.technique)} / {_md_safe(cell.expected_boundary)}`: {_md_safe(cell.missing_reason or 'no covered evidence')}")
    return "\n".join(lines).rstrip() + "\n"


def render_coverage_html(report: CoverageReport) -> str:
    rows = []
    for cell in report.cells:
        rows.append(
            "<tr>"
            f"<td>{_html_safe(cell.source_surface)}</td>"
            f"<td>{_html_safe(cell.technique)}</td>"
            f"<td>{_html_safe(cell.expected_boundary)}</td>"
            f"<td class='{_html_safe(cell.status)}'>{_html_safe(cell.status)}</td>"
            f"<td>{len(cell.evidence_refs)}</td>"
            f"<td>{cell.finding_count}</td>"
            f"<td>{cell.gate_count}</td>"
            f"<td>{_html_safe(cell.missing_reason or '')}</td>"
            "</tr>"
        )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Malleus coverage</title><style>body{{font-family:system-ui,sans-serif;margin:32px;background:#0b0c0f;color:#f5f5f5}}table{{border-collapse:collapse;width:100%;font-size:13px}}th,td{{border:1px solid #333;padding:8px;text-align:left;vertical-align:top}}th{{background:#181a20}}.covered{{color:#41d17d}}.partial{{color:#f5b84b}}.missing{{color:#ff6b6b}}.cards{{display:flex;gap:12px;flex-wrap:wrap}}.card{{border:1px solid #333;border-radius:12px;padding:12px;background:#15171c}}</style></head>
<body><h1>Malleus Attack-Surface Coverage</h1><div class="cards"><div class="card">Covered: {report.summary.covered_cells}/{report.summary.total_cells}</div><div class="card">Partial: {report.summary.partial_cells}</div><div class="card">Missing: {report.summary.missing_cells}</div><div class="card">Evidence refs: {report.summary.evidence_refs}</div></div>
<table><thead><tr><th>Source surface</th><th>Technique</th><th>Expected boundary</th><th>Status</th><th>Evidence</th><th>Findings</th><th>Gates</th><th>Gap reason</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
<footer>Generated from local metadata only; missing and partial cells are not treated as passed.</footer></body></html>"""


def write_coverage_report(report: CoverageReport, output_dir: str | Path) -> tuple[Path, Path, Path]:
    destination = Path(output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    json_path = destination / "coverage.json"
    markdown_path = destination / "coverage.md"
    html_path = destination / "coverage.html"
    json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    markdown_path.write_text(render_coverage_markdown(report), encoding="utf-8")
    html_path.write_text(render_coverage_html(report), encoding="utf-8")
    return json_path, markdown_path, html_path


def load_coverage_report(path: str | Path) -> CoverageReport:
    return CoverageReport.model_validate_json(Path(path).read_text(encoding="utf-8"))
