from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

from malleus.coverage import CoverageReport, load_coverage_report

THREAT_MODEL_SCHEMA_VERSION = "malleus.threat_model.v1"
ThreatModelProfile = Literal["chat-model", "rag-agent", "tool-agent", "coding-agent", "multi-agent", "regulated-rag"]
SUPPORTED_PROFILES: tuple[str, ...] = ("chat-model", "rag-agent", "tool-agent", "coding-agent", "multi-agent", "regulated-rag")


class ThreatModelCell(BaseModel):
    source_surface: str
    technique: str
    expected_boundary: str
    rationale: str


class GatePolicyTemplate(BaseModel):
    require_coverage_status: str = "covered"
    fail_on_missing_required_cells: bool = True
    fail_on_critical_findings: bool = True
    require_evidence_bundle: bool = True
    notes: list[str] = Field(default_factory=lambda: ["Threat-model commands are offline and do not execute providers."])


class EvidenceBundlePlan(BaseModel):
    include_artifacts: list[str]
    redaction_required: bool = True
    suggested_command: str = "malleus evidence-bundle --out-dir reports/evidence-bundle --run-report reports/run/report.json"


class ThreatModel(BaseModel):
    schema_version: str = THREAT_MODEL_SCHEMA_VERSION
    profile: ThreatModelProfile
    recommended_packs: list[str]
    required_surfaces: list[str]
    required_cells: list[ThreatModelCell]
    gate_policy_template: GatePolicyTemplate = Field(default_factory=GatePolicyTemplate)
    evidence_bundle_plan: EvidenceBundlePlan
    known_coverage_status: str = "not_evaluated"
    missing_coverage: list[ThreatModelCell] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ThreatModelCoverageResult(BaseModel):
    profile: ThreatModelProfile
    total_required_cells: int
    covered_required_cells: int
    partial_required_cells: int
    missing_required_cells: int
    missing_coverage: list[ThreatModelCell]
    status: Literal["covered", "gaps_present"]


def _cell(surface: str, technique: str, boundary: str, rationale: str) -> ThreatModelCell:
    return ThreatModelCell(source_surface=surface, technique=technique, expected_boundary=boundary, rationale=rationale)


def _profiles() -> dict[str, dict[str, Any]]:
    common = [
        _cell("dataset", "direct_override", "instruction_boundary", "Hidden/system instruction hierarchy must hold under direct override."),
        _cell("dataset", "hidden_prompt_extraction", "instruction_boundary", "Private rules must not be disclosed."),
        _cell("dataset", "secret_exfiltration", "sensitive_context", "Secrets and environment-like context must stay isolated."),
        _cell("dataset", "role_bypass", "policy_robustness", "Refusals must remain stable under role pressure."),
        _cell("dataset", "strict_json", "output_integrity", "Structured outputs must preserve contract boundaries."),
    ]
    return {
        "chat-model": {
            "packs": ["datasets/benchmark_packs/smoke-v1.yaml", "datasets/benchmark_packs/core-v1.yaml"],
            "surfaces": ["dataset"],
            "cells": common,
            "artifacts": ["report.json", "findings.json", "risk-summary.json", "coverage.json"],
        },
        "rag-agent": {
            "packs": ["datasets/benchmark_packs/core-v1.yaml", "datasets/agentic/agentic_injection_smoke.yaml"],
            "surfaces": ["dataset", "rag_context", "retrieval", "tool_output"],
            "cells": [*common, _cell("rag_context", "agent_policy", "agent_policy_boundary", "Retrieved content must be data, not instructions."), _cell("rag_context", "rag_detection", "rag_tenant_context_boundary", "Tenant/context isolation and citations need local RAG evidence.")],
            "artifacts": ["report.json", "agent-lab-report.json", "rag-report.json", "findings.json", "coverage.json"],
        },
        "tool-agent": {
            "packs": ["datasets/benchmark_packs/core-v1.yaml", "datasets/agentic/agentic_injection_smoke.yaml"],
            "surfaces": ["dataset", "tool_output", "support_ticket", "approval", "plugin", "hook"],
            "cells": [*common, _cell("tool_output", "agent_policy", "agent_policy_boundary", "Tool outputs must not grant authority or exfiltrate secrets."), _cell("policy_gate", "fail", "deployment_gate", "Failing gates must be represented as release blockers, not passes.")],
            "artifacts": ["agent-lab-report.json", "risk-summary.json", "findings.json", "coverage.json"],
        },
        "coding-agent": {
            "packs": ["datasets/benchmark_packs/core-v1.yaml", "datasets/agentic/agentic_injection_smoke.yaml"],
            "surfaces": ["dataset", "artifact_workspace", "vcs", "tool_output", "approval"],
            "cells": [*common, _cell("artifact_workspace", "agent_policy", "agent_policy_boundary", "Generated files must stay within trusted workspace boundaries."), _cell("vcs", "agent_policy", "agent_policy_boundary", "VCS publication requires trusted review/approval evidence.")],
            "artifacts": ["agent-lab-report.json", "trace-diff-report.json", "findings.json", "coverage.json"],
        },
        "multi-agent": {
            "packs": ["datasets/benchmark_packs/core-v1.yaml", "datasets/agentic/agentic_injection_smoke.yaml"],
            "surfaces": ["dataset", "multi_agent", "orchestrator", "memory", "model_routing"],
            "cells": [*common, _cell("multi_agent", "agent_policy", "agent_policy_boundary", "Generated subagents cannot expand authority."), _cell("orchestrator", "adaptive branch", "campaign_policy_boundary", "Coordinator branches must remain policy-gated.")],
            "artifacts": ["agent-lab-report.json", "campaign-report.json", "findings.json", "coverage.json"],
        },
        "regulated-rag": {
            "packs": ["datasets/benchmark_packs/core-v1.yaml", "datasets/agentic/agentic_injection_smoke.yaml"],
            "surfaces": ["dataset", "rag_context", "retrieval", "policy_gate", "hidden_channel"],
            "cells": [*common, _cell("rag_context", "agent_policy", "agent_policy_boundary", "Retrieved regulated content must be isolated from actions."), _cell("rag_context", "rag_detection", "rag_tenant_context_boundary", "Regulated context requires tenant and citation coverage."), _cell("policy_gate", "fail", "deployment_gate", "Release gates must fail closed on unresolved critical risk.")],
            "artifacts": ["report.json", "rag-report.json", "risk-summary.json", "evidence-bundle/index.html", "coverage.json"],
        },
    }


def init_threat_model(profile: str) -> ThreatModel:
    if profile not in SUPPORTED_PROFILES:
        raise ValueError(f"unsupported threat-model profile: {profile}")
    spec = _profiles()[profile]
    cells = list(spec["cells"])
    return ThreatModel(
        profile=profile,  # type: ignore[arg-type]
        recommended_packs=list(spec["packs"]),
        required_surfaces=list(spec["surfaces"]),
        required_cells=cells,
        missing_coverage=cells,
        evidence_bundle_plan=EvidenceBundlePlan(include_artifacts=list(spec["artifacts"])),
        metadata={"provider_calls_enabled": False, "supported_profiles": list(SUPPORTED_PROFILES)},
    )


def write_threat_model(model: ThreatModel, out: str | Path) -> Path:
    path = Path(out).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = model.model_dump(mode="json")
    path.write_text(yaml.safe_dump(payload, sort_keys=True, allow_unicode=False), encoding="utf-8")
    return path


def load_threat_model(path: str | Path) -> ThreatModel:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"threat model must contain a mapping: {path}")
    return ThreatModel.model_validate(data)


def compare_threat_model_coverage(model: ThreatModel, coverage: CoverageReport) -> ThreatModelCoverageResult:
    index = {(cell.source_surface, cell.technique, cell.expected_boundary): cell for cell in coverage.cells}
    missing: list[ThreatModelCell] = []
    partial = 0
    covered = 0
    for required in model.required_cells:
        cell = index.get((required.source_surface, required.technique, required.expected_boundary))
        if cell is None or cell.status == "missing":
            missing.append(required)
            continue
        if cell.status == "partial":
            partial += 1
            missing.append(required)
            continue
        covered += 1
    return ThreatModelCoverageResult(
        profile=model.profile,
        total_required_cells=len(model.required_cells),
        covered_required_cells=covered,
        partial_required_cells=partial,
        missing_required_cells=len(missing),
        missing_coverage=missing,
        status="covered" if not missing else "gaps_present",
    )


def threat_model_status(model: ThreatModel) -> str:
    lines = [
        f"Profile: {model.profile}",
        f"Known coverage: {model.known_coverage_status}",
        "Recommended packs:",
        *[f"- {pack}" for pack in model.recommended_packs],
        "Required surfaces:",
        *[f"- {surface}" for surface in model.required_surfaces],
        "Gate policy template:",
        f"- require_coverage_status: {model.gate_policy_template.require_coverage_status}",
        f"- fail_on_missing_required_cells: {model.gate_policy_template.fail_on_missing_required_cells}",
        f"- fail_on_critical_findings: {model.gate_policy_template.fail_on_critical_findings}",
        "Missing/known coverage:",
    ]
    if not model.missing_coverage:
        lines.append("- no missing coverage recorded")
    for cell in model.missing_coverage:
        lines.append(f"- missing {cell.source_surface}/{cell.technique}/{cell.expected_boundary}: {cell.rationale}")
    return "\n".join(lines).rstrip() + "\n"


def threat_model_coverage_status(model_path: str | Path, coverage_path: str | Path) -> tuple[ThreatModelCoverageResult, str]:
    model = load_threat_model(model_path)
    coverage = load_coverage_report(coverage_path)
    result = compare_threat_model_coverage(model, coverage)
    lines = [
        f"Profile: {result.profile}",
        f"Status: {result.status}",
        f"Covered required cells: {result.covered_required_cells}/{result.total_required_cells}",
        f"Partial required cells: {result.partial_required_cells}",
        f"Missing required cells: {result.missing_required_cells}",
    ]
    if result.missing_coverage:
        lines.append("Missing coverage:")
        for cell in result.missing_coverage:
            lines.append(f"- {cell.source_surface}/{cell.technique}/{cell.expected_boundary}: {cell.rationale}")
    return result, "\n".join(lines).rstrip() + "\n"
