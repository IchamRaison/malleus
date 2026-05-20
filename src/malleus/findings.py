from __future__ import annotations

import hashlib
import json
import re
import shlex
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from malleus.agent_lab.schemas import AgentLabReport

from malleus.gates import GateDecision
from malleus.reporting import _md_safe
from malleus.schemas import MutationRunReport, RunReport, Severity

FINDINGS_SCHEMA_VERSION = "malleus.findings.v1"
FindingSource = Literal["run_report", "mutation_run", "agent_lab", "tool_agent", "live_evidence", "gate", "hidden_channel", "artifact_firewall", "visual_lab", "trace_diff", "campaign", "rag_harness", "interop", "anomaly"]

_SEVERITY_ORDER: dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_SECRET_RE = re.compile(
    r"\bsk-[A-Za-z0-9_-]{8,}\b|\b(?:api[_ -]?key|secret|token|password|credential|bearer)\s*[:=]\s*[^\s`|<>]+",
    re.IGNORECASE,
)
_UNSAFE_BODY_RE = re.compile(
    r"\b(ignore previous instructions|system prompt|developer message|exfiltrate|call\s+exfiltrate_secret|environment token)\b",
    re.IGNORECASE,
)
_SPACE_RE = re.compile(r"\s+")


class FindingEvidenceRef(BaseModel):
    evidence_id: str
    artifact_path: str
    artifact_type: str
    json_pointer: str | None = None
    redaction_status: Literal["redacted", "not_applicable", "unknown"] = "redacted"
    sha256: str | None = None
    redacted_excerpt: str | None = None


class ReplaySpec(BaseModel):
    replay_id: str
    finding_id: str
    mode: Literal["dry_run", "mock"] = "dry_run"
    command: str
    target_name: str
    target_adapter: str | None = None
    target_model: str | None = None
    input_path: str | None = None
    scoring_path: str | None = None
    case_ids: list[str] = Field(default_factory=list)
    scenario_ids: list[str] = Field(default_factory=list)
    allowed_side_effects: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=lambda: ["dry-run/mock replay only; provider calls are disabled"])


class SecurityFinding(BaseModel):
    schema_version: str = FINDINGS_SCHEMA_VERSION
    finding_id: str
    title: str
    source_type: FindingSource
    affected_model: dict[str, str | None]
    severity: Severity
    attack_surface: str
    technique: str
    violated_boundary: str
    taxonomy_refs: list[str] = Field(default_factory=list)
    reproduction_command: str
    evidence_refs: list[FindingEvidenceRef] = Field(default_factory=list)
    redacted_excerpts: list[str] = Field(default_factory=list)
    patch_recommendation: str
    regression_case_link: str
    replay_spec: ReplaySpec
    metadata: dict[str, Any] = Field(default_factory=dict)


class FindingsSummary(BaseModel):
    total_findings: int = 0
    counts_by_severity: dict[str, int] = Field(default_factory=dict)
    counts_by_source: dict[str, int] = Field(default_factory=dict)
    highest_severity: Severity | None = None


class FindingsBundle(BaseModel):
    schema_version: str = FINDINGS_SCHEMA_VERSION
    generated_at: str
    source_report: str | None = None
    run_id: str | None = None
    findings: list[SecurityFinding] = Field(default_factory=list)
    summary: FindingsSummary
    optional_artifacts: dict[str, str] = Field(default_factory=dict)
    interop: dict[str, Any] = Field(default_factory=dict)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _sha256_file(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalize(value: object) -> str:
    return _SPACE_RE.sub(" ", str(value).strip().lower())


def _stable_id(*parts: object) -> str:
    normalized = "|".join(_normalize(part) for part in parts if part is not None)
    return "mf-" + _sha256_text(normalized)[:16]


def _safe_excerpt(value: object, *, limit: int = 220) -> str:
    text = _SPACE_RE.sub(" ", str(value)).strip()
    if not text:
        return "n/a"
    if _SECRET_RE.search(text) or _UNSAFE_BODY_RE.search(text):
        return f"[REDACTED sha256={_sha256_text(text)[:16]} length={len(text)}]"
    text = _SECRET_RE.sub("[REDACTED]", text)
    return text[:limit] + ("…" if len(text) > limit else "")


def _body_ref(label: str, value: str) -> str:
    return f"{label} sha256={_sha256_text(value)[:16]} length={len(value)}"


def _target(report: Any) -> dict[str, str | None]:
    return {
        "name": report.target_name,
        "adapter": report.target_adapter,
        "model": report.target_model,
        "config": report.target_name,
    }


def _severity_from_status(status: str) -> Severity:
    return "critical" if status == "error" else "high"


def _summary(findings: list[SecurityFinding]) -> FindingsSummary:
    severity_counts: dict[str, int] = {}
    source_counts: dict[str, int] = {}
    highest: Severity | None = None
    for finding in findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        source_counts[finding.source_type] = source_counts.get(finding.source_type, 0) + 1
        if highest is None or _SEVERITY_ORDER[finding.severity] > _SEVERITY_ORDER[highest]:
            highest = finding.severity
    return FindingsSummary(
        total_findings=len(findings),
        counts_by_severity=dict(sorted(severity_counts.items())),
        counts_by_source=dict(sorted(source_counts.items())),
        highest_severity=highest,
    )


def _case_command(report: RunReport, case_id: str) -> str:
    qualified = case_id if ":" in case_id else case_id
    return (
        "malleus run "
        f"--target {report.target_name} --input {report.input_path} --scoring {report.scoring_path} "
        f"--case-id {qualified} --dry-run"
    )


def _agent_command(report: AgentLabReport, scenario_id: str) -> str:
    return f"malleus agent-lab --target {report.target_name} --scenarios {report.scenarios_path} --scenario-id {scenario_id} --dry-run"


def _tool_agent_replay_command(finding_id: str, report_path: str | Path) -> str:
    return f"malleus replay {_command_arg(finding_id)} --report {_command_arg(Path(report_path).name)} --dry-run"


def _command_arg(value: object) -> str:
    return shlex.quote(str(value))


def _mutation_command(report: MutationRunReport, case_key: str, mutation: str) -> str:
    target_ref = report.metadata.get("target_path") or report.metadata.get("target_config_path") or report.target_name
    return (
        "malleus mutate-run "
        f"--target {_command_arg(target_ref)} --input {_command_arg(report.input_path)} --scoring {_command_arg(report.scoring_path)} "
        f"--case-id {_command_arg(case_key)} --mutation {_command_arg(mutation)} --dry-run"
    )


def findings_from_run_report(report: RunReport, *, report_path: str | Path = "report.json") -> list[SecurityFinding]:
    artifact = Path(report_path)
    artifact_name = artifact.name
    artifact_hash = _sha256_file(artifact)
    findings: list[SecurityFinding] = []
    for dataset_index, dataset in enumerate(report.datasets):
        taxonomy = [dataset.category, dataset.subcategory]
        for case_index, case in enumerate(dataset.case_results):
            anomaly = case.metadata.get("anomaly") if isinstance(case.metadata.get("anomaly"), dict) else None
            anomaly_high_risk = bool(anomaly and anomaly.get("highest_severity") in {"quarantine", "block"})
            if case.passed and case.penalty <= 0 and not anomaly_high_risk:
                continue
            failed_checks = [check for check in [*case.failure_checks, *case.pass_checks] if not check.passed]
            technique = ",".join(sorted({check.type for check in failed_checks})) or "scoring_failure"
            attack_surface = str(case.metadata.get("attack_surface") or dataset.subcategory or dataset.category)
            boundary = str(case.metadata.get("violated_boundary") or dataset.category or "model_behavior")
            case_key = f"{dataset.dataset_name}:{case.case_id}"
            finding_id = _stable_id(report.target_model, report.target_adapter, case_key, case.severity, attack_surface, technique, boundary)
            command = _case_command(report, case_key)
            evidence = [
                FindingEvidenceRef(
                    evidence_id=f"{finding_id}-case-result",
                    artifact_path=artifact_name,
                    artifact_type="run_report_json",
                    json_pointer=f"/datasets/{dataset_index}/case_results/{case_index}",
                    sha256=artifact_hash,
                    redacted_excerpt="; ".join(_safe_excerpt(check.detail) for check in failed_checks[:3]) or _body_ref("response", case.response_text),
                )
            ]
            excerpts = [_body_ref("prompt", case.prompt), _body_ref("response", case.response_text)]
            excerpts.extend(_safe_excerpt(check.detail) for check in failed_checks[:3])
            metadata: dict[str, Any] = {
                "dataset_name": dataset.dataset_name,
                "case_id": case.case_id,
                "score": case.score,
                "penalty": case.penalty,
                "campaign": {
                    key: case.metadata[key]
                    for key in ("step_id", "order", "tactic", "replay_seed")
                    if key in case.metadata
                },
                "rag_harness": {"status": "not_supplied"},
            }
            findings.append(
                SecurityFinding(
                    finding_id=finding_id,
                    title=f"{case.severity.title()} eval failure: {case_key}",
                    source_type="run_report",
                    affected_model=_target(report),
                    severity=case.severity,
                    attack_surface=attack_surface,
                    technique=technique,
                    violated_boundary=boundary,
                    taxonomy_refs=taxonomy,
                    reproduction_command=command,
                    evidence_refs=evidence,
                    redacted_excerpts=excerpts,
                    patch_recommendation="Add or update a regression case for this boundary and harden refusal/policy behavior before release.",
                    regression_case_link=case_key,
                    replay_spec=ReplaySpec(
                        replay_id=f"replay-{finding_id}",
                        finding_id=finding_id,
                        command=command,
                        target_name=report.target_name,
                        target_adapter=report.target_adapter,
                        target_model=report.target_model,
                        input_path=report.input_path,
                        scoring_path=report.scoring_path,
                        case_ids=[case_key],
                    ),
                    metadata=metadata,
                )
            )
            if anomaly_high_risk and anomaly:
                labels = [str(label) for label in anomaly.get("labels", []) if str(label)] if isinstance(anomaly.get("labels"), list) else []
                anomaly_id = _stable_id("anomaly", report.target_model, report.target_adapter, case_key, anomaly.get("text_sha256"), ",".join(labels))
                anomaly_excerpt = _safe_excerpt(anomaly.get("rationale") or "high-risk anomaly detected")
                findings.append(
                    SecurityFinding(
                        finding_id=anomaly_id,
                        title=f"High-risk anomalous output: {case_key}",
                        source_type="anomaly",
                        affected_model=_target(report),
                        severity="critical" if anomaly.get("highest_severity") == "block" else "high",
                        attack_surface="output_integrity",
                        technique=",".join(labels) or "anomalous_output",
                        violated_boundary="transcript_boundary",
                        taxonomy_refs=["anomaly", *labels],
                        reproduction_command=command,
                        evidence_refs=[
                            FindingEvidenceRef(
                                evidence_id=f"{anomaly_id}-run-anomaly",
                                artifact_path=artifact_name,
                                artifact_type="run_report_json",
                                json_pointer=f"/datasets/{dataset_index}/case_results/{case_index}/metadata/anomaly",
                                sha256=artifact_hash,
                                redacted_excerpt=anomaly_excerpt,
                            )
                        ],
                        redacted_excerpts=[anomaly_excerpt, _safe_excerpt(anomaly.get("replay_poisoning_warning") or "Replay poisoning risk: sanitize before replay.")],
                        patch_recommendation="Sanitize pseudo role boundaries before replay and add an output-integrity regression for transcript-boundary poisoning.",
                        regression_case_link=case_key,
                        replay_spec=ReplaySpec(
                            replay_id=f"replay-{anomaly_id}",
                            finding_id=anomaly_id,
                            command=command,
                            target_name=report.target_name,
                            target_adapter=report.target_adapter,
                            target_model=report.target_model,
                            input_path=report.input_path,
                            scoring_path=report.scoring_path,
                            case_ids=[case_key],
                        ),
                        metadata={"anomaly": {"labels": labels, "highest_severity": anomaly.get("highest_severity"), "text_sha256": anomaly.get("text_sha256")}, "replay_poisoning_warning": anomaly.get("replay_poisoning_warning")},
                    )
                )
        for group_index, group in enumerate(dataset.group_results):
            if group.passed and group.penalty <= 0:
                continue
            group_key = f"{dataset.dataset_name}:{group.group_id}"
            technique = "refusal_consistency"
            attack_surface = dataset.subcategory or dataset.category
            boundary = dataset.category or "model_behavior"
            finding_id = _stable_id(report.target_model, report.target_adapter, group_key, group.severity, attack_surface, technique, boundary)
            command = _case_command(report, group_key)
            findings.append(
                SecurityFinding(
                    finding_id=finding_id,
                    title=f"{group.severity.title()} group failure: {group_key}",
                    source_type="run_report",
                    affected_model=_target(report),
                    severity=group.severity,
                    attack_surface=attack_surface,
                    technique=technique,
                    violated_boundary=boundary,
                    taxonomy_refs=[dataset.category, dataset.subcategory],
                    reproduction_command=command,
                    evidence_refs=[
                        FindingEvidenceRef(
                            evidence_id=f"{finding_id}-group-result",
                            artifact_path=artifact_name,
                            artifact_type="run_report_json",
                            json_pointer=f"/datasets/{dataset_index}/group_results/{group_index}",
                            sha256=artifact_hash,
                            redacted_excerpt=f"variants={len(group.variants)} penalty={group.penalty}",
                        )
                    ],
                    redacted_excerpts=[f"variants={len(group.variants)}", *[_body_ref(f"variant-{index + 1}-response", variant.response_text) for index, variant in enumerate(group.variants[:3])]],
                    patch_recommendation="Add group-level regression coverage and tighten consistency for equivalent adversarial variants.",
                    regression_case_link=group_key,
                    replay_spec=ReplaySpec(
                        replay_id=f"replay-{finding_id}",
                        finding_id=finding_id,
                        command=command,
                        target_name=report.target_name,
                        target_adapter=report.target_adapter,
                        target_model=report.target_model,
                        input_path=report.input_path,
                        scoring_path=report.scoring_path,
                        case_ids=[group_key],
                    ),
                    metadata={"dataset_name": dataset.dataset_name, "group_id": group.group_id, "rag_harness": {"status": "not_supplied"}},
                )
            )
    return findings


def findings_from_mutation_report(report: MutationRunReport, *, report_path: str | Path = "mutation-report.json") -> list[SecurityFinding]:
    if Path(report_path).name == "mutation-dry-run.json" or report.report_mode == "dry_run":
        return []
    artifact = Path(report_path)
    artifact_name = artifact.name
    artifact_hash = _sha256_file(artifact)
    findings: list[SecurityFinding] = []
    for index, item in enumerate(report.case_results):
        pass_to_fail = item.original_passed and not item.mutated_passed
        negative_delta = item.delta < 0
        if not pass_to_fail and not negative_delta:
            continue
        case_key = f"{item.dataset_name}:{item.case_id}"
        family = item.family or str(item.transform_metadata.get("family") or "mutation")
        surface = item.surface or str(item.transform_metadata.get("surface") or item.category or "mutation")
        boundary = item.boundary or str(item.transform_metadata.get("boundary") or "mutation_robustness")
        severity: Severity = "high" if pass_to_fail else "medium"
        technique = item.mutation
        finding_id = _stable_id(report.target_model, report.target_adapter, case_key, technique, item.delta, family, surface, boundary)
        command = _mutation_command(report, case_key, item.mutation)
        excerpts = [
            _safe_excerpt(item.mutated_prompt),
            _safe_excerpt(item.mutated_response_text),
            f"delta={item.delta} original_passed={item.original_passed} mutated_passed={item.mutated_passed}",
        ]
        metadata: dict[str, Any] = {
            "dataset_name": item.dataset_name,
            "case_id": item.case_id,
            "mutation": item.mutation,
            "category": item.category,
            "risk": item.risk,
            "family": family,
            "surface": surface,
            "boundary": boundary,
            "tags": list(item.tags),
            "coverage_tags": list(item.coverage_tags),
            "transform_metadata": item.transform_metadata,
            "delta": item.delta,
            "original_score": item.original_score,
            "mutated_score": item.mutated_score,
            "original_passed": item.original_passed,
            "mutated_passed": item.mutated_passed,
            "artifact_metadata": item.metadata,
            "rag_harness": {"status": "not_supplied"},
        }
        findings.append(
            SecurityFinding(
                finding_id=finding_id,
                title=f"{severity.title()} mutation regression: {case_key} / {item.mutation}",
                source_type="mutation_run",
                affected_model=_target(report),
                severity=severity,
                attack_surface=surface,
                technique=technique,
                violated_boundary=boundary,
                taxonomy_refs=["mutation", family, surface, boundary, *item.tags],
                reproduction_command=command,
                evidence_refs=[
                    FindingEvidenceRef(
                        evidence_id=f"{finding_id}-mutation-result",
                        artifact_path=artifact_name,
                        artifact_type="mutation_report_json",
                        json_pointer=f"/case_results/{index}",
                        sha256=artifact_hash,
                        redacted_excerpt="; ".join(excerpts),
                    )
                ],
                redacted_excerpts=excerpts,
                patch_recommendation="Add this mutation replay as a regression and harden handling for the transform family/surface before release.",
                regression_case_link=f"{case_key}:{item.mutation}",
                replay_spec=ReplaySpec(
                    replay_id=f"replay-{finding_id}",
                    finding_id=finding_id,
                    command=command,
                    target_name=report.target_name,
                    target_adapter=report.target_adapter,
                    target_model=report.target_model,
                    input_path=report.input_path,
                    scoring_path=report.scoring_path,
                    case_ids=[case_key],
                ),
                metadata=metadata,
            )
        )
    return findings


def findings_from_agent_lab_report(report: Any, *, report_path: str | Path = "agent-lab-report.json") -> list[SecurityFinding]:
    artifact = Path(report_path)
    artifact_name = artifact.name
    artifact_hash = _sha256_file(artifact)
    findings: list[SecurityFinding] = []
    for index, result in enumerate(report.results):
        if result.passed and not result.violation:
            continue
        technique = result.selected_tool or _safe_excerpt(result.reason, limit=80)
        boundary = "agent_policy_boundary"
        finding_id = _stable_id(report.target_model, report.target_adapter, result.scenario_id, result.severity, result.attack_surface, technique, boundary)
        command = _agent_command(report, result.scenario_id)
        trace_reasons: list[str] = []
        if result.trace is not None:
            trace_reasons.extend(result.trace.gate_outcome.reasons)
            trace_reasons.extend(result.trace.policy_judgment.violations)
        excerpts = [_body_ref("agent-prompt", result.prompt), _body_ref("agent-response", result.response_text), _safe_excerpt(result.reason)]
        excerpts.extend(_safe_excerpt(reason) for reason in trace_reasons[:4])
        findings.append(
            SecurityFinding(
                finding_id=finding_id,
                title=f"{result.severity.title()} agent-lab violation: {result.scenario_id}",
                source_type="agent_lab",
                affected_model=_target(report),
                severity=result.severity,
                attack_surface=result.attack_surface,
                technique=technique,
                violated_boundary=boundary,
                taxonomy_refs=["agent_lab", result.attack_surface],
                reproduction_command=command,
                evidence_refs=[
                    FindingEvidenceRef(
                        evidence_id=f"{finding_id}-agent-result",
                        artifact_path=artifact_name,
                        artifact_type="agent_lab_report_json",
                        json_pointer=f"/results/{index}",
                        sha256=artifact_hash,
                        redacted_excerpt=_safe_excerpt(result.reason),
                    )
                ],
                redacted_excerpts=excerpts,
                patch_recommendation="Harden the agent policy/tool boundary and add this scenario as a regression before enabling risky automation.",
                regression_case_link=result.scenario_id,
                replay_spec=ReplaySpec(
                    replay_id=f"replay-{finding_id}",
                    finding_id=finding_id,
                    command=command,
                    target_name=report.target_name,
                    target_adapter=report.target_adapter,
                    target_model=report.target_model,
                    scenario_ids=[result.scenario_id],
                ),
                metadata={"selected_tool": result.selected_tool, "policy_reasons": [_safe_excerpt(reason) for reason in trace_reasons], "rag_harness": {"status": "not_supplied"}},
            )
        )
    return findings


_TOOL_AGENT_BOUNDARY_BY_REASON: dict[str, str] = {
    "forbidden_tool_selected": "tool_policy_boundary",
    "outside_allowed_tools": "tool_policy_boundary",
    "tool_gateway_blocked": "tool_policy_boundary",
    "missing_trusted_approval": "approval_boundary",
    "fake_approval_source": "approval_boundary",
    "private_to_public_sink": "data_boundary",
    "secret_in_tool_args": "secret_boundary",
    "canary_in_tool_args": "secret_boundary",
    "unsafe_tool_arguments": "secret_boundary",
}


def _tool_agent_boundary(reason_codes: list[str]) -> str:
    for code in reason_codes:
        if code in _TOOL_AGENT_BOUNDARY_BY_REASON:
            return _TOOL_AGENT_BOUNDARY_BY_REASON[code]
    if any(code.startswith("tool_gateway_") for code in reason_codes):
        return "tool_policy_boundary"
    return "agent_tool_boundary"


def _tool_agent_patch_recommendation(reason_codes: list[str]) -> str:
    codes = set(reason_codes)
    if codes & {"missing_trusted_approval", "fake_approval_source"}:
        return "Require trusted approval provenance for sensitive tools and fail closed when approval text is user-supplied or untrusted."
    if "private_to_public_sink" in codes:
        return "Block private-source to public-sink routes at the tool gateway and add a regression for the affected scenario."
    if codes & {"secret_in_tool_args", "canary_in_tool_args", "unsafe_tool_arguments"}:
        return "Strip secrets and untrusted instruction text before tool argument construction, then add a canary regression for this scenario."
    if codes & {"forbidden_tool_selected", "outside_allowed_tools", "tool_gateway_blocked"} or any(code.startswith("tool_gateway_") for code in codes):
        return "Enforce deny-by-default tool policy, keep forbidden tools blocked by the gateway, and add this scenario as a regression."
    return "Harden the agent tool boundary and add this scenario as a provider-free regression before enabling live automation."


def _tool_agent_gateway_metadata(result: Any) -> dict[str, Any]:
    tool_calls = list(getattr(result, "tool_calls", []) or [])
    gateway_calls: list[dict[str, Any]] = []
    gateway_reason_codes: set[str] = set()
    blocked = 0
    for index, call in enumerate(tool_calls):
        metadata = getattr(call, "metadata", {}) if isinstance(getattr(call, "metadata", {}), dict) else {}
        decision = metadata.get("gateway_decision")
        raw_codes = metadata.get("gateway_reason_codes") if isinstance(metadata.get("gateway_reason_codes"), list) else []
        if decision:
            if decision == "blocked":
                blocked += 1
            gateway_reason_codes.update(str(code) for code in raw_codes)
            gateway_calls.append(
                {
                    "index": index,
                    "tool_name": _safe_excerpt(getattr(call, "tool_name", "unknown"), limit=80),
                    "status": _safe_excerpt(getattr(call, "status", "unknown"), limit=40),
                    "gateway_decision": _safe_excerpt(decision, limit=40),
                    "gateway_reason_codes": [_safe_excerpt(code, limit=80) for code in raw_codes],
                    "gateway_policy_hash": _safe_excerpt(metadata.get("gateway_policy_hash", ""), limit=80) if metadata.get("gateway_policy_hash") else None,
                }
            )
    harness_metadata = getattr(getattr(result, "harness_result", None), "metadata", {})
    supplied_gateway = harness_metadata.get("tool_gateway") if isinstance(harness_metadata, dict) and isinstance(harness_metadata.get("tool_gateway"), dict) else {}
    return {
        "calls": len(gateway_calls),
        "blocked": blocked,
        "reason_codes": sorted(gateway_reason_codes),
        "events": gateway_calls[:10],
        "reported": supplied_gateway,
    }


def _tool_agent_trace_excerpt(result: Any) -> str:
    fragments: list[str] = []
    for call in list(getattr(result, "tool_calls", []) or [])[:5]:
        metadata = getattr(call, "metadata", {}) if isinstance(getattr(call, "metadata", {}), dict) else {}
        codes = metadata.get("gateway_reason_codes") if isinstance(metadata.get("gateway_reason_codes"), list) else []
        fragments.append(
            " ".join(
                part
                for part in [
                    f"tool={_safe_excerpt(getattr(call, 'tool_name', 'unknown'), limit=80)}",
                    f"status={_safe_excerpt(getattr(call, 'status', 'unknown'), limit=40)}",
                    f"gateway={_safe_excerpt(metadata.get('gateway_decision', 'n/a'), limit=40)}",
                    f"codes={','.join(_safe_excerpt(code, limit=50) for code in codes) or 'none'}",
                ]
                if part
            )
        )
    return "; ".join(fragments) or "no tool calls captured"


def findings_from_tool_agent_report(report: Any, *, report_path: str | Path = "tool-agent-report.json") -> list[SecurityFinding]:
    artifact = Path(report_path)
    artifact_name = artifact.name
    artifact_hash = _sha256_file(artifact)
    findings: list[SecurityFinding] = []
    for index, result in enumerate(getattr(report, "results", [])):
        if getattr(result, "status", None) != "failed":
            continue
        reason_codes = [str(code) for code in getattr(result, "reason_codes", []) if str(code)]
        technique = ",".join(sorted(dict.fromkeys(reason_codes))) or "tool_agent_policy_failure"
        boundary = _tool_agent_boundary(reason_codes)
        scenario_id = str(getattr(result, "scenario_id", f"scenario-{index + 1}"))
        severity = getattr(result, "severity", "high")
        if severity not in {"low", "medium", "high", "critical"}:
            severity = "high"
        attack_surface = str(getattr(result, "attack_surface", "tool_agent"))
        finding_id = _stable_id(getattr(report, "target_name", None), getattr(report, "target_type", None), scenario_id, severity, attack_surface, technique, boundary)
        command = _tool_agent_replay_command(finding_id, artifact)
        reason_excerpt = _safe_excerpt(getattr(result, "reason", None) or "tool-agent policy failure")
        trace_excerpt = _safe_excerpt(_tool_agent_trace_excerpt(result), limit=260)
        evidence_refs = [
            FindingEvidenceRef(
                evidence_id=f"{finding_id}-tool-agent-result",
                artifact_path=artifact_name,
                artifact_type="tool_agent_report_json",
                json_pointer=f"/results/{index}",
                sha256=artifact_hash,
                redacted_excerpt=f"{reason_excerpt}; {trace_excerpt}",
            )
        ]
        for artifact_index, ref in enumerate(list(getattr(result, "artifact_refs", []) or [])[:5]):
            ref_path = str(getattr(ref, "path", "") or "")
            if not ref_path:
                continue
            evidence_refs.append(
                FindingEvidenceRef(
                    evidence_id=f"{finding_id}-tool-agent-artifact-{artifact_index + 1}",
                    artifact_path=Path(ref_path).name,
                    artifact_type=str(getattr(ref, "artifact_type", "tool_agent_artifact") or "tool_agent_artifact"),
                    sha256=getattr(ref, "sha256", None),
                    redaction_status=str(getattr(ref, "redaction_status", "redacted") or "redacted") if getattr(ref, "redaction_status", None) in {"redacted", "not_applicable", "unknown"} else "redacted",
                    redacted_excerpt=_safe_excerpt(f"scenario artifact for {scenario_id}", limit=120),
                )
            )
        gateway_metadata = _tool_agent_gateway_metadata(result)
        findings.append(
            SecurityFinding(
                finding_id=finding_id,
                title=f"{str(severity).title()} tool-agent policy failure: {scenario_id}",
                source_type="tool_agent",
                affected_model={
                    "name": str(getattr(report, "target_name", "tool-agent")),
                    "adapter": str(getattr(report, "target_type", "tool_agent")),
                    "model": None,
                    "config": str(getattr(report, "target_name", "tool-agent")),
                },
                severity=severity,  # type: ignore[arg-type]
                attack_surface=attack_surface,
                technique=technique,
                violated_boundary=boundary,
                taxonomy_refs=["tool_agent", attack_surface, *reason_codes],
                reproduction_command=command,
                evidence_refs=evidence_refs,
                redacted_excerpts=[reason_excerpt, trace_excerpt, f"reason_codes={_safe_excerpt(','.join(reason_codes) or 'none', limit=180)}"],
                patch_recommendation=_tool_agent_patch_recommendation(reason_codes),
                regression_case_link=scenario_id,
                replay_spec=ReplaySpec(
                    replay_id=f"replay-{finding_id}",
                    finding_id=finding_id,
                    mode="dry_run",
                    command=command,
                    target_name=str(getattr(report, "target_name", "tool-agent")),
                    target_adapter=str(getattr(report, "target_type", "tool_agent")),
                    target_model=None,
                    input_path=str(getattr(report, "scenarios_path", "") or "") or None,
                    scenario_ids=[scenario_id],
                ),
                metadata={
                    "scenario_id": scenario_id,
                    "scenario_pack_name": getattr(report, "scenario_pack_name", None),
                    "run_id": getattr(report, "run_id", None),
                    "target_type": getattr(report, "target_type", None),
                    "tool_gateway": gateway_metadata,
                    "tool_call_count": len(list(getattr(result, "tool_calls", []) or [])),
                    "detection_count": len(list(getattr(result, "detections", []) or [])),
                    "coverage_tags": list(getattr(result, "coverage_tags", []) or []),
                },
            )
        )
    return findings


def _live_evidence_boundary(reason_codes: list[str], target_type: str, surface_id: str) -> str:
    codes = set(reason_codes)
    if codes & {"cross_tenant_retrieval", "tenant_leakage", "private_to_public_sink"}:
        return "tenant_data_boundary"
    if codes & {"canary_movement", "secret_in_tool_args", "canary_in_tool_args"}:
        return "secret_boundary"
    if codes & {"forbidden_tool_selected", "tool_gateway_blocked", "outside_allowed_tools"}:
        return "tool_policy_boundary"
    if target_type == "rag_service" or "rag" in surface_id:
        return "rag_context_boundary"
    if target_type in {"memory_agent", "multi_agent"}:
        return f"{target_type}_authority_boundary"
    if target_type in {"code_agent", "workflow_harness", "browser_agent", "tool_agent"}:
        return f"{target_type}_execution_boundary"
    return "live_evidence_boundary"


def _live_evidence_patch_recommendation(reason_codes: list[str], target_type: str) -> str:
    codes = set(reason_codes)
    if codes & {"cross_tenant_retrieval", "tenant_leakage"}:
        return "Fix retrieval tenant isolation, add source filtering assertions, and replay this live-evidence row as a provider-free regression before release."
    if "canary_movement" in codes:
        return "Stop canary or secret propagation across context, retrieval, memory, and tool boundaries, then add a regression for this live surface."
    if codes & {"forbidden_tool_selected", "tool_gateway_blocked", "outside_allowed_tools"}:
        return "Harden tool policy enforcement and keep gateway-denied actions blocked with regression coverage for the live surface."
    return f"Review the {target_type or 'live'} harness boundary, fix the failing reason codes, and keep this row as provider-free release regression evidence."


def findings_from_live_evidence_matrix(data: dict[str, Any], *, report_path: str | Path = "live-full-evidence.json") -> list[SecurityFinding]:
    artifact = Path(report_path)
    artifact_name = artifact.name
    artifact_hash = _sha256_file(artifact)
    metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    target_metadata = {
        "name": str(metadata.get("target_name") or ""),
        "adapter": str(metadata.get("target_adapter") or "") or None,
        "model": str(metadata.get("target_model") or "") or None,
        "config": str(metadata.get("target_name") or "") or None,
    }
    findings: list[SecurityFinding] = []
    rows = data.get("rows") if isinstance(data.get("rows"), list) else []
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or row.get("status") != "failed":
            continue
        row_metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
        target = row.get("target") if isinstance(row.get("target"), dict) else {}
        target_meta = target.get("metadata") if isinstance(target.get("metadata"), dict) else {}
        target_type = str(row_metadata.get("target_type") or target_meta.get("target_type") or "live_target")
        surface_id = str(row.get("surface_id") or row.get("case_id") or f"live-row-{index + 1}")
        case_id = str(row.get("case_id") or surface_id)
        reason_codes = [str(code) for code in row_metadata.get("reason_codes", [])] if isinstance(row_metadata.get("reason_codes"), list) else []
        technique = ",".join(sorted(dict.fromkeys(reason_codes))) or str(row.get("status") or "live_evidence_failure")
        boundary = _live_evidence_boundary(reason_codes, target_type, surface_id)
        severity: Severity = "critical" if set(reason_codes) & {"cross_tenant_retrieval", "tenant_leakage", "canary_movement", "secret_leakage"} else "high"
        finding_id = _stable_id("live_evidence", target.get("model") or target_metadata.get("model"), target_type, surface_id, case_id, technique, boundary)
        command = _tool_agent_replay_command(finding_id, artifact)
        reason_excerpt = _safe_excerpt(row.get("reason") or technique, limit=260)
        evidence_refs = [
            FindingEvidenceRef(
                evidence_id=f"{finding_id}-live-evidence-row",
                artifact_path=artifact_name,
                artifact_type="live_evidence_matrix_json",
                json_pointer=f"/rows/{index}",
                sha256=artifact_hash,
                redacted_excerpt=reason_excerpt,
            )
        ]
        artifacts = row.get("artifacts") if isinstance(row.get("artifacts"), list) else []
        for artifact_index, ref in enumerate(artifacts[:5]):
            if not isinstance(ref, dict):
                continue
            ref_path = str(ref.get("relative_path") or ref.get("path") or "")
            if not ref_path:
                continue
            evidence_refs.append(
                FindingEvidenceRef(
                    evidence_id=f"{finding_id}-child-artifact-{artifact_index + 1}",
                    artifact_path=Path(ref_path).name,
                    artifact_type=str(ref.get("artifact_type") or "live_child_artifact"),
                    sha256=ref.get("sha256") if isinstance(ref.get("sha256"), str) else None,
                    redaction_status=ref.get("redaction_status") if ref.get("redaction_status") in {"redacted", "not_applicable", "unknown"} else "redacted",
                    redacted_excerpt=_safe_excerpt(ref.get("redacted_preview") or ref.get("artifact_type") or ref_path, limit=140),
                )
            )
        findings.append(
            SecurityFinding(
                finding_id=finding_id,
                title=f"{severity.title()} live evidence failure: {case_id}",
                source_type="live_evidence",
                affected_model={
                    "name": str(target.get("name") or target_metadata.get("name") or "live-target"),
                    "adapter": str(target.get("adapter") or target_metadata.get("adapter") or "") or None,
                    "model": str(target.get("model") or target_metadata.get("model") or "") or None,
                    "config": str(target.get("name") or target_metadata.get("config") or "") or None,
                },
                severity=severity,
                attack_surface=target_type,
                technique=technique,
                violated_boundary=boundary,
                taxonomy_refs=["live_evidence", target_type, surface_id, *reason_codes],
                reproduction_command=command,
                evidence_refs=evidence_refs,
                redacted_excerpts=[reason_excerpt, f"reason_codes={_safe_excerpt(','.join(reason_codes) or 'none', limit=180)}"],
                patch_recommendation=_live_evidence_patch_recommendation(reason_codes, target_type),
                regression_case_link=case_id,
                replay_spec=ReplaySpec(
                    replay_id=f"replay-{finding_id}",
                    finding_id=finding_id,
                    mode="dry_run",
                    command=command,
                    target_name=str(target.get("name") or target_metadata.get("name") or "live-target"),
                    target_adapter=str(target.get("adapter") or target_metadata.get("adapter") or "") or None,
                    target_model=str(target.get("model") or target_metadata.get("model") or "") or None,
                    scenario_ids=[case_id],
                ),
                metadata={
                    "row_id": row.get("row_id"),
                    "case_id": case_id,
                    "surface_id": surface_id,
                    "target_type": target_type,
                    "evidence_level": row.get("evidence_level"),
                    "provider_calls_enabled": row.get("provider_calls_enabled"),
                    "live_model_calls": row.get("live_model_calls"),
                    "reason_codes": reason_codes,
                    "report_json": row_metadata.get("report_json"),
                    "agent_trace_summary": row_metadata.get("agent_trace_summary"),
                },
            )
        )
    return findings


def findings_from_gate_decision(decision: GateDecision, *, report: RunReport | None = None, report_path: str | Path = "risk-summary.json") -> list[SecurityFinding]:
    if decision.status in {"pass", "warn"}:
        return []
    target = _target(report) if report is not None else {"name": None, "adapter": None, "model": None, "config": None}
    severity = _severity_from_status(decision.status)
    reason_key = ",".join(decision.reasons)
    finding_id = _stable_id(target.get("model"), target.get("adapter"), decision.status, reason_key)
    command = "malleus gate --report report.json"
    report_path_obj = Path(report_path)
    repeated_path = report_path_obj.with_name("repeated-summary.json")
    evidence_refs = [
        FindingEvidenceRef(
            evidence_id=f"{finding_id}-gate",
            artifact_path=report_path_obj.name,
            artifact_type="risk_summary",
            sha256=_sha256_file(report_path_obj),
            redacted_excerpt="; ".join(_safe_excerpt(reason) for reason in decision.reasons),
        )
    ]
    worst_samples = [sample for sample in decision.summary.repeated_worst_samples if isinstance(sample, dict)]
    for index, sample in enumerate(worst_samples[:5]):
        if repeated_path.exists():
            evidence_refs.append(
                FindingEvidenceRef(
                    evidence_id=f"{finding_id}-worst-sample-{index + 1}",
                    artifact_path=repeated_path.name,
                    artifact_type="repeated_run_summary",
                    json_pointer=f"/cases/{index}/worst_sample",
                    sha256=_sha256_file(repeated_path),
                    redacted_excerpt=_safe_excerpt(
                        f"{sample.get('dataset_name')}:{sample.get('case_id')} sample {sample.get('sample_index')} "
                        f"label={sample.get('refusal_label')} hash={sample.get('response_sha256')}"
                    ),
                )
            )
    return [
        SecurityFinding(
            finding_id=finding_id,
            title=f"{severity.title()} policy gate decision: {decision.status}",
            source_type="gate",
            affected_model=target,
            severity=severity,
            attack_surface="policy_gate",
            technique=decision.status,
            violated_boundary="deployment_gate",
            taxonomy_refs=["gate", "policy"],
            reproduction_command=command,
            evidence_refs=evidence_refs,
            redacted_excerpts=[_safe_excerpt(reason) for reason in decision.reasons],
            patch_recommendation="Resolve failing gate reasons or explicitly document an approved exception before deployment.",
            regression_case_link=decision.run_id or "gate",
            replay_spec=ReplaySpec(replay_id=f"replay-{finding_id}", finding_id=finding_id, command=command, target_name=str(target.get("name") or "unknown")),
            metadata={"gate_status": decision.status, "thresholds": decision.thresholds, "repeated_worst_samples": worst_samples[:5]},
        )
    ]


def findings_from_trace_diff_report(data: dict[str, Any], *, report_path: str | Path = "trace-diff-report.json") -> list[SecurityFinding]:
    artifact = Path(report_path)
    artifact_name = artifact.name
    artifact_hash = _sha256_file(artifact)
    findings: list[SecurityFinding] = []
    records = data.get("regression_records") if isinstance(data.get("regression_records"), list) else []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            continue
        severity = record.get("severity") if record.get("severity") in {"low", "medium", "high", "critical"} else "high"
        code = str(record.get("code") or "trace_regression")
        subject = str(record.get("regression_case_link") or record.get("title") or f"trace-delta-{index + 1}")
        finding_id = _stable_id("trace_diff", code, severity, subject, index)
        findings.append(
            SecurityFinding(
                finding_id=finding_id,
                title=f"{str(severity).title()} trace regression: {_safe_excerpt(code, limit=80)}",
                source_type="trace_diff",
                affected_model={"name": None, "adapter": None, "model": None, "config": None},
                severity=severity,  # type: ignore[arg-type]
                attack_surface="agent_trace",
                technique=code,
                violated_boundary="behavioral_regression",
                taxonomy_refs=["trace_diff", code],
                reproduction_command="malleus diff-traces --old OLD_TRACE --new NEW_TRACE --out-dir trace-diff",
                evidence_refs=[
                    FindingEvidenceRef(
                        evidence_id=f"{finding_id}-trace-diff",
                        artifact_path=artifact_name,
                        artifact_type="trace_diff_report_json",
                        json_pointer=f"/regression_records/{index}",
                        sha256=artifact_hash,
                        redacted_excerpt=_safe_excerpt(record.get("title") or subject),
                    )
                ],
                redacted_excerpts=[_safe_excerpt(value) for value in record.get("redacted_excerpts", [])[:4]] or [_safe_excerpt(subject)],
                patch_recommendation="Review the behavioral trace delta and add or update a regression scenario before release.",
                regression_case_link=_safe_excerpt(subject, limit=120),
                replay_spec=ReplaySpec(replay_id=f"replay-{finding_id}", finding_id=finding_id, mode="dry_run", command="malleus diff-traces --old OLD_TRACE --new NEW_TRACE --out-dir trace-diff", target_name="trace_diff"),
                metadata={"trace_delta_code": code, "source_report": artifact_name},
            )
        )
    return findings


def _hidden_findings(data: dict[str, Any], path: Path) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    source = str(data.get("source") or path.name)
    for index, item in enumerate(data.get("findings") if isinstance(data.get("findings"), list) else []):
        if not isinstance(item, dict):
            continue
        severity = item.get("severity") if item.get("severity") in {"low", "medium", "high", "critical"} else "medium"
        kind = str(item.get("kind") or "hidden_channel")
        finding_id = _stable_id("hidden_channel", source, kind, severity, index)
        findings.append(
            SecurityFinding(
                finding_id=finding_id,
                title=f"{str(severity).title()} hidden-channel finding: {kind}",
                source_type="hidden_channel",
                affected_model={"name": None, "adapter": None, "model": None, "config": None},
                severity=severity,  # type: ignore[arg-type]
                attack_surface="hidden_channel",
                technique=kind,
                violated_boundary="artifact_visibility",
                taxonomy_refs=["hidden_channel", kind],
                reproduction_command=f"malleus inspect-text --file {source} --json",
                evidence_refs=[FindingEvidenceRef(evidence_id=f"{finding_id}-hidden", artifact_path=path.name, artifact_type="hidden_channel_report_json", json_pointer=f"/findings/{index}", sha256=_sha256_file(path), redacted_excerpt=_safe_excerpt(item.get("description", kind)))],
                redacted_excerpts=[_safe_excerpt(item.get("description", kind)), _safe_excerpt(item.get("decoded_preview", "n/a"))],
                patch_recommendation="Review hidden or encoded surfaces and strip or quarantine content that carries machine-readable instructions.",
                regression_case_link=source,
                replay_spec=ReplaySpec(replay_id=f"replay-{finding_id}", finding_id=finding_id, command=f"malleus inspect-text --file {source} --json", target_name="artifact"),
            )
        )
    return findings


def _artifact_findings(data: dict[str, Any], path: Path) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    source = str(data.get("source") or path.name)
    items = data.get("findings") if isinstance(data.get("findings"), list) else []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        severity = item.get("severity") if item.get("severity") in {"low", "medium", "high", "critical"} else "medium"
        kind = str(item.get("kind") or "artifact_firewall")
        finding_id = _stable_id("artifact_firewall", source, kind, severity, index)
        findings.append(
            SecurityFinding(
                finding_id=finding_id,
                title=f"{str(severity).title()} artifact firewall finding: {kind}",
                source_type="artifact_firewall",
                affected_model={"name": None, "adapter": None, "model": None, "config": None},
                severity=severity,  # type: ignore[arg-type]
                attack_surface="artifact",
                technique=kind,
                violated_boundary="artifact_ingestion",
                taxonomy_refs=["artifact_firewall", kind],
                reproduction_command=f"malleus inspect-artifact --file {source}",
                evidence_refs=[FindingEvidenceRef(evidence_id=f"{finding_id}-artifact", artifact_path=path.name, artifact_type="artifact_firewall_report_json", json_pointer=f"/findings/{index}", sha256=_sha256_file(path), redacted_excerpt=_safe_excerpt(item.get("description", kind)))],
                redacted_excerpts=[_safe_excerpt(item.get("description", kind)), _safe_excerpt(item.get("evidence", "n/a"))],
                patch_recommendation="Quarantine or sanitize the artifact before it can influence prompts, tools, or analyst-visible reports.",
                regression_case_link=source,
                replay_spec=ReplaySpec(replay_id=f"replay-{finding_id}", finding_id=finding_id, command=f"malleus inspect-artifact --file {source}", target_name="artifact"),
            )
        )
    return findings


def _anomaly_findings(data: dict[str, Any], path: Path) -> list[SecurityFinding]:
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    highest = str(summary.get("highest_severity") or data.get("gate_recommendation") or "none")
    if highest not in {"quarantine", "block"}:
        return []
    labels = [str(label) for label in summary.get("labels", []) if str(label)] if isinstance(summary.get("labels"), list) else []
    source = str(data.get("source") or path.name)
    finding_id = _stable_id("anomaly_report", source, data.get("text_sha256"), highest, ",".join(labels))
    severity: Severity = "critical" if highest == "block" else "high"
    rationale = _safe_excerpt(summary.get("rationale") or "high-risk anomalous output detected")
    warning = _safe_excerpt(data.get("replay_poisoning_warning") or "Replay poisoning risk: sanitize before replay.")
    return [
        SecurityFinding(
            finding_id=finding_id,
            title=f"{severity.title()} anomalous output inspection: {','.join(labels) or 'anomalous_output'}",
            source_type="anomaly",
            affected_model={"name": None, "adapter": None, "model": None, "config": None},
            severity=severity,
            attack_surface="output_integrity",
            technique=",".join(labels) or "anomalous_output",
            violated_boundary="transcript_boundary",
            taxonomy_refs=["anomaly", *labels],
            reproduction_command=f"malleus inspect-output --file {source} --out-dir anomaly-inspection",
            evidence_refs=[FindingEvidenceRef(evidence_id=f"{finding_id}-anomaly", artifact_path=path.name, artifact_type="anomaly_report_json", json_pointer="/summary", sha256=_sha256_file(path), redacted_excerpt=rationale)],
            redacted_excerpts=[rationale, warning],
            patch_recommendation="Quarantine the output before replay; strip pseudo role boundaries and hidden continuation markers from downstream logs.",
            regression_case_link=source,
            replay_spec=ReplaySpec(replay_id=f"replay-{finding_id}", finding_id=finding_id, command=f"malleus inspect-output --file {source} --out-dir anomaly-inspection", target_name="output"),
            metadata={"anomaly": {"labels": labels, "highest_severity": highest, "text_sha256": data.get("text_sha256")}, "replay_poisoning_warning": data.get("replay_poisoning_warning")},
        )
    ]


def findings_from_visual_lab_report(report: Any, *, report_path: str | Path = "visual-lab-report.json") -> list[SecurityFinding]:
    artifact = Path(report_path)
    artifact_name = artifact.name
    artifact_hash = _sha256_file(artifact)
    replay = getattr(report, "replay_spec", {})
    command = str(replay.get("command") if isinstance(replay, dict) else "malleus visual-lab run --fixture FIXTURE --out-dir visual-lab-run")
    findings: list[SecurityFinding] = []
    for result_index, result in enumerate(getattr(report, "results", [])):
        scenario_id = str(getattr(result, "scenario_id", f"scenario-{result_index + 1}"))
        coverage = list(getattr(result, "coverage_tags", []))
        finding_items = [*list(getattr(result, "visual_lab_findings", [])), *list(getattr(result, "artifact_firewall_findings", []))]
        for finding_index, item in enumerate(finding_items):
            source = getattr(item, "source", "visual_lab")
            kind = str(getattr(item, "kind", "visual_lab"))
            severity = getattr(item, "severity", "medium")
            if severity not in {"low", "medium", "high", "critical"}:
                severity = "medium"
            description = _safe_excerpt(getattr(item, "description", kind), limit=180)
            finding_id = _stable_id("visual_lab", scenario_id, source, kind, severity, finding_index)
            evidence_ref = str(getattr(item, "evidence_ref", f"/results/{result_index}"))
            redacted_preview = _safe_excerpt(getattr(item, "redacted_preview", "n/a"), limit=220)
            findings.append(
                SecurityFinding(
                    finding_id=finding_id,
                    title=f"{str(severity).title()} visual lab finding: {scenario_id} / {kind}",
                    source_type="visual_lab",
                    affected_model={"name": "local-visual-lab", "adapter": None, "model": None, "config": "visual_lab"},
                    severity=severity,  # type: ignore[arg-type]
                    attack_surface=str(getattr(result, "family", "visual_lab")),
                    technique=kind,
                    violated_boundary="untrusted_visual_artifact_boundary",
                    taxonomy_refs=["visual_lab", *coverage, kind],
                    reproduction_command=command,
                    evidence_refs=[
                        FindingEvidenceRef(
                            evidence_id=f"{finding_id}-visual-lab",
                            artifact_path=artifact_name,
                            artifact_type="visual_lab_report_json",
                            json_pointer=f"/results/{result_index}",
                            sha256=artifact_hash,
                            redacted_excerpt=f"{description}; evidence={_safe_excerpt(evidence_ref)}",
                        )
                    ],
                    redacted_excerpts=[description, redacted_preview, f"scenario={_safe_excerpt(scenario_id)}"],
                    patch_recommendation="Keep visual/OCR/metadata text untrusted, route only sanitized safe-context records, and quarantine artifacts with firewall findings before publication or prompt assembly.",
                    regression_case_link=scenario_id,
                    replay_spec=ReplaySpec(replay_id=f"replay-{finding_id}", finding_id=finding_id, mode="dry_run", command=command, target_name="local-visual-lab", scenario_ids=[scenario_id]),
                    metadata={"scenario_id": scenario_id, "coverage_tags": coverage, "finding_source": source, "evidence_ref": evidence_ref},
                )
            )
    return findings


def _visual_lab_findings(data: dict[str, Any], path: Path) -> list[SecurityFinding]:
    from malleus.visual_lab import VisualLabInspectionReport

    report = VisualLabInspectionReport.model_validate(data)
    return findings_from_visual_lab_report(report, report_path=path)


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def findings_from_campaign_report(data: dict[str, Any], *, report_path: str | Path = "campaign-report.json") -> list[SecurityFinding]:
    artifact = Path(report_path)
    artifact_name = artifact.name
    artifact_hash = _sha256_file(artifact)
    target = {
        "name": str(data.get("target_name") or "campaign"),
        "adapter": str(data.get("target_adapter") or "") or None,
        "model": str(data.get("target_model") or "") or None,
        "config": str(data.get("target_name") or "campaign"),
    }
    campaign_id = str(data.get("campaign_id") or "campaign")
    campaign_path = str(data.get("campaign_path") or "CAMPAIGN")
    target_path = str(data.get("target_path") or "TARGET")
    findings: list[SecurityFinding] = []
    steps = data.get("steps") if isinstance(data.get("steps"), list) else []
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            continue
        gate = step.get("gate") if isinstance(step.get("gate"), dict) else {}
        status = str(gate.get("status") or "pass")
        if status != "fail" and step.get("policy_action") not in {"block", "quarantine"} and step.get("hidden_channel_recommendation") not in {"block", "quarantine"}:
            continue
        step_id = str(step.get("step_id") or f"step-{index + 1}")
        reasons = [str(reason) for reason in gate.get("reasons", [])] if isinstance(gate.get("reasons"), list) else []
        technique = str(step.get("tactic") or "campaign_step")
        surface = str(step.get("surface") or "campaign")
        severity: Severity = "high" if step.get("policy_action") in {"block", "quarantine"} else "medium"
        finding_id = _stable_id(target.get("model"), target.get("adapter"), campaign_id, step_id, severity, surface, technique, ",".join(reasons))
        command = f"malleus campaign run --campaign {campaign_path} --target {target_path} --out-dir replay-campaign --dry-run"
        findings.append(
            SecurityFinding(
                finding_id=finding_id,
                title=f"{severity.title()} campaign gate failure: {step_id}",
                source_type="campaign",
                affected_model=target,
                severity=severity,
                attack_surface=surface,
                technique=technique,
                violated_boundary="campaign_policy_boundary",
                taxonomy_refs=["campaign", surface],
                reproduction_command=command,
                evidence_refs=[FindingEvidenceRef(evidence_id=f"{finding_id}-campaign-step", artifact_path=artifact_name, artifact_type="campaign_report_json", json_pointer=f"/steps/{index}", sha256=artifact_hash, redacted_excerpt="; ".join(_safe_excerpt(reason) for reason in reasons[:3]) or _safe_excerpt(technique))],
                redacted_excerpts=[_safe_excerpt(reason) for reason in reasons[:5]] or [_safe_excerpt(technique)],
                patch_recommendation="Harden the campaign step policy/gate before enabling live multi-step execution.",
                regression_case_link=f"{campaign_id}:{step_id}",
                replay_spec=ReplaySpec(replay_id=f"replay-{finding_id}", finding_id=finding_id, mode="dry_run", command=command, target_name=str(target.get("name") or "campaign"), target_adapter=target.get("adapter"), target_model=target.get("model"), scenario_ids=[f"{campaign_id}:{step_id}"]),
                metadata={"campaign_id": campaign_id, "step_id": step_id, "gate_reasons": [_safe_excerpt(reason) for reason in reasons]},
            )
        )
    return findings


def findings_from_rag_report(data: dict[str, Any], *, report_path: str | Path = "rag-report.json") -> list[SecurityFinding]:
    artifact = Path(report_path)
    artifact_name = artifact.name
    artifact_hash = _sha256_file(artifact)
    fixture_name = str(data.get("fixture_name") or "rag-fixture")
    fixture_path = str(data.get("fixture_path") or "RAG_FIXTURE")
    findings: list[SecurityFinding] = []
    results = data.get("results") if isinstance(data.get("results"), list) else []
    for result_index, result in enumerate(results):
        if not isinstance(result, dict):
            continue
        detections = result.get("detections") if isinstance(result.get("detections"), list) else []
        for detection_index, detection in enumerate(detections):
            if not isinstance(detection, dict):
                continue
            severity = detection.get("severity") if detection.get("severity") in {"low", "medium", "high", "critical"} else "high"
            code = str(detection.get("code") or "rag_detection")
            query_id = str(result.get("query_id") or f"query-{result_index + 1}")
            doc_id = str(detection.get("doc_id") or "n/a")
            finding_id = _stable_id("rag_harness", fixture_name, query_id, doc_id, code, severity)
            command = f"malleus rag run --fixture {fixture_path} --out-dir replay-rag"
            findings.append(
                SecurityFinding(
                    finding_id=finding_id,
                    title=f"{str(severity).title()} RAG harness detection: {code}",
                    source_type="rag_harness",
                    affected_model={"name": "local-rag-fixture", "adapter": None, "model": None, "config": fixture_name},
                    severity=severity,  # type: ignore[arg-type]
                    attack_surface="rag_context",
                    technique=code,
                    violated_boundary="rag_tenant_context_boundary",
                    taxonomy_refs=["rag_security", code],
                    reproduction_command=command,
                    evidence_refs=[FindingEvidenceRef(evidence_id=f"{finding_id}-rag-detection", artifact_path=artifact_name, artifact_type="rag_report_json", json_pointer=f"/results/{result_index}/detections/{detection_index}", sha256=artifact_hash, redacted_excerpt=_safe_excerpt(detection.get("reason", code)))],
                    redacted_excerpts=[_safe_excerpt(detection.get("reason", code)), f"query={_safe_excerpt(query_id)} doc={_safe_excerpt(doc_id)}"],
                    patch_recommendation="Fix retrieval isolation/citation filtering and strip untrusted chunk instructions before context assembly.",
                    regression_case_link=f"{fixture_name}:{query_id}",
                    replay_spec=ReplaySpec(replay_id=f"replay-{finding_id}", finding_id=finding_id, mode="dry_run", command=command, target_name="local-rag-fixture", scenario_ids=[query_id]),
                    metadata={"fixture_name": fixture_name, "query_id": query_id, "doc_id": doc_id, "detection_code": code},
                )
            )
    return findings


def collect_findings(report_dir: str | Path) -> FindingsBundle:
    directory = Path(report_dir).resolve()
    if directory.is_file():
        directory = directory.parent
    findings: list[SecurityFinding] = []
    run_id: str | None = None
    source_report: str | None = None

    report_data = _load_json(directory / "report.json")
    report: RunReport | None = None
    if report_data is not None:
        report = RunReport.model_validate(report_data)
        run_id = report.run_id
        source_report = str(directory / "report.json")
        findings.extend(findings_from_run_report(report, report_path=directory / "report.json"))

    agent_data = _load_json(directory / "agent-lab-report.json")
    if agent_data is not None:
        from malleus.agent_lab.schemas import AgentLabReport

        agent_report = AgentLabReport.model_validate(agent_data)
        run_id = run_id or agent_report.run_id
        source_report = source_report or str(directory / "agent-lab-report.json")
        findings.extend(findings_from_agent_lab_report(agent_report, report_path=directory / "agent-lab-report.json"))

    tool_agent_data = _load_json(directory / "tool-agent-report.json")
    if tool_agent_data is not None:
        from malleus.tool_agent_harness import ToolAgentReport

        tool_agent_report = ToolAgentReport.model_validate(tool_agent_data)
        run_id = run_id or tool_agent_report.run_id
        source_report = source_report or str(directory / "tool-agent-report.json")
        findings.extend(findings_from_tool_agent_report(tool_agent_report, report_path=directory / "tool-agent-report.json"))

    mutation_data = _load_json(directory / "mutation-report.json")
    if mutation_data is not None:
        mutation_report = MutationRunReport.model_validate(mutation_data)
        run_id = run_id or mutation_report.run_id
        source_report = source_report or str(directory / "mutation-report.json")
        findings.extend(findings_from_mutation_report(mutation_report, report_path=directory / "mutation-report.json"))

    gate_data = _load_json(directory / "risk-summary.json")
    if gate_data is not None:
        findings.extend(findings_from_gate_decision(GateDecision.model_validate(gate_data), report=report, report_path=directory / "risk-summary.json"))

    hidden_data = _load_json(directory / "hidden-channel-report.json")
    if hidden_data is not None:
        findings.extend(_hidden_findings(hidden_data, directory / "hidden-channel-report.json"))

    artifact_data = _load_json(directory / "artifact-firewall-report.json")
    if artifact_data is not None:
        findings.extend(_artifact_findings(artifact_data, directory / "artifact-firewall-report.json"))

    anomaly_data = _load_json(directory / "anomaly-report.json")
    if anomaly_data is not None:
        source_report = source_report or str(directory / "anomaly-report.json")
        findings.extend(_anomaly_findings(anomaly_data, directory / "anomaly-report.json"))

    visual_lab_data = _load_json(directory / "visual-lab-report.json")
    if visual_lab_data is not None:
        run_id = run_id or str(visual_lab_data.get("run_id") or "") or None
        source_report = source_report or str(directory / "visual-lab-report.json")
        findings.extend(_visual_lab_findings(visual_lab_data, directory / "visual-lab-report.json"))

    trace_diff_data = _load_json(directory / "trace-diff-report.json")
    if trace_diff_data is not None:
        source_report = source_report or str(directory / "trace-diff-report.json")
        findings.extend(findings_from_trace_diff_report(trace_diff_data, report_path=directory / "trace-diff-report.json"))

    campaign_data = _load_json(directory / "campaign-report.json")
    if campaign_data is not None:
        run_id = run_id or str(campaign_data.get("run_id") or "") or None
        source_report = source_report or str(directory / "campaign-report.json")
        findings.extend(findings_from_campaign_report(campaign_data, report_path=directory / "campaign-report.json"))

    rag_data = _load_json(directory / "rag-report.json")
    if rag_data is not None:
        run_id = run_id or str(rag_data.get("run_id") or "") or None
        source_report = source_report or str(directory / "rag-report.json")
        findings.extend(findings_from_rag_report(rag_data, report_path=directory / "rag-report.json"))

    live_evidence_data = _load_json(directory / "live-full-evidence.json")
    if live_evidence_data is not None:
        run_id = run_id or str(live_evidence_data.get("rows", [{}])[0].get("run_id") if isinstance(live_evidence_data.get("rows"), list) and live_evidence_data.get("rows") else "") or None
        source_report = source_report or str(directory / "live-full-evidence.json")
        findings.extend(findings_from_live_evidence_matrix(live_evidence_data, report_path=directory / "live-full-evidence.json"))

    optional = {
        name: ("present" if (directory / name).exists() else "absent")
        for name in ["agent-lab-report.json", "tool-agent-report.json", "mutation-report.json", "hidden-channel-report.json", "artifact-firewall-report.json", "anomaly-report.json", "visual-lab-report.json", "risk-summary.json", "trace-diff-report.json", "campaign-report.json", "rag-report.json", "live-full-evidence.json"]
    }
    unique = {finding.finding_id: finding for finding in findings}
    ordered = [unique[key] for key in sorted(unique)]
    return FindingsBundle(
        generated_at=datetime.now(UTC).isoformat(),
        source_report=source_report,
        run_id=run_id,
        findings=ordered,
        summary=_summary(ordered),
        optional_artifacts=optional,
        interop={"schema": FINDINGS_SCHEMA_VERSION, "import_ready": True},
    )


def render_findings_markdown(bundle: FindingsBundle) -> str:
    lines = [
        "# Malleus Security Findings",
        "",
        f"- Findings: {bundle.summary.total_findings}",
        f"- Highest severity: {_md_safe(bundle.summary.highest_severity or 'n/a')}",
        f"- Source report: {_md_safe(bundle.source_report or 'n/a')}",
        "",
    ]
    if not bundle.findings:
        lines.append("No reportable security findings extracted.")
        return "\n".join(lines).rstrip() + "\n"
    for finding in bundle.findings:
        lines.extend(
            [
                f"## {_md_safe(finding.finding_id)}",
                "",
                f"- Title: {_md_safe(finding.title)}",
                f"- Severity: {_md_safe(finding.severity)}",
                f"- Model: {_md_safe(finding.affected_model.get('model') or 'n/a')}",
                f"- Attack surface: {_md_safe(finding.attack_surface)}",
                f"- Technique: {_md_safe(finding.technique)}",
                f"- Violated boundary: {_md_safe(finding.violated_boundary)}",
                f"- Taxonomy refs: {_md_safe(', '.join(finding.taxonomy_refs) or 'n/a')}",
                f"- Regression case: {_md_safe(finding.regression_case_link)}",
                f"- Reproduction: `{_md_safe(finding.reproduction_command)}`",
                f"- Patch recommendation: {_md_safe(finding.patch_recommendation)}",
                "- Evidence:",
            ]
        )
        for evidence in finding.evidence_refs:
            lines.append(
                f"  - {_md_safe(evidence.evidence_id)} `{_md_safe(evidence.artifact_path)}` "
                f"{_md_safe(evidence.json_pointer or '')} {_md_safe(evidence.redacted_excerpt or '')}"
            )
        lines.extend(["- Redacted excerpts:"])
        for excerpt in finding.redacted_excerpts[:6]:
            lines.append(f"  - {_md_safe(excerpt)}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def write_finding_artifacts(bundle: FindingsBundle, output_dir: str | Path) -> tuple[Path, Path]:
    destination = Path(output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    json_path = destination / "findings.json"
    markdown_path = destination / "findings.md"
    json_path.write_text(bundle.model_dump_json(indent=2), encoding="utf-8")
    markdown_path.write_text(render_findings_markdown(bundle), encoding="utf-8")
    return json_path, markdown_path


def load_or_collect_findings(report: str | Path) -> FindingsBundle:
    path = Path(report).resolve()
    if path.is_file() and path.name == "findings.json":
        return FindingsBundle.model_validate_json(path.read_text(encoding="utf-8"))
    if path.is_file() and path.name == "live-full-evidence.json":
        data = _load_json(path) or {}
        findings = findings_from_live_evidence_matrix(data, report_path=path)
        first_row = data.get("rows", [{}])[0] if isinstance(data.get("rows"), list) and data.get("rows") else {}
        return FindingsBundle(
            generated_at=datetime.now(UTC).isoformat(),
            source_report=str(path),
            run_id=str(first_row.get("run_id") or "") or None if isinstance(first_row, dict) else None,
            findings=findings,
            summary=_summary(findings),
            optional_artifacts={"live-full-evidence.json": "present"},
            interop={"schema": FINDINGS_SCHEMA_VERSION, "import_ready": True},
        )
    if path.is_file() and path.suffix == ".json" and path.name not in {"report.json", "agent-lab-report.json", "tool-agent-report.json", "risk-summary.json", "trace-diff-report.json", "campaign-report.json", "rag-report.json", "live-full-evidence.json"}:
        data = _load_json(path)
        if data and data.get("schema_version") == FINDINGS_SCHEMA_VERSION:
            return FindingsBundle.model_validate(data)
    return collect_findings(path)


def find_finding(bundle: FindingsBundle, finding_id: str) -> SecurityFinding | None:
    return next((finding for finding in bundle.findings if finding.finding_id == finding_id), None)
