from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from malleus.agent_trace import CANONICAL_AGENT_TRACE_EVENT_TYPES
from malleus.live_evidence import LiveEvidenceMatrix
from malleus.reporting import _md_safe


STACK_COVERAGE_SCHEMA_VERSION = "malleus.stack_coverage.v1"

StackCoverageStatus = Literal["covered", "declared_gap", "missing", "not_applicable"]


class StackCoverageEntry(BaseModel):
    signal: str
    category: str
    status: StackCoverageStatus
    observed_count: int = 0
    required_for: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    notes: str = ""


class StackCoverageReport(BaseModel):
    schema_version: str = STACK_COVERAGE_SCHEMA_VERSION
    target_name: str
    target_type: str
    matrix_id: str
    generated_at: str
    summary: dict[str, int] = Field(default_factory=dict)
    entries: list[StackCoverageEntry] = Field(default_factory=list)


STACK_COVERAGE_SIGNALS: tuple[dict[str, Any], ...] = (
    {"signal": "prompts_incoming", "category": "request", "events": ("prompt_input", "message", "user_message"), "required_for": ["all_l2"]},
    {"signal": "system_developer_user_messages", "category": "request", "events": ("system_message", "developer_message", "user_message"), "required_for": ["all_l2"]},
    {"signal": "tool_calls", "category": "tooling", "events": ("tool_call",), "required_for": ["tool_agent", "workflow_harness", "code_agent", "browser_agent"]},
    {"signal": "tool_args", "category": "tooling", "events": ("tool_args",), "required_for": ["tool_agent", "workflow_harness", "code_agent"]},
    {"signal": "tool_outputs", "category": "tooling", "events": ("tool_output",), "required_for": ["tool_agent", "workflow_harness", "code_agent"]},
    {"signal": "refusals", "category": "behavior", "events": ("refusal",), "required_for": ["all_l2"]},
    {"signal": "approvals", "category": "authority", "events": ("approval",), "required_for": ["workflow_harness", "tool_agent", "code_agent"]},
    {"signal": "handoffs", "category": "authority", "events": ("handoff",), "required_for": ["multi_agent"]},
    {"signal": "memory_reads_writes", "category": "state", "events": ("memory_read", "memory_write", "memory_event"), "required_for": ["memory_agent", "multi_agent"]},
    {"signal": "browser_actions", "category": "browser", "events": ("browser_action",), "required_for": ["browser_agent"]},
    {"signal": "navigation_events", "category": "browser", "events": ("navigation",), "required_for": ["browser_agent"]},
    {"signal": "network_egress", "category": "side_effect", "events": ("network_egress",), "required_for": ["browser_agent", "tool_agent", "code_agent"]},
    {"signal": "file_writes", "category": "side_effect", "events": ("file_write",), "required_for": ["code_agent"]},
    {"signal": "subprocess_command_execution", "category": "side_effect", "events": ("command_execution",), "required_for": ["code_agent"]},
    {"signal": "retries", "category": "runtime", "events": ("retry",), "required_for": ["all_l2"]},
    {"signal": "streaming_chunks", "category": "runtime", "events": ("streaming_chunk",), "required_for": ["all_l2"]},
    {"signal": "background_jobs", "category": "runtime", "events": ("background_job",), "required_for": ["workflow_harness", "multi_agent", "browser_agent"]},
    {"signal": "policy_blocks", "category": "policy", "events": ("policy_block",), "required_for": ["all_l2"]},
    {"signal": "sinks", "category": "side_effect", "events": ("sink",), "required_for": ["tool_agent", "workflow_harness", "memory_agent", "multi_agent"]},
    {"signal": "blocked_operations", "category": "policy", "events": ("blocked_operation",), "required_for": ["all_l2"]},
    {"signal": "final_answer", "category": "response", "events": ("final_answer",), "required_for": ["all_l2"]},
    {"signal": "artifacts", "category": "evidence", "events": ("artifact",), "metadata": ("target_artifact_count",), "required_for": ["all_l2"]},
    {"signal": "diffs", "category": "evidence", "events": ("file_diff",), "required_for": ["code_agent"]},
    {"signal": "live_model_calls", "category": "model", "metadata": ("live_model_calls",), "row_field": "live_model_calls", "required_for": ["chat_completion", "vision_model"]},
    {"signal": "backing_model_calls", "category": "model", "metadata": ("backing_model_calls",), "required_for": ["all_l2"]},
    {"signal": "capability_gap_metadata", "category": "coverage", "events": ("capability_gap",), "metadata": ("agent_trace_capability_gap_count",), "required_for": ["all_l2"]},
)


def build_stack_coverage_from_live_matrix(evidence: LiveEvidenceMatrix) -> StackCoverageReport:
    target_name = evidence.rows[0].target.name if evidence.rows else str(evidence.metadata.get("target_name") or "unknown")
    target_type = _matrix_target_type(evidence)
    event_counts = _event_counts(evidence)
    metadata_counts = _metadata_counts(evidence)
    row_field_counts = _row_field_counts(evidence)
    row_status_counts = Counter(row.status for row in evidence.rows)
    entries: list[StackCoverageEntry] = []

    for spec in STACK_COVERAGE_SIGNALS:
        signal = str(spec["signal"])
        observed = 0
        evidence_refs: list[str] = []
        for event_name in spec.get("events", ()):
            count = int(event_counts.get(event_name, 0))
            observed += count
            if count:
                evidence_refs.append(f"agent_trace_event_type_counts.{event_name}={count}")
        for metadata_name in spec.get("metadata", ()):
            count = int(metadata_counts.get(metadata_name, 0))
            observed += count
            if count:
                evidence_refs.append(f"row.metadata.{metadata_name}={count}")
        row_field = spec.get("row_field")
        if row_field:
            count = int(row_field_counts.get(str(row_field), 0))
            observed += count
            if count:
                evidence_refs.append(f"row.{row_field}={count}")

        required_for = list(spec.get("required_for", []))
        applicable = _signal_applies(target_type, required_for)
        status: StackCoverageStatus
        notes = ""
        if observed > 0:
            status = "covered"
        elif signal == "capability_gap_metadata" and any(row_status_counts.get(status, 0) for status in ("target_capability_gap", "provider_capability_gap")):
            status = "covered"
            observed = sum(row_status_counts.get(status, 0) for status in ("target_capability_gap", "provider_capability_gap"))
            evidence_refs.append(f"row.status.capability_gap={observed}")
        elif not applicable:
            status = "not_applicable"
            notes = f"not required for target_type={target_type}"
        elif _has_declared_gap(evidence, signal):
            status = "declared_gap"
            notes = "target reported an explicit capability gap for this signal"
        else:
            status = "missing"
            notes = "not observed in live evidence; expose this signal in metadata.agent_trace_events or structured response fields"
        entries.append(
            StackCoverageEntry(
                signal=signal,
                category=str(spec["category"]),
                status=status,
                observed_count=observed,
                required_for=required_for,
                evidence=evidence_refs,
                notes=notes,
            )
        )

    summary = Counter(entry.status for entry in entries)
    summary["total"] = len(entries)
    summary["canonical_trace_event_types"] = len(CANONICAL_AGENT_TRACE_EVENT_TYPES)
    return StackCoverageReport(
        target_name=target_name,
        target_type=target_type,
        matrix_id=evidence.matrix_id,
        generated_at=evidence.generated_at,
        summary=dict(summary),
        entries=entries,
    )


def write_stack_coverage_report(report: StackCoverageReport, out_dir: str | Path) -> tuple[Path, Path]:
    destination = Path(out_dir)
    destination.mkdir(parents=True, exist_ok=True)
    json_path = destination / "stack-coverage.json"
    markdown_path = destination / "stack-coverage.md"
    json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    markdown_path.write_text(render_stack_coverage_markdown(report), encoding="utf-8")
    return json_path, markdown_path


def render_stack_coverage_markdown(report: StackCoverageReport) -> str:
    lines = [
        "# Malleus stack coverage",
        "",
        f"- Target: `{_md_safe(report.target_name)}`",
        f"- Target type: `{_md_safe(report.target_type)}`",
        f"- Matrix: `{_md_safe(report.matrix_id)}`",
        f"- Generated at: `{_md_safe(report.generated_at)}`",
        f"- Covered: {report.summary.get('covered', 0)}",
        f"- Declared gaps: {report.summary.get('declared_gap', 0)}",
        f"- Missing: {report.summary.get('missing', 0)}",
        "",
        "| Signal | Category | Status | Observed | Evidence | Notes |",
        "|---|---|---:|---:|---|---|",
    ]
    for entry in report.entries:
        evidence = ", ".join(entry.evidence[:4])
        if len(entry.evidence) > 4:
            evidence += f", +{len(entry.evidence) - 4} more"
        lines.append(
            f"| `{_md_safe(entry.signal)}` | `{_md_safe(entry.category)}` | {_md_safe(entry.status)} | {entry.observed_count} | {_md_safe(evidence)} | {_md_safe(entry.notes)} |"
        )
    lines.extend(
        [
            "",
            "Coverage is trace coverage, not universal security coverage. Missing rows mean Malleus did not observe that production-stack signal in the live artifacts.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def _matrix_target_type(evidence: LiveEvidenceMatrix) -> str:
    observed: Counter[str] = Counter()
    for row in evidence.rows:
        metadata = row.target.metadata if isinstance(row.target.metadata, dict) else {}
        row_metadata = row.metadata if isinstance(row.metadata, dict) else {}
        target_type = metadata.get("target_type") or row_metadata.get("target_type")
        if isinstance(target_type, str) and target_type:
            observed[target_type] += 1
    if observed:
        return observed.most_common(1)[0][0]
    return str(evidence.rows[0].target.adapter if evidence.rows else "unknown")


def _event_counts(evidence: LiveEvidenceMatrix) -> Counter[str]:
    counts: Counter[str] = Counter()
    for row in evidence.rows:
        metadata = row.metadata if isinstance(row.metadata, dict) else {}
        raw = metadata.get("agent_trace_event_type_counts")
        if isinstance(raw, dict):
            for key, value in raw.items():
                counts[str(key)] += _as_count(value)
    return counts


def _metadata_counts(evidence: LiveEvidenceMatrix) -> Counter[str]:
    counts: Counter[str] = Counter()
    for row in evidence.rows:
        metadata = row.metadata if isinstance(row.metadata, dict) else {}
        for key, value in metadata.items():
            count = _as_count(value)
            if count:
                counts[str(key)] += count
    return counts


def _row_field_counts(evidence: LiveEvidenceMatrix) -> Counter[str]:
    counts: Counter[str] = Counter()
    for row in evidence.rows:
        if row.live_model_calls:
            counts["live_model_calls"] += int(row.live_model_calls)
    return counts


def _signal_applies(target_type: str, required_for: list[str]) -> bool:
    if "all_l2" in required_for:
        return target_type not in {"chat_completion", "vision_model", "openai_compatible", "nvidia", "ollama"}
    return target_type in set(required_for)


def _has_declared_gap(evidence: LiveEvidenceMatrix, signal: str) -> bool:
    needles = {signal, signal.replace("_", "-")}
    for row in evidence.rows:
        metadata = row.metadata if isinstance(row.metadata, dict) else {}
        if row.status in {"target_capability_gap", "provider_capability_gap"}:
            reason = f"{row.reason or ''} {' '.join(str(code) for code in metadata.get('reason_codes', []) if code)}".lower()
            if any(needle in reason for needle in needles):
                return True
        summary = metadata.get("agent_trace_summary")
        if isinstance(summary, dict):
            gaps = summary.get("capability_gaps", [])
            if isinstance(gaps, list) and any(any(needle in str(gap).lower() for needle in needles) for gap in gaps):
                return True
    return False


def _as_count(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return max(value, 0)
    if isinstance(value, float):
        return max(int(value), 0)
    if isinstance(value, (list, tuple, set, dict)):
        return len(value)
    return 0


__all__ = [
    "STACK_COVERAGE_SCHEMA_VERSION",
    "STACK_COVERAGE_SIGNALS",
    "StackCoverageEntry",
    "StackCoverageReport",
    "build_stack_coverage_from_live_matrix",
    "render_stack_coverage_markdown",
    "write_stack_coverage_report",
]
