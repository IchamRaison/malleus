from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from malleus.schemas import HarnessResult, TargetType
from malleus.utils.ids import new_run_id
from malleus.utils.redact import redact_public_text, sha256_text


AGENT_TRACE_SCHEMA_VERSION = "malleus.agent_trace.v1"
AgentTraceEvidenceType = Literal[
    "service_trace",
    "agent_trace",
    "workflow_trace",
    "code_agent_trace",
    "memory_trace",
    "multi_agent_trace",
    "browser_trace",
]
AgentTraceStatus = Literal["ok", "failed", "capability_gap", "target_error", "target_config_error", "not_run"]
CANONICAL_AGENT_TRACE_EVENT_TYPES: tuple[str, ...] = (
    "prompt_input",
    "message",
    "system_message",
    "developer_message",
    "user_message",
    "tool_call",
    "tool_args",
    "tool_output",
    "retrieval",
    "citation",
    "refusal",
    "approval",
    "handoff",
    "memory_read",
    "memory_write",
    "memory_event",
    "browser_action",
    "navigation",
    "network_egress",
    "file_write",
    "file_diff",
    "command_execution",
    "retry",
    "streaming_chunk",
    "background_job",
    "policy_block",
    "sink",
    "blocked_operation",
    "final_answer",
    "capability_gap",
    "action",
    "artifact",
)


class AgentTraceEvent(BaseModel):
    event_type: str
    event_id: str | None = None
    summary: str = ""
    status: str = "ok"
    ref: str | None = None
    role: str | None = None
    name: str | None = None
    direction: Literal["input", "output", "internal"] | None = None
    redacted_preview: str | None = None
    sha256: str | None = None
    length: int | None = None
    parent_event_id: str | None = None
    timestamp: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentTrace(BaseModel):
    schema_version: str = AGENT_TRACE_SCHEMA_VERSION
    trace_id: str = Field(default_factory=new_run_id)
    target_type: TargetType
    evidence_type: AgentTraceEvidenceType
    status: AgentTraceStatus
    case_id: str
    target_call_count: int = 0
    target_trace_count: int = 0
    live_model_calls: int = 0
    capability_gaps: list[str] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
    events: list[AgentTraceEvent] = Field(default_factory=list)
    evidence_ref: str | None = None
    artifact_refs: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentTraceSummary(BaseModel):
    total_traces: int = 0
    status_counts: dict[str, int] = Field(default_factory=dict)
    evidence_type_counts: dict[str, int] = Field(default_factory=dict)
    event_type_counts: dict[str, int] = Field(default_factory=dict)
    capability_gap_count: int = 0
    capability_gaps: list[str] = Field(default_factory=list)
    target_call_count: int = 0
    target_trace_count: int = 0
    live_model_calls: int = 0


class AgentTraceCollection(BaseModel):
    schema_version: str = "malleus.agent_trace_collection.v1"
    sources: list[str] = Field(default_factory=list)
    traces: list[AgentTrace] = Field(default_factory=list)
    summary: AgentTraceSummary = Field(default_factory=AgentTraceSummary)
    embedded_summaries: list[dict[str, Any]] = Field(default_factory=list)


def trace_status(result_status: str, reason_codes: list[str] | None = None) -> AgentTraceStatus:
    if result_status == "target_capability_gap":
        return "capability_gap"
    if result_status == "target_config_error":
        return "target_config_error"
    if result_status in {"target_error", "infra_error"}:
        return "target_error"
    if result_status == "failed":
        return "failed"
    if result_status in {"passed", "ok"}:
        return "ok"
    if reason_codes and any("missing" in code or "unsupported" in code for code in reason_codes):
        return "capability_gap"
    return "not_run"


def capability_gaps_from_reason_codes(reason_codes: list[str]) -> list[str]:
    return sorted(code for code in reason_codes if code.startswith("missing_") or code.startswith("unsupported_") or code.endswith("_gap"))


def artifact_paths(refs: list[Any]) -> list[str]:
    values: list[str] = []
    for ref in refs:
        path = getattr(ref, "path", None)
        uri = getattr(ref, "uri", None)
        if isinstance(path, str) and path:
            values.append(path)
        elif isinstance(uri, str) and uri:
            values.append(uri)
    return values


def events_from_harness_result(harness_result: HarnessResult) -> list[AgentTraceEvent]:
    events: list[AgentTraceEvent] = []
    events.extend(_explicit_trace_events(harness_result.metadata))
    for retrieval in harness_result.retrievals:
        events.append(
            AgentTraceEvent(
                event_type="retrieval",
                event_id=retrieval.source_id,
                summary="Retrieved source from target trace",
                status="ok",
                metadata={
                    "source_id": retrieval.source_id,
                    "title": retrieval.title,
                    "score": retrieval.score,
                },
            )
        )
    for call in harness_result.tool_calls:
        argument_keys = sorted(call.arguments.keys())
        events.append(
            AgentTraceEvent(
                event_type="tool_call",
                event_id=call.call_id,
                summary=f"Tool call {call.tool_name}",
                status=call.status,
                name=call.tool_name,
                direction="internal",
                metadata={
                    "tool_name": call.tool_name,
                    "argument_keys": argument_keys,
                    "sink": call.metadata.get("sink"),
                    "approved": call.metadata.get("approved"),
                    "approval_source": call.metadata.get("approval_source"),
                },
            )
        )
        if call.arguments:
            events.append(
                AgentTraceEvent(
                    event_type="tool_args",
                    event_id=f"{call.call_id or call.tool_name}-args",
                    parent_event_id=call.call_id,
                    summary=f"Arguments for tool {call.tool_name}",
                    status=call.status,
                    name=call.tool_name,
                    direction="input",
                    metadata={"tool_name": call.tool_name, "argument_keys": argument_keys, "unsafe_argument_canary": call.metadata.get("unsafe_argument_canary"), "unsafe_argument_text": call.metadata.get("unsafe_argument_text")},
                )
            )
        if call.result_preview:
            events.append(
                AgentTraceEvent(
                    event_type="tool_output",
                    event_id=f"{call.call_id or call.tool_name}-output",
                    parent_event_id=call.call_id,
                    summary=f"Output from tool {call.tool_name}",
                    status=call.status,
                    name=call.tool_name,
                    direction="output",
                    **_text_evidence(call.result_preview),
                    metadata={"tool_name": call.tool_name},
                )
            )
    for action in [*harness_result.traces, *harness_result.actions]:
        events.append(
            AgentTraceEvent(
                event_type=_event_type_for_action(action.action_type, action.metadata),
                event_id=action.action_id,
                summary=action.summary,
                status=action.status,
                name=action.action_type,
                direction="internal",
                timestamp=action.started_at,
                metadata={"action_type": action.action_type, **dict(action.metadata)},
            )
        )
    for diff in harness_result.diffs:
        events.append(
            AgentTraceEvent(
                event_type="file_diff",
                event_id=diff.path,
                summary=f"File {diff.change_type}: {diff.path}",
                status="ok",
                metadata={"path": diff.path, "change_type": diff.change_type, **dict(diff.metadata)},
            )
        )
    for artifact in harness_result.artifacts:
        events.append(
            AgentTraceEvent(
                event_type="artifact",
                event_id=artifact.artifact_id,
                summary=f"Artifact {artifact.artifact_type}",
                status="ok",
                name=artifact.artifact_type,
                ref=artifact.path or artifact.uri,
                metadata={"artifact_type": artifact.artifact_type, "redaction_status": artifact.redaction_status, **dict(artifact.metadata)},
            )
        )
    if harness_result.output_text:
        events.append(
            AgentTraceEvent(
                event_type="final_answer",
                event_id="final-answer",
                summary="Final answer emitted by target",
                status=harness_result.status,
                direction="output",
                **_text_evidence(harness_result.output_text),
            )
        )
    return events


def build_agent_trace(
    *,
    target_type: TargetType,
    evidence_type: AgentTraceEvidenceType,
    case_id: str,
    result_status: str,
    reason_codes: list[str],
    harness_result: HarnessResult,
    target_call_count: int,
    target_trace_count: int,
    evidence_ref: str | None,
    artifact_refs_list: list[Any],
    metadata: dict[str, Any] | None = None,
) -> AgentTrace:
    return AgentTrace(
        target_type=target_type,
        evidence_type=evidence_type,
        status=trace_status(result_status, reason_codes),
        case_id=case_id,
        target_call_count=target_call_count,
        target_trace_count=target_trace_count,
        live_model_calls=int(harness_result.metadata.get("live_model_calls") or 0),
        capability_gaps=capability_gaps_from_reason_codes(reason_codes),
        reason_codes=list(reason_codes),
        events=[*events_from_harness_result(harness_result), *_capability_gap_events(capability_gaps_from_reason_codes(reason_codes))],
        evidence_ref=evidence_ref,
        artifact_refs=artifact_paths(artifact_refs_list),
        metadata=dict(metadata or {}),
    )


def summarize_agent_traces(traces: list[AgentTrace]) -> AgentTraceSummary:
    status_counts: dict[str, int] = {}
    evidence_type_counts: dict[str, int] = {}
    event_type_counts: dict[str, int] = {}
    for trace in traces:
        status_counts[trace.status] = status_counts.get(trace.status, 0) + 1
        evidence_type_counts[trace.evidence_type] = evidence_type_counts.get(trace.evidence_type, 0) + 1
        for event in trace.events:
            event_type_counts[event.event_type] = event_type_counts.get(event.event_type, 0) + 1
    return AgentTraceSummary(
        total_traces=len(traces),
        status_counts=status_counts,
        evidence_type_counts=evidence_type_counts,
        event_type_counts=event_type_counts,
        capability_gap_count=sum(1 for trace in traces if trace.status == "capability_gap"),
        capability_gaps=sorted({gap for trace in traces for gap in trace.capability_gaps}),
        target_call_count=sum(trace.target_call_count for trace in traces),
        target_trace_count=sum(trace.target_trace_count for trace in traces),
        live_model_calls=sum(trace.live_model_calls for trace in traces),
    )


def collect_agent_traces_from_payload(payload: dict[str, Any]) -> tuple[list[AgentTrace], list[dict[str, Any]]]:
    traces: list[AgentTrace] = []
    embedded_summaries: list[dict[str, Any]] = []

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            raw_traces = value.get("agent_traces")
            if isinstance(raw_traces, list):
                traces.extend(AgentTrace.model_validate(item) for item in raw_traces if isinstance(item, dict))
            raw_summary = value.get("agent_trace_summary")
            if isinstance(raw_summary, dict):
                embedded_summaries.append(dict(raw_summary))
            for item in value.values():
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(payload)
    return traces, embedded_summaries


def load_agent_trace_collection(paths: list[str | Path]) -> AgentTraceCollection:
    sources: list[str] = []
    traces: list[AgentTrace] = []
    embedded_summaries: list[dict[str, Any]] = []
    for pathlike in paths:
        path = Path(pathlike)
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"{path} is not a JSON object report")
        found_traces, found_summaries = collect_agent_traces_from_payload(payload)
        sources.append(str(path))
        traces.extend(found_traces)
        embedded_summaries.extend(found_summaries)
    return AgentTraceCollection(
        sources=sources,
        traces=traces,
        summary=summarize_agent_traces(traces),
        embedded_summaries=embedded_summaries,
    )


def render_agent_trace_summary(collection: AgentTraceCollection) -> str:
    summary = collection.summary
    lines = [
        "Agent trace summary",
        f"Reports: {len(collection.sources)}",
        f"Traces: {summary.total_traces}",
        f"Capability gaps: {summary.capability_gap_count}",
        f"Target calls: {summary.target_call_count}",
        f"Target trace items: {summary.target_trace_count}",
        f"Live model calls: {summary.live_model_calls}",
        f"Status counts: {_format_counts(summary.status_counts)}",
        f"Evidence types: {_format_counts(summary.evidence_type_counts)}",
        f"Event types: {_format_counts(summary.event_type_counts)}",
    ]
    if summary.capability_gaps:
        lines.append(f"Gap codes: {', '.join(summary.capability_gaps)}")
    if collection.embedded_summaries and not collection.traces:
        lines.append(f"Embedded summaries: {len(collection.embedded_summaries)}")
    return "\n".join(lines)


def _format_counts(counts: dict[str, int]) -> str:
    if not counts:
        return "none"
    return ", ".join(f"{key}={counts[key]}" for key in sorted(counts))


def _text_evidence(value: str) -> dict[str, Any]:
    redacted = redact_public_text(value, limit=180)
    return {"redacted_preview": redacted.text, "sha256": sha256_text(value), "length": len(value)}


def _explicit_trace_events(metadata: dict[str, Any]) -> list[AgentTraceEvent]:
    raw = metadata.get("agent_trace_events") or metadata.get("trace_events") or []
    if not isinstance(raw, list):
        return []
    events: list[AgentTraceEvent] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            continue
        event_type = str(item.get("event_type") or item.get("type") or "action")
        payload = _safe_explicit_event_payload(item)
        payload["event_type"] = event_type
        payload.setdefault("event_id", f"explicit-trace-event-{index + 1}")
        if "text" in payload and "redacted_preview" not in payload:
            payload.update(_text_evidence(str(payload.pop("text"))))
        else:
            payload.pop("text", None)
        try:
            events.append(AgentTraceEvent.model_validate(payload))
        except Exception:
            events.append(
                AgentTraceEvent(
                    event_type=event_type,
                    event_id=f"explicit-trace-event-{index + 1}",
                    summary=redact_public_text(str(item), limit=160).text,
                    status=str(item.get("status") or "ok"),
                    metadata={"parse_error": True},
                )
            )
    return events


def _safe_explicit_event_payload(item: dict[str, Any]) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key, value in item.items():
        if key in {"redacted_preview", "summary", "ref", "role", "name", "timestamp", "sha256", "event_id", "event_type", "type", "status", "direction", "parent_event_id", "text"}:
            safe[key] = redact_public_text(value, limit=180).text if isinstance(value, str) and key not in {"sha256", "event_type", "type", "status", "direction"} else value
        elif key == "length":
            safe[key] = value
        else:
            safe[key] = _safe_trace_value(value)
    return safe


def _safe_trace_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_public_text(value, limit=120).text
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        return [_safe_trace_value(entry) for entry in value[:20]]
    if isinstance(value, dict):
        return {str(k): _safe_trace_value(v) for k, v in list(value.items())[:20]}
    return redact_public_text(str(value), limit=120).text


def _capability_gap_events(gaps: list[str]) -> list[AgentTraceEvent]:
    return [
        AgentTraceEvent(
            event_type="capability_gap",
            event_id=f"capability-gap-{index + 1}",
            summary=f"Target capability gap: {gap}",
            status="gap",
            metadata={"gap_code": gap},
        )
        for index, gap in enumerate(gaps)
    ]


def _event_type_for_action(action_type: str, metadata: dict[str, Any]) -> str:
    text = " ".join([action_type, str(metadata.get("kind", "")), str(metadata.get("event_type", ""))]).lower()
    if "memory_key" in metadata and "read" in text:
        return "memory_read"
    if "memory_key" in metadata and any(token in text for token in ("write", "store", "update", "delete")):
        return "memory_write"
    if "memory_key" in metadata:
        return "memory_event"
    if "memory" in text and "read" in text:
        return "memory_read"
    if "memory" in text and any(token in text for token in ("write", "store", "update", "delete")):
        return "memory_write"
    if "memory" in text:
        return "memory_event"
    if "handoff" in text or "delegate" in text:
        return "handoff"
    if "approval" in text or "approve" in text:
        return "approval"
    if "policy" in text and ("block" in text or "deny" in text):
        return "policy_block"
    if "browser" in text or "click" in text or "type" in text or "selector" in metadata:
        return "browser_action"
    if "navigate" in text or "navigation" in text or "goto" in text or "url" in metadata:
        return "navigation"
    if "http" in text or "network" in text or "egress" in text or "webhook" in text:
        return "network_egress"
    if "subprocess" in text or "command" in text or "shell" in text or "exec" in text:
        return "command_execution"
    if "retry" in text:
        return "retry"
    if "stream" in text or "chunk" in text:
        return "streaming_chunk"
    if "background" in text or "job" in text:
        return "background_job"
    if "refusal" in text or "refuse" in text:
        return "refusal"
    return "action"
