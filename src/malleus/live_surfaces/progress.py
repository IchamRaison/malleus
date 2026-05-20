from __future__ import annotations

from typing import Any, Callable

from malleus.live_surfaces.common import sanitize_metadata


LiveProgressCallback = Callable[[dict[str, Any]], None]


def emit_progress(callback: LiveProgressCallback | None, **event: Any) -> None:
    if callback is None:
        return
    callback(sanitize_metadata(event))


def emit_system_harness_progress(callback: LiveProgressCallback | None, *, pack: Any, report: Any) -> None:
    report_metadata = getattr(report, "metadata", {}) if isinstance(getattr(report, "metadata", {}), dict) else {}
    hosted_runtime = bool(report_metadata.get("hosted_runtime") or report_metadata.get("hosted_tool_runtime") or _report_has_hosted_runtime_results(report))
    controlled_lab = bool(report_metadata.get("lab_environment") or report_metadata.get("controlled_lab") or report_metadata.get("controlled_surface"))
    evidence_fidelity = (
        _system_evidence_fidelity(str(getattr(report, "target_type", "")), str(getattr(pack, "id", "")), controlled_lab=controlled_lab)
        if hosted_runtime
        else "auto_wrapper_trace"
        if report_metadata.get("auto_wrapped") or _report_has_auto_wrapper_results(report)
        else _system_evidence_fidelity(str(getattr(report, "target_type", "")), str(getattr(pack, "id", "")), controlled_lab=controlled_lab)
    )
    for result in getattr(report, "results", []) or []:
        case_id = _system_result_id(result)
        emit_progress(
            callback,
            event="system_case_end",
            dataset=pack.id,
            case_id=case_id,
            kind="system_case",
            objective=str(getattr(result, "objective", "") or getattr(result, "attack_surface", "") or pack.surface_name or pack.id),
            status=str(getattr(result, "status", "unknown")),
            passed=getattr(result, "status", None) == "passed",
            reason=str(getattr(result, "reason", "") or ""),
            reason_codes=list(getattr(result, "reason_codes", []) or []),
            latency_seconds=getattr(result, "latency_seconds", None),
            evidence_fidelity=evidence_fidelity,
            response=_system_result_excerpt(result),
            trace_summary=_system_result_trace_summary(result),
        )


def _system_result_id(result: Any) -> str:
    for field in ("query_id", "scenario_id", "workflow_id", "prompt_id"):
        value = getattr(result, field, None)
        if value:
            return str(value)
    return "system-result"


def _system_result_excerpt(result: Any) -> str:
    for field in ("answer_excerpt", "final_answer_excerpt", "response_excerpt", "dom_excerpt", "final_status"):
        value = getattr(result, field, None)
        if value:
            return str(value)
    harness_result = getattr(result, "harness_result", None)
    output_text = getattr(harness_result, "output_text", None)
    return str(output_text or "")


def _system_result_trace_summary(result: Any) -> dict[str, Any]:
    tool_calls = getattr(result, "tool_calls", []) or []
    actions = getattr(result, "actions", []) or []
    blocked = getattr(result, "blocked_operations", []) or []
    retrieved = getattr(result, "retrieved_ids", []) or []
    cited = getattr(result, "cited_ids", []) or []
    changed_files = getattr(result, "changed_files", []) or []
    return sanitize_metadata(
        {
            "tool_calls": len(tool_calls),
            "actions": len(actions),
            "blocked_operations": len(blocked),
            "retrieved_ids": list(retrieved)[:20],
            "cited_ids": list(cited)[:20],
            "changed_files": list(changed_files)[:20],
            "target_call_count": getattr(result, "target_call_count", 0),
            "target_trace_count": getattr(result, "target_trace_count", 0),
        }
    )


def _report_has_auto_wrapper_results(report: Any) -> bool:
    for result in getattr(report, "results", []) or []:
        harness_result = getattr(result, "harness_result", None)
        metadata = getattr(harness_result, "metadata", {}) if harness_result is not None else {}
        if isinstance(metadata, dict) and metadata.get("auto_wrapped") is True:
            return True
    return False


def _report_has_hosted_runtime_results(report: Any) -> bool:
    for result in getattr(report, "results", []) or []:
        harness_result = getattr(result, "harness_result", None)
        metadata = getattr(harness_result, "metadata", {}) if harness_result is not None else {}
        if isinstance(metadata, dict) and (metadata.get("hosted_runtime") is True or metadata.get("hosted_tool_runtime") is True):
            return True
    return False


def _system_evidence_fidelity(target_type: str, pack_id: str, *, controlled_lab: bool = False) -> str:
    if target_type == "rag_service" or pack_id == "rag-v1":
        return "controlled_rag_trace" if controlled_lab else "live_rag_service_trace"
    if target_type == "tool_agent":
        return "controlled_tool_trace" if controlled_lab else "live_tool_trace"
    if target_type == "workflow_harness":
        return "controlled_workflow_trace" if controlled_lab else "live_workflow_trace"
    if target_type == "memory_agent":
        return "controlled_memory_trace" if controlled_lab else "live_memory_trace"
    if target_type == "multi_agent":
        return "controlled_multi_agent_trace" if controlled_lab else "live_multi_agent_trace"
    if target_type == "browser_agent":
        return "controlled_browser_trace" if controlled_lab else "live_browser_trace"
    if target_type == "code_agent":
        return "controlled_code_workspace_trace" if controlled_lab else "live_code_agent_trace"
    return "target_error"
