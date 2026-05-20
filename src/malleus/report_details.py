from __future__ import annotations

import json
from typing import Any, Iterable

from malleus.reporting import _md_safe


def render_case_detail_section(title: str, cases: Iterable[dict[str, Any]]) -> list[str]:
    lines = ["", f"## {_md_safe(title)}", ""]
    for case in cases:
        lines.extend(render_case_detail(case))
    return lines


def render_case_detail(case: dict[str, Any]) -> list[str]:
    case_id = str(case.get("id") or "unknown")
    status = str(case.get("status") or "unknown")
    reason_codes = _list_text(case.get("reason_codes")) or "none"
    latency = case.get("latency")
    latency_text = f"{latency:.3f}s" if isinstance(latency, int | float) else "n/a"
    lines = [
        f"### {_md_safe(case_id)}",
        "",
        f"- Status: `{_md_safe(status)}`",
        f"- Reason codes: `{_md_safe(reason_codes)}`",
        f"- Latency: `{_md_safe(latency_text)}`",
    ]
    for label, key in [
        ("Objective", "objective"),
        ("Why this verdict", "verdict_reason"),
        ("Expected boundary", "expected_boundary"),
        ("Observed behavior", "observed_behavior"),
        ("Evidence ref", "evidence_ref"),
    ]:
        value = case.get(key)
        if value not in (None, "", [], {}):
            lines.append(f"- {label}: {_md_safe(_inline(value))}")
    for section_label, key in [
        ("Trace", "trace"),
        ("Tool calls", "tool_calls"),
        ("Actions", "actions"),
        ("Blocked operations", "blocked_operations"),
        ("Approvals", "approvals"),
        ("Memory events", "memory_events"),
        ("Handoffs", "handoffs"),
        ("Retrieval", "retrieval"),
        ("Citations", "citations"),
        ("Changed files", "changed_files"),
        ("Detections", "detections"),
        ("Artifacts", "artifacts"),
    ]:
        values = _as_list(case.get(key))
        if values:
            lines.append(f"- {section_label}:")
            lines.extend(f"  - {_md_safe(_inline(value))}" for value in values[:12])
            if len(values) > 12:
                lines.append(f"  - ... {len(values) - 12} more")
    excerpt = case.get("response_excerpt") or case.get("answer_excerpt") or case.get("final_answer_excerpt") or case.get("dom_excerpt")
    if excerpt:
        lines.extend(["", "Response/evidence excerpt:", "", "```text", _code_block_text(str(excerpt)), "```"])
    lines.append("")
    return lines


def summarize_harness_result(harness_result: Any) -> str:
    status = getattr(harness_result, "status", None) or _dict_get(harness_result, "status") or "unknown"
    error_type = getattr(harness_result, "error_type", None) or _dict_get(harness_result, "error_type")
    error_message = getattr(harness_result, "error_message", None) or _dict_get(harness_result, "error_message")
    output = getattr(harness_result, "output_text", None) or _dict_get(harness_result, "output_text")
    pieces = [f"harness_status={status}"]
    if error_type:
        pieces.append(f"error_type={error_type}")
    if error_message:
        pieces.append(f"error={error_message}")
    if output:
        pieces.append(f"output={str(output)[:180]}")
    return "; ".join(pieces)


def action_summary(action: Any) -> str:
    action_type = getattr(action, "action_type", None) or _dict_get(action, "action_type") or "action"
    status = getattr(action, "status", None) or _dict_get(action, "status") or "unknown"
    summary = getattr(action, "summary", None) or _dict_get(action, "summary") or ""
    action_id = getattr(action, "action_id", None) or _dict_get(action, "action_id")
    parts = [str(action_type)]
    if action_id:
        parts.append(str(action_id))
    parts.append(f"status={status}")
    if summary:
        parts.append(str(summary))
    return " - ".join(parts)


def tool_call_summary(call: Any) -> str:
    tool_name = getattr(call, "tool_name", None) or _dict_get(call, "tool_name") or "tool"
    status = getattr(call, "status", None) or _dict_get(call, "status") or "unknown"
    args = getattr(call, "arguments", None) or _dict_get(call, "arguments") or {}
    arg_keys = ", ".join(sorted(str(key) for key in args.keys())) if isinstance(args, dict) else ""
    result_preview = getattr(call, "result_preview", None) or _dict_get(call, "result_preview")
    pieces = [str(tool_name), f"status={status}"]
    if arg_keys:
        pieces.append(f"args={arg_keys}")
    if result_preview:
        pieces.append(f"result={result_preview}")
    return "; ".join(pieces)


def detection_summary(detection: Any) -> str:
    code = getattr(detection, "code", None) or _dict_get(detection, "code") or "detection"
    severity = getattr(detection, "severity", None) or _dict_get(detection, "severity")
    reason = getattr(detection, "reason", None) or _dict_get(detection, "reason")
    subject = getattr(detection, "subject", None) or _dict_get(detection, "subject")
    pieces = [str(code)]
    if severity:
        pieces.append(f"severity={severity}")
    if subject:
        pieces.append(f"subject={subject}")
    if reason:
        pieces.append(str(reason))
    return "; ".join(pieces)


def artifact_summary(artifact: Any) -> str:
    artifact_id = getattr(artifact, "artifact_id", None) or _dict_get(artifact, "artifact_id") or "artifact"
    artifact_type = getattr(artifact, "artifact_type", None) or _dict_get(artifact, "artifact_type")
    path = getattr(artifact, "path", None) or _dict_get(artifact, "path")
    pieces = [str(artifact_id)]
    if artifact_type:
        pieces.append(str(artifact_type))
    if path:
        pieces.append(str(path))
    return "; ".join(pieces)


def verdict_reason(status: str, reason_codes: list[str], fallback: str | None = None) -> str:
    if fallback:
        return fallback
    if status == "passed":
        return "No deterministic policy or trace violation was detected for this scenario."
    if status == "failed":
        codes = ", ".join(reason_codes) or "unspecified failure"
        return f"The observed trace violated the expected boundary: {codes}."
    if "capability_gap" in status:
        return "The target did not expose enough evidence to score this scenario as model behavior."
    if "error" in status:
        return "The target or harness failed before a complete behavioral verdict could be produced."
    return "No additional verdict explanation was recorded."


def _list_text(value: Any) -> str:
    values = _as_list(value)
    return ", ".join(str(item) for item in values)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple | set):
        return list(value)
    return [value]


def _inline(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, int | float | bool):
        return str(value)
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    except TypeError:
        return str(value)


def _code_block_text(value: str) -> str:
    return value.replace("```", "` ` `").strip()[:2000]


def _dict_get(value: Any, key: str) -> Any:
    return value.get(key) if isinstance(value, dict) else None
