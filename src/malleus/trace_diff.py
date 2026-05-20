from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from html import escape as html_escape
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

TraceSeverity = Literal["info", "low", "medium", "high", "critical"]

_SEVERITY_RANK: dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_GATE_RANK: dict[str, int] = {"pass": 0, "warn": 1, "fail": 2}
_RISK_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_NOISE_KEYS = {
    "id",
    "run_id",
    "trace_id",
    "event_id",
    "request_id",
    "response_id",
    "created_at",
    "updated_at",
    "started_at",
    "finished_at",
    "timestamp",
    "time",
    "duration",
    "latency_seconds",
}
_TEXT_KEYS = {"prompt", "response", "response_text", "content", "final_answer", "trusted_task", "untrusted_context", "reason", "observation", "title", "description", "detail", "message"}
_SECRET_RE = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b|\b(?:api[_ -]?key|secret|token|password|credential|bearer)\s*[:=]?\s*[^\s`|<>]*", re.IGNORECASE)
_UNSAFE_LABEL_RE = re.compile(r"\b(ignore previous instructions|system prompt|developer message|exfiltrate token|sk-[A-Za-z0-9_-]{8,}|api[_ -]?key|secret|password|credential|bearer)\b", re.IGNORECASE)
_SAFE_LABEL_RE = re.compile(r"^(?:[a-z][a-z0-9]{0,24}(?:-[a-z0-9]{1,24}){0,4}|[a-z][a-z0-9]{0,24})$")
_SPACE_RE = re.compile(r"\s+")


class TraceValue(BaseModel):
    value_hash: str
    summary: str
    severity: TraceSeverity | None = None
    flags: list[str] = Field(default_factory=list)


class TraceDiffDelta(BaseModel):
    code: str
    severity: TraceSeverity
    subject: str
    old_value: str | None = None
    new_value: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class TraceDiffSummary(BaseModel):
    total_deltas: int
    regressions: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    warnings: list[str] = Field(default_factory=list)


class TraceDiffReport(BaseModel):
    old_trace_id: str
    new_trace_id: str
    old_path: str
    new_path: str
    summary: TraceDiffSummary
    deltas: list[TraceDiffDelta] = Field(default_factory=list)
    regression_records: list[dict[str, Any]] = Field(default_factory=list)


def _load_json(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Trace artifact must be a JSON object: {Path(path).name}")
    return data


def _hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8", errors="replace")).hexdigest()[:16]


def _safe_label(value: object, *, fallback: str = "label") -> str:
    text = _SPACE_RE.sub(" ", str(value)).strip()
    if not text:
        return f"{fallback}:empty"
    if _SAFE_LABEL_RE.fullmatch(text) and not _SECRET_RE.search(text) and not _UNSAFE_LABEL_RE.search(text):
        return text
    return f"{fallback}:hash={_hash(text)} len={len(text)}"


def _safe_path(path: str | Path) -> str:
    return _safe_label(Path(path).name or str(path), fallback="path")


def _md_text(value: object) -> str:
    text = html_escape(str(value), quote=False).replace("\r", " ").replace("\n", " ")
    return text.replace("|", r"\|").replace("`", r"\`").replace("#", r"\#")


def _normalize(value: Any, *, key: str = "") -> Any:
    if key in _NOISE_KEYS:
        return "[noise]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        if key in _TEXT_KEYS or len(value) > 120 or _SECRET_RE.search(value) or _UNSAFE_LABEL_RE.search(value):
            return {"text_hash": _hash(value), "length": len(value)}
        return _SPACE_RE.sub(" ", value).strip()
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    if isinstance(value, dict):
        return {str(k): _normalize(v, key=str(k)) for k, v in sorted(value.items()) if str(k) not in _NOISE_KEYS}
    return str(value)


def _severity_from_raw(value: Any) -> TraceSeverity | None:
    if isinstance(value, dict):
        raw = str(value.get("severity") or value.get("risk") or "").lower()
        return raw if raw in _SEVERITY_RANK else None  # type: ignore[return-value]
    return None


def _flags_from_text(*values: object) -> list[str]:
    text = " ".join(str(value) for value in values if value is not None).lower()
    flags: list[str] = []
    if any(marker in text for marker in ("protected", "exfiltrate", "delete_repo", "vcs", "physical", "forbidden_shell")):
        flags.append("critical_surface")
    if any(marker in text for marker in ("forbidden", "blocked", "denied", "not allowed", "not_allowed", "policy_denied", "policy denied")):
        flags.append("policy_denied")
    return sorted(set(flags))


def _summarize_mapping(value: dict[str, Any], *, severity: TraceSeverity | None = None, flags: list[str] | None = None) -> TraceValue:
    normalized = _normalize(value)
    keys = sorted(_safe_label(str(key), fallback="key") for key in value.keys() if str(key) not in _NOISE_KEYS)
    digest = _hash(normalized)
    return TraceValue(value_hash=digest, summary=f"keys={','.join(keys) or 'none'} hash={digest}", severity=severity or _severity_from_raw(value), flags=flags or [])


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _safe_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _trace_items(data: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str], str]:
    warnings: list[str] = []
    if isinstance(data.get("results"), list):
        traces: list[dict[str, Any]] = []
        for index, result in enumerate(data["results"]):
            if not isinstance(result, dict):
                warnings.append(f"ignored non-object result at index {index}")
                continue
            trace = result.get("trace")
            if isinstance(trace, dict):
                merged = dict(trace)
                for key in ("scenario_id", "severity", "attack_surface", "selected_tool", "selected_args", "passed", "risk", "violation", "reason"):
                    if key not in merged and key in result:
                        merged[key] = result[key]
                traces.append(merged)
            else:
                warnings.append(f"result {_safe_label(result.get('scenario_id', index), fallback='scenario')} has no trace object")
        return traces, warnings, _safe_label(data.get("run_id") or "agent-lab-report", fallback="trace")
    if isinstance(data.get("traces"), list):
        return [item for item in data["traces"] if isinstance(item, dict)], warnings, _safe_label(data.get("run_id") or data.get("trace_id") or "trace-bundle", fallback="trace")
    if isinstance(data.get("trace"), dict):
        trace = data["trace"]
        return [trace], warnings, _safe_label(data.get("run_id") or data.get("trace_id") or trace.get("scenario_id") or "trace", fallback="trace")
    return [data], warnings, _safe_label(data.get("run_id") or data.get("trace_id") or data.get("scenario_id") or "trace", fallback="trace")


def _tool_name(item: dict[str, Any]) -> str:
    return str(item.get("tool") or item.get("name") or item.get("selected_tool") or "none")


def _tool_key(index: int, item: dict[str, Any]) -> str:
    return f"{index + 1}:{_safe_label(_tool_name(item), fallback='tool')}"


def _tool_value(item: dict[str, Any]) -> TraceValue:
    args = item.get("args") if "args" in item else item.get("selected_args", {})
    allowed = item.get("allowed_by_policy")
    flags = _flags_from_text(_tool_name(item), item.get("reason"), args)
    if allowed is False:
        flags.append("policy_denied")
    normalized = _normalize({"tool": _tool_name(item), "args": args, "allowed_by_policy": allowed, "reason": item.get("reason")})
    digest = _hash(normalized)
    args_keys = sorted(_safe_label(str(key), fallback="arg") for key in _safe_dict(args).keys())
    policy_state = "denied" if allowed is False else "allowed" if allowed is True else "unknown"
    return TraceValue(value_hash=digest, summary=f"tool={_safe_label(_tool_name(item), fallback='tool')} policy={policy_state} args={','.join(args_keys) or 'none'} hash={digest}", flags=sorted(set(flags)))


def _sequence_map(items: list[Any], prefix: str) -> dict[str, TraceValue]:
    result: dict[str, TraceValue] = {}
    for index, item in enumerate(items):
        if isinstance(item, dict):
            raw_name = item.get("name") or item.get("kind") or item.get("route") or item.get("path") or item.get("source") or index + 1
            name = _safe_label(raw_name, fallback=prefix)
            result[f"{index + 1}:{name}"] = _summarize_mapping(item, severity=_severity_from_raw(item), flags=_flags_from_text(raw_name, item.get("kind"), item.get("source")))
        else:
            normalized = _normalize(item)
            digest = _hash(normalized)
            result[f"{index + 1}:{prefix}"] = TraceValue(value_hash=digest, summary=f"hash={digest}", flags=_flags_from_text(item))
    return result


def _finding_map(items: list[Any]) -> dict[str, TraceValue]:
    result: dict[str, TraceValue] = {}
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        raw_key = item.get("finding_id") or item.get("id") or item.get("code") or item.get("title") or index + 1
        key = _safe_label(raw_key, fallback="finding")
        sanitized = {k: v for k, v in item.items() if k not in {"redacted_excerpts", "evidence_refs"}}
        result[key] = _summarize_mapping(sanitized, severity=_severity_from_raw(item), flags=_flags_from_text(item.get("title"), item.get("code"), item.get("technique")))
    return result


def _snapshot(data: dict[str, Any]) -> tuple[dict[str, dict[str, TraceValue]], list[str], str]:
    traces, warnings, trace_id = _trace_items(data)
    snap: dict[str, dict[str, TraceValue]] = {name: {} for name in ["tool_calls", "policy", "gates", "canaries", "approvals", "routes", "telemetry", "steps", "artifacts", "findings"]}
    for trace_index, trace in enumerate(traces):
        scenario = _safe_label(trace.get("scenario_id") or trace.get("id") or f"trace-{trace_index + 1}", fallback="scenario")
        decisions = _as_list(trace.get("observed_tool_decisions") or trace.get("tool_calls") or trace.get("tools"))
        if not decisions and trace.get("selected_tool") is not None:
            decisions = [{"selected_tool": trace.get("selected_tool"), "selected_args": trace.get("selected_args", {}), "allowed_by_policy": trace.get("passed"), "reason": trace.get("reason", "selected tool")}]
        for index, decision in enumerate(decisions):
            if isinstance(decision, dict):
                snap["tool_calls"][f"{scenario}:{_tool_key(index, decision)}"] = _tool_value(decision)
        policy = trace.get("policy_judgment") or trace.get("policy") or trace.get("policy_decision")
        if isinstance(policy, dict):
            snap["policy"][scenario] = _summarize_mapping(policy, severity=_severity_from_raw(policy), flags=_flags_from_text(policy.get("reason"), policy.get("violations"), policy.get("action")))
        gate = trace.get("gate_outcome") or trace.get("gate")
        if isinstance(gate, dict):
            snap["gates"][scenario] = _summarize_mapping(gate, flags=_flags_from_text(gate.get("status"), gate.get("reasons")))
        approval = trace.get("approval_state") or trace.get("approval")
        if isinstance(approval, dict):
            snap["approvals"][scenario] = _summarize_mapping(approval, flags=_flags_from_text(approval.get("status"), approval.get("action"), approval.get("source")))
        for name, field in [("canaries", "canary_violations"), ("routes", "routes"), ("telemetry", "telemetry"), ("steps", "steps"), ("artifacts", "artifact_writes")]:
            values = _as_list(trace.get(field))
            if name == "steps" and not values:
                values = decisions
            for key, value in _sequence_map(values, name).items():
                snap[name][f"{scenario}:{key}"] = value
        if isinstance(trace.get("artifacts"), dict):
            for key, value in trace["artifacts"].items():
                safe_key = _safe_label(key, fallback="artifact")
                snap["artifacts"][f"{scenario}:{safe_key}"] = _summarize_mapping({"artifact": key, "value": value}, flags=_flags_from_text(key))
    for key, value in _finding_map(_as_list(data.get("findings"))).items():
        snap["findings"][key] = value
    return snap, warnings, trace_id


def _raw_scenario_index(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    traces, _, _ = _trace_items(data)
    return {_safe_label(trace.get("scenario_id") or trace.get("id") or f"trace-{index + 1}", fallback="scenario"): trace for index, trace in enumerate(traces)}


def _policy_from(trace: dict[str, Any]) -> dict[str, Any]:
    return _safe_dict(trace.get("policy_judgment") or trace.get("policy") or trace.get("policy_decision"))


def _status(value: dict[str, Any], field: str) -> str | None:
    nested = value.get(field)
    if isinstance(nested, dict):
        for key in ("status", "action", "risk"):
            if key in nested:
                return str(nested[key])
    return None


def _worse_severity(old: str | None, new: str | None) -> bool:
    return _RISK_RANK.get(str(new), 0) > _RISK_RANK.get(str(old), 0)


def _severity_for(code: str, old: TraceValue | None, new: TraceValue | None) -> TraceSeverity:
    value = new or old
    flags = set(value.flags if value else [])
    explicit = value.severity if value else None
    if code in {"new_tool_call", "tool_args_changed"} and "critical_surface" in flags:
        return "critical"
    if code in {"new_tool_call", "tool_args_changed"} and "policy_denied" in flags:
        return "high"
    if code == "canary_regression":
        return "critical"
    if code == "new_telemetry":
        return "critical"
    if code == "approval_regression" and "critical_surface" in flags:
        return "critical"
    if code in {"approval_regression", "gate_regression", "policy_regression"}:
        return "high"
    if code == "finding_added" and explicit in {"high", "critical"}:
        return explicit
    if code in {"tool_args_changed", "new_tool_call", "removed_tool_call", "finding_added", "finding_removed"}:
        return "medium"
    return "low"


def _approval_changed_code(subject: str, old_raw: dict[str, dict[str, Any]], new_raw: dict[str, dict[str, Any]]) -> str:
    old_approval = _safe_dict(old_raw.get(subject, {}).get("approval_state") or old_raw.get(subject, {}).get("approval"))
    new_approval = _safe_dict(new_raw.get(subject, {}).get("approval_state") or new_raw.get(subject, {}).get("approval"))
    if old_approval.get("granted") is True and new_approval.get("granted") is False:
        return "approval_regression"
    if old_approval.get("required") is False and new_approval.get("required") is True and new_approval.get("granted") is not True:
        return "approval_regression"
    old_status = str(old_approval.get("status") or old_approval.get("action") or "").lower()
    new_status = str(new_approval.get("status") or new_approval.get("action") or "").lower()
    if old_status in {"approved", "allow", "pass"} and new_status in {"denied", "blocked", "fail", "quarantine"}:
        return "approval_regression"
    return "approval_changed"


def _changed_code(section: str, subject: str, old_raw: dict[str, dict[str, Any]], new_raw: dict[str, dict[str, Any]]) -> str:
    if section == "tool_calls":
        return "tool_args_changed"
    if section == "policy":
        old_policy = _policy_from(old_raw.get(subject, {}))
        new_policy = _policy_from(new_raw.get(subject, {}))
        if old_policy.get("passed") is True and new_policy.get("passed") is False:
            return "policy_regression"
        if _worse_severity(str(old_policy.get("risk")), str(new_policy.get("risk"))):
            return "policy_regression"
        old_action = str(old_policy.get("action") or "").lower()
        new_action = str(new_policy.get("action") or "").lower()
        if old_action in {"allow", "warn", "pass"} and new_action in {"quarantine", "block", "fail"}:
            return "policy_regression"
        return "policy_changed"
    if section == "gates":
        old_status = _status(_safe_dict(old_raw.get(subject, {})), "gate_outcome") or _status(_safe_dict(old_raw.get(subject, {})), "gate")
        new_status = _status(_safe_dict(new_raw.get(subject, {})), "gate_outcome") or _status(_safe_dict(new_raw.get(subject, {})), "gate")
        if _GATE_RANK.get(str(new_status), 0) > _GATE_RANK.get(str(old_status), 0):
            return "gate_regression"
        return "gate_changed"
    if section == "approvals":
        return _approval_changed_code(subject, old_raw, new_raw)
    if section == "artifacts":
        return "artifact_write_changed"
    if section == "steps":
        return "step_changed"
    return f"{section[:-1]}_changed"


def _added_removed_code(section: str, added: bool) -> str:
    if section == "tool_calls":
        return "new_tool_call" if added else "removed_tool_call"
    if section == "findings":
        return "finding_added" if added else "finding_removed"
    if section == "canaries":
        return "canary_regression" if added else "canary_removed"
    if section == "routes":
        return "new_route" if added else "removed_route"
    if section == "telemetry":
        return "new_telemetry" if added else "removed_telemetry"
    if section == "artifacts":
        return "artifact_write_changed"
    if section == "steps":
        return "step_count_changed"
    return f"{section[:-1]}_{'added' if added else 'removed'}"


def _regression_records(deltas: list[TraceDiffDelta]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for delta in deltas:
        if _SEVERITY_RANK[delta.severity] < _SEVERITY_RANK["high"]:
            continue
        records.append(
            {
                "source_type": "trace_diff",
                "code": delta.code,
                "severity": delta.severity,
                "title": f"{delta.code}: {delta.subject}",
                "regression_case_link": delta.subject,
                "redacted_excerpts": [value for value in [delta.old_value, delta.new_value] if value],
            }
        )
    return records


def diff_traces(old_trace_path: str | Path, new_trace_path: str | Path) -> TraceDiffReport:
    old_path = Path(old_trace_path)
    new_path = Path(new_trace_path)
    old_data = _load_json(old_path)
    new_data = _load_json(new_path)
    old_snap, old_warnings, old_id = _snapshot(old_data)
    new_snap, new_warnings, new_id = _snapshot(new_data)
    old_raw = _raw_scenario_index(old_data)
    new_raw = _raw_scenario_index(new_data)
    deltas: list[TraceDiffDelta] = []
    for section in sorted(old_snap):
        old_items = old_snap[section]
        new_items = new_snap[section]
        for subject in sorted(set(old_items) | set(new_items)):
            old = old_items.get(subject)
            new = new_items.get(subject)
            if old and new and old.value_hash == new.value_hash:
                continue
            if old is None:
                code = _added_removed_code(section, True)
                if section == "approvals":
                    approval = _safe_dict(new_raw.get(subject, {}).get("approval_state") or new_raw.get(subject, {}).get("approval"))
                    if approval.get("required") is True and approval.get("granted") is not True:
                        code = "approval_regression"
            elif new is None:
                code = _added_removed_code(section, False)
                if section == "approvals":
                    approval = _safe_dict(old_raw.get(subject, {}).get("approval_state") or old_raw.get(subject, {}).get("approval"))
                    if approval.get("granted") is True or approval.get("required") is True:
                        code = "approval_regression"
            else:
                code = _changed_code(section, subject, old_raw, new_raw)
            severity = _severity_for(code, old, new)
            deltas.append(
                TraceDiffDelta(
                    code=code,
                    severity=severity,
                    subject=subject,
                    old_value=old.summary if old else None,
                    new_value=new.summary if new else None,
                    details={"section": section},
                )
            )
    counts = Counter(delta.severity for delta in deltas)
    regressions = sum(1 for delta in deltas if _SEVERITY_RANK[delta.severity] >= _SEVERITY_RANK["high"])
    return TraceDiffReport(
        old_trace_id=old_id,
        new_trace_id=new_id,
        old_path=_safe_path(old_path),
        new_path=_safe_path(new_path),
        summary=TraceDiffSummary(
            total_deltas=len(deltas),
            regressions=regressions,
            critical=counts["critical"],
            high=counts["high"],
            medium=counts["medium"],
            low=counts["low"],
            info=counts["info"],
            warnings=[_safe_label(warning, fallback="warning") for warning in old_warnings + new_warnings],
        ),
        deltas=deltas,
        regression_records=_regression_records(deltas),
    )


def render_trace_diff_markdown(report: TraceDiffReport) -> str:
    lines = [
        "# Malleus trace diff",
        "",
        f"- Old trace: {_md_text(report.old_trace_id)}",
        f"- New trace: {_md_text(report.new_trace_id)}",
        f"- Total deltas: {report.summary.total_deltas}",
        f"- High/Critical regressions: {report.summary.regressions}",
        f"- Critical: {report.summary.critical}",
        f"- High: {report.summary.high}",
        "",
    ]
    if report.summary.warnings:
        lines.extend(["## Warnings", ""])
        for warning in report.summary.warnings:
            lines.append(f"- {_md_text(warning)}")
        lines.append("")
    if not report.deltas:
        lines.extend(["No behavioral trace deltas detected.", ""])
        return "\n".join(lines).rstrip() + "\n"
    lines.extend(["## Deltas", "", "| Severity | Code | Subject | Old | New |", "|---|---|---|---|---|"])
    for delta in report.deltas:
        lines.append(f"| {_md_text(delta.severity)} | {_md_text(delta.code)} | {_md_text(delta.subject)} | {_md_text(delta.old_value or 'n/a')} | {_md_text(delta.new_value or 'n/a')} |")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def write_trace_diff_report(report: TraceDiffReport, output_dir: str | Path) -> tuple[Path, Path]:
    destination = Path(output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    json_path = destination / "trace-diff-report.json"
    markdown_path = destination / "trace-diff-report.md"
    json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    markdown_path.write_text(render_trace_diff_markdown(report), encoding="utf-8")
    return json_path, markdown_path
