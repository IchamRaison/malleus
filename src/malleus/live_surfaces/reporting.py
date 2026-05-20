from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from malleus.live_evidence import LiveEvidenceMatrix, LiveEvidenceRow, LiveTargetMetadata
from malleus.live_surfaces.common import sanitize_metadata
from malleus.reporting import _md_safe
from malleus.surface_names import public_surface_name
from malleus.utils.redact import redact_public_text


CANONICAL_LEGACY_STATUS_VALUES = {"not_supported", "not_implemented"}
CANONICAL_LEGACY_EVIDENCE_LEVELS = {"not_supported", "not_implemented"}
LIVE_MODEL_EVIDENCE_LEVELS = {"live_text_model", "live_multimodal_model"}
LIVE_SYSTEM_EVIDENCE_LEVELS = {"live_system", "live_system_trace"}
PROVIDER_OPERATIONAL_STATUSES = {"provider_error", "timeout", "infra_error"}
CAPABILITY_GAP_STATUSES = {"provider_capability_gap", "target_capability_gap"}
TARGET_ERROR_STATUSES = {"target_config_error", "target_error"}
NON_BEHAVIOR_STATUSES = PROVIDER_OPERATIONAL_STATUSES | CAPABILITY_GAP_STATUSES | TARGET_ERROR_STATUSES | {"skipped_by_operator", "checkpoint_not_run", "preflight_failed", "skipped_by_flag", "not_supported", "not_implemented"}


def write_full_benchmark_reports(evidence: LiveEvidenceMatrix, out_dir: str | Path) -> dict[str, Path]:
    destination = Path(out_dir)
    destination.mkdir(parents=True, exist_ok=True)
    matrix = aggregate_matrix_payload(evidence, destination)
    paths = {
        "matrix_json": destination / "FULL_BENCHMARK_MATRIX.json",
        "matrix_markdown": destination / "FULL_BENCHMARK_MATRIX.md",
        "summary": destination / "FULL_BENCHMARK_SUMMARY.md",
        "command_log": destination / "COMMAND_LOG.md",
        "provider_errors": destination / "PROVIDER_ERRORS.md",
        "model_failures": destination / "MODEL_FAILURES.md",
        "model_failure_triage_json": destination / "MODEL_FAILURE_TRIAGE.json",
        "model_failure_triage_markdown": destination / "MODEL_FAILURE_TRIAGE.md",
        "run_quality": destination / "RUN_QUALITY.md",
        "server_diagnostics": destination / "SERVER_DIAGNOSTICS.md",
    }
    triage = model_failure_triage_payload(matrix)
    paths["matrix_json"].write_text(json.dumps(matrix, indent=2) + "\n", encoding="utf-8")
    paths["matrix_markdown"].write_text(render_full_matrix_markdown(matrix), encoding="utf-8")
    paths["summary"].write_text(render_full_summary_markdown(matrix), encoding="utf-8")
    paths["command_log"].write_text(render_command_log_markdown(matrix), encoding="utf-8")
    paths["provider_errors"].write_text(render_provider_errors_markdown(matrix), encoding="utf-8")
    paths["model_failures"].write_text(render_model_failures_markdown(matrix), encoding="utf-8")
    paths["model_failure_triage_json"].write_text(json.dumps(triage, indent=2) + "\n", encoding="utf-8")
    paths["model_failure_triage_markdown"].write_text(render_model_failure_triage_markdown(triage), encoding="utf-8")
    paths["run_quality"].write_text(render_run_quality_markdown(matrix), encoding="utf-8")
    paths["server_diagnostics"].write_text(render_server_diagnostics_markdown(matrix), encoding="utf-8")
    return paths


def invalid_live_artifact_rows(evidence: LiveEvidenceMatrix) -> list[LiveEvidenceRow]:
    return [row for row in evidence.rows if row.metadata.get("invalid_live_artifact") is True]


def render_live_full_markdown(evidence: LiveEvidenceMatrix) -> str:
    metadata = evidence.metadata
    lines = [
        "# Malleus live-full evidence matrix",
        "",
        f"- Matrix: {_md_safe(evidence.matrix_id)}",
        f"- Target: {_md_safe(metadata.get('target_name', 'unknown'))}",
        f"- Dry run: {str(metadata.get('dry_run', False)).lower()}",
        f"- Provider calls enabled: {str(metadata.get('provider_calls_enabled', True)).lower()}",
        f"- Rows: {len(evidence.rows)}",
        "",
        "This artifact records the live-full evidence matrix for the configured target, including live/provider evidence, real-system trace evidence, capability gaps, target/config errors, and checkpoint rows. Dry-run, scaffold, static, fixture, and provider-free artifacts cannot satisfy live evidence claims.",
        "",
        "## Evidence rows",
        "",
        "| Row | Surface | Status | Live calls | Reason |",
        "|---|---|---:|---:|---|",
    ]
    for row in evidence.rows:
        lines.append(f"| `{_md_safe(row.row_id)}` | `{_md_safe(row.surface_id)}` | {_md_safe(row.status)} | {row.live_model_calls or 0} | {_md_safe(row.reason or '')} |")
    return "\n".join(lines).rstrip() + "\n"


def aggregate_matrix_payload(evidence: LiveEvidenceMatrix, out_dir: Path) -> dict[str, Any]:
    rows = [_aggregate_row(row, out_dir) for row in evidence.rows]
    _assert_final_canonical_rows(rows)
    status_counts: dict[str, int] = {}
    evidence_counts: dict[str, int] = {}
    fidelity_counts: dict[str, int] = {}
    verdict_layer_counts: dict[str, int] = {}
    for row in rows:
        status_counts[row["status"]] = status_counts.get(row["status"], 0) + 1
        evidence_counts[row["evidence_level"]] = evidence_counts.get(row["evidence_level"], 0) + 1
        fidelity_counts[row["evidence_fidelity"]] = fidelity_counts.get(row["evidence_fidelity"], 0) + 1
        verdict_layer_counts[row["verdict_layer"]] = verdict_layer_counts.get(row["verdict_layer"], 0) + 1
    preflight = _final_report_value(sanitize_metadata(evidence.metadata.get("preflight", {})))
    quality_scores = _run_quality_scores(rows)
    return sanitize_metadata(
        {
            "schema_version": "malleus.full_benchmark_matrix.v1",
            "benchmark_mode": evidence.metadata.get("benchmark_mode", "live-full"),
            "exhaustive": bool(evidence.metadata.get("exhaustive", False)),
            "matrix_id": evidence.matrix_id,
            "matrix_path": evidence.metadata.get("matrix_path"),
            "generated_at": evidence.generated_at,
            "target": {
                "name": evidence.metadata.get("target_name", "unknown"),
                "adapter": evidence.metadata.get("target_adapter", "unknown"),
                "model": evidence.metadata.get("target_model", "unknown"),
                "endpoint": preflight.get("endpoint", {}) if isinstance(preflight, dict) else {},
            },
            "dry_run": False,
            "provider_calls_enabled": bool(evidence.metadata.get("provider_calls_enabled", True)),
            "git_commit": evidence.metadata.get("git_commit", "unknown"),
            "operator_confirmed": bool(evidence.metadata.get("operator_confirmed", False)),
            "include_deep_mutations": bool(evidence.metadata.get("include_deep_mutations", False)),
            "unsupported_surfaces_explicit": bool(evidence.metadata.get("unsupported_surfaces_explicit", True)),
            "deferred_surfaces_explicit": bool(evidence.metadata.get("deferred_surfaces_explicit", True)),
            "status_counts": status_counts,
            "evidence_level_counts": evidence_counts,
            "evidence_fidelity_counts": fidelity_counts,
            "verdict_layer_counts": verdict_layer_counts,
            "run_quality": {
                "high_fidelity_passes": sum(1 for row in rows if row["status"] == "passed" and not row.get("low_fidelity") and not row.get("coverage_gap")),
                "low_fidelity_passes": sum(1 for row in rows if row["status"] == "passed" and row.get("low_fidelity")),
                "model_failures": sum(1 for row in rows if row.get("model_behavior_failure")),
                "harness_failures": sum(1 for row in rows if row.get("harness_failure")),
                "provider_gaps": sum(1 for row in rows if row["status"] == "provider_capability_gap"),
                "capability_gaps": sum(1 for row in rows if row.get("coverage_gap")),
                "suspected_false_positives": sum(1 for row in rows if row.get("metadata", {}).get("suspected_false_positive") is True),
                **quality_scores,
            },
            "live_model_calls": sum(int(row["live_model_calls"] or 0) for row in rows),
            "direct_model_calls": sum(int(row.get("direct_model_calls") or 0) for row in rows),
            "backing_model_calls": sum(int(row.get("backing_model_calls") or 0) for row in rows),
            "system_trace_items": sum(int(row.get("system_trace_items") or 0) for row in rows),
            "system_artifact_count": sum(int(row.get("system_artifact_count") or 0) for row in rows),
            "total_rows": len(rows),
            "live_rows": sum(1 for row in rows if row["evidence_level"] in LIVE_MODEL_EVIDENCE_LEVELS and row["live_model_calls"] > 0),
            "preflight": preflight,
            "rows": rows,
        }
    )


def _run_quality_scores(rows: list[dict[str, Any]]) -> dict[str, Any]:
    behavioral_rows = [row for row in rows if not row.get("coverage_gap") and not row.get("harness_failure") and row.get("status") not in {"provider_capability_gap", "target_capability_gap"}]
    high_fidelity_rows = [
        row
        for row in behavioral_rows
        if not row.get("low_fidelity") and str(row.get("evidence_fidelity") or "").startswith(("live_", "controlled_"))
    ]
    real_agent_rows = [row for row in high_fidelity_rows if row.get("target_type") not in {"chat_completion", "vision_model"}]
    covered_rows = [row for row in rows if not row.get("coverage_gap") and row.get("status") not in {"provider_capability_gap", "target_capability_gap"}]
    return {
        "model_score": _percent(sum(1 for row in behavioral_rows if row.get("status") == "passed"), len(behavioral_rows)),
        "real_agent_score": _percent(sum(1 for row in real_agent_rows if row.get("status") == "passed"), len(real_agent_rows)),
        "coverage_score": _percent(len(covered_rows), len(rows)),
        "fidelity_score": _percent(len(high_fidelity_rows), len(behavioral_rows)),
        "score_denominators": {
            "model_rows": len(behavioral_rows),
            "real_agent_rows": len(real_agent_rows),
            "coverage_rows": len(rows),
            "fidelity_rows": len(behavioral_rows),
        },
    }


def _percent(numerator: int, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return round((numerator / denominator) * 100.0, 2)


def _aggregate_row(row: LiveEvidenceRow, out_dir: Path) -> dict[str, Any]:
    metadata = _final_report_value(sanitize_metadata(row.metadata))
    status_counts = metadata.get("status_counts") if isinstance(metadata, dict) else None
    scenario_counts = metadata.get("scenario_counts") if isinstance(metadata, dict) else None
    report_path = _row_report_path(row, metadata)
    reason_codes = _row_reason_codes(row, metadata)
    live_calls = int(row.live_model_calls or 0)
    direct_model_calls = live_calls
    backing_model_calls = int(metadata.get("backing_model_calls") or 0) if isinstance(metadata, dict) else 0
    system_target_calls = int(metadata.get("target_call_count") or 0) if isinstance(metadata, dict) else 0
    system_trace_items = int(metadata.get("target_trace_count") or 0) if isinstance(metadata, dict) else 0
    system_artifact_count = int(metadata.get("target_artifact_count") or 0) if isinstance(metadata, dict) else 0
    evidence_call_summary = (
        f"direct_model_calls={direct_model_calls}; "
        f"backing_model_calls={backing_model_calls}; "
        f"system_trace_items={system_trace_items}; "
        f"system_artifacts={system_artifact_count}"
    )
    target_type = row_target_type(row.target)
    evidence_type = _row_evidence_type(row)
    evidence_fidelity = str(getattr(row, "evidence_fidelity", "") or metadata.get("evidence_fidelity") or "")
    verdict_layer = _row_verdict_layer(row, evidence_fidelity=evidence_fidelity, metadata=metadata)
    low_fidelity = evidence_fidelity == "auto_wrapper_trace"
    harness_failure = row.status in TARGET_ERROR_STATUSES or bool(_harness_suspect_reason_codes(metadata))
    coverage_gap = row.status in CAPABILITY_GAP_STATUSES or row.status in {"checkpoint_not_run", "skipped_by_operator", "skipped_by_flag", "not_supported", "not_implemented", "preflight_failed"}
    surface_name = _row_surface_name(row, metadata)
    return sanitize_metadata(
        {
            "row_id": row.row_id,
            "surface": row.surface_id,
            "surface_name": surface_name,
            "runner": _row_runner(row, metadata),
            "evidence_level": row.evidence_level,
            "evidence_fidelity": evidence_fidelity,
            "evidence_type": evidence_type,
            "live_evidence_category": evidence_type,
            "verdict_layer": verdict_layer,
            "low_fidelity": low_fidelity,
            "model_behavior_failure": _live_row_is_model_behavior_failure(row),
            "harness_failure": harness_failure,
            "coverage_gap": coverage_gap,
            "target_type": target_type,
            "live_model_calls": live_calls,
            "direct_model_calls": direct_model_calls,
            "backing_model_calls": backing_model_calls,
            "system_target_calls": system_target_calls,
            "system_trace_items": system_trace_items,
            "system_artifact_count": system_artifact_count,
            "evidence_call_summary": evidence_call_summary,
            "dry_run": row.dry_run,
            "provider_calls_enabled": row.provider_calls_enabled,
            "status": row.status,
            "pass": row.status == "passed",
            "fail": row.status == "failed",
            "provider_error": row.status in PROVIDER_OPERATIONAL_STATUSES,
            "provider_capability_gap": row.status == "provider_capability_gap",
            "target_capability_gap": row.status == "target_capability_gap",
            "target_config_error": row.status == "target_config_error",
            "target_error": row.status == "target_error",
            "skipped_by_operator": row.status in {"skipped_by_operator", "skipped_by_flag"},
            "checkpoint_not_run": row.status == "checkpoint_not_run",
            "capability_gap": row.status in CAPABILITY_GAP_STATUSES,
            "target_or_config_error": row.status in TARGET_ERROR_STATUSES,
            "operational_or_coverage_outcome": row.status in NON_BEHAVIOR_STATUSES,
            "report_path": report_path,
            "report_paths": _row_report_paths(row, report_path),
            "git_commit": row.git_commit,
            "reason": _final_report_value(row.reason),
            "reason_codes": reason_codes,
            "harness_suspect": bool(_harness_suspect_reason_codes(metadata)),
            "harness_suspect_reason_codes": _harness_suspect_reason_codes(metadata),
            "response_evidence": _row_response_evidence(row, out_dir, report_path),
            "status_counts": status_counts if isinstance(status_counts, dict) else scenario_counts if isinstance(scenario_counts, dict) else {},
            "metadata": metadata,
            "target": row.target.model_dump(mode="json"),
            "target_metadata": {"target_type": target_type, "evidence_type": evidence_type},
            "adapter": row.target.adapter,
            "model": row.target.model,
            "endpoint": row.target.base_url,
            "command": redact_public_text(row.command).text,
            "reproduction_command": redact_public_text(row.command).text,
        }
    )


def _row_verdict_layer(row: LiveEvidenceRow, *, evidence_fidelity: str, metadata: dict[str, Any]) -> str:
    if evidence_fidelity == "auto_wrapper_trace":
        return "low_fidelity"
    if row.status in CAPABILITY_GAP_STATUSES:
        return "capability_gap"
    if row.status in TARGET_ERROR_STATUSES or bool(_harness_suspect_reason_codes(metadata)):
        return "harness"
    if row.status in PROVIDER_OPERATIONAL_STATUSES:
        return "provider"
    if row.status == "failed":
        return "model"
    if row.status == "passed":
        return "model" if row.evidence_level in LIVE_MODEL_EVIDENCE_LEVELS else "agent"
    return "coverage"


def row_target_type(target: LiveTargetMetadata) -> str:
    value = target.metadata.get("target_type") if isinstance(target.metadata, dict) else None
    return str(value or "chat_completion")


def human_surface_name(identifier: str) -> str:
    return public_surface_name(identifier)


def _row_surface_name(row: LiveEvidenceRow, metadata: Any) -> str:
    if isinstance(metadata, dict):
        value = metadata.get("surface_name") or metadata.get("profile_name")
        if isinstance(value, str) and value.strip():
            return value.strip()
    return human_surface_name(row.surface_id)


def _surface_display(row: dict[str, Any]) -> str:
    value = row.get("surface_name")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return human_surface_name(str(row.get("surface") or "surface"))


def _assert_final_canonical_rows(rows: list[dict[str, Any]]) -> None:
    for row in rows:
        status = row.get("status")
        evidence_level = row.get("evidence_level")
        if status in CANONICAL_LEGACY_STATUS_VALUES:
            raise ValueError(f"final canonical live-full row {row.get('row_id') or row.get('surface')} uses legacy status {status}")
        if evidence_level in CANONICAL_LEGACY_EVIDENCE_LEVELS:
            raise ValueError(f"final canonical live-full row {row.get('row_id') or row.get('surface')} uses legacy evidence_level {evidence_level}")
        if "not_supported" in row or "not_implemented" in row:
            raise ValueError(f"final canonical live-full row {row.get('row_id') or row.get('surface')} uses legacy boolean fields")


def _final_report_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _final_report_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_final_report_value(item) for item in value]
    if isinstance(value, str):
        return final_report_text(value)
    return value


def final_report_text(value: str) -> str:
    return value.replace("not_supported", "provider_capability_gap").replace("not_implemented", "target_capability_gap")


def final_preflight_status_label(value: str | None) -> str:
    if value == "not_supported" or value is None:
        return "provider_capability_gap"
    if value == "not_implemented":
        return "target_capability_gap"
    return value


def _row_runner(row: LiveEvidenceRow, metadata: dict[str, Any]) -> str:
    output_dir = str(metadata.get("output_dir", ""))
    if row.row_id.startswith("mutation-profile:"):
        return "mutate-run"
    if output_dir.startswith("classic/"):
        return "malleus run"
    if output_dir.startswith("agent-lab/"):
        return "agent-lab"
    if output_dir.startswith("rag/"):
        return "rag-live"
    if output_dir.startswith("rag-service/"):
        return "rag-service-harness"
    if output_dir.startswith("tool-agent/"):
        return "tool-agent-harness"
    if output_dir.startswith("workflow-harness/"):
        return "workflow-harness"
    if output_dir.startswith("code-agent/"):
        return "code-agent-harness"
    if output_dir.startswith("self-modification-tool-agent/"):
        return "tool-agent-harness"
    if output_dir.startswith("self-modification-workflow/"):
        return "workflow-harness"
    if output_dir.startswith("self-modification-code-agent/"):
        return "code-agent-harness"
    if output_dir.startswith("hidden-artifact/"):
        return "hidden-artifact-live"
    if output_dir.startswith("ui-action/"):
        return "ui-action-live"
    if output_dir.startswith("campaign/"):
        return "campaign-live"
    if output_dir.startswith("visual/"):
        return "visual-live"
    return "classification"


def _row_evidence_type(row: LiveEvidenceRow) -> str:
    if row.evidence_level == "live_multimodal_model" or row.surface_id in {"pack:visual-ocr-matrix"}:
        return "multimodal_model_evidence"
    if row.evidence_level == "live_text_model":
        return "chat_model_evidence"
    if row.evidence_level in LIVE_SYSTEM_EVIDENCE_LEVELS:
        return "live_system_evidence"
    if row.evidence_level == "scaffold_static":
        return "coverage_boundary_evidence"
    return "coverage_boundary_evidence"


def _row_report_path(row: LiveEvidenceRow, metadata: dict[str, Any]) -> str | None:
    value = metadata.get("report_json")
    if isinstance(value, str) and value:
        return value
    output_dir = metadata.get("output_dir")
    for artifact in row.artifacts:
        artifact_path = artifact.relative_path or artifact.path
        if not artifact_path:
            continue
        if output_dir:
            return f"{output_dir}/{artifact_path}"
        return artifact_path
    return None


def _row_report_paths(row: LiveEvidenceRow, report_path: str | None) -> list[str]:
    paths = [report_path] if report_path else []
    for artifact in row.artifacts:
        candidate = artifact.relative_path or artifact.path
        if candidate and candidate not in paths:
            paths.append(candidate)
    return [sanitize_metadata(path) for path in paths]


def _row_reason_codes(row: LiveEvidenceRow, metadata: dict[str, Any]) -> list[str]:
    value = metadata.get("reason_codes")
    if isinstance(value, list):
        return [sanitize_metadata(item) for item in value]
    if isinstance(value, dict):
        return [sanitize_metadata(key) for key, count in value.items() if count]
    if row.status == "provider_error":
        return ["provider_error"]
    if row.status == "timeout":
        return ["timeout"]
    if row.status == "infra_error":
        return ["infra_error"]
    if row.status == "failed":
        return ["model_behavior_failure"]
    return []


def _harness_suspect_reason_codes(metadata: dict[str, Any]) -> list[str]:
    value = metadata.get("harness_suspect_reason_codes")
    if isinstance(value, list):
        return [sanitize_metadata(item) for item in value if str(item)]
    if isinstance(value, str) and value:
        return [sanitize_metadata(value)]
    return []


def _row_response_evidence(row: LiveEvidenceRow, out_dir: Path, report_path: str | None) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    if row.response_summary is not None:
        summary = row.response_summary.model_dump(mode="json")
        evidence.append(
            sanitize_metadata(
                {
                    "source": "live_evidence_row",
                    "sha256": summary.get("sha256"),
                    "length": summary.get("length"),
                    "redacted_excerpt": summary.get("redacted_excerpt"),
                }
            )
        )
    if report_path:
        path = (out_dir / report_path).resolve()
        try:
            if path.is_file() and path.is_relative_to(out_dir.resolve()):
                payload = json.loads(path.read_text(encoding="utf-8"))
                evidence.extend(_extract_response_evidence(payload, source=report_path))
        except Exception:
            return evidence
    return evidence[:20]


def _extract_response_evidence(value: Any, *, source: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(value, dict):
        sha_value = value.get("response_sha256") or value.get("answer_sha256") or value.get("original_response_sha256") or value.get("mutated_response_sha256")
        excerpt = value.get("response_excerpt") or value.get("redacted_excerpt")
        if isinstance(sha_value, str):
            found.append(
                sanitize_metadata(
                    {
                        "source": source,
                        "sha256": sha_value,
                        "length": value.get("response_length") or value.get("length"),
                        "redacted_excerpt": excerpt,
                    }
                )
            )
        for item in value.values():
            found.extend(_extract_response_evidence(item, source=source))
    elif isinstance(value, list):
        for item in value:
            found.extend(_extract_response_evidence(item, source=source))
    return found[:20]


def render_full_matrix_markdown(matrix: dict[str, Any]) -> str:
    controlled_lab_rows = [
        row
        for row in matrix.get("rows", [])
        if str(row.get("evidence_fidelity") or "").startswith("controlled_") or bool((row.get("metadata") or {}).get("controlled_lab"))
    ]
    lines = [
        "# Full benchmark matrix",
        "",
        f"- Matrix: {_md_safe(matrix.get('matrix_id', 'unknown'))}",
        f"- Generated: {_md_safe(matrix.get('generated_at', 'unknown'))}",
        f"- Dry run: {str(matrix.get('dry_run', False)).lower()}",
        f"- Provider calls enabled: {str(matrix.get('provider_calls_enabled', True)).lower()}",
        f"- Live model calls: {int(matrix.get('live_model_calls') or 0)}",
        f"- Direct model calls: {int(matrix.get('direct_model_calls') or 0)}",
        f"- Backing model calls reported by system harnesses: {int(matrix.get('backing_model_calls') or 0)}",
        f"- System trace items: {int(matrix.get('system_trace_items') or 0)}",
        f"- System artifacts: {int(matrix.get('system_artifact_count') or 0)}",
        f"- Evidence fidelity counts: `{_md_safe(json.dumps(matrix.get('evidence_fidelity_counts', {}), sort_keys=True))}`",
        f"- Verdict layer counts: `{_md_safe(json.dumps(matrix.get('verdict_layer_counts', {}), sort_keys=True))}`",
        f"- Lab benchmark controlled by Malleus: {len(controlled_lab_rows)} controlled system rows.",
        "",
        "`direct_model_calls` are direct chat/multimodal model calls on the row. `backing_model_calls` are provider calls reported inside system harness metadata. `system_trace_items` and `system_artifact_count` show live system/scaffold evidence when direct model calls are intentionally zero.",
        "",
        "`controlled_*_trace` means the run used a Malleus-controlled lab surface, not production coverage. Production coverage requires the user to expose their own compatible target endpoint.",
        "",
        "| Surface | ID | Runner | Target type | Fidelity | Verdict layer | Evidence | Status | Direct calls | Backing calls | Trace items | Artifacts | Report | Reason codes |",
        "|---|---|---|---|---|---|---|---|---:|---:|---:|---:|---|---|",
    ]
    for row in matrix["rows"]:
        lines.append(f"| {_md_safe(_surface_display(row))} | `{_md_safe(row['surface'])}` | {_md_safe(row['runner'])} | {_md_safe(row.get('target_type') or 'chat_completion')} | {_md_safe(row.get('evidence_fidelity') or '')} | {_md_safe(row.get('verdict_layer') or '')} | {_md_safe(row['evidence_level'])} | {_md_safe(row['status'])} | {int(row.get('direct_model_calls') or row.get('live_model_calls') or 0)} | {int(row.get('backing_model_calls') or 0)} | {int(row.get('system_trace_items') or 0)} | {int(row.get('system_artifact_count') or 0)} | {_md_safe(row.get('report_path') or '')} | {_md_safe(', '.join(row.get('reason_codes') or []))} |")
    return "\n".join(lines).rstrip() + "\n"


def render_full_summary_markdown(matrix: dict[str, Any]) -> str:
    rows = matrix["rows"]
    live_rows = [row for row in rows if row["evidence_level"] in LIVE_MODEL_EVIDENCE_LEVELS and row["live_model_calls"] > 0]
    system_rows = [row for row in rows if row["evidence_level"] in LIVE_SYSTEM_EVIDENCE_LEVELS]
    controlled_lab_rows = [
        row
        for row in system_rows
        if str(row.get("evidence_fidelity") or "").startswith("controlled_") or bool((row.get("metadata") or {}).get("controlled_lab"))
    ]
    gap_rows = [row for row in rows if row.get("capability_gap") or row.get("target_or_config_error") or row.get("skipped_by_operator") or row.get("checkpoint_not_run")]
    visual_rows = [row for row in rows if row["surface"] == "pack:visual-ocr-matrix"]
    agent_trace_rows = [row for row in rows if row_agent_trace_summary(row).get("total_traces")]
    provider_rows = provider_error_rows(matrix)
    failure_rows = model_failure_rows(matrix)
    lines = [
        "# Full benchmark summary",
        "",
        f"Model `{_md_safe((matrix.get('target') or {}).get('model', 'unknown'))}` on adapter `{_md_safe((matrix.get('target') or {}).get('adapter', 'unknown'))}` produced {int(matrix.get('live_model_calls') or 0)} live model calls across {len(rows)} matrix rows. Provider calls were enabled and `dry_run` was false for the aggregate run.",
        "",
        f"Lab benchmark controlled by Malleus: {len(controlled_lab_rows)} system rows used controlled lab evidence. These rows are valid Malleus lab benchmark evidence, not production coverage of a user's deployed stack.",
        "",
        "## 1. Which surfaces had live chat or multimodal model evidence?",
        _bullet_rows(live_rows, include_calls=True) or "- None.",
        "",
        "## 2. Which surfaces had live system trace evidence?",
        _bullet_rows(system_rows, include_reason=True) or "- None.",
        "",
        "## 3. Which surfaces had explicit capability, configuration, target, checkpoint, or operator-skip outcomes?",
        _bullet_rows(gap_rows, include_reason=True) or "- None.",
        "",
        "System `target_capability_gap` rows are coverage outcomes, not model failures. They require compatible `code_agent`, `tool_agent`, or `workflow_harness` targets for system-surface coverage.",
        "",
        "## 4. What was the visual probe outcome?",
        _bullet_rows(visual_rows, include_reason=True, include_calls=True) or "- No visual surface row was present.",
        "",
        "## 5. Were there provider, timeout, infrastructure, or server errors?",
        _bullet_rows(provider_rows, include_reason=True) or "- None.",
        "",
        "## 6. Were there deterministic model behavior failures?",
        _bullet_rows(failure_rows, include_reason=True, include_codes=True) or "- None.",
        "",
        "## 7. Which system surfaces produced canonical AgentTrace evidence?",
        _bullet_agent_trace_rows(agent_trace_rows) or "- None.",
        "",
        "## 8. How can this run be reproduced?",
        "- See `COMMAND_LOG.md` for sanitized reproduction commands. The same commands are also present per row in `FULL_BENCHMARK_MATRIX.json`.",
        "- See `RUN_QUALITY.md` to separate model failures from operational outcomes and weak harness evidence.",
    ]
    return "\n".join(lines).rstrip() + "\n"


def render_command_log_markdown(matrix: dict[str, Any]) -> str:
    lines = ["# Command log", "", "All commands are sanitized for public artifacts.", "", "| Surface | ID | Runner | Reproduction command |", "|---|---|---|---|"]
    seen: set[tuple[str, str]] = set()
    for row in matrix["rows"]:
        key = (row["surface"], row["reproduction_command"])
        if key in seen:
            continue
        seen.add(key)
        lines.append(f"| {_md_safe(_surface_display(row))} | `{_md_safe(row['surface'])}` | {_md_safe(row['runner'])} | `{_md_safe(row['reproduction_command'])}` |")
    return "\n".join(lines).rstrip() + "\n"


def render_provider_errors_markdown(matrix: dict[str, Any]) -> str:
    rows = provider_error_rows(matrix)
    lines = ["# Provider and infrastructure errors", "", "Provider errors, timeouts, and infrastructure errors are operational run conditions, not model behavior findings.", ""]
    return _render_row_table(lines, rows, empty="No provider, timeout, or infrastructure error rows were recorded.")


def render_model_failures_markdown(matrix: dict[str, Any]) -> str:
    rows = model_failure_rows(matrix)
    lines = ["# Model behavior failures", "", "Rows here completed live model calls and failed deterministic scoring or policy checks.", ""]
    return _render_row_table(lines, rows, empty="No deterministic model behavior failures were recorded.")


def render_run_quality_markdown(matrix: dict[str, Any]) -> str:
    rows = matrix["rows"]
    model_rows = model_failure_rows(matrix)
    system_rows = [row for row in rows if row.get("evidence_level") in LIVE_SYSTEM_EVIDENCE_LEVELS and row.get("status") == "failed"]
    harness_suspect_rows = [row for row in rows if row.get("harness_suspect")]
    low_fidelity_rows = [row for row in rows if row.get("low_fidelity")]
    operational_rows = [row for row in rows if row.get("operational_or_coverage_outcome")]
    run_quality = matrix.get("run_quality") if isinstance(matrix.get("run_quality"), dict) else {}
    lines = [
        "# Run quality triage",
        "",
        "This file separates model behavior findings from operational, capability, and harness-quality outcomes. A passed row with weak evidence should not be marketed as a full behavioral verdict.",
        "",
        "## Summary",
        f"- Model score: {_score_text(run_quality.get('model_score'))}",
        f"- Real-agent score: {_score_text(run_quality.get('real_agent_score'))}",
        f"- Coverage score: {_score_text(run_quality.get('coverage_score'))}",
        f"- Fidelity score: {_score_text(run_quality.get('fidelity_score'))}",
        f"- High-fidelity passes: {int(run_quality.get('high_fidelity_passes') or 0)}",
        f"- Low-fidelity passes: {int(run_quality.get('low_fidelity_passes') or 0)}",
        f"- Model failures: {int(run_quality.get('model_failures') or 0)}",
        f"- Harness failures: {int(run_quality.get('harness_failures') or 0)}",
        f"- Provider gaps: {int(run_quality.get('provider_gaps') or 0)}",
        f"- Capability/coverage gaps: {int(run_quality.get('capability_gaps') or 0)}",
        f"- Suspected false positives: {int(run_quality.get('suspected_false_positives') or 0)}",
        "",
        "## Model behavior failures",
        _bullet_rows(model_rows, include_reason=True, include_codes=True) or "- None.",
        "",
        "## System trace findings",
        _bullet_rows(system_rows, include_reason=True, include_codes=True) or "- None.",
        "",
        "## Low-fidelity auto-wrapper passes",
        _bullet_rows(low_fidelity_rows, include_reason=True, include_codes=True) or "- None.",
        "",
        "## Harness suspect or weak-evidence rows",
        _bullet_rows(harness_suspect_rows, include_reason=True, include_codes=True) or "- None.",
        "",
        "## Operational and coverage outcomes",
        _bullet_rows(operational_rows, include_reason=True, include_codes=True) or "- None.",
    ]
    return "\n".join(lines).rstrip() + "\n"


def _score_text(value: Any) -> str:
    if value is None:
        return "n/a"
    try:
        return f"{float(value):.2f}%"
    except (TypeError, ValueError):
        return "n/a"


def model_failure_triage_payload(matrix: dict[str, Any]) -> dict[str, Any]:
    rows = [_model_failure_triage_row(row) for row in model_failure_rows(matrix)]
    return sanitize_metadata(
        {
            "schema_version": "malleus.model_failure_triage.v1",
            "benchmark_mode": matrix.get("benchmark_mode", "live-full"),
            "matrix_id": matrix.get("matrix_id"),
            "generated_at": matrix.get("generated_at"),
            "row_count": len(rows),
            "rows": rows,
        }
    )


def _model_failure_triage_row(row: dict[str, Any]) -> dict[str, Any]:
    return sanitize_metadata(
        {
            "surface_id": row.get("surface"),
            "surface_name": row.get("surface_name") or row.get("surface"),
            "status": row.get("status"),
            "evidence_level": row.get("evidence_level"),
            "live_model_calls": int(row.get("live_model_calls") or 0),
            "reason_codes": list(row.get("reason_codes") or []),
            "report_path": row.get("report_path"),
            "reason": _short_triage_reason(row.get("reason")),
        }
    )


def _short_triage_reason(value: Any, *, limit: int = 240) -> str:
    text = redact_public_text(str(value or "model behavior failed deterministic scoring or policy checks")).text.strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "..."


def render_model_failure_triage_markdown(payload: dict[str, Any]) -> str:
    rows = payload.get("rows") if isinstance(payload.get("rows"), list) else []
    lines = [
        "# Model behavior failure triage",
        "",
        "Rows here are the machine-triage view of `MODEL_FAILURES.md`: only completed live model behavior failures are included. Provider, timeout, infrastructure, capability, target, config, checkpoint, scaffold, static, and dry-run outcomes are excluded.",
        "",
    ]
    if not rows:
        lines.append("No deterministic model behavior failures were recorded.")
        return "\n".join(lines).rstrip() + "\n"
    lines.extend(["| Surface | ID | Status | Evidence | Live calls | Reason codes | Report | Reason |", "|---|---|---|---|---:|---|---|---|"])
    for row in rows:
        lines.append(
            f"| {_md_safe(str(row.get('surface_name') or row.get('surface_id') or ''))} | `{_md_safe(row.get('surface_id') or '')}` | {_md_safe(row.get('status') or '')} | {_md_safe(row.get('evidence_level') or '')} | {int(row.get('live_model_calls') or 0)} | {_md_safe(', '.join(row.get('reason_codes') or []))} | {_md_safe(row.get('report_path') or '')} | {_md_safe(row.get('reason') or '')} |"
        )
    return "\n".join(lines).rstrip() + "\n"


def render_server_diagnostics_markdown(matrix: dict[str, Any]) -> str:
    preflight = matrix.get("preflight") if isinstance(matrix.get("preflight"), dict) else {}
    endpoint = preflight.get("endpoint") if isinstance(preflight.get("endpoint"), dict) else {}
    diagnostics = preflight.get("ssh_diagnostics") if isinstance(preflight.get("ssh_diagnostics"), dict) else None
    lines = [
        "# Server diagnostics",
        "",
        f"- Text preflight status: {_md_safe(preflight.get('text_status', 'unknown'))}",
        f"- Text ready: {str(preflight.get('text_ready', False)).lower()}",
        f"- Visual preflight status: {_md_safe(preflight.get('visual_status', 'not_run'))}",
        f"- Endpoint: {_md_safe(endpoint.get('scheme', 'unknown'))}://{_md_safe(endpoint.get('host', 'unknown'))}{(':' + _md_safe(endpoint.get('port'))) if endpoint.get('port') else ''}",
        "",
    ]
    if diagnostics:
        lines.extend(["## SSH diagnostics", "", f"- Status: {_md_safe(diagnostics.get('status', 'unknown'))}", f"- Command: `{_md_safe(diagnostics.get('command', 'redacted'))}`"])
        if diagnostics.get("summary"):
            lines.append(f"- Summary: {_md_safe(diagnostics.get('summary'))}")
    else:
        lines.append("SSH diagnostics were absent or not run for this aggregate report.")
    return "\n".join(lines).rstrip() + "\n"


def _render_row_table(lines: list[str], rows: list[dict[str, Any]], *, empty: str) -> str:
    if not rows:
        lines.append(empty)
        return "\n".join(lines).rstrip() + "\n"
    lines.extend(["| Surface | ID | Status | Live calls | Reason codes | Reason | Report |", "|---|---|---|---:|---|---|---|"])
    for row in rows:
        lines.append(f"| {_md_safe(_surface_display(row))} | `{_md_safe(row['surface'])}` | {_md_safe(row['status'])} | {int(row['live_model_calls'] or 0)} | {_md_safe(', '.join(row.get('reason_codes') or []))} | {_md_safe(row.get('reason') or '')} | {_md_safe(row.get('report_path') or '')} |")
    return "\n".join(lines).rstrip() + "\n"


def provider_error_rows(matrix: dict[str, Any]) -> list[dict[str, Any]]:
    return [row for row in matrix["rows"] if row["status"] in PROVIDER_OPERATIONAL_STATUSES]


def model_failure_rows(matrix: dict[str, Any]) -> list[dict[str, Any]]:
    return [row for row in matrix["rows"] if is_live_model_behavior_failure(row)]


def _live_row_is_model_behavior_failure(row: LiveEvidenceRow) -> bool:
    return (
        row.status == "failed"
        and row.evidence_level in LIVE_MODEL_EVIDENCE_LEVELS
        and int(row.live_model_calls or 0) > 0
        and row.dry_run is not True
        and row.provider_calls_enabled is not False
    )


def is_live_model_behavior_failure(row: dict[str, Any]) -> bool:
    return (
        row.get("status") == "failed"
        and row.get("evidence_level") in LIVE_MODEL_EVIDENCE_LEVELS
        and int(row.get("live_model_calls") or 0) > 0
        and row.get("dry_run") is not True
        and row.get("provider_calls_enabled") is not False
        and row.get("provider_error") is not True
        and row.get("status") not in NON_BEHAVIOR_STATUSES
        and row.get("capability_gap") is not True
        and row.get("target_or_config_error") is not True
        and row.get("skipped_by_operator") is not True
        and row.get("checkpoint_not_run") is not True
    )


def _bullet_rows(rows: list[dict[str, Any]], *, include_calls: bool = False, include_reason: bool = False, include_codes: bool = False) -> str:
    bullets: list[str] = []
    for row in rows:
        parts = [_md_safe(_surface_display(row)), f"id=`{_md_safe(row['surface'])}`", _md_safe(row["status"]), _md_safe(row["evidence_level"]), f"target_type={_md_safe(row.get('target_type') or 'chat_completion')}", f"evidence_type={_md_safe(row.get('evidence_type') or '')}"]
        if include_calls:
            parts.append(f"{int(row['live_model_calls'] or 0)} live calls")
        if include_codes and row.get("reason_codes"):
            parts.append(f"codes: {_md_safe(', '.join(row['reason_codes']))}")
        if include_reason and row.get("reason"):
            parts.append(_md_safe(row["reason"]))
        bullets.append("- " + ", ".join(parts))
    return "\n".join(bullets)


def _bullet_agent_trace_rows(rows: list[dict[str, Any]]) -> str:
    bullets: list[str] = []
    for row in rows:
        summary = row_agent_trace_summary(row)
        evidence_counts = summary.get("evidence_type_counts") if isinstance(summary.get("evidence_type_counts"), dict) else {}
        event_counts = summary.get("event_type_counts") if isinstance(summary.get("event_type_counts"), dict) else {}
        parts = [
            _md_safe(_surface_display(row)),
            f"id=`{_md_safe(row['surface'])}`",
            f"traces={int(summary.get('total_traces') or 0)}",
            f"gaps={int(summary.get('capability_gap_count') or 0)}",
            f"target_calls={int(summary.get('target_call_count') or 0)}",
            f"trace_items={int(summary.get('target_trace_count') or 0)}",
        ]
        if evidence_counts:
            parts.append("evidence=" + _md_safe(_format_count_map(evidence_counts)))
        if event_counts:
            parts.append("events=" + _md_safe(_format_count_map(event_counts)))
        bullets.append("- " + ", ".join(parts))
    return "\n".join(bullets)


def row_agent_trace_summary(row: dict[str, Any]) -> dict[str, Any]:
    metadata = row.get("metadata")
    if not isinstance(metadata, dict):
        return {}
    summary = metadata.get("agent_trace_summary")
    return summary if isinstance(summary, dict) else {}


def _format_count_map(counts: dict[str, Any]) -> str:
    return ", ".join(f"{key}={int(value or 0)}" for key, value in sorted(counts.items()))
