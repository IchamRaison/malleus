from __future__ import annotations

from typing import Any

from malleus.live_evidence import LiveEvidenceStatus


def nonnegative_int(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return max(value, 0)
    if isinstance(value, float):
        return max(int(value), 0)
    return 0


def system_report_live_model_calls(report: Any) -> int:
    total = 0
    for result in getattr(report, "results", []) or []:
        harness_result = getattr(result, "harness_result", None)
        metadata = getattr(harness_result, "metadata", {}) if harness_result is not None else {}
        if isinstance(metadata, dict):
            total += nonnegative_int(metadata.get("live_model_calls", 0))
    return total


def system_summary_status(summary: Any) -> LiveEvidenceStatus:
    counts = getattr(summary, "status_counts", {}) or {}
    if counts.get("target_config_error", 0):
        return "target_config_error"
    if counts.get("target_error", 0):
        return "target_error"
    if counts.get("infra_error", 0):
        return "infra_error"
    if counts.get("target_capability_gap", 0):
        return "target_capability_gap"
    if counts.get("failed", 0):
        return "failed"
    if counts.get("passed", 0):
        return "passed"
    return "target_capability_gap"


def system_summary_reason(pack_id: str, summary: Any, status: LiveEvidenceStatus, *, evidence_fidelity: str | None = None) -> str | None:
    caveat = ""
    if evidence_fidelity == "auto_wrapper_trace":
        caveat = " with low-fidelity auto-wrapper evidence"
    controlled_lab = bool(evidence_fidelity and evidence_fidelity.startswith("controlled_"))
    if status == "passed":
        if caveat:
            return f"{pack_id} completed{caveat}; observable wrapper traces had no deterministic findings"
        if controlled_lab:
            return f"{pack_id} controlled Malleus lab harness completed with observable target traces and no deterministic findings"
        return f"{pack_id} real system harness completed with observable target traces and no deterministic findings"
    codes = ", ".join(getattr(summary, "reason_codes", []) or []) or status
    if caveat:
        return f"{pack_id} completed{caveat} with status {status}; reason codes: {codes}"
    if controlled_lab:
        return f"{pack_id} controlled Malleus lab harness completed with status {status}; reason codes: {codes}"
    return f"{pack_id} real system harness completed with status {status}; reason codes: {codes}"
