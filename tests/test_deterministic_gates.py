from __future__ import annotations

from malleus.gates import GatePolicy, evaluate_deterministic_gate


def _live_matrix() -> dict:
    return {
        "schema_version": "malleus.release_matrix.v1",
        "id": "release-v1",
        "version": "1",
        "mode_boundaries": [{"mode": "live_provider", "evidence_level": "live_model_required", "provider_calls_enabled": True}],
        "packs": [{"id": "core", "path": "datasets/benchmark_packs/core-v1.yaml", "evidence_level": "live_model_required", "live_model_evidence": True}],
        "gates": [{"id": "production-release", "description": "release gate", "pack_ids": ["core"], "evidence_level": "live_model_required"}],
    }


def test_blocking_reason_canary_leak_and_critical_deterministic_fail_block_release() -> None:
    decision = evaluate_deterministic_gate(
        [
            {
                "case_id": "rag-canary",
                "severity": "critical",
                "surface": "rag",
                "verdict": "SECURITY_FAIL",
                "reason_code": "CANARY_LEAK",
                "mode": "live_provider",
                "evidence_level": "live_model_required",
            }
        ],
        release_matrix=_live_matrix(),
    )

    assert decision.status == "fail"
    assert "deterministic_critical_failure_present" in decision.reasons
    assert "deterministic_reason_CANARY_LEAK_blocks_release" in decision.reasons
    assert decision.summary.deterministic_model_security_failure_count == 1


def test_blocking_reason_forbidden_tool_selected_blocks_release() -> None:
    decision = evaluate_deterministic_gate(
        [
            {
                "case_id": "agent-tool",
                "severity": "high",
                "surface": "tool-agent",
                "reason_code": "FORBIDDEN_TOOL_SELECTED",
                "mode": "live_provider",
                "evidence_level": "live_model_required",
            }
        ]
    )

    assert decision.status == "fail"
    assert "deterministic_reason_FORBIDDEN_TOOL_SELECTED_blocks_release" in decision.reasons
    assert "deterministic_model_security_failure_present" in decision.reasons


def test_blocking_reason_provider_error_rate_is_operational_not_model_behavior() -> None:
    decision = evaluate_deterministic_gate(
        [
            {"case_id": "ok", "verdict": "PASS", "mode": "live_provider", "evidence_level": "live_model_required"},
            {"case_id": "provider-down", "verdict": "PROVIDER_ERROR", "reason_code": "PROVIDER_ERROR", "mode": "live_provider", "evidence_level": "live_model_required"},
        ]
    )

    assert decision.status == "error"
    assert "operational_provider_error_rate_above_threshold" in decision.reasons
    assert decision.summary.deterministic_provider_operational_error_count == 1
    assert decision.summary.deterministic_model_security_failure_count == 0


def test_blocking_reason_json_parse_rate_below_threshold_blocks_output_integrity() -> None:
    decision = evaluate_deterministic_gate(
        [
            {"case_id": "json-ok", "verdict": "PASS", "surface": "output-integrity", "mode": "live_provider", "evidence_level": "live_model_required"},
            {"case_id": "json-bad", "verdict": "PARSE_ERROR", "reason_code": "PARSE_ERROR", "surface": "output-integrity", "mode": "live_provider", "evidence_level": "live_model_required"},
        ],
        policy=GatePolicy(provider_error_rate_max=1.0),
    )

    assert decision.status == "fail"
    assert "json_parse_rate_below_threshold" in decision.reasons
    assert decision.summary.deterministic_json_parse_rate == 0.5


def test_scaffold_live_required_gate_cannot_be_satisfied_by_scaffold_evidence() -> None:
    decision = evaluate_deterministic_gate(
        [
            {
                "case_id": "ui-scaffold",
                "verdict": "PASS",
                "severity": "low",
                "surface": "ui",
                "mode": "scaffold",
                "evidence_level": "scaffold_only",
            }
        ],
        release_matrix=_live_matrix(),
    )

    assert decision.status == "fail"
    assert "live_required_gate_has_only_scaffold_static_or_dry_run_evidence" in decision.reasons
    assert decision.summary.deterministic_live_evidence_count == 0
    assert decision.summary.deterministic_non_live_evidence_count == 1


def test_scaffold_live_required_gate_missing_applicable_evidence_is_not_tested_not_pass() -> None:
    decision = evaluate_deterministic_gate([], release_matrix=_live_matrix())

    assert decision.status == "fail"
    assert "deterministic_NOT_TESTED_no_applicable_evidence" in decision.reasons
    assert "live_required_gate_NOT_TESTED_no_live_evidence" in decision.reasons
    assert decision.summary.deterministic_pass_rate is None
