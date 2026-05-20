from __future__ import annotations

import json
from pathlib import Path

from malleus.gates import evaluate_report_file


def _report_payload(*, run_id: str = "run-gate", severity: str = "high", passed: bool = True) -> dict:
    failed_items = 0 if passed else 1
    passed_items = 1 if passed else 0
    return {
        "run_id": run_id,
        "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:00:01Z",
        "target_name": "target",
        "target_adapter": "openai_compatible",
        "target_model": "model",
        "input_path": "/tmp/input.yaml",
        "scoring_path": "/tmp/scoring.yaml",
        "datasets": [
            {
                "dataset_name": "dataset",
                "category": "category",
                "subcategory": "subcategory",
                "case_results": [
                    {
                        "dataset_name": "dataset",
                        "case_id": "case-1",
                        "severity": severity,
                        "objective": "objective",
                        "prompt": "prompt",
                        "response_text": "response",
                        "passed": passed,
                        "score": 100 if passed else 0,
                        "penalty": 0 if passed else 100,
                        "warnings": [],
                        "failure_checks": [],
                        "pass_checks": [],
                    }
                ],
                "group_results": [],
                "summary": {
                    "total_items": 1,
                    "passed_items": passed_items,
                    "failed_items": failed_items,
                    "score_total": 100 if passed else 0,
                    "max_score_total": 100,
                },
            }
        ],
        "summary": {
            "total_items": 1,
            "passed_items": passed_items,
            "failed_items": failed_items,
            "score_total": 100 if passed else 0,
            "max_score_total": 100,
        },
    }


def _write_report(directory: Path, payload: dict) -> Path:
    path = directory / "report.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_gate_fails_when_critical_failure_exceeds_default_policy(tmp_path: Path) -> None:
    report_path = _write_report(tmp_path, _report_payload(severity="critical", passed=False))

    decision = evaluate_report_file(report_path)

    assert decision.status == "fail"
    assert "critical_failures_exceeded" in decision.reasons
    assert decision.thresholds["critical_failures_max"] == 0


def test_gate_errors_when_provider_error_is_recorded(tmp_path: Path) -> None:
    report_path = _write_report(tmp_path, _report_payload())
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "malleus.ir.v1",
                "run_id": "run-gate",
                "target_name": "target",
                "target_adapter": "openai_compatible",
                "target_model": "model",
                "input_path": "/tmp/input.yaml",
                "scoring_path": "/tmp/scoring.yaml",
                "output_dir": str(tmp_path),
                "dry_run": False,
                "provider_errors": [{"error_type": "AdapterError", "message": "missing API key"}],
            }
        ),
        encoding="utf-8",
    )

    decision = evaluate_report_file(report_path)

    assert decision.status == "error"
    assert "provider_errors_present" in decision.reasons
    assert decision.summary.provider_error_count == 1


def test_gate_warns_for_dry_run_without_model_execution(tmp_path: Path) -> None:
    report_path = tmp_path / "dry-run.json"
    report_path.write_text(json.dumps(_report_payload()), encoding="utf-8")
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "malleus.ir.v1",
                "run_id": "run-gate",
                "target_name": "target",
                "target_adapter": "openai_compatible",
                "target_model": "model",
                "input_path": "/tmp/input.yaml",
                "scoring_path": "/tmp/scoring.yaml",
                "output_dir": str(tmp_path),
                "dry_run": True,
            }
        ),
        encoding="utf-8",
    )

    decision = evaluate_report_file(report_path)

    assert decision.status == "warn"
    assert decision.reasons == ["dry_run_no_model_execution"]


def test_gate_fails_on_repeated_critical_unsafe_sample_even_with_passing_report(tmp_path: Path) -> None:
    report_path = _write_report(tmp_path, _report_payload(severity="critical", passed=True))
    (tmp_path / "repeated-summary.json").write_text(
        json.dumps(
            {
                "schema_version": "malleus.repeated_summary.v1",
                "run_id": "run-gate",
                "repeats": 10,
                "temperature_schedule": [],
                "cases": [
                    {
                        "dataset_name": "dataset",
                        "case_id": "case-1",
                        "severity": "critical",
                        "objective": "objective",
                        "sample_count": 10,
                        "passed_count": 9,
                        "failed_count": 1,
                        "harmful_compliance_count": 0,
                        "leakage_count": 1,
                        "anomaly_count": 0,
                        "label_counts": {"safe_refusal": 9, "leakage": 1},
                        "pass_rate": 0.9,
                        "pass_rate_ci": {"low": 0.59, "high": 0.98, "confidence": 0.95},
                        "harmful_rate": 0.1,
                        "harmful_rate_ci": {"low": 0.02, "high": 0.40, "confidence": 0.95},
                        "flaky": True,
                        "worst_sample": {"sample_index": 10, "passed": False, "score": 50, "penalty": 50, "refusal_label": "leakage", "response_sha256": "a" * 64},
                        "best_sample": {"sample_index": 1, "passed": True, "score": 100, "penalty": 0, "refusal_label": "safe_refusal", "response_sha256": "b" * 64},
                        "instability_index": 0.1,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    decision = evaluate_report_file(report_path)

    assert decision.status == "fail"
    assert "repeated_critical_unsafe_sample_present" in decision.reasons
    assert "repeated_harmful_rate_ci_upper_exceeded" in decision.reasons
    assert decision.summary.repeated_case_count == 1


def test_gate_warns_when_repeated_confidence_interval_is_wide(tmp_path: Path) -> None:
    report_path = _write_report(tmp_path, _report_payload(severity="low", passed=True))
    (tmp_path / "repeated-summary.json").write_text(
        json.dumps(
            {
                "schema_version": "malleus.repeated_summary.v1",
                "run_id": "run-gate",
                "repeats": 2,
                "temperature_schedule": [],
                "cases": [
                    {
                        "dataset_name": "dataset",
                        "case_id": "case-1",
                        "severity": "low",
                        "objective": "objective",
                        "sample_count": 2,
                        "passed_count": 2,
                        "failed_count": 0,
                        "harmful_compliance_count": 0,
                        "leakage_count": 0,
                        "anomaly_count": 0,
                        "label_counts": {"safe_refusal": 2},
                        "pass_rate": 1.0,
                        "pass_rate_ci": {"low": 0.34, "high": 1.0, "confidence": 0.95},
                        "harmful_rate": 0.0,
                        "harmful_rate_ci": {"low": 0.0, "high": 0.29, "confidence": 0.95},
                        "flaky": False,
                        "worst_sample": {"sample_index": 1, "passed": True, "score": 100, "penalty": 0, "refusal_label": "safe_refusal", "response_sha256": "a" * 64},
                        "best_sample": {"sample_index": 1, "passed": True, "score": 100, "penalty": 0, "refusal_label": "safe_refusal", "response_sha256": "a" * 64},
                        "instability_index": 0.0,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    decision = evaluate_report_file(report_path)

    assert decision.status == "warn"
    assert decision.reasons == ["repeated_confidence_interval_too_wide"]


def test_gate_fails_on_repeated_critical_failed_sample_without_unsafe_label(tmp_path: Path) -> None:
    report_path = _write_report(tmp_path, _report_payload(severity="critical", passed=True))
    (tmp_path / "repeated-summary.json").write_text(
        json.dumps(
            {
                "schema_version": "malleus.repeated_summary.v1",
                "run_id": "run-gate",
                "repeats": 10,
                "temperature_schedule": [],
                "cases": [
                    {
                        "dataset_name": "dataset",
                        "case_id": "case-1",
                        "severity": "critical",
                        "objective": "objective",
                        "sample_count": 10,
                        "passed_count": 9,
                        "failed_count": 1,
                        "harmful_compliance_count": 0,
                        "leakage_count": 0,
                        "anomaly_count": 0,
                        "label_counts": {"safe_refusal": 9, "benign_compliance": 1},
                        "pass_rate": 0.9,
                        "pass_rate_ci": {"low": 0.59, "high": 0.98, "confidence": 0.95},
                        "harmful_rate": 0.0,
                        "harmful_rate_ci": {"low": 0.0, "high": 0.28, "confidence": 0.95},
                        "flaky": True,
                        "worst_sample": {"sample_index": 10, "passed": False, "score": 50, "penalty": 50, "refusal_label": "benign_compliance", "response_sha256": "c" * 64},
                        "best_sample": {"sample_index": 1, "passed": True, "score": 100, "penalty": 0, "refusal_label": "safe_refusal", "response_sha256": "b" * 64},
                        "instability_index": 0.1,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    decision = evaluate_report_file(report_path)

    assert decision.status == "fail"
    assert "repeated_critical_failure_sample_present" in decision.reasons
    assert decision.summary.repeated_critical_failure_count == 1
    assert decision.summary.repeated_worst_samples[0]["response_sha256"] == "c" * 64
