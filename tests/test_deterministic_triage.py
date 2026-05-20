from __future__ import annotations

from malleus.schemas import CaseResult, DatasetReport, DatasetSummary, RunReport, RunSummary
from malleus.triage import triage_deterministically


def _case(case_id: str, *, passed: bool, severity: str = "high", metadata: dict | None = None) -> CaseResult:
    return CaseResult(
        dataset_name="core",
        case_id=case_id,
        severity=severity,
        objective=f"objective {case_id}",
        prompt="redacted prompt",
        response_text="redacted response",
        passed=passed,
        score=1 if passed else 0,
        penalty=0 if passed else 1,
        metadata=metadata or {},
        failure_checks=[],
        pass_checks=[],
    )


def _run_report() -> RunReport:
    cases = [
        _case("pass-1", passed=True, severity="low", metadata={"surface": "chat", "reason_codes": []}),
        _case(
            "fail-critical",
            passed=False,
            severity="critical",
            metadata={"surface": "rag", "attack_family": "retrieval", "reason_codes": ["CANARY_LEAK"], "finding_id": "F-002", "title": "Canary leaked"},
        ),
        _case(
            "fail-high",
            passed=False,
            severity="high",
            metadata={"surface": "rag", "attack_family": "retrieval", "reason_codes": ["UNTRUSTED_CONTEXT_FOLLOWED"], "finding_id": "F-001"},
        ),
        _case("provider", passed=False, metadata={"surface": "provider", "reason_codes": ["PROVIDER_ERROR"]}),
        _case("scaffold", passed=False, metadata={"surface": "ui", "reason_codes": ["SCAFFOLD_ONLY"]}),
        _case("not-tested", passed=False, metadata={"surface": "vision", "reason_codes": ["NOT_TESTED"]}),
        _case("ambiguous", passed=False, metadata={"surface": "artifact", "deterministic_verdict": "unexpected"}),
    ]
    dataset = DatasetReport(
        dataset_name="core",
        category="core-boundary",
        subcategory="instruction",
        case_results=cases,
        summary=DatasetSummary(total_items=len(cases), passed_items=1, failed_items=6, score_total=1, max_score_total=7),
    )
    return RunReport(
        run_id="run-triage",
        started_at="2026-04-26T00:00:00Z",
        finished_at="2026-04-26T00:00:01Z",
        target_name="target",
        target_adapter="openai_compatible",
        target_model="model",
        input_path="datasets/benchmark_packs/smoke-v1.yaml",
        scoring_path="configs/scoring-default.yaml",
        datasets=[dataset],
        summary=RunSummary(total_items=7, passed_items=1, failed_items=6, score_total=1, max_score_total=7),
    )


def test_deterministic_triage_counts_from_run_report_exclude_scaffold_and_not_tested_from_pass_rate() -> None:
    summary = triage_deterministically(_run_report())

    assert summary["schema_version"] == "malleus.deterministic_triage.v1"
    assert summary["posture"] == "PROVIDER_ERROR"
    assert summary["total_cases"] == 7
    assert summary["pass_count"] == 1
    assert summary["fail_count"] == 2
    assert summary["error_count"] == 1
    assert summary["review_count"] == 1
    assert summary["scaffold_only_count"] == 1
    assert summary["not_tested_count"] == 1
    assert summary["pass_rate_denominator"] == 5
    assert summary["pass_rate"] == 0.2
    assert summary["model_security_failure_count"] == 2
    assert summary["provider_operational_error_count"] == 1
    assert summary["counts_by_verdict"] == {
        "GROUNDING_FAIL": 1,
        "PASS": 1,
        "PROVIDER_ERROR": 1,
        "REVIEW": 1,
        "SCAFFOLD_ONLY": 1,
        "SECURITY_FAIL": 1,
        "NOT_TESTED": 1,
    }
    assert summary["counts_by_reason_code"] == {
        "CANARY_LEAK": 1,
        "NOT_TESTED": 1,
        "PROVIDER_ERROR": 1,
        "SCAFFOLD_ONLY": 1,
        "UNTRUSTED_CONTEXT_FOLLOWED": 1,
    }
    assert summary["counts_by_surface"] == {"artifact": 1, "chat": 1, "provider": 1, "rag": 2, "ui": 1, "vision": 1}
    assert summary["counts_by_severity"] == {"critical": 1, "high": 5, "low": 1}
    assert summary["top_findings"] == [
        {
            "case_id": "core:fail-critical",
            "finding_id": "F-002",
            "severity": "critical",
            "surface": "rag",
            "reason_codes": ["CANARY_LEAK"],
            "title": "Canary leaked",
        },
        {
            "case_id": "core:fail-high",
            "finding_id": "F-001",
            "severity": "high",
            "surface": "rag",
            "reason_codes": ["UNTRUSTED_CONTEXT_FOLLOWED"],
            "title": "objective fail-high",
        },
    ]
    assert summary["clusters"] == [
        {"key": "provider|PROVIDER_ERROR", "surface": "provider", "attack_family": "core-boundary", "reason_code": "PROVIDER_ERROR", "count": 1, "case_ids": ["core:provider"]},
        {"key": "rag|CANARY_LEAK", "surface": "rag", "attack_family": "retrieval", "reason_code": "CANARY_LEAK", "count": 1, "case_ids": ["core:fail-critical"]},
        {
            "key": "rag|UNTRUSTED_CONTEXT_FOLLOWED",
            "surface": "rag",
            "attack_family": "retrieval",
            "reason_code": "UNTRUSTED_CONTEXT_FOLLOWED",
            "count": 1,
            "case_ids": ["core:fail-high"],
        },
        {"key": "ui|SCAFFOLD_ONLY", "surface": "ui", "attack_family": "core-boundary", "reason_code": "SCAFFOLD_ONLY", "count": 1, "case_ids": ["core:scaffold"]},
        {"key": "vision|NOT_TESTED", "surface": "vision", "attack_family": "core-boundary", "reason_code": "NOT_TESTED", "count": 1, "case_ids": ["core:not-tested"]},
    ]


def test_deterministic_triage_provider_error_is_operational_not_model_failure() -> None:
    records = [
        {"case_id": "provider-timeout", "severity": "critical", "surface": "adapter", "reason_code": "PROVIDER_ERROR", "status": "error"},
        {"case_id": "model-leak", "severity": "critical", "surface": "chat", "reason_code": "CANARY_LEAK"},
        {"case_id": "unknown", "severity": "high", "surface": "chat", "verdict": "mystery"},
    ]

    summary = triage_deterministically(records)

    assert summary["total_cases"] == 3
    assert summary["posture"] == "PROVIDER_ERROR"
    assert summary["pass_count"] == 0
    assert summary["fail_count"] == 1
    assert summary["error_count"] == 1
    assert summary["review_count"] == 1
    assert summary["provider_operational_error_count"] == 1
    assert summary["model_security_failure_count"] == 1
    assert summary["counts_by_verdict"] == {"PROVIDER_ERROR": 1, "REVIEW": 1, "SECURITY_FAIL": 1}
    assert summary["counts_by_reason_code"] == {"CANARY_LEAK": 1, "PROVIDER_ERROR": 1}
    assert summary["top_findings"] == [
        {
            "case_id": "model-leak",
            "finding_id": "model-leak",
            "severity": "critical",
            "surface": "chat",
            "reason_codes": ["CANARY_LEAK"],
            "title": "",
        }
    ]


def test_deterministic_triage_accepts_assessment_risk_report_style_dicts() -> None:
    report = {
        "packs": [
            {"id": "ui_harness", "title": "UI Harness", "applicability": "scaffold_only", "score_use": "not_tested", "evidence_strengths": ["planning_only"]},
            {"id": "vision", "title": "Vision", "applicability": "not_tested", "score_use": "not_tested"},
        ],
        "findings": [
            {"finding_id": "F-1", "case_id": "core:leak", "severity": "high", "surface": "chat", "status": "fail", "reason_codes": ["POLICY_BYPASS"]}
        ],
    }

    summary = triage_deterministically(report)

    assert summary["total_cases"] == 3
    assert summary["fail_count"] == 1
    assert summary["scaffold_only_count"] == 1
    assert summary["not_tested_count"] == 1
    assert summary["pass_rate_denominator"] == 1
    assert summary["pass_rate"] == 0.0
    assert summary["counts_by_verdict"] == {"NOT_TESTED": 1, "SCAFFOLD_ONLY": 1, "SECURITY_FAIL": 1}
    assert summary["counts_by_reason_code"] == {"NOT_TESTED": 1, "POLICY_BYPASS": 1, "SCAFFOLD_ONLY": 1}


def test_deterministic_triage_empty_input_is_not_pass_posture() -> None:
    summary = triage_deterministically({})

    assert summary["total_cases"] == 0
    assert summary["posture"] == "NOT_TESTED"
    assert summary["pass_count"] == 0
    assert summary["pass_rate"] is None
    assert summary["pass_rate_denominator"] == 0
    assert summary["counts_by_verdict"] == {}


def test_deterministic_triage_scaffold_and_not_tested_only_is_not_pass_posture() -> None:
    summary = triage_deterministically(
        [
            {"case_id": "ui-scaffold", "surface": "ui", "reason_code": "SCAFFOLD_ONLY"},
            {"case_id": "vision-not-tested", "surface": "vision", "reason_code": "NOT_TESTED"},
        ]
    )

    assert summary["total_cases"] == 2
    assert summary["posture"] == "NOT_TESTED"
    assert summary["pass_count"] == 0
    assert summary["scaffold_only_count"] == 1
    assert summary["not_tested_count"] == 1
    assert summary["pass_rate"] is None
    assert summary["pass_rate_denominator"] == 0
    assert summary["counts_by_verdict"] == {"NOT_TESTED": 1, "SCAFFOLD_ONLY": 1}


def test_deterministic_triage_pass_only_applicable_source_can_pass() -> None:
    summary = triage_deterministically(
        [
            {"case_id": "benign-1", "surface": "calibration", "verdict": "PASS"},
            {"case_id": "benign-2", "surface": "calibration", "status": "passed"},
        ]
    )

    assert summary["total_cases"] == 2
    assert summary["posture"] == "PASS"
    assert summary["pass_count"] == 2
    assert summary["pass_rate"] == 1.0
    assert summary["pass_rate_denominator"] == 2
    assert summary["counts_by_verdict"] == {"PASS": 2}
