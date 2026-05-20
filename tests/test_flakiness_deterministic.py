from __future__ import annotations

import json
from pathlib import Path

from malleus.gates import evaluate_gate
from malleus.reporting import write_model_risk_card
from malleus.schemas import CaseResult, RunReport, RunSummary
from malleus.statistics import summarize_case_samples
from malleus.triage import triage_deterministically


def _case(
    sample_id: str,
    *,
    verdict: str = "PASS",
    reason_codes: list[str] | None = None,
    fingerprint: str = "fp-stable",
    severity: str = "high",
) -> CaseResult:
    return CaseResult(
        dataset_name="dataset",
        case_id="case-1",
        severity=severity,
        objective="objective",
        prompt="prompt",
        response_text=f"response {sample_id}",
        passed=True,
        score=100,
        penalty=0,
        metadata={
            "deterministic_verdict": verdict,
            "reason_codes": list(reason_codes or []),
            "run_fingerprint": {"fingerprint_id": fingerprint},
        },
        failure_checks=[],
        pass_checks=[],
    )


def _report() -> RunReport:
    return RunReport(
        run_id="run-flaky",
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
        target_name="target",
        target_adapter="openai_compatible",
        target_model="model",
        input_path="input.yaml",
        scoring_path="scoring.yaml",
        datasets=[],
        summary=RunSummary(total_items=0, passed_items=0, failed_items=0, score_total=0, max_score_total=0),
    )


def test_verdict_changes_mark_same_case_flaky_and_project_to_gate_triage_risk_card(tmp_path: Path) -> None:
    summary = summarize_case_samples(
        "dataset",
        "case-1",
        [
            _case("one", verdict="PASS", reason_codes=[]),
            _case("two", verdict="REVIEW", reason_codes=["POLICY_BYPASS"]),
        ],
    )
    repeated_summary = {"schema_version": "malleus.repeated_summary.v1", "run_id": "run-flaky", "repeats": 2, "cases": [summary.model_dump(mode="json")]}

    assert summary.flaky is True
    assert summary.deterministic_flaky is True
    assert summary.deterministic_verdict_counts == {"PASS": 1, "REVIEW": 1}
    assert summary.deterministic_reason_sequence_counts == {"<none>": 1, "POLICY_BYPASS": 1}

    gate = evaluate_gate(_report(), repeated_summary=repeated_summary)
    assert gate.status == "fail"
    assert "repeated_high_severity_flaky" in gate.reasons
    assert gate.summary.repeated_deterministic_flaky_count == 1
    assert gate.summary.repeated_fingerprint_mismatch_count == 0

    triage = triage_deterministically({"repeated_summary": repeated_summary})
    assert triage["repeated_case_count"] == 1
    assert triage["repeated_flaky_case_count"] == 1
    assert triage["repeated_deterministic_flaky_count"] == 1

    (tmp_path / "risk-summary.json").write_text(gate.model_dump_json(indent=2), encoding="utf-8")
    path = write_model_risk_card(_report(), tmp_path)
    markdown = path.read_text(encoding="utf-8")
    assert "1 deterministic flaky cases" in markdown
    assert "0 fingerprint mismatches across 1 repeated cases" in markdown


def test_identical_verdict_and_reason_sequences_are_not_flaky() -> None:
    summary = summarize_case_samples(
        "dataset",
        "case-1",
        [
            _case("one", verdict="PASS", reason_codes=[]),
            _case("two", verdict="PASS", reason_codes=[]),
        ],
    )

    assert summary.flaky is False
    assert summary.deterministic_flaky is False
    assert summary.aggregation_status == "OK"
    assert summary.deterministic_verdict_counts == {"PASS": 2}
    assert summary.deterministic_reason_sequence_counts == {"<none>": 2}


def test_fingerprint_mismatch_is_fail_closed_and_not_normal_flakiness() -> None:
    summary = summarize_case_samples(
        "dataset",
        "case-1",
        [
            _case("one", verdict="PASS", reason_codes=[], fingerprint="fp-a"),
            _case("two", verdict="REVIEW", reason_codes=["POLICY_BYPASS"], fingerprint="fp-b"),
        ],
    )
    repeated_summary = {"schema_version": "malleus.repeated_summary.v1", "run_id": "run-flaky", "repeats": 2, "cases": [summary.model_dump(mode="json")]}

    assert summary.fingerprint_mismatch is True
    assert summary.fingerprint_ids == ["fp-a", "fp-b"]
    assert summary.flaky is False
    assert summary.deterministic_flaky is False
    assert summary.aggregation_status == "CONFIG_ERROR"
    assert summary.fail_closed_verdict == "CONFIG_ERROR"
    assert summary.fail_closed_reason_codes == ["CONFIG_ERROR"]

    gate = evaluate_gate(_report(), repeated_summary=repeated_summary)
    assert gate.status == "error"
    assert "repeated_fingerprint_mismatch_config_error" in gate.reasons
    assert "repeated_high_severity_flaky" not in gate.reasons
    assert gate.summary.repeated_flaky_high_severity_count == 0
    assert gate.summary.repeated_fingerprint_mismatch_count == 1
    assert gate.summary.repeated_config_error_count == 1

    triage = triage_deterministically(repeated_summary)
    assert triage["total_cases"] == 0
    assert triage["repeated_flaky_case_count"] == 0
    assert triage["repeated_fingerprint_mismatch_count"] == 1
    assert triage["repeated_config_error_count"] == 1

    serialized = json.dumps(repeated_summary, sort_keys=True)
    assert "response_text" not in serialized
