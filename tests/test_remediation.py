from malleus.flight_recorder import FlightRecording, InvariantViolation
from malleus.remediation import (
    CalibrationItem,
    RemediationGatePolicy,
    calibrate_verdicts,
    compare_remediation,
    evaluate_remediation_gate,
    generate_regression_pack,
    integration_issue_payload,
)


def _violation(identifier: str, *, severity: str = "high") -> InvariantViolation:
    return InvariantViolation(
        violation_id=identifier,
        invariant_id=identifier,
        invariant_title=f"Invariant {identifier}",
        severity=severity,
        trace_id="trace",
        event_id=identifier,
        event_type="tool_call",
        reason="unsafe call",
    )


def test_regression_comparison_and_gate() -> None:
    baseline = FlightRecording(source="baseline", events=[], violations=[_violation("fixed"), _violation("remaining")])
    candidate = FlightRecording(source="candidate", events=[], violations=[_violation("remaining")])

    pack = generate_regression_pack(baseline)
    comparison = compare_remediation(baseline, candidate)
    gate = evaluate_remediation_gate(
        comparison, candidate, RemediationGatePolicy(fail_on_remaining_critical=True)
    )

    assert len(pack.scenarios) == 2
    assert comparison.fixed == ["fixed:tool_call:fixed"]
    assert comparison.remaining == ["remaining:tool_call:remaining"]
    assert gate.status == "warn"


def test_critical_remaining_violation_fails_gate() -> None:
    candidate = FlightRecording(source="candidate", events=[], violations=[_violation("critical", severity="critical")])
    comparison = compare_remediation(FlightRecording(source="baseline", events=[]), candidate)
    assert evaluate_remediation_gate(comparison, candidate).status == "fail"


def test_calibration_and_integration_payloads() -> None:
    report = calibrate_verdicts(
        [
            CalibrationItem(item_id="tp", expected_violation=True, predicted_violation=True),
            CalibrationItem(item_id="fp", expected_violation=False, predicted_violation=True),
            CalibrationItem(item_id="tn", expected_violation=False, predicted_violation=False),
        ]
    )
    violation = _violation("issue")

    assert report.precision == 0.5
    assert report.false_positive_rate == 0.5
    assert integration_issue_payload(violation, platform="github")["labels"][0] == "ai-security"
    assert integration_issue_payload(violation, platform="jira", project="AISEC")["fields"]["project"] == {"key": "AISEC"}
