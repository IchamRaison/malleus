from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

from malleus.flight_recorder import FlightRecording, InvariantViolation
from malleus.utils.time import now_iso


class RegressionScenario(BaseModel):
    id: str
    title: str
    invariant_id: str
    severity: str
    source_violation_id: str
    trace_id: str
    replay_path: str | None = None
    expected: dict[str, Any] = Field(default_factory=dict)


class RegressionPack(BaseModel):
    schema_version: str = "malleus.security_regression_pack.v1"
    name: str
    created_at: str = Field(default_factory=now_iso)
    scenarios: list[RegressionScenario]


class RemediationComparison(BaseModel):
    schema_version: str = "malleus.remediation_comparison.v1"
    baseline_recording_id: str
    candidate_recording_id: str
    fixed: list[str]
    remaining: list[str]
    introduced: list[str]
    baseline_count: int
    candidate_count: int


class RemediationGatePolicy(BaseModel):
    schema_version: str = "malleus.remediation_gate_policy.v1"
    fail_on_introduced: bool = True
    fail_on_remaining_critical: bool = True
    max_candidate_violations: int | None = None


class RemediationGateResult(BaseModel):
    schema_version: str = "malleus.remediation_gate_result.v1"
    status: Literal["pass", "warn", "fail"]
    reasons: list[str]
    comparison: RemediationComparison


class CalibrationItem(BaseModel):
    item_id: str
    expected_violation: bool
    predicted_violation: bool
    reviewer: str | None = None


class CalibrationReport(BaseModel):
    schema_version: str = "malleus.verdict_calibration.v1"
    total: int
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int
    precision: float
    recall: float
    false_positive_rate: float


class ReviewRecord(BaseModel):
    schema_version: str = "malleus.finding_review.v1"
    violation_id: str
    status: Literal["confirmed", "false_positive", "accepted_risk", "needs_evidence"]
    reviewer: str
    rationale: str
    reviewed_at: str = Field(default_factory=now_iso)


def generate_regression_pack(
    recording: FlightRecording, *, name: str = "Malleus generated security regressions"
) -> RegressionPack:
    scenarios = [
        RegressionScenario(
            id=f"regression-{violation.violation_id}",
            title=violation.invariant_title,
            invariant_id=violation.invariant_id,
            severity=violation.severity,
            source_violation_id=violation.violation_id,
            trace_id=violation.trace_id,
            expected={
                "violation_absent": True,
                "invariant_id": violation.invariant_id,
                "causal_event_ids": violation.causal_event_ids,
            },
        )
        for violation in recording.violations
    ]
    return RegressionPack(name=name, scenarios=scenarios)


def write_regression_pack(pack: RegressionPack, path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        yaml.safe_dump(pack.model_dump(mode="json"), sort_keys=False), encoding="utf-8"
    )
    return destination


def compare_remediation(
    baseline: FlightRecording, candidate: FlightRecording
) -> RemediationComparison:
    baseline_keys = {_violation_key(item): item for item in baseline.violations}
    candidate_keys = {_violation_key(item): item for item in candidate.violations}
    return RemediationComparison(
        baseline_recording_id=baseline.recording_id,
        candidate_recording_id=candidate.recording_id,
        fixed=sorted(baseline_keys.keys() - candidate_keys.keys()),
        remaining=sorted(baseline_keys.keys() & candidate_keys.keys()),
        introduced=sorted(candidate_keys.keys() - baseline_keys.keys()),
        baseline_count=len(baseline.violations),
        candidate_count=len(candidate.violations),
    )


def evaluate_remediation_gate(
    comparison: RemediationComparison,
    candidate: FlightRecording,
    policy: RemediationGatePolicy | None = None,
) -> RemediationGateResult:
    policy = policy or RemediationGatePolicy()
    reasons: list[str] = []
    if policy.fail_on_introduced and comparison.introduced:
        reasons.append(f"{len(comparison.introduced)} new invariant violation(s)")
    remaining_critical = [
        item for item in candidate.violations if item.severity == "critical"
    ]
    if policy.fail_on_remaining_critical and remaining_critical:
        reasons.append(f"{len(remaining_critical)} critical violation(s) remain")
    if (
        policy.max_candidate_violations is not None
        and comparison.candidate_count > policy.max_candidate_violations
    ):
        reasons.append(
            f"candidate has {comparison.candidate_count} violations; "
            f"maximum is {policy.max_candidate_violations}"
        )
    status: Literal["pass", "warn", "fail"] = "fail" if reasons else "pass"
    if not reasons and comparison.remaining:
        status = "warn"
        reasons.append(f"{len(comparison.remaining)} non-critical violation(s) remain")
    return RemediationGateResult(status=status, reasons=reasons, comparison=comparison)


def calibrate_verdicts(items: list[CalibrationItem]) -> CalibrationReport:
    tp = sum(item.expected_violation and item.predicted_violation for item in items)
    fp = sum(not item.expected_violation and item.predicted_violation for item in items)
    tn = sum(not item.expected_violation and not item.predicted_violation for item in items)
    fn = sum(item.expected_violation and not item.predicted_violation for item in items)
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    false_positive_rate = fp / (fp + tn) if fp + tn else 0.0
    return CalibrationReport(
        total=len(items),
        true_positive=tp,
        false_positive=fp,
        true_negative=tn,
        false_negative=fn,
        precision=precision,
        recall=recall,
        false_positive_rate=false_positive_rate,
    )


def integration_issue_payload(
    violation: InvariantViolation,
    *,
    platform: Literal["github", "gitlab", "jira"],
    project: str | None = None,
) -> dict[str, Any]:
    title = f"[{violation.severity.upper()}] {violation.invariant_title}"
    description = (
        f"Malleus invariant `{violation.invariant_id}` was violated.\n\n"
        f"Reason: {violation.reason}\n\n"
        f"Trace: `{violation.trace_id}`\nEvent: `{violation.event_id}`\n"
        f"Violation: `{violation.violation_id}`"
    )
    labels = ["ai-security", "malleus", f"severity:{violation.severity}"]
    if platform == "github":
        return {"title": title, "body": description, "labels": labels}
    if platform == "gitlab":
        return {"title": title, "description": description, "labels": ",".join(labels)}
    return {
        "fields": {
            "project": {"key": project or "SEC"},
            "summary": title,
            "description": description,
            "issuetype": {"name": "Bug"},
            "labels": [label.replace(":", "-") for label in labels],
        }
    }


def write_json_model(model: BaseModel, path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(model.model_dump_json(indent=2), encoding="utf-8")
    return destination


def load_recording(path: str | Path) -> FlightRecording:
    return FlightRecording.model_validate_json(Path(path).read_text(encoding="utf-8"))


def load_calibration_items(path: str | Path) -> list[CalibrationItem]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("calibration input must be a JSON array")
    return [CalibrationItem.model_validate(item) for item in payload]


def _violation_key(violation: InvariantViolation) -> str:
    return f"{violation.invariant_id}:{violation.event_type}:{violation.event_id}"
