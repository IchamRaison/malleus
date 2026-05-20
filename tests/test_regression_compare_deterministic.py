from __future__ import annotations

import json
from pathlib import Path

from malleus.diff_runs import diff_run_reports, render_diff_markdown, write_diff_report


def _case(
    case_id: str,
    *,
    passed: bool,
    score: int,
    severity: str = "high",
    objective: str | None = None,
    metadata: dict | None = None,
) -> dict:
    return {
        "dataset_name": "security-cases",
        "case_id": case_id,
        "severity": severity,
        "objective": objective or f"Objective {case_id}",
        "prompt": "prompt",
        "response_text": "response",
        "passed": passed,
        "score": score,
        "penalty": 100 - score,
        "latency_seconds": 0.01,
        "warnings": [],
        "failure_checks": [],
        "pass_checks": [],
        "metadata": metadata or {},
    }


def _report(path: Path, *, run_id: str, cases: list[dict], category: str = "Security Category", extra: dict | None = None) -> Path:
    total = len(cases)
    payload = {
        "run_id": run_id,
        "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:00:01Z",
        "target_name": "target",
        "target_adapter": "nvidia",
        "target_model": "model",
        "input_path": "datasets/benchmark_packs/core-v1.yaml",
        "scoring_path": "configs/scoring-default.yaml",
        "datasets": [
            {
                "dataset_name": "security-cases",
                "category": category,
                "subcategory": "deterministic",
                "case_results": cases,
                "group_results": [],
                "summary": {
                    "total_items": total,
                    "passed_items": sum(1 for item in cases if item["passed"]),
                    "failed_items": sum(1 for item in cases if not item["passed"]),
                    "score_total": sum(item["score"] for item in cases),
                    "max_score_total": total * 100,
                },
            }
        ],
        "summary": {
            "total_items": total,
            "passed_items": sum(1 for item in cases if item["passed"]),
            "failed_items": sum(1 for item in cases if not item["passed"]),
            "score_total": sum(item["score"] for item in cases),
            "max_score_total": total * 100,
        },
    }
    if extra:
        payload.update(extra)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _meta(verdict: str, reasons: list[str] | None = None, *, scenario_id: str | None = None, evidence_level: str = "provider_free_static", provider_error: str | None = None) -> dict:
    metadata = {
        "deterministic_verdict": verdict,
        "reason_codes": reasons or [],
        "evidence_level": evidence_level,
        "evidence_strength": evidence_level,
    }
    if scenario_id:
        metadata["scenario_id"] = scenario_id
    if provider_error:
        metadata["provider_error"] = provider_error
    return metadata


def test_categories_detect_deterministic_regression_classes_and_redact_output(tmp_path: Path) -> None:
    old = _report(
        tmp_path / "old.json",
        run_id="old-run",
        category="Security Category",
        cases=[
            _case("CASE ONE", passed=True, score=100, severity="critical", metadata=_meta("PASS", scenario_id=" Core Case ")),
            _case("resolved", passed=False, score=0, severity="high", metadata=_meta("SECURITY_FAIL", ["CANARY_LEAK"])),
            _case("changed", passed=False, score=50, severity="medium", metadata=_meta("REVIEW", ["POLICY_BYPASS"])),
            _case("provider", passed=True, score=100, severity="low", metadata=_meta("PASS")),
            _case("removed", passed=False, score=0, severity="critical", metadata=_meta("SECURITY_FAIL", ["POLICY_BYPASS"])),
        ],
    )
    new = _report(
        tmp_path / "new.json",
        run_id="new-run",
        category="security category",
        cases=[
            _case("renamed", passed=False, score=0, severity="critical", objective="secret: SYNTHETIC-SK-OPENAI-SECRET leaked", metadata=_meta("SECURITY_FAIL", ["CANARY_LEAK"], scenario_id="core case")),
            _case("resolved", passed=True, score=100, severity="high", metadata=_meta("PASS")),
            _case("changed", passed=False, score=50, severity="medium", metadata=_meta("SCHEMA_FAIL", ["MISSING_REQUIRED_KEY"])),
            _case("provider", passed=False, score=0, severity="low", metadata=_meta("PROVIDER_ERROR", ["PROVIDER_ERROR"], provider_error="Bearer secret-token-123456")),
            _case("added", passed=False, score=0, severity="high", metadata=_meta("SECURITY_FAIL", ["FORBIDDEN_TOOL_SELECTED"])),
        ],
        extra={"provider_errors": [{"error_type": "AdapterError", "message": "api_key=SYNTHETIC-SK-OPENAI-SECRET"}]},
    )

    diff = diff_run_reports(old, new)
    _, markdown_path = write_diff_report(diff, tmp_path / "out")
    report_json = (tmp_path / "out" / "diff-runs-report.json").read_text(encoding="utf-8")
    markdown = markdown_path.read_text(encoding="utf-8")

    assert diff.summary.comparison_status == "REVIEW"
    assert diff.summary.new_failures == 1
    assert diff.summary.resolved_failures == 1
    assert diff.summary.changed_verdicts == 1
    assert diff.summary.new_provider_errors == 1
    assert diff.summary.added_items == 1
    assert diff.summary.removed_items == 1
    assert diff.summary.new_provider_error_total == 2
    assert diff.summary.weighted_score_delta == -200
    assert {item.raw_id for item in diff.new_failures} == {"renamed"}
    assert {item.raw_id for item in diff.resolved_failures} == {"resolved"}
    assert {item.raw_id for item in diff.changed_verdicts} == {"changed"}
    assert {item.raw_id for item in diff.new_provider_errors} == {"provider"}
    assert {item.raw_id for item in diff.added} == {"added"}
    assert {item.raw_id for item in diff.removed} == {"removed"}
    assert "SYNTHETIC-SK-OPENAI-SECRET" not in report_json
    assert "secret-token-123456" not in report_json
    assert "SYNTHETIC-SK-OPENAI-SECRET" not in report_json
    assert "[REDACTED]" in report_json
    assert "SYNTHETIC-SK-OPENAI-SECRET" not in markdown
    assert "New provider errors: 1" in markdown
    assert "Severity-weighted score delta: -200" in markdown


def test_categories_baseline_schema_mismatch_fails_closed_with_reason(tmp_path: Path) -> None:
    old = _report(tmp_path / "old.json", run_id="old-run", cases=[_case("c1", passed=True, score=100)], extra={"schema_version": "malleus.future.v9"})
    new = _report(tmp_path / "new.json", run_id="new-run", cases=[_case("c1", passed=True, score=100)])

    diff = diff_run_reports(old, new)

    assert diff.summary.comparison_status == "ERROR"
    assert diff.summary.baseline_incompatible is True
    assert diff.summary.reasons == ["stale_or_incompatible_baseline_schema"]
    assert diff.incompatible[0].new_deterministic_verdict == "CONFIG_ERROR"
    assert "Baseline incompatible: True" in render_diff_markdown(diff)


def test_legacy_old_reports_compare_with_pass_score_semantics(tmp_path: Path) -> None:
    old = _report(
        tmp_path / "old.json",
        run_id="old-run",
        cases=[
            _case("same", passed=True, score=100),
            _case("legacy-regressed", passed=True, score=100),
            _case("legacy-improved", passed=False, score=0),
        ],
    )
    new = _report(
        tmp_path / "new.json",
        run_id="new-run",
        cases=[
            _case("same", passed=True, score=100),
            _case("legacy-regressed", passed=False, score=0),
            _case("legacy-improved", passed=True, score=100),
        ],
    )

    diff = diff_run_reports(old, new)

    assert diff.summary.legacy_items == 6
    assert diff.summary.deterministic_items == 0
    assert diff.summary.newly_failing == 1
    assert diff.summary.newly_passing == 1
    assert diff.summary.changed_verdicts == 0
    assert diff.newly_failing[0].item_id == "case:Security Category:legacy-regressed"
    assert diff.newly_passing[0].item_id == "case:Security Category:legacy-improved"
