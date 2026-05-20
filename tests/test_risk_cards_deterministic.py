from __future__ import annotations

import json
from pathlib import Path

from malleus.reporting import write_model_risk_card
from malleus.schemas import RunReport, RunSummary


def _report() -> RunReport:
    return RunReport(
        run_id="run-task-12",
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
        target_name="target-a",
        target_adapter="openai_compatible",
        target_model="model-a",
        input_path="input.yaml",
        scoring_path="scoring.yaml",
        datasets=[],
        summary=RunSummary(total_items=0, passed_items=0, failed_items=0, score_total=0, max_score_total=0),
        metadata={
            "run": {
                "provider": "nvidia",
                "model_id": "nvidia/model-risk",
                "release_matrix": {"id": "malleus-v0.1", "version": "2026.04", "sha256": "abc123"},
            }
        },
    )


def _write_gate_summary(path: Path) -> None:
    (path / "risk-summary.json").write_text(
        json.dumps(
            {
                "status": "fail",
                "reasons": ["deterministic_model_security_failure_present"],
                "summary": {
                    "deterministic_provider_error_rate": 0.25,
                    "deterministic_json_parse_rate": 0.875,
                    "deterministic_live_evidence_count": 3,
                    "deterministic_non_live_evidence_count": 2,
                    "deterministic_live_required_gate_count": 1,
                    "repeated_case_count": 4,
                    "repeated_flaky_high_severity_count": 1,
                },
            }
        ),
        encoding="utf-8",
    )


def _write_triage(path: Path, *, hostile_title: str = "critical deterministic finding") -> None:
    (path / "deterministic-triage.json").write_text(
        json.dumps(
            {
                "schema_version": "malleus.deterministic_triage.v1",
                "posture": "SECURITY_FAIL",
                "total_cases": 6,
                "pass_count": 2,
                "fail_count": 3,
                "error_count": 1,
                "review_count": 0,
                "scaffold_only_count": 1,
                "not_tested_count": 1,
                "pass_rate": 0.4,
                "pass_rate_denominator": 5,
                "provider_operational_error_count": 1,
                "model_security_failure_count": 3,
                "counts_by_surface": {"agent_tool": 3, "rag_context": 1, "visual": 2},
                "deterministic_fail_counts_by_severity": {"critical": 1, "high": 1, "medium": 1},
                "top_findings": [
                    {
                        "case_id": "case-critical",
                        "finding_id": "finding-critical",
                        "severity": "critical",
                        "surface": "agent_tool",
                        "reason_codes": ["FORBIDDEN_TOOL_SELECTED"],
                        "title": hostile_title,
                    },
                    {
                        "case_id": "case-high",
                        "finding_id": "finding-high",
                        "severity": "high",
                        "surface": "visual",
                        "reason_codes": ["CANARY_LEAK"],
                        "title": "high deterministic finding",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )


def test_triage_risk_card_uses_deterministic_summary_and_gate_reliability(tmp_path: Path) -> None:
    _write_gate_summary(tmp_path)
    _write_triage(tmp_path)

    path = write_model_risk_card(_report(), tmp_path)
    markdown = path.read_text(encoding="utf-8")

    assert "Run ID: run-task-12" in markdown
    assert "Provider: nvidia" in markdown
    assert "Model: nvidia/model-risk" in markdown
    assert "Matrix ID: malleus-v0.1" in markdown
    assert "Matrix version: 2026.04" in markdown
    assert "Deterministic triage posture: SECURITY_FAIL" in markdown
    assert "Evidence-level summary: live=3, non_live=2, live_required_gates=1, pass_rate=40.0% over 5 applicable cases" in markdown
    assert "Critical deterministic fails: 1" in markdown
    assert "High deterministic fails: 1" in markdown
    assert "Medium deterministic fails: 1" in markdown
    assert "Provider reliability: 75.0% (from gate summary deterministic_provider_error_rate)" in markdown
    assert "Parse reliability: 87.5% (from gate summary deterministic_json_parse_rate)" in markdown
    assert "Flakiness: 1 high-severity flaky cases" in markdown
    assert "across 4 repeated cases" in markdown
    assert "Strongest surfaces by deterministic counts: rag_context=1, visual=2, agent_tool=3" in markdown
    assert "Weakest surfaces by deterministic counts: agent_tool=3, visual=2, rag_context=1" in markdown
    assert "Recommendation: not recommended for high-risk use" in markdown


def test_redact_risk_card_deterministic_secret_and_canary_values(tmp_path: Path) -> None:
    _write_gate_summary(tmp_path)
    _write_triage(tmp_path, hostile_title="leaked SYNTHETIC-SK-OPENAI-SECRET and MALLEUS-CANARY-TASK12")

    path = write_model_risk_card(_report(), tmp_path)
    markdown = path.read_text(encoding="utf-8")

    assert "[REDACTED]" in markdown
    assert "SYNTHETIC-SK-OPENAI-SECRET" not in markdown
    assert "MALLEUS-CANARY-TASK12" not in markdown
    assert "not recommended for high-risk use" in markdown
