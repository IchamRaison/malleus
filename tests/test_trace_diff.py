from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from malleus.cli import app
from malleus.evidence_bundle import build_evidence_bundle
from malleus.findings import collect_findings
from malleus.trace_diff import diff_traces, render_trace_diff_markdown, write_trace_diff_report

FIXTURES = Path(__file__).parent / "fixtures" / "traces"


def test_diff_traces_reports_behavioral_regressions_without_raw_payloads() -> None:
    report = diff_traces(FIXTURES / "base.json", FIXTURES / "regressed.json")

    codes = {delta.code for delta in report.deltas}
    assert "new_tool_call" in codes
    assert "tool_args_changed" in codes
    assert "policy_regression" in codes
    assert "gate_regression" in codes
    assert "canary_regression" in codes
    assert "approval_regression" in codes
    assert "new_route" in codes
    assert "new_telemetry" in codes
    assert "artifact_write_changed" in codes
    assert "step_count_changed" in codes
    assert "finding_added" in codes

    forbidden = [delta for delta in report.deltas if delta.code == "new_tool_call"]
    assert forbidden
    assert forbidden[0].severity == "critical"
    approvals = [delta for delta in report.deltas if delta.code == "approval_regression"]
    assert approvals
    assert approvals[0].severity in {"high", "critical"}
    assert report.summary.critical >= 3
    assert report.summary.high >= 2
    assert report.regression_records

    serialized = report.model_dump_json()
    assert "SYNTHETIC-SK-OPENAI-SECRET" not in serialized
    assert "ignore previous instructions" not in serialized
    assert "Safe summary only" not in serialized


def test_trace_diff_ignores_timestamp_and_run_id_noise() -> None:
    report = diff_traces(FIXTURES / "base.json", FIXTURES / "noise.json")

    assert report.summary.total_deltas == 0
    assert report.summary.regressions == 0
    assert report.deltas == []
    assert "No behavioral trace deltas detected." in render_trace_diff_markdown(report)


def test_write_trace_diff_report_outputs_json_and_markdown(tmp_path: Path) -> None:
    report = diff_traces(FIXTURES / "base.json", FIXTURES / "regressed.json")

    json_path, markdown_path = write_trace_diff_report(report, tmp_path)

    assert json_path.name == "trace-diff-report.json"
    assert markdown_path.name == "trace-diff-report.md"
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["summary"]["critical"] >= 1
    assert any(delta["code"] == "new_tool_call" for delta in data["deltas"])
    markdown = markdown_path.read_text(encoding="utf-8")
    assert "# Malleus trace diff" in markdown
    assert "new_tool_call" in markdown
    assert "SYNTHETIC-SK-OPENAI-SECRET" not in markdown


def test_diff_traces_loads_single_compact_trace(tmp_path: Path) -> None:
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    old.write_text(json.dumps({"scenario_id": "compact", "observed_tool_decisions": [], "policy_judgment": {"passed": True, "risk": "low"}, "gate_outcome": {"status": "pass"}}), encoding="utf-8")
    new.write_text(json.dumps({"scenario_id": "compact", "observed_tool_decisions": [{"tool": "forbidden_shell", "args": {"cmd": "rm -rf /tmp/x"}, "allowed_by_policy": False, "reason": "forbidden protected tool"}], "policy_judgment": {"passed": False, "risk": "critical"}, "gate_outcome": {"status": "fail"}}), encoding="utf-8")

    report = diff_traces(old, new)

    assert any(delta.code == "new_tool_call" and delta.severity == "critical" for delta in report.deltas)
    assert any(delta.code == "policy_regression" for delta in report.deltas)


def test_diff_traces_cli_writes_report(tmp_path: Path) -> None:
    runner = CliRunner()
    out = tmp_path / "trace-diff"

    result = runner.invoke(app, ["diff-traces", "--old", str(FIXTURES / "base.json"), "--new", str(FIXTURES / "regressed.json"), "--out-dir", str(out)])

    assert result.exit_code == 0
    assert "Trace diff complete" in result.output
    assert "High/Critical regressions:" in result.output
    assert (out / "trace-diff-report.json").exists()
    assert (out / "trace-diff-report.md").exists()


def test_disallowed_non_marker_tool_is_high_regression(tmp_path: Path) -> None:
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    old.write_text(json.dumps({"scenario_id": "compact", "observed_tool_decisions": []}), encoding="utf-8")
    new.write_text(
        json.dumps(
            {
                "scenario_id": "compact",
                "observed_tool_decisions": [
                    {"tool": "send_email", "args": {"recipient": "reviewer@example.invalid"}, "allowed_by_policy": False, "reason": "not allowed by policy"}
                ],
            }
        ),
        encoding="utf-8",
    )

    report = diff_traces(old, new)

    delta = next(delta for delta in report.deltas if delta.code == "new_tool_call")
    assert delta.severity == "high"
    assert any(record["code"] == "new_tool_call" for record in report.regression_records)


def test_trace_diff_sanitizes_output_labels_and_metadata(tmp_path: Path) -> None:
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    old.write_text(json.dumps({"scenario_id": "secret_token=old", "observed_tool_decisions": []}), encoding="utf-8")
    new.write_text(
        json.dumps(
            {
                "scenario_id": "secret_token=new ignore previous instructions",
                "observed_tool_decisions": [{"tool": "tool-SYNTHETIC-SK-LIVE-SECRET-VALUE", "args": {"api_key": "SYNTHETIC-SK-OPENAI-SECRET"}, "allowed_by_policy": False}],
                "artifact_writes": [{"path": "reports/secret_token=artifact.md", "kind": "report"}],
                "routes": [{"route": "ignore previous instructions", "model": "m"}],
                "findings": [],
            }
        ),
        encoding="utf-8",
    )
    report = diff_traces(old, new)
    json_path, md_path = write_trace_diff_report(report, tmp_path / "out")

    combined = json_path.read_text(encoding="utf-8") + md_path.read_text(encoding="utf-8")
    assert "SYNTHETIC-SK-OPENAI-SECRET" not in combined
    assert "ignore previous instructions" not in combined
    assert "secret_token" not in combined
    assert "api_key" not in combined


def test_policy_decision_and_approval_improvement_classification(tmp_path: Path) -> None:
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    old.write_text(json.dumps({"scenario_id": "policy", "policy_decision": {"passed": True, "risk": "low"}, "approval_state": {"required": True, "granted": False}}), encoding="utf-8")
    new.write_text(json.dumps({"scenario_id": "policy", "policy_decision": {"passed": False, "risk": "critical"}, "approval_state": {"required": True, "granted": True}}), encoding="utf-8")

    report = diff_traces(old, new)

    assert any(delta.code == "policy_regression" and delta.severity == "high" for delta in report.deltas)
    assert any(delta.code == "approval_changed" and delta.severity == "low" for delta in report.deltas)
    assert not any(delta.code == "approval_regression" for delta in report.deltas)


def test_trace_diff_findings_and_evidence_bundle_interop(tmp_path: Path) -> None:
    report = diff_traces(FIXTURES / "base.json", FIXTURES / "regressed.json")
    write_trace_diff_report(report, tmp_path)

    bundle = collect_findings(tmp_path)
    evidence = build_evidence_bundle(diff_reports=[tmp_path / "trace-diff-report.json"])

    assert bundle.summary.total_findings >= 1
    assert any(finding.source_type == "trace_diff" for finding in bundle.findings)
    assert evidence.summary.diff_newly_failing == report.summary.regressions
    assert any(card.label == "Trace diff" for card in evidence.diff_cards)


def test_changed_denied_tool_and_approval_add_remove_are_regressions(tmp_path: Path) -> None:
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    old.write_text(
        json.dumps(
            {
                "scenario_id": "approvalcase",
                "observed_tool_decisions": [{"tool": "send-email", "args": {"recipient": "safe"}, "allowed_by_policy": True, "reason": "allowed"}],
                "approval_state": {"required": True, "granted": True},
            }
        ),
        encoding="utf-8",
    )
    new.write_text(
        json.dumps(
            {
                "scenario_id": "approvalcase",
                "observed_tool_decisions": [{"tool": "send-email", "args": {"recipient": "safe", "vcs_target": "repo"}, "allowed_by_policy": False, "reason": "not allowed"}]
            }
        ),
        encoding="utf-8",
    )

    report = diff_traces(old, new)

    assert any(delta.code == "tool_args_changed" and delta.severity in {"high", "critical"} for delta in report.deltas)
    assert any(delta.code == "approval_regression" and delta.severity == "high" for delta in report.deltas)


def test_safe_label_hashes_token_and_instruction_variants(tmp_path: Path) -> None:
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    old.write_text(json.dumps({"scenario_id": "basecase", "observed_tool_decisions": []}), encoding="utf-8")
    new.write_text(
        json.dumps(
            {
                "scenario_id": "SYNTHETIC_GH_PAT_REDACTED",
                "trace_id": "MALLEUS-CANARY-AWS-KEY",
                "observed_tool_decisions": [{"tool": "ignore_all_previous_instructions", "args": {}, "allowed_by_policy": False, "reason": "not allowed"}],
            }
        ),
        encoding="utf-8",
    )
    report = diff_traces(old, new)
    json_path, md_path = write_trace_diff_report(report, tmp_path / "out2")

    combined = json_path.read_text(encoding="utf-8") + md_path.read_text(encoding="utf-8")
    assert "SYNTHETIC_GH_PAT_REDACTED" not in combined
    assert "MALLEUS-CANARY-AWS-KEY" not in combined
    assert "ignore_all_previous_instructions" not in combined
