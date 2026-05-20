from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from malleus.cli import app
from malleus.code_agent import inspect_code_agent_trace
from malleus.utils.redact import scan_public_artifact_text

FIXTURES = Path("tests/fixtures/code_agent")
RAW_FIXTURE_SECRET = "SYNTHETIC-SK-CODE-AGENT-SECRET"

EXPECTED_RISKS = [
    ("generated-publish.yaml", "generated_file_publishing", "medium", "vcs"),
    ("secret-leak.yaml", "secret_leakage", "critical", "vcs"),
    ("dangerous-untracked.yaml", "dangerous_untracked_files", "high", "vcs"),
    ("policy-modification.yaml", "policy_file_modification", "high", "vcs"),
    ("missing-tests.yaml", "missing_tests", "high", "lifecycle"),
    ("skipped-planning.yaml", "skipped_planning_gate", "medium", "lifecycle"),
    ("skipped-review.yaml", "skipped_review_gate", "high", "lifecycle"),
    ("skipped-review.yaml", "commit_push_without_review", "critical", "vcs"),
    ("skipped-test.yaml", "skipped_test_gate", "high", "lifecycle"),
    ("push-deploy-no-approval.yaml", "push_deploy_without_approval", "critical", "vcs"),
    ("workspace-escape.yaml", "workspace_escape", "critical", "vcs"),
]


def _public_text(out: Path) -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in sorted(out.iterdir()) if path.suffix in {".json", ".md"})


def _findings_for(report_kind: str, fixture: str):
    inspection = inspect_code_agent_trace(FIXTURES / fixture)
    report = inspection.vcs_report if report_kind == "vcs" else inspection.lifecycle_report
    return report.findings


def test_code_agent_inspect_cli_writes_vcs_and_lifecycle_reports(tmp_path: Path) -> None:
    out = tmp_path / "code-agent"
    result = CliRunner().invoke(app, ["code-agent", "inspect", "--trace", str(FIXTURES / "push-deploy-no-approval.yaml"), "--out-dir", str(out)])

    assert result.exit_code == 0, result.output
    assert "Code-agent inspection complete" in result.output
    assert "Provider calls enabled: false" in result.output
    assert "VCS findings:" in result.output
    assert "Lifecycle findings:" in result.output
    expected = {"vcs-workflow-report.json", "vcs-workflow-report.md", "code-agent-lifecycle-report.json", "code-agent-lifecycle-report.md"}
    assert expected.issubset({path.name for path in out.iterdir()})

    vcs = json.loads((out / "vcs-workflow-report.json").read_text(encoding="utf-8"))
    lifecycle = json.loads((out / "code-agent-lifecycle-report.json").read_text(encoding="utf-8"))
    assert vcs["schema_version"] == "malleus.vcs_workflow_report.v1"
    assert lifecycle["schema_version"] == "malleus.code_agent_lifecycle_report.v1"
    assert vcs["mode"] == "local_fixture"
    assert lifecycle["provider_calls_enabled"] is False
    assert vcs["metadata"]["trace_execution_enabled"] is False
    assert vcs["metadata"]["git_mutation_enabled"] is False
    assert vcs["summary"]["gate_recommendation"] == "block"
    assert lifecycle["gates"]["planning"] is True
    assert lifecycle["gates"]["review"] is True
    assert lifecycle["gates"]["tests"] is True
    assert lifecycle["gates"]["all_required_satisfied"] is True
    assert "push_deploy_without_approval" in {finding["code"] for finding in vcs["findings"]}
    for finding in vcs["findings"]:
        assert finding["remediation"]
        assert finding["patch_recommendation"]
        assert finding["evidence"]["sha256"] and len(finding["evidence"]["sha256"]) == 64
        assert finding["evidence"]["length"] >= 1
        assert finding["evidence"]["redacted_preview"]
    assert vcs["wowpp_metadata"]["provider_calls_enabled"] is False
    assert vcs["evidence_refs"]
    assert vcs["coverage_cells"]


def test_fixture_matrix_covers_each_major_code_agent_risk() -> None:
    for fixture, expected_code, expected_severity, report_kind in EXPECTED_RISKS:
        matches = [finding for finding in _findings_for(report_kind, fixture) if finding.code == expected_code]

        assert matches, fixture
        assert any(finding.severity == expected_severity for finding in matches), fixture
        assert all(finding.remediation for finding in matches)
        assert all(finding.patch_recommendation for finding in matches)
        assert all(finding.evidence.sha256 and finding.evidence.length >= 1 for finding in matches)


def test_missing_review_before_push_is_flagged_in_vcs_report() -> None:
    inspection = inspect_code_agent_trace(FIXTURES / "skipped-review.yaml")
    lifecycle_codes = {finding.code for finding in inspection.lifecycle_report.findings}
    vcs_matches = [finding for finding in inspection.vcs_report.findings if finding.code == "commit_push_without_review"]

    assert "skipped_review_gate" in lifecycle_codes
    assert vcs_matches
    assert any(finding.severity in {"high", "critical"} for finding in vcs_matches)
    assert all(finding.gate == "review" for finding in vcs_matches)
    assert all(finding.remediation and finding.patch_recommendation for finding in vcs_matches)


def test_safe_lifecycle_fixture_has_all_gates_and_no_high_or_critical_findings(tmp_path: Path) -> None:
    inspection = inspect_code_agent_trace(FIXTURES / "safe-lifecycle.yaml", tmp_path / "safe")

    assert inspection.lifecycle_report.gates.planning is True
    assert inspection.lifecycle_report.gates.review is True
    assert inspection.lifecycle_report.gates.tests is True
    assert inspection.lifecycle_report.gates.approval is False
    assert inspection.lifecycle_report.gates.all_required_satisfied is True
    all_findings = [*inspection.vcs_report.findings, *inspection.lifecycle_report.findings]
    assert not [finding for finding in all_findings if finding.severity in {"high", "critical"}]
    assert inspection.vcs_report.summary.gate_recommendation in {"allow", "warn"}
    assert inspection.lifecycle_report.summary.gate_recommendation in {"allow", "warn"}
    assert scan_public_artifact_text(_public_text(tmp_path / "safe")).passed


def test_public_reports_redact_secret_paths_and_raw_trace_payloads(tmp_path: Path) -> None:
    out = tmp_path / "secret"
    inspect_code_agent_trace(FIXTURES / "secret-leak.yaml", out)

    public_text = _public_text(out)
    assert RAW_FIXTURE_SECRET not in public_text
    assert "/home/" not in public_text
    assert "[REDACTED_CODE_AGENT_TRACE]" in public_text
    assert "sha256=" in public_text
    assert "length=" in public_text
    assert scan_public_artifact_text(public_text).passed


def test_workspace_escape_paths_are_hashed_not_published(tmp_path: Path) -> None:
    out = tmp_path / "escape"
    inspect_code_agent_trace(FIXTURES / "workspace-escape.yaml", out)
    payload = json.loads((out / "vcs-workflow-report.json").read_text(encoding="utf-8"))
    findings = [finding for finding in payload["findings"] if finding["code"] == "workspace_escape"]

    assert findings
    assert all(finding["evidence"]["path"].startswith("[REDACTED_PATH sha256=") for finding in findings)
    public_text = _public_text(out)
    assert "../outside.txt" not in public_text
    assert scan_public_artifact_text(public_text).passed
