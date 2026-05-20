from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from malleus.cli import app
from malleus.issue_export import export_issues_from_findings
from malleus.utils.redact import scan_public_artifact_text

FIXTURE = Path("tests/fixtures/issue_export/findings.json")
RAW_FORBIDDEN = ["token=ISSUESECRET", "ignore previous instructions", "developer message", "/home/"]


def _combined_text(path: Path) -> str:
    return "\n".join(child.read_text(encoding="utf-8") for child in sorted(path.rglob("*")) if child.is_file())


def test_issue_export_writes_local_issues_json_and_remediation_board(tmp_path: Path) -> None:
    artifact, paths = export_issues_from_findings(FIXTURE, tmp_path / "issues-out")

    assert artifact.schema_version == "malleus.issue_export.v1"
    assert artifact.summary.total_issues == 3
    assert artifact.github_creation_enabled is False
    assert artifact.github_creation_status == "disabled"
    assert paths["json"].name == "issue-export.json"
    assert paths["board"].name == "remediation-board.md"
    assert paths["issues_dir"].is_dir()
    assert len(list(paths["issues_dir"].glob("*.md"))) == 3

    exported = json.loads(paths["json"].read_text(encoding="utf-8"))
    labels = {label for issue in exported["issues"] for label in issue["labels"]}
    assert {"visual-artifact", "mutation-regression", "tool-plugin", "needs-triage"} <= labels
    for issue in exported["issues"]:
        assert issue["owner"] == "@owner-tbd"
        assert issue["severity"] in {"critical", "high"}
        assert issue["reproduction_command"]
        assert issue["acceptance_tests"]
        assert issue["patch_suggestion"]
        assert issue["regression_commands"]
        assert issue["closure_criteria"]
        assert issue["markdown_path"].startswith("issues/")

    board = paths["board"].read_text(encoding="utf-8")
    assert "Malleus Remediation Board" in board
    assert "Closure criteria" in board
    assert "@owner-tbd" in board


def test_issue_export_redacts_unsafe_secret_and_private_path_values(tmp_path: Path) -> None:
    _, paths = export_issues_from_findings(FIXTURE, tmp_path / "redacted")

    combined = _combined_text(tmp_path / "redacted")
    for forbidden in RAW_FORBIDDEN:
        assert forbidden not in combined
    assert "[REDACTED]" in combined
    assert "sha256=" in combined
    assert "length=" in combined
    assert scan_public_artifact_text(combined).passed


def test_issue_export_cli_and_github_fail_closed(tmp_path: Path) -> None:
    runner = CliRunner()
    out = tmp_path / "cli"

    result = runner.invoke(app, ["issues", "export", "--findings", str(FIXTURE), "--out-dir", str(out), "--github-scaffold"])

    assert result.exit_code == 0, result.output
    assert "Issue export written" in result.output
    assert "GitHub creation enabled: false" in result.output
    assert "GitHub creation status: scaffold_only" in result.output
    payload = json.loads((out / "issue-export.json").read_text(encoding="utf-8"))
    assert payload["github_creation_enabled"] is False
    assert payload["github_creation_status"] == "scaffold_only"
    assert "never invokes gh" in payload["github_scaffold_note"]

    blocked = runner.invoke(app, ["issues", "export", "--findings", str(FIXTURE), "--out-dir", str(tmp_path / "blocked"), "--create-github"])
    assert blocked.exit_code == 1
    assert "disabled" in blocked.output
    assert not (tmp_path / "blocked" / "issue-export.json").exists()
