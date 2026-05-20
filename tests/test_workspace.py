from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from malleus.cli import app
from malleus.workspace import init_workspace, inspect_workspace, render_workspace_next, render_workspace_status


def test_workspace_init_creates_expected_local_layout(tmp_path: Path) -> None:
    root = init_workspace(tmp_path / "workspace", "rag-agent")

    assert (root / "threat-model.yaml").exists()
    assert (root / "workspace.json").exists()
    for name in ["runs", "findings", "patches", "adjudications", "coverage", "risk-cards"]:
        assert (root / name).is_dir()
    metadata = json.loads((root / "workspace.json").read_text(encoding="utf-8"))
    assert metadata["profile"] == "rag-agent"
    assert metadata["provider_calls_enabled"] is False
    assert metadata["local_only"] is True


def test_workspace_status_reports_artifact_state_and_safe_commands(tmp_path: Path) -> None:
    root = init_workspace(tmp_path / "workspace", "rag-agent")
    (root / "findings" / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": "malleus.findings.v1",
                "summary": {"total_findings": 1},
                "findings": [{"finding_id": "mf-open", "severity": "high", "title": "Open finding"}],
            }
        ),
        encoding="utf-8",
    )
    (root / "coverage" / "coverage.json").write_text(json.dumps({"summary": {"missing_cells": 2, "partial_cells": 1}, "cells": []}), encoding="utf-8")
    (root / "runs" / "risk-summary.json").write_text(json.dumps({"status": "fail", "reasons": ["blocking"]}), encoding="utf-8")

    status = inspect_workspace(root)
    text = render_workspace_status(status)

    assert status.unpatched_findings == 1
    assert status.missing_coverage == 3
    assert status.blocking_gates == 1
    assert status.adjudication_status == "not_supplied"
    assert "malleus patch suggest" in text
    assert "malleus replay <finding-id>" in text
    assert "does not run models" in text


def test_workspace_next_is_deterministic_and_local_only(tmp_path: Path) -> None:
    root = init_workspace(tmp_path / "workspace", "rag-agent")
    (root / "findings" / "findings.json").write_text(
        json.dumps({"schema_version": "malleus.findings.v1", "findings": [{"finding_id": "mf-open"}], "summary": {"total_findings": 1}}),
        encoding="utf-8",
    )

    first = render_workspace_next(inspect_workspace(root))
    second = render_workspace_next(inspect_workspace(root))

    assert first == second
    assert "malleus patch suggest" in first
    assert "malleus replay <finding-id> --report <workspace>/findings/findings.json --dry-run" in first
    assert "malleus run" not in first
    assert "campaign run" not in first


def test_workspace_cli_init_status_next_without_model_calls(tmp_path: Path) -> None:
    runner = CliRunner()
    root = tmp_path / "workspace"

    init_result = runner.invoke(app, ["workspace", "init", "--path", str(root), "--profile", "rag-agent"])
    status_result = runner.invoke(app, ["workspace", "status", "--path", str(root)])
    next_result = runner.invoke(app, ["workspace", "next", "--path", str(root)])

    assert init_result.exit_code == 0
    assert status_result.exit_code == 0
    assert next_result.exit_code == 0
    assert (root / "threat-model.yaml").exists()
    assert "Next safe commands" in status_result.output
    assert "malleus coverage build" in status_result.output
    assert "malleus coverage build" in next_result.output
