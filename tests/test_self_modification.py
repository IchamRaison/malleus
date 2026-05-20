from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from malleus.cli import app
from malleus.self_modification import inspect_self_modification
from malleus.utils.redact import scan_public_artifact_text

FIXTURES = Path("tests/fixtures/self_modification")


def _public_text(out: Path) -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in sorted(out.iterdir()) if path.suffix in {".json", ".md"})


def test_self_mod_inspect_cli_writes_report_and_flags_policy_weakening(tmp_path: Path) -> None:
    out = tmp_path / "self-mod"
    result = CliRunner().invoke(app, ["self-mod", "inspect", "--diff", str(FIXTURES / "policy-weakening.diff"), "--out-dir", str(out)])

    assert result.exit_code == 0, result.output
    assert "Self-modification inspection complete" in result.output
    assert "Provider calls enabled: false" in result.output
    assert {"self-modification-report.json", "self-modification-report.md"}.issubset({path.name for path in out.iterdir()})

    payload = json.loads((out / "self-modification-report.json").read_text(encoding="utf-8"))
    assert payload["schema_version"] == "malleus.self_modification_report.v1"
    assert payload["mode"] == "local_fixture"
    assert payload["provider_calls_enabled"] is False
    assert payload["metadata"]["diff_application_enabled"] is False
    assert payload["metadata"]["trace_execution_enabled"] is False
    assert payload["metadata"]["autonomous_self_editing_enabled"] is False
    assert payload["summary"]["gate_recommendation"] == "block"
    matches = [finding for finding in payload["findings"] if finding["code"] == "guardrail_weakening"]
    assert matches
    assert any(finding["severity"] == "critical" for finding in matches)
    assert all(finding["patch_suggestion"] and finding["replay_suggestion"] for finding in matches)
    assert payload["wowpp_metadata"]["provider_calls_enabled"] is False
    assert payload["evidence_refs"]
    assert payload["coverage_cells"]
    assert scan_public_artifact_text(_public_text(out)).passed


def test_benign_docs_only_diff_has_no_high_or_critical_findings(tmp_path: Path) -> None:
    out = tmp_path / "benign"
    report = inspect_self_modification([FIXTURES / "benign-docs.diff"], [], out)

    assert not [finding for finding in report.findings if finding.severity in {"high", "critical"}]
    assert report.summary.gate_recommendation == "allow"
    assert "low risk" in report.summary.rationale
    markdown = (out / "self-modification-report.md").read_text(encoding="utf-8")
    assert "No high-risk self-modification patterns" in markdown
    assert scan_public_artifact_text(_public_text(out)).passed


def test_fixture_matrix_covers_required_self_modification_detection_classes() -> None:
    report = inspect_self_modification([FIXTURES / "policy-weakening.diff", FIXTURES / "risk-matrix.diff"], [FIXTURES / "loop-trace.yaml"])
    codes = {finding.code for finding in report.findings}

    assert "guardrail_weakening" in codes
    assert "hidden_change" in codes
    assert "scoring_threshold_change" in codes
    assert "test_weakening" in codes
    assert "unsafe_tool_addition" in codes
    assert "self_modification_loop" in codes
    assert report.summary.counts_by_code["guardrail_weakening"] >= 1
    assert report.summary.gate_recommendation == "block"
    assert all(finding.evidence.sha256 and finding.evidence.length >= 1 for finding in report.findings)


def test_public_reports_redact_unsafe_payloads_and_private_paths(tmp_path: Path) -> None:
    out = tmp_path / "matrix"
    inspect_self_modification([FIXTURES / "risk-matrix.diff"], [FIXTURES / "loop-trace.yaml"], out)

    public_text = _public_text(out)
    assert "subprocess.run" not in public_text
    assert "while True" not in public_text
    assert "/home/" not in public_text
    assert "[REDACTED_SELF_MODIFICATION]" in public_text
    assert "sha256=" in public_text
    assert "length=" in public_text
    assert scan_public_artifact_text(public_text).passed


def test_provider_enabled_trace_fails_closed(tmp_path: Path) -> None:
    trace = tmp_path / "provider-trace.yaml"
    trace.write_text("schema_version: test\nprovider_calls_enabled: true\nevents: []\n", encoding="utf-8")

    result = CliRunner().invoke(app, ["self-mod", "inspect", "--trace", str(trace), "--out-dir", str(tmp_path / "out")])

    assert result.exit_code == 1
    assert "provider-free local fixture" in result.output
