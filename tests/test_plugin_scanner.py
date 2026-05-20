from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from malleus.cli import app
from malleus.plugin_scanner import scan_plugin_manifest
from malleus.utils.redact import scan_public_artifact_text

FIXTURES = Path("tests/fixtures/plugins")

EXPECTED_RISKS = [
    ("dangerous-route.yaml", "dangerous_route", "critical"),
    ("excessive-permissions.yaml", "excessive_permissions", "critical"),
    ("contract-mismatch.yaml", "contract_route_mismatch", "medium"),
    ("secret-example.yaml", "secret_in_example", "high"),
    ("external-sink.yaml", "external_network_sink", "high"),
    ("missing-approval.yaml", "missing_approval", "high"),
    ("ambiguous-name.yaml", "ambiguous_tool_name", "medium"),
    ("unsafe-default.yaml", "unsafe_default_action", "high"),
]


def _public_text(out: Path) -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in sorted(out.iterdir()) if path.suffix in {".json", ".md"})


def test_plugin_scan_cli_writes_safe_reports_for_unsafe_openapi(tmp_path: Path) -> None:
    out = tmp_path / "plugin"
    result = CliRunner().invoke(app, ["plugin-scan", "--input", str(FIXTURES / "unsafe-openapi.yaml"), "--out-dir", str(out)])

    assert result.exit_code == 0, result.output
    assert "Plugin risk scan complete" in result.output
    assert "Provider calls enabled: false" in result.output
    assert {"plugin-risk-report.json", "plugin-risk-report.md", "plugin-risk-findings.json"}.issubset({path.name for path in out.iterdir()})

    payload = json.loads((out / "plugin-risk-report.json").read_text(encoding="utf-8"))
    codes = {finding["code"] for finding in payload["findings"]}
    assert payload["schema_version"] == "malleus.plugin_risk_report.v1"
    assert payload["mode"] == "local_fixture"
    assert payload["provider_calls_enabled"] is False
    assert payload["metadata"]["remote_schema_fetch_enabled"] is False
    assert payload["metadata"]["plugin_code_execution_enabled"] is False
    assert payload["wowpp_metadata"]["provider_calls_enabled"] is False
    assert payload["summary"]["gate_recommendation"] == "block"
    assert {code for _, code, _ in EXPECTED_RISKS} <= codes
    assert payload["coverage_cells"]
    assert payload["evidence_refs"]

    for finding in payload["findings"]:
        evidence = finding["evidence"]
        assert finding["recommendation"]
        assert finding["approval_gate"]
        assert finding["coverage_tags"]
        assert evidence["source_path"] == "tests/fixtures/plugins/unsafe-openapi.yaml"
        assert evidence["route_hash"] and len(evidence["route_hash"]) == 64
        assert evidence["route_length"] >= 1
        assert evidence["sha256"] and len(evidence["sha256"]) == 64
        assert "redacted_preview" in evidence

    public_text = _public_text(out)
    assert "SYNTHETIC-SK-PLUGIN-SECRET" not in public_text
    assert "[REDACTED]" in public_text
    assert "sha256=" in public_text
    assert "length=" in public_text
    assert "/home/" not in public_text
    assert scan_public_artifact_text(public_text).passed


def test_plugin_fixture_matrix_covers_each_risk_class_with_expected_severity() -> None:
    for fixture, expected_code, expected_severity in EXPECTED_RISKS:
        report = scan_plugin_manifest(FIXTURES / fixture)
        matches = [finding for finding in report.findings if finding.code == expected_code]

        assert matches, fixture
        assert any(finding.severity == expected_severity for finding in matches), fixture
        assert all(finding.recommendation for finding in matches)
        assert all(finding.approval_gate for finding in matches)
        assert all(finding.evidence.route_hash and finding.evidence.route_length for finding in matches)


def test_safe_plugin_fixture_remains_low_or_no_risk(tmp_path: Path) -> None:
    report = scan_plugin_manifest(FIXTURES / "safe-openapi.yaml", tmp_path / "safe")
    payload = json.loads((tmp_path / "safe" / "plugin-risk-report.json").read_text(encoding="utf-8"))

    assert report.summary.total_findings == 0
    assert report.summary.highest_severity is None
    assert report.summary.gate_recommendation == "allow"
    assert payload["findings"] == []
    assert payload["summary"]["total_findings"] == 0
    assert scan_public_artifact_text(_public_text(tmp_path / "safe")).passed


def test_secret_redaction_in_public_plugin_artifacts(tmp_path: Path) -> None:
    out = tmp_path / "secret"
    scan_plugin_manifest(FIXTURES / "secret-example.yaml", out)

    public_text = _public_text(out)
    assert "SYNTHETIC-SK-PLUGIN-SECRET" not in public_text
    assert "[REDACTED]" in public_text
    assert "sha256=" in public_text
    assert "length=" in public_text
    assert scan_public_artifact_text(public_text).passed
