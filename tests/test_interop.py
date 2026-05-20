from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

from typer.testing import CliRunner

from malleus.cli import app

FIXTURES = Path("tests/fixtures/interop")
FINDINGS = Path("tests/fixtures/findings/findings.json")
UNSAFE_STRINGS = ["Ignore previous instructions", "system prompt", "PFSECRET", "GARAKSECRET", "PYRITSECRET", "INSPECTSECRET"]


def _assert_no_unsafe_text(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    for unsafe in UNSAFE_STRINGS:
        assert unsafe not in text


def test_promptfoo_import_writes_sanitized_findings_and_lossy_warnings(tmp_path: Path) -> None:
    out = tmp_path / "imported"
    result = CliRunner().invoke(app, ["import", "promptfoo", str(FIXTURES / "promptfoo-result.json"), "--out-dir", str(out)])

    assert result.exit_code == 0, result.output
    findings = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    report = json.loads((out / "interop-report.json").read_text(encoding="utf-8"))

    assert findings["summary"]["total_findings"] == 1
    assert findings["findings"][0]["source_type"] == "interop"
    assert findings["findings"][0]["metadata"]["interop_source"] == "promptfoo"
    assert report["normalized_finding_count"] == 1
    assert report["warnings"]
    assert any("unsupported" in warning for warning in report["unsupported_field_warnings"])
    _assert_no_unsafe_text(out / "findings.json")
    _assert_no_unsafe_text(out / "findings.md")
    _assert_no_unsafe_text(out / "interop-report.json")


def test_import_warning_field_labels_redact_secret_like_external_keys(tmp_path: Path) -> None:
    fixture = tmp_path / "promptfoo-secret-keys.json"
    fixture.write_text(
        json.dumps(
            {
                "version": 1,
                "token=TOPLEVELSECRET": "top-level value",
                "results": [
                    {
                        "id": "pf-secret-key-case",
                        "success": False,
                        "severity": "high",
                        "prompt": "safe placeholder",
                        "response": "safe placeholder",
                        "unsupported_token=ROWSECRET": "row value",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "imported-secret-keys"

    result = CliRunner().invoke(app, ["import", "promptfoo", str(fixture), "--out-dir", str(out)])

    assert result.exit_code == 0, result.output
    report = json.loads((out / "interop-report.json").read_text(encoding="utf-8"))
    assert len(report["unsupported_field_warnings"]) == 2
    assert all("field_sha256=" in warning for warning in report["unsupported_field_warnings"])
    artifact_text = "\n".join(
        [
            (out / "findings.json").read_text(encoding="utf-8"),
            (out / "findings.md").read_text(encoding="utf-8"),
            (out / "interop-report.json").read_text(encoding="utf-8"),
        ]
    )
    for leaked in ["TOPLEVELSECRET", "ROWSECRET", "token=TOPLEVELSECRET", "unsupported_token=ROWSECRET"]:
        assert leaked not in artifact_text


def test_all_minimum_import_sources_normalize(tmp_path: Path) -> None:
    fixtures = {
        "garak": "garak-result.json",
        "pyrit": "pyrit-result.json",
        "inspect": "inspect-result.json",
    }
    for source, fixture in fixtures.items():
        out = tmp_path / source
        result = CliRunner().invoke(app, ["import", source, str(FIXTURES / fixture), "--out-dir", str(out)])
        assert result.exit_code == 0, result.output
        payload = json.loads((out / "findings.json").read_text(encoding="utf-8"))
        assert payload["summary"]["total_findings"] == 1
        assert payload["findings"][0]["metadata"]["interop_source"] == source
        _assert_no_unsafe_text(out / "findings.json")


def test_invalid_import_schema_fails_cleanly(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, ["import", "promptfoo", str(FIXTURES / "invalid-result.json"), "--out-dir", str(tmp_path / "bad")])

    assert result.exit_code == 1
    assert "invalid promptfoo schema" in result.output
    assert not (tmp_path / "bad" / "findings.json").exists()


def test_export_sarif_junit_github_promptfoo_and_inspect_shapes(tmp_path: Path) -> None:
    runner = CliRunner()

    sarif = tmp_path / "malleus.sarif"
    sarif_result = runner.invoke(app, ["export", "sarif", "--findings", str(FINDINGS), "--out", str(sarif)])
    assert sarif_result.exit_code == 0, sarif_result.output
    sarif_payload = json.loads(sarif.read_text(encoding="utf-8"))
    assert sarif_payload["version"] == "2.1.0"
    assert sarif_payload["runs"][0]["tool"]["driver"]["name"] == "Malleus"
    assert sarif_payload["runs"][0]["results"]

    junit = tmp_path / "malleus.xml"
    junit_result = runner.invoke(app, ["export", "junit", "--findings", str(FINDINGS), "--out", str(junit)])
    assert junit_result.exit_code == 0, junit_result.output
    suite = ET.fromstring(junit.read_text(encoding="utf-8"))
    assert suite.tag == "testsuite"
    assert suite.findall("testcase")

    github = tmp_path / "annotations.json"
    github_result = runner.invoke(app, ["export", "github", "--findings", str(FINDINGS), "--out", str(github)])
    assert github_result.exit_code == 0, github_result.output
    annotations = json.loads(github.read_text(encoding="utf-8"))
    assert {"path", "start_line", "title", "message"}.issubset(annotations[0])

    promptfoo = tmp_path / "promptfoo.json"
    promptfoo_result = runner.invoke(app, ["export", "promptfoo", "--findings", str(FINDINGS), "--out", str(promptfoo)])
    assert promptfoo_result.exit_code == 0, promptfoo_result.output
    promptfoo_payload = json.loads(promptfoo.read_text(encoding="utf-8"))
    assert promptfoo_payload["results"][0]["metadata"]["finding_id"] == "mf-interop-fixture-1"

    inspect = tmp_path / "inspect.json"
    inspect_result = runner.invoke(app, ["export", "inspect", "--findings", str(FINDINGS), "--out", str(inspect)])
    assert inspect_result.exit_code == 0, inspect_result.output
    inspect_payload = json.loads(inspect.read_text(encoding="utf-8"))
    assert inspect_payload["samples"][0]["id"] == "mf-interop-fixture-1"


def test_github_jsonl_export_shape(tmp_path: Path) -> None:
    out = tmp_path / "annotations.jsonl"
    result = CliRunner().invoke(app, ["export", "github", "--findings", str(FINDINGS), "--out", str(out)])

    assert result.exit_code == 0, result.output
    lines = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert lines[0]["annotation_level"] == "failure"
