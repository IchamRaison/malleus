from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from malleus.cli import app
from malleus.compound_risk import build_compound_risk_report, render_compound_risk_html, write_compound_risk_report
from malleus.utils.redact import scan_public_artifact_text


def _write(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _findings_bundle(tmp_path: Path) -> Path:
    return _write(
        tmp_path / "findings.json",
        {
            "schema_version": "malleus.findings.v1",
            "generated_at": "2026-04-25T00:00:00+00:00",
            "summary": {"total_findings": 2, "counts_by_severity": {"high": 1, "critical": 1}, "counts_by_source": {"visual_lab": 1, "rag_harness": 1}, "highest_severity": "critical"},
            "findings": [
                {
                    "finding_id": "mf-visual-1",
                    "title": "Visual metadata instruction",
                    "source_type": "visual_lab",
                    "affected_model": {"name": "local-visual-lab", "adapter": None, "model": None, "config": "visual_lab"},
                    "severity": "high",
                    "attack_surface": "visual",
                    "technique": "metadata_instruction",
                    "violated_boundary": "untrusted_context_boundary",
                    "taxonomy_refs": ["visual_lab"],
                    "reproduction_command": "malleus visual-lab run --fixture fixture.yaml --out-dir out",
                    "evidence_refs": [
                        {"evidence_id": "ev-visual", "artifact_path": "visual-lab-report.json", "artifact_type": "visual_lab_report_json", "json_pointer": "/results/0", "redaction_status": "redacted", "sha256": "a" * 64, "redacted_excerpt": "redacted visual evidence"}
                    ],
                    "redacted_excerpts": ["[REDACTED] unsafe sha256=abcd length=20"],
                    "patch_recommendation": "Treat visual context as untrusted.",
                    "regression_case_link": "visual:s1",
                    "replay_spec": {"replay_id": "rv", "finding_id": "mf-visual-1", "mode": "dry_run", "command": "malleus visual-lab run --fixture fixture.yaml --out-dir out", "target_name": "visual"},
                    "metadata": {},
                },
                {
                    "finding_id": "mf-rag-1",
                    "title": "RAG context leakage",
                    "source_type": "rag_harness",
                    "affected_model": {"name": "local-rag-fixture", "adapter": None, "model": None, "config": "rag"},
                    "severity": "critical",
                    "attack_surface": "rag_context",
                    "technique": "context_leakage",
                    "violated_boundary": "untrusted_context_boundary",
                    "taxonomy_refs": ["rag_security"],
                    "reproduction_command": "malleus rag run --fixture fixture.yaml --out-dir out",
                    "evidence_refs": [
                        {"evidence_id": "ev-rag", "artifact_path": "rag-report.json", "artifact_type": "rag_report_json", "json_pointer": "/results/0/detections/0", "redaction_status": "redacted", "sha256": "b" * 64, "redacted_excerpt": "redacted rag evidence"}
                    ],
                    "redacted_excerpts": ["query hash only"],
                    "patch_recommendation": "Isolate retrieval context.",
                    "regression_case_link": "rag:q1",
                    "replay_spec": {"replay_id": "rr", "finding_id": "mf-rag-1", "mode": "dry_run", "command": "malleus rag run --fixture fixture.yaml --out-dir out", "target_name": "rag"},
                    "metadata": {},
                },
            ],
        },
    )


def _plugin_report(tmp_path: Path) -> Path:
    return _write(
        tmp_path / "plugin-risk-report.json",
        {
            "schema_version": "malleus.plugin_risk_report.v1",
            "findings": [
                {
                    "finding_id": "plugin-1",
                    "code": "missing_approval",
                    "severity": "high",
                    "title": "Tool can write without approval",
                    "description": "approval gate is absent; raw secret SYNTHETIC-SK-OPENAI-SECRET should not publish",
                    "recommendation": "Require approval for write tools.",
                    "evidence": {"json_pointer": "/paths/~1write", "sha256": "c" * 64},
                }
            ],
            "summary": {"total_findings": 1},
        },
    )


def _code_agent_report(tmp_path: Path, name: str, schema: str) -> Path:
    return _write(
        tmp_path / name,
        {
            "schema_version": schema,
            "findings": [
                {
                    "finding_id": f"{name}-1",
                    "code": "push_without_review" if "vcs" in name else "missing_tests",
                    "severity": "medium",
                    "title": "Change-control gate missing",
                    "description": "Local fixture summary only from /home/private/workspace",
                    "remediation": "Require review and tests before VCS/deploy actions.",
                    "evidence": {"json_pointer": "/findings/0", "sha256": "d" * 64},
                }
            ],
            "summary": {"total_findings": 1},
        },
    )


def test_compound_risk_groups_visual_rag_tool_and_vcs_surfaces(tmp_path: Path) -> None:
    report = build_compound_risk_report(
        [
            _findings_bundle(tmp_path),
            _plugin_report(tmp_path),
            _code_agent_report(tmp_path, "vcs-workflow-report.json", "malleus.vcs_workflow_report.v1"),
            _code_agent_report(tmp_path, "code-agent-lifecycle-report.json", "malleus.code_agent_lifecycle_report.v1"),
        ]
    )

    assert report.provider_calls_enabled is False
    assert report.summary.total_findings == 5
    assert report.summary.total_scenarios >= 3
    assert {"visual", "rag_context", "tool_plugin_manifest", "vcs_workflow", "code_agent_lifecycle"}.issubset(set(report.summary.attack_surfaces))
    assert any(scenario.attack_surface == "rag_context" or "rag_context" in scenario.linked_surfaces for scenario in report.scenarios)
    assert any(scenario.threat_class == "agent_tool_misuse" for scenario in report.scenarios)
    assert any(scenario.threat_class == "code_change_control_failure" for scenario in report.scenarios)
    assert all(scenario.evidence_refs for scenario in report.scenarios)
    assert all(scenario.countermeasure for scenario in report.scenarios)


def test_compound_risk_writes_local_only_sanitized_reports(tmp_path: Path) -> None:
    report = build_compound_risk_report([_findings_bundle(tmp_path), _plugin_report(tmp_path)])

    json_path, markdown_path, html_path = write_compound_risk_report(report, tmp_path / "out")

    assert json_path.name == "compound-risk-report.json"
    assert markdown_path.name == "compound-risk-report.md"
    assert html_path.name == "compound-risk-report.html"
    combined = "\n".join(path.read_text(encoding="utf-8") for path in [json_path, markdown_path, html_path])
    lowered = combined.lower()
    assert "SYNTHETIC-SK-OPENAI-SECRET" not in combined
    assert "/home/" not in combined
    assert "http://" not in lowered
    assert "https://" not in lowered
    assert "cdn" not in lowered
    assert "raw secret" not in lowered
    assert "deterministic ordinal heuristic" in lowered
    assert scan_public_artifact_text(combined).passed
    html = render_compound_risk_html(report)
    assert "Graph-like local scenario table" in html
    assert "Risk cards" in html
    assert "<script" not in html.lower()


def test_compound_risk_cli_writes_expected_artifacts(tmp_path: Path) -> None:
    out = tmp_path / "compound"
    result = CliRunner().invoke(app, ["compound-risk", "--input", str(_findings_bundle(tmp_path)), "--input", str(_plugin_report(tmp_path)), "--out-dir", str(out)])

    assert result.exit_code == 0, result.output
    assert "Provider calls enabled: false" in result.output
    assert "Scenarios:" in result.output
    for name in ["compound-risk-report.json", "compound-risk-report.md", "compound-risk-report.html"]:
        assert (out / name).exists()
    data = json.loads((out / "compound-risk-report.json").read_text(encoding="utf-8"))
    assert data["schema_version"] == "malleus.compound_risk.v1"
    assert data["provider_calls_enabled"] is False
