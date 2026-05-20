from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from malleus.cli import app
from malleus.coverage import build_coverage_report, write_coverage_report
from malleus.campaign_runner import load_campaign
from malleus.datasets import load_benchmark_pack, load_input_datasets
from malleus.validation import validate_input_path


def test_coverage_build_from_smoke_pack_marks_missing_baseline_explicit(tmp_path: Path) -> None:
    report = build_coverage_report("datasets/benchmark_packs/smoke-v1.yaml")

    assert report.summary.covered_cells > 0
    assert report.summary.missing_cells > 0
    assert report.summary.covered_cells + report.summary.partial_cells + report.summary.missing_cells == report.summary.total_cells
    covered = {(cell.source_surface, cell.technique, cell.expected_boundary): cell for cell in report.cells if cell.status == "covered"}
    assert ("dataset", "direct_override", "instruction_boundary") in covered
    missing = [cell for cell in report.cells if cell.status == "missing"]
    assert missing
    assert all(cell.missing_reason for cell in missing)


def test_taxonomy_metadata_loads_for_public_packs_and_campaign_fixture() -> None:
    smoke_pack = load_benchmark_pack("datasets/benchmark_packs/smoke-v1.yaml")
    core_pack = load_benchmark_pack("datasets/benchmark_packs/core-v1.yaml")
    smoke_dataset = load_input_datasets("datasets/benchmark_packs/smoke-v1.yaml")[0]
    campaign = load_campaign("tests/fixtures/campaigns/agentic-extreme.yaml")

    assert "LLM01 Prompt Injection" in smoke_pack.metadata["owasp"]
    assert "LLM08 Excessive Agency" in core_pack.metadata["owasp"]
    assert smoke_dataset.cases is not None
    assert all("malleus_boundary" in case.metadata for case in smoke_dataset.cases)
    assert campaign.metadata["malleus_boundary"] == "campaign_policy_boundary"
    assert all("avid_effect" in step.metadata for step in campaign.steps)


def test_coverage_uses_taxonomy_mapped_smoke_metadata() -> None:
    report = build_coverage_report("datasets/benchmark_packs/smoke-v1.yaml")
    covered = {(cell.source_surface, cell.technique, cell.expected_boundary): cell for cell in report.cells if cell.status == "covered"}

    assert ("prompt", "direct_override", "instruction_boundary") in covered
    assert ("memory", "secret_exfiltration", "sensitive_context") in covered
    assert ("structured_output", "strict_json", "output_integrity") in covered


def test_coverage_includes_agent_campaign_findings_and_gate_metadata(tmp_path: Path) -> None:
    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    (report_dir / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": "malleus.findings.v1",
                "generated_at": "2026-01-01T00:00:00Z",
                "findings": [
                    {
                        "finding_id": "mf-test",
                        "title": "finding",
                        "source_type": "agent_lab",
                        "affected_model": {"name": None, "adapter": None, "model": None, "config": None},
                        "severity": "high",
                        "attack_surface": "tool_output",
                        "technique": "agent_policy",
                        "violated_boundary": "agent_policy_boundary",
                        "taxonomy_refs": ["agent_lab", "tool_output"],
                        "reproduction_command": "malleus agent-lab --dry-run",
                        "evidence_refs": [],
                        "redacted_excerpts": [],
                        "patch_recommendation": "Harden policy.",
                        "regression_case_link": "scenario",
                        "replay_spec": {"replay_id": "r", "finding_id": "mf-test", "command": "malleus agent-lab --dry-run", "target_name": "target"},
                        "metadata": {},
                    }
                ],
                "summary": {"total_findings": 1, "counts_by_severity": {"high": 1}, "counts_by_source": {"agent_lab": 1}, "highest_severity": "high"},
            }
        ),
        encoding="utf-8",
    )
    (report_dir / "risk-summary.json").write_text(json.dumps({"status": "fail", "reasons": ["critical gap"]}), encoding="utf-8")

    report = build_coverage_report(
        "datasets/benchmark_packs/smoke-v1.yaml",
        report_paths=[report_dir],
        campaign_paths=["tests/fixtures/campaigns/agentic-extreme.yaml"],
        agent_scenario_paths=["datasets/agentic/agentic_injection_smoke.yaml"],
    )
    index = {(cell.source_surface, cell.technique, cell.expected_boundary): cell for cell in report.cells}

    assert index[("tool_output", "agent_policy", "agent_policy_boundary")].finding_count == 1
    assert index[("policy_gate", "fail", "deployment_gate")].gate_count == 1
    assert index[("tool", "approval_bypass", "campaign_policy_boundary")].status == "covered"
    assert index[("rag_context", "agent_policy", "agent_policy_boundary")].status == "covered"


def test_coverage_uses_agent_and_campaign_taxonomy_aliases(tmp_path: Path) -> None:
    campaign = tmp_path / "campaign.yaml"
    campaign.write_text(
        """id: c
title: c
objective: c
replay_seed: 1
steps:
  - id: s
    order: 1
    surface: tool
    tactic: fallback tactic
    prompt: safe
    metadata:
      malleus_surface: approval
      malleus_technique: approval_gate
      malleus_boundary: campaign_boundary
""",
        encoding="utf-8",
    )
    scenarios = tmp_path / "scenarios.yaml"
    scenarios.write_text(
        """name: s
version: 1
scenarios:
  - id: a
    severity: high
    attack_surface: tool_output
    objective: safe
    user_task: safe
    untrusted_context: safe
    available_tools: [classify]
    metadata:
      malleus_surface: plugin
      malleus_technique: plugin_policy
      malleus_boundary: plugin_boundary
""",
        encoding="utf-8",
    )
    report = build_coverage_report("datasets/benchmark_packs/smoke-v1.yaml", campaign_paths=[campaign], agent_scenario_paths=[scenarios])
    covered = {(cell.source_surface, cell.technique, cell.expected_boundary): cell for cell in report.cells if cell.status == "covered"}

    assert ("approval", "approval_gate", "campaign_boundary") in covered
    assert ("plugin", "plugin_policy", "plugin_boundary") in covered


def test_taxonomy_validation_rejects_malformed_metadata(tmp_path: Path) -> None:
    dataset = tmp_path / "bad.yaml"
    dataset.write_text(
        """name: bad
version: 1
category: c
subcategory: s
cases:
  - id: bad-1
    severity: high
    objective: bad
    prompt: bad
    pass_signals:
      - type: refusal_marker
    metadata:
      maps_to: missing-slash
      malleus_boundary: []
""",
        encoding="utf-8",
    )

    report = validate_input_path(dataset)

    assert not report.ok
    text = report.to_text()
    assert "maps_to" in text
    assert "malleus_boundary" in text


def test_coverage_cli_writes_json_markdown_and_html(tmp_path: Path) -> None:
    out = tmp_path / "coverage"
    result = CliRunner().invoke(app, ["coverage", "build", "--input", "datasets/benchmark_packs/smoke-v1.yaml", "--out-dir", str(out)])

    assert result.exit_code == 0, result.output
    assert (out / "coverage.json").exists()
    assert (out / "coverage.md").exists()
    assert (out / "coverage.html").exists()
    payload = json.loads((out / "coverage.json").read_text(encoding="utf-8"))
    assert payload["summary"]["missing_cells"] > 0
    assert "Explicit gaps" in (out / "coverage.md").read_text(encoding="utf-8")


def test_coverage_rendering_escapes_user_controlled_metadata(tmp_path: Path) -> None:
    dataset = tmp_path / "dataset.yaml"
    dataset.write_text(
        """name: unsafe-coverage
version: 1
category: instruction_boundary
subcategory: direct_override
cases:
  - id: unsafe
    severity: high
    objective: test
    prompt: test
    metadata:
      attack_surface: "<script>alert(1)</script>"
      technique: "pipe|tick`hash#"
      expected_boundary: "boundary<unsafe>"
""",
        encoding="utf-8",
    )

    report = build_coverage_report(dataset)
    _, markdown_path, html_path = write_coverage_report(report, tmp_path / "out")

    html = html_path.read_text(encoding="utf-8")
    markdown = markdown_path.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "pipe\\|tick\\`hash\\#" in markdown


def test_coverage_cli_ingests_wowpp_report_matrix_and_writes_parseable_artifacts(tmp_path: Path) -> None:
    runner = CliRunner()
    rag_out = tmp_path / "rag"
    campaign_out = tmp_path / "campaign"
    visual_out = tmp_path / "visual"
    safety_out = tmp_path / "safety"
    mutation_out = tmp_path / "mutation"
    hidden_out = tmp_path / "hidden"
    artifact_out = tmp_path / "artifact"
    anomaly_out = tmp_path / "anomaly"
    artifact_file = tmp_path / "artifact.html"
    artifact_file.write_text("<html><body><div hidden>synthetic hidden fixture</div></body></html>", encoding="utf-8")

    commands = [
        ["rag", "run", "--fixture", "tests/fixtures/rag/security-fixture.yaml", "--out-dir", str(rag_out)],
        ["campaign", "run", "--campaign", "tests/fixtures/campaigns/agentic-extreme.yaml", "--target", "examples/targets/openai.yaml", "--out-dir", str(campaign_out), "--dry-run"],
        ["visual-lab", "run", "--fixture", "tests/fixtures/visual/support-ticket.yaml", "--out-dir", str(visual_out)],
        ["safety-tune", "run", "--target", "examples/targets/openai.yaml", "--input", "datasets/benchmark_packs/smoke-v1.yaml", "--out-dir", str(safety_out), "--temperature", "0,1", "--top-p", "1", "--max-tokens", "64", "--repeats", "1", "--dry-run"],
        ["mutate-run", "--target", "examples/targets/openai.yaml", "--input", "datasets/benchmark_packs/smoke-v1.yaml", "--scoring", "configs/scoring-default.yaml", "--out-dir", str(mutation_out), "--mutation", "spacing", "--limit", "1", "--dry-run"],
        ["inspect-text", "synthetic hidden text with zero\u200bwidth marker", "--out-dir", str(hidden_out)],
        ["inspect-artifact", "--file", str(artifact_file), "--out-dir", str(artifact_out)],
        ["inspect-output", "system: synthetic boundary\nassistant: synthetic reply\nuser: synthetic future turn", "--out-dir", str(anomaly_out)],
    ]
    for command in commands:
        result = runner.invoke(app, command)
        assert result.exit_code == 0, result.output

    out = tmp_path / "coverage"
    result = runner.invoke(
        app,
        [
            "coverage",
            "build",
            "--input",
            "datasets/benchmark_packs/smoke-v1.yaml",
            "--out-dir",
            str(out),
            "--mutation-report",
            str(mutation_out / "mutation-dry-run.json"),
            "--hidden-report",
            str(hidden_out / "hidden-channel-report.json"),
            "--artifact-report",
            str(artifact_out / "artifact-firewall-report.json"),
            "--rag-report",
            str(rag_out / "rag-report.json"),
            "--campaign-report",
            str(campaign_out / "campaign-report.json"),
            "--visual-report",
            str(visual_out / "visual-lab-report.json"),
            "--safety-report",
            str(safety_out / "safety-tuning-report.json"),
            "--anomaly-report",
            str(anomaly_out / "anomaly-report.json"),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads((out / "coverage.json").read_text(encoding="utf-8"))
    markdown = (out / "coverage.md").read_text(encoding="utf-8")
    html = (out / "coverage.html").read_text(encoding="utf-8")
    assert payload["metadata"]["mutation_report_items"] > 0
    assert payload["metadata"]["rag_report_items"] > 0
    assert payload["metadata"]["campaign_report_items"] > 0
    assert payload["metadata"]["visual_report_items"] > 0
    assert payload["metadata"]["safety_report_items"] > 0
    assert payload["metadata"]["anomaly_report_items"] > 0
    cells = {(cell["source_surface"], cell["technique"], cell["expected_boundary"]): cell for cell in payload["cells"]}
    assert any(key[0] == "rag_context" and key[2] == "rag_tenant_context_boundary" for key in cells)
    assert any(key[2] == "campaign_policy_boundary" for key in cells)
    assert any(key[0] in {"visual", "visual_lab", "visual"} or key[2] == "untrusted_visual_artifact_boundary" for key in cells)
    assert any(key[0] == "safety_tuner" or key[0] == "decoding_parameters" for key in cells)
    assert any(key[0] == "output_integrity" for key in cells)
    assert payload["summary"]["covered_cells"] > 0
    assert payload["summary"]["missing_cells"] > 0
    assert "Explicit gaps" in markdown
    assert "Malleus Attack-Surface Coverage" in html


def test_coverage_cli_optional_report_errors_are_explicit_and_do_not_write_output(tmp_path: Path) -> None:
    runner = CliRunner()
    out = tmp_path / "coverage"
    missing = tmp_path / "missing-rag-report.json"

    missing_result = runner.invoke(app, ["coverage", "build", "--input", "datasets/benchmark_packs/smoke-v1.yaml", "--out-dir", str(out), "--rag-report", str(missing)])

    assert missing_result.exit_code != 0
    assert "missing-rag-report.json" in missing_result.output
    assert not (out / "coverage.json").exists()

    corrupt = tmp_path / "corrupt-rag-report.json"
    corrupt.write_text("{not-json", encoding="utf-8")
    corrupt_result = runner.invoke(app, ["coverage", "build", "--input", "datasets/benchmark_packs/smoke-v1.yaml", "--out-dir", str(out), "--rag-report", str(corrupt)])

    assert corrupt_result.exit_code == 1
    assert "RAG report is not valid JSON" in corrupt_result.output
    assert str(corrupt) in corrupt_result.output
    assert not (out / "coverage.json").exists()
