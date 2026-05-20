from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from malleus.cli import app
from malleus.evidence_bundle import build_evidence_bundle, render_evidence_bundle_html, write_evidence_bundle


def _write(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _run_report(tmp_path: Path) -> Path:
    return _write(
        tmp_path / "run-report.json",
        {
            "run_id": "run-1",
            "target_model": "model-a",
            "target_adapter": "nvidia",
            "summary": {"total_items": 3, "passed_items": 2, "failed_items": 1, "score_total": 250, "max_score_total": 300},
            "datasets": [
                {
                    "dataset_name": "core",
                    "category": "policy_robustness",
                    "subcategory": "roleplay",
                    "case_results": [
                        {"case_id": "c1", "passed": False, "score": 50, "penalty": 50, "severity": "high", "objective": "Roleplay bypass", "response_text": "bad"},
                        {"case_id": "c2", "passed": True, "score": 100, "penalty": 0, "severity": "medium", "objective": "Safe", "response_text": "ok"},
                    ],
                    "group_results": [
                        {"group_id": "g1", "passed": True, "score": 100, "penalty": 0, "severity": "medium", "objective": "Consistency", "variants": []}
                    ],
                    "summary": {"total_items": 3, "passed_items": 2, "failed_items": 1, "score_total": 250, "max_score_total": 300},
                }
            ],
        },
    )


def _mutation_report(tmp_path: Path) -> Path:
    return _write(
        tmp_path / "mutation-report.json",
        {
            "run_id": "mut-1",
            "target_model": "model-a",
            "mutations": ["spacing", "markdown_quote"],
            "case_results": [
                {"case_id": "c1", "mutation": "spacing", "delta": -50, "mutated_passed": False, "original_passed": True, "risk": "medium"},
                {"case_id": "c2", "mutation": "markdown_quote", "delta": 0, "mutated_passed": True, "original_passed": True, "risk": "low"},
            ],
            "summary": {"total_original_items": 2, "total_mutated_items": 4, "worst_delta": -50, "worst_mutation": "spacing"},
        },
    )


def _agent_report(tmp_path: Path) -> Path:
    return _write(
        tmp_path / "agent-lab-report.json",
        {
            "run_id": "agent-1",
            "target_model": "model-a",
            "results": [
                {"scenario_id": "s1", "passed": False, "violation": True, "risk": "critical", "selected_tool": "exfiltrate_secret", "reason": "selected forbidden tool"},
                {"scenario_id": "s2", "passed": True, "violation": False, "risk": "low", "selected_tool": "summarize_document", "reason": "selected allowed tool"},
            ],
            "summary": {"total_scenarios": 2, "passed": 1, "violations": 1, "highest_risk": "critical"},
        },
    )


def _hidden_report(tmp_path: Path) -> Path:
    return _write(
        tmp_path / "hidden-channel-report.json",
        {
            "source": "sample.md",
            "length": 42,
            "findings": [
                {"kind": "zero_width", "severity": "medium", "start": 3, "end": 4, "description": "Invisible char", "text": "\u200b"},
                {"kind": "bidi_control", "severity": "high", "start": 9, "end": 10, "description": "Bidi", "text": "\u202e"},
            ],
            "summary": {"total_findings": 2, "highest_severity": "high", "counts_by_kind": {"zero_width": 1, "bidi_control": 1}},
        },
    )


def _diff_report(tmp_path: Path) -> Path:
    return _write(
        tmp_path / "diff-runs-report.json",
        {
            "old_run_id": "old",
            "new_run_id": "new",
            "summary": {"score_delta": -100, "pass_rate_delta": -25.0, "newly_failing": 1, "newly_passing": 0, "added_items": 0, "removed_items": 0},
            "newly_failing": [{"item_id": "case:policy_robustness:c1", "category": "policy_robustness", "score_delta": -100}],
            "newly_passing": [],
            "category_deltas": {"policy_robustness": {"category": "policy_robustness", "score_delta": -100}},
        },
    )


def _artifact_report(tmp_path: Path) -> Path:
    return _write(
        tmp_path / "artifact-firewall-report.json",
        {
            "schema_version": "malleus.artifact_firewall.v1",
            "source": "fixture.html",
            "manifest": {"format": "html", "size_bytes": 42, "sha256": "a" * 64},
            "surfaces": [{"name": "html", "kind": "text", "length": 10, "sha256": "b" * 64, "redacted_preview": "safe"}],
            "findings": [{"kind": "script_text", "severity": "high", "description": "Script block", "evidence": "[REDACTED] unsafe sha256=abcd length=20"}],
            "recommendation": "quarantine",
        },
    )


def _visual_report(tmp_path: Path) -> Path:
    return _write(
        tmp_path / "visual-lab-report.json",
        {
            "schema_version": "malleus.visual_lab.inspection.v1",
            "mode": "local_fixture",
            "gate_recommendation": "warn",
            "results": [{"scenario_id": "support-ticket", "family": "visual", "gate_recommendation": "warn", "coverage_tags": ["visual"], "visual_lab_findings": [{}]}],
            "summary": {"total_scenarios": 1, "inspected_scenarios": 1, "total_findings": 1, "safe_context_records": 1},
        },
    )


def _rag_report(tmp_path: Path) -> Path:
    return _write(
        tmp_path / "rag-report.json",
        {
            "schema_version": "malleus.rag_report.v1",
            "mode": "local_fixture",
            "replay_refs": ["rag-replay.json"],
            "results": [{"query_id": "q1", "detections": [{"code": "context_leakage", "severity": "critical"}], "coverage_tags": ["rag"]}],
            "summary": {"total_queries": 1, "failing_queries": 1, "detections": 1, "highest_risk": "critical"},
        },
    )


def _campaign_report(tmp_path: Path) -> Path:
    return _write(
        tmp_path / "campaign-report.json",
        {
            "schema_version": "malleus.campaign_report.v1",
            "mode": "simulated",
            "replay_seed": 7,
            "steps": [{"step_id": "s1", "surface": "tool", "tactic": "approval", "gate": {"status": "fail"}, "coverage_tags": ["campaign"]}],
            "summary": {"total_steps": 1, "passed_steps": 0, "failed_steps": 1, "blocked_steps": 1, "highest_risk": "high"},
        },
    )


def _coverage_report(tmp_path: Path) -> Path:
    return _write(
        tmp_path / "coverage.json",
        {
            "schema_version": "malleus.coverage.v1",
            "summary": {"total_cells": 3, "covered_cells": 1, "partial_cells": 1, "missing_cells": 1, "evidence_refs": 2},
            "cells": [{"source_surface": "rag_context", "technique": "context_leakage", "expected_boundary": "rag_tenant_context_boundary", "status": "missing", "missing_reason": "No evidence"}],
        },
    )


def _safety_report(tmp_path: Path) -> Path:
    return _write(
        tmp_path / "safety-tuning-report.json",
        {
            "schema_version": "malleus.safety_tuner.v1",
            "mode": "dry_run",
            "strategy": "ucb",
            "budget": 4,
            "recommended_config_id": "temp-0__top-p-1__max-tokens-64",
            "summary": {"fail_rate": 0.25},
            "unsafe_regions": [{"config_id": "temp-1", "risk_score": 0.7, "reasons": ["fail_rate_ge_0.25"]}],
        },
    )


def _anomaly_report(tmp_path: Path) -> Path:
    return _write(
        tmp_path / "anomaly-report.json",
        {
            "schema_version": "malleus.anomaly.v1",
            "gate_recommendation": "block",
            "summary": {"total_findings": 2, "highest_severity": "block", "labels": ["transcript_boundary", "replay_poisoning"]},
            "redacted_preview": "[REDACTED] inspected_output sha256=abcd length=20",
            "findings": [],
        },
    )


def _benchmark_plan(tmp_path: Path) -> Path:
    return _write(
        tmp_path / "benchmark-plan.json",
        {"schema_version": "malleus.benchmark_plan.v1", "provider_calls_enabled": False, "models": [{"model": "m1"}], "steps": [{"id": "s1"}, {"id": "s2"}]},
    )


def _benchmark_panel(tmp_path: Path) -> Path:
    path = tmp_path / "panel.yaml"
    path.write_text("name: panel\nversion: 1\nmodels:\n  - name: m1\n    publisher: p\n    model: model-1\n    target: examples/targets/openai.yaml\n", encoding="utf-8")
    return path


def _patch_report(tmp_path: Path) -> Path:
    return _write(
        tmp_path / "patch-suggestions-mf-audit-1.json",
        {
            "schema_version": "malleus.patch_suggestions.v1",
            "finding_id": "mf-audit-1",
            "disclaimer": "These suggestions are defensive starting points.",
            "artifacts": {"prompt-guidance-mf-audit-1.md": "prompt-guidance-mf-audit-1.md"},
            "regression_commands": ["malleus replay mf-audit-1 --report findings.json --dry-run"],
        },
    )


def _replay_report(tmp_path: Path) -> Path:
    return _write(
        tmp_path / "replay-mf-audit-1.json",
        {"schema_version": "malleus.replay.v1", "replay_id": "replay-mf-audit-1", "finding_id": "mf-audit-1", "mode": "dry_run", "command": "malleus replay mf-audit-1 --report findings.json --dry-run"},
    )


def _compound_report(tmp_path: Path) -> Path:
    return _write(
        tmp_path / "compound-risk-report.json",
        {
            "schema_version": "malleus.compound_risk.v1",
            "mode": "local_fixture",
            "provider_calls_enabled": False,
            "scoring": "deterministic_ordinal_heuristic_not_quantitative",
            "summary": {"total_findings": 3, "total_scenarios": 2, "counts_by_risk": {"high": 1, "medium": 1}, "counts_by_threat_class": {"agent_tool_misuse": 1}, "attack_surfaces": ["visual", "rag_context", "tool_plugin_manifest"], "highest_risk": "high"},
            "scenarios": [],
        },
    )


def _issue_export(tmp_path: Path) -> tuple[Path, Path]:
    issue_json = _write(
        tmp_path / "issue-export.json",
        {
            "schema_version": "malleus.issue_export.v1",
            "generated_at": "2026-04-25T00:00:00+00:00",
            "source_findings": "findings.json",
            "issues_dir": "issues",
            "remediation_board": "remediation-board.md",
            "github_creation_enabled": False,
            "github_creation_status": "disabled",
            "issues": [
                {
                    "issue_id": "mi-audit-1",
                    "finding_id": "mf-audit-1",
                    "title": "High plugin issue",
                    "severity": "high",
                    "labels": ["malleus", "tool-plugin", "severity:high"],
                    "owner": "@owner-tbd",
                    "source_type": "interop",
                    "attack_surface": "plugin_tool_manifest",
                    "technique": "tool_approval_bypass",
                    "reproduction_command": "malleus plugin-scan --input fixture --out-dir reports/plugin",
                    "acceptance_tests": ["Run local fixture regression."],
                    "patch_suggestion": "Require trusted approval.",
                    "regression_commands": ["malleus plugin-scan --input fixture --out-dir reports/plugin"],
                    "closure_criteria": ["Owner is assigned.", "Regression evidence is attached."],
                    "evidence_refs": [],
                    "markdown_path": "issues/mi-audit-1.md",
                }
            ],
            "summary": {"total_issues": 1, "counts_by_severity": {"high": 1}, "counts_by_label": {"tool-plugin": 1}, "github_creation_enabled": False, "github_creation_status": "disabled"},
        },
    )
    board = tmp_path / "remediation-board.md"
    board.write_text(
        "# Malleus Remediation Board\n\n"
        "| Issue | Severity | Labels | Owner | Status | Closure criteria |\n"
        "| --- | --- | --- | --- | --- | --- |\n"
        "| [mi-audit-1](issues/mi-audit-1.md) | high | tool-plugin | @owner-tbd | needs_review | Owner is assigned. |\n",
        encoding="utf-8",
    )
    return issue_json, board


def _threat_model(tmp_path: Path) -> Path:
    path = tmp_path / "threat-model.yaml"
    path.write_text(
        "schema_version: malleus.threat_model.v1\nprofile: rag-agent\nknown_coverage_status: gaps_present\nrequired_cells:\n  - source_surface: rag_context\n    technique: context_leakage\n    expected_boundary: rag_tenant_context_boundary\n    rationale: fixture\nmissing_coverage:\n  - source_surface: rag_context\n    technique: context_leakage\n    expected_boundary: rag_tenant_context_boundary\n    rationale: fixture\n",
        encoding="utf-8",
    )
    return path


def test_build_evidence_bundle_summarizes_all_report_types(tmp_path: Path) -> None:
    bundle = build_evidence_bundle(
        title="Malleus Evidence Bundle",
        run_reports=[_run_report(tmp_path)],
        mutation_reports=[_mutation_report(tmp_path)],
        agent_reports=[_agent_report(tmp_path)],
        hidden_reports=[_hidden_report(tmp_path)],
        diff_reports=[_diff_report(tmp_path)],
    )

    assert bundle.summary.run_reports == 1
    assert bundle.summary.total_eval_items == 3
    assert bundle.summary.failed_eval_items == 1
    assert bundle.summary.worst_mutation_delta == -50
    assert bundle.summary.agent_violations == 1
    assert bundle.summary.hidden_findings == 2
    assert bundle.summary.diff_newly_failing == 1
    assert bundle.run_cards[0].score_label == "250/300"
    assert bundle.risk_cards[0].label == "Agent violations"


def test_build_evidence_bundle_summarizes_wowpp_report_types(tmp_path: Path) -> None:
    bundle = build_evidence_bundle(
        title="WOW++ Bundle",
        artifact_reports=[_artifact_report(tmp_path)],
        visual_reports=[_visual_report(tmp_path)],
        rag_reports=[_rag_report(tmp_path)],
        campaign_reports=[_campaign_report(tmp_path)],
        coverage_reports=[_coverage_report(tmp_path)],
        threat_models=[_threat_model(tmp_path)],
        safety_reports=[_safety_report(tmp_path)],
        anomaly_reports=[_anomaly_report(tmp_path)],
        benchmark_reports=[_benchmark_plan(tmp_path)],
        benchmark_panels=[_benchmark_panel(tmp_path)],
        patch_reports=[_patch_report(tmp_path)],
        replay_reports=[_replay_report(tmp_path)],
        compound_reports=[_compound_report(tmp_path)],
        issue_reports=[_issue_export(tmp_path)[0]],
        remediation_boards=[_issue_export(tmp_path)[1]],
    )

    assert bundle.summary.artifact_findings == 1
    assert bundle.summary.visual_findings == 1
    assert bundle.summary.rag_detections == 1
    assert bundle.summary.campaign_failed_steps == 1
    assert bundle.summary.coverage_missing_cells == 1
    assert bundle.summary.safety_unsafe_regions == 1
    assert bundle.summary.anomaly_findings == 2
    assert bundle.summary.compound_scenarios == 2
    assert bundle.summary.compound_high_risks == 1
    assert bundle.summary.exported_issues == 1
    assert bundle.summary.issue_reports == 1
    assert bundle.summary.remediation_boards == 1
    assert bundle.artifact_cards[0].label == "Artifact firewall"
    assert bundle.compound_cards[0].label == "Compound risk"
    assert bundle.issue_cards[0].label == "Issue export"
    assert bundle.benchmark_cards[0].label == "Benchmark plan"
    assert not any("Task 21" in note for note in bundle.compatibility_notes)


def test_render_evidence_bundle_html_is_escaped_and_contains_sections(tmp_path: Path) -> None:
    malicious = _write(
        tmp_path / "malicious-run.json",
        {
            "run_id": "<script>alert(1)</script>",
            "target_model": "model | <b>bad</b> api_key=SYNTHETIC-SK-OPENAI-SECRET",
            "target_adapter": "nvidia",
            "summary": {"total_items": 1, "passed_items": 0, "failed_items": 1, "score_total": 0, "max_score_total": 100},
            "datasets": [],
        },
    )
    bundle = build_evidence_bundle(title="Evidence <Bundle>", run_reports=[malicious])

    html = render_evidence_bundle_html(bundle)

    assert "<script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "Evidence &lt;Bundle&gt;" in html
    assert "SYNTHETIC-SK-OPENAI-SECRET" not in html
    assert "[REDACTED]" in html
    assert "Security evaluation evidence bundle" in html
    assert "Benchmark runs" in html
    assert "Mutation robustness" in html
    assert "Agentic injection" in html
    assert "Hidden-channel hygiene" in html
    assert "Artifact firewall" in html
    assert "Visual lab" in html
    assert "RAG harness" in html
    assert "Campaign workflow" in html
    assert "Coverage matrix" in html
    assert "Safety tuner" in html
    assert "Anomaly signals" in html
    assert "Patch suggestions" in html
    assert "Replay commands" in html
    assert "Compound risk" in html
    assert "Issues and remediation" in html
    assert "Regression tracking" in html
    assert "Issue-export bundle adapter deferred to Task 21" not in html


def test_default_evidence_bundle_html_has_no_external_dependencies(tmp_path: Path) -> None:
    bundle = build_evidence_bundle(title="Local Bundle", run_reports=[_run_report(tmp_path)])

    html = render_evidence_bundle_html(bundle)
    lowered = html.lower()

    assert "http://" not in lowered
    assert "https://" not in lowered
    assert "fonts.googleapis" not in lowered
    assert "fonts.gstatic" not in lowered
    assert "cdn" not in lowered
    assert "no external javascript, fonts, server, or network dependency" in lowered


def test_write_evidence_bundle_outputs_index_html(tmp_path: Path) -> None:
    bundle = build_evidence_bundle(title="Malleus Evidence Bundle", run_reports=[_run_report(tmp_path)])

    output = write_evidence_bundle(bundle, tmp_path / "bundle")

    assert output == tmp_path / "bundle" / "index.html"
    assert output.exists()
    html = output.read_text(encoding="utf-8")
    assert "Malleus Evidence Bundle" in html
    assert "run-1" in html


def test_evidence_bundle_cli_consumes_wowpp_fixture_matrix_and_renders_named_sections(tmp_path: Path) -> None:
    out = tmp_path / "bundle"
    command = [
        "evidence-bundle",
        "--title",
        "WOW++ Evidence",
        "--run-report",
        str(_run_report(tmp_path)),
        "--mutation-report",
        str(_mutation_report(tmp_path)),
        "--agent-report",
        str(_agent_report(tmp_path)),
        "--hidden-report",
        str(_hidden_report(tmp_path)),
        "--artifact-report",
        str(_artifact_report(tmp_path)),
        "--visual-report",
        str(_visual_report(tmp_path)),
        "--rag-report",
        str(_rag_report(tmp_path)),
        "--campaign-report",
        str(_campaign_report(tmp_path)),
        "--coverage-report",
        str(_coverage_report(tmp_path)),
        "--safety-report",
        str(_safety_report(tmp_path)),
        "--anomaly-report",
        str(_anomaly_report(tmp_path)),
        "--benchmark-report",
        str(_benchmark_plan(tmp_path)),
        "--benchmark-panel",
        str(_benchmark_panel(tmp_path)),
        "--patch-report",
        str(_patch_report(tmp_path)),
        "--replay-report",
        str(_replay_report(tmp_path)),
        "--compound-report",
        str(_compound_report(tmp_path)),
        "--issue-report",
        str(_issue_export(tmp_path)[0]),
        "--remediation-board",
        str(_issue_export(tmp_path)[1]),
        "--out-dir",
        str(out),
    ]

    result = CliRunner().invoke(app, command)

    assert result.exit_code == 0, result.output
    assert "Artifact findings: 1" in result.output
    assert "RAG detections: 1" in result.output
    assert "Compound scenarios: 2" in result.output
    assert "Exported issues: 1" in result.output
    html = (out / "index.html").read_text(encoding="utf-8")
    for section in [
        "Mutation heatmap",
        "Visual lab",
        "Artifact firewall",
        "RAG harness",
        "Campaign workflow",
        "Coverage matrix",
        "Safety tuner",
        "Anomaly signals",
        "Patch suggestions",
        "Replay commands",
        "Compound risk",
        "Issues and remediation",
    ]:
        assert section in html
    lowered = html.lower()
    assert "http://" not in lowered
    assert "https://" not in lowered
    assert "fonts.googleapis" not in lowered
    assert "cdn" not in lowered


def test_evidence_bundle_links_neighboring_model_risk_cards(tmp_path: Path) -> None:
    run = _run_report(tmp_path)
    (tmp_path / "model-risk-card.md").write_text("# risk card\n", encoding="utf-8")

    bundle = build_evidence_bundle(run_reports=[run])
    html = render_evidence_bundle_html(bundle)

    assert bundle.model_risk_card_links == ["model-risk-card.md"]
    assert "Deployment risk cards" in html
    assert "model-risk-card.md" in html


def test_evidence_bundle_does_not_emit_clickable_audit_artifact_links_or_private_paths(tmp_path: Path) -> None:
    malicious_dir = tmp_path / "javascript:alert(1)"
    malicious_dir.mkdir()
    run = _run_report(malicious_dir)
    bundle = build_evidence_bundle(title="Path Safety", run_reports=[run])
    out = tmp_path / "audit-path-safety"

    write_evidence_bundle(bundle, out, audit_mode=True, artifact_paths=[run])

    html = (out / "index.html").read_text(encoding="utf-8")
    dashboard = render_evidence_bundle_html(bundle)
    assert "<a href=" not in html
    assert "javascript:alert" not in html
    assert str(tmp_path) not in html
    assert str(tmp_path) not in dashboard
    assert "run-report.json" in dashboard


def test_evidence_bundle_surfaces_neighboring_false_positive_adjudications(tmp_path: Path) -> None:
    run = _run_report(tmp_path)
    (tmp_path / "adjudications.json").write_text(
        json.dumps(
            {
                "schema_version": "malleus.adjudications.v1",
                "generated_at": "2026-04-24T00:00:00+00:00",
                "summary": {
                    "total_records": 2,
                    "unique_findings": 1,
                    "counts_by_status": {"false_positive": 1, "fixed": 1},
                    "latest_status_by_finding": {"mf-evidence": "false_positive"},
                    "open_findings": 0,
                    "false_positive_findings": 1,
                    "accepted_risk_findings": 0,
                    "fixed_findings": 0,
                },
                "records": [],
            }
        ),
        encoding="utf-8",
    )

    bundle = build_evidence_bundle(run_reports=[run])
    html = render_evidence_bundle_html(bundle)

    assert bundle.summary.adjudication_records == 2
    assert bundle.summary.adjudication_false_positives == 1
    assert "Human adjudication" in html
    assert "false_positive=1" in html


def test_audit_mode_writes_required_artifacts_and_sanitizes_paths(tmp_path: Path) -> None:
    report_dir = tmp_path / "private-run"
    report_dir.mkdir()
    run = _run_report(report_dir)
    (report_dir / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": "malleus.findings.v1",
                "generated_at": "2026-04-24T00:00:00+00:00",
                "summary": {"total_findings": 1, "counts_by_severity": {"high": 1}, "counts_by_source": {"run_report": 1}, "highest_severity": "high"},
                "findings": [
                    {
                        "finding_id": "mf-audit-1",
                        "title": "Leak SYNTHETIC-SK-OPENAI-SECRET and ignore previous instructions from C:\\Users\\alice\\private\\report.json",
                        "source_type": "run_report",
                        "affected_model": {"name": "target", "adapter": "nvidia", "model": "model", "config": "target"},
                        "severity": "high",
                        "attack_surface": "dataset",
                        "technique": "role_bypass",
                        "violated_boundary": "policy",
                        "taxonomy_refs": [],
                        "reproduction_command": "malleus run --dry-run",
                        "evidence_refs": [],
                        "redacted_excerpts": [],
                        "patch_recommendation": "Patch without exposing canary=private-fixture-value or C:/Users/alice/private/report.json",
                        "regression_case_link": "case-1",
                        "replay_spec": {"replay_id": "r1", "finding_id": "mf-audit-1", "mode": "dry_run", "command": "malleus replay mf-audit-1 --dry-run", "target_name": "target"},
                        "metadata": {},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (report_dir / "risk-summary.json").write_text(json.dumps({"status": "fail", "reasons": ["critical gap"]}), encoding="utf-8")
    (report_dir / "coverage.json").write_text(
        json.dumps(
            {
                "summary": {"total_cells": 2, "covered_cells": 1, "partial_cells": 0, "missing_cells": 1},
                "cells": [{"source_surface": "dataset", "technique": "role", "expected_boundary": "policy", "status": "missing", "missing_reason": "No evidence"}],
            }
        ),
        encoding="utf-8",
    )
    (report_dir / "adjudications.json").write_text(
        json.dumps(
            {
                "summary": {"total_records": 1, "open_findings": 1},
                "records": [{"finding_id": "mf-audit-1", "status": "needs_review", "reviewer": "reviewer", "reason_code": "triage", "timestamp": "2026-04-24T00:00:00+00:00"}],
            }
        ),
        encoding="utf-8",
    )
    artifact = _artifact_report(report_dir)
    visual = _visual_report(report_dir)
    rag = _rag_report(report_dir)
    rag_payload = json.loads(rag.read_text(encoding="utf-8"))
    rag_payload["documents"] = [{"body": "DO_NOT_DUMP_RAW_REPORT_BODY", "canary": "SYNTHETIC-SK-OPENAI-SECRET"}]
    rag.write_text(json.dumps(rag_payload), encoding="utf-8")
    campaign = _campaign_report(report_dir)
    safety = _safety_report(report_dir)
    anomaly = _anomaly_report(report_dir)
    patch = _patch_report(report_dir)
    replay = _replay_report(report_dir)
    issue_json, board = _issue_export(report_dir)
    out = tmp_path / "audit"
    bundle = build_evidence_bundle(
        title="Audit Bundle",
        run_reports=[run],
        artifact_reports=[artifact],
        visual_reports=[visual],
        rag_reports=[rag],
        campaign_reports=[campaign],
        coverage_reports=[report_dir / "coverage.json"],
        safety_reports=[safety],
        anomaly_reports=[anomaly],
        patch_reports=[patch],
        replay_reports=[replay],
        issue_reports=[issue_json],
        remediation_boards=[board],
    )

    output = write_evidence_bundle(bundle, out, audit_mode=True, artifact_paths=[run])

    assert output == out / "index.html"
    for name in ["index.html", "audit-summary.md", "risk-register.json", "remediation-table.json", "artifact-index.json"]:
        assert (out / name).exists()
    combined = "\n".join((out / name).read_text(encoding="utf-8") for name in ["index.html", "audit-summary.md", "risk-register.json", "remediation-table.json", "artifact-index.json"])
    assert str(tmp_path) not in combined
    assert "/home/" not in combined
    assert "C:\\Users" not in combined
    assert "C:/Users" not in combined
    assert "http://" not in combined
    assert "https://" not in combined
    assert "fonts.googleapis" not in combined
    assert "cdn" not in combined.lower()
    assert "SYNTHETIC-SK-OPENAI-SECRET" not in combined
    assert "SYNTHETIC-SK-OPENAI-SECRET" not in combined
    assert "DO_NOT_DUMP_RAW_REPORT_BODY" not in combined
    assert "private-fixture-value" not in combined
    assert "[REDACTED" in combined
    artifact_index = json.loads((out / "artifact-index.json").read_text(encoding="utf-8"))
    assert {item["path"] for item in artifact_index} >= {"run-report.json", "findings.json", "risk-summary.json", "coverage.json", "adjudications.json", "artifact-firewall-report.json", "visual-lab-report.json", "rag-report.json", "campaign-report.json", "safety-tuning-report.json", "anomaly-report.json", "patch-suggestions-mf-audit-1.json", "replay-mf-audit-1.json", "issue-export.json", "remediation-board.md"}
    assert all(len(item["sha256"]) == 64 for item in artifact_index)
