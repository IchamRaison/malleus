from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_release_docs_describe_provider_free_premium_workflows() -> None:
    readme = _read("README.md")

    for command in [
        "malleus campaign run",
        "malleus rag run",
        "malleus coverage build",
        "malleus threat-model init",
        "malleus workspace init",
        "malleus benchmark plan",
        "malleus benchmark summarize",
        "malleus visual-lab generate",
        "malleus visual-lab run",
        "malleus artifact-firewall",
        "malleus taxonomy snapshot",
        "malleus taxonomy diff",
        "malleus compound-risk",
        "malleus issues export",
        "malleus studio export",
        "malleus ui-harness run",
    ]:
        assert command in readme
    assert "Provider-free release/CI planning" in readme
    assert "Provider-free and scaffold artifacts are local evidence" in readme
    assert "scaffold-only" in readme


def test_readme_leads_with_live_benchmark_workflow_before_advanced_references() -> None:
    readme = _read("README.md")

    workflow_positions = [
        readme.index("Malleus is a defensive assessment workflow"),
        readme.index("## Quickstart: run a live benchmark"),
        readme.index("malleus benchmark soft --target <target-name>"),
        readme.index("## What an assessment writes"),
        readme.index("## How to read the evidence"),
        readme.index("## Profiles, packs, and gates"),
    ]
    assert workflow_positions == sorted(workflow_positions)
    assert max(workflow_positions) < readme.index("## Capability map")
    assert readme.index("## Capability map") < readme.index("## Command reference")


def test_readme_assessment_claims_are_provider_free_and_fail_closed() -> None:
    readme = _read("README.md")

    for phrase in [
        "Assessment mode remains provider-free in the current implementation",
        "All assessment modes disable provider and network calls",
        "use assessment for CI/dev planning artifacts, not live benchmark claims",
        "does not instantiate adapters or collect provider response evidence",
        "Non-assessment commands keep their documented behavior",
        "Planning-only, scaffold, advisory, excluded, not-applicable, not-tested",
        "cannot inflate the primary score",
        "It is not proof that a model or system is safe in all settings",
        "It does not create GitHub issues in the default path",
        "does not drive a browser or capture screenshots",
        "Provider errors are separate",
        "records provider errors separately from model behavior evidence/findings",
    ]:
        assert phrase in readme


def test_docs_distinguish_provider_errors_from_model_behavior_findings() -> None:
    docs = "\n".join(
        _read(path)
        for path in [
            "README.md",
            "docs/live-provider-assessments.md",
            "docs/interpreting-results.md",
            "docs/methodology.md",
            "docs/limitations.md",
            "docs/nvidia.md",
            "docs/scoring-methodology.md",
            "docs/ci-gates.md",
        ]
    )

    for phrase in [
        "Provider errors are recorded separately from model behavior findings",
        "provider errors are operational records, not model behavior findings",
        "Provider availability, account access, quota, routing, timeout, and adapter errors are run conditions",
        "Only completed model responses can support model behavior findings",
        "Provider or workflow errors force an error posture for the run, but they are operational conditions",
        "provider errors are run conditions, not model behavior findings",
    ]:
        assert phrase in docs


def test_readme_avoids_unsafe_or_unsupported_assessment_claims() -> None:
    readme = _read("README.md").lower()
    forbidden_patterns = [
        r"guarantee(?:s|d)? safety",
        r"prove(?:s|d)? universal safety",
        r"production-grade live",
        r"assessment[^\n]{0,120}calls? providers?",
        r"assessment[^\n]{0,120}drives? a browser",
        r"assessment[^\n]{0,120}captures? screenshots",
        r"(?<!not )creates? github issues",
        r"raw jailbreak",
        r"bearer\s+[a-z0-9._-]+",
        r"sk-[a-z0-9]{10,}",
        r"/home/[^\s`]+",
        r"/users/[^\s`]+",
        r"c:/users/",
        r"c:\\\\users\\\\",
    ]
    for pattern in forbidden_patterns:
        assert re.search(pattern, readme) is None, pattern


def test_artifact_compatibility_doc_covers_schema_and_audit_contracts() -> None:
    text = _read("docs/artifact-compatibility.md")

    for phrase in [
        "malleus.ir.v1",
        "malleus.artifact.v1",
        "malleus.report_manifest.v1",
        "findings.json",
        "patch suggestions",
        "adjudications",
        "Interop",
        "coverage",
        "threat-model",
        "workspace",
        "benchmark plan --dry-run",
        "visual lab reports",
        "artifact firewall reports",
        "taxonomy snapshots",
        "compound-risk reports",
        "issue exports",
        "UI harness reports",
        "studio indexes",
        "artifact-index.json",
        "absolute private paths",
    ]:
        assert phrase in text


def test_audit_docs_state_local_only_no_external_dependencies() -> None:
    text = _read("docs/evidence-bundle.md")

    assert "no external fonts, CDN links, or network dependency" in text
    assert "system font stacks only" in text
    assert "Audit mode is stricter" in text
    assert "no external JavaScript, fonts, CDN, server, or network dependency" in text
    assert "SHA-256" in text


def test_evidence_bundle_docs_cover_wowpp_inputs_and_deferrals() -> None:
    text = _read("docs/evidence-bundle.md")

    for phrase in [
        "--artifact-report",
        "--visual-report",
        "--rag-report",
        "--campaign-report",
        "--coverage-report",
        "--threat-model",
        "--safety-report",
        "--anomaly-report",
        "--benchmark-report",
        "--benchmark-panel",
        "--patch-report",
        "--replay-report",
        "--compound-report",
        "--issue-report",
        "--remediation-board",
        "compound-risk cards",
        "issue export and remediation-board cards",
    ]:
        assert phrase in text


def test_taxonomy_docs_cover_wowpp_surfaces_and_provider_free_commands() -> None:
    text = _read("docs/taxonomy.md")

    for phrase in [
        "visual_injection",
        "artifact_firewall",
        "taxonomy_garden",
        "compound_risk",
        "ui_scaffold",
        "issue_export",
        "malleus taxonomy snapshot",
        "malleus taxonomy diff",
        "These commands are provider-free",
    ]:
        assert phrase in text


def test_public_docs_avoid_unsupported_wowpp_claims() -> None:
    docs = "\n".join(
        _read(path)
        for path in [
            "README.md",
            "docs/artifact-compatibility.md",
            "docs/evidence-bundle.md",
            "docs/taxonomy.md",
        ]
    ).lower()

    forbidden_patterns = [
        r"universal safety",
        r"guarantee(?:s|d)? safety",
        r"payload corpus",
        r"mock(?:ed)?[^\n]{0,80}live model evaluation",
        r"provider-free[^\n]{0,80}live model evaluation",
        r"scaffold[^\n]{0,80}live model evaluation",
        r"ui harness[^\n]{0,120}(?:drives|automates) a browser",
        r"vision-run[^\n]{0,120}calls? provider",
    ]
    for pattern in forbidden_patterns:
        assert re.search(pattern, docs) is None, pattern


def test_readme_commands_are_real_or_labeled_optional_scaffold_live() -> None:
    readme = _read("README.md")
    required_real_commands = [
        "malleus assess",
        "malleus list-cases",
        "malleus inspect-refusal",
        "malleus inspect-text",
        "malleus diff-runs",
        "malleus evidence-bundle",
        "malleus run",
        "malleus benchmark plan",
        "malleus benchmark summarize",
        "malleus dashboard",
        "malleus compare",
        "malleus mutations list",
        "malleus mutations inspect",
        "malleus mutate-run",
        "malleus agent-lab",
        "malleus visual-lab generate",
        "malleus visual-lab run",
        "malleus artifact-firewall",
        "malleus visual-lab vision-run",
        "malleus campaign run",
        "malleus rag run",
        "malleus coverage build",
        "malleus threat-model init",
        "malleus threat-model coverage",
        "malleus taxonomy snapshot",
        "malleus taxonomy diff",
        "malleus findings export",
        "malleus patch suggest",
        "malleus replay",
        "malleus regression generate",
        "malleus regression validate",
        "malleus adjudicate",
        "malleus issues export",
        "malleus compound-risk",
        "malleus studio export",
        "malleus ui-harness run",
        "malleus workspace init",
        "malleus workspace status",
        "malleus workspace next",
        "malleus mutate",
    ]
    for command in required_real_commands:
        assert command in readme

    assert "scaffold-only" in readme
    assert "does not drive a browser or capture screenshots" in readme
