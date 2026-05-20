from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

ASSESSMENT_DOCS = [
    "docs/assessment-mode.md",
    "docs/attack-packs.md",
    "docs/assessment-profiles.md",
    "docs/interpreting-results.md",
    "docs/live-provider-assessments.md",
    "docs/model-comparison.md",
    "docs/ci-gates.md",
    "docs/remediation-and-regression.md",
    "docs/regression-tracking.md",
    "docs/extensions.md",
    "docs/security-model.md",
    "docs/limitations.md",
    "docs/scoring-methodology.md",
]

CASE_STUDY_DOCS = [
    "docs/case-studies/synthetic-rag-injection-weakness.md",
    "docs/case-studies/synthetic-tool" + "-use-fake-approval.md",
    "docs/case-studies/synthetic-model" + "-configuration-risk-surface.md",
]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_assessment_product_docs_exist_and_cover_core_claims() -> None:
    for path in ASSESSMENT_DOCS:
        text = _read(path)
        assert "evidence" in text.lower(), path

    combined = "\n".join(_read(path) for path in ASSESSMENT_DOCS)
    for phrase in [
        "malleus assess",
        "--target examples/targets/openai.yaml",
        "--profile rag-agent",
        "--packs core,rag",
        "--mode dry_run",
        "--out-dir reports/assessment",
        "risk-report.json",
        "executive-summary.md",
        "coverage/coverage.html",
        "findings/findings.json",
        "remediation/remediation-board.md",
        "regression/regression-pack.yaml",
        "evidence-bundle/index.html",
        "studio/index.html",
        "model-comparison/comparison.json",
        "gate/gate-summary.json",
        "malleus regression generate",
        "malleus regression validate",
        "accepted_risk",
        "expires-at",
        "malleus.extension_manifest.v1",
    ]:
        assert phrase in combined


def test_assessment_docs_pin_provider_free_fail_closed_behavior() -> None:
    live_doc = _read("docs/live-provider-assessments.md")
    combined = "\n".join(_read(path) for path in ASSESSMENT_DOCS)

    assert "`malleus assess --mode live_provider` is fail-closed scaffold behavior" in live_doc
    assert "does not instantiate adapters" in live_doc
    assert "does not collect provider response evidence" in live_doc
    assert "Non-assessment commands can retain their existing documented behavior" in live_doc
    assert "provider and network calls are disabled" in combined


def test_assessment_scoring_docs_separate_score_confidence_and_advisory() -> None:
    text = _read("docs/scoring-methodology.md")

    for phrase in [
        "primary score",
        "coverage confidence",
        "advisory findings",
        "Planning-only, scaffold, advisory, excluded, not-applicable, not-tested",
        "cannot inflate the primary score",
        "They do not appear as pass results",
    ]:
        assert phrase in text


def test_assessment_docs_avoid_unsupported_or_unsafe_claims() -> None:
    combined = "\n".join(_read(path) for path in ASSESSMENT_DOCS).lower()
    forbidden_patterns = [
        r"guarantee(?:s|d)? safety",
        r"prove(?:s|d)? universal safety",
        r"production-grade live",
        r"calls? providers? in assessment",
        r'assessment[^\n]{0,120}drives? a browser',
        r'assessment[^\n]{0,120}captures? screenshots',
        r"creates? github issues",
        r"raw jailbreak",
        r"bearer\s+[a-z0-9._-]+",
        r"sk-[a-z0-9]{10,}",
        r"/home/[^\s`]+",
        r"/users/[^\s`]+",
    ]
    for pattern in forbidden_patterns:
        assert re.search(pattern, combined) is None, pattern

    assert "nvidia_api_key" in combined


def test_synthetic_case_studies_cover_required_sections_and_refs() -> None:
    expected_phrases = {
        "docs/case-studies/synthetic-rag-injection-weakness.md": [
            "RAG Injection Weakness",
            "--profile rag-agent",
            "--packs core,rag",
            "raw/rag/planning-metadata.json",
        ],
        "docs/case-studies/synthetic-tool" + "-use-fake-approval.md": [
            "Tool-Use Fake Approval Weakness",
            "--profile tool-agent",
            "--packs core,tools",
            "raw/tools/planning-metadata.json",
        ],
        "docs/case-studies/synthetic-model" + "-configuration-risk-surface.md": [
            "Model Configuration Risk Surface",
            "--profile model-selection",
            "--packs comparison,safety_tuning",
            "raw/comparison/planning-metadata.json",
            "raw/safety_tuning/planning-metadata.json",
        ],
    }

    for path, phrases in expected_phrases.items():
        text = _read(path)
        for heading in [
            "## Summary",
            "## Case",
            "## Evidence refs",
            "## Risk explanation",
            "## Remediation",
            "## Regression and retest",
            "## Limitations",
        ]:
            assert heading in text, path
        for phrase in [
            "provider-free",
            "findings/findings.json",
            "regression/regression-pack.yaml",
            "evidence-bundle/artifact-index.json",
            "malleus assess",
            "--target examples/targets/openai.yaml",
            "--mode dry_run",
            "not proof of live endpoint behavior",
        ]:
            assert phrase in text, path
        for phrase in phrases:
            assert phrase in text, path


def test_synthetic_case_studies_are_sanitized_and_do_not_claim_live_evidence() -> None:
    combined = "\n".join(_read(path) for path in CASE_STUDY_DOCS).lower()

    forbidden_patterns = [
        r"raw prompt",
        r"raw response",
        r"jailbreak",
        r"exploit payload",
        r"bearer\s+[a-z0-9._-]+",
        r"sk-[a-z0-9]{10,}",
        r"/home/[^\s`]+",
        r"/users/[^\s`]+",
        r"c:/users/",
        r"c:\\\\users\\\\",
        r"live model behavior evidence",
        r"validated against live",
        r"calls? providers?",
        r"drives? tools",
        r"drives? a browser",
        r"creates? remote issues",
        r"guarantee(?:s|d)? safety",
        r"prove(?:s|d)? safety",
    ]
    for pattern in forbidden_patterns:
        assert re.search(pattern, combined) is None, pattern

    for phrase in [
        "provider-free",
        "local",
        "planning",
        "static",
        "simulated",
        "not live model behavior",
    ]:
        assert phrase in combined


def test_synthetic_case_studies_do_not_use_unknown_pack_ids() -> None:
    combined = "\n".join(_read(path) for path in CASE_STUDY_DOCS)

    forbidden_unknown_pack_ids = [
        "tool-use",
        "model-configuration",
        "raw/tool-use/",
        "raw/model-configuration/",
        "--packs core,tool-use",
        "--packs core,model-configuration",
    ]
    for pack_id in forbidden_unknown_pack_ids:
        assert pack_id not in combined, pack_id
