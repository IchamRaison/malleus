from __future__ import annotations

import hashlib
import json
import re
import shlex
from dataclasses import dataclass, field
from html import escape
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from malleus.utils.redact import redact_public_text, redacted_preview, sha256_text


RISK_REPORT_SCHEMA_VERSION = "malleus.assessment_risk_report.v1"
MANIFEST_SCHEMA_VERSION = "malleus.assessment_manifest.v1"
ARTIFACT_SCHEMA_VERSION = "malleus.artifact.v1"

TOP_LEVEL_ARTIFACTS = (
    "risk-report.json",
    "risk-report.html",
    "executive-summary.md",
    "strengths-weaknesses.md",
    "assessment-manifest.json",
)
CANONICAL_ARTIFACTS = (
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
)
ARTIFACT_PATHS = {
    "coverage_json": "coverage/coverage.json",
    "coverage_markdown": "coverage/coverage.md",
    "coverage_html": "coverage/coverage.html",
    "findings_json": "findings/findings.json",
    "findings_markdown": "findings/findings.md",
    "remediation_board": "remediation/remediation-board.md",
    "issue_export": "remediation/issue-export.json",
    "patches_readme": "remediation/patches/README.md",
    "regression_pack": "regression/regression-pack.yaml",
    "replay_commands": "regression/replay-commands.md",
    "evidence_bundle_index": "evidence-bundle/index.html",
    "evidence_index": "evidence-bundle/artifact-index.json",
    "audit_summary": "evidence-bundle/audit-summary.md",
    "studio_index": "studio/index.html",
}

SCORE_USE_EXPLANATION = {
    "included": "Contributes to the primary assessment score.",
    "advisory": "Reported for context but excluded from the primary score.",
    "excluded": "Tracked as metadata, coverage, or infrastructure and excluded from scoring.",
    "not_applicable": "Pack is not applicable to the selected profile or target.",
    "not_tested": "Pack was not executed or is scaffold-only in this run.",
    "evidence_strengths": {
        "model_behavior": "Live or recorded model behavior evidence.",
        "fixture_behavior": "Provider-free local fixture evidence.",
        "static_analysis": "Deterministic local artifact or configuration analysis.",
        "planning_only": "Planning/scaffold evidence; never primary score evidence.",
    },
}

_UNSAFE_TEXT_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"<\s*script\b[^>]*>.*?<\s*/\s*script\s*>", re.IGNORECASE), "[REDACTED]"),
    (re.compile(r"<\s*/?\s*script\b[^>]*>", re.IGNORECASE), "[REDACTED]"),
    (re.compile(r"javascript\s*:", re.IGNORECASE), "[REDACTED]"),
    (re.compile(r"\bBearer\s+[^\s`|<>]+", re.IGNORECASE), "[REDACTED]"),
    (re.compile(r"\$\([^)]*\)", re.IGNORECASE), "[REDACTED]"),
    (re.compile(r"\brm\s+-rf\b", re.IGNORECASE), "[REDACTED]"),
    (re.compile(r"https?://[^\s`|<>\])]+", re.IGNORECASE), "[REDACTED]"),
    (re.compile(r"\braw_(?:prompt|response)\b", re.IGNORECASE), "[REDACTED]"),
    (re.compile(r"\bRunReport\b"), "[REDACTED]"),
)


@dataclass(frozen=True)
class AssessmentEvidenceRef:
    evidence_id: str
    artifact_path: str
    artifact_type: str
    sha256: str
    source_length: int
    redacted_length: int
    redacted_preview: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AssessmentReportInput:
    assessment_id: str
    generated_at: str
    target: dict[str, Any]
    provider: dict[str, Any]
    profile: str
    mode: str
    packs: list[dict[str, Any]] = field(default_factory=list)
    scores: dict[str, Any] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    coverage: list[dict[str, Any]] = field(default_factory=list)
    evidence_refs: list[AssessmentEvidenceRef] = field(default_factory=list)
    gate: dict[str, Any] = field(default_factory=dict)
    remediation_refs: list[dict[str, Any]] = field(default_factory=list)
    regression_refs: list[dict[str, Any]] = field(default_factory=list)
    artifact_paths: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AssessmentReportResult:
    manifest_path: Path
    risk_report_path: Path
    output_dir: Path
    artifact_paths: dict[str, Path]


def write_assessment_reports(input: AssessmentReportInput, out_dir: str | Path) -> AssessmentReportResult:
    destination = Path(out_dir)
    destination.mkdir(parents=True, exist_ok=True)
    for relative_path in CANONICAL_ARTIFACTS:
        (destination / relative_path).parent.mkdir(parents=True, exist_ok=True)

    artifacts = _artifact_paths(input.artifact_paths)
    risk_report = _risk_report(input, artifacts)
    evidence_index = _evidence_index(input, risk_report)

    written: dict[str, Path] = {}
    written["risk-report.json"] = _write_text(destination, "risk-report.json", _json(risk_report))
    written["coverage/coverage.json"] = _write_text(destination, "coverage/coverage.json", _json(_coverage_report(input, risk_report)))
    written["findings/findings.json"] = _write_text(destination, "findings/findings.json", _json(_findings_report(input, risk_report)))
    written["evidence-bundle/artifact-index.json"] = _write_text(destination, "evidence-bundle/artifact-index.json", _json(evidence_index))
    written["executive-summary.md"] = _write_text(destination, "executive-summary.md", _executive_summary(risk_report))
    written["strengths-weaknesses.md"] = _write_text(destination, "strengths-weaknesses.md", _strengths_weaknesses(risk_report))
    written["coverage/coverage.md"] = _write_text(destination, "coverage/coverage.md", _coverage_markdown(risk_report))
    written["coverage/coverage.html"] = _write_text(destination, "coverage/coverage.html", _coverage_html(risk_report))
    written["findings/findings.md"] = _write_text(destination, "findings/findings.md", _findings_markdown(risk_report))
    written["remediation/remediation-board.md"] = _write_text(destination, "remediation/remediation-board.md", _remediation_board(risk_report))
    written["remediation/issue-export.json"] = _write_text(destination, "remediation/issue-export.json", _json(_issue_export(risk_report)))
    written["remediation/patches/README.md"] = _write_text(destination, "remediation/patches/README.md", _patches_readme(risk_report))
    written["regression/regression-pack.yaml"] = _write_text(destination, "regression/regression-pack.yaml", _regression_pack(risk_report))
    written["regression/replay-commands.md"] = _write_text(destination, "regression/replay-commands.md", _replay_commands(risk_report))
    written["evidence-bundle/index.html"] = _write_text(destination, "evidence-bundle/index.html", _evidence_bundle_html(risk_report, evidence_index))
    written["evidence-bundle/audit-summary.md"] = _write_text(destination, "evidence-bundle/audit-summary.md", _audit_summary_markdown(risk_report, evidence_index))
    written["risk-report.html"] = _write_text(destination, "risk-report.html", _risk_report_html(risk_report))
    written["studio/index.html"] = _write_text(destination, "studio/index.html", _studio_html(risk_report, evidence_index))

    manifest = _manifest(input, destination, tuple(TOP_LEVEL_ARTIFACTS + CANONICAL_ARTIFACTS))
    written["assessment-manifest.json"] = _write_text(destination, "assessment-manifest.json", _json(manifest))

    return AssessmentReportResult(
        manifest_path=destination / "assessment-manifest.json",
        risk_report_path=destination / "risk-report.json",
        output_dir=destination,
        artifact_paths={relative_path: path for relative_path, path in written.items()},
    )


def _json(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def _write_text(destination: Path, relative_path: str, text: str) -> Path:
    path = destination / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _artifact_paths(paths: dict[str, str]) -> dict[str, str]:
    merged = dict(ARTIFACT_PATHS)
    merged.update(paths)
    return {key: _safe_relative_path(value, fallback=ARTIFACT_PATHS.get(key, key)) for key, value in merged.items()}


def _safe_relative_path(value: object, *, fallback: str = "artifact") -> str:
    text = str(value or fallback).replace("\\", "/")
    decoded = unquote(text)
    if _is_unsafe_relative_path(decoded):
        return fallback
    text = _safe_text(text, limit=180)
    text = text.replace(" ", "-")
    decoded = unquote(text)
    if _is_unsafe_relative_path(decoded):
        return fallback
    return text


def _is_unsafe_relative_path(value: str) -> bool:
    if not value or value.startswith(("/", "//")) or Path(value).is_absolute() or ".." in Path(value).parts:
        return True
    parts = [part for part in Path(value).parts if part]
    if not parts:
        return True
    if _has_url_scheme(parts[0]):
        return True
    return any(_has_url_scheme(part) for part in parts)


def _has_url_scheme(value: object) -> bool:
    return re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", str(value)) is not None


def _risk_report(input: AssessmentReportInput, artifacts: dict[str, str]) -> dict[str, Any]:
    return {
        "schema_version": RISK_REPORT_SCHEMA_VERSION,
        "assessment_id": _safe_text(input.assessment_id),
        "generated_at": _safe_text(input.generated_at),
        "profile": _safe_text(input.profile),
        "mode": _safe_text(input.mode),
        "target": _target(input.target),
        "provider": _provider(input.provider),
        "packs": [_pack(pack) for pack in input.packs],
        "scores": _safe_json_value(input.scores),
        "gate": _gate(input.gate),
        "score_use_explanation": _score_use_explanation(input.packs),
        "findings": [_finding(finding) for finding in input.findings],
        "coverage": [_coverage_row(row) for row in input.coverage],
        "evidence_refs": [_evidence_ref(ref) for ref in input.evidence_refs],
        "remediation_refs": [_remediation_ref(ref) for ref in input.remediation_refs],
        "regression_refs": [_regression_ref(ref) for ref in input.regression_refs],
        "artifacts": artifacts,
        "metadata": _safe_json_value(input.metadata),
    }


def _score_use_explanation(packs: list[dict[str, Any]]) -> dict[str, Any]:
    explanation = dict(SCORE_USE_EXPLANATION)
    declared_strengths = {
        str(strength)
        for pack in packs
        for strength in [*_as_list(pack.get("evidence_strengths")), *_as_list(pack.get("primary_score_evidence"))]
    }
    explanation["evidence_strengths"] = {
        strength: description
        for strength, description in SCORE_USE_EXPLANATION["evidence_strengths"].items()
        if strength in declared_strengths
    }
    return explanation


def _target(target: dict[str, Any]) -> dict[str, str]:
    base_url = str(target.get("base_url", ""))
    host = urlparse(base_url).netloc or urlparse(f"//{base_url}").netloc
    return {
        "name": _safe_text(target.get("name", "unknown")),
        "adapter": _safe_text(target.get("adapter", "unknown")),
        "base_url_host": _safe_text(host or "unknown"),
    }


def _provider(provider: dict[str, Any]) -> dict[str, str]:
    normalized: dict[str, str] = {
        "name": _safe_text(provider.get("name", "unknown")),
        "model": _safe_text(provider.get("model", "unknown")),
    }
    if provider.get("config_hash") is not None:
        normalized["config_hash"] = _safe_text(provider["config_hash"])
    return normalized


def _pack(pack: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": _safe_text(pack.get("id", "unknown")),
        "title": _safe_text(pack.get("title", "unknown")),
        "description": _safe_text(pack.get("description", ""), limit=420),
        "tier": _safe_text(pack.get("tier", "unknown")),
        "maturity": _safe_text(pack.get("maturity", "unknown")),
        "score_use": _safe_text(pack.get("score_use", "unknown")),
        "applicability": _safe_text(pack.get("applicability", "unknown")),
        "mode": _safe_text(pack.get("mode", "unknown")),
        "applicable_profiles": [_safe_text(value) for value in _as_list(pack.get("applicable_profiles"))],
        "surfaces": [_safe_text(value) for value in _as_list(pack.get("surfaces"))],
        "techniques": [_safe_text(value) for value in _as_list(pack.get("techniques"))],
        "required_inputs": [_safe_text(value) for value in _as_list(pack.get("required_inputs"))],
        "expected_artifacts": [_safe_text(value) for value in _as_list(pack.get("expected_artifacts"))],
        "scoring_dimensions": [_safe_text(value) for value in _as_list(pack.get("scoring_dimensions"))],
        "finding_categories": [_safe_text(value) for value in _as_list(pack.get("finding_categories"))],
        "remediation_themes": [_safe_text(value) for value in _as_list(pack.get("remediation_themes"))],
        "evidence_strengths": [_safe_text(value) for value in _as_list(pack.get("evidence_strengths"))],
        "primary_score_evidence": [_safe_text(value) for value in _as_list(pack.get("primary_score_evidence"))],
        "score": _safe_json_value(pack.get("score", {})),
    }


def _finding(finding: dict[str, Any]) -> dict[str, Any]:
    evidence_refs = [_evidence_id(ref) for ref in _as_list(finding.get("evidence_refs"))]
    regression = _safe_json_value(finding.get("regression", {}))
    if not isinstance(regression, dict):
        regression = {}
    return {
        "finding_id": _safe_text(finding.get("finding_id", "unknown")),
        "pack_id": _safe_text(finding.get("pack_id", "unknown")),
        "case_id": _safe_text(finding.get("case_id", "unknown")),
        "severity": _safe_text(finding.get("severity", "unknown")),
        "category": _safe_text(finding.get("category", "unknown")),
        "technique": _safe_text(finding.get("technique", "unknown")),
        "surface": _safe_text(finding.get("surface", "unknown")),
        "profile": _safe_text(finding.get("profile", "unknown")),
        "status": _safe_text(finding.get("status", "unknown")),
        "owner": _safe_text(finding.get("owner", "unassigned")),
        "title": _safe_text(finding.get("title", "Untitled finding")),
        "summary": _preview(finding.get("summary", "")),
        "redacted_preview": _preview(finding.get("redacted_preview", finding.get("summary", ""))),
        "impact": _safe_text(finding.get("impact", "unknown")),
        "likelihood": _safe_text(finding.get("likelihood", "unknown")),
        "confidence": _safe_text(finding.get("confidence", "unknown")),
        "remediation": _safe_text(finding.get("remediation", "Review control and add regression coverage."), limit=520),
        "regression": {
            "pack_id": _safe_text(regression.get("pack_id", finding.get("pack_id", "unknown"))),
            "expected_fixed_behavior": _safe_text(regression.get("expected_fixed_behavior", "Document fixed behavior before replay."), limit=420),
            "replay_mode": _safe_text(regression.get("replay_mode", "provider_free_required")),
            "replay_command_ref": _safe_relative_path(regression.get("replay_command_ref", "regression/replay-commands.md"), fallback="regression/replay-commands.md"),
            "tags": [_safe_text(tag) for tag in _as_list(regression.get("tags"))],
        },
        "evidence_refs": evidence_refs,
        "remediation_ref": _safe_relative_path(finding.get("remediation_ref", "remediation/remediation-board.md"), fallback="remediation/remediation-board.md"),
    }


def _coverage_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "dimension": _safe_text(row.get("dimension", "unknown")),
        "value": _safe_text(row.get("value", "unknown")),
        "status": _safe_text(row.get("status", "unknown")),
        "pack_ids": [_safe_text(value) for value in _as_list(row.get("pack_ids"))],
        "evidence_refs": [_evidence_id(ref) for ref in _as_list(row.get("evidence_refs"))],
    }


def _evidence_ref(ref: AssessmentEvidenceRef) -> dict[str, Any]:
    preview = _safe_text(ref.redacted_preview, limit=260)
    if "sha256=" not in preview or "length=" not in preview:
        preview = f"{preview} [REDACTED evidence sha256={ref.sha256[:16]} length={ref.source_length}]"
    return {
        "evidence_id": _safe_text(ref.evidence_id),
        "artifact_path": _safe_relative_path(ref.artifact_path, fallback="evidence-bundle/artifact-index.json"),
        "artifact_type": _safe_text(ref.artifact_type),
        "sha256": _safe_hash(ref.sha256),
        "source_length": int(ref.source_length),
        "redacted_length": int(ref.redacted_length),
        "redacted_preview": preview,
    }


def _remediation_ref(ref: dict[str, Any]) -> dict[str, Any]:
    return {
        "finding_id": _safe_text(ref.get("finding_id", "unknown")),
        "path": _safe_relative_path(ref.get("path", "remediation/remediation-board.md"), fallback="remediation/remediation-board.md"),
    }


def _regression_ref(ref: dict[str, Any]) -> dict[str, Any]:
    return {
        "pack_id": _safe_text(ref.get("pack_id", "unknown")),
        "path": _safe_relative_path(ref.get("path", "regression/regression-pack.yaml"), fallback="regression/regression-pack.yaml"),
        "case_ids": [_safe_text(value) for value in _as_list(ref.get("case_ids"))],
    }


def _gate(gate: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": _safe_text(gate.get("status", "unknown")),
        "reasons": [_safe_text(value) for value in _as_list(gate.get("reasons"))],
        "policy": _safe_text(gate.get("policy", "default")),
    }


def _evidence_id(ref: object) -> str:
    if isinstance(ref, AssessmentEvidenceRef):
        return _safe_text(ref.evidence_id)
    if isinstance(ref, dict):
        return _safe_text(ref.get("evidence_id", "unknown"))
    return _safe_text(ref)


def _coverage_report(input: AssessmentReportInput, risk_report: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "malleus.assessment_coverage.v1",
        "redaction_status": _redaction_marker(),
        "assessment_id": risk_report["assessment_id"],
        "profile": risk_report["profile"],
        "mode": risk_report["mode"],
        "coverage": risk_report["coverage"],
        "untested": [pack for pack in risk_report["packs"] if pack["score_use"] == "not_tested" or pack["applicability"] == "not_tested"],
        "not_applicable": [pack for pack in risk_report["packs"] if pack["applicability"] == "not_applicable"],
        "scaffold_only": [pack for pack in risk_report["packs"] if pack["applicability"] == "scaffold_only"],
        "evidence_refs": [_evidence_ref(ref) for ref in input.evidence_refs],
    }


def _findings_report(input: AssessmentReportInput, risk_report: dict[str, Any]) -> dict[str, Any]:
    findings = risk_report["findings"]
    return {
        "schema_version": "malleus.assessment_findings.v1",
        "redaction_status": _redaction_marker(),
        "assessment_id": risk_report["assessment_id"],
        "status": "active_findings" if findings else "no_active_findings",
        "note": "Active findings require triage." if findings else "No active findings recorded for this provider-free assessment run.",
        "findings": findings,
        "evidence_refs": [_evidence_ref(ref) for ref in input.evidence_refs],
    }


def _evidence_index(input: AssessmentReportInput, risk_report: dict[str, Any]) -> dict[str, Any]:
    artifacts = [_evidence_artifact_entry(ref, risk_report) for ref in input.evidence_refs]
    return {
        "schema_version": "malleus.assessment_evidence_index.v1",
        "redaction_status": _redaction_marker(),
        "assessment_id": risk_report["assessment_id"],
        "mode": risk_report["mode"],
        "artifacts": artifacts,
        "evidence_refs": [_evidence_ref(ref) for ref in input.evidence_refs],
        "note": "Public evidence index contains refs, hashes, lengths, and redacted previews only.",
    }


def _evidence_artifact_entry(ref: AssessmentEvidenceRef, risk_report: dict[str, Any]) -> dict[str, Any]:
    relative_path = _safe_relative_path(ref.artifact_path, fallback="evidence-bundle/artifact-index.json")
    metadata = ref.metadata if isinstance(ref.metadata, dict) else {}
    pack_id = _safe_text(metadata.get("pack_id") or _pack_id_from_path(relative_path) or "unknown")
    pack = _pack_for_id(risk_report, pack_id)
    mode = _safe_text(metadata.get("mode") or pack.get("mode") or risk_report["mode"])
    evidence_strength = _safe_text(
        metadata.get("evidence_strength")
        or _first_text(_as_list(pack.get("evidence_strengths")))
        or "unknown"
    )
    evidence_id = _safe_text(ref.evidence_id)
    sha256 = _safe_hash(ref.sha256)
    return {
        "evidence_id": evidence_id,
        "stable_ref": _safe_text(f"{pack_id}/{relative_path}#{evidence_id}", limit=360),
        "pack_id": pack_id,
        "relative_path": relative_path,
        "path": relative_path,
        "artifact_path": relative_path,
        "sha256": sha256,
        "hash": sha256,
        "length": int(ref.source_length),
        "source_length": int(ref.source_length),
        "redacted_length": int(ref.redacted_length),
        "mode": mode,
        "mode_label": mode,
        "evidence_strength": evidence_strength,
        "artifact_type": _safe_text(ref.artifact_type),
        "redacted_preview": _safe_text(ref.redacted_preview, limit=260),
    }


def _pack_id_from_path(relative_path: str) -> str | None:
    parts = Path(relative_path).parts
    if len(parts) >= 3 and parts[0] == "raw":
        return str(parts[1])
    return None


def _pack_for_id(risk_report: dict[str, Any], pack_id: str) -> dict[str, Any]:
    for pack in risk_report["packs"]:
        if pack["id"] == pack_id:
            return pack
    return {}


def _first_text(values: list[Any]) -> str:
    return _safe_text(values[0]) if values else ""


def _score_label(score: object) -> str:
    if score is None:
        return "not scored"
    return _safe_text(score)


def _primary_score(report: dict[str, Any]) -> object:
    scores = report.get("scores", {})
    if isinstance(scores, dict):
        primary = scores.get("primary_score") or scores.get("primary")
        if isinstance(primary, dict):
            if primary.get("score") is not None:
                return primary["score"]
            earned = primary.get("earned")
            possible = primary.get("possible")
            if possible:
                return round((int(earned or 0) / int(possible)) * 100)
    return None


def _coverage_confidence(report: dict[str, Any]) -> object:
    scores = report.get("scores", {})
    if isinstance(scores, dict):
        coverage = scores.get("coverage_confidence")
        if isinstance(coverage, dict):
            return coverage.get("score")
    return None


def _severity_counts(report: dict[str, Any]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0}
    for finding in report["findings"]:
        severity = str(finding.get("severity", "")).lower()
        if severity in counts:
            counts[severity] += 1
    return counts


def _score_uses(report: dict[str, Any]) -> dict[str, int]:
    uses = {"included": 0, "advisory": 0, "excluded": 0, "not_applicable": 0, "not_tested": 0}
    for pack in report["packs"]:
        score_use = pack.get("score_use", "")
        if score_use in uses:
            uses[score_use] += 1
    return uses


def _category_rows(report: dict[str, Any]) -> list[str]:
    scores = report.get("scores", {})
    category_scores = scores.get("category_scores", {}) if isinstance(scores, dict) else {}
    rows: list[str] = []
    if isinstance(category_scores, dict):
        for category, payload in sorted(category_scores.items()):
            if isinstance(payload, dict):
                rows.append(f"| {_md(category)} | {_md(_score_label(payload.get('score')))} | {_md(', '.join(_as_list(payload.get('pack_ids'))) or 'none')} |")
    if not rows:
        rows.append("| none | not scored | none |")
    return rows


def _retest_reference(report: dict[str, Any], pack_id: str) -> str:
    for ref in report.get("regression_refs", []):
        if isinstance(ref, dict) and ref.get("pack_id") == pack_id:
            return _safe_relative_path(ref.get("path", "regression/replay-commands.md"), fallback="regression/replay-commands.md")
    return "regression/replay-commands.md"


def _executive_summary(report: dict[str, Any]) -> str:
    posture = report["gate"]["status"] or report.get("scores", {}).get("posture", "unknown")
    primary_score = _primary_score(report)
    coverage_score = _coverage_confidence(report)
    severity_counts = _severity_counts(report)
    score_uses = _score_uses(report)
    caveats = _as_list(report.get("metadata", {}).get("caveats")) if isinstance(report.get("metadata"), dict) else []
    lines = [
        "# Executive Summary",
        "",
        f"- Assessment: {_md(report['assessment_id'])}",
        f"- Profile: {_md(report['profile'])}",
        f"- Mode: {_md(report['mode'])}",
        f"- Target: {_md(report['target']['name'])} ({_md(report['target']['adapter'])})",
        f"- Overall posture: {_md(posture)}",
        f"- Primary score: {_md(_score_label(primary_score))}",
        f"- Coverage confidence: {_md(_score_label(coverage_score))}",
        f"- Critical findings: {severity_counts['critical']}",
        f"- High findings: {severity_counts['high']}",
        f"- Pack score-use mix: included={score_uses['included']}, advisory={score_uses['advisory']}, excluded={score_uses['excluded']}, not_applicable={score_uses['not_applicable']}, not_tested={score_uses['not_tested']}",
        "",
        "## High-level strengths",
        "",
        *([f"- {_md(pack['id'])}: {_md(pack['title'])} is included in the primary score for this run." for pack in report["packs"] if pack["score_use"] == "included"] or ["- No primary-score strengths were recorded for this provider-free run."]),
        "",
        "## High-level weaknesses and triage",
        "",
        *([f"- {_md(pack['id'])}: {_md(pack['applicability'])} / {_md(pack['score_use'])}; prioritize {_md(', '.join(pack['remediation_themes']) or 'documented review')} and retest with {_md(_retest_reference(report, pack['id']))}." for pack in report["packs"] if pack["score_use"] in {"advisory", "not_tested"}] or ["- No advisory or not-tested weaknesses were recorded."]),
        "",
        "## Recommended next actions",
        "",
        "- Triage critical/high findings first, then coverage gaps for selected profile packs.",
        "- Use `remediation/remediation-board.md` and `remediation/issue-export.json` for owner assignment.",
        "- Retest fixed gaps with `regression/replay-commands.md` and `regression/regression-pack.yaml`.",
        "",
        "## Caveats and limitations",
        "",
        *([f"- {_md(caveat)}" for caveat in caveats] or ["- Results apply only to selected packs, profile, mode, and local artifacts."]),
        "- Untested, fixture-required, configuration-required, scaffold-only, and not-applicable surfaces are not counted as safe.",
        "- Provider-free evidence is not live model behavior evidence.",
        "",
        "## Score-use table",
        "",
        "| Label | Meaning |",
        "|---|---|",
    ]
    for key in ("included", "advisory", "excluded", "not_applicable", "not_tested"):
        lines.append(f"| {_md(key)} | {_md(report['score_use_explanation'][key])} |")
    lines.extend(["", "## Evidence strengths", "", "| Strength | Meaning |", "|---|---|"])
    for key, value in report["score_use_explanation"]["evidence_strengths"].items():
        lines.append(f"| {_md(key)} | {_md(value)} |")
    lines.extend(["", "## Pack summary", "", "| Pack | Score use | Applicability | Mode | Evidence |", "|---|---|---|---|---|"])
    for pack in report["packs"]:
        lines.append(
            f"| {_md(pack['id'])} | {_md(pack['score_use'])} | {_md(pack['applicability'])} | {_md(pack['mode'])} | {_md(', '.join(pack['evidence_strengths']) or 'none')} |"
        )
    lines.extend(["", "## Untested / not-applicable / scaffold-only", ""])
    lines.extend(_pack_section_lines(report, "not_tested", "Untested"))
    lines.extend(_pack_section_lines(report, "not_applicable", "Not applicable", field_name="applicability"))
    lines.extend(_pack_section_lines(report, "scaffold_only", "Scaffold-only", field_name="applicability"))
    return "\n".join(lines).rstrip() + "\n"


def _strengths_weaknesses(report: dict[str, Any]) -> str:
    strengths = [pack for pack in report["packs"] if pack["score_use"] == "included"]
    weaknesses = [pack for pack in report["packs"] if pack["score_use"] in {"advisory", "not_tested"}]
    severity_counts = _severity_counts(report)
    lines = [
        "# Strengths and Weaknesses",
        "",
        f"Public redaction status: {_md(_redaction_marker())}",
        "",
        "This report separates included, advisory, excluded, not_applicable, not_tested, and scaffold-only evidence. Weaknesses are triage inputs, not proof of universal model behavior.",
        "",
        "## Assessment posture",
        "",
        f"- Posture: {_md(report['gate']['status'])}",
        f"- Primary score: {_md(_score_label(_primary_score(report)))}",
        f"- Coverage confidence: {_md(_score_label(_coverage_confidence(report)))}",
        f"- Critical/high findings: {severity_counts['critical']} critical, {severity_counts['high']} high",
        "",
        "## Strengths",
    ]
    lines.extend(
        [
            f"- {_md(pack['id'])}: {_md(pack['title'])}; category dimensions {_md(', '.join(pack['scoring_dimensions']) or 'none')}; evidence {_md(', '.join(pack['evidence_strengths']) or 'none')}."
            for pack in strengths
        ]
        or ["- None recorded."]
    )
    lines.extend(["", "## Category scores", "", "| Category | Score | Packs |", "|---|---|---|"])
    lines.extend(_category_rows(report))
    lines.extend(["", "## Per-attack-pack results", "", "| Pack | Tier | Maturity | Score use | Applicability | Surfaces |", "|---|---|---|---|---|---|"])
    for pack in report["packs"]:
        lines.append(
            f"| {_md(pack['id'])} | {_md(pack['tier'])} | {_md(pack['maturity'])} | {_md(pack['score_use'])} | {_md(pack['applicability'])} | {_md(', '.join(pack['surfaces']) or 'none')} |"
        )
    lines.extend(["", "## Weaknesses and gaps"])
    lines.extend(
        [
            f"- {_md(pack['id'])}: {_md(pack['score_use'])} / {_md(pack['applicability'])}. Why it matters: {_md(', '.join(pack['finding_categories']) or 'coverage gap')} can hide deployment risk on {_md(', '.join(pack['surfaces']) or 'unknown surfaces')}. Priority: {_md(', '.join(pack['remediation_themes']) or 'review and retest')}. Retest reference: {_md(_retest_reference(report, pack['id']))}."
            for pack in weaknesses
        ]
        or ["- None recorded."]
    )
    lines.extend(["", "## Remediation priorities", ""])
    lines.extend(
        [
            f"- {_md(pack['id'])}: address {_md(', '.join(pack['remediation_themes']) or 'documented remediation')} before treating {_md(', '.join(pack['surfaces']) or pack['id'])} as covered."
            for pack in weaknesses
        ]
        or ["- No remediation priorities were generated."]
    )
    lines.extend(["", "## Retest commands", "", "- Use `regression/replay-commands.md` for per-finding commands.", "- Use `regression/regression-pack.yaml` as the provider-free regression pack reference."])
    lines.extend(["", "## Evidence strength definitions"])
    for key, value in report["score_use_explanation"]["evidence_strengths"].items():
        lines.append(f"- {_md(key)}: {_md(value)}")
    lines.extend(["", "## Score-use definitions"])
    for key in ("included", "advisory", "excluded", "not_applicable", "not_tested"):
        lines.append(f"- {_md(key)}: {_md(report['score_use_explanation'][key])}")
    return "\n".join(lines).rstrip() + "\n"


def _coverage_markdown(report: dict[str, Any]) -> str:
    lines = ["# Coverage", "", f"Public redaction status: {_md(_redaction_marker())}", "", "| Dimension | Value | Status | Packs | Evidence refs |", "|---|---|---|---|---|"]
    for row in report["coverage"]:
        lines.append(
            f"| {_md(row['dimension'])} | {_md(row['value'])} | {_md(row['status'])} | {_md(', '.join(row['pack_ids']))} | {_md(', '.join(row['evidence_refs']) or 'none')} |"
        )
    lines.extend(["", "## Untested", ""])
    lines.extend(_pack_section_lines(report, "not_tested", "Untested"))
    lines.extend(["", "## Not applicable", ""])
    lines.extend(_pack_section_lines(report, "not_applicable", "Not applicable", field_name="applicability"))
    lines.extend(["", "## Scaffold-only", ""])
    lines.extend(_pack_section_lines(report, "scaffold_only", "Scaffold-only", field_name="applicability"))
    return "\n".join(lines).rstrip() + "\n"


def _coverage_html(report: dict[str, Any]) -> str:
    rows = "".join(
        "<tr>"
        f"<td>{_html(row['dimension'])}</td>"
        f"<td>{_html(row['value'])}</td>"
        f"<td>{_html(row['status'])}</td>"
        f"<td>{_html(', '.join(row['pack_ids']))}</td>"
        f"<td>{_html(', '.join(row['evidence_refs']) or 'none')}</td>"
        "</tr>"
        for row in report["coverage"]
    ) or "<tr><td colspan=\"5\">No coverage rows recorded.</td></tr>"
    untested = [pack for pack in report["packs"] if pack["score_use"] == "not_tested" or pack["applicability"] == "not_tested"]
    not_applicable = [pack for pack in report["packs"] if pack["applicability"] == "not_applicable"]
    scaffold_only = [pack for pack in report["packs"] if pack["applicability"] == "scaffold_only"]
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Malleus Assessment Coverage</title>
<style>{_static_style()}</style>
</head>
<body>
<main>
<section class="hero"><p class="eyebrow">Malleus / assessment coverage</p><h1>Coverage</h1><p>Public redaction status: {_html(_redaction_marker())}. Coverage rows use evidence refs, hashes, and status labels only.</p></section>
<section class="cards"><article>Coverage rows<strong>{len(report['coverage'])}</strong></article><article>Untested<strong>{len(untested)}</strong></article><article>Not applicable<strong>{len(not_applicable)}</strong></article><article>Scaffold-only<strong>{len(scaffold_only)}</strong></article></section>
<section class="panel"><h2>Coverage matrix</h2><table><thead><tr><th>Dimension</th><th>Value</th><th>Status</th><th>Packs</th><th>Evidence refs</th></tr></thead><tbody>{rows}</tbody></table></section>
<section class="panel"><h2>Explicit gaps</h2><ul>{_pack_list(untested, 'No untested packs.')} {_pack_list(not_applicable, 'No not-applicable packs.')} {_pack_list(scaffold_only, 'No scaffold-only packs.')}</ul></section>
<footer>Static HTML. No external JavaScript, fonts, iframes, server, or network dependency.</footer>
</main>
</body>
</html>
"""


def _evidence_bundle_html(report: dict[str, Any], evidence_index: dict[str, Any]) -> str:
    artifact_rows = "".join(
        "<tr>"
        f"<td><a href=\"{_html(_href_from('evidence-bundle', artifact['relative_path']))}\">{_html(artifact['relative_path'])}</a></td>"
        f"<td>{_html(artifact['pack_id'])}</td>"
        f"<td>{_html(artifact['artifact_type'])}</td>"
        f"<td>{_html(artifact['mode'])}</td>"
        f"<td>{_html(artifact['evidence_strength'])}</td>"
        f"<td><code>{_html(artifact['sha256'])}</code></td>"
        f"<td>{_html(artifact['source_length'])}</td>"
        f"<td>{_html(artifact['redacted_length'])}</td>"
        f"<td>{_html(artifact['stable_ref'])}</td>"
        "</tr>"
        for artifact in evidence_index["artifacts"]
    ) or "<tr><td colspan=\"9\">No evidence artifacts recorded.</td></tr>"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Malleus Assessment Evidence Bundle</title>
<style>{_static_style()}</style>
</head>
<body>
<main>
<section class="hero"><p class="eyebrow">Malleus / evidence bundle</p><h1>Evidence bundle</h1><p>Assessment {_html(report['assessment_id'])} in {_html(report['mode'])} mode. Public redaction status: {_html(_redaction_marker())}. Raw report bodies are omitted; artifacts are indexed by relative path, SHA-256, lengths, pack, mode, and evidence strength.</p></section>
<section class="cards"><article>Artifacts<strong>{len(evidence_index['artifacts'])}</strong></article><article>Findings<strong>{len(report['findings'])}</strong></article><article>Coverage rows<strong>{len(report['coverage'])}</strong></article><article>Gate<strong>{_html(report['gate']['status'])}</strong></article></section>
<section class="panel"><h2>Artifact index</h2><table><thead><tr><th>Relative path</th><th>Pack</th><th>Type</th><th>Mode</th><th>Evidence strength</th><th>SHA-256</th><th>Source length</th><th>Redacted length</th><th>Stable ref</th></tr></thead><tbody>{artifact_rows}</tbody></table></section>
<section class="panel"><h2>Reviewer note</h2><p>Use <a href="artifact-index.json">artifact-index.json</a> and <a href="audit-summary.md">audit-summary.md</a> for machine-readable and Markdown review. Links are local relative paths only.</p></section>
<footer>Static HTML. No external JavaScript, fonts, iframes, server, or network dependency.</footer>
</main>
</body>
</html>
"""


def _audit_summary_markdown(report: dict[str, Any], evidence_index: dict[str, Any]) -> str:
    lines = [
        "# Assessment Evidence Audit Summary",
        "",
        f"- Assessment: {_md(report['assessment_id'])}",
        f"- Profile: {_md(report['profile'])}",
        f"- Mode: {_md(report['mode'])}",
        f"- Gate: {_md(report['gate']['status'])}",
        f"- Public redaction status: {_md(_redaction_marker())}",
        "",
        "## Artifact index",
        "",
        "| Evidence | Pack | Relative path | Type | Mode | Evidence strength | SHA-256 | Source length | Redacted length | Stable ref |",
        "|---|---|---|---|---|---|---|---:|---:|---|",
    ]
    for artifact in evidence_index["artifacts"]:
        lines.append(
            f"| {_md(artifact['evidence_id'])} | {_md(artifact['pack_id'])} | {_md(artifact['relative_path'])} | {_md(artifact['artifact_type'])} | {_md(artifact['mode'])} | {_md(artifact['evidence_strength'])} | {_md(artifact['sha256'])} | {artifact['source_length']} | {artifact['redacted_length']} | {_md(artifact['stable_ref'])} |"
        )
    if not evidence_index["artifacts"]:
        lines.append("| none | none | none | none | none | none | none | 0 | 0 | none |")
    lines.extend(
        [
            "",
            "## Coverage and findings",
            "",
            f"- Coverage rows: {len(report['coverage'])}",
            f"- Findings: {len(report['findings'])}",
            "- Raw prompts, raw responses, private paths, provider secrets, and full raw report bodies are intentionally omitted from public assessment artifacts.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def _findings_markdown(report: dict[str, Any]) -> str:
    lines = ["# Findings", "", f"Public redaction status: {_md(_redaction_marker())}", ""]
    for finding in report["findings"]:
        lines.extend(
            [
                f"## {_md(finding['finding_id'])}: {_md(finding['title'])}",
                "",
                f"- Severity: {_md(finding['severity'])}",
                f"- Category: {_md(finding['category'])}",
                f"- Status: {_md(finding['status'])}",
                f"- Pack: {_md(finding['pack_id'])}",
                f"- Technique: {_md(finding['technique'])}",
                f"- Surface: {_md(finding['surface'])}",
                f"- Profile: {_md(finding['profile'])}",
                f"- Owner: {_md(finding['owner'])}",
                f"- Evidence refs: {_md(', '.join(finding['evidence_refs']) or 'none')}",
                f"- Remediation: {_md(finding['remediation_ref'])}",
                f"- Impact: {_md(finding['impact'])}",
                f"- Likelihood: {_md(finding['likelihood'])}",
                f"- Confidence: {_md(finding['confidence'])}",
                f"- Regression replay: {_md(finding['regression']['replay_command_ref'])}",
                f"- Summary: {_md(finding['summary'])}",
                f"- Redacted preview: {_md(finding['redacted_preview'])}",
                "",
            ]
        )
    if not report["findings"]:
        lines.append("No active findings recorded.")
    return "\n".join(lines).rstrip() + "\n"


def _remediation_board(report: dict[str, Any]) -> str:
    lines = [
        "# Remediation Board",
        "",
        f"Public redaction status: {_md(_redaction_marker())}",
        "",
        "| Finding | Severity | Status | Owner | Evidence refs | Action |",
        "|---|---|---|---|---|---|",
    ]
    for finding in report["findings"]:
        lines.append(
            f"| {_md(finding['finding_id'])} | {_md(finding['severity'])} | {_md(finding['status'])} | {_md(finding['owner'])} | {_md(', '.join(finding['evidence_refs']))} | {_md(finding['remediation'])} |"
        )
    if not report["findings"]:
        lines.append("| none | n/a | n/a | unassigned | none | No remediation required. |")
    return "\n".join(lines).rstrip() + "\n"


def _issue_export(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "malleus.assessment_issue_export.v1",
        "redaction_status": _redaction_marker(),
        "assessment_id": report["assessment_id"],
        "remote_creation": "disabled",
        "issues": [
            {
                "finding_id": finding["finding_id"],
                "title": finding["title"],
                "severity": finding["severity"],
                "status": finding["status"],
                "owner": finding["owner"],
                "labels": ["malleus-assessment", finding["category"], finding["pack_id"]],
                "body": finding["summary"],
                "remediation": finding["remediation"],
                "evidence_refs": finding["evidence_refs"],
            }
            for finding in report["findings"]
        ],
    }


def _patches_readme(report: dict[str, Any]) -> str:
    lines = [
        "# Remediation Patch Mapping",
        "",
        f"Public redaction status: {_md(_redaction_marker())}",
        "",
        "This assessment creates the PRD-required `remediation/patches/` directory as a safe scaffold.",
        "No executable patch content is generated automatically in provider-free assessment mode; remediation remains report-first and human-reviewed.",
        "",
        "## Mapping",
        "",
        "| Source | Patch mapping | Validation |",
        "|---|---|---|",
    ]
    if report["findings"]:
        for finding in report["findings"]:
            lines.append(
                f"| {_md(finding['finding_id'])} | remediation/patches/ is reserved for reviewed defensive changes only | {_md(finding['regression']['replay_command_ref'])} |"
            )
    else:
        lines.append("| no active findings | remediation/patches/ remains empty by design | regression/replay-commands.md |")
    return "\n".join(lines).rstrip() + "\n"


def _regression_pack(report: dict[str, Any]) -> str:
    lines = ["schema_version: malleus.assessment_regression_pack.v1", f"assessment_id: {_yaml_scalar(report['assessment_id'])}", "regressions:"]
    for finding in report["findings"]:
        regression = finding["regression"]
        lines.append(f"  - finding_id: {_yaml_scalar(finding['finding_id'])}")
        lines.append(f"    pack_id: {_yaml_scalar(finding['pack_id'])}")
        lines.append(f"    severity: {_yaml_scalar(finding['severity'])}")
        lines.append(f"    sanitized_prompt_ref: {_yaml_scalar(','.join(finding['evidence_refs']) or 'none')}")
        lines.append("    fixture_refs:")
        for evidence_ref in finding["evidence_refs"]:
            lines.append(f"      - {_yaml_scalar(evidence_ref)}")
        lines.append(f"    expected_fixed_behavior: {_yaml_scalar(regression['expected_fixed_behavior'])}")
        lines.append(f"    replay_mode: {_yaml_scalar(regression['replay_mode'])}")
        lines.append(f"    replay_command_ref: {_yaml_scalar(regression['replay_command_ref'])}")
        lines.append("    tags:")
        for tag in regression["tags"]:
            lines.append(f"      - {_yaml_scalar(tag)}")
    if not report["findings"]:
        lines.append("  []")
    return "\n".join(lines).rstrip() + "\n"


def _replay_commands(report: dict[str, Any]) -> str:
    lines = ["# Replay Commands", "", f"Public redaction status: {_md(_redaction_marker())}", ""]
    if not report["findings"]:
        lines.append("No replay commands generated because no active findings were recorded.")
        return "\n".join(lines).rstrip() + "\n"
    for finding in report["findings"]:
        command = shlex.join(
            [
                "malleus",
                "assess",
                "--profile",
                finding["profile"],
                "--packs",
                finding["pack_id"],
                "--mode",
                "local_fixture",
                "--out-dir",
                "<assessment-output>",
            ]
        )
        lines.extend([f"## {_md(finding['finding_id'])}", "", "```text", _safe_text(command, limit=420), "```", ""])
    return "\n".join(lines).rstrip() + "\n"


def _risk_report_html(report: dict[str, Any]) -> str:
    evidence_labels = ", ".join(report["score_use_explanation"]["evidence_strengths"]) or "none"
    pack_rows = "".join(
        "<tr>"
        f"<td>{_html(pack['id'])}</td>"
        f"<td>{_html(pack['score_use'])}</td>"
        f"<td>{_html(pack['applicability'])}</td>"
        f"<td>{_html(pack['mode'])}</td>"
        f"<td>{_html(', '.join(pack['evidence_strengths']))}</td>"
        "</tr>"
        for pack in report["packs"]
    )
    explanation_rows = "".join(
        f"<tr><td>{_html(key)}</td><td>{_html(report['score_use_explanation'][key])}</td></tr>"
        for key in ("included", "advisory", "excluded", "not_applicable", "not_tested")
    )
    strength_rows = "".join(
        f"<tr><td>{_html(key)}</td><td>{_html(value)}</td></tr>"
        for key, value in report["score_use_explanation"]["evidence_strengths"].items()
    )
    finding_rows = "".join(
        f"<tr><td>{_html(finding['finding_id'])}</td><td>{_html(finding['severity'])}</td><td>{_html(finding['summary'])}</td><td>{_html(', '.join(finding['evidence_refs']))}</td></tr>"
        for finding in report["findings"]
    ) or "<tr><td colspan=\"4\">No findings recorded.</td></tr>"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Malleus Assessment Risk Report</title>
<style>
body {{ font-family: ui-sans-serif, system-ui, sans-serif; margin: 2rem; background: #0f172a; color: #e5e7eb; }}
.card {{ background: #111827; border: 1px solid #334155; border-radius: 12px; padding: 1rem; margin-bottom: 1rem; }}
table {{ border-collapse: collapse; width: 100%; margin-bottom: 1rem; }}
th, td {{ border: 1px solid #334155; padding: .55rem; text-align: left; vertical-align: top; }}
th {{ background: #1e293b; }}
</style>
</head>
<body>
<h1>Malleus Assessment Risk Report</h1>
<section class="card"><p><strong>Assessment:</strong> {_html(report['assessment_id'])}</p><p><strong>Profile:</strong> {_html(report['profile'])}</p><p><strong>Mode:</strong> {_html(report['mode'])}</p><p><strong>Target:</strong> {_html(report['target']['name'])}</p><p><strong>Gate:</strong> {_html(report['gate']['status'])}</p></section>
<h2>Score-use table</h2><table><thead><tr><th>Label</th><th>Meaning</th></tr></thead><tbody>{explanation_rows}</tbody></table>
<h2>Evidence strengths</h2><table><thead><tr><th>Strength</th><th>Meaning</th></tr></thead><tbody>{strength_rows}</tbody></table>
<h2>Packs</h2><table><thead><tr><th>Pack</th><th>Score use</th><th>Applicability</th><th>Mode</th><th>Evidence</th></tr></thead><tbody>{pack_rows}</tbody></table>
<h2>Findings</h2><table><thead><tr><th>Finding</th><th>Severity</th><th>Summary</th><th>Evidence refs</th></tr></thead><tbody>{finding_rows}</tbody></table>
<p>Sections: included, advisory, excluded, not_applicable, not_tested, scaffold-only. Evidence: {_html(evidence_labels)}.</p>
</body>
</html>
"""


def _studio_html(report: dict[str, Any], evidence_index: dict[str, Any]) -> str:
    evidence_labels = ", ".join(report["score_use_explanation"]["evidence_strengths"]) or "none"
    artifacts = "".join(
        f"<li>{_html(key)}: <a href=\"{_html(_href_from('studio', value))}\">{_html(value)}</a></li>"
        for key, value in sorted(report["artifacts"].items())
    )
    evidence = "".join(
        f"<li>{_html(ref['evidence_id'])}: {_html(ref['artifact_type'])}, sha256 {_html(ref['sha256'])}, length {_html(ref['source_length'])}, preview {_html(ref['redacted_preview'])}</li>"
        for ref in report["evidence_refs"]
    ) or "<li>No evidence refs recorded.</li>"
    artifact_rows = "".join(
        "<tr>"
        f"<td><a href=\"{_html(_href_from('studio', artifact['relative_path']))}\">{_html(artifact['relative_path'])}</a></td>"
        f"<td>{_html(artifact['pack_id'])}</td>"
        f"<td>{_html(artifact['evidence_id'])}</td>"
        f"<td>{_html(artifact['artifact_type'])}</td>"
        f"<td>{_html(artifact['mode'])}</td>"
        f"<td>{_html(artifact['evidence_strength'])}</td>"
        f"<td>{_html(artifact['source_length'])}</td>"
        f"<td><code>{_html(artifact['sha256'])}</code></td>"
        "</tr>"
        for artifact in evidence_index["artifacts"]
    ) or "<tr><td colspan=\"8\">No evidence artifacts recorded.</td></tr>"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Malleus Assessment Studio</title>
<style>{_static_style()}</style>
</head>
<body>
<main>
<h1>Assessment Studio</h1>
<div class="panel"><p>Assessment {_html(report['assessment_id'])} for profile {_html(report['profile'])} in mode {_html(report['mode'])}. This studio view is a static sanitized navigation surface; raw report bodies are intentionally omitted.</p></div>
<div class="panel"><h2>Canonical artifacts</h2><ul>{artifacts}</ul></div>
<div class="panel"><h2>Evidence refs</h2><ul>{evidence}</ul></div>
<div class="panel"><h2>Evidence artifact navigation</h2><table><thead><tr><th>Relative path</th><th>Pack</th><th>Evidence</th><th>Type</th><th>Mode</th><th>Strength</th><th>Length</th><th>SHA-256</th></tr></thead><tbody>{artifact_rows}</tbody></table></div>
<p>Score-use labels: included, advisory, excluded, not_applicable, not_tested, scaffold-only. Evidence: {_html(evidence_labels)}.</p>
<footer>Static HTML. No external JavaScript, fonts, iframes, server, or network dependency.</footer>
</main>
</body>
</html>
"""


def _static_style() -> str:
    return """
:root { color-scheme: dark; --bg:#0b0c0f; --panel:#15171c; --surface:#181a20; --line:#333946; --text:#f5f5f5; --muted:#b8c0cc; --accent:#93c5fd; --space-2:8px; --space-3:12px; --space-4:16px; --space-5:24px; --radius:12px; }
* { box-sizing:border-box; }
body { margin:0; font-family:ui-sans-serif,system-ui,sans-serif; background:var(--bg); color:var(--text); }
main { max-width:1180px; margin:0 auto; padding:32px 24px 56px; }
a { color:var(--accent); }
.hero,.panel,article { border:1px solid var(--line); border-radius:var(--radius); background:var(--panel); padding:var(--space-4); margin-bottom:var(--space-4); }
.eyebrow { color:var(--accent); font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:12px; letter-spacing:.08em; text-transform:uppercase; margin:0 0 var(--space-2); }
h1 { margin:0 0 var(--space-3); font-size:32px; }
h2 { margin:0 0 var(--space-3); font-size:21px; }
p,li { color:var(--muted); line-height:1.55; }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:var(--space-3); margin:var(--space-4) 0; }
article strong { display:block; color:var(--text); font-size:24px; margin-top:var(--space-2); }
table { border-collapse:collapse; width:100%; font-size:13px; }
th,td { border:1px solid var(--line); padding:var(--space-2); text-align:left; vertical-align:top; }
th { background:var(--surface); color:var(--text); }
code { color:var(--accent); overflow-wrap:anywhere; }
footer { color:var(--muted); margin-top:var(--space-5); font-size:13px; }
""".strip()


def _pack_list(packs: list[dict[str, Any]], empty: str) -> str:
    if not packs:
        return f"<li>{_html(empty)}</li>"
    return "".join(f"<li>{_html(pack['id'])}: {_html(pack['title'])} ({_html(pack['applicability'])})</li>" for pack in packs)


def _href_from(current_dir: str, relative_path: object) -> str:
    path = _safe_relative_path(relative_path, fallback="")
    if not path:
        return "#"
    prefix = f"{current_dir}/"
    if path.startswith(prefix):
        return _safe_href(path.removeprefix(prefix) or ".")
    return _safe_href(f"../{path}")


def _safe_href(value: object) -> str:
    text = str(value or "#").replace("\\", "/")
    decoded = unquote(text)
    if _has_url_scheme(decoded) or decoded.startswith(("//", "/")) or ".." in Path(decoded).parts:
        return "#"
    if any(_has_url_scheme(part) for part in Path(decoded).parts):
        return "#"
    if any(ord(character) < 32 for character in decoded):
        return "#"
    return _safe_text(text, limit=220)


def _manifest(input: AssessmentReportInput, destination: Path, relative_paths: tuple[str, ...]) -> dict[str, Any]:
    artifacts = []
    for relative_path in relative_paths:
        path = destination / relative_path
        artifacts.append(
            {
                "relative_path": relative_path,
                "path": relative_path,
                "sha256": _file_sha256(path),
                "artifact_schema_version": ARTIFACT_SCHEMA_VERSION,
                "redaction_status": "not_applicable" if relative_path == "regression/regression-pack.yaml" else "redacted",
            }
        )
    metadata = _safe_json_value(input.metadata)
    if not isinstance(metadata, dict):
        metadata = {}
    target_metadata = metadata.get("target_config", {}) if isinstance(metadata.get("target_config", {}), dict) else {}
    command_summary = metadata.get("command_summary", {}) if isinstance(metadata.get("command_summary", {}), dict) else {}
    schema_versions = {
        "risk_report": RISK_REPORT_SCHEMA_VERSION,
        "manifest": MANIFEST_SCHEMA_VERSION,
        "artifact": ARTIFACT_SCHEMA_VERSION,
        "coverage": "malleus.assessment_coverage.v1",
        "findings": "malleus.assessment_findings.v1",
        "issue_export": "malleus.assessment_issue_export.v1",
        "regression_pack": "malleus.assessment_regression_pack.v1",
        **(metadata.get("schema_versions", {}) if isinstance(metadata.get("schema_versions", {}), dict) else {}),
    }
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "redaction_status": _redaction_marker(),
        "assessment_id": _safe_text(input.assessment_id),
        "generated_at": _safe_text(input.generated_at),
        "inputs": {
            "target_config_path": _safe_relative_path(target_metadata.get("path", "unknown"), fallback="unknown"),
            "target_config_sha256": _safe_hash(target_metadata.get("sha256", "unknown")),
            "regression_pack": _safe_relative_path(metadata.get("optional_inputs", {}).get("regression_pack", "none"), fallback="none") if isinstance(metadata.get("optional_inputs", {}), dict) else "none",
            "policy_path": _safe_relative_path(metadata.get("optional_inputs", {}).get("policy_path", "none"), fallback="none") if isinstance(metadata.get("optional_inputs", {}), dict) else "none",
            "baseline_path": _safe_relative_path(metadata.get("optional_inputs", {}).get("baseline_path", "none"), fallback="none") if isinstance(metadata.get("optional_inputs", {}), dict) else "none",
        },
        "target_config_path": _safe_relative_path(target_metadata.get("path", "unknown"), fallback="unknown"),
        "target_config_sha256": _safe_hash(target_metadata.get("sha256", "unknown")),
        "profile": _safe_text(input.profile),
        "mode": _safe_text(input.mode),
        "requested_packs": [_safe_text(value) for value in _as_list(metadata.get("requested_packs"))],
        "selected_packs": [_safe_text(value) for value in _as_list(metadata.get("expanded_packs"))],
        "packs": [_safe_text(value) for value in _as_list(metadata.get("expanded_packs"))],
        "command_summary": command_summary,
        "options_summary": command_summary,
        "generated_artifacts": artifacts,
        "artifacts": artifacts,
        "schema_versions": schema_versions,
        "provider_calls_enabled": bool(metadata.get("provider_calls_enabled", False)),
        "provider_calls_requested": bool(metadata.get("provider_calls_requested", False)),
        "network_enabled": bool(metadata.get("network_enabled", False)),
        "browser_enabled": bool(metadata.get("browser_enabled", False)),
        "git_commit": _safe_text(metadata.get("git_commit", "unknown")),
        "caveats": [_safe_text(value) for value in _as_list(metadata.get("caveats"))],
        "raw_artifact_mapping": _safe_text(metadata.get("raw_artifact_mapping", "raw/<pack-id>/planning-metadata.json"), limit=420),
        "remediation_patch_mapping": _safe_text(metadata.get("remediation_patch_mapping", "remediation/patches/README.md"), limit=420),
    }


def _file_sha256(path: Path) -> str:
    if not path.exists():
        return hashlib.sha256(b"").hexdigest()
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _pack_section_lines(report: dict[str, Any], value: str, title: str, *, field_name: str = "score_use") -> list[str]:
    packs = [pack for pack in report["packs"] if pack[field_name] == value]
    if not packs:
        return [f"- {title}: none."]
    return [f"- {title}: {_md(pack['id'])} ({_md(pack['title'])})" for pack in packs]


def _safe_json_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            _safe_text(key): _safe_json_value(item)
            for key, item in value.items()
            if str(key) not in {"raw_prompt", "raw_response"}
        }
    if isinstance(value, list):
        return [_safe_json_value(item) for item in value]
    if isinstance(value, tuple):
        return [_safe_json_value(item) for item in value]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return _safe_text(value)


def _safe_text(value: object, *, limit: int = 240) -> str:
    text = redact_public_text(str(value), limit=limit).text
    for pattern, replacement in _UNSAFE_TEXT_PATTERNS:
        text = pattern.sub(replacement, text)
    text = text.replace("\r", " ").replace("\n", " ")
    if len(text) > limit:
        text = text[:limit] + "…"
    return text


def _preview(value: object) -> str:
    return _safe_text(redacted_preview(str(value), limit=260), limit=280)


def _safe_hash(value: object) -> str:
    text = str(value)
    if re.fullmatch(r"[0-9a-f]{64}", text):
        return text
    return sha256_text(text)


def _as_list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _md(value: object) -> str:
    text = _safe_text(value, limit=360)
    return text.replace("&", "&amp;").replace("<", "&lt;").replace("|", r"\|").replace("`", r"\`")


def _html(value: object) -> str:
    return escape(_safe_text(value, limit=420), quote=True)


def _yaml_scalar(value: object) -> str:
    text = _safe_text(value, limit=240).replace("'", "''")
    return f"'{text}'"


def _redaction_marker() -> str:
    return "[REDACTED report_marker sha256=e3b0c44298fc1c14 length=0]"
