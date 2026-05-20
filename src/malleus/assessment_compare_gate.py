from __future__ import annotations

import json
import re
from dataclasses import dataclass
from html import escape
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

import yaml

from malleus.datasets import load_target_config
from malleus.regression import validate_regression_pack
from malleus.utils.redact import redact_public_text


ASSESSMENT_GATE_SCHEMA_VERSION = "malleus.assessment_gate.v1"
MODEL_COMPARISON_SCHEMA_VERSION = "malleus.assessment_model_comparison.v1"
PROVIDER_CALLS_ENABLED = False
NETWORK_ENABLED = False
GatePosture = Literal["PASS", "WARN", "FAIL", "ERROR"]

_UNSAFE_TEXT_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"<\s*script\b[^>]*>.*?<\s*/\s*script\s*>", re.IGNORECASE), "[REDACTED]"),
    (re.compile(r"<\s*/?\s*script\b[^>]*>", re.IGNORECASE), "[REDACTED]"),
    (re.compile(r"javascript\s*:", re.IGNORECASE), "[REDACTED]"),
    (re.compile(r"\bBearer\s+[^\s`|<>]+", re.IGNORECASE), "[REDACTED]"),
    (re.compile(r"https?://[^\s`|<>\])]+", re.IGNORECASE), "[REDACTED]"),
    (re.compile(r"\braw_(?:prompt|response)\b", re.IGNORECASE), "[REDACTED]"),
)


@dataclass(frozen=True)
class AssessmentGateResult:
    status: GatePosture
    ci_exit_code: int
    summary_path: Path
    json_path: Path
    markdown_path: Path
    sarif_path: Path
    junit_path: Path


@dataclass(frozen=True)
class ModelComparisonResult:
    json_path: Path
    summary_path: Path
    leaderboard_path: Path
    strengths_path: Path
    shared_failures_path: Path
    risks_path: Path


def write_model_comparison_artifacts(
    *,
    out_dir: Path,
    risk_report: dict[str, Any],
    target_path: Path,
    compare_targets: list[Path],
) -> ModelComparisonResult | None:
    if not compare_targets:
        return None

    destination = out_dir / "model-comparison"
    destination.mkdir(parents=True, exist_ok=True)
    targets = [target_path, *compare_targets]
    primary_score = _primary_score(risk_report)
    findings = _finding_summary(risk_report)
    entries = []
    for rank, path in enumerate(targets, start=1):
        target = load_target_config(path)
        pass_rate = primary_score["pass_rate"]
        entries.append(
            {
                "rank": rank,
                "target_role": "primary" if rank == 1 else "compare",
                "name": _safe_text(target.name),
                "adapter": _safe_text(target.adapter),
                "model": _safe_text(target.model),
                "base_url_host": _base_url_host(target.base_url),
                "config_hash": _target_config_hash(target),
                "provider_calls_enabled": PROVIDER_CALLS_ENABLED,
                "network_enabled": NETWORK_ENABLED,
                "score": primary_score,
                "gap_to_best": 0 if pass_rate is not None else None,
                "finding_summary": findings,
                "assessment_output": "provider_free_composed_from_current_risk_report",
            }
        )

    comparison = {
        "schema_version": MODEL_COMPARISON_SCHEMA_VERSION,
        "assessment_id": _safe_text(risk_report.get("assessment_id", "unknown")),
        "profile": _safe_text(risk_report.get("profile", "unknown")),
        "mode": _safe_text(risk_report.get("mode", "unknown")),
        "provider_calls_enabled": PROVIDER_CALLS_ENABLED,
        "network_enabled": NETWORK_ENABLED,
        "note": "Comparison is provider-free and reuses normalized assessment outputs; no adapters are instantiated.",
        "models": entries,
        "shared_failures": _shared_failures(risk_report),
        "model_specific_risks": _model_specific_risks(entries),
    }
    json_path = _write_json(destination / "comparison.json", comparison)
    summary_path = _write_text(destination / "comparison-summary.md", _comparison_summary_markdown(comparison))
    leaderboard_path = _write_text(destination / "leaderboard.html", _leaderboard_html(comparison))
    strengths_path = _write_text(destination / "per-model-strengths-weaknesses.md", _strengths_weaknesses_markdown(comparison))
    shared_failures_path = _write_text(destination / "shared-failures.md", _shared_failures_markdown(comparison))
    risks_path = _write_text(destination / "model-specific-risks.md", _model_specific_risks_markdown(comparison))
    return ModelComparisonResult(json_path, summary_path, leaderboard_path, strengths_path, shared_failures_path, risks_path)


def write_assessment_gate_artifacts(
    *,
    out_dir: Path,
    risk_report: dict[str, Any],
    policy_path: Path | None,
    baseline_path: Path | None,
) -> AssessmentGateResult:
    destination = out_dir / "gate"
    destination.mkdir(parents=True, exist_ok=True)
    decision = _evaluate_assessment_gate(risk_report=risk_report, policy_path=policy_path, baseline_path=baseline_path)
    json_path = _write_json(destination / "gate-summary.json", decision)
    markdown_path = _write_text(destination / "gate-summary.md", _gate_markdown(decision))
    sarif_path = _write_json(destination / "gate-results.sarif", _gate_sarif(decision))
    junit_path = _write_text(destination / "gate-results.junit.xml", _gate_junit(decision))
    return AssessmentGateResult(
        status=decision["status"],
        ci_exit_code=int(decision["ci_exit_code"]),
        summary_path=json_path,
        json_path=json_path,
        markdown_path=markdown_path,
        sarif_path=sarif_path,
        junit_path=junit_path,
    )


def _evaluate_assessment_gate(*, risk_report: dict[str, Any], policy_path: Path | None, baseline_path: Path | None) -> dict[str, Any]:
    policy, policy_errors = _load_policy(policy_path)
    baseline, baseline_errors = _load_baseline(baseline_path, risk_report)
    regression, regression_errors, regression_warnings = _load_regression_status(risk_report)
    findings = [finding for finding in risk_report.get("findings", []) if isinstance(finding, dict)]
    coverage_gaps = [finding for finding in findings if str(finding.get("category")) == "coverage_gap"]
    blocking_findings = [finding for finding in findings if str(finding.get("severity")) in set(policy["blocking_severities"])]
    warning_findings = [finding for finding in findings if finding not in blocking_findings]
    reasons: list[str] = []
    warnings: list[str] = []
    status: GatePosture = "PASS"

    if policy_errors:
        status = "ERROR"
        reasons.extend(policy_errors)
    if baseline_errors:
        status = "ERROR"
        reasons.extend(baseline_errors)
    if regression_errors:
        status = "ERROR"
        reasons.extend(regression_errors)

    if status != "ERROR":
        if len(blocking_findings) > int(policy["max_blocking_findings"]):
            status = "FAIL"
            reasons.append("blocking_findings_exceeded")
        if len(findings) > int(policy["max_total_findings"]):
            status = "FAIL"
            reasons.append("total_findings_exceeded")
        if coverage_gaps and bool(policy["warn_on_coverage_gaps"]):
            if status == "PASS":
                status = "WARN"
            warnings.append("coverage_gaps_present")
        if regression_warnings:
            if status == "PASS":
                status = "WARN"
            warnings.extend(regression_warnings)
        if warning_findings and status == "PASS":
            status = "WARN"
            warnings.append("non_blocking_findings_present")
        if not reasons and not warnings:
            reasons.append("policy_passed")

    return {
        "schema_version": ASSESSMENT_GATE_SCHEMA_VERSION,
        "assessment_id": _safe_text(risk_report.get("assessment_id", "unknown")),
        "status": status,
        "ci_exit_code": 0 if status in {"PASS", "WARN"} else 1,
        "reasons": [_safe_text(reason) for reason in reasons],
        "warnings": [_safe_text(warning) for warning in warnings],
        "blocking_findings": [_gate_finding(finding) for finding in blocking_findings],
        "warning_findings": [_gate_finding(finding) for finding in warning_findings],
        "summary": {
            "total_findings": len(findings),
            "blocking_findings": len(blocking_findings),
            "warnings": len(warning_findings) + len(warnings),
            "coverage_gaps": len(coverage_gaps),
            "baseline_configured": baseline_path is not None,
            "baseline_status": baseline.get("status", "not_configured") if isinstance(baseline, dict) else "not_configured",
            "regression_pack_configured": regression.get("configured", False),
            "regression_pack_status": regression.get("status", "not_configured"),
            "regression_cases": regression.get("total_cases", 0),
        },
        "policy": {
            "configured": policy_path is not None,
            "name": _safe_text(policy.get("name", "default")),
            "thresholds": {
                "max_blocking_findings": policy["max_blocking_findings"],
                "max_total_findings": policy["max_total_findings"],
                "warn_on_coverage_gaps": policy["warn_on_coverage_gaps"],
                "blocking_severities": policy["blocking_severities"],
            },
        },
    }


def _load_regression_status(risk_report: dict[str, Any]) -> tuple[dict[str, Any], list[str], list[str]]:
    metadata = risk_report.get("metadata") if isinstance(risk_report.get("metadata"), dict) else {}
    optional = metadata.get("optional_inputs") if isinstance(metadata.get("optional_inputs"), dict) else {}
    raw_path = optional.get("regression_pack")
    findings = [finding for finding in risk_report.get("findings", []) if isinstance(finding, dict)]
    if not raw_path:
        return {"configured": False, "status": "not_configured", "total_cases": 0}, [], (["regression_pack_missing_for_findings"] if findings else [])
    try:
        report = validate_regression_pack(Path(str(raw_path)))
    except Exception as exc:  # noqa: BLE001 - configured CI artifact must fail closed.
        return {"configured": True, "status": "invalid", "total_cases": 0}, [f"invalid_regression_pack: {exc.__class__.__name__}"], []
    if report.status != "pass":
        return {"configured": True, "status": report.status, "total_cases": report.total_cases}, [f"regression_pack_invalid: {','.join(report.errors) or 'unknown'}"], report.warnings
    return {"configured": True, "status": "pass", "total_cases": report.total_cases}, [], report.warnings


def _load_policy(path: Path | None) -> tuple[dict[str, Any], list[str]]:
    policy = {
        "name": "default",
        "max_blocking_findings": 0,
        "max_total_findings": 999999,
        "warn_on_coverage_gaps": True,
        "blocking_severities": ["critical", "high"],
    }
    if path is None:
        return policy, []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - invalid local policy must fail closed with reason.
        return policy, [f"invalid_policy: {exc.__class__.__name__}"]
    if not isinstance(data, dict):
        return policy, ["invalid_policy: policy must be a mapping"]
    merged = {**policy, **data}
    errors = []
    for key in ("max_blocking_findings", "max_total_findings"):
        if not isinstance(merged.get(key), int) or int(merged[key]) < 0:
            errors.append(f"invalid_policy: {key} must be a non-negative integer")
    if not isinstance(merged.get("warn_on_coverage_gaps"), bool):
        errors.append("invalid_policy: warn_on_coverage_gaps must be boolean")
    severities = merged.get("blocking_severities")
    if not isinstance(severities, list) or not all(str(item) in {"critical", "high", "medium", "low", "info"} for item in severities):
        errors.append("invalid_policy: blocking_severities must be a list of known severities")
    return merged, errors


def _load_baseline(path: Path | None, risk_report: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    if path is None:
        return {"status": "not_configured"}, []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - stale/malformed baseline must fail closed with reason.
        return {"status": "invalid"}, [f"invalid_baseline: {exc.__class__.__name__}"]
    if not isinstance(data, dict):
        return {"status": "invalid"}, ["invalid_baseline: baseline must be a JSON object"]
    schema_version = data.get("schema_version")
    if schema_version not in {"malleus.assessment_gate_baseline.v1", "malleus.assessment_risk_report.v1"}:
        return {"status": "incompatible"}, ["stale_or_incompatible_baseline"]
    baseline_profile = data.get("profile")
    if baseline_profile is not None and baseline_profile != risk_report.get("profile"):
        return {"status": "incompatible"}, ["baseline_profile_mismatch"]
    return {"status": "compatible"}, []


def _primary_score(risk_report: dict[str, Any]) -> dict[str, Any]:
    scores = risk_report.get("scores") if isinstance(risk_report.get("scores"), dict) else {}
    primary = scores.get("primary_score") or scores.get("primary") or {}
    if not isinstance(primary, dict):
        primary = {}
    earned = int(primary.get("earned") or 0)
    possible = int(primary.get("possible") or 0)
    pass_rate = primary.get("pass_rate")
    if pass_rate is None and possible:
        pass_rate = earned / possible
    return {"earned": earned, "possible": possible, "pass_rate": pass_rate}


def _finding_summary(risk_report: dict[str, Any]) -> dict[str, int]:
    findings = [finding for finding in risk_report.get("findings", []) if isinstance(finding, dict)]
    return {
        "total": len(findings),
        "coverage_gaps": sum(1 for finding in findings if finding.get("category") == "coverage_gap"),
        "critical": sum(1 for finding in findings if finding.get("severity") == "critical"),
        "high": sum(1 for finding in findings if finding.get("severity") == "high"),
    }


def _shared_failures(risk_report: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {
            "finding_id": _safe_text(finding.get("finding_id", "unknown")),
            "pack_id": _safe_text(finding.get("pack_id", "unknown")),
            "category": _safe_text(finding.get("category", "unknown")),
            "summary": _safe_text(finding.get("summary", ""), limit=320),
        }
        for finding in risk_report.get("findings", [])
        if isinstance(finding, dict)
    ]


def _model_specific_risks(entries: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [
        {
            "model": entry["model"],
            "risk": "No model-specific provider behavior was collected; compare entry uses provider-free assessment composition.",
            "target_role": entry["target_role"],
        }
        for entry in entries
    ]


def _gate_finding(finding: dict[str, Any]) -> dict[str, str]:
    return {
        "finding_id": _safe_text(finding.get("finding_id", "unknown")),
        "severity": _safe_text(finding.get("severity", "unknown")),
        "category": _safe_text(finding.get("category", "unknown")),
        "pack_id": _safe_text(finding.get("pack_id", "unknown")),
        "summary": _safe_text(finding.get("summary", ""), limit=320),
    }


def _comparison_summary_markdown(comparison: dict[str, Any]) -> str:
    lines = ["# Model Comparison Summary", "", "Provider calls enabled: false", "Network enabled: false", "", "| Rank | Role | Model | Target | Score | Gap | Findings |", "|---:|---|---|---|---:|---:|---:|"]
    for entry in comparison["models"]:
        score = entry["score"]
        score_text = f"{score['earned']}/{score['possible']}" if score["possible"] else "0/0"
        gap = "n/a" if entry["gap_to_best"] is None else str(entry["gap_to_best"])
        lines.append(f"| {entry['rank']} | {_md(entry['target_role'])} | {_md(entry['model'])} | {_md(entry['name'])} | {_md(score_text)} | {_md(gap)} | {entry['finding_summary']['total']} |")
    return "\n".join(lines).rstrip() + "\n"


def _strengths_weaknesses_markdown(comparison: dict[str, Any]) -> str:
    lines = ["# Per-model Strengths and Weaknesses", ""]
    for entry in comparison["models"]:
        lines.extend([
            f"## {_md(entry['model'])}",
            "",
            "- Strength: provider-free assessment artifacts were composed without adapter instantiation.",
            f"- Weakness: {_md(str(entry['finding_summary']['coverage_gaps']))} coverage gaps are shared in the current risk report.",
            "- Caveat: no provider behavior was collected for this comparison entry.",
            "",
        ])
    return "\n".join(lines).rstrip() + "\n"


def _shared_failures_markdown(comparison: dict[str, Any]) -> str:
    lines = ["# Shared Failures", ""]
    failures = comparison["shared_failures"]
    if not failures:
        lines.append("No shared findings recorded in the current provider-free risk report.")
    for failure in failures:
        lines.append(f"- {_md(failure['finding_id'])} ({_md(failure['pack_id'])}): {_md(failure['summary'])}")
    return "\n".join(lines).rstrip() + "\n"


def _model_specific_risks_markdown(comparison: dict[str, Any]) -> str:
    lines = ["# Model-specific Risks", ""]
    for risk in comparison["model_specific_risks"]:
        lines.append(f"- {_md(risk['model'])}: {_md(risk['risk'])}")
    return "\n".join(lines).rstrip() + "\n"


def _leaderboard_html(comparison: dict[str, Any]) -> str:
    rows = "".join(
        "<tr>"
        f"<td>{entry['rank']}</td>"
        f"<td>{_html(entry['target_role'])}</td>"
        f"<td>{_html(entry['model'])}</td>"
        f"<td>{_html(entry['name'])}</td>"
        f"<td>{_html(str(entry['score']['earned']))}/{_html(str(entry['score']['possible']))}</td>"
        f"<td>{_html(str(entry['finding_summary']['total']))}</td>"
        "</tr>"
        for entry in comparison["models"]
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Malleus Assessment Model Comparison</title>
<style>
body {{ font-family: ui-sans-serif, system-ui, sans-serif; margin: 2rem; background: #0f172a; color: #e5e7eb; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #334155; padding: .55rem; text-align: left; }}
th {{ background: #1e293b; }}
</style>
</head>
<body>
<h1>Malleus Assessment Model Comparison</h1>
<p>Provider calls enabled: false. Network enabled: false. Static provider-free leaderboard.</p>
<table><thead><tr><th>Rank</th><th>Role</th><th>Model</th><th>Target</th><th>Score</th><th>Findings</th></tr></thead><tbody>{rows}</tbody></table>
</body>
</html>
"""


def _gate_markdown(decision: dict[str, Any]) -> str:
    lines = [
        "# Assessment Gate Summary",
        "",
        f"- Status: {_md(decision['status'])}",
        f"- CI exit code: {decision['ci_exit_code']}",
        f"- Assessment: {_md(decision['assessment_id'])}",
        "",
        "## Reasons",
    ]
    lines.extend([f"- {_md(reason)}" for reason in decision["reasons"]] or ["- none"])
    lines.extend(["", "## Warnings"])
    lines.extend([f"- {_md(warning)}" for warning in decision["warnings"]] or ["- none"])
    return "\n".join(lines).rstrip() + "\n"


def _gate_sarif(decision: dict[str, Any]) -> dict[str, Any]:
    results = [
        {
            "ruleId": finding["category"],
            "level": "error" if finding in decision["blocking_findings"] else "warning",
            "message": {"text": finding["summary"]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "risk-report.json"}}}],
        }
        for finding in [*decision["blocking_findings"], *decision["warning_findings"]]
    ]
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "malleus-assessment-gate"}}, "results": results}]}


def _gate_junit(decision: dict[str, Any]) -> str:
    failures = 1 if decision["status"] in {"FAIL", "ERROR"} else 0
    body = ""
    if failures:
        message = _xml("; ".join(decision["reasons"]) or decision["status"])
        body = f'<failure message="{message}">{message}</failure>'
    return f'<?xml version="1.0" encoding="utf-8"?>\n<testsuite name="malleus-assessment-gate" tests="1" failures="{failures}" errors="0"><testcase name="assessment_gate">{body}</testcase></testsuite>\n'


def _base_url_host(base_url: str) -> str:
    host = urlparse(base_url).netloc or urlparse(f"//{base_url}").netloc
    return _safe_text(host or "unknown")


def _target_config_hash(target: Any) -> str:
    payload = json.dumps(
        {
            "name": target.name,
            "adapter": target.adapter,
            "model": target.model,
            "base_url": target.base_url,
        },
        indent=2,
        sort_keys=True,
    ).encode("utf-8") + b"\n"
    return _sha256_bytes(payload)


def _sha256_bytes(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def _safe_text(value: object, *, limit: int = 240) -> str:
    text = redact_public_text(str(value), limit=limit).text
    for pattern, replacement in _UNSAFE_TEXT_PATTERNS:
        text = pattern.sub(replacement, text)
    text = text.replace("\r", " ").replace("\n", " ")
    if len(text) > limit:
        text = text[:limit] + "…"
    return text


def _md(value: object) -> str:
    return _safe_text(value, limit=360).replace("&", "&amp;").replace("<", "&lt;").replace("|", r"\|").replace("`", r"\`")


def _html(value: object) -> str:
    return escape(_safe_text(value, limit=420), quote=True)


def _xml(value: object) -> str:
    return escape(_safe_text(value, limit=420), quote=True)


def _write_json(path: Path, payload: dict[str, Any]) -> Path:
    return _write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _write_text(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


__all__ = [
    "ASSESSMENT_GATE_SCHEMA_VERSION",
    "MODEL_COMPARISON_SCHEMA_VERSION",
    "AssessmentGateResult",
    "ModelComparisonResult",
    "write_assessment_gate_artifacts",
    "write_model_comparison_artifacts",
]
