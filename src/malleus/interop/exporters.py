from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from malleus.findings import FindingsBundle, SecurityFinding, _safe_excerpt, load_or_collect_findings
from malleus.interop.schemas import ExportFormat, InteropExportReport

_FORMATS = {"sarif", "junit", "promptfoo", "inspect", "github"}
_SARIF_LEVEL = {"info": "note", "low": "note", "medium": "warning", "high": "error", "critical": "error"}


def supported_export_formats() -> list[str]:
    return sorted(_FORMATS)


def _message(finding: SecurityFinding) -> str:
    return _safe_excerpt(f"{finding.title}; {finding.patch_recommendation}", limit=240)


def _location(finding: SecurityFinding) -> tuple[str, int]:
    evidence = finding.evidence_refs[0] if finding.evidence_refs else None
    return (evidence.artifact_path if evidence else "findings.json", 1)


def _sarif(bundle: FindingsBundle) -> dict[str, Any]:
    rules = []
    results = []
    seen = set()
    for finding in bundle.findings:
        if finding.technique not in seen:
            seen.add(finding.technique)
            rules.append({"id": finding.technique, "name": finding.technique, "shortDescription": {"text": _safe_excerpt(finding.violated_boundary, limit=120)}})
        path, line = _location(finding)
        results.append(
            {
                "ruleId": finding.technique,
                "level": _SARIF_LEVEL[finding.severity],
                "message": {"text": _message(finding)},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": path}, "region": {"startLine": line}}}],
                "partialFingerprints": {"malleusFindingId": finding.finding_id},
            }
        )
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "Malleus", "rules": rules}}, "results": results}]}


def _junit(bundle: FindingsBundle) -> str:
    suite = ET.Element("testsuite", {"name": "malleus-findings", "tests": str(len(bundle.findings)), "failures": str(sum(1 for item in bundle.findings if item.severity in {"high", "critical"}))})
    for finding in bundle.findings:
        case = ET.SubElement(suite, "testcase", {"classname": finding.source_type, "name": finding.finding_id})
        if finding.severity in {"high", "critical"}:
            failure = ET.SubElement(case, "failure", {"type": finding.severity, "message": _safe_excerpt(finding.title, limit=180)})
            failure.text = _message(finding)
        else:
            case.set("severity", finding.severity)
    return ET.tostring(suite, encoding="unicode")


def _promptfoo(bundle: FindingsBundle) -> dict[str, Any]:
    return {
        "version": "malleus.interop.promptfoo.v1",
        "results": [
            {
                "success": finding.severity in {"info", "low"},
                "score": 0 if finding.severity in {"high", "critical"} else 1,
                "namedScores": {"malleus_severity": finding.severity},
                "metadata": {"finding_id": finding.finding_id, "source_type": finding.source_type, "technique": finding.technique},
                "error": _message(finding),
            }
            for finding in bundle.findings
        ],
        "summary": {"total": bundle.summary.total_findings, "bySeverity": bundle.summary.counts_by_severity},
    }


def _inspect(bundle: FindingsBundle) -> dict[str, Any]:
    return {
        "version": "malleus.interop.inspect.v1",
        "eval": {"name": "malleus-findings", "status": "fail" if any(item.severity in {"high", "critical"} for item in bundle.findings) else "pass"},
        "samples": [
            {
                "id": finding.finding_id,
                "score": 0 if finding.severity in {"high", "critical"} else 1,
                "target": finding.affected_model,
                "metadata": {"severity": finding.severity, "attack_surface": finding.attack_surface, "technique": finding.technique, "message": _message(finding)},
            }
            for finding in bundle.findings
        ],
        "summary": bundle.summary.model_dump(),
    }


def _github(bundle: FindingsBundle) -> list[dict[str, Any]]:
    annotations = []
    for finding in bundle.findings:
        path, line = _location(finding)
        annotations.append(
            {
                "path": path or "findings.json",
                "start_line": line,
                "end_line": line,
                "annotation_level": "failure" if finding.severity in {"high", "critical"} else "warning",
                "title": _safe_excerpt(finding.title, limit=120),
                "message": _message(finding),
                "raw_details": f"finding_id={finding.finding_id} severity={finding.severity}",
            }
        )
    return annotations


def export_findings(format_name: ExportFormat | str, findings_path: str | Path, out: str | Path) -> InteropExportReport:
    fmt = str(format_name).lower()
    if fmt not in _FORMATS:
        raise ValueError(f"unsupported export format: {format_name}. supported: {', '.join(supported_export_formats())}")
    bundle = load_or_collect_findings(findings_path)
    destination = Path(out).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    warnings = ["lossy export: Malleus replay specs/evidence metadata are summarized for external consumer compatibility"]
    unsupported = ["replay_spec", "full evidence_refs", "adjudication state"]
    if fmt == "sarif":
        destination.write_text(json.dumps(_sarif(bundle), indent=2), encoding="utf-8")
    elif fmt == "junit":
        destination.write_text(_junit(bundle), encoding="utf-8")
    elif fmt == "promptfoo":
        destination.write_text(json.dumps(_promptfoo(bundle), indent=2), encoding="utf-8")
    elif fmt == "inspect":
        destination.write_text(json.dumps(_inspect(bundle), indent=2), encoding="utf-8")
    else:
        annotations = _github(bundle)
        if destination.suffix == ".jsonl":
            destination.write_text("\n".join(json.dumps(item, sort_keys=True) for item in annotations) + ("\n" if annotations else ""), encoding="utf-8")
        else:
            destination.write_text(json.dumps(annotations, indent=2), encoding="utf-8")
    return InteropExportReport(format=fmt, findings_path=str(Path(findings_path).resolve()), output_artifact=str(destination), warnings=warnings, unsupported_field_warnings=unsupported, exported_finding_count=len(bundle.findings))  # type: ignore[arg-type]
