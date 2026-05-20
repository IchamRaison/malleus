from __future__ import annotations

import json
import hashlib
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from malleus.findings import FindingEvidenceRef, FindingsBundle, ReplaySpec, SecurityFinding, _safe_excerpt, _sha256_file, _stable_id, _summary, write_finding_artifacts
from malleus.interop.schemas import ImportSource, InteropImportReport

_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_SAFE_FIELD_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,80}$")
_UNSAFE_FIELD_RE = re.compile(r"ignore previous instructions|system prompt|developer message|api[_ -]?key|secret|token|password|credential|bearer|canary|=", re.IGNORECASE)
_SOURCE_KEYS: dict[str, set[str]] = {
    "promptfoo": {"version", "results", "prompts", "providers", "summary"},
    "garak": {"results", "runs", "probes", "plugins", "model", "summary"},
    "pyrit": {"attacks", "results", "conversations", "target", "summary"},
    "inspect": {"samples", "eval", "model", "results", "summary"},
}


def supported_import_sources() -> list[str]:
    return sorted(_SOURCE_KEYS)


def _read_json(path: str | Path) -> dict[str, Any]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {Path(path).name}: {exc.msg}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"interop import expects a JSON object: {Path(path).name}")
    return data


def _severity(value: Any, *, passed: bool | None = None) -> str:
    text = str(value or "").strip().lower()
    if text in _SEVERITIES:
        return text
    if passed is True:
        return "info"
    return "high"


def _safe_identifier(value: Any, *, fallback: str) -> str:
    text = _safe_excerpt(value or fallback, limit=96)
    if text.startswith("[REDACTED"):
        return f"{fallback}-{_stable_id(text)[3:11]}"
    return text or fallback


def _safe_metadata(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _safe_excerpt(value, limit=180)
    if isinstance(value, list):
        return [_safe_metadata(item) for item in value[:20]]
    if isinstance(value, dict):
        return {str(key): _safe_metadata(item) for key, item in sorted(value.items()) if str(key).lower() not in {"raw", "prompt", "response", "messages", "conversation"}}
    return _safe_excerpt(value, limit=180)


def _safe_field_label(value: Any) -> str:
    text = str(value)
    if _SAFE_FIELD_RE.fullmatch(text) and not _UNSAFE_FIELD_RE.search(text):
        return text
    digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]
    return f"field_sha256={digest} length={len(text)}"


def _unsupported(source: str, data: dict[str, Any], rows: list[dict[str, Any]]) -> list[str]:
    warnings: list[str] = []
    for key in sorted(set(data) - _SOURCE_KEYS[source]):
        warnings.append(f"unsupported top-level field for {source}: {_safe_field_label(key)}")
    for index, row in enumerate(rows):
        expected = {
            "id",
            "case_id",
            "test_id",
            "name",
            "prompt",
            "response",
            "output",
            "passed",
            "success",
            "severity",
            "risk",
            "score",
            "error",
            "metadata",
            "provider",
            "model",
            "probe",
            "detector",
            "objective",
            "description",
            "eval_id",
            "sample_id",
            "status",
            "attack_identifier",
            "conversation_id",
            "category",
        }
        for key in sorted(set(row) - expected):
            warnings.append(f"unsupported {source} result field at index {index}: {_safe_field_label(key)}")
    return warnings


def _rows(source: str, data: dict[str, Any]) -> list[dict[str, Any]]:
    key = {"promptfoo": "results", "garak": "results", "pyrit": "attacks", "inspect": "samples"}[source]
    value = data.get(key)
    if value is None and source in {"garak", "pyrit"}:
        value = data.get("runs") if source == "garak" else data.get("results")
    if not isinstance(value, list):
        raise ValueError(f"invalid {source} schema: expected list field '{key}'")
    rows = [item for item in value if isinstance(item, dict)]
    if len(rows) != len(value):
        raise ValueError(f"invalid {source} schema: every '{key}' item must be an object")
    return rows


def _failed(source: str, row: dict[str, Any]) -> bool:
    if source == "promptfoo":
        if "success" in row:
            return not bool(row.get("success"))
        if "passed" in row:
            return not bool(row.get("passed"))
    if source == "garak":
        return bool(row.get("detector") or row.get("failure") or row.get("vulnerable") or row.get("severity"))
    if source == "pyrit":
        return str(row.get("status") or row.get("outcome") or "").lower() in {"failed", "success", "vulnerable", "unsafe"} or bool(row.get("severity"))
    if source == "inspect":
        return str(row.get("status") or row.get("score") or "").lower() in {"fail", "failed", "0", "false"} or row.get("passed") is False
    return True


def _row_identity(source: str, row: dict[str, Any], index: int) -> str:
    return _safe_identifier(row.get("id") or row.get("case_id") or row.get("test_id") or row.get("sample_id") or row.get("attack_identifier") or row.get("name") or f"{source}-{index + 1}", fallback=f"{source}-{index + 1}")


def _finding(source: str, row: dict[str, Any], index: int, artifact: Path) -> SecurityFinding:
    passed = None
    if "passed" in row:
        passed = bool(row.get("passed"))
    if "success" in row:
        passed = bool(row.get("success"))
    severity = _severity(row.get("severity") or row.get("risk"), passed=passed)
    case_id = _row_identity(source, row, index)
    technique = _safe_identifier(row.get("probe") or row.get("detector") or row.get("category") or row.get("objective") or source, fallback=source)
    surface = _safe_identifier(row.get("provider") or row.get("attack_surface") or source, fallback=source)
    boundary = _safe_identifier(row.get("violated_boundary") or row.get("category") or "external_eval_boundary", fallback="external_eval_boundary")
    finding_id = _stable_id(source, case_id, severity, technique, surface, boundary)
    excerpt_source = row.get("error") or row.get("description") or row.get("output") or row.get("response") or row.get("prompt") or case_id
    command = f"malleus import {source} {artifact.name} --out-dir interop-import"
    metadata = {
        "interop_source": source,
        "external_case_id": case_id,
        "external_status": _safe_metadata(row.get("status") or row.get("passed") or row.get("success")),
        "external_score": _safe_metadata(row.get("score")),
        "external_metadata": _safe_metadata(row.get("metadata") if isinstance(row.get("metadata"), dict) else {}),
    }
    return SecurityFinding(
        finding_id=finding_id,
        title=f"{severity.title()} {source} imported finding: {case_id}",
        source_type="interop",
        affected_model={"name": _safe_excerpt(row.get("provider") or source, limit=80), "adapter": source, "model": _safe_excerpt(row.get("model") or "external", limit=80), "config": source},
        severity=severity,  # type: ignore[arg-type]
        attack_surface=surface,
        technique=technique,
        violated_boundary=boundary,
        taxonomy_refs=["interop", source, technique],
        reproduction_command=command,
        evidence_refs=[
            FindingEvidenceRef(
                evidence_id=f"{finding_id}-external-result",
                artifact_path=artifact.name,
                artifact_type=f"{source}_result_json",
                json_pointer=f"/{'samples' if source == 'inspect' else 'attacks' if source == 'pyrit' else 'results'}/{index}",
                sha256=_sha256_file(artifact),
                redacted_excerpt=_safe_excerpt(excerpt_source),
            )
        ],
        redacted_excerpts=[_safe_excerpt(row.get("prompt") or "n/a"), _safe_excerpt(row.get("response") or row.get("output") or "n/a"), _safe_excerpt(excerpt_source)],
        patch_recommendation="Review the external finding, add an equivalent Malleus regression case, and harden the affected boundary before release.",
        regression_case_link=f"{source}:{case_id}",
        replay_spec=ReplaySpec(replay_id=f"replay-{finding_id}", finding_id=finding_id, command=command, target_name=source, target_adapter=source, target_model=_safe_excerpt(row.get("model") or "external", limit=80), case_ids=[f"{source}:{case_id}"]),
        metadata=metadata,
    )


def import_external_results(source: ImportSource | str, path: str | Path, out_dir: str | Path) -> InteropImportReport:
    source_name = str(source).lower()
    if source_name not in _SOURCE_KEYS:
        raise ValueError(f"unsupported import source: {source}. supported: {', '.join(supported_import_sources())}")
    artifact = Path(path).resolve()
    data = _read_json(artifact)
    rows = _rows(source_name, data)
    unsupported = _unsupported(source_name, data, rows)
    findings = [_finding(source_name, row, index, artifact) for index, row in enumerate(rows) if _failed(source_name, row)]
    bundle = FindingsBundle(
        generated_at=datetime.now(UTC).isoformat(),
        source_report=str(artifact),
        run_id=None,
        findings=sorted(findings, key=lambda item: item.finding_id),
        summary=_summary(findings),
        optional_artifacts={},
        interop={"schema": "malleus.interop.v1", "source": source_name, "unsupported_field_warnings": unsupported, "sanitized": True},
    )
    destination = Path(out_dir).resolve()
    json_path, markdown_path = write_finding_artifacts(bundle, destination)
    report = InteropImportReport(
        source=source_name,  # type: ignore[arg-type]
        source_path=str(artifact),
        warnings=["lossy import: unsupported external fields were omitted; see unsupported_field_warnings"] if unsupported else [],
        unsupported_field_warnings=unsupported,
        output_artifacts={"findings_json": str(json_path), "findings_markdown": str(markdown_path), "interop_report": str(destination / "interop-report.json")},
        normalized_finding_count=len(findings),
        gate={"status": "warn" if unsupported else "pass", "reasons": unsupported[:10]},
    )
    try:
        bundle.model_validate(bundle.model_dump())
    except ValidationError as exc:
        raise ValueError(f"normalized findings failed validation: {exc}") from exc
    (destination / "interop-report.json").write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return report
