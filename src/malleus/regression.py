from __future__ import annotations

import hashlib
import json
import shlex
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

from malleus.findings import SecurityFinding, load_or_collect_findings
from malleus.reporting import _md_safe


REGRESSION_PACK_SCHEMA_VERSION = "malleus.regression_pack.v1"
REGRESSION_VALIDATION_SCHEMA_VERSION = "malleus.regression_validation.v1"


class RegressionEvidenceRef(BaseModel):
    evidence_id: str
    artifact_path: str
    artifact_type: str
    json_pointer: str | None = None
    sha256: str | None = None
    redaction_status: str = "redacted"


class RegressionCase(BaseModel):
    id: str
    source_finding_id: str
    source_finding_sha256: str
    severity: str
    source_type: str
    surface: str
    technique: str
    expected_boundary: str
    affected_target: dict[str, str | None] = Field(default_factory=dict)
    replay_mode: Literal["provider_free_required"] = "provider_free_required"
    replay_command: str
    case_ids: list[str] = Field(default_factory=list)
    scenario_ids: list[str] = Field(default_factory=list)
    evidence_refs: list[RegressionEvidenceRef] = Field(default_factory=list)
    expected_fixed_behavior: str
    tags: list[str] = Field(default_factory=list)


class RegressionPack(BaseModel):
    schema_version: str = REGRESSION_PACK_SCHEMA_VERSION
    generated_at: str
    generated_from: str
    source_findings_sha256: str | None = None
    provider_calls_enabled: bool = False
    network_enabled: bool = False
    replay_mode: Literal["provider_free_required"] = "provider_free_required"
    cases: list[RegressionCase] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RegressionValidationReport(BaseModel):
    schema_version: str = REGRESSION_VALIDATION_SCHEMA_VERSION
    validated_at: str
    pack_path: str
    status: Literal["pass", "fail"]
    provider_calls_enabled: bool = False
    network_enabled: bool = False
    total_cases: int
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _sha256_file(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _finding_sha(finding: SecurityFinding) -> str:
    payload = json.dumps(finding.model_dump(mode="json", exclude={"metadata"}), sort_keys=True, separators=(",", ":"))
    return _sha256_text(payload)


def _safe_id(value: str) -> str:
    return "".join(char if char.isalnum() or char in {"-", "_"} else "-" for char in value)[:96]


def _case_from_finding(finding: SecurityFinding, *, report_ref: str) -> RegressionCase:
    candidate_command = finding.replay_spec.command or finding.reproduction_command
    command = candidate_command if "--dry-run" in shlex.split(candidate_command) else f"malleus replay {shlex.quote(finding.finding_id)} --report {shlex.quote(report_ref)} --dry-run"
    tags = sorted(
        {
            "regression",
            "provider_free",
            finding.source_type,
            finding.attack_surface,
            finding.technique,
            finding.severity,
        }
    )
    evidence_refs = [
        RegressionEvidenceRef(
            evidence_id=ref.evidence_id,
            artifact_path=ref.artifact_path,
            artifact_type=ref.artifact_type,
            json_pointer=ref.json_pointer,
            sha256=ref.sha256,
            redaction_status=ref.redaction_status,
        )
        for ref in finding.evidence_refs
    ]
    return RegressionCase(
        id=f"reg-{_safe_id(finding.finding_id)}",
        source_finding_id=finding.finding_id,
        source_finding_sha256=_finding_sha(finding),
        severity=finding.severity,
        source_type=finding.source_type,
        surface=finding.attack_surface,
        technique=finding.technique,
        expected_boundary=finding.violated_boundary,
        affected_target=dict(finding.affected_model),
        replay_command=command,
        case_ids=list(finding.replay_spec.case_ids),
        scenario_ids=list(finding.replay_spec.scenario_ids),
        evidence_refs=evidence_refs,
        expected_fixed_behavior=finding.patch_recommendation,
        tags=tags,
    )


def build_regression_pack(report: str | Path) -> RegressionPack:
    report_path = Path(report).resolve()
    bundle = load_or_collect_findings(report_path)
    source_path = report_path if report_path.is_file() else report_path / "findings.json"
    report_ref = str(report_path)
    cases = [_case_from_finding(finding, report_ref=report_ref) for finding in bundle.findings]
    return RegressionPack(
        generated_at=datetime.now(UTC).isoformat(),
        generated_from=str(report_path),
        source_findings_sha256=_sha256_file(source_path),
        cases=cases,
        metadata={
            "source_report": bundle.source_report,
            "run_id": bundle.run_id,
            "finding_count": len(bundle.findings),
            "source_summary": bundle.summary.model_dump(mode="json"),
            "provider_free_ci": True,
        },
    )


def render_replay_commands(pack: RegressionPack) -> str:
    lines = [
        "# Malleus Regression Replay Commands",
        "",
        "- Provider calls enabled: false",
        "- Network enabled: false",
        "- Replay mode: provider_free_required",
        "",
    ]
    if not pack.cases:
        lines.append("No regression cases were generated.")
        return "\n".join(lines).rstrip() + "\n"
    for case in pack.cases:
        lines.extend(
            [
                f"## {_md_safe(case.source_finding_id)}",
                "",
                f"- Severity: {_md_safe(case.severity)}",
                f"- Surface: {_md_safe(case.surface)}",
                f"- Technique: {_md_safe(case.technique)}",
                "",
                "```text",
                _md_safe(case.replay_command),
                "```",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def write_regression_pack(report: str | Path, out_dir: str | Path) -> tuple[RegressionPack, dict[str, Path]]:
    destination = Path(out_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    pack = build_regression_pack(report)
    pack_path = destination / "regression-pack.yaml"
    commands_path = destination / "replay-commands.md"
    manifest_path = destination / "regression-manifest.json"
    pack_path.write_text(yaml.safe_dump(pack.model_dump(mode="json"), sort_keys=False), encoding="utf-8")
    commands_path.write_text(render_replay_commands(pack), encoding="utf-8")
    manifest = {
        "schema_version": "malleus.regression_manifest.v1",
        "provider_calls_enabled": False,
        "network_enabled": False,
        "artifacts": {
            "regression-pack.yaml": {"sha256": _sha256_file(pack_path), "artifact_type": "regression_pack"},
            "replay-commands.md": {"sha256": _sha256_file(commands_path), "artifact_type": "replay_commands"},
        },
        "case_count": len(pack.cases),
        "source_findings_sha256": pack.source_findings_sha256,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return pack, {"pack": pack_path, "commands": commands_path, "manifest": manifest_path}


def load_regression_pack(path: str | Path) -> RegressionPack:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError("regression pack must be a YAML mapping")
    return RegressionPack.model_validate(data)


def validate_regression_pack(path: str | Path, *, source_findings: str | Path | None = None) -> RegressionValidationReport:
    pack_path = Path(path).resolve()
    errors: list[str] = []
    warnings: list[str] = []
    try:
        pack = load_regression_pack(pack_path)
    except Exception as exc:  # noqa: BLE001 - validation report must explain malformed local artifact.
        return RegressionValidationReport(
            validated_at=datetime.now(UTC).isoformat(),
            pack_path=str(pack_path),
            status="fail",
            total_cases=0,
            errors=[f"invalid_pack: {exc.__class__.__name__}"],
        )
    if pack.provider_calls_enabled:
        errors.append("provider_calls_enabled_must_be_false")
    if pack.network_enabled:
        errors.append("network_enabled_must_be_false")
    if pack.replay_mode != "provider_free_required":
        errors.append("replay_mode_must_be_provider_free_required")
    if not pack.cases:
        warnings.append("no_regression_cases")
    seen: set[str] = set()
    for case in pack.cases:
        if case.id in seen:
            errors.append(f"duplicate_case_id:{case.id}")
        seen.add(case.id)
        if case.replay_mode != "provider_free_required":
            errors.append(f"case_replay_mode_not_provider_free:{case.id}")
        argv = shlex.split(case.replay_command)
        if "--dry-run" not in argv:
            errors.append(f"replay_command_missing_dry_run:{case.id}")
        if "--no-dry-run" in argv or "--yes" in argv:
            errors.append(f"replay_command_allows_live_or_side_effects:{case.id}")
        if any(token in {"--allow-live-provider", "--live-provider"} for token in argv):
            errors.append(f"replay_command_allows_provider:{case.id}")
        if not case.evidence_refs:
            warnings.append(f"case_missing_evidence_refs:{case.id}")
    if source_findings is not None:
        expected = _sha256_file(Path(source_findings).resolve())
        if expected and pack.source_findings_sha256 and expected != pack.source_findings_sha256:
            errors.append("source_findings_hash_mismatch")
    return RegressionValidationReport(
        validated_at=datetime.now(UTC).isoformat(),
        pack_path=str(pack_path),
        status="fail" if errors else "pass",
        total_cases=len(pack.cases),
        errors=errors,
        warnings=warnings,
    )


def render_validation_markdown(report: RegressionValidationReport) -> str:
    lines = [
        "# Malleus Regression Pack Validation",
        "",
        f"- Status: {_md_safe(report.status)}",
        f"- Provider calls enabled: {str(report.provider_calls_enabled).lower()}",
        f"- Network enabled: {str(report.network_enabled).lower()}",
        f"- Cases: {report.total_cases}",
        "",
        "## Errors",
        "",
    ]
    lines.extend(f"- {_md_safe(error)}" for error in report.errors) if report.errors else lines.append("No errors.")
    lines.extend(["", "## Warnings", ""])
    lines.extend(f"- {_md_safe(warning)}" for warning in report.warnings) if report.warnings else lines.append("No warnings.")
    return "\n".join(lines).rstrip() + "\n"


def write_regression_validation(report: RegressionValidationReport, out_dir: str | Path) -> tuple[Path, Path]:
    destination = Path(out_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    json_path = destination / "regression-validation.json"
    markdown_path = destination / "regression-validation.md"
    json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    markdown_path.write_text(render_validation_markdown(report), encoding="utf-8")
    return json_path, markdown_path
