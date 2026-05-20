from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, Field

from malleus.reporting import _md_safe
from malleus.schemas import CoverageCell, EvaluationSurface, EvidenceRef, EvidenceRecord, RedactionMetadata, Severity, WowppReportMetadata
from malleus.utils.ids import new_run_id
from malleus.utils.redact import redact_public_text, redacted_preview, sha256_text

PLUGIN_RISK_SCHEMA_VERSION = "malleus.plugin_risk_report.v1"
PLUGIN_FINDINGS_SCHEMA_VERSION = "malleus.plugin_risk_findings.v1"
_MAX_PREVIEW = 180
_HTTP_METHODS = {"get", "put", "post", "delete", "patch", "options", "head", "trace"}
_SEVERITY_ORDER: dict[str, int] = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_DANGEROUS_WORDS = {
    "write",
    "delete",
    "destroy",
    "remove",
    "drop",
    "truncate",
    "purge",
    "push",
    "commit",
    "merge",
    "deploy",
    "publish",
    "release",
    "send",
    "email",
    "refund",
    "charge",
    "transfer",
    "execute",
    "run",
}
_EXCESSIVE_PERMISSIONS = {
    "*",
    "admin",
    "root",
    "owner",
    "sudo",
    "write:*",
    "repo",
    "repo:write",
    "delete:*",
    "deploy:*",
    "network:*",
    "all",
    "full_access",
}
_AMBIGUOUS_TOOL_NAMES = {"run", "exec", "execute", "action", "tool", "do", "send", "write", "delete", "update", "manage", "admin", "deploy"}
_SECRET_RE = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b|\b(?:api[_ -]?key|secret|token|password|credential|bearer)\s*[:=]\s*[^\s`|<>]+", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s\]})>'\"]+", re.IGNORECASE)
_WORD_RE = re.compile(r"[A-Za-z0-9_]+")


class PluginEvidence(BaseModel):
    evidence_id: str
    source_path: str
    json_pointer: str
    route_name: str | None = None
    route_hash: str | None = None
    route_length: int | None = None
    sha256: str
    length: int
    redacted_preview: str


class PluginFinding(BaseModel):
    finding_id: str
    code: str
    severity: Severity
    title: str
    description: str
    recommendation: str
    approval_gate: str
    coverage_tags: list[str] = Field(default_factory=list)
    evidence: PluginEvidence
    metadata: dict[str, Any] = Field(default_factory=dict)


class PluginRiskSummary(BaseModel):
    total_findings: int = 0
    counts_by_severity: dict[str, int] = Field(default_factory=dict)
    counts_by_code: dict[str, int] = Field(default_factory=dict)
    highest_severity: Severity | None = None
    gate_recommendation: Literal["allow", "warn", "quarantine", "block"] = "allow"


class PluginRiskReport(BaseModel):
    schema_version: str = PLUGIN_RISK_SCHEMA_VERSION
    run_id: str
    generated_at: str
    input_path: str
    mode: str = "local_fixture"
    provider_calls_enabled: bool = False
    scanner: str = "deterministic_local_manifest_heuristics"
    wowpp_task: str = "13. Add plugin/OpenAPI/tool manifest risk scanner"
    parsed_format: str
    route_count: int = 0
    tool_count: int = 0
    findings: list[PluginFinding] = Field(default_factory=list)
    summary: PluginRiskSummary
    coverage_cells: list[CoverageCell] = Field(default_factory=list)
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    wowpp_metadata: WowppReportMetadata | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class PluginFindingsBundle(BaseModel):
    schema_version: str = PLUGIN_FINDINGS_SCHEMA_VERSION
    source_report: str = "plugin-risk-report.json"
    mode: str = "local_fixture"
    provider_calls_enabled: bool = False
    findings: list[PluginFinding] = Field(default_factory=list)
    summary: PluginRiskSummary


class _ToolRecord(BaseModel):
    name: str
    pointer: str
    method: str | None = None
    path: str | None = None
    description: str = ""
    permissions: list[str] = Field(default_factory=list)
    requires_approval: bool | None = None
    default_action: str | None = None
    raw: Any = None


def scan_plugin_manifest(input_path: str | Path, output_dir: str | Path | None = None) -> PluginRiskReport:
    manifest_path = Path(input_path)
    data, parsed_format = _load_manifest(manifest_path)
    display_path = _display_path(manifest_path)
    tools = _extract_tools(data)
    findings: list[PluginFinding] = []

    _scan_dangerous_routes(findings, tools, display_path)
    _scan_excessive_permissions(findings, data, tools, display_path)
    _scan_contract_mismatch(findings, data, tools, display_path)
    _scan_secrets(findings, data, display_path)
    _scan_external_sinks(findings, data, display_path)
    _scan_ambiguous_names(findings, tools, display_path)
    _scan_unsafe_defaults(findings, data, tools, display_path)

    findings = sorted(findings, key=lambda item: (_SEVERITY_ORDER[item.severity], item.code, item.finding_id), reverse=True)
    summary = _summary(findings)
    evidence_refs = [_evidence_ref(finding) for finding in findings]
    coverage_cells = _coverage_cells(findings)
    artifact_hash = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    report = PluginRiskReport(
        run_id=new_run_id(),
        generated_at=datetime.now(UTC).isoformat(),
        input_path=display_path,
        parsed_format=parsed_format,
        route_count=sum(1 for tool in tools if tool.path),
        tool_count=len(tools),
        findings=findings,
        summary=summary,
        coverage_cells=coverage_cells,
        evidence_refs=evidence_refs,
        wowpp_metadata=WowppReportMetadata(
            mode="local_fixture",
            provider_calls_enabled=False,
            evaluation_surfaces=[EvaluationSurface(surface_id="plugin_manifest", name="Plugin/OpenAPI/tool manifest", category="plugin_security", modality="yaml_json")],
            evidence_records=[
                EvidenceRecord(
                    evidence_id="plugin-manifest-input",
                    mode="local_fixture",
                    artifact_sha256=artifact_hash,
                    artifact_length=len(manifest_path.read_bytes()),
                    redacted_preview=_safe_preview(manifest_path.read_text(encoding="utf-8", errors="replace")),
                    redaction=RedactionMetadata(status="redacted", sha256=artifact_hash, length=len(manifest_path.read_bytes())),
                )
            ],
            artifact_hashes={display_path: artifact_hash},
            redaction=RedactionMetadata(status="redacted"),
            metadata={"wowpp_task": "13", "coverage_tags": sorted({tag for finding in findings for tag in finding.coverage_tags})},
        ),
        metadata={
            "provider_calls_enabled": False,
            "remote_schema_fetch_enabled": False,
            "plugin_code_execution_enabled": False,
            "mode": "local_fixture",
        },
    )
    if output_dir is not None:
        write_plugin_risk_report(report, output_dir)
    return report


def write_plugin_risk_report(report: PluginRiskReport, output_dir: str | Path) -> tuple[Path, Path, Path]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / "plugin-risk-report.json"
    markdown_path = out / "plugin-risk-report.md"
    findings_path = out / "plugin-risk-findings.json"
    json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    markdown_path.write_text(render_plugin_risk_markdown(report), encoding="utf-8")
    findings_path.write_text(PluginFindingsBundle(findings=report.findings, summary=report.summary).model_dump_json(indent=2), encoding="utf-8")
    return json_path, markdown_path, findings_path


def render_plugin_risk_markdown(report: PluginRiskReport) -> str:
    lines = [
        "# Plugin risk report",
        "",
        f"- Schema version: `{_md_safe(report.schema_version)}`",
        f"- Mode: `{_md_safe(report.mode)}`",
        f"- Provider calls enabled: `{str(report.provider_calls_enabled).lower()}`",
        f"- Input: `{_md_safe(report.input_path)}`",
        f"- Scanner: `{_md_safe(report.scanner)}`",
        f"- Findings: {report.summary.total_findings}",
        f"- Highest severity: `{_md_safe(report.summary.highest_severity or 'none')}`",
        f"- Gate recommendation: `{_md_safe(report.summary.gate_recommendation)}`",
        "",
        "## Findings",
        "",
    ]
    if not report.findings:
        lines.append("No plugin risk findings were detected by the deterministic local scanner.")
    for finding in report.findings:
        lines.extend(
            [
                f"### {_md_safe(finding.code)} ({_md_safe(finding.severity)})",
                f"- ID: `{_md_safe(finding.finding_id)}`",
                f"- Title: {_md_safe(finding.title)}",
                f"- Description: {_md_safe(finding.description)}",
                f"- Recommendation: {_md_safe(finding.recommendation)}",
                f"- Approval gate: {_md_safe(finding.approval_gate)}",
                f"- Evidence: `{_md_safe(finding.evidence.json_pointer)}` route=`{_md_safe(finding.evidence.route_name or 'n/a')}` hash=`{_md_safe(finding.evidence.route_hash or 'n/a')}` length=`{finding.evidence.route_length or 0}`",
                f"- Preview: {_md_safe(finding.evidence.redacted_preview)}",
                "",
            ]
        )
    lines.extend(["## Coverage cells", ""])
    for cell in report.coverage_cells:
        lines.append(f"- `{_md_safe(cell.dimension)}` = `{_md_safe(cell.value)}` findings={len(cell.finding_ids)}")
    return "\n".join(lines) + "\n"


def _load_manifest(path: Path) -> tuple[dict[str, Any], str]:
    if not path.exists() or not path.is_file():
        raise ValueError(f"plugin manifest not found: {path}")
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        data = json.loads(text)
        parsed_format = "json"
    else:
        data = yaml.safe_load(text)
        parsed_format = "yaml"
    if not isinstance(data, dict):
        raise ValueError("plugin manifest must contain a JSON/YAML object")
    return data, parsed_format


def _display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        text = resolved.as_posix()
        return redact_public_text(text).text if "/home/" in text else resolved.name


def _extract_tools(data: dict[str, Any]) -> list[_ToolRecord]:
    tools: list[_ToolRecord] = []
    paths = data.get("paths")
    if isinstance(paths, dict):
        for path, path_item in sorted(paths.items()):
            if not isinstance(path_item, dict):
                continue
            for method, operation in sorted(path_item.items()):
                if method.lower() not in _HTTP_METHODS or not isinstance(operation, dict):
                    continue
                name = str(operation.get("operationId") or operation.get("x-tool-name") or f"{method.upper()} {path}")
                tools.append(
                    _ToolRecord(
                        name=name,
                        pointer=f"/paths/{_pointer_token(str(path))}/{_pointer_token(str(method))}",
                        method=method.upper(),
                        path=str(path),
                        description=" ".join(str(operation.get(key) or "") for key in ("summary", "description")),
                        permissions=_permissions(operation),
                        requires_approval=_approval_value(operation),
                        default_action=_default_action(operation),
                        raw=operation,
                    )
                )
    for key in ("tools", "tool_registry", "registry", "functions", "actions"):
        _extract_registry_tools(data.get(key), f"/{key}", tools)
    return _dedupe_tools(tools)


def _extract_registry_tools(value: Any, pointer: str, tools: list[_ToolRecord]) -> None:
    if isinstance(value, list):
        for index, item in enumerate(value):
            if isinstance(item, dict):
                name = str(item.get("name") or item.get("id") or item.get("operationId") or f"tool_{index}")
                tools.append(_registry_record(name, item, f"{pointer}/{index}"))
    elif isinstance(value, dict):
        for name, item in sorted(value.items()):
            if isinstance(item, dict):
                tools.append(_registry_record(str(item.get("name") or name), item, f"{pointer}/{_pointer_token(str(name))}"))


def _registry_record(name: str, item: dict[str, Any], pointer: str) -> _ToolRecord:
    route = item.get("path") or item.get("route") or item.get("endpoint") or item.get("url")
    method = item.get("method")
    return _ToolRecord(
        name=name,
        pointer=pointer,
        method=str(method).upper() if method else None,
        path=str(route) if route else None,
        description=" ".join(str(item.get(key) or "") for key in ("description", "summary")),
        permissions=_permissions(item),
        requires_approval=_approval_value(item),
        default_action=_default_action(item),
        raw=item,
    )


def _dedupe_tools(tools: list[_ToolRecord]) -> list[_ToolRecord]:
    seen: set[tuple[str, str | None, str | None]] = set()
    unique: list[_ToolRecord] = []
    for tool in tools:
        key = (tool.name, tool.method, tool.path)
        if key in seen:
            continue
        seen.add(key)
        unique.append(tool)
    return unique


def _scan_dangerous_routes(findings: list[PluginFinding], tools: list[_ToolRecord], source_path: str) -> None:
    for tool in tools:
        if _is_dangerous_tool(tool):
            _add_finding(
                findings,
                code="dangerous_route",
                severity="critical" if _contains_any(tool, {"delete", "destroy", "deploy", "push", "transfer"}) else "high",
                title="Dangerous write/delete/push/deploy route",
                description="The manifest exposes a route or tool whose method/name/path can mutate state, deploy, push, delete, or transfer data.",
                recommendation="Restrict the route to least privilege, require explicit user intent, and bind it to a trusted approval gate before execution.",
                approval_gate="required_for_state_changing_routes",
                evidence=_tool_evidence(source_path, tool),
                coverage_tags=["plugin_manifest", "dangerous_route", "approval_gate"],
                metadata={"method": tool.method, "path_present": bool(tool.path)},
            )
            if tool.requires_approval is not True:
                _add_finding(
                    findings,
                    code="missing_approval",
                    severity="high",
                    title="Dangerous route lacks explicit approval metadata",
                    description="A state-changing tool or route does not declare a trusted approval requirement.",
                    recommendation="Add requires_approval=true or an equivalent trusted approval policy and fail closed when approval is absent.",
                    approval_gate="requires_approval_true",
                    evidence=_tool_evidence(source_path, tool),
                    coverage_tags=["plugin_manifest", "missing_approval", "approval_gate"],
                )


def _scan_excessive_permissions(findings: list[PluginFinding], data: dict[str, Any], tools: list[_ToolRecord], source_path: str) -> None:
    root_permissions = _permissions(data)
    for permission in root_permissions:
        if _is_excessive_permission(permission):
            _add_generic_finding(findings, source_path, "/permissions", "excessive_permissions", "critical", "Excessive manifest permission", f"Manifest requests broad permission `{permission}`.")
    for tool in tools:
        for permission in tool.permissions:
            if _is_excessive_permission(permission):
                _add_finding(
                    findings,
                    code="excessive_permissions",
                    severity="critical",
                    title="Excessive tool permission",
                    description=f"Tool requests broad permission `{permission}`.",
                    recommendation="Replace broad permissions with narrow route-scoped capabilities and document why each scope is needed.",
                    approval_gate="least_privilege_review",
                    evidence=_tool_evidence(source_path, tool),
                    coverage_tags=["plugin_manifest", "excessive_permissions", "least_privilege"],
                    metadata={"permission_hash": sha256_text(permission), "permission_length": len(permission)},
                )


def _scan_contract_mismatch(findings: list[PluginFinding], data: dict[str, Any], tools: list[_ToolRecord], source_path: str) -> None:
    declared = data.get("declared_tools") or data.get("contract") or data.get("tool_contract")
    if declared is None:
        return
    declared_routes: set[str] = set()
    declared_names: set[str] = set()
    if isinstance(declared, dict):
        declared = declared.get("tools") or declared.get("routes") or declared
    if isinstance(declared, dict):
        iterable = declared.values()
    elif isinstance(declared, list):
        iterable = declared
    else:
        iterable = []
    for item in iterable:
        if isinstance(item, dict):
            if item.get("name"):
                declared_names.add(str(item["name"]).lower())
            if item.get("path") or item.get("route") or item.get("endpoint"):
                declared_routes.add(str(item.get("path") or item.get("route") or item.get("endpoint")))
    actual_names = {tool.name.lower() for tool in tools}
    actual_routes = {tool.path for tool in tools if tool.path}
    if declared_names and not declared_names <= actual_names:
        missing = sorted(declared_names - actual_names)
        _add_generic_finding(findings, source_path, "/declared_tools", "contract_route_mismatch", "medium", "Declared tool missing from implementation", f"Declared tool names are not present in parsed routes/tools: {', '.join(missing[:3])}.")
    if declared_routes and not declared_routes <= actual_routes:
        missing_routes = sorted(declared_routes - actual_routes)
        _add_generic_finding(findings, source_path, "/declared_tools", "contract_route_mismatch", "medium", "Declared route missing from implementation", f"Declared routes are not present in parsed paths/tools: {', '.join(missing_routes[:3])}.")
    for tool in tools:
        if declared_names and tool.name.lower() not in declared_names:
            _add_finding(
                findings,
                code="contract_route_mismatch",
                severity="medium",
                title="Implemented route missing from declared contract",
                description="A parsed route/tool is not declared in the manifest contract.",
                recommendation="Synchronize declared tool contracts with actual OpenAPI paths/tool registry entries before release.",
                approval_gate="contract_review_required",
                evidence=_tool_evidence(source_path, tool),
                coverage_tags=["plugin_manifest", "contract_route_mismatch", "contract_review"],
            )


def _scan_secrets(findings: list[PluginFinding], data: Any, source_path: str) -> None:
    for pointer, value in _walk(data):
        if not isinstance(value, str) or not _SECRET_RE.search(value):
            continue
        _add_finding(
            findings,
            code="secret_in_example",
            severity="high",
            title="Secret-like value appears in manifest example",
            description="A manifest field contains a secret/token/API-key-shaped value. Public report output stores only redacted previews and hashes.",
            recommendation="Remove real or realistic secrets from examples and replace them with clearly fake placeholders.",
            approval_gate="redaction_review_required",
            evidence=_evidence(source_path, pointer, value),
            coverage_tags=["plugin_manifest", "secret_in_example", "redaction"],
        )


def _scan_external_sinks(findings: list[PluginFinding], data: Any, source_path: str) -> None:
    for pointer, value in _walk(data):
        if not isinstance(value, str):
            continue
        for url in _URL_RE.findall(value):
            if _is_external_url(url):
                _add_finding(
                    findings,
                    code="external_network_sink",
                    severity="high",
                    title="External network sink in plugin manifest",
                    description="The manifest references an external HTTP(S) endpoint that could receive tool data.",
                    recommendation="Require allow-listed egress, explicit user consent, and trusted approval before sending data to external endpoints.",
                    approval_gate="egress_allowlist_required",
                    evidence=_evidence(source_path, pointer, url, route_name=url),
                    coverage_tags=["plugin_manifest", "external_network_sink", "egress_control"],
                )


def _scan_ambiguous_names(findings: list[PluginFinding], tools: list[_ToolRecord], source_path: str) -> None:
    for tool in tools:
        normalized = re.sub(r"[^a-z0-9_]+", "_", tool.name.lower()).strip("_")
        if normalized in _AMBIGUOUS_TOOL_NAMES or len(normalized) <= 3:
            _add_finding(
                findings,
                code="ambiguous_tool_name",
                severity="medium",
                title="Ambiguous tool name",
                description="A tool name is too generic to communicate action, target, and risk to a model or reviewer.",
                recommendation="Rename the tool with a specific verb, object, and risk-relevant target such as `send_customer_email_requires_approval`.",
                approval_gate="naming_review_required",
                evidence=_tool_evidence(source_path, tool),
                coverage_tags=["plugin_manifest", "ambiguous_tool_name", "tool_naming"],
            )


def _scan_unsafe_defaults(findings: list[PluginFinding], data: Any, tools: list[_ToolRecord], source_path: str) -> None:
    for tool in tools:
        if tool.default_action and _contains_dangerous_word(tool.default_action):
            _add_finding(
                findings,
                code="unsafe_default_action",
                severity="high",
                title="Unsafe default tool action",
                description="A tool default action selects a state-changing or externally visible behavior.",
                recommendation="Make defaults read-only/no-op and require explicit approval for destructive or external actions.",
                approval_gate="safe_default_review_required",
                evidence=_tool_evidence(source_path, tool),
                coverage_tags=["plugin_manifest", "unsafe_default_action", "safe_defaults"],
            )
    for pointer, value in _walk(data):
        key = pointer.rsplit("/", 1)[-1].lower()
        if key in {"default_action", "action_default", "default_behavior", "on_missing_input"} and _contains_dangerous_word(str(value)):
            _add_finding(
                findings,
                code="unsafe_default_action",
                severity="high",
                title="Unsafe default action",
                description="A manifest default selects a destructive, write, push, deploy, send, or execute behavior.",
                recommendation="Change defaults to safe/no-op/read-only behavior and require explicit approval for risky actions.",
                approval_gate="safe_default_review_required",
                evidence=_evidence(source_path, pointer, value),
                coverage_tags=["plugin_manifest", "unsafe_default_action", "safe_defaults"],
            )


def _add_generic_finding(findings: list[PluginFinding], source_path: str, pointer: str, code: str, severity: Severity, title: str, description: str) -> None:
    recommendations = {
        "excessive_permissions": "Replace broad permissions with narrow route-scoped capabilities and document why each scope is needed.",
        "contract_route_mismatch": "Synchronize declared contracts with actual routes/tool registry entries before release.",
    }
    gates = {"excessive_permissions": "least_privilege_review", "contract_route_mismatch": "contract_review_required"}
    _add_finding(
        findings,
        code=code,
        severity=severity,
        title=title,
        description=description,
        recommendation=recommendations.get(code, "Review and remediate the manifest risk before enabling the plugin."),
        approval_gate=gates.get(code, "security_review_required"),
        evidence=_evidence(source_path, pointer, description),
        coverage_tags=["plugin_manifest", code],
    )


def _add_finding(
    findings: list[PluginFinding],
    *,
    code: str,
    severity: Severity,
    title: str,
    description: str,
    recommendation: str,
    approval_gate: str,
    evidence: PluginEvidence,
    coverage_tags: list[str],
    metadata: dict[str, Any] | None = None,
) -> None:
    finding_id = "prf-" + sha256_text("|".join([code, severity, evidence.source_path, evidence.json_pointer, evidence.sha256]))[:16]
    if any(existing.finding_id == finding_id for existing in findings):
        return
    findings.append(
        PluginFinding(
            finding_id=finding_id,
            code=code,
            severity=severity,
            title=title,
            description=description,
            recommendation=recommendation,
            approval_gate=approval_gate,
            coverage_tags=sorted(set(coverage_tags)),
            evidence=evidence,
            metadata=metadata or {},
        )
    )


def _tool_evidence(source_path: str, tool: _ToolRecord) -> PluginEvidence:
    route = " ".join(part for part in [tool.method, tool.path or tool.name] if part)
    preview_parts = [tool.name, tool.method or "", tool.path or "", tool.description]
    return _evidence(source_path, tool.pointer, " ".join(preview_parts), route_name=route)


def _evidence(source_path: str, pointer: str, value: Any, route_name: str | None = None) -> PluginEvidence:
    text = str(value)
    route = route_name or _safe_preview(text, limit=80)
    return PluginEvidence(
        evidence_id="plugin-evidence-" + sha256_text("|".join([source_path, pointer, text]))[:16],
        source_path=source_path,
        json_pointer=pointer or "/",
        route_name=_safe_preview(route, limit=120),
        route_hash=sha256_text(route),
        route_length=len(route),
        sha256=sha256_text(text),
        length=len(text),
        redacted_preview=_safe_preview(text),
    )


def _evidence_ref(finding: PluginFinding) -> EvidenceRef:
    evidence = finding.evidence
    return EvidenceRef(
        evidence_id=evidence.evidence_id,
        artifact_path=evidence.source_path,
        artifact_type="plugin_manifest",
        sha256=evidence.sha256,
        redacted_preview=evidence.redacted_preview,
        metadata={"json_pointer": evidence.json_pointer, "route_hash": evidence.route_hash, "route_length": evidence.route_length, "finding_code": finding.code},
    )


def _coverage_cells(findings: list[PluginFinding]) -> list[CoverageCell]:
    by_code: dict[str, list[str]] = {}
    by_tag: dict[str, list[str]] = {}
    for finding in findings:
        by_code.setdefault(finding.code, []).append(finding.finding_id)
        for tag in finding.coverage_tags:
            by_tag.setdefault(tag, []).append(finding.finding_id)
    cells = [CoverageCell(dimension="plugin_risk_code", value=code, total_items=len(ids), covered_items=len(ids), finding_ids=sorted(ids)) for code, ids in sorted(by_code.items())]
    cells.extend(CoverageCell(dimension="coverage_tag", value=tag, total_items=len(ids), covered_items=len(ids), finding_ids=sorted(ids)) for tag, ids in sorted(by_tag.items()))
    return cells


def _summary(findings: list[PluginFinding]) -> PluginRiskSummary:
    severity_counts: dict[str, int] = {}
    code_counts: dict[str, int] = {}
    highest: Severity | None = None
    for finding in findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        code_counts[finding.code] = code_counts.get(finding.code, 0) + 1
        if highest is None or _SEVERITY_ORDER[finding.severity] > _SEVERITY_ORDER[highest]:
            highest = finding.severity
    gate: Literal["allow", "warn", "quarantine", "block"] = "allow"
    if highest in {"critical"}:
        gate = "block"
    elif highest == "high":
        gate = "quarantine"
    elif highest == "medium":
        gate = "warn"
    return PluginRiskSummary(total_findings=len(findings), counts_by_severity=dict(sorted(severity_counts.items())), counts_by_code=dict(sorted(code_counts.items())), highest_severity=highest, gate_recommendation=gate)


def _permissions(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    collected: list[str] = []
    for key in ("permissions", "permission", "scopes", "scope", "oauth_scopes", "capabilities"):
        candidate = value.get(key)
        if isinstance(candidate, str):
            collected.extend(part.strip() for part in re.split(r"[,\s]+", candidate) if part.strip())
        elif isinstance(candidate, list):
            collected.extend(str(part).strip() for part in candidate if str(part).strip())
        elif isinstance(candidate, dict):
            collected.extend(str(key) for key, enabled in candidate.items() if enabled)
    return sorted(set(collected))


def _approval_value(value: Any) -> bool | None:
    if not isinstance(value, dict):
        return None
    for key in ("requires_approval", "approval_required", "x-requires-approval", "x-approval-required", "human_approval", "confirmation_required"):
        if key in value:
            return bool(value[key])
    return None


def _default_action(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None
    for key in ("default_action", "action_default", "default_behavior", "on_missing_input"):
        if key in value:
            return str(value[key])
    return None


def _is_dangerous_tool(tool: _ToolRecord) -> bool:
    if tool.method in {"DELETE", "PUT", "PATCH"}:
        return True
    if tool.method == "POST" and _contains_any(tool, _DANGEROUS_WORDS):
        return True
    return _contains_any(tool, _DANGEROUS_WORDS)


def _contains_any(tool: _ToolRecord, words: set[str]) -> bool:
    text = " ".join(str(part or "") for part in [tool.name, tool.path, tool.description, tool.default_action]).lower()
    tokens = _tokens(text)
    return bool(tokens & words)


def _contains_dangerous_word(text: str) -> bool:
    tokens = _tokens(text.lower())
    return bool(tokens & _DANGEROUS_WORDS)


def _tokens(text: str) -> set[str]:
    tokens: set[str] = set()
    for word in _WORD_RE.findall(text):
        tokens.update(part for part in word.lower().split("_") if part)
    return tokens


def _is_excessive_permission(permission: str) -> bool:
    normalized = permission.strip().lower()
    return normalized in _EXCESSIVE_PERMISSIONS or normalized.endswith(":*") or normalized.endswith(".*")


def _is_external_url(url: str) -> bool:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host or host in {"localhost", "127.0.0.1", "::1"}:
        return False
    if host.endswith(".local") or host.endswith(".invalid") or host.endswith(".example"):
        return False
    return True


def _walk(value: Any, pointer: str = "") -> list[tuple[str, Any]]:
    rows: list[tuple[str, Any]] = [(pointer or "/", value)]
    if isinstance(value, dict):
        for key, child in value.items():
            rows.extend(_walk(child, f"{pointer}/{_pointer_token(str(key))}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            rows.extend(_walk(child, f"{pointer}/{index}"))
    return rows


def _pointer_token(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _safe_preview(value: Any, *, limit: int = _MAX_PREVIEW) -> str:
    text = redacted_preview(str(value), limit=limit)
    result = redact_public_text(text, limit=limit)
    return result.text if result.redacted else text
