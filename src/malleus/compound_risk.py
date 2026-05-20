from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from html import escape
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from malleus.findings import FindingsBundle, SecurityFinding, load_or_collect_findings
from malleus.schemas import Severity
from malleus.utils.ids import new_run_id
from malleus.utils.redact import redacted_preview, sha256_text

COMPOUND_RISK_SCHEMA_VERSION = "malleus.compound_risk.v1"
RiskBand = Literal["low", "medium", "high", "critical"]

_SEVERITY_ORDER: dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_BAND_ORDER: dict[str, int] = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_SPACE_RE = re.compile(r"\s+")
_UNSAFE_RE = re.compile(
    r"\b(ignore previous instructions|system prompt|developer message|exfiltrate|call\s+exfiltrate_secret|environment token|do_not_dump_raw|raw_unsafe|raw secret|private fixture)\b",
    re.IGNORECASE,
)


class CompoundRiskEvidenceRef(BaseModel):
    evidence_id: str
    source_path: str
    source_type: str
    json_pointer: str | None = None
    sha256: str | None = None
    redacted_excerpt: str = ""


class CompoundLinkedFinding(BaseModel):
    finding_id: str
    title: str
    source_type: str
    severity: Severity
    attack_surface: str
    technique: str
    violated_boundary: str
    evidence_refs: list[CompoundRiskEvidenceRef] = Field(default_factory=list)


class CompoundRiskScenario(BaseModel):
    scenario_id: str
    title: str
    threat_class: str
    attack_surface: str
    linked_surfaces: list[str] = Field(default_factory=list)
    likelihood: RiskBand
    impact: RiskBand
    detectability: RiskBand
    compound_risk: RiskBand
    heuristic_rationale: list[str] = Field(default_factory=list)
    countermeasure: str
    linked_findings: list[CompoundLinkedFinding] = Field(default_factory=list)
    evidence_refs: list[CompoundRiskEvidenceRef] = Field(default_factory=list)


class CompoundRiskSummary(BaseModel):
    total_findings: int = 0
    total_scenarios: int = 0
    counts_by_risk: dict[str, int] = Field(default_factory=dict)
    counts_by_threat_class: dict[str, int] = Field(default_factory=dict)
    attack_surfaces: list[str] = Field(default_factory=list)
    highest_risk: RiskBand | None = None


class CompoundRiskReport(BaseModel):
    schema_version: str = COMPOUND_RISK_SCHEMA_VERSION
    run_id: str
    generated_at: str
    mode: str = "local_fixture"
    provider_calls_enabled: bool = False
    scoring: str = "deterministic_ordinal_heuristic_not_quantitative"
    source_paths: list[str] = Field(default_factory=list)
    scenarios: list[CompoundRiskScenario] = Field(default_factory=list)
    summary: CompoundRiskSummary
    metadata: dict[str, Any] = Field(default_factory=dict)


def build_compound_risk_report(inputs: list[str | Path]) -> CompoundRiskReport:
    if not inputs:
        raise ValueError("at least one local findings/report artifact is required")
    findings: list[SecurityFinding] = []
    source_paths: list[str] = []
    for raw in inputs:
        path = Path(raw)
        if not path.exists():
            raise ValueError(f"compound-risk input not found: {path}")
        source_paths.append(_display_path(path))
        findings.extend(_findings_from_path(path))
    unique = {finding.finding_id: finding for finding in findings}
    ordered = [unique[key] for key in sorted(unique)]
    scenarios = _group_scenarios(ordered)
    return CompoundRiskReport(
        run_id=new_run_id(),
        generated_at=datetime.now(UTC).isoformat(),
        source_paths=source_paths,
        scenarios=scenarios,
        summary=_summary(ordered, scenarios),
        metadata={
            "provider_calls_enabled": False,
            "network_access_enabled": False,
            "heuristic_note": "Ordinal bands are deterministic triage heuristics, not measured probabilities.",
        },
    )


def write_compound_risk_report(report: CompoundRiskReport, output_dir: str | Path) -> tuple[Path, Path, Path]:
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    json_path = destination / "compound-risk-report.json"
    markdown_path = destination / "compound-risk-report.md"
    html_path = destination / "compound-risk-report.html"
    json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    markdown_path.write_text(render_compound_risk_markdown(report), encoding="utf-8")
    html_path.write_text(render_compound_risk_html(report), encoding="utf-8")
    return json_path, markdown_path, html_path


def render_compound_risk_markdown(report: CompoundRiskReport) -> str:
    lines = [
        "# Compound risk report",
        "",
        f"- Schema version: `{_md_safe(report.schema_version)}`",
        f"- Mode: `{_md_safe(report.mode)}`",
        f"- Provider calls enabled: `{str(report.provider_calls_enabled).lower()}`",
        "- Scoring: deterministic ordinal heuristic; not a quantitative probability model.",
        f"- Findings considered: {report.summary.total_findings}",
        f"- Scenarios: {report.summary.total_scenarios}",
        f"- Highest compound risk: {_md_safe(report.summary.highest_risk or 'n/a')}",
        "",
        "## Local graph view",
        "",
        "| Scenario | Threat class | Attack surface | Linked surfaces | Risk | Evidence refs |",
        "| --- | --- | --- | --- | --- | ---: |",
    ]
    for scenario in report.scenarios:
        lines.append(
            f"| {_md_safe(scenario.scenario_id)} | {_md_safe(scenario.threat_class)} | {_md_safe(scenario.attack_surface)} | "
            f"{_md_safe(', '.join(scenario.linked_surfaces))} | {_md_safe(scenario.compound_risk)} | {len(scenario.evidence_refs)} |"
        )
    lines.extend(["", "## Risk cards", ""])
    if not report.scenarios:
        lines.append("No compound scenarios were derived from the supplied local artifacts.")
    for scenario in report.scenarios:
        lines.extend(
            [
                f"### {_md_safe(scenario.title)}",
                "",
                f"- Threat class: {_md_safe(scenario.threat_class)}",
                f"- Attack surface: {_md_safe(scenario.attack_surface)}",
                f"- Likelihood: {_md_safe(scenario.likelihood)}",
                f"- Impact: {_md_safe(scenario.impact)}",
                f"- Detectability: {_md_safe(scenario.detectability)}",
                f"- Compound risk: {_md_safe(scenario.compound_risk)}",
                f"- Countermeasure: {_md_safe(scenario.countermeasure)}",
                f"- Linked evidence refs: {_md_safe(', '.join(ref.evidence_id for ref in scenario.evidence_refs) or 'n/a')}",
                "- Rationale:",
            ]
        )
        for reason in scenario.heuristic_rationale:
            lines.append(f"  - {_md_safe(reason)}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_compound_risk_html(report: CompoundRiskReport) -> str:
    rows = "".join(
        "<tr>"
        f"<td>{_html_safe(scenario.scenario_id)}</td>"
        f"<td>{_html_safe(scenario.threat_class)}</td>"
        f"<td>{_html_safe(scenario.attack_surface)}</td>"
        f"<td>{_html_safe(', '.join(scenario.linked_surfaces))}</td>"
        f"<td><span class='risk {scenario.compound_risk}'>{_html_safe(scenario.compound_risk)}</span></td>"
        f"<td>{len(scenario.evidence_refs)}</td>"
        "</tr>"
        for scenario in report.scenarios
    ) or "<tr><td colspan='6'>No compound scenarios derived.</td></tr>"
    cards = "".join(_risk_card_html(scenario) for scenario in report.scenarios) or "<p class='empty'>No risk cards.</p>"
    title = "Compound risk report"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title><style>
body{{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:32px;background:#0b0c0f;color:#f5f5f5}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px}}.card{{border:1px solid #333;border-radius:14px;padding:14px;background:#15171c}}
table{{border-collapse:collapse;width:100%;font-size:13px;margin:12px 0 28px}}th,td{{border:1px solid #333;padding:8px;text-align:left;vertical-align:top}}th{{background:#181a20}}
.risk{{display:inline-block;border-radius:999px;padding:3px 9px;font-weight:700}}.critical{{background:#7f1d1d}}.high{{background:#92400e}}.medium{{background:#854d0e}}.low{{background:#14532d}}.empty{{color:#a1a1aa}}
</style></head><body>
<h1>{title}</h1><p>Local-only deterministic compound-risk triage. Ordinal bands are heuristics, not quantitative probabilities.</p>
<div class="cards"><div class="card">Findings: {report.summary.total_findings}</div><div class="card">Scenarios: {report.summary.total_scenarios}</div><div class="card">Highest risk: {_html_safe(report.summary.highest_risk or 'n/a')}</div><div class="card">Surfaces: {_html_safe(', '.join(report.summary.attack_surfaces))}</div></div>
<h2>Graph-like local scenario table</h2><table><thead><tr><th>Scenario</th><th>Threat class</th><th>Attack surface</th><th>Linked surfaces</th><th>Risk</th><th>Evidence refs</th></tr></thead><tbody>{rows}</tbody></table>
<h2>Risk cards</h2><div class="cards">{cards}</div>
<footer>Static HTML. No external JavaScript, fonts, third-party assets, server, or network dependency.</footer></body></html>"""


def _findings_from_path(path: Path) -> list[SecurityFinding]:
    if path.is_dir() or path.name in {"findings.json", "report.json", "agent-lab-report.json", "risk-summary.json", "trace-diff-report.json", "campaign-report.json", "rag-report.json"}:
        return list(load_or_collect_findings(path).findings)
    data = _load_json(path)
    schema = str(data.get("schema_version") or "")
    if schema == "malleus.findings.v1":
        return list(FindingsBundle.model_validate(data).findings)
    if path.name in {"plugin-risk-report.json", "plugin-risk-findings.json"} or schema.startswith("malleus.plugin_risk"):
        return _generic_report_findings(data, path, source_type="plugin", default_surface="tool_plugin_manifest", boundary="tool_approval_boundary")
    if path.name in {"vcs-workflow-report.json", "code-agent-lifecycle-report.json"} or schema in {"malleus.vcs_workflow_report.v1", "malleus.code_agent_lifecycle_report.v1"}:
        source = "vcs" if "vcs" in path.name or "vcs" in schema else "code_agent"
        return _generic_report_findings(data, path, source_type=source, default_surface="vcs_workflow" if source == "vcs" else "code_agent_lifecycle", boundary="agent_change_control_boundary")
    return list(load_or_collect_findings(path).findings)


def _generic_report_findings(data: dict[str, Any], path: Path, *, source_type: str, default_surface: str, boundary: str) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    items = data.get("findings") if isinstance(data.get("findings"), list) else []
    for index, item in enumerate(item for item in items if isinstance(item, dict)):
        severity = _severity(item.get("severity"))
        code = _safe_text(item.get("code") or item.get("kind") or source_type, limit=80)
        finding_id = _safe_text(item.get("finding_id") or _stable_id(source_type, path.name, code, index), limit=120)
        evidence = item.get("evidence") if isinstance(item.get("evidence"), dict) else {}
        pointer = str(evidence.get("json_pointer") or f"/findings/{index}")
        sha = str(evidence.get("sha256") or _sha256_file(path) or "") or None
        findings.append(
            SecurityFinding(
                finding_id=finding_id,
                title=_safe_text(item.get("title") or f"{severity} {source_type} finding: {code}", limit=180),
                source_type="interop",
                affected_model={"name": source_type, "adapter": None, "model": None, "config": source_type},
                severity=severity,
                attack_surface=_safe_text(item.get("attack_surface") or default_surface, limit=80),
                technique=code,
                violated_boundary=boundary,
                taxonomy_refs=[source_type, code],
                reproduction_command=f"malleus compound-risk --input {path.name} --out-dir compound-risk",
                evidence_refs=[],
                redacted_excerpts=[_safe_text(item.get("description") or item.get("remediation") or code, limit=180)],
                patch_recommendation=_safe_text(item.get("patch_recommendation") or item.get("recommendation") or item.get("remediation") or "Review and harden this local control.", limit=260),
                regression_case_link=f"{path.name}:{index + 1}",
                replay_spec={"replay_id": f"replay-{finding_id}", "finding_id": finding_id, "mode": "dry_run", "command": f"malleus compound-risk --input {path.name} --out-dir compound-risk", "target_name": source_type},
                metadata={"compound_source": source_type, "source_path": path.name, "json_pointer": pointer, "source_sha256": sha},
            )
        )
    return findings


def _severity(value: object) -> Severity:
    if value == "low":
        return "low"
    if value == "medium":
        return "medium"
    if value == "high":
        return "high"
    if value == "critical":
        return "critical"
    return "medium"


def _group_scenarios(findings: list[SecurityFinding]) -> list[CompoundRiskScenario]:
    groups: dict[tuple[str, str], list[SecurityFinding]] = {}
    for finding in findings:
        key = (_threat_class(finding), _safe_text(finding.violated_boundary or finding.attack_surface, limit=80))
        groups.setdefault(key, []).append(finding)
    scenarios: list[CompoundRiskScenario] = []
    for (threat_class, boundary), items in sorted(groups.items()):
        ordered = sorted(items, key=lambda item: (_safe_text(item.attack_surface), _safe_text(item.finding_id)))
        surfaces = sorted({_safe_text(item.attack_surface, limit=80) for item in ordered if item.attack_surface})
        severity_max = max(_SEVERITY_ORDER.get(item.severity, 1) for item in ordered)
        likelihood = _band(min(4, 1 + len(ordered) + (1 if len(surfaces) > 1 else 0)))
        impact = _band(severity_max)
        detectability = _detectability(ordered, surfaces)
        risk = _compound_band(likelihood, impact, detectability, len(surfaces))
        evidence = _scenario_evidence(ordered)
        scenario_id = "cr-" + sha256_text("|".join([threat_class, boundary, *[item.finding_id for item in ordered]]))[:12]
        scenarios.append(
            CompoundRiskScenario(
                scenario_id=scenario_id,
                title=f"{risk.title()} compound {threat_class} across {surfaces[0] if surfaces else 'unknown_surface'}",
                threat_class=threat_class,
                attack_surface=surfaces[0] if surfaces else "unknown_surface",
                linked_surfaces=surfaces,
                likelihood=likelihood,
                impact=impact,
                detectability=detectability,
                compound_risk=risk,
                heuristic_rationale=[
                    f"{len(ordered)} linked local finding(s) share boundary {_safe_text(boundary, limit=80)}.",
                    f"{len(surfaces)} attack surface(s) linked: {', '.join(surfaces) or 'unknown'}.",
                    f"Highest source severity is {_band(severity_max)}; detectability is {detectability} based on evidence and hidden/indirect surfaces.",
                ],
                countermeasure=_countermeasure(threat_class, surfaces),
                linked_findings=[_linked_finding(item) for item in ordered],
                evidence_refs=evidence,
            )
        )
    return sorted(scenarios, key=lambda item: (-_BAND_ORDER[item.compound_risk], item.threat_class, item.scenario_id))


def _linked_finding(finding: SecurityFinding) -> CompoundLinkedFinding:
    return CompoundLinkedFinding(
        finding_id=_safe_text(finding.finding_id, limit=120),
        title=_safe_text(finding.title, limit=180),
        source_type=_safe_text(finding.source_type, limit=60),
        severity=finding.severity,
        attack_surface=_safe_text(finding.attack_surface, limit=80),
        technique=_safe_text(finding.technique, limit=100),
        violated_boundary=_safe_text(finding.violated_boundary, limit=100),
        evidence_refs=_finding_evidence(finding),
    )


def _finding_evidence(finding: SecurityFinding) -> list[CompoundRiskEvidenceRef]:
    refs: list[CompoundRiskEvidenceRef] = []
    for ref in finding.evidence_refs:
        refs.append(
            CompoundRiskEvidenceRef(
                evidence_id=_safe_text(ref.evidence_id, limit=120),
                source_path=_display_path(Path(ref.artifact_path)),
                source_type=_safe_text(ref.artifact_type, limit=80),
                json_pointer=_safe_text(ref.json_pointer, limit=160) if ref.json_pointer else None,
                sha256=ref.sha256,
                redacted_excerpt=_safe_text(ref.redacted_excerpt or "", limit=180),
            )
        )
    if not refs:
        refs.append(
            CompoundRiskEvidenceRef(
                evidence_id=f"{_safe_text(finding.finding_id, limit=90)}-compound-ref",
                source_path=_display_path(Path(str(finding.metadata.get("source_path") or finding.regression_case_link or "local-artifact"))),
                source_type=_safe_text(str(finding.metadata.get("compound_source") or finding.source_type), limit=80),
                json_pointer=_safe_text(finding.metadata.get("json_pointer"), limit=160) if finding.metadata.get("json_pointer") else None,
                sha256=str(finding.metadata.get("source_sha256") or "") or None,
                redacted_excerpt=_safe_text("; ".join(finding.redacted_excerpts[:2]) or finding.title, limit=180),
            )
        )
    return refs


def _scenario_evidence(findings: list[SecurityFinding]) -> list[CompoundRiskEvidenceRef]:
    refs: dict[str, CompoundRiskEvidenceRef] = {}
    for finding in findings:
        for ref in _finding_evidence(finding):
            refs.setdefault(ref.evidence_id, ref)
    return [refs[key] for key in sorted(refs)[:20]]


def _summary(findings: list[SecurityFinding], scenarios: list[CompoundRiskScenario]) -> CompoundRiskSummary:
    risk_counts: dict[str, int] = {}
    threat_counts: dict[str, int] = {}
    highest: RiskBand | None = None
    for scenario in scenarios:
        risk_counts[scenario.compound_risk] = risk_counts.get(scenario.compound_risk, 0) + 1
        threat_counts[scenario.threat_class] = threat_counts.get(scenario.threat_class, 0) + 1
        if highest is None or _BAND_ORDER[scenario.compound_risk] > _BAND_ORDER[highest]:
            highest = scenario.compound_risk
    return CompoundRiskSummary(
        total_findings=len(findings),
        total_scenarios=len(scenarios),
        counts_by_risk=dict(sorted(risk_counts.items())),
        counts_by_threat_class=dict(sorted(threat_counts.items())),
        attack_surfaces=sorted({_safe_text(finding.attack_surface, limit=80) for finding in findings}),
        highest_risk=highest,
    )


def _threat_class(finding: SecurityFinding) -> str:
    text = f"{finding.source_type} {finding.attack_surface} {finding.technique} {finding.violated_boundary}".lower()
    if "rag" in text or "context" in text:
        return "retrieval_context_compromise"
    if "visual" in text or "artifact" in text or "hidden" in text:
        return "untrusted_artifact_instruction"
    if "vcs" in text or "code" in text or "change" in text:
        return "code_change_control_failure"
    if "plugin" in text or "tool" in text or "agent" in text:
        return "agent_tool_misuse"
    if "campaign" in text:
        return "multi_step_campaign_drift"
    return "model_behavior_boundary"


def _countermeasure(threat_class: str, surfaces: list[str]) -> str:
    if threat_class == "retrieval_context_compromise":
        return "Isolate retrieved context by tenant, strip untrusted chunk instructions, and require citation-aware refusal checks."
    if threat_class == "untrusted_artifact_instruction":
        return "Treat OCR, metadata, hidden text, and artifact contents as untrusted; pass only sanitized safe-context records downstream."
    if threat_class == "agent_tool_misuse":
        return "Require least-privilege manifests, explicit approval gates, and deny-by-default tool routing for risky operations."
    if threat_class == "code_change_control_failure":
        return "Require planning, review, tests, and approval before VCS or deployment actions; quarantine secret-like untracked files."
    if threat_class == "multi_step_campaign_drift":
        return "Replay the campaign locally, add per-step gates, and block progression when hidden-channel or policy gates fail."
    return f"Add regression coverage and policy gates for {', '.join(surfaces) or 'the linked surface'}."


def _detectability(findings: list[SecurityFinding], surfaces: list[str]) -> RiskBand:
    text = " ".join([*(finding.attack_surface for finding in findings), *(finding.technique for finding in findings), *(finding.source_type for finding in findings)]).lower()
    if any(token in text for token in ("hidden", "visual", "artifact", "rag_context")):
        return "high"
    if len(surfaces) > 1:
        return "medium"
    return "low"


def _compound_band(likelihood: RiskBand, impact: RiskBand, detectability: RiskBand, surface_count: int) -> RiskBand:
    score = _BAND_ORDER[likelihood] + _BAND_ORDER[impact] + max(0, _BAND_ORDER[detectability] - 1) + (1 if surface_count > 1 else 0)
    if score >= 10:
        return "critical"
    if score >= 8:
        return "high"
    if score >= 5:
        return "medium"
    return "low"


def _band(value: int) -> RiskBand:
    if value >= 4:
        return "critical"
    if value == 3:
        return "high"
    if value == 2:
        return "medium"
    return "low"


def _risk_card_html(scenario: CompoundRiskScenario) -> str:
    reasons = "".join(f"<li>{_html_safe(reason)}</li>" for reason in scenario.heuristic_rationale)
    evidence = ", ".join(ref.evidence_id for ref in scenario.evidence_refs[:6])
    return f"""<article class="card"><h3>{_html_safe(scenario.title)}</h3><p><span class="risk {scenario.compound_risk}">{_html_safe(scenario.compound_risk)}</span> {_html_safe(scenario.threat_class)}</p><p>Surface: {_html_safe(scenario.attack_surface)} / linked: {_html_safe(', '.join(scenario.linked_surfaces))}</p><p>Likelihood {_html_safe(scenario.likelihood)} · Impact {_html_safe(scenario.impact)} · Detectability {_html_safe(scenario.detectability)}</p><ul>{reasons}</ul><p>Countermeasure: {_html_safe(scenario.countermeasure)}</p><p>Evidence: {_html_safe(evidence or 'n/a')}</p></article>"""


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"compound-risk input is not valid JSON: {path}: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"compound-risk input must contain a JSON object: {path}")
    return value


def _safe_text(value: object, *, limit: int = 240) -> str:
    text = _SPACE_RE.sub(" ", str(value or "")).strip()
    text = _UNSAFE_RE.sub(lambda match: f"[REDACTED] unsafe sha256={sha256_text(match.group(0))[:16]} length={len(match.group(0))}", text)
    return redacted_preview(text, limit=limit)


def _md_safe(value: object) -> str:
    return _safe_text(value).replace("&", "&amp;").replace("<", "&lt;").replace("\r", " ").replace("\n", " ").replace("|", r"\|").replace("`", r"\`").replace("#", r"\#")


def _html_safe(value: object) -> str:
    return escape(_safe_text(value))


def _display_path(path: Path) -> str:
    return _safe_text(path.name, limit=180)


def _sha256_file(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _stable_id(*parts: object) -> str:
    return "cf-" + sha256_text("|".join(_safe_text(part, limit=120).lower() for part in parts))[:16]
