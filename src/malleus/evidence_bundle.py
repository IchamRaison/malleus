from __future__ import annotations

import json
import re
import hashlib
from html import escape
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


_SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\b(?:api[_ -]?key|secret|token|password|credential|bearer|canary)\s*[:=]?\s*[^\s`|<>]+", re.IGNORECASE),
    re.compile(r"/home/[^\s`|<>\]\)]+"),
    re.compile(r"/Users/[^\s`|<>\]\)]+"),
    re.compile(r"/tmp/[^\s`|<>\]\)]+"),
    re.compile(r"[A-Za-z]:[\\/]+Users[\\/]+[^\s`|<>\]\)]+"),
)
_UNSAFE_PATTERNS = (
    re.compile(r"\b(ignore previous instructions|system prompt|developer message|exfiltrate|call\s+exfiltrate_secret|environment token|reveal hidden|private fixture)\b", re.IGNORECASE),
)
_SPACE_RE = re.compile(r"\s+")
_KNOWN_ARTIFACT_NAMES = {
    "report.json",
    "dry-run.json",
    "mutation-report.json",
    "agent-lab-report.json",
    "hidden-channel-report.json",
    "artifact-firewall-report.json",
    "diff-runs-report.json",
    "trace-diff-report.json",
    "campaign-report.json",
    "rag-report.json",
    "risk-summary.json",
    "findings.json",
    "adjudications.json",
    "coverage.json",
    "model-risk-card.md",
    "patch-suggestions.json",
    "patch-manifest.json",
    "artifact-firewall-report.json",
    "artifact-firewall-report.md",
    "visual-lab-manifest.json",
    "visual-lab-report.json",
    "visual-lab-report.md",
    "visual-lab-report.html",
    "visual-run-report.json",
    "visual-run-report.md",
    "safe-context.json",
    "replay-spec.json",
    "rag-report.json",
    "rag-report.md",
    "rag-evidence-ledger.json",
    "rag-replay.json",
    "campaign-report.json",
    "campaign-report.md",
    "campaign-trace.json",
    "campaign-risk-card.md",
    "campaign-evidence-ledger.json",
    "campaign-replay.json",
    "coverage.md",
    "coverage.html",
    "safety-tuning-report.json",
    "safety-tuning-report.md",
    "risk-surface.html",
    "recommended-target.yaml",
    "unsafe-regions.json",
    "anomaly-report.json",
    "anomaly-report.md",
    "benchmark-plan.json",
    "benchmark-plan.md",
    "leaderboard.json",
    "leaderboard.md",
    "panel.yaml",
    "threat-model.yaml",
    "compound-risk-report.json",
    "compound-risk-report.md",
    "compound-risk-report.html",
    "issue-export.json",
    "remediation-board.md",
}

_KNOWN_ARTIFACT_PREFIXES = ("patch-suggestions-", "replay-")


class EvidenceBundleSummary(BaseModel):
    run_reports: int = 0
    mutation_reports: int = 0
    agent_reports: int = 0
    hidden_reports: int = 0
    diff_reports: int = 0
    artifact_reports: int = 0
    visual_reports: int = 0
    rag_reports: int = 0
    campaign_reports: int = 0
    coverage_reports: int = 0
    threat_models: int = 0
    safety_reports: int = 0
    anomaly_reports: int = 0
    benchmark_reports: int = 0
    patch_reports: int = 0
    replay_reports: int = 0
    total_eval_items: int = 0
    failed_eval_items: int = 0
    score_total: int = 0
    max_score_total: int = 0
    worst_mutation_delta: int = 0
    agent_violations: int = 0
    hidden_findings: int = 0
    diff_newly_failing: int = 0
    adjudication_records: int = 0
    adjudication_false_positives: int = 0
    adjudication_open_findings: int = 0
    artifact_findings: int = 0
    visual_findings: int = 0
    rag_detections: int = 0
    campaign_failed_steps: int = 0
    coverage_missing_cells: int = 0
    safety_unsafe_regions: int = 0
    anomaly_findings: int = 0
    compound_scenarios: int = 0
    compound_high_risks: int = 0
    issue_reports: int = 0
    remediation_boards: int = 0
    exported_issues: int = 0


class EvidenceCard(BaseModel):
    label: str
    value: str
    detail: str = ""
    tone: str = "neutral"


class RunCard(BaseModel):
    run_id: str
    model: str
    score_label: str
    pass_label: str
    failed_items: int
    source_path: str


class EvidenceBundle(BaseModel):
    title: str
    summary: EvidenceBundleSummary
    risk_cards: list[EvidenceCard] = Field(default_factory=list)
    run_cards: list[RunCard] = Field(default_factory=list)
    mutation_cards: list[EvidenceCard] = Field(default_factory=list)
    agent_cards: list[EvidenceCard] = Field(default_factory=list)
    hidden_cards: list[EvidenceCard] = Field(default_factory=list)
    diff_cards: list[EvidenceCard] = Field(default_factory=list)
    adjudication_cards: list[EvidenceCard] = Field(default_factory=list)
    artifact_cards: list[EvidenceCard] = Field(default_factory=list)
    visual_cards: list[EvidenceCard] = Field(default_factory=list)
    rag_cards: list[EvidenceCard] = Field(default_factory=list)
    campaign_cards: list[EvidenceCard] = Field(default_factory=list)
    coverage_cards: list[EvidenceCard] = Field(default_factory=list)
    threat_model_cards: list[EvidenceCard] = Field(default_factory=list)
    safety_cards: list[EvidenceCard] = Field(default_factory=list)
    anomaly_cards: list[EvidenceCard] = Field(default_factory=list)
    benchmark_cards: list[EvidenceCard] = Field(default_factory=list)
    patch_cards: list[EvidenceCard] = Field(default_factory=list)
    replay_cards: list[EvidenceCard] = Field(default_factory=list)
    compound_cards: list[EvidenceCard] = Field(default_factory=list)
    issue_cards: list[EvidenceCard] = Field(default_factory=list)
    compatibility_notes: list[str] = Field(default_factory=list)
    model_risk_card_links: list[str] = Field(default_factory=list)


class AuditArtifact(BaseModel):
    path: str
    sha256: str
    size_bytes: int
    artifact_type: str
    redaction_status: str = "hashed_only"


class AuditRiskEntry(BaseModel):
    risk_id: str
    source: str
    severity: str
    title: str
    status: str
    evidence: list[str] = Field(default_factory=list)
    recommendation: str


class AuditRemediationEntry(BaseModel):
    finding_id: str
    severity: str
    status: str
    action: str
    command: str
    evidence: list[str] = Field(default_factory=list)


class AuditBundle(BaseModel):
    title: str
    summary: dict[str, Any]
    coverage_summary: dict[str, Any] = Field(default_factory=dict)
    gate_decisions: list[dict[str, str]] = Field(default_factory=list)
    reviewer_log: list[dict[str, str]] = Field(default_factory=list)
    artifacts: list[AuditArtifact] = Field(default_factory=list)
    risk_register: list[AuditRiskEntry] = Field(default_factory=list)
    remediation_table: list[AuditRemediationEntry] = Field(default_factory=list)


def _load(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _load_yaml(path: str | Path) -> dict[str, Any]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return data if isinstance(data, dict) else {}


def _html_safe(value: object) -> str:
    text = _sanitize_text(value)
    return escape(text)


def _sanitize_text(value: object, *, limit: int = 500) -> str:
    text = _SPACE_RE.sub(" ", str(value)).strip()
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(lambda match: _redaction_label(match.group(0)), text)
    for pattern in _UNSAFE_PATTERNS:
        text = pattern.sub(lambda match: _redaction_label(match.group(0), kind="unsafe"), text)
    return text[:limit] + ("..." if len(text) > limit else "")


def _md_safe(value: object) -> str:
    return _sanitize_text(value).replace("&", "&amp;").replace("<", "&lt;").replace("\r", " ").replace("\n", " ").replace("|", r"\|").replace("`", r"\`").replace("#", r"\#")


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _redaction_label(value: str, *, kind: str = "sensitive") -> str:
    return f"[REDACTED] {kind} sha256={_sha256_text(value)[:16]} length={len(value)}"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_relpath(path: Path, base: Path) -> str:
    resolved = path.resolve()
    try:
        raw = str(resolved.relative_to(base.resolve()))
    except ValueError:
        raw = path.name
    return _sanitize_text(raw.replace("\\", "/"), limit=240)


def _display_path(path: str | Path) -> str:
    return _sanitize_text(Path(path).name, limit=240)


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists() or not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _pct(score: int, max_score: int) -> float:
    return 0.0 if max_score == 0 else (score / max_score) * 100


def _int(value: object, default: int = 0) -> int:
    try:
        return int(value or default)
    except (TypeError, ValueError):
        return default


def _float(value: object, default: float = 0.0) -> float:
    try:
        return float(value or default)
    except (TypeError, ValueError):
        return default


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _items(value: object) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _as_paths(paths: list[str | Path] | None) -> list[Path]:
    return [Path(path) for path in paths or []]


def _artifact_type(path: Path) -> str:
    return path.name.removesuffix(".json").removesuffix(".md").removesuffix(".html").removesuffix(".yaml").replace("-", "_")


def _is_known_artifact(path: Path) -> bool:
    return path.name in _KNOWN_ARTIFACT_NAMES or any(path.name.startswith(prefix) for prefix in _KNOWN_ARTIFACT_PREFIXES)


def _collect_artifact_paths(paths: list[str | Path] | None) -> list[Path]:
    collected: dict[Path, Path] = {}
    for raw in paths or []:
        path = Path(raw)
        if path.exists() and path.is_file():
            collected[path.resolve()] = path
            directory = path.parent
        else:
            directory = path if path.is_dir() else path.parent
        if directory.exists():
            for child in sorted(directory.iterdir(), key=lambda item: item.name):
                if child.is_file() and _is_known_artifact(child):
                    collected[child.resolve()] = child
    return [collected[key] for key in sorted(collected, key=lambda item: str(item))]


def _artifact_index(paths: list[Path], base: Path) -> list[AuditArtifact]:
    artifacts: list[AuditArtifact] = []
    for path in paths:
        if not path.exists() or not path.is_file():
            continue
        artifacts.append(
            AuditArtifact(
                path=_safe_relpath(path, base),
                sha256=_sha256_file(path),
                size_bytes=path.stat().st_size,
                artifact_type=_artifact_type(path),
            )
        )
    return artifacts


def _artifact_link(path: str) -> str:
    return _html_safe(path)


def _risk_id(*parts: object) -> str:
    return "risk-" + _sha256_text("|".join(_sanitize_text(part, limit=120) for part in parts))[:12]


def _finding_entries(path: Path, data: dict[str, Any], base: Path) -> tuple[list[AuditRiskEntry], list[AuditRemediationEntry]]:
    risks: list[AuditRiskEntry] = []
    remediations: list[AuditRemediationEntry] = []
    artifact = _safe_relpath(path, base)
    for finding in data.get("findings", []) if isinstance(data.get("findings"), list) else []:
        if not isinstance(finding, dict):
            continue
        finding_id = _sanitize_text(finding.get("finding_id") or "unknown-finding", limit=120)
        severity = _sanitize_text(finding.get("severity") or "unknown", limit=40)
        status = "needs_review"
        risks.append(
            AuditRiskEntry(
                risk_id=_risk_id("finding", finding_id),
                source="finding",
                severity=severity,
                title=_sanitize_text(finding.get("title") or finding_id, limit=220),
                status=status,
                evidence=[artifact],
                recommendation=_sanitize_text(finding.get("patch_recommendation") or "Review and patch this finding before release.", limit=360),
            )
        )
        remediations.append(
            AuditRemediationEntry(
                finding_id=finding_id,
                severity=severity,
                status=status,
                action=_sanitize_text(finding.get("patch_recommendation") or "Generate defensive patch suggestions and replay locally.", limit=360),
                command=f"malleus patch suggest --finding {finding_id} --report <report-dir-or-findings.json> --out <patch-output-dir>",
                evidence=[artifact],
            )
        )
    return risks, remediations


def _gate_entries(path: Path, data: dict[str, Any], base: Path) -> list[AuditRiskEntry]:
    status = _sanitize_text(data.get("status") or "unknown", limit=40)
    if status in {"pass", "unknown"}:
        return []
    reasons = data.get("reasons") if isinstance(data.get("reasons"), list) else []
    title = "; ".join(_sanitize_text(reason, limit=120) for reason in reasons[:3]) or f"Gate decision: {status}"
    return [
        AuditRiskEntry(
            risk_id=_risk_id("gate", path.name, status, title),
            source="gate",
            severity="high" if status == "fail" else "medium",
            title=title,
            status=status,
            evidence=[_safe_relpath(path, base)],
            recommendation="Resolve blocking gate reasons or document accepted risk before release.",
        )
    ]


def _coverage_entries(path: Path, data: dict[str, Any], base: Path) -> list[AuditRiskEntry]:
    risks: list[AuditRiskEntry] = []
    artifact = _safe_relpath(path, base)
    for cell in data.get("cells", []) if isinstance(data.get("cells"), list) else []:
        if not isinstance(cell, dict):
            continue
        status = str(cell.get("status") or "unknown")
        if status == "covered":
            continue
        title = f"{cell.get('source_surface', 'unknown')}/{cell.get('technique', 'unknown')}/{cell.get('expected_boundary', 'unknown')}"
        risks.append(
            AuditRiskEntry(
                risk_id=_risk_id("coverage", title, status),
                source="coverage",
                severity="medium" if status == "missing" else "low",
                title=_sanitize_text(title, limit=220),
                status=_sanitize_text(status, limit=40),
                evidence=[artifact],
                recommendation=_sanitize_text(cell.get("missing_reason") or "Add local evidence for this coverage cell.", limit=260),
            )
        )
    return risks


def _adjudication_entries(path: Path, data: dict[str, Any], base: Path) -> tuple[list[AuditRiskEntry], list[dict[str, str]]]:
    risks: list[AuditRiskEntry] = []
    reviewers: list[dict[str, str]] = []
    artifact = _safe_relpath(path, base)
    for record in data.get("records", []) if isinstance(data.get("records"), list) else []:
        if not isinstance(record, dict):
            continue
        status = _sanitize_text(record.get("status") or "unknown", limit=60)
        finding_id = _sanitize_text(record.get("finding_id") or "unknown-finding", limit=120)
        reviewers.append(
            {
                "finding_id": finding_id,
                "status": status,
                "reviewer": _sanitize_text(record.get("reviewer") or "n/a", limit=120),
                "reason_code": _sanitize_text(record.get("reason_code") or "n/a", limit=120),
                "timestamp": _sanitize_text(record.get("timestamp") or "n/a", limit=80),
            }
        )
        if status in {"confirmed", "needs_review", "accepted_risk"}:
            risks.append(
                AuditRiskEntry(
                    risk_id=_risk_id("adjudication", finding_id, status),
                    source="adjudication",
                    severity="high" if status == "confirmed" else "medium",
                    title=f"Adjudication status for {finding_id}",
                    status=status,
                    evidence=[artifact],
                    recommendation="Close, fix, or explicitly accept this adjudicated risk before release.",
                )
            )
    return risks, reviewers


def build_audit_bundle(bundle: EvidenceBundle, artifact_paths: list[str | Path] | None = None, *, output_dir: str | Path = ".") -> AuditBundle:
    base = Path(output_dir).resolve()
    paths = _collect_artifact_paths(artifact_paths)
    artifacts = _artifact_index(paths, base)
    risks: list[AuditRiskEntry] = []
    remediations: list[AuditRemediationEntry] = []
    reviewer_log: list[dict[str, str]] = []
    gate_decisions: list[dict[str, str]] = []
    coverage_summary: dict[str, Any] = {}

    for path in paths:
        data = _load_json(path)
        if data is None:
            continue
        if path.name == "findings.json":
            finding_risks, finding_remediations = _finding_entries(path, data, base)
            risks.extend(finding_risks)
            remediations.extend(finding_remediations)
        elif path.name == "risk-summary.json":
            status = _sanitize_text(data.get("status") or "unknown", limit=40)
            gate_decisions.append({"path": _safe_relpath(path, base), "status": status})
            risks.extend(_gate_entries(path, data, base))
        elif path.name == "coverage.json":
            summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
            coverage_summary = {str(key): _sanitize_text(value, limit=80) for key, value in summary.items()}
            risks.extend(_coverage_entries(path, data, base))
        elif path.name == "adjudications.json":
            adjudication_risks, reviewers = _adjudication_entries(path, data, base)
            risks.extend(adjudication_risks)
            reviewer_log.extend(reviewers)
        elif path.name in {"mutation-report.json", "diff-runs-report.json", "trace-diff-report.json"}:
            summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
            if int(summary.get("worst_delta", 0) or 0) < 0 or int(summary.get("newly_failing", 0) or summary.get("regressions", 0) or 0) > 0:
                risks.append(
                    AuditRiskEntry(
                        risk_id=_risk_id("statistical", path.name, summary),
                        source="repeated_or_regression",
                        severity="medium",
                        title=f"Repeated or regression risk from {path.name}",
                        status="needs_review",
                        evidence=[_safe_relpath(path, base)],
                        recommendation="Review repeated-run, mutation, or regression deltas before release.",
                    )
                )
        elif path.name == "artifact-firewall-report.json":
            recommendation = _sanitize_text(data.get("recommendation") or "unknown", limit=60)
            findings = _items(data.get("findings"))
            if recommendation in {"warn", "quarantine", "block"} or findings:
                risks.append(
                    AuditRiskEntry(
                        risk_id=_risk_id("artifact", path.name, recommendation, len(findings)),
                        source="artifact_firewall",
                        severity="high" if recommendation in {"quarantine", "block"} else "medium",
                        title=f"Artifact firewall recommendation: {recommendation}",
                        status=recommendation,
                        evidence=[_safe_relpath(path, base)],
                        recommendation="Review artifact metadata/surface findings before routing artifacts into trusted model context.",
                    )
                )
        elif path.name in {"visual-lab-report.json", "visual-run-report.json"}:
            report_summary = _dict(data.get("summary"))
            gate = _sanitize_text(data.get("gate_recommendation") or report_summary.get("gate_decision") or "unknown", limit=60)
            findings = _int(report_summary.get("total_findings"))
            if gate in {"warn", "quarantine", "block", "scaffold"} or findings:
                risks.append(
                    AuditRiskEntry(
                        risk_id=_risk_id("visual", path.name, gate, findings),
                        source="visual_lab",
                        severity="high" if gate in {"quarantine", "block"} else "medium",
                        title=f"Visual lab gate: {gate}; findings={findings}",
                        status=gate,
                        evidence=[_safe_relpath(path, base)],
                        recommendation="Keep visual/OCR/metadata surfaces untrusted; review safe-context hashes and redacted refs only.",
                    )
                )
        elif path.name == "rag-report.json":
            report_summary = _dict(data.get("summary"))
            detections = _int(report_summary.get("detections"))
            failing = _int(report_summary.get("failing_queries"))
            if detections or failing:
                risks.append(
                    AuditRiskEntry(
                        risk_id=_risk_id("rag", path.name, detections, failing),
                        source="rag",
                        severity="high" if failing else "medium",
                        title=f"RAG detections={detections}; failing_queries={failing}",
                        status="needs_review",
                        evidence=[_safe_relpath(path, base)],
                        recommendation="Review RAG tenant/citation detections using hashes, evidence refs, and replay artifacts.",
                    )
                )
        elif path.name == "campaign-report.json":
            report_summary = _dict(data.get("summary"))
            failed = _int(report_summary.get("failed_steps"))
            blocked = _int(report_summary.get("blocked_steps"))
            if failed or blocked:
                risks.append(
                    AuditRiskEntry(
                        risk_id=_risk_id("campaign", path.name, failed, blocked),
                        source="campaign",
                        severity="high" if blocked else "medium",
                        title=f"Campaign failed_steps={failed}; blocked_steps={blocked}",
                        status="needs_review",
                        evidence=[_safe_relpath(path, base)],
                        recommendation="Review campaign gates, policy decisions, and replay refs before release.",
                    )
                )
        elif path.name == "safety-tuning-report.json":
            unsafe = len(_items(data.get("unsafe_regions")))
            if unsafe:
                risks.append(
                    AuditRiskEntry(
                        risk_id=_risk_id("safety", path.name, unsafe),
                        source="safety_tuner",
                        severity="medium",
                        title=f"Safety tuner unsafe regions: {unsafe}",
                        status="needs_review",
                        evidence=[_safe_relpath(path, base)],
                        recommendation="Use recommended target settings or explicitly review unsafe decoding regions.",
                    )
                )
        elif path.name == "anomaly-report.json":
            report_summary = _dict(data.get("summary"))
            gate = _sanitize_text(data.get("gate_recommendation") or report_summary.get("highest_severity") or "none", limit=60)
            findings = _int(report_summary.get("total_findings"))
            if gate in {"warn", "quarantine", "block"} or findings:
                risks.append(
                    AuditRiskEntry(
                        risk_id=_risk_id("anomaly", path.name, gate, findings),
                        source="anomaly",
                        severity="high" if gate in {"quarantine", "block"} else "medium",
                        title=f"Anomaly gate: {gate}; findings={findings}",
                        status=gate,
                        evidence=[_safe_relpath(path, base)],
                        recommendation="Sanitize transcript/replay boundaries before feeding this output into future runs.",
                    )
                )
        elif path.name == "issue-export.json":
            issues = _items(data.get("issues"))
            for issue in issues:
                finding_id = _sanitize_text(issue.get("finding_id") or issue.get("issue_id") or "unknown-finding", limit=120)
                commands = issue.get("regression_commands") if isinstance(issue.get("regression_commands"), list) else []
                remediations.append(
                    AuditRemediationEntry(
                        finding_id=finding_id,
                        severity=_sanitize_text(issue.get("severity") or "unknown", limit=40),
                        status="needs_review",
                        action=_sanitize_text(issue.get("patch_suggestion") or "Review local issue export and close acceptance tests.", limit=360),
                        command=_sanitize_text(commands[0] if commands else issue.get("reproduction_command") or "malleus issues export --findings <findings.json> --out-dir <issues-dir>", limit=360),
                        evidence=[_safe_relpath(path, base)],
                    )
                )
        elif path.name.startswith("patch-suggestions-"):
            finding_id = _sanitize_text(data.get("finding_id") or path.stem, limit=120)
            commands = data.get("regression_commands") if isinstance(data.get("regression_commands"), list) else []
            remediations.append(
                AuditRemediationEntry(
                    finding_id=finding_id,
                    severity="info",
                    status="suggested",
                    action="Review defensive patch suggestion artifacts and run local regression commands.",
                    command=_sanitize_text(commands[0] if commands else "malleus patch suggest --finding <finding-id> --report <report-dir-or-findings.json> --out <patch-output-dir>", limit=360),
                    evidence=[_safe_relpath(path, base)],
                )
            )
        elif path.name.startswith("replay-") or path.name in {"rag-replay.json", "campaign-replay.json", "replay-spec.json"}:
            remediations.append(
                AuditRemediationEntry(
                    finding_id=_sanitize_text(data.get("finding_id") or data.get("run_id") or path.stem, limit=120),
                    severity="info",
                    status="replay_available",
                    action="Replay dry-run or local fixture plan is indexed for analyst reproduction.",
                    command=_sanitize_text(data.get("command") or "malleus replay <finding-id> --report <report-dir-or-findings.json> --dry-run", limit=360),
                    evidence=[_safe_relpath(path, base)],
                )
            )

    if not remediations:
        remediations.append(
            AuditRemediationEntry(
                finding_id="workspace",
                severity="info",
                status="recommended",
                action="Collect findings, coverage, gates, adjudications, and patch suggestions as local artifacts.",
                command="malleus replay <finding-id> --report <report-dir-or-findings.json> --dry-run",
            )
        )

    return AuditBundle(
        title=bundle.title,
        summary={
            "run_reports": bundle.summary.run_reports,
            "failed_eval_items": bundle.summary.failed_eval_items,
            "agent_violations": bundle.summary.agent_violations,
            "hidden_findings": bundle.summary.hidden_findings,
            "new_regressions": bundle.summary.diff_newly_failing,
            "adjudication_records": bundle.summary.adjudication_records,
            "artifact_findings": bundle.summary.artifact_findings,
            "visual_findings": bundle.summary.visual_findings,
            "rag_detections": bundle.summary.rag_detections,
            "campaign_failed_steps": bundle.summary.campaign_failed_steps,
            "coverage_missing_cells": bundle.summary.coverage_missing_cells,
            "safety_unsafe_regions": bundle.summary.safety_unsafe_regions,
            "anomaly_findings": bundle.summary.anomaly_findings,
            "exported_issues": bundle.summary.exported_issues,
        },
        coverage_summary=coverage_summary,
        gate_decisions=gate_decisions,
        reviewer_log=reviewer_log,
        artifacts=artifacts,
        risk_register=risks,
        remediation_table=remediations,
    )


def _card(label: str, value: object, detail: str = "", tone: str = "neutral") -> EvidenceCard:
    return EvidenceCard(label=label, value=str(value), detail=detail, tone=tone)


def build_evidence_bundle(
    *,
    title: str = "Malleus Evidence Bundle",
    run_reports: list[str | Path] | None = None,
    mutation_reports: list[str | Path] | None = None,
    agent_reports: list[str | Path] | None = None,
    hidden_reports: list[str | Path] | None = None,
    diff_reports: list[str | Path] | None = None,
    artifact_reports: list[str | Path] | None = None,
    visual_reports: list[str | Path] | None = None,
    rag_reports: list[str | Path] | None = None,
    campaign_reports: list[str | Path] | None = None,
    coverage_reports: list[str | Path] | None = None,
    threat_models: list[str | Path] | None = None,
    safety_reports: list[str | Path] | None = None,
    anomaly_reports: list[str | Path] | None = None,
    benchmark_reports: list[str | Path] | None = None,
    benchmark_panels: list[str | Path] | None = None,
    patch_reports: list[str | Path] | None = None,
    replay_reports: list[str | Path] | None = None,
    compound_reports: list[str | Path] | None = None,
    issue_reports: list[str | Path] | None = None,
    remediation_boards: list[str | Path] | None = None,
) -> EvidenceBundle:
    summary = EvidenceBundleSummary(
        run_reports=len(run_reports or []),
        mutation_reports=len(mutation_reports or []),
        agent_reports=len(agent_reports or []),
        hidden_reports=len(hidden_reports or []),
        diff_reports=len(diff_reports or []),
        artifact_reports=len(artifact_reports or []),
        visual_reports=len(visual_reports or []),
        rag_reports=len(rag_reports or []),
        campaign_reports=len(campaign_reports or []),
        coverage_reports=len(coverage_reports or []),
        threat_models=len(threat_models or []),
        safety_reports=len(safety_reports or []),
        anomaly_reports=len(anomaly_reports or []),
        benchmark_reports=len(benchmark_reports or []) + len(benchmark_panels or []),
        patch_reports=len(patch_reports or []),
        replay_reports=len(replay_reports or []),
        issue_reports=len(issue_reports or []),
        remediation_boards=len(remediation_boards or []),
    )
    run_cards: list[RunCard] = []
    mutation_cards: list[EvidenceCard] = []
    agent_cards: list[EvidenceCard] = []
    hidden_cards: list[EvidenceCard] = []
    diff_cards: list[EvidenceCard] = []
    adjudication_cards: list[EvidenceCard] = []
    artifact_cards: list[EvidenceCard] = []
    visual_cards: list[EvidenceCard] = []
    rag_cards: list[EvidenceCard] = []
    campaign_cards: list[EvidenceCard] = []
    coverage_cards: list[EvidenceCard] = []
    threat_model_cards: list[EvidenceCard] = []
    safety_cards: list[EvidenceCard] = []
    anomaly_cards: list[EvidenceCard] = []
    benchmark_cards: list[EvidenceCard] = []
    patch_cards: list[EvidenceCard] = []
    replay_cards: list[EvidenceCard] = []
    compound_cards: list[EvidenceCard] = []
    issue_cards: list[EvidenceCard] = []
    model_risk_card_links: list[str] = []

    for path in _as_paths(run_reports):
        report = _load(path)
        run_summary = report.get("summary", {})
        total = int(run_summary.get("total_items", 0))
        failed = int(run_summary.get("failed_items", 0))
        passed = int(run_summary.get("passed_items", 0))
        score = int(run_summary.get("score_total", 0))
        max_score = int(run_summary.get("max_score_total", 0))
        summary.total_eval_items += total
        summary.failed_eval_items += failed
        summary.score_total += score
        summary.max_score_total += max_score
        risk_card_path = Path(path).parent / "model-risk-card.md"
        if risk_card_path.exists():
            model_risk_card_links.append(_display_path(risk_card_path))
        adjudication_path = Path(path).parent / "adjudications.json"
        if adjudication_path.exists():
            adjudication = _load(adjudication_path)
            adjudication_summary = adjudication.get("summary", {}) if isinstance(adjudication.get("summary"), dict) else {}
            records = int(adjudication_summary.get("total_records", 0))
            false_positives = int(adjudication_summary.get("false_positive_findings", 0))
            open_findings = int(adjudication_summary.get("open_findings", 0))
            summary.adjudication_records += records
            summary.adjudication_false_positives += false_positives
            summary.adjudication_open_findings += open_findings
            adjudication_cards.append(
                _card(
                    "Human adjudication",
                    f"{records} records",
                    f"false_positive={false_positives}, open={open_findings}, source={_display_path(adjudication_path)}",
                    "warning" if false_positives else "neutral",
                )
            )
        run_cards.append(
            RunCard(
                run_id=str(report.get("run_id", "unknown")),
                model=str(report.get("target_model", "unknown")),
                score_label=f"{score}/{max_score}",
                pass_label=f"{passed}/{total}",
                failed_items=failed,
                source_path=_display_path(path),
            )
        )

    worst_delta: int | None = None
    for path in _as_paths(mutation_reports):
        report = _load(path)
        mut_summary = report.get("summary", {})
        delta = int(mut_summary.get("worst_delta", 0))
        worst_delta = delta if worst_delta is None else min(worst_delta, delta)
        mutation_cards.append(
            _card(
                "Worst mutation",
                mut_summary.get("worst_mutation") or "n/a",
                f"delta={delta}, mutated_items={mut_summary.get('total_mutated_items', 0)}",
                "danger" if delta < 0 else "ok",
            )
        )
    summary.worst_mutation_delta = worst_delta or 0

    for path in _as_paths(agent_reports):
        report = _load(path)
        agent_summary = report.get("summary", {})
        violations = int(agent_summary.get("violations", 0))
        summary.agent_violations += violations
        agent_cards.append(
            _card(
                "Agent lab",
                f"{violations} violations",
                f"highest_risk={agent_summary.get('highest_risk') or 'n/a'}, scenarios={agent_summary.get('total_scenarios', 0)}",
                "danger" if violations else "ok",
            )
        )

    for path in _as_paths(hidden_reports):
        report = _load(path)
        hidden_summary = report.get("summary", {})
        findings = int(hidden_summary.get("total_findings", 0))
        summary.hidden_findings += findings
        hidden_cards.append(
            _card(
                "Hidden-channel hygiene",
                f"{findings} findings",
                f"highest={hidden_summary.get('highest_severity', 'none')}, source={report.get('source', path)}",
                "warning" if findings else "ok",
            )
        )

    for path in _as_paths(diff_reports):
        report = _load(path)
        diff_summary = report.get("summary", {})
        if "regressions" in diff_summary and "total_deltas" in diff_summary:
            failing = int(diff_summary.get("regressions", 0))
            summary.diff_newly_failing += failing
            diff_cards.append(
                _card(
                    "Trace diff",
                    f"{failing} high/critical regressions",
                    f"deltas={diff_summary.get('total_deltas', 0)}, critical={diff_summary.get('critical', 0)}, high={diff_summary.get('high', 0)}",
                    "danger" if failing else "ok",
                )
            )
            continue
        failing = int(diff_summary.get("newly_failing", 0))
        summary.diff_newly_failing += failing
        diff_cards.append(
            _card(
                "Regression diff",
                f"{failing} newly failing",
                f"score_delta={diff_summary.get('score_delta', 0)}, pass_rate_delta={diff_summary.get('pass_rate_delta', 0)}%",
                "danger" if failing else "ok",
            )
        )

    for path in _as_paths(artifact_reports):
        report = _load(path)
        findings = _items(report.get("findings"))
        surfaces = _items(report.get("surfaces"))
        manifest = _dict(report.get("manifest"))
        recommendation = _sanitize_text(report.get("recommendation") or "unknown", limit=60)
        summary.artifact_findings += len(findings)
        artifact_cards.append(
            _card(
                "Artifact firewall",
                recommendation,
                f"findings={len(findings)}, surfaces={len(surfaces)}, format={manifest.get('format', 'unknown')}",
                "danger" if recommendation in {"block", "quarantine"} else ("warning" if findings or recommendation == "warn" else "ok"),
            )
        )

    for path in _as_paths(visual_reports):
        report = _load(path)
        visual_summary = _dict(report.get("summary"))
        findings = _int(visual_summary.get("total_findings"))
        if not findings:
            findings = sum(len(_items(result.get("visual_lab_findings"))) + len(_items(result.get("artifact_firewall_findings"))) for result in _items(report.get("results")))
        summary.visual_findings += findings
        gate = _sanitize_text(report.get("gate_recommendation") or visual_summary.get("gate_recommendation") or _dict(visual_summary).get("gate_decision") or "unknown", limit=60)
        inspected = visual_summary.get("inspected_scenarios", visual_summary.get("total_scenarios", "n/a"))
        total = visual_summary.get("total_scenarios", inspected)
        visual_cards.append(
            _card(
                "Visual lab",
                f"{findings} findings",
                f"gate={gate}, scenarios={inspected}/{total}, safe_context={visual_summary.get('safe_context_records', 'n/a')}",
                "danger" if gate in {"block", "quarantine"} else ("warning" if findings or gate == "warn" else "ok"),
            )
        )

    for path in _as_paths(rag_reports):
        report = _load(path)
        rag_summary = _dict(report.get("summary"))
        detections = _int(rag_summary.get("detections"))
        failing = _int(rag_summary.get("failing_queries"))
        total = _int(rag_summary.get("total_queries"))
        summary.rag_detections += detections
        rag_cards.append(
            _card(
                "RAG harness",
                f"{detections} detections",
                f"failing_queries={failing}/{total}, mode={report.get('mode', 'unknown')}, replay_refs={len(report.get('replay_refs', []) if isinstance(report.get('replay_refs'), list) else [])}",
                "danger" if failing else ("warning" if detections else "ok"),
            )
        )

    for path in _as_paths(campaign_reports):
        report = _load(path)
        campaign_summary = _dict(report.get("summary"))
        failed = _int(campaign_summary.get("failed_steps"))
        blocked = _int(campaign_summary.get("blocked_steps"))
        total = _int(campaign_summary.get("total_steps"))
        summary.campaign_failed_steps += failed
        campaign_cards.append(
            _card(
                "Campaign",
                f"{failed} failed steps",
                f"blocked={blocked}, total={total}, mode={report.get('mode', 'unknown')}, replay_seed={report.get('replay_seed', 'n/a')}",
                "danger" if blocked else ("warning" if failed else "ok"),
            )
        )

    for path in _as_paths(coverage_reports):
        report = _load(path)
        coverage_summary = _dict(report.get("summary"))
        covered = _int(coverage_summary.get("covered_cells"))
        total = _int(coverage_summary.get("total_cells"))
        partial = _int(coverage_summary.get("partial_cells"))
        missing = _int(coverage_summary.get("missing_cells"))
        summary.coverage_missing_cells += missing
        coverage_cards.append(
            _card(
                "Coverage matrix",
                f"{covered}/{total} covered",
                f"partial={partial}, missing={missing}, evidence_refs={coverage_summary.get('evidence_refs', 0)}",
                "danger" if missing else ("warning" if partial else "ok"),
            )
        )

    for path in _as_paths(threat_models):
        model = _load_yaml(path)
        missing = len(_items(model.get("missing_coverage")))
        threat_model_cards.append(
            _card(
                "Threat model",
                model.get("known_coverage_status") or "not_evaluated",
                f"profile={model.get('profile', 'unknown')}, required_cells={len(_items(model.get('required_cells')))}, missing={missing}",
                "warning" if missing else "neutral",
            )
        )

    for path in _as_paths(safety_reports):
        report = _load(path)
        safety_summary = _dict(report.get("summary"))
        unsafe = len(_items(report.get("unsafe_regions")))
        summary.safety_unsafe_regions += unsafe
        safety_cards.append(
            _card(
                "Safety tuner",
                f"{unsafe} unsafe regions",
                f"strategy={report.get('strategy', 'grid')}, budget={report.get('budget', 'n/a')}, fail_rate={_float(safety_summary.get('fail_rate')):.3f}, recommended={report.get('recommended_config_id', 'n/a')}",
                "danger" if unsafe else "ok",
            )
        )

    for path in _as_paths(anomaly_reports):
        report = _load(path)
        anomaly_summary = _dict(report.get("summary"))
        findings = _int(anomaly_summary.get("total_findings"))
        gate = _sanitize_text(report.get("gate_recommendation") or anomaly_summary.get("highest_severity") or "none", limit=60)
        labels = anomaly_summary.get("labels") if isinstance(anomaly_summary.get("labels"), list) else []
        summary.anomaly_findings += findings
        anomaly_cards.append(
            _card(
                "Anomaly detector",
                f"{findings} findings",
                f"gate={gate}, labels={', '.join(_sanitize_text(label, limit=40) for label in labels[:4]) or 'none'}",
                "danger" if gate in {"block", "quarantine"} else ("warning" if findings else "ok"),
            )
        )

    for path in _as_paths(benchmark_reports):
        report = _load(path)
        if "steps" in report:
            steps = _items(report.get("steps"))
            models = report.get("models") if isinstance(report.get("models"), list) else []
            benchmark_cards.append(_card("Benchmark plan", f"{len(steps)} steps", f"models={len(models)}, provider_calls_enabled={report.get('provider_calls_enabled', False)}", "neutral"))
            continue
        leaderboard = report.get("leaderboard") if isinstance(report.get("leaderboard"), list) else []
        benchmark_cards.append(_card("Benchmark panel", f"{len(leaderboard)} rows", f"case_studies={len(report.get('case_studies', []) if isinstance(report.get('case_studies'), list) else [])}", "neutral"))

    for path in _as_paths(benchmark_panels):
        panel = _load_yaml(path)
        models = panel.get("models") if isinstance(panel.get("models"), list) else []
        benchmark_cards.append(_card("Benchmark panel", f"{len(models)} models", f"name={panel.get('name', 'unknown')}, version={panel.get('version', 'n/a')}", "neutral"))

    for path in _as_paths(patch_reports):
        report = _load(path)
        artifacts = report.get("artifacts") if isinstance(report.get("artifacts"), dict) else {}
        commands = report.get("regression_commands") if isinstance(report.get("regression_commands"), list) else []
        finding_id = _sanitize_text(report.get("finding_id") or Path(path).stem, limit=120)
        patch_cards.append(_card("Patch suggestions", finding_id, f"artifacts={len(artifacts)}, regression_commands={len(commands)}, disclaimer={report.get('disclaimer', 'n/a')}", "neutral"))
        for command in commands[:3]:
            replay_cards.append(_card("Patch regression command", "local", _sanitize_text(command, limit=260), "neutral"))

    for path in _as_paths(replay_reports):
        report = _load(path)
        command = _sanitize_text(report.get("command") or report.get("safe_command") or report.get("replay_command") or "see artifact", limit=260)
        replay_id = _sanitize_text(report.get("replay_id") or report.get("run_id") or Path(path).stem, limit=120)
        replay_cards.append(_card("Replay command", replay_id, f"mode={report.get('mode', 'dry_run')}, command={command}", "neutral"))

    for path in _as_paths(compound_reports):
        report = _load(path)
        compound_summary = _dict(report.get("summary"))
        scenarios = _int(compound_summary.get("total_scenarios"))
        highest = _sanitize_text(compound_summary.get("highest_risk") or "n/a", limit=40)
        counts = _dict(compound_summary.get("counts_by_risk"))
        high_risks = _int(counts.get("high")) + _int(counts.get("critical"))
        summary.compound_scenarios += scenarios
        summary.compound_high_risks += high_risks
        compound_cards.append(
            _card(
                "Compound risk",
                f"{scenarios} scenarios",
                f"highest={highest}, high_or_critical={high_risks}, surfaces={len(compound_summary.get('attack_surfaces', []) if isinstance(compound_summary.get('attack_surfaces'), list) else [])}",
                "danger" if highest in {"high", "critical"} else ("warning" if scenarios else "ok"),
            )
        )


    for path in _as_paths(issue_reports):
        report = _load(path)
        issues = _items(report.get("issues"))
        report_summary = _dict(report.get("summary"))
        total = _int(report_summary.get("total_issues"), len(issues))
        labels = _dict(report_summary.get("counts_by_label"))
        closure_count = sum(len(issue.get("closure_criteria") if isinstance(issue.get("closure_criteria"), list) else []) for issue in issues)
        summary.exported_issues += total
        issue_cards.append(
            _card(
                "Issue export",
                f"{total} issues",
                f"labels={len(labels)}, closure_criteria={closure_count}, github={report.get('github_creation_status', 'disabled')}",
                "warning" if total else "ok",
            )
        )

    for path in _as_paths(remediation_boards):
        text = Path(path).read_text(encoding="utf-8") if Path(path).exists() else ""
        issue_rows = max(0, text.count("| ["))
        issue_cards.append(_card("Remediation board", f"{issue_rows} rows", f"source={_display_path(path)}, closure criteria included", "warning" if issue_rows else "neutral"))

    risk_cards = [
        _card("Agent violations", summary.agent_violations, "synthetic tool-selection failures", "danger" if summary.agent_violations else "ok"),
        _card("Failed eval items", summary.failed_eval_items, f"across {summary.total_eval_items} items", "danger" if summary.failed_eval_items else "ok"),
        _card("Worst mutation delta", summary.worst_mutation_delta, "lower is worse", "danger" if summary.worst_mutation_delta < 0 else "ok"),
        _card("Hidden findings", summary.hidden_findings, "low-visibility artifact signals", "warning" if summary.hidden_findings else "ok"),
        _card("New regressions", summary.diff_newly_failing, "newly failing run-diff items or high/critical trace deltas", "danger" if summary.diff_newly_failing else "ok"),
        _card("Artifact findings", summary.artifact_findings, f"across {summary.artifact_reports} artifact firewall reports", "warning" if summary.artifact_findings else "ok"),
        _card("RAG detections", summary.rag_detections, f"across {summary.rag_reports} RAG reports", "danger" if summary.rag_detections else "ok"),
        _card("Safety unsafe regions", summary.safety_unsafe_regions, f"across {summary.safety_reports} safety reports", "warning" if summary.safety_unsafe_regions else "ok"),
        _card("Anomaly findings", summary.anomaly_findings, f"across {summary.anomaly_reports} anomaly reports", "danger" if summary.anomaly_findings else "ok"),
        _card("Compound scenarios", summary.compound_scenarios, f"{summary.compound_high_risks} high/critical heuristic scenarios", "danger" if summary.compound_high_risks else ("warning" if summary.compound_scenarios else "ok")),
        _card("Exported issues", summary.exported_issues, f"across {summary.issue_reports} issue exports and {summary.remediation_boards} boards", "warning" if summary.exported_issues else "neutral"),
        _card("False positives", summary.adjudication_false_positives, f"from {summary.adjudication_records} adjudication records", "warning" if summary.adjudication_false_positives else "neutral"),
        _card("Run reports", summary.run_reports, f"{summary.score_total}/{summary.max_score_total} total score", "neutral"),
    ]

    return EvidenceBundle(
        title=title,
        summary=summary,
        risk_cards=risk_cards,
        run_cards=run_cards,
        mutation_cards=mutation_cards,
        agent_cards=agent_cards,
        hidden_cards=hidden_cards,
        diff_cards=diff_cards,
        adjudication_cards=adjudication_cards,
        artifact_cards=artifact_cards,
        visual_cards=visual_cards,
        rag_cards=rag_cards,
        campaign_cards=campaign_cards,
        coverage_cards=coverage_cards,
        threat_model_cards=threat_model_cards,
        safety_cards=safety_cards,
        anomaly_cards=anomaly_cards,
        benchmark_cards=benchmark_cards,
        patch_cards=patch_cards,
        replay_cards=replay_cards,
        compound_cards=compound_cards,
        issue_cards=issue_cards,
        compatibility_notes=[],
        model_risk_card_links=model_risk_card_links,
    )


def _cards(cards: list[EvidenceCard]) -> str:
    if not cards:
        return "<p class='empty'>No artifact provided for this section.</p>"
    return "".join(
        f"<article class='metric {_html_safe(card.tone)}'><span>{_html_safe(card.label)}</span><strong>{_html_safe(card.value)}</strong><small>{_html_safe(card.detail)}</small></article>"
        for card in cards
    )


def _risk_card_links(paths: list[str]) -> str:
    if not paths:
        return "<p class='empty'>No model risk card artifacts found next to supplied run reports.</p>"
    return "<ul>" + "".join(f"<li>{_html_safe(path)}</li>" for path in paths) + "</ul>"


def _notes(notes: list[str]) -> str:
    if not notes:
        return "<p class='empty'>No compatibility notes.</p>"
    return "<ul>" + "".join(f"<li>{_html_safe(note)}</li>" for note in notes) + "</ul>"


def _run_table(cards: list[RunCard]) -> str:
    if not cards:
        return "<p class='empty'>No benchmark run reports provided.</p>"
    rows = []
    for card in cards:
        rows.append(
            "<tr>"
            f"<td>{_html_safe(card.run_id)}</td>"
            f"<td>{_html_safe(card.model)}</td>"
            f"<td>{_html_safe(card.score_label)}</td>"
            f"<td>{_html_safe(card.pass_label)}</td>"
            f"<td>{card.failed_items}</td>"
            f"<td>{_html_safe(card.source_path)}</td>"
            "</tr>"
        )
    return "<table><thead><tr><th>Run</th><th>Model</th><th>Score</th><th>Passed</th><th>Failed</th><th>Source</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"


def render_evidence_bundle_html(bundle: EvidenceBundle) -> str:
    title = _html_safe(bundle.title)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root {{ color-scheme: dark; --bg:#08090a; --panel:#0f1011; --surface:#191a1b; --line:rgba(255,255,255,.08); --text:#f7f8f8; --muted:#8a8f98; --soft:#d0d6e0; --accent:#7170ff; --danger:#ef4444; --warning:#f59e0b; --ok:#10b981; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; font-feature-settings:'cv01','ss03'; background:radial-gradient(circle at 20% 0%, rgba(113,112,255,.18), transparent 30%), var(--bg); color:var(--text); }}
main {{ max-width:1220px; margin:0 auto; padding:42px 22px 64px; }}
.hero {{ border:1px solid var(--line); background:linear-gradient(180deg, rgba(255,255,255,.045), rgba(255,255,255,.018)); border-radius:24px; padding:32px; box-shadow:0 30px 120px rgba(0,0,0,.34); }}
.eyebrow {{ color:var(--accent); font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:12px; letter-spacing:.08em; text-transform:uppercase; }}
h1 {{ font-size:clamp(34px,6vw,68px); line-height:1; letter-spacing:-1.2px; font-weight:500; margin:12px 0; }}
.subtitle {{ color:var(--muted); max-width:820px; font-size:17px; line-height:1.65; }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:14px; margin:22px 0 34px; }}
.metric {{ border:1px solid var(--line); background:rgba(255,255,255,.025); border-radius:16px; padding:16px; min-height:118px; }}
.metric span {{ display:block; color:var(--muted); font-size:13px; }}
.metric strong {{ display:block; margin:10px 0 6px; font-size:26px; letter-spacing:-.04em; }}
.metric small {{ color:var(--soft); font-size:12px; line-height:1.45; }}
.metric.danger {{ border-color:rgba(239,68,68,.36); }} .metric.warning {{ border-color:rgba(245,158,11,.34); }} .metric.ok {{ border-color:rgba(16,185,129,.32); }}
section {{ margin-top:34px; }}
h2 {{ font-size:24px; font-weight:510; letter-spacing:-.3px; margin:0 0 14px; }}
.panel {{ border:1px solid var(--line); background:rgba(15,16,17,.82); border-radius:18px; padding:18px; overflow:hidden; }}
table {{ width:100%; border-collapse:collapse; font-size:13px; }} th,td {{ border-bottom:1px solid rgba(255,255,255,.06); padding:11px 10px; text-align:left; vertical-align:top; }} th {{ color:var(--soft); font-weight:510; background:rgba(255,255,255,.025); }} td {{ color:#e5e7eb; }}
.empty {{ color:var(--muted); margin:0; }}
footer {{ color:var(--muted); margin-top:38px; font-size:13px; }}
</style>
</head>
<body>
<main>
<section class="hero"><div class="eyebrow">Malleus / AI security evidence</div><h1>{title}</h1><p class="subtitle">Security evaluation evidence bundle aggregating benchmark runs, mutation heatmaps, agentic injection, hidden-channel hygiene, artifact firewall checks, visual lab findings, RAG/campaign workflows, coverage, safety tuning, anomaly signals, patches, and replay refs into one static artifact.</p></section>
<section><div class="grid">{_cards(bundle.risk_cards)}</div></section>
<section><h2>Benchmark runs</h2><div class="panel">{_run_table(bundle.run_cards)}</div></section>
<section><h2>Mutation heatmap / Mutation robustness</h2><div class="grid">{_cards(bundle.mutation_cards)}</div></section>
<section><h2>Agentic injection</h2><div class="grid">{_cards(bundle.agent_cards)}</div></section>
<section><h2>Hidden-channel hygiene</h2><div class="grid">{_cards(bundle.hidden_cards)}</div></section>
<section><h2>Artifact firewall</h2><div class="grid">{_cards(bundle.artifact_cards)}</div></section>
<section><h2>Visual lab</h2><div class="grid">{_cards(bundle.visual_cards)}</div></section>
<section><h2>RAG harness</h2><div class="grid">{_cards(bundle.rag_cards)}</div></section>
<section><h2>Campaign workflow</h2><div class="grid">{_cards(bundle.campaign_cards)}</div></section>
<section><h2>Coverage matrix</h2><div class="grid">{_cards(bundle.coverage_cards)}</div></section>
<section><h2>Threat model status</h2><div class="grid">{_cards(bundle.threat_model_cards)}</div></section>
<section><h2>Safety tuner</h2><div class="grid">{_cards(bundle.safety_cards)}</div></section>
<section><h2>Anomaly signals</h2><div class="grid">{_cards(bundle.anomaly_cards)}</div></section>
<section><h2>Benchmark plan and panel</h2><div class="grid">{_cards(bundle.benchmark_cards)}</div></section>
<section><h2>Patch suggestions</h2><div class="grid">{_cards(bundle.patch_cards)}</div></section>
<section><h2>Replay commands</h2><div class="grid">{_cards(bundle.replay_cards)}</div></section>
<section><h2>Compound risk</h2><div class="grid">{_cards(bundle.compound_cards)}</div></section>
<section><h2>Issues and remediation</h2><div class="grid">{_cards(bundle.issue_cards)}</div></section>
<section><h2>Regression tracking</h2><div class="grid">{_cards(bundle.diff_cards)}</div></section>
<section><h2>Human adjudication</h2><div class="grid">{_cards(bundle.adjudication_cards)}</div></section>
<section><h2>Deployment risk cards</h2><div class="panel">{_risk_card_links(bundle.model_risk_card_links)}</div></section>
<section><h2>Adapter deferrals</h2><div class="panel">{_notes(bundle.compatibility_notes)}</div></section>
<footer>Generated by Malleus from local JSON report artifacts. Static HTML with no external JavaScript, fonts, server, or network dependency.</footer>
</main>
</body>
</html>
"""


def render_audit_summary_markdown(audit: AuditBundle) -> str:
    lines = [
        f"# {_md_safe(audit.title)}",
        "",
        "## Executive summary",
        "",
        f"- Run reports: {audit.summary.get('run_reports', 0)}",
        f"- Failed eval items: {audit.summary.get('failed_eval_items', 0)}",
        f"- Agent violations: {audit.summary.get('agent_violations', 0)}",
        f"- Hidden findings: {audit.summary.get('hidden_findings', 0)}",
        f"- New regressions: {audit.summary.get('new_regressions', 0)}",
        f"- Artifact findings: {audit.summary.get('artifact_findings', 0)}",
        f"- Visual findings: {audit.summary.get('visual_findings', 0)}",
        f"- RAG detections: {audit.summary.get('rag_detections', 0)}",
        f"- Campaign failed steps: {audit.summary.get('campaign_failed_steps', 0)}",
        f"- Coverage missing cells: {audit.summary.get('coverage_missing_cells', 0)}",
        f"- Safety unsafe regions: {audit.summary.get('safety_unsafe_regions', 0)}",
        f"- Anomaly findings: {audit.summary.get('anomaly_findings', 0)}",
        f"- Exported issues: {audit.summary.get('exported_issues', 0)}",
        f"- Risk register entries: {len(audit.risk_register)}",
        "",
        "## Coverage matrix summary",
        "",
    ]
    if audit.coverage_summary:
        for key, value in sorted(audit.coverage_summary.items()):
            lines.append(f"- {_md_safe(key)}: {_md_safe(value)}")
    else:
        lines.append("- No coverage artifact supplied.")
    lines.extend(["", "## Gate decisions", ""])
    if audit.gate_decisions:
        for gate in audit.gate_decisions:
            lines.append(f"- {_md_safe(gate['path'])}: {_md_safe(gate['status'])}")
    else:
        lines.append("- No gate decision artifacts supplied.")
    lines.extend(["", "## Findings and risk register", ""])
    if audit.risk_register:
        lines.extend(["| Risk | Source | Severity | Status | Recommendation |", "| --- | --- | --- | --- | --- |"])
        for risk in audit.risk_register:
            lines.append(f"| {_md_safe(risk.risk_id)} | {_md_safe(risk.source)} | {_md_safe(risk.severity)} | {_md_safe(risk.status)} | {_md_safe(risk.recommendation)} |")
    else:
        lines.append("No risk register entries were derived from supplied artifacts.")
    lines.extend(["", "## Remediation table", ""])
    lines.extend(["| Finding | Status | Action | Safe command |", "| --- | --- | --- | --- |"])
    for item in audit.remediation_table:
        lines.append(f"| {_md_safe(item.finding_id)} | {_md_safe(item.status)} | {_md_safe(item.action)} | `{_md_safe(item.command)}` |")
    lines.extend(["", "## Reviewer and adjudication log", ""])
    if audit.reviewer_log:
        for record in audit.reviewer_log:
            lines.append(f"- {_md_safe(record['finding_id'])}: {_md_safe(record['status'])} by {_md_safe(record['reviewer'])} because {_md_safe(record['reason_code'])}")
    else:
        lines.append("- No adjudication records supplied.")
    lines.extend(["", "## Reproducibility appendix", "", "Safe local commands only, no provider calls by default.", "", "```bash", "malleus replay <finding-id> --report <report-dir-or-findings.json> --dry-run", "malleus patch suggest --finding <finding-id> --report <report-dir-or-findings.json> --out <patch-output-dir>", "malleus evidence-bundle --audit-mode --out-dir <audit-dir> --run-report <report.json>", "```", "", "## Artifact hashes", ""])
    for artifact in audit.artifacts:
        lines.append(f"- `{_md_safe(artifact.path)}` sha256 `{artifact.sha256}` size `{artifact.size_bytes}` bytes")
    return "\n".join(lines).rstrip() + "\n"


def _audit_table(rows: list[str], empty: str) -> str:
    return "".join(rows) if rows else f"<tr><td colspan='5'>{_html_safe(empty)}</td></tr>"


def render_audit_index_html(audit: AuditBundle) -> str:
    title = _html_safe(audit.title)
    risk_rows = [
        "<tr>"
        f"<td>{_html_safe(risk.risk_id)}</td><td>{_html_safe(risk.source)}</td><td>{_html_safe(risk.severity)}</td>"
        f"<td>{_html_safe(risk.status)}</td><td>{_html_safe(risk.title)}</td>"
        "</tr>"
        for risk in audit.risk_register
    ]
    remediation_rows = [
        "<tr>"
        f"<td>{_html_safe(item.finding_id)}</td><td>{_html_safe(item.status)}</td><td>{_html_safe(item.action)}</td>"
        f"<td><code>{_html_safe(item.command)}</code></td>"
        "</tr>"
        for item in audit.remediation_table
    ]
    artifact_rows = [
        "<tr>"
        f"<td>{_artifact_link(artifact.path)}</td><td><code>{artifact.sha256}</code></td><td>{artifact.size_bytes}</td><td>{_html_safe(artifact.artifact_type)}</td>"
        "</tr>"
        for artifact in audit.artifacts
    ]
    reviewer_rows = [
        "<tr>"
        f"<td>{_html_safe(record['finding_id'])}</td><td>{_html_safe(record['status'])}</td><td>{_html_safe(record['reviewer'])}</td><td>{_html_safe(record['reason_code'])}</td>"
        "</tr>"
        for record in audit.reviewer_log
    ]
    coverage_items = "".join(f"<li>{_html_safe(key)}: {_html_safe(value)}</li>" for key, value in sorted(audit.coverage_summary.items())) or "<li>No coverage artifact supplied.</li>"
    gates = "".join(f"<li>{_html_safe(gate['path'])}: {_html_safe(gate['status'])}</li>" for gate in audit.gate_decisions) or "<li>No gate decision artifacts supplied.</li>"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title><style>body{{font-family:system-ui,sans-serif;margin:32px;background:#0b0c0f;color:#f5f5f5}}a{{color:#93c5fd}}table{{border-collapse:collapse;width:100%;font-size:13px;margin:12px 0 28px}}th,td{{border:1px solid #333;padding:8px;text-align:left;vertical-align:top}}th{{background:#181a20}}code{{color:#d8b4fe}}.cards{{display:flex;gap:12px;flex-wrap:wrap}}.card{{border:1px solid #333;border-radius:12px;padding:12px;background:#15171c}}</style></head>
<body><h1>{title}</h1><p>Auditor mode evidence bundle generated from local artifacts only. Raw artifact content is not embedded. Artifact files are indexed by sanitized relative path and SHA-256 hash.</p>
<div class="cards"><div class="card">Failed eval items: {_html_safe(audit.summary.get('failed_eval_items', 0))}</div><div class="card">RAG detections: {_html_safe(audit.summary.get('rag_detections', 0))}</div><div class="card">Safety unsafe regions: {_html_safe(audit.summary.get('safety_unsafe_regions', 0))}</div><div class="card">Risks: {len(audit.risk_register)}</div><div class="card">Artifacts: {len(audit.artifacts)}</div></div>
<h2>Coverage matrix summary</h2><ul>{coverage_items}</ul><h2>Gate decisions</h2><ul>{gates}</ul>
<h2>Risk register</h2><table><thead><tr><th>Risk</th><th>Source</th><th>Severity</th><th>Status</th><th>Title</th></tr></thead><tbody>{_audit_table(risk_rows, 'No risks derived.')}</tbody></table>
<h2>Remediation table</h2><table><thead><tr><th>Finding</th><th>Status</th><th>Action</th><th>Safe command</th></tr></thead><tbody>{_audit_table(remediation_rows, 'No remediations derived.')}</tbody></table>
<h2>Reviewer and adjudication log</h2><table><thead><tr><th>Finding</th><th>Status</th><th>Reviewer</th><th>Reason</th></tr></thead><tbody>{_audit_table(reviewer_rows, 'No adjudication records supplied.')}</tbody></table>
<h2>Reproducibility appendix</h2><pre>malleus replay &lt;finding-id&gt; --report &lt;report-dir-or-findings.json&gt; --dry-run
malleus patch suggest --finding &lt;finding-id&gt; --report &lt;report-dir-or-findings.json&gt; --out &lt;patch-output-dir&gt;</pre>
<h2>Artifact hashes</h2><table><thead><tr><th>Artifact</th><th>SHA-256</th><th>Bytes</th><th>Type</th></tr></thead><tbody>{_audit_table(artifact_rows, 'No artifacts indexed.')}</tbody></table>
<footer>Static HTML. No external JavaScript, fonts, third-party assets, server, or network dependency.</footer></body></html>"""


def write_audit_bundle(audit: AuditBundle, output_dir: str | Path) -> dict[str, Path]:
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    paths = {
        "index_html": destination / "index.html",
        "audit_summary": destination / "audit-summary.md",
        "risk_register": destination / "risk-register.json",
        "remediation_table": destination / "remediation-table.json",
        "artifact_index": destination / "artifact-index.json",
    }
    paths["index_html"].write_text(render_audit_index_html(audit), encoding="utf-8")
    paths["audit_summary"].write_text(render_audit_summary_markdown(audit), encoding="utf-8")
    paths["risk_register"].write_text(json.dumps([item.model_dump(mode="json") for item in audit.risk_register], indent=2), encoding="utf-8")
    paths["remediation_table"].write_text(json.dumps([item.model_dump(mode="json") for item in audit.remediation_table], indent=2), encoding="utf-8")
    paths["artifact_index"].write_text(json.dumps([item.model_dump(mode="json") for item in audit.artifacts], indent=2), encoding="utf-8")
    return paths


def write_evidence_bundle(bundle: EvidenceBundle, output_dir: str | Path, *, audit_mode: bool = False, artifact_paths: list[str | Path] | None = None) -> Path:
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    if audit_mode:
        audit = build_audit_bundle(bundle, artifact_paths, output_dir=destination)
        return write_audit_bundle(audit, destination)["index_html"]
    path = destination / "index.html"
    path.write_text(render_evidence_bundle_html(bundle), encoding="utf-8")
    return path
