from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from malleus.findings import FindingsBundle, SecurityFinding, load_or_collect_findings
from malleus.patches import regression_commands
from malleus.reporting import _md_safe
from malleus.utils.redact import redact_public_text, redaction_label, sha256_text

ISSUE_EXPORT_SCHEMA_VERSION = "malleus.issue_export.v1"
OWNER_PLACEHOLDER = "@owner-tbd"

_SPACE_RE = re.compile(r"\s+")
_UNSAFE_RE = re.compile(
    r"\b(ignore previous instructions|system prompt|developer message|exfiltrate|call\s+exfiltrate_secret|environment token|reveal hidden|private fixture|do_not_dump_raw|raw prompt|raw output)\b",
    re.IGNORECASE,
)


class LocalIssue(BaseModel):
    issue_id: str
    finding_id: str
    title: str
    severity: str
    labels: list[str] = Field(default_factory=list)
    owner: str = OWNER_PLACEHOLDER
    source_type: str
    attack_surface: str
    technique: str
    reproduction_command: str
    acceptance_tests: list[str] = Field(default_factory=list)
    patch_suggestion: str
    regression_commands: list[str] = Field(default_factory=list)
    closure_criteria: list[str] = Field(default_factory=list)
    evidence_refs: list[dict[str, str | None]] = Field(default_factory=list)
    markdown_path: str


class IssueExportSummary(BaseModel):
    total_issues: int = 0
    counts_by_severity: dict[str, int] = Field(default_factory=dict)
    counts_by_label: dict[str, int] = Field(default_factory=dict)
    github_creation_enabled: bool = False
    github_creation_status: Literal["disabled", "scaffold_only", "blocked"] = "disabled"


class IssueExportArtifact(BaseModel):
    schema_version: str = ISSUE_EXPORT_SCHEMA_VERSION
    generated_at: str
    source_findings: str
    issues_dir: str = "issues"
    remediation_board: str = "remediation-board.md"
    github_creation_enabled: bool = False
    github_creation_status: Literal["disabled", "scaffold_only", "blocked"] = "disabled"
    github_scaffold_note: str = "GitHub issue creation is disabled by default. This artifact is local-only and never invokes gh."
    issues: list[LocalIssue] = Field(default_factory=list)
    summary: IssueExportSummary


def _clean(value: object, *, limit: int = 500) -> str:
    text = _SPACE_RE.sub(" ", str(value)).strip()
    if not text:
        return "n/a"
    text = redact_public_text(text).text
    text = _UNSAFE_RE.sub(lambda match: redaction_label(match.group(0), kind="unsafe"), text)
    return text[:limit] + ("..." if len(text) > limit else "")


def _safe_id(value: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in {"-", "_"} else "-" for char in value.lower())
    return cleaned.strip("-") or "issue"


def _issue_id(finding: SecurityFinding) -> str:
    return "mi-" + sha256_text(finding.finding_id)[:12]


def _labels(finding: SecurityFinding) -> list[str]:
    labels = {
        "malleus",
        "security-finding",
        f"severity:{_clean(finding.severity, limit=40)}",
        f"source:{_clean(finding.source_type, limit=60)}",
        f"surface:{_safe_id(_clean(finding.attack_surface, limit=60))}",
    }
    if finding.source_type in {"visual_lab", "artifact_firewall"}:
        labels.add("visual-artifact")
    if finding.source_type == "mutation_run" or "mutation" in finding.metadata:
        labels.add("mutation-regression")
    if finding.source_type in {"agent_lab", "interop"} or "tool" in finding.attack_surface.lower() or "plugin" in finding.attack_surface.lower():
        labels.add("tool-plugin")
    if finding.severity in {"high", "critical"}:
        labels.add("needs-triage")
    return sorted(labels)


def _acceptance_tests(finding: SecurityFinding) -> list[str]:
    tests = [
        "Run the reproduction command in dry-run or local fixture mode and confirm the finding no longer reproduces.",
        "Run the regression commands listed below and confirm they pass without provider calls unless explicitly reviewed.",
        "Confirm public artifacts contain only redacted previews, hashes, lengths, evidence refs, and relative paths.",
    ]
    if finding.source_type == "visual_lab":
        tests.append("Confirm OCR, metadata, and visual artifact text stay untrusted and safe-context only.")
    if finding.source_type == "mutation_run" or "mutation" in finding.metadata:
        tests.append("Confirm the mutated case is covered as a regression for the same transform family or surface.")
    if "plugin" in finding.attack_surface.lower() or "tool" in finding.attack_surface.lower() or finding.source_type in {"agent_lab", "interop"}:
        tests.append("Confirm tool or plugin actions require trusted approval and cannot be granted by model output alone.")
    return [_clean(item, limit=260) for item in tests]


def _closure_criteria(finding: SecurityFinding) -> list[str]:
    return [
        f"Owner {OWNER_PLACEHOLDER} is replaced with an accountable reviewer or team.",
        f"Severity {_clean(finding.severity, limit=40)} is resolved, downgraded with written rationale, or explicitly accepted.",
        "Patch suggestion has been implemented or a safer equivalent has been documented.",
        "Regression command evidence is attached to the remediation record.",
        "No raw unsafe excerpts, prompt/output bodies, token/cookie values, or private paths appear in public artifacts.",
    ]


def _evidence_refs(finding: SecurityFinding) -> list[dict[str, str | None]]:
    refs: list[dict[str, str | None]] = []
    for evidence in finding.evidence_refs:
        refs.append(
            {
                "evidence_id": _clean(evidence.evidence_id, limit=120),
                "artifact_path": _clean(Path(evidence.artifact_path).name, limit=160),
                "artifact_type": _clean(evidence.artifact_type, limit=80),
                "json_pointer": _clean(evidence.json_pointer or "n/a", limit=160),
                "redaction_status": evidence.redaction_status,
                "sha256": evidence.sha256,
                "redacted_excerpt": _clean(evidence.redacted_excerpt or "n/a", limit=220),
            }
        )
    return refs


def issue_from_finding(finding: SecurityFinding, markdown_path: str) -> LocalIssue:
    context = {"finding_id": finding.finding_id, "reproduction_command": finding.reproduction_command}
    commands = [_clean(command, limit=360) for command in regression_commands(context)]
    replay_command = _clean(finding.replay_spec.command or finding.reproduction_command, limit=360)
    if replay_command not in commands:
        commands.insert(0, replay_command)
    return LocalIssue(
        issue_id=_issue_id(finding),
        finding_id=_clean(finding.finding_id, limit=120),
        title=_clean(finding.title, limit=180),
        severity=_clean(finding.severity, limit=40),
        labels=_labels(finding),
        source_type=_clean(finding.source_type, limit=80),
        attack_surface=_clean(finding.attack_surface, limit=160),
        technique=_clean(finding.technique, limit=160),
        reproduction_command=_clean(finding.reproduction_command, limit=360),
        acceptance_tests=_acceptance_tests(finding),
        patch_suggestion=_clean(finding.patch_recommendation, limit=420),
        regression_commands=commands,
        closure_criteria=_closure_criteria(finding),
        evidence_refs=_evidence_refs(finding),
        markdown_path=markdown_path,
    )


def render_issue_markdown(issue: LocalIssue) -> str:
    lines = [
        f"# {_md_safe(issue.title)}",
        "",
        f"- Issue ID: `{_md_safe(issue.issue_id)}`",
        f"- Finding ID: `{_md_safe(issue.finding_id)}`",
        f"- Severity: {_md_safe(issue.severity)}",
        f"- Labels: {_md_safe(', '.join(issue.labels))}",
        f"- Owner: {_md_safe(issue.owner)}",
        f"- Source: {_md_safe(issue.source_type)}",
        f"- Attack surface: {_md_safe(issue.attack_surface)}",
        f"- Technique: {_md_safe(issue.technique)}",
        "",
        "## Reproduction command",
        "",
        "```bash",
        _md_safe(issue.reproduction_command),
        "```",
        "",
        "## Acceptance tests",
        "",
    ]
    lines.extend(f"- {_md_safe(item)}" for item in issue.acceptance_tests)
    lines.extend(["", "## Patch suggestion", "", _md_safe(issue.patch_suggestion), "", "## Regression commands", ""])
    for command in issue.regression_commands:
        lines.extend(["```bash", _md_safe(command), "```", ""])
    lines.extend(["## Evidence refs", ""])
    if issue.evidence_refs:
        for ref in issue.evidence_refs:
            lines.append(
                f"- `{_md_safe(ref.get('evidence_id') or 'n/a')}` in `{_md_safe(ref.get('artifact_path') or 'n/a')}` "
                f"at `{_md_safe(ref.get('json_pointer') or 'n/a')}`: {_md_safe(ref.get('redacted_excerpt') or 'n/a')}"
            )
    else:
        lines.append("- No evidence refs supplied.")
    lines.extend(["", "## Closure criteria", ""])
    lines.extend(f"- {_md_safe(item)}" for item in issue.closure_criteria)
    lines.extend(["", "## GitHub creation status", "", "Local export only. GitHub issue creation is scaffold-only, explicit, and disabled by default. This command did not call gh.", ""])
    return "\n".join(lines).rstrip() + "\n"


def render_remediation_board(artifact: IssueExportArtifact) -> str:
    lines = [
        "# Malleus Remediation Board",
        "",
        f"- Issues: {artifact.summary.total_issues}",
        f"- GitHub creation: {_md_safe(artifact.github_creation_status)}",
        "- Default behavior: local-only export, no gh invocation, no network calls.",
        "",
        "| Issue | Severity | Labels | Owner | Status | Closure criteria |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for issue in artifact.issues:
        criteria = "; ".join(issue.closure_criteria[:2])
        lines.append(f"| [{_md_safe(issue.issue_id)}]({_md_safe(issue.markdown_path)}) | {_md_safe(issue.severity)} | {_md_safe(', '.join(issue.labels))} | {_md_safe(issue.owner)} | needs_review | {_md_safe(criteria)} |")
    if not artifact.issues:
        lines.append("| n/a | n/a | n/a | n/a | no_findings | No local issues generated. |")
    return "\n".join(lines).rstrip() + "\n"


def _summary(issues: list[LocalIssue], *, github_creation_status: Literal["disabled", "scaffold_only", "blocked"]) -> IssueExportSummary:
    severity_counts: dict[str, int] = {}
    label_counts: dict[str, int] = {}
    for issue in issues:
        severity_counts[issue.severity] = severity_counts.get(issue.severity, 0) + 1
        for label in issue.labels:
            label_counts[label] = label_counts.get(label, 0) + 1
    return IssueExportSummary(total_issues=len(issues), counts_by_severity=dict(sorted(severity_counts.items())), counts_by_label=dict(sorted(label_counts.items())), github_creation_enabled=False, github_creation_status=github_creation_status)


def export_issues(findings: str | Path | FindingsBundle, out_dir: str | Path, *, github_scaffold: bool = False, create_github: bool = False) -> tuple[IssueExportArtifact, dict[str, Path]]:
    if create_github:
        raise ValueError("GitHub issue creation is scaffold-only and disabled in this command. Re-run without --create-github to write local artifacts.")
    bundle = findings if isinstance(findings, FindingsBundle) else load_or_collect_findings(findings)
    destination = Path(out_dir).resolve()
    issues_dir = destination / "issues"
    issues_dir.mkdir(parents=True, exist_ok=True)
    issues: list[LocalIssue] = []
    for finding in bundle.findings:
        issue_id = _issue_id(finding)
        markdown_name = f"{_safe_id(issue_id + '-' + finding.finding_id)}.md"
        issue = issue_from_finding(finding, f"issues/{markdown_name}")
        (issues_dir / markdown_name).write_text(render_issue_markdown(issue), encoding="utf-8")
        issues.append(issue)
    status: Literal["disabled", "scaffold_only", "blocked"] = "scaffold_only" if github_scaffold else "disabled"
    artifact = IssueExportArtifact(
        generated_at=datetime.now(UTC).isoformat(),
        source_findings=_clean(getattr(bundle, "source_report", None) or "findings", limit=240),
        github_creation_enabled=False,
        github_creation_status=status,
        github_scaffold_note=("Scaffold only: review issue-export.json and create GitHub issues manually. This command never invokes gh." if github_scaffold else "GitHub issue creation is disabled by default. This artifact is local-only and never invokes gh."),
        issues=issues,
        summary=_summary(issues, github_creation_status=status),
    )
    json_path = destination / "issue-export.json"
    board_path = destination / "remediation-board.md"
    json_path.write_text(artifact.model_dump_json(indent=2), encoding="utf-8")
    board_path.write_text(render_remediation_board(artifact), encoding="utf-8")
    return artifact, {"json": json_path, "board": board_path, "issues_dir": issues_dir}


def export_issues_from_findings(findings: str | Path, out_dir: str | Path, *, github_scaffold: bool = False, create_github: bool = False) -> tuple[IssueExportArtifact, dict[str, Path]]:
    return export_issues(findings, out_dir, github_scaffold=github_scaffold, create_github=create_github)
