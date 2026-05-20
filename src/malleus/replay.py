from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from malleus.findings import SecurityFinding, find_finding, load_or_collect_findings
from malleus.reporting import _md_safe

REPLAY_SCHEMA_VERSION = "malleus.replay.v1"


class ReplayArtifact(BaseModel):
    schema_version: str = REPLAY_SCHEMA_VERSION
    replay_id: str
    finding_id: str
    generated_at: str
    mode: Literal["dry_run", "mock"] = "dry_run"
    provider_calls_enabled: bool = False
    command: str
    target_name: str
    target_adapter: str | None = None
    target_model: str | None = None
    input_path: str | None = None
    scoring_path: str | None = None
    case_ids: list[str] = Field(default_factory=list)
    scenario_ids: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    safety_notes: list[str] = Field(default_factory=list)


def build_replay_artifact(finding: SecurityFinding) -> ReplayArtifact:
    spec = finding.replay_spec
    return ReplayArtifact(
        replay_id=spec.replay_id,
        finding_id=finding.finding_id,
        generated_at=datetime.now(UTC).isoformat(),
        mode=spec.mode,
        provider_calls_enabled=False,
        command=spec.command,
        target_name=spec.target_name,
        target_adapter=spec.target_adapter,
        target_model=spec.target_model,
        input_path=spec.input_path,
        scoring_path=spec.scoring_path,
        case_ids=spec.case_ids,
        scenario_ids=spec.scenario_ids,
        evidence_refs=[evidence.evidence_id for evidence in finding.evidence_refs],
        safety_notes=[
            "Replay is dry-run/mock only in this release.",
            "No model, browser, shell, network, hardware, or external side effects are executed.",
            "Use the command as an analyst plan; future explicit configuration is required for live replay.",
        ],
    )


def render_replay_markdown(artifact: ReplayArtifact) -> str:
    lines = [
        "# Malleus Replay Plan",
        "",
        f"- Replay ID: {_md_safe(artifact.replay_id)}",
        f"- Finding ID: {_md_safe(artifact.finding_id)}",
        f"- Mode: {_md_safe(artifact.mode)}",
        f"- Provider calls enabled: {artifact.provider_calls_enabled}",
        f"- Command: `{_md_safe(artifact.command)}`",
        f"- Target: {_md_safe(artifact.target_name)} / {_md_safe(artifact.target_model or 'n/a')}",
        "",
        "## Safety notes",
        "",
    ]
    lines.extend(f"- {_md_safe(note)}" for note in artifact.safety_notes)
    if artifact.case_ids:
        lines.extend(["", "## Case IDs", "", *[f"- {_md_safe(case_id)}" for case_id in artifact.case_ids]])
    if artifact.scenario_ids:
        lines.extend(["", "## Scenario IDs", "", *[f"- {_md_safe(scenario_id)}" for scenario_id in artifact.scenario_ids]])
    return "\n".join(lines).rstrip() + "\n"


def write_replay_artifact(finding: SecurityFinding, output_dir: str | Path) -> tuple[Path, Path]:
    destination = Path(output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    artifact = build_replay_artifact(finding)
    safe_id = "".join(char if char.isalnum() or char in {"-", "_"} else "-" for char in finding.finding_id)
    json_path = destination / f"replay-{safe_id}.json"
    markdown_path = destination / f"replay-{safe_id}.md"
    json_path.write_text(artifact.model_dump_json(indent=2), encoding="utf-8")
    markdown_path.write_text(render_replay_markdown(artifact), encoding="utf-8")
    return json_path, markdown_path


def replay_finding(finding_id: str, report: str | Path, *, dry_run: bool = True) -> tuple[Path, Path]:
    if not dry_run:
        raise ValueError("live replay is not supported; use --dry-run")
    report_path = Path(report).resolve()
    bundle = load_or_collect_findings(report_path)
    finding = find_finding(bundle, finding_id)
    if finding is None:
        raise ValueError(f"finding not found: {finding_id}")
    output_dir = report_path.parent if report_path.is_file() else report_path
    return write_replay_artifact(finding, output_dir)
