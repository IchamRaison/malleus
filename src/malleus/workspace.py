from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from malleus.threat_model import init_threat_model, write_threat_model

WORKSPACE_SCHEMA_VERSION = "malleus.workspace.v1"
WORKSPACE_DIRS = ("runs", "findings", "patches", "adjudications", "coverage", "risk-cards")


class WorkspaceStatus(BaseModel):
    path: str
    profile: str
    unpatched_findings: int = 0
    missing_coverage: int = 0
    blocking_gates: int = 0
    adjudication_status: str = "not_supplied"
    next_commands: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists() or not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _workspace_path(path: str | Path) -> Path:
    return Path(path).resolve()


def init_workspace(path: str | Path, profile: str) -> Path:
    root = _workspace_path(path)
    root.mkdir(parents=True, exist_ok=True)
    for name in WORKSPACE_DIRS:
        (root / name).mkdir(exist_ok=True)
    model = init_threat_model(profile)
    write_threat_model(model, root / "threat-model.yaml")
    metadata = {
        "schema_version": WORKSPACE_SCHEMA_VERSION,
        "profile": profile,
        "created_at": _now(),
        "provider_calls_enabled": False,
        "local_only": True,
        "safe_commands": [
            "malleus workspace status --path <workspace>",
            "malleus workspace next --path <workspace>",
        ],
    }
    (root / "workspace.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    (root / "README.md").write_text(
        "# Malleus Workspace\n\nLocal artifact workspace. Status and next commands inspect files only and do not run models.\n",
        encoding="utf-8",
    )
    for name in WORKSPACE_DIRS:
        marker = root / name / ".gitkeep"
        if not marker.exists():
            marker.write_text("", encoding="utf-8")
    return root


def _profile(root: Path) -> str:
    metadata = _load_json(root / "workspace.json") or {}
    if metadata.get("profile"):
        return str(metadata["profile"])
    model_path = root / "threat-model.yaml"
    if model_path.exists():
        data = yaml.safe_load(model_path.read_text(encoding="utf-8")) or {}
        if isinstance(data, dict) and data.get("profile"):
            return str(data["profile"])
    return "unknown"


def _findings(root: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for path in sorted(root.glob("**/findings.json")):
        data = _load_json(path)
        if data is None:
            continue
        for finding in data.get("findings", []) if isinstance(data.get("findings"), list) else []:
            if isinstance(finding, dict):
                findings.append(finding)
    return findings


def _patched_finding_ids(root: Path) -> set[str]:
    patched: set[str] = set()
    for path in sorted((root / "patches").glob("**/*.json")) if (root / "patches").exists() else []:
        data = _load_json(path)
        if data is None:
            continue
        finding_id = data.get("finding_id") or data.get("source_finding_id")
        if isinstance(finding_id, str) and finding_id:
            patched.add(finding_id)
    return patched


def _missing_coverage(root: Path) -> int:
    total = 0
    for path in sorted((root / "coverage").glob("**/coverage.json")) if (root / "coverage").exists() else []:
        data = _load_json(path)
        if data is None:
            continue
        summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
        total += int(summary.get("missing_cells", 0) or 0)
        total += int(summary.get("partial_cells", 0) or 0)
    if total == 0 and not list((root / "coverage").glob("**/coverage.json")):
        threat = root / "threat-model.yaml"
        if threat.exists():
            data = yaml.safe_load(threat.read_text(encoding="utf-8")) or {}
            if isinstance(data, dict):
                total = len(data.get("missing_coverage", []) or data.get("required_cells", []) or [])
    return total


def _blocking_gates(root: Path) -> int:
    count = 0
    for path in sorted(root.glob("**/risk-summary.json")):
        data = _load_json(path)
        if data and data.get("status") == "fail":
            count += 1
    return count


def _adjudication_status(root: Path, finding_count: int) -> str:
    records = 0
    open_items = 0
    for path in sorted(root.glob("**/adjudications.json")):
        data = _load_json(path)
        if data is None:
            continue
        summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
        records += int(summary.get("total_records", 0) or 0)
        open_items += int(summary.get("open_findings", 0) or 0)
    if records == 0:
        return "not_supplied" if finding_count else "not_required"
    return "open" if open_items else "complete"


def workspace_next_commands(status: WorkspaceStatus) -> list[str]:
    commands: list[str] = []
    if status.unpatched_findings:
        commands.append("malleus patch suggest --finding <finding-id> --report <workspace>/findings/findings.json --out <workspace>/patches/<finding-id>")
        commands.append("malleus replay <finding-id> --report <workspace>/findings/findings.json --dry-run")
    if status.missing_coverage:
        commands.append("malleus coverage build --input <dataset-or-pack.yaml> --out-dir <workspace>/coverage --report <workspace>/findings/findings.json")
    if status.blocking_gates:
        commands.append("malleus evidence-bundle --audit-mode --out-dir <workspace>/audit --run-report <workspace>/runs/report.json")
    if status.adjudication_status in {"not_supplied", "open"} and status.unpatched_findings:
        commands.append("malleus adjudicate --finding <finding-id> --report <workspace>/findings/findings.json --status needs_review --reviewer <reviewer> --reason-code initial_triage")
    if not commands:
        commands.append("malleus evidence-bundle --audit-mode --out-dir <workspace>/audit --run-report <workspace>/runs/report.json")
    return commands


def inspect_workspace(path: str | Path) -> WorkspaceStatus:
    root = _workspace_path(path)
    findings = _findings(root)
    patched = _patched_finding_ids(root)
    unpatched = sum(1 for finding in findings if str(finding.get("finding_id") or "") not in patched)
    status = WorkspaceStatus(
        path=str(root),
        profile=_profile(root),
        unpatched_findings=unpatched,
        missing_coverage=_missing_coverage(root),
        blocking_gates=_blocking_gates(root),
        adjudication_status=_adjudication_status(root, len(findings)),
        notes=["Workspace status inspects local artifacts only and does not run models."],
    )
    status.next_commands = workspace_next_commands(status)
    return status


def render_workspace_status(status: WorkspaceStatus) -> str:
    lines = [
        f"Workspace: {status.path}",
        f"Profile: {status.profile}",
        f"Unpatched findings: {status.unpatched_findings}",
        f"Missing coverage: {status.missing_coverage}",
        f"Blocking gates: {status.blocking_gates}",
        f"Adjudication status: {status.adjudication_status}",
        "Next safe commands:",
    ]
    lines.extend(f"- {command}" for command in status.next_commands)
    lines.extend(["Notes:", *[f"- {note}" for note in status.notes]])
    return "\n".join(lines).rstrip() + "\n"


def render_workspace_next(status: WorkspaceStatus) -> str:
    return "\n".join(status.next_commands).rstrip() + "\n"
