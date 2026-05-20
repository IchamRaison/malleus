from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

V1_READINESS_SCHEMA_VERSION = "malleus.v1_readiness.v1"


@dataclass(frozen=True)
class V1ReadinessItem:
    phase: str
    requirement: str
    status: str
    evidence: str
    next_step: str = ""


def build_v1_readiness_report(repo_root: Path | None = None) -> dict[str, Any]:
    root = (repo_root or Path.cwd()).resolve()
    items = [
        _item(root, "architecture", "CLI onboarding extracted from monolithic CLI", "src/malleus/cli_onboarding.py", "Refactor remaining target/benchmark/report command groups."),
        _item(root, "architecture", "Project doctor extracted from monolithic CLI", "src/malleus/cli_doctor.py", "Split target doctor helpers from cli.py."),
        _item(root, "architecture", "Live surface helper package exists", "src/malleus/live_surfaces", "Continue moving per-surface implementations out of live_full.py."),
        _line_budget_item(root, "architecture", "live_full.py reduced to v1 compatibility-orchestrator size budget", "src/malleus/live_full.py", max_lines=2800, next_step="Keep moving compatibility wrappers into per-surface modules after v1 without breaking monkeypatchable imports."),
        _item(root, "onboarding", "Guided first-run command", "src/malleus/cli_onboarding.py", "Add optional smoke-run prompt after target creation."),
        _item(root, "onboarding", "Human quickstart doc", "docs/quickstart.md", "Keep screenshots/output examples current."),
        _item(root, "providers", "Provider compatibility matrix", "src/malleus/model_universe.py", "Collect community live verification artifacts."),
        _item(root, "providers", "Provider-free protocol tests", "src/malleus/provider_protocol.py", "Expand fixtures for streaming and provider-specific error bodies."),
        _item(root, "l2_contracts", "Public production stack coverage doc", "docs/production-stack-coverage.md", "Promote stable vs experimental L2 fields."),
        _item(root, "l2_contracts", "Trace schema doc", "docs/trace-schema.md", "Add schema examples for every L2 target type."),
        _item(root, "sandboxing", "Sandbox safety module present", "src/malleus/system_harness_safety.py", "Add cross-platform fallback guidance and stricter sandbox tests."),
        _item(root, "benchmark_quality", "Canonical release matrix", "datasets/release_matrices/malleus-v0.1.yaml", "Freeze v1 pack IDs and move experimental cases out of stable matrix."),
        _item(root, "reporting", "Operational evidence bundle and dashboard", "src/malleus/evidence_bundle.py", "Keep audit outputs stable and documented."),
        _item(root, "release", "Wheel install smoke script", "scripts/install_smoke.py", "Run in release workflow and document PyPI install path."),
        _item(root, "docs", "Documentation index", "docs/index.md", "Add troubleshooting/provider-specific pages as feedback arrives."),
        _item(root, "stability", "Release notes", "docs/release-notes-v0.1.0-rc1.md", "Add semver and deprecation policy before v1.0.0-rc1."),
    ]
    counts: dict[str, int] = {}
    for item in items:
        counts[item.status] = counts.get(item.status, 0) + 1
    blocking = [item for item in items if item.status != "done"]
    return {
        "schema_version": V1_READINESS_SCHEMA_VERSION,
        "status": "ready_for_v1" if not blocking else "not_ready_for_v1",
        "summary": counts,
        "items": [item.__dict__ for item in items],
        "blocking_count": len(blocking),
    }


def render_v1_readiness(report: dict[str, Any]) -> str:
    lines = [
        "Malleus v1 readiness",
        f"Status: {report.get('status', 'unknown')}",
        f"Blocking items: {report.get('blocking_count', 0)}",
        "",
    ]
    current_phase = ""
    for item in report.get("items", []):
        if not isinstance(item, dict):
            continue
        phase = str(item.get("phase", ""))
        if phase != current_phase:
            current_phase = phase
            lines.extend([f"{phase}:", ""])
        marker = "[done]" if item.get("status") == "done" else "[todo]"
        lines.append(f"  {marker} {item.get('requirement')}")
        lines.append(f"         evidence: {item.get('evidence')}")
        if item.get("next_step"):
            lines.append(f"         next: {item.get('next_step')}")
    return "\n".join(lines).rstrip()


def write_v1_readiness_report(report: dict[str, Any], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "v1-readiness.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return path


def _item(root: Path, phase: str, requirement: str, relative_path: str, next_step: str) -> V1ReadinessItem:
    path = root / relative_path
    exists = path.exists()
    return V1ReadinessItem(
        phase=phase,
        requirement=requirement,
        status="done" if exists else "todo",
        evidence=relative_path if exists else f"missing: {relative_path}",
        next_step="" if exists else next_step,
    )


def _line_budget_item(root: Path, phase: str, requirement: str, relative_path: str, *, max_lines: int, next_step: str) -> V1ReadinessItem:
    path = root / relative_path
    if not path.exists():
        return V1ReadinessItem(phase=phase, requirement=requirement, status="todo", evidence=f"missing: {relative_path}", next_step=next_step)
    line_count = len(path.read_text(encoding="utf-8").splitlines())
    if line_count <= max_lines:
        return V1ReadinessItem(phase=phase, requirement=requirement, status="done", evidence=f"{relative_path}: {line_count}/{max_lines} lines")
    return V1ReadinessItem(phase=phase, requirement=requirement, status="todo", evidence=f"{relative_path}: {line_count}/{max_lines} lines", next_step=next_step)
