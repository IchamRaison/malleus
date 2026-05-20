from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PROD_READINESS_SCHEMA_VERSION = "malleus.prod_readiness.v1"


@dataclass(frozen=True)
class ProdReadinessItem:
    axis: str
    requirement: str
    status: str
    evidence: str
    next_step: str = ""


def build_prod_readiness_report(repo_root: Path | None = None) -> dict[str, Any]:
    root = (repo_root or Path.cwd()).resolve()
    items = [
        _contains_item(root, "ci_cd", "CI runs tests, full ruff, build, install smoke, CLI smoke, and package asset checks", ".github/workflows/ci.yml", ["pytest -q", "ruff check src tests scripts", "python -m build", "scripts/install_smoke.py", "malleus quickstart"], "Extend CI with OS/Python matrix and optional typecheck once annotations are tightened."),
        _max_line_item(root, "architecture", "live_full.py is a compatibility orchestrator with live-surface helpers split out", "src/malleus/live_full.py", max_lines=2800, extra_paths=["src/malleus/live_surfaces/reporting.py", "src/malleus/live_surfaces/checkpointing.py", "src/malleus/live_surfaces/mutations.py", "src/malleus/live_surfaces/self_modification.py"], next_step="Continue moving surface runners out behind stable wrappers after v1."),
        _all_paths_item(root, "docs", "User docs cover quickstart, providers, production stack coverage, trace schema, release readiness, and evidence boundaries", ["docs/index.md", "docs/quickstart.md", "docs/providers.md", "docs/production-stack-coverage.md", "docs/trace-schema.md", "docs/release-readiness.md", "docs/what-malleus-tests.md"], "Keep examples focused on installation, integration, and audit workflows."),
        _contains_item(root, "release_hygiene", "Release guidance distinguishes audit artifacts from raw local reports and documents pre-publish checks", "docs/release-readiness.md", ["git diff --cached --check", "Audit artifacts", "Confirm no raw local report directory is staged"], "Generate one final sanitized evidence bundle for the release tag."),
        _all_paths_item(root, "providers", "Provider compatibility is protocol-tested without requiring paid API credits", ["src/malleus/model_universe.py", "src/malleus/provider_protocol.py", "tests/test_provider_protocol.py", "docs/providers.md"], "Collect user-submitted live verification artifacts for additional providers."),
        _all_paths_item(root, "sandboxing", "Sandbox safety module, tests, and docs are present", ["src/malleus/system_harness_safety.py", "tests/test_system_harness_safety.py", "docs/production-stack-coverage.md"], "Add a Linux bwrap integration job when CI runner permissions allow it."),
        _all_paths_item(root, "cli_ux", "CLI has guided onboarding, project doctor, quickstart, target store, and readiness commands", ["src/malleus/cli_onboarding.py", "src/malleus/cli_doctor.py", "src/malleus/cli_quickstart.py", "src/malleus/target_store.py", "src/malleus/v1_readiness.py"], "Add concise aliases for smoke/soft/exterminatus if user feedback asks for them."),
        _all_paths_item(root, "plugins", "Pack/scorer/target extension contracts are documented and validated by tests", ["docs/attack-packs.md", "docs/agent-target-contract.md", "src/malleus/benchmark_contracts.py", "tests/test_agent_target_contracts.py"], "Add a cookiecutter-style external pack template."),
        _all_paths_item(root, "observability", "Reports include stack coverage, command logs, trace schema, redaction, replayable evidence, dashboard, and evidence bundle output", ["src/malleus/stack_coverage.py", "src/malleus/live_surfaces/reporting.py", "src/malleus/utils/redact.py", "src/malleus/dashboard.py", "src/malleus/evidence_bundle.py", "docs/trace-schema.md"], "Add a dedicated report doctor command for third-party artifacts."),
        _all_paths_item(root, "packaging_public", "Package includes assets, install smoke, README, release notes, and operational evidence docs", ["pyproject.toml", "src/malleus/assets", "scripts/install_smoke.py", "README.md", "docs/evidence-bundle.md", "docs/release-notes-v0.1.0-rc1.md"], "Publish the final release artifact after a clean tag build."),
    ]
    counts: dict[str, int] = {}
    for item in items:
        counts[item.status] = counts.get(item.status, 0) + 1
    blocking = [item for item in items if item.status != "done"]
    return {
        "schema_version": PROD_READINESS_SCHEMA_VERSION,
        "status": "prod_ready" if not blocking else "not_prod_ready",
        "summary": counts,
        "blocking_count": len(blocking),
        "items": [item.__dict__ for item in items],
    }


def render_prod_readiness(report: dict[str, Any]) -> str:
    lines = [
        "Malleus production readiness",
        f"Status: {report.get('status', 'unknown')}",
        f"Blocking items: {report.get('blocking_count', 0)}",
        "",
    ]
    for item in report.get("items", []):
        if not isinstance(item, dict):
            continue
        marker = "[done]" if item.get("status") == "done" else "[todo]"
        lines.append(f"  {marker} {item.get('axis')}: {item.get('requirement')}")
        lines.append(f"         evidence: {item.get('evidence')}")
        if item.get("next_step"):
            lines.append(f"         next: {item.get('next_step')}")
    return "\n".join(lines).rstrip()


def write_prod_readiness_report(report: dict[str, Any], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "prod-readiness.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return path


def _all_paths_item(root: Path, axis: str, requirement: str, relative_paths: list[str], next_step: str) -> ProdReadinessItem:
    missing = [path for path in relative_paths if not (root / path).exists()]
    if missing:
        return ProdReadinessItem(axis=axis, requirement=requirement, status="todo", evidence="missing: " + ", ".join(missing), next_step=next_step)
    return ProdReadinessItem(axis=axis, requirement=requirement, status="done", evidence=", ".join(relative_paths))


def _contains_item(root: Path, axis: str, requirement: str, relative_path: str, needles: list[str], next_step: str) -> ProdReadinessItem:
    path = root / relative_path
    if not path.exists():
        return ProdReadinessItem(axis=axis, requirement=requirement, status="todo", evidence=f"missing: {relative_path}", next_step=next_step)
    text = path.read_text(encoding="utf-8")
    missing = [needle for needle in needles if needle not in text]
    if missing:
        return ProdReadinessItem(axis=axis, requirement=requirement, status="todo", evidence=f"{relative_path} missing markers: {', '.join(missing)}", next_step=next_step)
    return ProdReadinessItem(axis=axis, requirement=requirement, status="done", evidence=relative_path)


def _max_line_item(root: Path, axis: str, requirement: str, relative_path: str, *, max_lines: int, extra_paths: list[str], next_step: str) -> ProdReadinessItem:
    path = root / relative_path
    missing = [candidate for candidate in [relative_path, *extra_paths] if not (root / candidate).exists()]
    if missing:
        return ProdReadinessItem(axis=axis, requirement=requirement, status="todo", evidence="missing: " + ", ".join(missing), next_step=next_step)
    line_count = len(path.read_text(encoding="utf-8").splitlines())
    if line_count > max_lines:
        return ProdReadinessItem(axis=axis, requirement=requirement, status="todo", evidence=f"{relative_path}: {line_count}/{max_lines} lines", next_step=next_step)
    return ProdReadinessItem(axis=axis, requirement=requirement, status="done", evidence=f"{relative_path}: {line_count}/{max_lines} lines; helpers: {', '.join(extra_paths)}")
