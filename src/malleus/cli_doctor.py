from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path
from typing import Any

from malleus.datasets import load_release_matrix, load_scoring_config, validate_release_matrix_references
from malleus.resources import resource_path
from malleus.target_store import TargetStoreError, list_managed_targets


def build_project_doctor_report(*, config_dir: Path | None = None) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def add(name: str, status: str, detail: str, **extra: Any) -> None:
        checks.append({"name": name, "status": status, "detail": detail, **extra})

    add("python", "passed", sys.version.split()[0], executable=sys.executable)
    _asset_check(add)
    _optional_dependency_check(add, "playwright", module_name="playwright", hint="pip install 'malleus-evals[browser]'")
    _optional_dependency_check(add, "langgraph", module_name="langgraph", hint="pip install 'malleus-evals[langgraph]'")
    _optional_dependency_check(add, "openai-agents", module_name="agents", hint="pip install 'malleus-evals[openai-agents]'")
    _optional_dependency_check(add, "langchain", module_name="langchain_core", hint="pip install 'malleus-evals[langchain]'")
    add("bwrap", "passed" if shutil.which("bwrap") else "missing", shutil.which("bwrap") or "bubblewrap not found on PATH")
    _managed_targets_check(add, config_dir=config_dir)

    status = "ok" if all(check["status"] in {"passed", "missing", "warning"} for check in checks) else "failed"
    return {"schema_version": "malleus.project_doctor.v1", "status": status, "checks": checks}


def render_project_doctor(report: dict[str, Any]) -> str:
    lines = ["Malleus project doctor", f"Status: {report.get('status', 'unknown')}", "", "Checks:"]
    for check in report.get("checks", []):
        if not isinstance(check, dict):
            continue
        status = str(check.get("status", "unknown"))
        name = str(check.get("name", "check"))
        detail = str(check.get("detail", ""))
        marker = "[ok]" if status == "passed" else "[warn]" if status in {"missing", "warning"} else "[fail]"
        lines.append(f"  {marker} {name}: {detail}")
        hint = check.get("hint")
        if hint:
            lines.append(f"       hint: {hint}")
    lines.extend(
        [
            "",
            "Recommended release checks:",
            "  ruff check src tests --select F",
            "  pytest -q",
            "  python -m build",
            "  python scripts/install_smoke.py --wheel dist/malleus_evals-0.1.0-py3-none-any.whl",
        ]
    )
    return "\n".join(lines)


def write_project_doctor(report: dict[str, Any], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "project-doctor.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return path


def _asset_check(add: Any) -> None:
    try:
        matrix_path = resource_path("datasets/release_matrices/malleus-v0.1.yaml")
        scoring_path = resource_path("configs/scoring-default.yaml")
        matrix = validate_release_matrix_references(load_release_matrix(matrix_path))
        scoring = load_scoring_config(scoring_path)
    except Exception as exc:
        add("package_assets", "failed", f"{type(exc).__name__}: {exc}")
        return
    add("package_assets", "passed", f"matrix={matrix.id} packs={len(matrix.packs)} scoring_max={scoring.max_score}")


def _optional_dependency_check(add: Any, name: str, *, module_name: str, hint: str) -> None:
    if importlib.util.find_spec(module_name) is None:
        add(name, "missing", "optional dependency not installed", hint=hint)
    else:
        add(name, "passed", "importable")


def _managed_targets_check(add: Any, *, config_dir: Path | None) -> None:
    try:
        targets = list_managed_targets(config_dir)
    except TargetStoreError as exc:
        add("managed_targets", "failed", str(exc))
    except Exception as exc:
        add("managed_targets", "failed", f"{type(exc).__name__}: {exc}")
    else:
        add("managed_targets", "passed", f"{len(targets)} target(s) found")
