from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

from malleus.datasets import load_target_config
from malleus.schemas import TargetType
from malleus.target_store import TargetStoreError, default_target_dir, resolve_target, sanitize_target_name


BUNDLE_SCHEMA_VERSION = "malleus.target_bundle.v1"
BundleSurface = Literal["rag", "tool_agent", "workflow", "memory", "multi_agent", "browser", "code_agent"]

SURFACE_TARGET_TYPES: dict[str, TargetType] = {
    "rag": "rag_service",
    "tool_agent": "tool_agent",
    "workflow": "workflow_harness",
    "memory": "memory_agent",
    "multi_agent": "multi_agent",
    "browser": "browser_agent",
    "code_agent": "code_agent",
}

SURFACE_PACK_IDS: dict[str, str] = {
    "rag": "rag-v1",
    "tool_agent": "agentic-injection-v1",
    "workflow": "plugin-workflow-v1",
    "memory": "memory-agent-v1",
    "multi_agent": "multi-agent-v1",
    "browser": "ui-browser-v1",
    "code_agent": "code-agent-v1",
}


class TargetBundleSurface(BaseModel):
    target: str
    required_target_type: TargetType | None = None
    optional: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class TargetBundle(BaseModel):
    schema_version: str = BUNDLE_SCHEMA_VERSION
    name: str
    model_target: str
    mode: Literal["reference_local", "user_agents"] = "reference_local"
    surfaces: dict[BundleSurface, TargetBundleSurface] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("schema_version")
    @classmethod
    def validate_schema_version(cls, value: str) -> str:
        if value != BUNDLE_SCHEMA_VERSION:
            raise ValueError(f"unsupported target bundle schema_version: {value}")
        return value

    @model_validator(mode="after")
    def populate_surface_requirements(self) -> "TargetBundle":
        for surface, config in self.surfaces.items():
            expected = SURFACE_TARGET_TYPES[str(surface)]
            if config.required_target_type is None:
                config.required_target_type = expected
        return self


@dataclass(frozen=True)
class BundleSurfaceCheck:
    surface: str
    target_reference: str
    required_target_type: str
    resolved_path: Path | None
    target_type: str | None
    status: Literal["passed", "failed", "missing"]
    message: str


@dataclass(frozen=True)
class BundleDoctorReport:
    bundle: TargetBundle
    bundle_path: Path
    model_target_path: Path | None
    model_target_type: str | None
    model_status: Literal["passed", "failed"]
    model_message: str
    surface_checks: list[BundleSurfaceCheck]

    @property
    def ok(self) -> bool:
        return self.model_status == "passed" and all(check.status == "passed" for check in self.surface_checks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": BUNDLE_SCHEMA_VERSION,
            "bundle": self.bundle.name,
            "bundle_path": str(self.bundle_path),
            "ok": self.ok,
            "model": {
                "target": self.bundle.model_target,
                "path": str(self.model_target_path) if self.model_target_path else None,
                "target_type": self.model_target_type,
                "status": self.model_status,
                "message": self.model_message,
            },
            "surfaces": [
                {
                    "surface": check.surface,
                    "target": check.target_reference,
                    "required_target_type": check.required_target_type,
                    "path": str(check.resolved_path) if check.resolved_path else None,
                    "target_type": check.target_type,
                    "status": check.status,
                    "message": check.message,
                }
                for check in self.surface_checks
            ],
        }


def default_bundle_dir() -> Path:
    return default_target_dir().parent / "bundles"


def managed_bundle_path(name: str, bundle_dir: str | Path | None = None) -> Path:
    root = Path(bundle_dir).expanduser() if bundle_dir is not None else default_bundle_dir()
    return root / f"{sanitize_target_name(name)}.yaml"


def resolve_bundle(reference: str | Path, bundle_dir: str | Path | None = None) -> Path:
    candidate = Path(reference).expanduser()
    if candidate.exists():
        return candidate.resolve()
    managed = managed_bundle_path(str(reference), bundle_dir)
    if managed.exists():
        return managed.resolve()
    raise TargetStoreError(
        f"target bundle not found: {reference}. Provide a bundle YAML path or create one with `malleus bundle init`."
    )


def load_target_bundle(path: str | Path) -> TargetBundle:
    bundle_path = Path(path).expanduser()
    data = yaml.safe_load(bundle_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"target bundle must be a YAML mapping: {bundle_path}")
    return TargetBundle.model_validate(data)


def is_target_bundle_file(path: str | Path) -> bool:
    candidate = Path(path).expanduser()
    if not candidate.exists() or not candidate.is_file():
        return False
    try:
        data = yaml.safe_load(candidate.read_text(encoding="utf-8"))
    except Exception:
        return False
    return isinstance(data, dict) and data.get("schema_version") == BUNDLE_SCHEMA_VERSION


def write_target_bundle(bundle: TargetBundle, path: str | Path, *, overwrite: bool = False) -> Path:
    bundle_path = Path(path).expanduser()
    if bundle_path.exists() and not overwrite:
        raise TargetStoreError(f"target bundle already exists: {bundle_path}")
    bundle_path.parent.mkdir(parents=True, exist_ok=True)
    bundle_path.write_text(yaml.safe_dump(bundle.model_dump(mode="json"), sort_keys=False), encoding="utf-8")
    return bundle_path


def make_reference_bundle(name: str, model_target: str) -> TargetBundle:
    safe = sanitize_target_name(name)
    return TargetBundle(
        name=safe,
        model_target=model_target,
        mode="reference_local",
        surfaces={
            "rag": TargetBundleSurface(target=f"{safe}-rag", required_target_type="rag_service"),
            "tool_agent": TargetBundleSurface(target=f"{safe}-tool-agent", required_target_type="tool_agent"),
            "workflow": TargetBundleSurface(target=f"{safe}-workflow", required_target_type="workflow_harness"),
            "memory": TargetBundleSurface(target=f"{safe}-memory", required_target_type="memory_agent"),
            "multi_agent": TargetBundleSurface(target=f"{safe}-multi-agent", required_target_type="multi_agent"),
            "browser": TargetBundleSurface(target=f"{safe}-browser", required_target_type="browser_agent"),
            "code_agent": TargetBundleSurface(target=f"{safe}-code-agent", required_target_type="code_agent"),
        },
        metadata={"generated_by": "malleus bundle init", "reference_model_target": model_target},
    )


def doctor_target_bundle(path: str | Path, *, target_dir: str | Path | None = None) -> BundleDoctorReport:
    bundle_path = Path(path).expanduser().resolve()
    bundle = load_target_bundle(bundle_path)
    model_path, model_type, model_status, model_message = _resolve_and_validate_model(bundle.model_target, target_dir)
    checks: list[BundleSurfaceCheck] = []
    for surface, surface_config in bundle.surfaces.items():
        checks.append(_surface_check(str(surface), surface_config, target_dir))
    return BundleDoctorReport(
        bundle=bundle,
        bundle_path=bundle_path,
        model_target_path=model_path,
        model_target_type=model_type,
        model_status=model_status,
        model_message=model_message,
        surface_checks=checks,
    )


def _resolve_and_validate_model(reference: str, target_dir: str | Path | None) -> tuple[Path | None, str | None, Literal["passed", "failed"], str]:
    try:
        path = resolve_target(reference, target_dir)
        config = load_target_config(path)
    except Exception as exc:
        return None, None, "failed", str(exc)
    if config.target_type not in {"chat_completion", "vision_model"}:
        return path, config.target_type, "failed", "model_target must be chat_completion or vision_model"
    return path, config.target_type, "passed", "model target resolved"


def _surface_check(surface: str, surface_config: TargetBundleSurface, target_dir: str | Path | None) -> BundleSurfaceCheck:
    expected = str(surface_config.required_target_type or SURFACE_TARGET_TYPES[surface])
    try:
        path = resolve_target(surface_config.target, target_dir)
        config = load_target_config(path)
    except Exception as exc:
        return BundleSurfaceCheck(surface, surface_config.target, expected, None, None, "missing", str(exc))
    if config.target_type != expected:
        return BundleSurfaceCheck(surface, surface_config.target, expected, path, config.target_type, "failed", f"expected target_type={expected}")
    return BundleSurfaceCheck(surface, surface_config.target, expected, path, config.target_type, "passed", "target resolved")


def bundle_surface_target(bundle: TargetBundle, surface: str, *, target_dir: str | Path | None = None) -> Path:
    config = bundle.surfaces.get(surface)  # type: ignore[arg-type]
    if config is None:
        raise TargetStoreError(f"bundle {bundle.name} does not define surface {surface}")
    return resolve_target(config.target, target_dir)
