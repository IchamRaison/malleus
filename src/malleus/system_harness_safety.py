from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Literal, Sequence
from urllib.parse import urlparse

from malleus.schemas import TargetType
from malleus.utils.redact import redact_public_text, redacted_preview, scan_public_artifact_text

HarnessSafetyStatus = Literal["ok", "target_config_error"]
SandboxBackend = Literal["bwrap", "unavailable"]

REAL_EXECUTION_TARGET_TYPES: frozenset[str] = frozenset({"code_agent", "workflow_harness"})
_ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")
_SECRET_LIKE_RE = re.compile(
    r"(?:sk-[A-Za-z0-9_-]{8,}|bearer\s+[A-Za-z0-9._~+/=-]{8,}|basic\s+[A-Za-z0-9._~+/=-]{8,}|[A-Za-z0-9_./+=-]{24,})",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class HarnessSafetyPolicy:
    allow_live_execution: bool = False
    allow_network: bool = False
    timeout_seconds: float | None = None
    budget_usd: float | None = None
    endpoint_allowlist: tuple[str, ...] = ()
    credential_env: dict[str, str] = field(default_factory=dict)
    env_allowlist: tuple[str, ...] = ()
    disposable_workspace: Path | None = None
    output_dir: Path | None = None
    max_artifact_bytes: int = 1_000_000
    max_total_artifact_bytes: int = 10_000_000
    cleanup_manifest_required: bool = True


@dataclass(frozen=True)
class CleanupManifest:
    workspace: str
    output_dir: str | None
    cleanup_required: bool = True
    remove_paths: tuple[str, ...] = ()

    def public_dict(self) -> dict[str, object]:
        return {
            "workspace": redacted_preview(self.workspace),
            "output_dir": redacted_preview(self.output_dir or ""),
            "cleanup_required": self.cleanup_required,
            "remove_paths": [redacted_preview(path) for path in self.remove_paths],
        }


@dataclass(frozen=True)
class HarnessSafetyDecision:
    allowed: bool
    status: HarnessSafetyStatus
    reasons: tuple[str, ...] = ()
    public_log: str = ""
    cleanup_manifest: CleanupManifest | None = None
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class SandboxPlan:
    allowed: bool
    status: HarnessSafetyStatus
    backend: SandboxBackend
    command: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()
    public_log: str = ""
    cleanup_manifest: CleanupManifest | None = None
    metadata: dict[str, object] = field(default_factory=dict)


def validate_harness_safety_policy(
    policy: HarnessSafetyPolicy,
    *,
    endpoints: Sequence[str] = (),
    log_text: str = "",
) -> HarnessSafetyDecision:
    reasons: list[str] = []

    if not policy.allow_live_execution:
        reasons.append("live execution requires explicit operator opt-in")
    if policy.timeout_seconds is None or policy.timeout_seconds <= 0:
        reasons.append("timeout_seconds must be a positive explicit limit")
    if policy.budget_usd is None or policy.budget_usd < 0:
        reasons.append("budget_usd must be an explicit non-negative limit")
    if not policy.endpoint_allowlist:
        reasons.append("endpoint_allowlist must be explicit, even when empty network use is expected")
    reasons.extend(_endpoint_violations(policy.endpoint_allowlist, endpoints))
    reasons.extend(_env_reference_violations(policy.credential_env, policy.env_allowlist))
    reasons.extend(_workspace_violations(policy.disposable_workspace, policy.output_dir))
    if policy.max_artifact_bytes <= 0:
        reasons.append("max_artifact_bytes must be positive")
    if policy.max_total_artifact_bytes < policy.max_artifact_bytes:
        reasons.append("max_total_artifact_bytes must be at least max_artifact_bytes")
    if policy.cleanup_manifest_required and policy.disposable_workspace is None:
        reasons.append("cleanup manifest requires a disposable workspace")

    scan = scan_public_artifact_text(log_text) if log_text else None
    redacted = redact_public_text(log_text, limit=1000).text if log_text else ""
    if scan is not None and not scan.passed:
        reasons.append("public harness log required redaction")

    cleanup_manifest = build_cleanup_manifest(policy) if policy.disposable_workspace is not None else None
    allowed = not reasons
    return HarnessSafetyDecision(
        allowed=allowed,
        status="ok" if allowed else "target_config_error",
        reasons=tuple(dict.fromkeys(reasons)),
        public_log=redacted,
        cleanup_manifest=cleanup_manifest,
        metadata={
            "redacted_log": bool(log_text and redacted != log_text),
            "artifact_limits": {
                "max_artifact_bytes": policy.max_artifact_bytes,
                "max_total_artifact_bytes": policy.max_total_artifact_bytes,
            },
        },
    )


def plan_local_subprocess_execution(
    command: Sequence[str],
    policy: HarnessSafetyPolicy,
    *,
    target_type: TargetType | str,
    endpoints: Sequence[str] = (),
    executable_paths: Sequence[str | Path] = (),
    runtime_bind_paths: Sequence[str | Path] = (),
    bwrap_lookup: Callable[[str], str | None] = shutil.which,
) -> SandboxPlan:
    decision = validate_harness_safety_policy(policy, endpoints=endpoints)
    if not command:
        return _blocked_plan("command must be a non-empty argv sequence", decision=decision)
    if target_type in REAL_EXECUTION_TARGET_TYPES:
        bwrap_path = bwrap_lookup("bwrap")
        if not bwrap_path:
            return _blocked_plan("bubblewrap sandbox is unavailable for real subprocess targets", decision=decision, backend="unavailable")
    else:
        bwrap_path = bwrap_lookup("bwrap")
        if not bwrap_path:
            return _blocked_plan("bubblewrap sandbox is unavailable", decision=decision, backend="unavailable")

    path_reasons = _command_path_violations(command, executable_paths)
    if path_reasons:
        merged = _merge_reasons(decision.reasons, path_reasons)
        return SandboxPlan(
            allowed=False,
            status="target_config_error",
            backend="bwrap",
            reasons=merged,
            public_log=decision.public_log,
            cleanup_manifest=decision.cleanup_manifest,
            metadata=decision.metadata,
        )
    if not decision.allowed:
        return SandboxPlan(
            allowed=False,
            status=decision.status,
            backend="bwrap",
            reasons=decision.reasons,
            public_log=decision.public_log,
            cleanup_manifest=decision.cleanup_manifest,
            metadata=decision.metadata,
        )

    sandbox_command = build_bwrap_command(
        command,
        workspace=policy.disposable_workspace,
        output_dir=policy.output_dir,
        executable_paths=executable_paths,
        runtime_bind_paths=runtime_bind_paths,
        allow_network=policy.allow_network,
        bwrap_path=bwrap_path,
    )
    return SandboxPlan(
        allowed=True,
        status="ok",
        backend="bwrap",
        command=tuple(sandbox_command),
        reasons=("sandbox_plan_ready",),
        cleanup_manifest=decision.cleanup_manifest,
        metadata=decision.metadata,
    )


def build_bwrap_command(
    command: Sequence[str],
    *,
    workspace: str | Path | None,
    output_dir: str | Path | None = None,
    executable_paths: Sequence[str | Path] = (),
    runtime_bind_paths: Sequence[str | Path] = (),
    allow_network: bool = False,
    bwrap_path: str | Path = "bwrap",
) -> list[str]:
    if workspace is None:
        raise ValueError("workspace is required for bwrap planning")
    workspace_path = Path(workspace).resolve()
    output_path = Path(output_dir).resolve() if output_dir is not None else workspace_path
    argv = [
        str(bwrap_path),
        "--die-with-parent",
        "--unshare-all",
    ]
    if allow_network:
        argv.append("--share-net")
    argv.extend([
        "--new-session",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
    ])
    bind_pairs = [*list(_runtime_bind_pairs(runtime_bind_paths)), *list(_executable_bind_pairs(executable_paths))]
    for directory in _bwrap_destination_dirs(((workspace_path, workspace_path), (output_path, output_path), *bind_pairs)):
        argv.extend(["--dir", str(directory)])
    argv.extend(["--bind", str(workspace_path), str(workspace_path)])
    if output_path != workspace_path:
        argv.extend(["--bind", str(output_path), str(output_path)])
    for source, destination in _runtime_bind_pairs(runtime_bind_paths):
        argv.extend(["--ro-bind", str(source), str(destination)])
    for source, destination in _executable_bind_pairs(executable_paths):
        argv.extend(["--ro-bind", str(source), str(destination)])
    argv.extend(["--chdir", str(workspace_path), "--"])
    argv.extend(str(part) for part in command)
    return argv


def build_cleanup_manifest(policy: HarnessSafetyPolicy) -> CleanupManifest:
    if policy.disposable_workspace is None:
        raise ValueError("disposable_workspace is required for cleanup manifest")
    workspace = str(Path(policy.disposable_workspace).resolve())
    output = str(Path(policy.output_dir).resolve()) if policy.output_dir is not None else None
    remove_paths = (workspace,) if output is None or output == workspace else (workspace, output)
    return CleanupManifest(workspace=workspace, output_dir=output, remove_paths=remove_paths)


def check_artifact_size_limits(paths: Sequence[str | Path], policy: HarnessSafetyPolicy) -> HarnessSafetyDecision:
    reasons: list[str] = []
    total = 0
    for item in paths:
        path = Path(item)
        size = path.stat().st_size
        total += size
        if size > policy.max_artifact_bytes:
            reasons.append(f"artifact exceeds max_artifact_bytes: {redacted_preview(str(path))}")
    if total > policy.max_total_artifact_bytes:
        reasons.append("artifact set exceeds max_total_artifact_bytes")
    allowed = not reasons
    return HarnessSafetyDecision(
        allowed=allowed,
        status="ok" if allowed else "target_config_error",
        reasons=tuple(reasons),
        cleanup_manifest=build_cleanup_manifest(policy) if policy.disposable_workspace is not None else None,
        metadata={"artifact_total_bytes": total},
    )


def _endpoint_violations(allowlist: Sequence[str], endpoints: Sequence[str]) -> list[str]:
    allowed = {_endpoint_origin(value) for value in allowlist if value}
    violations: list[str] = []
    for endpoint in endpoints:
        origin = _endpoint_origin(endpoint)
        if origin not in allowed:
            violations.append(f"endpoint not in allowlist: {redacted_preview(endpoint)}")
    return violations


def _endpoint_origin(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return value.rstrip("/")


def _env_reference_violations(credential_env: dict[str, str], env_allowlist: Sequence[str]) -> list[str]:
    allowed = set(env_allowlist)
    violations: list[str] = []
    for target_name, env_name in credential_env.items():
        if not _ENV_NAME_RE.fullmatch(env_name):
            violations.append(f"credential env for {target_name} must be an environment variable name")
            continue
        if _SECRET_LIKE_RE.search(env_name):
            violations.append(f"credential env for {target_name} looks like a raw secret")
        if allowed and env_name not in allowed:
            violations.append(f"credential env for {target_name} is outside env_allowlist")
    for env_name in allowed:
        if not _ENV_NAME_RE.fullmatch(env_name):
            violations.append("env_allowlist entries must be environment variable names")
    return violations


def _workspace_violations(workspace: Path | None, output_dir: Path | None) -> list[str]:
    if workspace is None:
        return ["disposable_workspace is required"]
    workspace_path = workspace.resolve()
    reasons: list[str] = []
    if workspace_path == Path.cwd().resolve() or workspace_path == Path.home().resolve() or workspace_path == Path("/"):
        reasons.append("disposable_workspace must not be the repo, home, or filesystem root")
    if not _looks_disposable(workspace_path):
        reasons.append("disposable_workspace must be an explicitly disposable temp path")
    if output_dir is not None:
        output_path = output_dir.resolve()
        if not _is_relative_to(output_path, workspace_path) and not _looks_disposable(output_path):
            reasons.append("output_dir must be inside the disposable workspace or another disposable temp path")
    return reasons


def _looks_disposable(path: Path) -> bool:
    temp_root = Path(os.getenv("TMPDIR", "/tmp")).resolve()
    parts = {part.lower() for part in path.parts}
    return _is_relative_to(path, temp_root) or bool(parts & {"tmp", "temp", "temporary"})


def _command_path_violations(command: Sequence[str], executable_paths: Sequence[str | Path]) -> tuple[str, ...]:
    allowed = {str(path) for path in _unique_resolved_paths(executable_paths)}
    executable = Path(str(command[0])).resolve()
    if str(executable) not in allowed:
        return ("command executable must be included in explicit read-only executable_paths",)
    return ()


def _executable_bind_pairs(paths: Sequence[str | Path]) -> tuple[tuple[Path, Path], ...]:
    pairs: dict[tuple[str, str], tuple[Path, Path]] = {}
    for item in paths:
        requested = Path(item)
        resolved = requested.resolve()
        pairs[(str(resolved), str(requested))] = (resolved, requested)
        if requested != resolved:
            pairs[(str(resolved), str(resolved))] = (resolved, resolved)
    return tuple(pairs.values())


def _runtime_bind_pairs(paths: Sequence[str | Path]) -> tuple[tuple[Path, Path], ...]:
    pairs: dict[tuple[str, str], tuple[Path, Path]] = {}
    for item in paths:
        path = Path(item)
        if not path.exists():
            continue
        pairs[(str(path), str(path))] = (path, path)
    return tuple(pairs.values())


def _bwrap_destination_dirs(bind_pairs: Sequence[tuple[Path, Path]]) -> tuple[Path, ...]:
    directories: dict[str, Path] = {}
    for source, destination in bind_pairs:
        bind_destination = destination if source.is_dir() else destination.parent
        for parent in reversed(bind_destination.parents):
            if str(parent) == "/":
                continue
            directories[str(parent)] = parent
        directories[str(bind_destination)] = bind_destination
        if source.is_dir():
            directories[str(destination)] = destination
    return tuple(sorted(directories.values(), key=lambda path: len(path.parts)))


def _unique_resolved_paths(paths: Sequence[str | Path]) -> tuple[Path, ...]:
    unique: dict[str, Path] = {}
    for item in paths:
        path = Path(item).resolve()
        unique[str(path)] = path
    return tuple(unique.values())


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _blocked_plan(
    reason: str,
    *,
    decision: HarnessSafetyDecision,
    backend: SandboxBackend = "unavailable",
) -> SandboxPlan:
    return SandboxPlan(
        allowed=False,
        status="target_config_error",
        backend=backend,
        reasons=_merge_reasons(decision.reasons, (reason,)),
        public_log=decision.public_log,
        cleanup_manifest=decision.cleanup_manifest,
        metadata=decision.metadata,
    )


def _merge_reasons(left: Sequence[str], right: Sequence[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys([*left, *right]))


__all__ = [
    "CleanupManifest",
    "HarnessSafetyDecision",
    "HarnessSafetyPolicy",
    "HarnessSafetyStatus",
    "SandboxBackend",
    "SandboxPlan",
    "build_bwrap_command",
    "build_cleanup_manifest",
    "check_artifact_size_limits",
    "plan_local_subprocess_execution",
    "validate_harness_safety_policy",
]
