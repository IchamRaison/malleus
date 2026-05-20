from __future__ import annotations

import subprocess
import shutil
from pathlib import Path

from malleus.system_harness_safety import (
    HarnessSafetyPolicy,
    check_artifact_size_limits,
    plan_local_subprocess_execution,
    validate_harness_safety_policy,
)
from malleus.utils.redact import scan_public_artifact_text


def _safe_policy(tmp_path: Path, **overrides) -> HarnessSafetyPolicy:
    values = {
        "allow_live_execution": True,
        "timeout_seconds": 30.0,
        "budget_usd": 0.0,
        "endpoint_allowlist": ("https://agent.example.test",),
        "credential_env": {"api_key": "AGENT_API_KEY"},
        "env_allowlist": ("AGENT_API_KEY",),
        "disposable_workspace": tmp_path / "workspace",
        "output_dir": tmp_path / "artifacts",
        "max_artifact_bytes": 128,
        "max_total_artifact_bytes": 512,
    }
    values.update(overrides)
    return HarnessSafetyPolicy(**values)


def test_safety_policy_requires_live_opt_in_timeout_budget_allowlist_and_workspace(tmp_path: Path) -> None:
    policy = HarnessSafetyPolicy(
        allow_live_execution=False,
        timeout_seconds=None,
        budget_usd=None,
        endpoint_allowlist=(),
        disposable_workspace=Path.cwd(),
    )

    decision = validate_harness_safety_policy(policy, endpoints=("https://agent.example.test/run",))

    assert not decision.allowed
    assert decision.status == "target_config_error"
    assert "live execution requires explicit operator opt-in" in decision.reasons
    assert "timeout_seconds must be a positive explicit limit" in decision.reasons
    assert "budget_usd must be an explicit non-negative limit" in decision.reasons
    assert "endpoint_allowlist must be explicit, even when empty network use is expected" in decision.reasons
    assert any("endpoint not in allowlist" in reason for reason in decision.reasons)
    assert "disposable_workspace must not be the repo, home, or filesystem root" in decision.reasons


def test_safety_policy_rejects_raw_or_unallowlisted_credential_env_references(tmp_path: Path) -> None:
    policy = _safe_policy(
        tmp_path,
        credential_env={"api_key": "SYNTHETIC-SK-OPENAI-SECRET", "token": "OTHER_TOKEN"},
        env_allowlist=("AGENT_API_KEY",),
    )

    decision = validate_harness_safety_policy(policy)

    assert not decision.allowed
    assert decision.status == "target_config_error"
    assert "credential env for api_key must be an environment variable name" in decision.reasons
    assert "credential env for token is outside env_allowlist" in decision.reasons


def test_secret_redaction_in_harness_logs(tmp_path: Path) -> None:
    policy = _safe_policy(tmp_path)

    decision = validate_harness_safety_policy(policy, log_text="agent log token=SYNTHETIC-SK-OPENAI-SECRET in /home/alice/project")

    assert not decision.allowed
    assert decision.status == "target_config_error"
    assert "public harness log required redaction" in decision.reasons
    assert "SYNTHETIC-SK-OPENAI-SECRET" not in decision.public_log
    assert "/home/alice" not in decision.public_log
    assert scan_public_artifact_text(decision.public_log).passed


def test_unsafe_host_command_rejected_when_not_explicitly_bound(tmp_path: Path) -> None:
    policy = _safe_policy(tmp_path)
    command = ("/usr/bin/python3", "-c", "print('not executed')")

    plan = plan_local_subprocess_execution(
        command,
        policy,
        target_type="code_agent",
        executable_paths=(),
        bwrap_lookup=lambda name: "/usr/bin/bwrap",
    )

    assert not plan.allowed
    assert plan.status == "target_config_error"
    assert plan.backend == "bwrap"
    assert "command executable must be included in explicit read-only executable_paths" in plan.reasons
    assert plan.command == ()


def test_bwrap_backend_selected_and_binds_only_workspace_output_and_executables(tmp_path: Path) -> None:
    policy = _safe_policy(tmp_path)
    interpreter = tmp_path / "python"
    command = (str(interpreter), "-c", "print('planned only')")

    plan = plan_local_subprocess_execution(
        command,
        policy,
        target_type="code_agent",
        endpoints=("https://agent.example.test/run",),
        executable_paths=(interpreter,),
        bwrap_lookup=lambda name: "/usr/bin/bwrap",
    )

    assert plan.allowed
    assert plan.status == "ok"
    assert plan.backend == "bwrap"
    assert plan.command[0] == "/usr/bin/bwrap"
    assert "--bind" in plan.command
    assert "--ro-bind" in plan.command
    assert str(policy.disposable_workspace.resolve()) in plan.command
    assert str(policy.output_dir.resolve()) in plan.command
    assert str(interpreter.resolve()) in plan.command
    assert str(Path.cwd().resolve()) not in plan.command
    assert str(Path.home().resolve()) not in plan.command
    assert plan.command[-len(command) :] == command


def test_real_subprocess_targets_fail_closed_without_bwrap(tmp_path: Path) -> None:
    policy = _safe_policy(tmp_path)
    interpreter = tmp_path / "python"

    plan = plan_local_subprocess_execution(
        (str(interpreter), "--version"),
        policy,
        target_type="workflow_harness",
        executable_paths=(interpreter,),
        bwrap_lookup=lambda name: None,
    )

    assert not plan.allowed
    assert plan.status == "target_config_error"
    assert plan.backend == "unavailable"
    assert "bubblewrap sandbox is unavailable for real subprocess targets" in plan.reasons
    assert plan.command == ()


def test_bwrap_python_runtime_paths_allow_host_python_to_execute(tmp_path: Path) -> None:
    bwrap = shutil.which("bwrap")
    python = shutil.which("python3")
    if bwrap is None or python is None:
        return
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    policy = _safe_policy(tmp_path, disposable_workspace=workspace, output_dir=None)

    plan = plan_local_subprocess_execution(
        (python, "-c", "print('malleus-bwrap-python-ok')"),
        policy,
        target_type="code_agent",
        executable_paths=(python,),
        runtime_bind_paths=(
            "/lib",
            "/lib64",
            "/usr/lib",
            "/etc/ld.so.cache",
            "/etc/resolv.conf",
            "/etc/nsswitch.conf",
            "/etc/hosts",
            "/etc/ssl/certs",
        ),
        bwrap_lookup=lambda name: bwrap,
    )

    assert plan.allowed
    completed = subprocess.run(plan.command, cwd=workspace, capture_output=True, text=True, timeout=10, check=False)
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "malleus-bwrap-python-ok"


def test_bwrap_network_is_shared_only_when_policy_explicitly_allows_it(tmp_path: Path) -> None:
    command = (str(tmp_path / "python"), "--version")
    closed_policy = _safe_policy(tmp_path, allow_network=False)
    open_policy = _safe_policy(tmp_path, allow_network=True)

    closed_plan = plan_local_subprocess_execution(
        command,
        closed_policy,
        target_type="code_agent",
        executable_paths=(command[0],),
        bwrap_lookup=lambda name: "/usr/bin/bwrap",
    )
    open_plan = plan_local_subprocess_execution(
        command,
        open_policy,
        target_type="code_agent",
        executable_paths=(command[0],),
        bwrap_lookup=lambda name: "/usr/bin/bwrap",
    )

    assert closed_plan.allowed
    assert "--share-net" not in closed_plan.command
    assert open_plan.allowed
    assert "--share-net" in open_plan.command


def test_artifact_size_limits_and_cleanup_manifest_are_reported(tmp_path: Path) -> None:
    policy = _safe_policy(tmp_path, max_artifact_bytes=4, max_total_artifact_bytes=8)
    artifact = tmp_path / "workspace" / "large.txt"
    artifact.parent.mkdir(parents=True)
    artifact.write_text("too large", encoding="utf-8")

    decision = check_artifact_size_limits((artifact,), policy)

    assert not decision.allowed
    assert decision.status == "target_config_error"
    assert any("artifact exceeds max_artifact_bytes" in reason for reason in decision.reasons)
    assert decision.cleanup_manifest is not None
    manifest = decision.cleanup_manifest.public_dict()
    assert manifest["cleanup_required"] is True
    assert scan_public_artifact_text(str(manifest)).passed
