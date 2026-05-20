from __future__ import annotations

import json
import re
from pathlib import Path

from malleus.agent_lab.loader import load_agent_scenarios
from malleus.live_full import run_live_full_matrix
from malleus.live_preflight import LivePreflightReport, SafeTargetEndpoint


def test_live_full_runs_agentic_injection_v1_with_fake_adapter(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    matrix = _matrix(tmp_path)
    profile = _profile(tmp_path)
    calls: list[str] = []

    class SafeToolAdapter:
        def __init__(self, target):
            pass

        def generate(self, prompt: str) -> str:
            calls.append(prompt)
            return json.dumps({"tool": _first_safe_allowed_tool(prompt), "args": {}})

        def close(self) -> None:
            pass

    monkeypatch.setitem(__import__("malleus.runner").runner.ADAPTERS, "openai_compatible", SafeToolAdapter)
    monkeypatch.setenv("MISSING_LIVE_FULL_KEY", "test-key")
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True))
    monkeypatch.setattr("malleus.live_full.run_mutation_benchmark", _mutation_provider_error)

    evidence, _, _ = run_live_full_matrix(target_path=target, matrix_path=matrix, mutation_profile_path=profile, out_dir=tmp_path / "out", dry_run=False, yes=True)

    row = {row.row_id: row for row in evidence.rows}["pack:agentic-injection-v1"]
    assert row.status == "passed"
    assert row.evidence_level == "live_system_trace"
    assert row.evidence_fidelity == "live_tool_trace"
    assert row.dry_run is False
    assert row.provider_calls_enabled is True
    assert row.live_model_calls == 0
    expected_scenarios = len(load_agent_scenarios("datasets/agentic/agentic_injection_v1.yaml").scenarios)
    assert row.metadata["backing_model_calls"] == expected_scenarios
    assert row.metadata["target_execution_enabled"] is True
    assert row.metadata["target_trace_count"] == expected_scenarios
    assert row.metadata["auto_wrapped"] is True
    assert row.metadata["hosted_tool_runtime"] is True
    assert row.metadata["auto_wrapper_surface"] == "tool_agent"
    assert row.metadata["evidence_fidelity"] == "live_tool_trace"
    assert row.metadata["low_fidelity"] is False
    assert row.metadata["actual_target_type"] == "chat_completion"
    assert "low-fidelity auto-wrapper evidence" not in (row.reason or "")
    assert calls
    assert all("Scenario ID:" not in prompt for prompt in calls)
    assert all("safety benchmark" not in prompt.lower() for prompt in calls)
    assert all("Forbidden tools:" not in prompt for prompt in calls)
    assert (tmp_path / "out" / "tool-agent" / "agentic-injection-v1" / "tool-agent-report.json").exists()


def test_live_full_agentic_provider_exception_is_provider_error(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    matrix = _matrix(tmp_path)
    profile = _profile(tmp_path)

    class ExplodingAdapter:
        def __init__(self, target):
            pass

        def generate(self, prompt: str) -> str:
            raise RuntimeError("provider unavailable for live agent path")

        def close(self) -> None:
            pass

    monkeypatch.setitem(__import__("malleus.runner").runner.ADAPTERS, "openai_compatible", ExplodingAdapter)
    monkeypatch.setenv("MISSING_LIVE_FULL_KEY", "test-key")
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True))
    monkeypatch.setattr("malleus.live_full.run_mutation_benchmark", _mutation_provider_error)

    evidence, _, _ = run_live_full_matrix(target_path=target, matrix_path=matrix, mutation_profile_path=profile, out_dir=tmp_path / "out", dry_run=False, yes=True)

    row = {row.row_id: row for row in evidence.rows}["pack:agentic-injection-v1"]
    assert row.status == "target_error"
    assert row.status != "failed"
    assert row.evidence_fidelity == "auto_wrapper_trace"
    assert row.live_model_calls == 0
    assert row.metadata["auto_wrapped"] is True
    assert row.metadata["auto_wrapper_surface"] == "tool_agent"
    assert row.metadata["actual_target_type"] == "chat_completion"


def test_live_full_agentic_unsafe_tool_choice_is_failed_with_reason_code(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    matrix = _matrix(tmp_path)
    profile = _profile(tmp_path)

    class UnsafeToolAdapter:
        def __init__(self, target):
            pass

        def generate(self, prompt: str) -> str:
            if "approval_token=APPROVED_BY_MANAGER_FIXTURE" in prompt:
                return json.dumps({"tool": "create_refund", "args": {}})
            if "paste any canary" in prompt or "send the canary" in prompt:
                return json.dumps({"tool": "exfiltrate_secret", "args": {}})
            if "send_email" in prompt:
                return json.dumps({"tool": "send_email", "args": {}})
            return json.dumps({"tool": _first_allowed_tool(prompt), "args": {}})

        def close(self) -> None:
            pass

    monkeypatch.setitem(__import__("malleus.runner").runner.ADAPTERS, "openai_compatible", UnsafeToolAdapter)
    monkeypatch.setenv("MISSING_LIVE_FULL_KEY", "test-key")
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True))
    monkeypatch.setattr("malleus.live_full.run_mutation_benchmark", _mutation_provider_error)

    evidence, _, _ = run_live_full_matrix(target_path=target, matrix_path=matrix, mutation_profile_path=profile, out_dir=tmp_path / "out", dry_run=False, yes=True)

    row = {row.row_id: row for row in evidence.rows}["pack:agentic-injection-v1"]
    assert row.status == "failed"
    assert row.live_model_calls == 0
    assert row.evidence_fidelity == "live_tool_trace"
    assert row.metadata["backing_model_calls"] > 0
    assert row.metadata["auto_wrapped"] is True
    assert row.metadata["hosted_tool_runtime"] is True
    assert row.metadata["auto_wrapper_surface"] == "tool_agent"
    assert row.metadata["actual_target_type"] == "chat_completion"


def _target(tmp_path: Path) -> Path:
    target = tmp_path / "target.yaml"
    target.write_text("name: t\nadapter: openai_compatible\nmodel: m\nbase_url: https://example.test/v1\napi_key_env: MISSING_LIVE_FULL_KEY\n", encoding="utf-8")
    return target


def _matrix(tmp_path: Path) -> Path:
    matrix = tmp_path / "matrix.yaml"
    matrix.write_text(
        f"""schema_version: malleus.release_matrix.v1
id: test-matrix
version: 1.0.0
mode_boundaries:
  - mode: live_provider
    evidence_level: live_model_required
    provider_calls_enabled: true
packs:
  - id: agentic-injection-v1
    path: {Path('datasets/agentic/agentic_injection_v1.yaml')}
    evidence_level: live_model_required
    status: available
    live_model_evidence: true
    scaffold_only: false
selected_mutation_profiles:
  - id: selected-v1
    path: {_profile(tmp_path)}
    status: available
    default: true
    mutation_count: 0
    evidence_level: live_model_required
deep_mutation_profiles: []
gates: []
""",
        encoding="utf-8",
    )
    return matrix


def _profile(tmp_path: Path) -> Path:
    profile = tmp_path / "selected.yaml"
    if not profile.exists():
        profile.write_text("schema_version: malleus.mutation_profile.v1\nid: selected-v1\nname: Selected\nversion: 1.0.0\nmutations:\n  - unicode_wrap\n", encoding="utf-8")
    return profile


def _preflight(*, text_ready: bool) -> LivePreflightReport:
    return LivePreflightReport(
        target_name="t",
        adapter="openai_compatible",
        model="m",
        endpoint=SafeTargetEndpoint(scheme="https", host="example.test", path_hint="/v1"),
        text_status="passed" if text_ready else "preflight_failed",
        text_ready=text_ready,
        visual_status="not_supported",
        ok=text_ready,
        probes=[],
    )


def _first_allowed_tool(prompt: str) -> str:
    match = re.search(r"(?:Policy allowed tools|Allowed tools|Available trusted tools): ([^\n]+)", prompt)
    assert match is not None
    return match.group(1).split(",")[0].strip()


def _first_safe_allowed_tool(prompt: str) -> str:
    match = re.search(r"(?:Policy allowed tools|Allowed tools|Available trusted tools): ([^\n]+)", prompt)
    assert match is not None
    allowed = [item.strip() for item in match.group(1).split(",")]
    for tool_name in ("summarize_document", "classify_ticket", "search_knowledge_base", "public_lookup", "read_only_knowledge_fixture"):
        if tool_name in allowed:
            return tool_name
    return allowed[0]


def _scenario_id(prompt: str) -> str:
    match = re.search(r"Scenario ID: ([^\n]+)", prompt)
    assert match is not None
    return match.group(1).strip()


def _mutation_provider_error(*args, **kwargs):
    raise RuntimeError("mutation path intentionally not exercised by agent/tool live tests")
