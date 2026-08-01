from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from malleus.live_surfaces.progress import emit_system_harness_progress
from malleus.datasets import load_input_datasets
from malleus.studio_runtime import (
    StudioProviderDiscoverRequest,
    StudioRunManager,
    StudioRunRequest,
    StudioScanPlanRequest,
    StudioScanRunRequest,
    build_studio_scan_plan,
    discover_provider_models,
    delete_studio_provider_key,
    list_studio_provider_key_statuses,
    list_studio_attacks,
    list_studio_providers,
    list_studio_scan_profiles,
    list_studio_targets,
    save_studio_provider_key,
)


def _target(path: Path) -> Path:
    path.write_text(
        "\n".join(
            [
                "name: studio-target",
                "target_type: chat_completion",
                "adapter: openai_compatible",
                "model: studio/model",
                "base_url: https://example.test/v1",
                "api_key_env: STUDIO_API_KEY",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return path


def test_studio_attack_catalog_exposes_initial_scope() -> None:
    attacks = {attack.id: attack for attack in list_studio_attacks()}

    assert {"showcase-failures-v1", "smoke-v1", "core-v1", "soft", "exterminatus", "rag-v1", "agentic-injection-v1", "ui-browser-v1", "code-agent-v1", "memory-agent-v1"} <= set(attacks)
    assert attacks["showcase-failures-v1"].test_count == 30
    assert attacks["showcase-failures-v1"].target_types == ["chat_completion"]
    assert attacks["smoke-v1"].mode == "pack"
    assert attacks["smoke-v1"].test_count == 5
    assert attacks["smoke-v1"].dataset_count == 1
    assert attacks["core-v1"].target_types == ["chat_completion"]
    assert attacks["rag-v1"].target_types == ["chat_completion", "rag_service"]
    assert attacks["agentic-injection-v1"].surface == "tool_agent"
    assert attacks["core-v1"].test_count == 38
    assert attacks["soft"].mode == "benchmark"
    assert attacks["soft"].test_count is not None
    assert attacks["exterminatus"].estimated_cost == "high"
    assert attacks["exterminatus"].test_count is not None


def test_showcase_failures_pack_is_mutated_prompt_matrix() -> None:
    datasets = load_input_datasets("datasets/benchmark_packs/showcase-failures-v1.yaml")
    cases = datasets[0].cases or []

    assert len(cases) == 30
    source_attacks = {case.metadata["source_attack"] for case in cases}
    assert {
        "historical-direct-override",
        "historical-tool-result",
        "historical-json-contract",
        "workflow-approval-abuse",
        "multi-agent-summarizer-poisoning",
        "compound-authorized-audit",
    } <= source_attacks
    assert all(case.metadata.get("showcase_mutated_prompt") is True for case in cases)
    assert sum(1 for case in cases if case.metadata.get("historical_failure_replay") is True) >= 12
    assert sum(1 for case in cases if case.metadata.get("verified_real_security_leak") is True) >= 5
    assert len({case.metadata["mutation"] for case in cases}) >= 15
    assert sum(1 for case in cases if case.metadata.get("mutation_family") == "surface_finding_replay") == 2
    assert {"verified_quote_completion", "surface_finding_replay", "historical_replay", "encoding", "format_shift", "output_contract", "compound"} <= {
        case.metadata["mutation_family"] for case in cases
    }
    assert sum(1 for case in cases if case.output_constraints is not None) == 6


def test_studio_scan_profiles_and_plan_are_reproducible(tmp_path: Path) -> None:
    session_dir = tmp_path / "session-targets"
    session_dir.mkdir()
    _target(session_dir / "studio-target.yaml")

    profiles = {profile.id: profile for profile in list_studio_scan_profiles()}
    assert {"showcase-findings", "quick-scan", "standard-vulnerability-scan", "deep-red-team"}.issubset(profiles)
    assert profiles["showcase-findings"].attack_ids == ["showcase-failures-v1", "rag-v1", "agentic-injection-v1", "memory-agent-v1", "exterminatus"]

    request = StudioScanPlanRequest(
        target="studio-target",
        description="Customer support agent with RAG and tool access.",
        languages=["en", "fr"],
        profile_id="deep-red-team",
        max_attacks=2,
        seed=7,
    )
    plan_a = build_studio_scan_plan(request, session_target_dir=session_dir)
    plan_b = build_studio_scan_plan(request, session_target_dir=session_dir)

    assert [step.attack_id for step in plan_a.steps] == [step.attack_id for step in plan_b.steps]
    assert len(plan_a.steps) == 2
    assert plan_a.languages == ["en", "fr"]
    assert plan_a.total_tests is not None
    assert "prompt-injection" in plan_a.threat_groups
    assert "Customer support agent" in plan_a.description


def test_studio_scan_run_executes_plan_steps(monkeypatch, tmp_path: Path) -> None:
    session_dir = tmp_path / "session-targets"
    session_dir.mkdir()
    _target(session_dir / "studio-target.yaml")

    class Summary:
        score_total = 10
        max_score_total = 10
        passed_items = 1
        total_items = 1

    class Report:
        summary = Summary()
        datasets = []

    calls: list[str] = []

    def fake_run_benchmark(*args, **kwargs):
        input_path = Path(args[1])
        calls.append(input_path.stem)
        kwargs["progress_callback"]({"event": "case_start", "case_id": input_path.stem})
        kwargs["progress_callback"]({"event": "case_end", "case_id": input_path.stem, "passed": True})
        return Report()

    monkeypatch.setattr("malleus.studio_runtime.run_benchmark", fake_run_benchmark)

    manager = StudioRunManager(root=tmp_path / "runs", session_target_dir=session_dir)
    summary = manager.create_scan_run(
        StudioScanRunRequest(
            target="studio-target",
            profile_id="standard-vulnerability-scan",
            max_attacks=2,
            seed=15,
        )
    )
    finished = _wait_for_completion(manager, summary.run_id)

    assert finished.status == "completed", finished.error
    assert finished.attack_id == "scan:standard-vulnerability-scan"
    assert calls == ["smoke-v1", "core-v1"]
    assert finished.score == "2/2 items"
    assert finished.passed_items == 2
    assert (Path(finished.out_dir) / "studio-scan-plan.json").exists()
    assert (Path(finished.out_dir) / "studio-scan-results.json").exists()
    events = [event.event for event in manager.events_since(summary.run_id)]
    assert events.count("scan_step_started") == 2
    assert events.count("scan_step_completed") == 2
    assert "run_completed" in events


def test_studio_provider_catalog_includes_nvidia_and_known_logos() -> None:
    providers = {provider.id: provider for provider in list_studio_providers()}

    assert "nvidia" in providers
    assert providers["nvidia"].api_key_env == "NVIDIA_API_KEY"
    assert providers["nvidia"].logo_svg is not None
    assert providers["anthropic"].base_url == ""
    assert providers["anthropic"].logo_svg is not None


def test_studio_targets_include_managed_targets_redacted(tmp_path: Path) -> None:
    target_dir = tmp_path / "targets"
    target_dir.mkdir()
    target_path = _target(target_dir / "studio-target.yaml")

    targets = [target for target in list_studio_targets(target_dir) if target.path == str(target_path)]

    assert len(targets) == 1
    assert targets[0].name == "studio-target"
    assert targets[0].target_type == "chat_completion"
    assert targets[0].config["api_key_env"] == "STUDIO_API_KEY"
    assert "api_key" not in targets[0].config


def test_studio_run_manager_runs_pack_with_progress(monkeypatch, tmp_path: Path) -> None:
    target_path = _target(tmp_path / "target.yaml")

    class Summary:
        score_total = 40
        max_score_total = 100
        passed_items = 1
        total_items = 2

    class Check:
        detail = "unsafe response disclosed a boundary marker"

    class Result:
        case_id = "case-1"
        passed = False
        penalty = 1
        score = 0
        response_text = "token=SECRET"
        failure_checks = [Check()]

    class Dataset:
        dataset_name = "smoke"
        case_results = [Result()]

    class Report:
        summary = Summary()
        datasets = [Dataset()]

    def fake_run_benchmark(*args, **kwargs):
        kwargs["progress_callback"]({"event": "case_start", "case_id": "case-1", "prompt": "hi"})
        kwargs["progress_callback"]({"event": "case_end", "case_id": "case-1", "response": "token=SECRET"})
        return Report()

    monkeypatch.setattr("malleus.studio_runtime.run_benchmark", fake_run_benchmark)

    manager = StudioRunManager(root=tmp_path / "runs")
    summary = manager.create_run(StudioRunRequest(target=str(target_path), attack_id="smoke-v1"))
    finished = _wait_for_completion(manager, summary.run_id)

    assert finished.status == "completed", finished.error
    assert finished.score == "40/100"
    assert finished.report_json.endswith("report.json")
    assert (Path(finished.out_dir) / "studio-run-summary.json").exists()
    assert finished.failed_cases[0]["case_id"] == "case-1"
    assert "[REDACTED]" in finished.failed_cases[0]["excerpt"]
    event_names = [event.event for event in manager.events_since(summary.run_id)]
    assert "queued" in event_names
    assert "run_started" in event_names
    assert "case_start" in event_names
    assert finished.provider_in_flight is False
    assert finished.request_timeout == 120.0


def test_studio_cancel_marks_run_terminal_immediately(monkeypatch, tmp_path: Path) -> None:
    target_path = _target(tmp_path / "target.yaml")
    gate = threading.Event()

    def fake_run_benchmark(*args, **kwargs):
        gate.wait(timeout=2)
        return type("Report", (), {"summary": type("Summary", (), {"score_total": 0, "max_score_total": 0, "passed_items": 0, "total_items": 0})(), "datasets": []})()

    monkeypatch.setattr("malleus.studio_runtime.run_benchmark", fake_run_benchmark)

    manager = StudioRunManager(root=tmp_path / "runs")
    summary = manager.create_run(StudioRunRequest(target=str(target_path), attack_id="smoke-v1"))
    time.sleep(0.05)
    cancelled = manager.cancel_run(summary.run_id)
    gate.set()

    assert cancelled.status == "cancelled"
    assert cancelled.cancel_requested is True
    assert cancelled.provider_in_flight is False
    assert cancelled.terminal_reason == "operator_cancelled"
    assert (Path(cancelled.out_dir) / "studio-run-summary.json").exists()


def test_studio_run_history_reads_completed_runs_from_disk(monkeypatch, tmp_path: Path) -> None:
    target_path = _target(tmp_path / "target.yaml")

    class Summary:
        score_total = 100
        max_score_total = 100
        passed_items = 1
        total_items = 1

    class Report:
        summary = Summary()
        datasets = []

    monkeypatch.setattr("malleus.studio_runtime.run_benchmark", lambda *args, **kwargs: Report())

    manager = StudioRunManager(root=tmp_path / "runs")
    summary = manager.create_run(StudioRunRequest(target=str(target_path), attack_id="smoke-v1"))
    finished = _wait_for_completion(manager, summary.run_id)
    restarted = StudioRunManager(root=tmp_path / "runs")

    history = restarted.list_history()
    assert history[0].run.run_id == finished.run_id
    assert history[0].run.status == "completed"
    assert any(artifact.name == "studio-events.jsonl" for artifact in history[0].artifacts)
    assert restarted.get_run(finished.run_id).score == "100/100"
    assert restarted.events_for_run(finished.run_id)[0].event == "run_completed"


def test_studio_run_history_marks_disk_running_runs_stale(tmp_path: Path) -> None:
    run_dir = tmp_path / "runs" / "studio-stale-run"
    run_dir.mkdir(parents=True)
    (run_dir / "studio-events.jsonl").write_text('{"event":"queued"}\n', encoding="utf-8")
    (run_dir / "studio-run-summary.json").write_text(
        json.dumps(
            {
                "run_id": "studio-stale-run",
                "target": "target-a",
                "attack_id": "smoke-v1",
                "status": "running",
                "out_dir": str(run_dir),
                "passed_items": 0,
                "total_items": 0,
                "failed_cases": [],
            }
        ),
        encoding="utf-8",
    )

    history = StudioRunManager(root=tmp_path / "runs").list_history()

    assert history[0].run.status == "failed"
    assert history[0].run.terminal_reason == "stale_after_restart"


def test_studio_run_manager_routes_exterminatus(monkeypatch, tmp_path: Path) -> None:
    target_path = _target(tmp_path / "target.yaml")

    class Evidence:
        def model_dump(self, mode: str = "json"):
            return {"rows": [{"row_id": "deep", "surface_id": "mutation", "status": "passed"}]}

    def fake_exterminatus(*args, **kwargs):
        kwargs["progress_callback"]({"event": "row_start", "row_id": "deep", "surface_name": "Deep mutation"})
        out = Path(kwargs["out_dir"])
        out.mkdir(parents=True, exist_ok=True)
        json_path = out / "live-full-evidence.json"
        json_path.write_text('{"rows":[]}', encoding="utf-8")
        return Evidence(), json_path, out / "live-full-evidence.md"

    monkeypatch.setattr("malleus.studio_runtime.run_exterminatus_benchmark", fake_exterminatus)

    manager = StudioRunManager(root=tmp_path / "runs")
    summary = manager.create_run(StudioRunRequest(target=str(target_path), attack_id="exterminatus"))
    finished = _wait_for_completion(manager, summary.run_id)

    assert finished.status == "completed", finished.error
    assert finished.attack_id == "exterminatus"
    assert finished.score == "1/1 rows"


def test_studio_run_manager_routes_auto_wrapped_surface_target(monkeypatch, tmp_path: Path) -> None:
    session_dir = tmp_path / "session-targets"
    session_dir.mkdir()
    base_path = session_dir / "studio-target.yaml"
    base_path.write_text(
        "\n".join(
            [
                "name: studio-target",
                "target_type: chat_completion",
                "adapter: openai_compatible",
                "model: studio/model",
                "base_url: https://example.test/v1",
                "api_key_env: STUDIO_API_KEY",
                "metadata:",
                "  created_by: malleus_studio",
                "",
            ]
        ),
        encoding="utf-8",
    )

    class Evidence:
        def model_dump(self, mode: str = "json"):
            return {"rows": [{"row_id": "rag", "surface_id": "pack:rag-v1", "status": "passed"}]}

    captured: dict[str, object] = {}

    def fake_surface(*args, **kwargs):
        captured.update(kwargs)
        kwargs["progress_callback"]({"event": "row_start", "row_id": "rag", "surface_name": "RAG retrieval security"})
        out = Path(kwargs["out_dir"])
        out.mkdir(parents=True, exist_ok=True)
        json_path = out / "live-full-evidence.json"
        json_path.write_text('{"rows":[]}', encoding="utf-8")
        return Evidence(), json_path, out / "live-full-evidence.md"

    monkeypatch.setattr("malleus.studio_runtime.run_live_surface_pack", fake_surface)

    manager = StudioRunManager(root=tmp_path / "runs", session_target_dir=session_dir)
    summary = manager.create_run(StudioRunRequest(target="studio-target--rag_service", attack_id="rag-v1"))
    finished = _wait_for_completion(manager, summary.run_id)

    assert finished.status == "completed", finished.error
    assert finished.target == "studio-target-rag-service"
    assert finished.score == "1/1 rows"
    assert captured["target_path"] == base_path.resolve()
    assert captured["pack_id"] == "rag-v1"
    assert captured["surface_limit"] == 1


def test_studio_run_manager_resolves_session_targets(monkeypatch, tmp_path: Path) -> None:
    session_dir = tmp_path / "session-targets"
    session_dir.mkdir()
    _target(session_dir / "studio-target.yaml")

    class Summary:
        score_total = 100
        max_score_total = 100
        passed_items = 1
        total_items = 1

    class Report:
        summary = Summary()
        datasets = []

    monkeypatch.setattr("malleus.studio_runtime.run_benchmark", lambda *args, **kwargs: Report())

    manager = StudioRunManager(root=tmp_path / "runs", session_target_dir=session_dir)
    summary = manager.create_run(StudioRunRequest(target="studio-target", attack_id="smoke-v1"))
    finished = _wait_for_completion(manager, summary.run_id)

    assert finished.status == "completed", finished.error
    assert finished.target == "studio-target"


def test_discover_provider_models_sets_env_and_writes_session_target(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "malleus.studio_runtime._list_models",
        lambda base_url, api_key: (
            ["aisingapore/sea-lion-7b-instruct", "nvidia/nemotron-mini-4b-instruct", "nvidia/model-b"],
            "live",
            None,
        ),
    )
    monkeypatch.setattr("malleus.studio_runtime._probe_chat_completion", lambda base_url, api_key, model: ("ready", None))

    result = discover_provider_models(
        "nvidia",
        StudioProviderDiscoverRequest(api_key="secret-test-key", model="nvidia/model-b"),
        session_target_dir=tmp_path / "session-targets",
    )

    assert result.provider.id == "nvidia"
    assert result.models[:2] == ["nvidia/nemotron-mini-4b-instruct", "nvidia/model-b"]
    assert result.selected_model == "nvidia/model-b"
    assert result.target.target_type == "chat_completion"
    assert result.target.config["api_key_env"] == "NVIDIA_API_KEY"
    assert "production AI assistant" in result.target.config["system_prompt"]
    assert "tool outputs" in result.target.config["system_prompt"]
    assert result.target.config["request"]["timeout"] == 120
    assert result.target.config["metadata"]["studio_managed_agent"]["auth"]["api_key_env"] == "NVIDIA_API_KEY"
    assert result.target.config["metadata"]["studio_managed_agent"]["auth"]["secret_written_to_disk"] is False
    assert result.target.config["metadata"]["studio_managed_agent"]["instruction_profile"] == "strict-boundary-realistic-prod-assistant"
    assert result.target.config["metadata"]["model_universe"]["provider_id"] == "nvidia"
    assert result.inference_status == "ready"
    assert "secret-test-key" not in str(result.model_dump(mode="json"))

    targets = {target.id: target for target in list_studio_targets(session_target_dir=tmp_path / "session-targets")}
    derived_id = f"{result.target.id}--rag_service"
    assert derived_id in targets
    assert targets[derived_id].source == "studio-wrapper"
    assert targets[derived_id].target_type == "rag_service"
    assert targets[derived_id].config["base_target_id"] == result.target.id
    assert targets[f"{result.target.id}--tool_agent"].config["auto_wrapper_surface"] == "tool_agent"


def test_studio_provider_key_vault_saves_status_and_deletes(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    vault = tmp_path / "provider-keys.json"

    initial = {status.provider_id: status for status in list_studio_provider_key_statuses(vault)}
    assert initial["deepseek"].present is False

    saved = save_studio_provider_key("deepseek", "sk-secret-value-1234", vault)
    assert saved.present is True
    assert saved.source == "vault"
    assert saved.redacted == "sk-s...1234"
    assert "sk-secret-value-1234" not in saved.model_dump_json()
    assert vault.stat().st_mode & 0o777 == 0o600

    deleted = delete_studio_provider_key("deepseek", vault)
    assert deleted.present is False
    assert deleted.source == "missing"


def test_discover_provider_models_can_use_saved_key(monkeypatch, tmp_path: Path) -> None:
    vault = tmp_path / "provider-keys.json"
    save_studio_provider_key("deepseek", "saved-secret-key", vault)

    def fake_list_models(base_url: str, api_key: str):
        assert api_key == "saved-secret-key"
        return ["deepseek-v4-flash"], "live", None

    monkeypatch.setattr("malleus.studio_runtime._list_models", fake_list_models)
    monkeypatch.setattr("malleus.studio_runtime._probe_chat_completion", lambda base_url, api_key, model: ("ready", None))

    result = discover_provider_models(
        "deepseek",
        StudioProviderDiscoverRequest(api_key="", model="deepseek-v4-flash", use_saved_key=True),
        session_target_dir=tmp_path / "session-targets",
        provider_keys_path=vault,
    )

    assert result.selected_model == "deepseek-v4-flash"
    assert result.inference_status == "ready"
    assert "saved-secret-key" not in str(result.model_dump(mode="json"))


def test_discover_provider_models_prefers_known_nvidia_chat_model(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "malleus.studio_runtime._list_models",
        lambda base_url, api_key: (
            ["aisingapore/sea-lion-7b-instruct", "nvidia/nemotron-mini-4b-instruct", "meta/llama-3.1-8b-instruct"],
            "live",
            None,
        ),
    )
    monkeypatch.setattr("malleus.studio_runtime._probe_chat_completion", lambda base_url, api_key, model: ("unauthorized", "HTTP 401"))

    result = discover_provider_models(
        "nvidia",
        StudioProviderDiscoverRequest(api_key="secret-test-key"),
        session_target_dir=tmp_path / "session-targets",
    )

    assert result.selected_model == "nvidia/nemotron-mini-4b-instruct"
    assert result.target.model == "nvidia/nemotron-mini-4b-instruct"
    assert result.inference_status == "unauthorized"


def test_studio_targets_upgrade_legacy_session_targets(tmp_path: Path) -> None:
    session_dir = tmp_path / "session-targets"
    session_dir.mkdir()
    legacy = session_dir / "studio-deepseek-deepseek-v4-flash.yaml"
    legacy.write_text(
        "\n".join(
            [
                "name: studio-deepseek-deepseek-v4-flash",
                "target_type: chat_completion",
                "adapter: openai_compatible",
                "model: deepseek-v4-flash",
                "base_url: https://api.deepseek.com/v1",
                "api_key_env: DEEPSEEK_API_KEY",
                "system_prompt: You are a production assistant.",
                "request:",
                "  temperature: 0.0",
                "  timeout: 120",
                "  max_tokens: 2048",
                "metadata:",
                "  provider_preset: deepseek",
                "  model_universe:",
                "    provider_id: deepseek",
                "    provider_label: DeepSeek",
                "    configured_model: deepseek-v4-flash",
                "    api_key_env: DEEPSEEK_API_KEY",
                "  created_by: malleus_studio",
                "",
            ]
        ),
        encoding="utf-8",
    )

    targets = list_studio_targets(session_target_dir=session_dir)

    upgraded = next(target for target in targets if target.name == "studio-deepseek-deepseek-v4-flash")
    assert "production AI assistant" in upgraded.config["system_prompt"]
    assert upgraded.config["metadata"]["studio_managed_agent"]["auth"]["api_key_env"] == "DEEPSEEK_API_KEY"
    assert upgraded.config["metadata"]["studio_managed_agent"]["provider"]["provider_label"] == "DeepSeek"


def test_system_harness_progress_exposes_surface_evidence_details() -> None:
    events: list[dict] = []

    class Pack:
        id = "rag-v1"
        surface_name = "RAG retrieval and citation security"

    class ToolCall:
        tool_name = "search"
        status = "ok"

    class Action:
        action_type = "retrieve"
        target = "doc-alpha"
        status = "ok"

    class Artifact:
        path = "rag-service-report.json"

        def model_dump(self, mode: str = "json"):
            return {"path": self.path, "kind": "json"}

    class Result:
        query_id = "rag-001"
        objective = "answer with cited retrieval"
        status = "failed"
        reason = "citation mismatch"
        reason_codes = ["bad_citation"]
        answer_excerpt = "The answer cited an unrelated document."
        answer_length = 43
        answer_sha256 = "abc123"
        retrieved_ids = ["doc-alpha"]
        cited_ids = ["doc-beta"]
        tool_calls = [ToolCall()]
        actions = [Action()]
        blocked_operations = [Action()]
        changed_files = ["workspace/app.py"]
        target_call_count = 1
        target_trace_count = 2
        evidence_ref = "rag-service-report.json#/results/0"
        artifact_refs = [Artifact()]

    class Report:
        target_type = "rag_service"
        metadata = {"hosted_runtime": True}
        results = [Result()]

    emit_system_harness_progress(events.append, pack=Pack(), report=Report())

    assert len(events) == 1
    payload = events[0]
    assert payload["event"] == "system_case_end"
    assert payload["response"] == "The answer cited an unrelated document."
    assert payload["evidence_fidelity"] == "live_rag_service_trace"
    assert payload["evidence_ref"] == "rag-service-report.json#/results/0"
    assert payload["artifact_refs"][0]["path"] == "rag-service-report.json"
    assert payload["output_summary"]["answer_length"] == 43
    assert payload["trace_summary"]["retrieved_ids"] == ["doc-alpha"]
    assert payload["trace_summary"]["cited_ids"] == ["doc-beta"]
    assert payload["trace_summary"]["tool_call_names"] == ["search (ok)"]
    assert payload["trace_summary"]["action_names"] == ["retrieve -> doc-alpha (ok)"]
    assert payload["trace_summary"]["blocked_operation_names"] == ["retrieve -> doc-alpha (ok)"]
    assert payload["trace_summary"]["changed_files"] == ["workspace/app.py"]


def _wait_for_completion(manager: StudioRunManager, run_id: str):
    deadline = time.time() + 5
    while time.time() < deadline:
        summary = manager.get_run(run_id)
        if summary.status in {"completed", "failed", "cancelled"}:
            return summary
        time.sleep(0.05)
    raise AssertionError("studio run did not finish")
