from __future__ import annotations

import json
import sys
import threading
from contextlib import contextmanager
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator

import pytest
import yaml

from malleus.agent_adapter import AgentRequest, create_agent_adapter_server
from malleus.agent_frameworks.generic import load_generic_agent_adapter
from malleus.agent_frameworks.langgraph import load_langgraph_adapter
from malleus.agent_frameworks.openai_agents import load_openai_agents_adapter
from malleus.agent_frameworks.rag import load_langchain_rag_adapter
from malleus.agent_target_contracts import validate_agent_target
from malleus.browser_agent_harness import run_browser_agent_harness
from malleus.code_agent_harness import run_code_agent_harness
from malleus.datasets import load_target_config
from malleus.rag_service_harness import run_rag_service_harness
from malleus.schemas import TargetConfig
from malleus.tool_agent_harness import run_tool_agent_harness


EXAMPLES = Path("examples/integrations/l2")
AGENTS = "examples.integrations.l2.agents"
REPO_ROOT = Path.cwd()
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def test_l2_example_target_configs_validate_contracts() -> None:
    expected = {
        "generic-callable-tool-agent.yaml": ("tool_agent", "generic_callable"),
        "langgraph-tool-agent.yaml": ("tool_agent", "langgraph"),
        "langgraph-official-minimal.yaml": ("tool_agent", "langgraph"),
        "openai-agents-tool-agent.yaml": ("tool_agent", "openai_agents"),
        "openai-agents-official-minimal.yaml": ("tool_agent", "openai_agents"),
        "rag-service-local.yaml": ("rag_service", "langchain"),
        "browser-agent-local.yaml": ("browser_agent", "generic_callable"),
        "code-agent-sandboxed.yaml": ("code_agent", "generic_subprocess"),
    }

    for filename, (target_type, framework) in expected.items():
        result = validate_agent_target(EXAMPLES / "targets" / filename)

        assert result.valid, f"{filename}: {result.errors}"
        assert result.target_type == target_type
        assert result.framework == framework
        assert "L2" in load_target_config(EXAMPLES / "targets" / filename).metadata["agent_target_depth"]


def test_l2_adapter_loader_imports_examples_from_cwd_without_pythonpath(monkeypatch: pytest.MonkeyPatch) -> None:
    module_name = f"{AGENTS}.generic_callable_tool_agent"
    sys.modules.pop(module_name, None)
    root = Path.cwd().resolve()
    monkeypatch.setattr(
        sys,
        "path",
        [
            item
            for item in sys.path
            if item
            and Path(item).resolve() != root
        ],
    )

    loaded = load_generic_agent_adapter(f"{module_name}:agent", target_type="tool_agent")

    assert loaded.adapter.health()["framework"] == "generic_callable"
    assert str(root) in sys.path


def test_l2_direct_adapter_contract_matrix() -> None:
    rows = [
        (
            load_generic_agent_adapter(f"{AGENTS}.generic_callable_tool_agent:agent", target_type="tool_agent").adapter,
            AgentRequest(target_type="tool_agent", payload={"allowed_tools": ["classify_ticket"]}),
            "generic_callable",
        ),
        (
            load_langgraph_adapter(f"{AGENTS}.langgraph_tool_agent:graph", target_type="tool_agent", run_mode="stream").adapter,
            AgentRequest(target_type="tool_agent", payload={"allowed_tools": ["classify_ticket"]}),
            "langgraph",
        ),
        (
            load_langgraph_adapter(f"{AGENTS}.langgraph_official_minimal:graph", target_type="tool_agent", run_mode="stream").adapter,
            AgentRequest(target_type="tool_agent", payload={"allowed_tools": ["classify_ticket"]}),
            "langgraph",
        ),
        (
            load_openai_agents_adapter(
                f"{AGENTS}.openai_agents_tool_agent:agent",
                runner_import_path=f"{AGENTS}.openai_agents_tool_agent:runner",
                target_type="tool_agent",
            ).adapter,
            AgentRequest(target_type="tool_agent", payload={"allowed_tools": ["classify_ticket"]}),
            "openai_agents",
        ),
        (
            load_openai_agents_adapter(
                f"{AGENTS}.openai_agents_official_minimal:agent",
                runner_import_path=f"{AGENTS}.openai_agents_official_minimal:runner",
                target_type="tool_agent",
            ).adapter,
            AgentRequest(target_type="tool_agent", payload={"allowed_tools": ["classify_ticket"]}),
            "openai_agents",
        ),
        (
            load_langchain_rag_adapter(f"{AGENTS}.rag_service:rag_chain", input_mode="mapping").adapter,
            AgentRequest(target_type="rag_service", payload={"query": "Which billing process is current?"}),
            "langchain",
        ),
        (
            load_generic_agent_adapter(f"{AGENTS}.browser_agent:agent", target_type="browser_agent").adapter,
            AgentRequest(target_type="browser_agent", payload={"selectors": {"submit_button": "button[data-testid='submit']"}}),
            "generic_callable",
        ),
    ]

    for adapter, request, framework in rows:
        response = adapter.run(request)

        assert response.final_answer or response.answer
        assert response.metadata["agent_framework"] == framework
        assert response.metadata["agent_target_depth"] == "L2"
        assert response.tool_calls or response.actions or response.retrievals


def test_l2_generic_callable_tool_agent_live_harness_has_evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    loaded = load_generic_agent_adapter(f"{AGENTS}.generic_callable_tool_agent:agent", target_type="tool_agent")
    monkeypatch.setenv("MALLEUS_EXAMPLE_AGENT_TOKEN", "test-token")
    with _adapter_server(loaded) as endpoint:
        target = _target_with_endpoint(EXAMPLES / "targets" / "generic-callable-tool-agent.yaml", endpoint)
        report = run_tool_agent_harness(
            target,
            EXAMPLES / "fixtures" / "tool-agent-scenarios.yaml",
            tmp_path / "tool-report",
            scenario_ids={"safe-classification"},
        )

    result = report.results[0]
    assert result.status == "passed"
    assert result.target_call_count == 1
    assert result.target_trace_count == 1
    assert result.tool_calls[0].tool_name == "classify_ticket"
    assert result.artifact_refs[0].artifact_type == "tool_agent_scenario_summary"
    assert report.agent_trace_summary.target_trace_count == 1


def test_l2_tool_agent_capability_gap_is_explicit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module_name = "_l2_gap_agent"
    gap_agent = type("GapAgent", (), {"run": lambda self, payload: {"answer": "no observable trace"}})()
    _install_runtime_module(module_name, gap_agent)
    loaded = load_generic_agent_adapter(f"{module_name}:agent", target_type="tool_agent")
    monkeypatch.setenv("MALLEUS_EXAMPLE_AGENT_TOKEN", "test-token")

    with _adapter_server(loaded) as endpoint:
        target = _target_with_endpoint(EXAMPLES / "targets" / "generic-callable-tool-agent.yaml", endpoint)
        report = run_tool_agent_harness(
            target,
            EXAMPLES / "fixtures" / "tool-agent-scenarios.yaml",
            tmp_path / "gap-report",
            scenario_ids={"safe-classification"},
        )

    result = report.results[0]
    assert result.status == "target_capability_gap"
    assert result.reason_codes == ["missing_tool_trace"]
    assert report.agent_traces[0].capability_gaps


def test_l2_rag_service_example_live_harness_has_retrieval_evidence(tmp_path: Path) -> None:
    loaded = load_langchain_rag_adapter(f"{AGENTS}.rag_service:rag_chain", input_mode="mapping")
    with _adapter_server(loaded) as endpoint:
        target = _target_with_endpoint(EXAMPLES / "targets" / "rag-service-local.yaml", endpoint)
        report = run_rag_service_harness(target, EXAMPLES / "fixtures" / "rag-service.yaml", tmp_path / "rag-report")

    assert report.summary.status_counts["passed"] == 2
    assert report.summary.target_capability_gap == 0
    assert report.results[0].retrieved_ids == ["trusted-password-policy"]
    assert report.results[0].cited_ids == ["trusted-password-policy"]
    assert report.results[0].artifact_refs[0].artifact_type == "rag_service_query_summary"
    assert report.agent_trace_summary.total_traces == 2


def test_l2_browser_agent_example_live_harness_writes_page_capture(tmp_path: Path) -> None:
    loaded = load_generic_agent_adapter(f"{AGENTS}.browser_agent:agent", target_type="browser_agent")
    with _static_site(EXAMPLES / "fixtures" / "browser-site") as site_url:
        with _adapter_server(loaded) as endpoint:
            target = _target_with_endpoint(EXAMPLES / "targets" / "browser-agent-local.yaml", endpoint, allowed_origin=site_url)
            fixture = _browser_fixture_with_url(EXAMPLES / "fixtures" / "browser-agent.yaml", tmp_path / "browser-fixture.yaml", f"{site_url}/index.html")
            report = run_browser_agent_harness(target, fixture, tmp_path / "browser-report", limit=1)

    result = report.results[0]
    assert result.status == "passed"
    assert result.browser_backend in {"http_dom", "playwright"}
    assert result.artifact_refs[0].artifact_type == "browser_page_capture_json"
    page_capture = tmp_path / "browser-report" / result.artifact_refs[0].path
    payload = json.loads(page_capture.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "malleus.browser_page_capture.v1"
    assert payload["dom_length"] > 0
    assert payload["capability_gaps"] in ([], ["missing_screenshot_trace"])
    assert report.agent_trace_summary.total_traces == 1


def test_l2_code_agent_example_sandboxed_harness_has_diff_evidence(tmp_path: Path) -> None:
    report = run_code_agent_harness(
        EXAMPLES / "targets" / "code-agent-sandboxed.yaml",
        EXAMPLES / "fixtures" / "code-agent-workspace",
        tmp_path / "code-report",
        sandbox_backend="fake_test",
    )

    result = report.results[0]
    assert result.status == "passed"
    assert result.changed_files == ["SAFE_NOTES.md"]
    assert result.file_write_count == 1
    assert result.artifact_refs[0].artifact_type == "code_agent_execution_summary"
    assert report.metadata["sandbox_backend"] == "fake_test"
    assert report.agent_trace_summary.total_traces == 1


def test_l2_example_readme_lists_executable_surface_commands() -> None:
    text = (EXAMPLES / "README.md").read_text(encoding="utf-8")

    for command in (
        "serve-callable",
        "serve-langgraph",
        "serve-openai-agents",
        "langgraph_official_minimal",
        "openai_agents_official_minimal",
        "serve-langchain-rag",
        "live-browser-agent",
        "live-code-agent",
    ):
        assert command in text


def test_l2_official_examples_are_explicit_about_optional_sdks() -> None:
    import examples.integrations.l2.agents.langgraph_official_minimal as langgraph_example
    import examples.integrations.l2.agents.openai_agents_official_minimal as openai_agents_example

    assert "langgraph" in langgraph_example.OFFICIAL_SDK_STATUS.lower()
    assert "official" in openai_agents_example.OFFICIAL_SDK_STATUS.lower()
    assert hasattr(langgraph_example.graph, "invoke")
    assert hasattr(openai_agents_example.runner, "run_sync") or openai_agents_example.runner is not None


@contextmanager
def _adapter_server(loaded) -> Iterator[str]:
    server = create_agent_adapter_server(loaded, port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}{loaded.route}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@contextmanager
def _static_site(root: Path) -> Iterator[str]:
    handler = partial(SimpleHTTPRequestHandler, directory=str(root.resolve()))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _target_with_endpoint(path: Path, endpoint: str, *, allowed_origin: str | None = None) -> TargetConfig:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    target_type = data["target_type"]
    data[target_type]["endpoint_url"] = endpoint
    if allowed_origin and target_type == "browser_agent":
        data[target_type]["allowed_origins"] = [allowed_origin]
    return TargetConfig.model_validate(data)


def _browser_fixture_with_url(source: Path, destination: Path, target_url: str) -> Path:
    data = yaml.safe_load(source.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    data["target_url"] = target_url
    destination.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return destination


def _install_runtime_module(module_name: str, agent: object) -> None:
    import sys

    module = type(sys)(module_name)
    module.agent = agent
    sys.modules[module_name] = module
