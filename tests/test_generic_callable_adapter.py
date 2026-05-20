from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.request import Request, urlopen

from typer.testing import CliRunner

from malleus.agent_adapter import AgentRequest, AgentResponse, BaseAgentAdapter, create_agent_adapter_server
from malleus.agent_frameworks.generic import load_generic_agent_adapter
from malleus.cli import app


def test_generic_callable_adapter_runs_plain_agent_object() -> None:
    class Agent:
        def kickoff(self, payload: dict[str, object]) -> dict[str, object]:
            return {
                "answer": "classified safely",
                "tool_calls": [{"tool": "classify_ticket", "arguments": {"queue": "billing"}, "id": "call-1"}],
                "actions": [{"action": "plan", "summary": "selected read-only route"}],
                "retrievals": [{"id": "policy-1", "title": "Policy", "preview": "safe policy excerpt"}],
            }

    adapter = load_generic_agent_adapter_from_object(Agent()).adapter
    response = adapter.run(AgentRequest(target_type="tool_agent", payload={"allowed_tools": ["classify_ticket"]}))

    assert response.final_answer == "classified safely"
    assert response.tool_calls[0].tool_name == "classify_ticket"
    assert response.tool_calls[0].arguments == {"queue": "billing"}
    assert response.actions[0].action_type == "plan"
    assert response.retrievals[0].source_id == "policy-1"
    assert response.metadata["agent_framework"] == "generic_callable"


def test_generic_callable_adapter_accepts_base_agent_adapter_object() -> None:
    class Adapter(BaseAgentAdapter):
        target_type = "memory_agent"

        def run(self, request: AgentRequest) -> AgentResponse:
            return AgentResponse(
                final_answer=f"handled {request.target_type}",
                memory_events=[{"type": "read", "key": "safe_context", "trusted": True}],
                metadata={"live_model_calls": 1},
            )

    adapter = load_generic_agent_adapter_from_object(Adapter(), target_type="memory_agent").adapter
    response = adapter.run(AgentRequest(target_type="memory_agent", payload={"tenant_id": "tenant-a"}))

    assert response.final_answer == "handled memory_agent"
    assert response.memory_events[0]["key"] == "safe_context"
    assert response.metadata["live_model_calls"] == 1
    assert response.metadata["target_type"] == "memory_agent"


def test_generic_callable_adapter_preserves_surface_specific_trace_fields() -> None:
    class Agent:
        def run(self, payload: dict[str, object]) -> dict[str, object]:
            return {
                "answer": "surface trace preserved",
                "memory_events": [{"type": "read", "key": "safe_context", "trusted": True}],
                "handoffs": [{"from": "planner", "to": "reviewer", "authority": "review_only", "trusted": True}],
                "browser_actions": [{"type": "observe", "selector": "button[data-testid='submit']", "status": "ok"}],
                "blocked_operations": [{"action_type": "external_export", "status": "blocked"}],
                "sinks": [{"name": "internal_queue", "trusted": True}],
                "metadata": {"live_model_calls": 1},
            }

    adapter = load_generic_agent_adapter_from_object(Agent(), target_type="multi_agent").adapter
    response = adapter.run(AgentRequest(target_type="multi_agent", payload={"task": "trace"}))

    assert response.memory_events[0]["key"] == "safe_context"
    assert response.handoffs[0]["to"] == "reviewer"
    assert response.browser_actions[0]["selector"] == "button[data-testid='submit']"
    assert response.blocked_operations[0]["status"] == "blocked"
    assert response.sinks[0]["name"] == "internal_queue"
    assert response.metadata["live_model_calls"] == 1


def test_generic_callable_adapter_text_mode_and_http_route() -> None:
    def agent(text: str) -> dict[str, object]:
        assert "Allowed tools: classify_ticket" in text
        return {"final_answer": "ok", "tool_calls": [{"name": "classify_ticket", "args": {}}]}

    loaded = load_generic_agent_adapter_from_object(agent, input_mode="text")
    server = create_agent_adapter_server(loaded, port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        request = Request(
            f"http://{host}:{port}/malleus/tool-agent",
            data=json.dumps({"user_task": "classify", "allowed_tools": ["classify_ticket"]}).encode("utf-8"),
            headers={"content-type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    finally:
        server.shutdown()
        server.server_close()

    assert payload["final_answer"] == "ok"
    assert payload["tool_calls"][0]["tool_name"] == "classify_ticket"
    assert payload["metadata"]["agent_framework"] == "generic_callable"


def test_agent_inspect_callable_cli_loads_plain_agent(tmp_path: Path, monkeypatch) -> None:
    module = tmp_path / "plain_agent.py"
    module.write_text(
        """class Agent:
    def run(self, payload):
        return {"answer": "ok"}

agent = Agent()
""",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))

    result = CliRunner().invoke(app, ["agent", "inspect-callable", "plain_agent:agent", "--target-type", "tool_agent"])

    assert result.exit_code == 0, result.output
    assert "callable_adapter: ok" in result.output
    assert "framework: generic_callable" in result.output
    assert "route: /malleus/tool-agent" in result.output


def test_serve_callable_subprocess_runs_live_agentic_surface(tmp_path: Path) -> None:
    module = tmp_path / "plain_agent.py"
    module.write_text(
        """class Agent:
    def run(self, payload):
        allowed = payload.get("allowed_tools") or ["summarize_document"]
        return {
            "answer": "completed with allowed generic callable tool",
            "tool_calls": [{"name": allowed[0], "args": {"classification": "internal_only"}, "id": "gc-call-1"}],
            "actions": [{"action": "tool_call", "summary": "called allowed tool"}],
        }

agent = Agent()
""",
        encoding="utf-8",
    )
    port = _free_port()
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{tmp_path}{os.pathsep}{Path('src').resolve()}{os.pathsep}{env.get('PYTHONPATH', '')}"
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "from malleus.cli import app; app()",
            "agent",
            "serve-callable",
            "plain_agent:agent",
            "--target-type",
            "tool_agent",
            "--port",
            str(port),
        ],
        cwd=Path.cwd(),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        _wait_for_server(process, port)
        target_path = tmp_path / "callable-target.yaml"
        target_path.write_text(
            f"""name: generic-callable-tool-agent
target_type: tool_agent
metadata:
  agent_framework: generic_callable
  agent_target_depth: L2
tool_agent:
  endpoint_url: http://127.0.0.1:{port}/malleus/tool-agent
  auth:
    bearer_token_env: MALLEUS_CALLABLE_AGENT_TOKEN
  request:
    timeout: 5
""",
            encoding="utf-8",
        )

        result = CliRunner().invoke(
            app,
            [
                "benchmark",
                "live-agentic",
                "--target",
                str(target_path),
                "--out-dir",
                str(tmp_path / "reports"),
                "--yes",
                "--request-timeout",
                "5",
                "--max-retries",
                "0",
            ],
            env={"MALLEUS_CALLABLE_AGENT_TOKEN": "test-token"},
        )
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    assert result.exit_code == 0, result.output
    report = json.loads((tmp_path / "reports" / "live-full-evidence.json").read_text(encoding="utf-8"))
    row = report["rows"][0]
    assert row["status"] == "passed"
    assert row["metadata"]["target_type"] == "tool_agent"
    assert row["metadata"]["target_trace_count"] > 0


def load_generic_agent_adapter_from_object(obj, *, input_mode: str = "payload", target_type: str = "tool_agent"):
    module_name = f"_test_generic_callable_runtime_{id(obj)}"
    module = type(sys)(module_name)
    module.agent = obj
    sys.modules[module_name] = module
    return load_generic_agent_adapter(f"{module_name}:agent", target_type=target_type, input_mode=input_mode)  # type: ignore[arg-type]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_server(process: subprocess.Popen[str], port: int) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout is not None else ""
            raise AssertionError(f"generic callable server exited early with code {process.returncode}: {output}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            try:
                sock.connect(("127.0.0.1", port))
                return
            except OSError:
                time.sleep(0.05)
    output = process.stdout.read() if process.stdout is not None else ""
    raise AssertionError(f"generic callable server did not listen on port {port}: {output}")
