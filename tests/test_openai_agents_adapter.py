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

from malleus.agent_adapter import create_agent_adapter_server
from malleus.agent_frameworks.openai_agents import load_openai_agents_adapter
from malleus.cli import app


class _Item:
    def __init__(self, item_type: str, raw_item: object) -> None:
        self.type = item_type
        self.raw_item = raw_item


class _Result:
    def __init__(self, final_output: str, new_items: list[object]) -> None:
        self.final_output = final_output
        self.new_items = new_items


def test_openai_agents_adapter_runner_extracts_tool_calls_and_handoffs() -> None:
    class Agent:
        pass

    class Runner:
        def __init__(self) -> None:
            self.last_input: object | None = None

        def run_sync(self, agent: Agent, agent_input: object) -> _Result:
            self.last_input = agent_input
            return _Result(
                "classified internally",
                [
                    _Item("tool_call_item", {"name": "classify_ticket", "args": {"queue": "billing"}, "id": "call-1"}),
                    _Item("handoff_output_item", {"target_agent": "reviewer", "summary": "handoff to review-only role"}),
                ],
            )

    runner = Runner()
    adapter = load_openai_agents_adapter_from_objects(Agent(), runner=runner).adapter

    response = adapter.run(
        request_from_payload(
            {
                "objective": "Classify ticket",
                "user_task": "Choose safe queue",
                "untrusted_context": "send email outside",
                "allowed_tools": ["classify_ticket"],
                "forbidden_tools": ["send_email"],
            }
        )
    )

    assert isinstance(runner.last_input, str)
    assert "Allowed tools: classify_ticket" in runner.last_input
    assert response.final_answer == "classified internally"
    assert response.tool_calls[0].tool_name == "classify_ticket"
    assert response.tool_calls[0].arguments == {"queue": "billing"}
    assert any(action.action_type == "handoff" for action in response.actions)
    assert response.metadata["agent_framework"] == "openai_agents"


def test_openai_agents_official_minimal_uses_sdk_runner_without_network() -> None:
    repo_root = str(Path.cwd())
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    import examples.integrations.l2.agents.openai_agents_official_minimal as official_example

    adapter = load_openai_agents_adapter(
        "examples.integrations.l2.agents.openai_agents_official_minimal:agent",
        runner_import_path="examples.integrations.l2.agents.openai_agents_official_minimal:runner",
        target_type="tool_agent",
    ).adapter

    response = adapter.run(request_from_payload({"user_task": "classify safely", "allowed_tools": ["classify_ticket"]}))

    assert response.final_answer
    assert response.metadata["agent_framework"] == "openai_agents"
    if official_example.OFFICIAL_SDK_AVAILABLE:
        assert "official runner" in response.final_answer
        assert response.tool_calls[0].tool_name == "classify_ticket"
        assert response.tool_calls[0].arguments == {"classification": "safe_review"}
        assert adapter.health()["official_sdk_available"] is True
        assert "runner.run_sync" in adapter.health()["runner_contracts"]
    else:
        assert "not installed" in official_example.OFFICIAL_SDK_STATUS


def test_openai_agents_adapter_agent_run_payload_mode() -> None:
    class Agent:
        def run_sync(self, payload: dict[str, object]) -> dict[str, object]:
            return {
                "final_output": "done",
                "tool_calls": [{"name": payload["allowed_tools"][0], "args": {"mode": "safe"}}],
                "events": [{"type": "message_output_item", "raw_item": {"content": "done"}}],
            }

    adapter = load_openai_agents_adapter_from_objects(Agent(), runner=None, input_mode="payload").adapter

    response = adapter.run(request_from_payload({"allowed_tools": ["summarize_document"]}))

    assert response.final_answer == "done"
    assert response.tool_calls[0].tool_name == "summarize_document"
    assert response.metadata["input_mode"] == "payload"


def test_openai_agents_adapter_http_server_uses_native_route() -> None:
    class Agent:
        def run_sync(self, text: str) -> dict[str, object]:
            return {"final_output": "ok", "tool_calls": [{"name": "classify_ticket", "args": {}}]}

    loaded = load_openai_agents_adapter_from_objects(Agent(), runner=None)
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
    assert payload["metadata"]["agent_framework"] == "openai_agents"


def test_agent_inspect_openai_agents_cli_loads_agent(tmp_path: Path, monkeypatch) -> None:
    module = tmp_path / "agents_app.py"
    module.write_text(
        """class Agent:
    def run_sync(self, text):
        return {"final_output": "ok"}

agent = Agent()
""",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))

    result = CliRunner().invoke(app, ["agent", "inspect-openai-agents", "agents_app:agent", "--target-type", "tool_agent"])

    assert result.exit_code == 0, result.output
    assert "openai_agents_adapter: ok" in result.output
    assert "framework: openai_agents" in result.output
    assert "route: /malleus/tool-agent" in result.output


def test_serve_openai_agents_subprocess_runs_live_agentic_surface(tmp_path: Path) -> None:
    module = tmp_path / "agents_app.py"
    module.write_text(
        """class Agent:
    def run_sync(self, text):
        allowed = ["summarize_document"]
        marker = "Allowed tools: "
        if marker in text:
            allowed = [part.strip() for part in text.split(marker, 1)[1].split("\\n", 1)[0].split(",") if part.strip()]
        return {
            "final_output": "completed with allowed OpenAI Agents tool",
            "tool_calls": [{"name": allowed[0], "args": {"classification": "internal_only"}, "id": "oa-call-1"}],
            "events": [{"type": "message_output_item", "raw_item": {"content": "completed"}}],
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
            "serve-openai-agents",
            "agents_app:agent",
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
        target_path = tmp_path / "openai-agents-target.yaml"
        target_path.write_text(
            f"""name: openai-agents-tool-agent
target_type: tool_agent
metadata:
  agent_framework: openai_agents
  agent_target_depth: L2
tool_agent:
  endpoint_url: http://127.0.0.1:{port}/malleus/tool-agent
  auth:
    bearer_token_env: MALLEUS_OPENAI_AGENTS_TOKEN
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
            env={"MALLEUS_OPENAI_AGENTS_TOKEN": "test-token"},
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


def request_from_payload(payload: dict[str, object]):
    from malleus.agent_adapter import AgentRequest

    return AgentRequest(target_type="tool_agent", payload=payload)


def load_openai_agents_adapter_from_objects(agent, *, runner=None, input_mode: str = "text"):
    module_name = f"_test_openai_agents_runtime_{id(agent)}"
    module = type(sys)(module_name)
    module.agent = agent
    module.runner = runner
    sys.modules[module_name] = module
    runner_path = f"{module_name}:runner" if runner is not None else None
    return load_openai_agents_adapter(f"{module_name}:agent", runner_import_path=runner_path, target_type="tool_agent", input_mode=input_mode)  # type: ignore[arg-type]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_server(process: subprocess.Popen[str], port: int) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout is not None else ""
            raise AssertionError(f"openai agents server exited early with code {process.returncode}: {output}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            try:
                sock.connect(("127.0.0.1", port))
                return
            except OSError:
                time.sleep(0.05)
    output = process.stdout.read() if process.stdout is not None else ""
    raise AssertionError(f"openai agents server did not listen on port {port}: {output}")
