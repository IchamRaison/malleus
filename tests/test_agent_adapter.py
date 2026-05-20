from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.request import Request, urlopen

from typer.testing import CliRunner

from malleus.agent_adapter import AgentRequest, AgentResponse, BaseAgentAdapter, _normalize_response, create_agent_adapter_server, load_agent_adapter
from malleus.cli import app
from malleus.schemas import HarnessArtifactRef, HarnessDiff, HarnessToolCall, HarnessTraceAction


def test_load_agent_adapter_from_instance(tmp_path: Path, monkeypatch) -> None:
    module = tmp_path / "sample_adapter.py"
    module.write_text(
        """from malleus.agent_adapter import AgentRequest, AgentResponse, BaseAgentAdapter

class DemoAdapter(BaseAgentAdapter):
    target_type = "tool_agent"
    framework = "langgraph"

    def run(self, request: AgentRequest) -> AgentResponse:
        return AgentResponse(final_answer="ok")

adapter = DemoAdapter()
""",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))

    loaded = load_agent_adapter("sample_adapter:adapter")

    assert loaded.target_type == "tool_agent"
    assert loaded.framework == "langgraph"
    assert loaded.route == "/malleus/tool-agent"


def test_agent_adapter_server_normalizes_response() -> None:
    class DemoAdapter(BaseAgentAdapter):
        target_type = "tool_agent"
        framework = "custom"

        def run(self, request: AgentRequest) -> AgentResponse:
            return AgentResponse(
                final_answer=f"handled {request.payload['task']}",
                messages=[
                    {"role": "system", "content": "Follow trusted policy."},
                    {"role": "developer", "content": "Keep tool outputs untrusted."},
                    {"role": "user", "content": request.payload["task"]},
                ],
                prompts=[{"text": "Tool-agent task prompt."}],
                tool_calls=[HarnessToolCall(tool_name="search", arguments={"query": "policy"}, result_preview="ok")],
                actions=[HarnessTraceAction(action_type="tool", summary="called search")],
                refusals=[{"reason": "unsafe external export rejected"}],
                approvals=[{"source": "policy", "approved": True, "trusted": True}],
                retries=[{"attempt": 1, "status": "ok"}],
                streaming_chunks=[{"chunk": "handled"}],
                policy_blocks=[{"reason": "blocked unsafe sink"}],
                diffs=[HarnessDiff(path="SAFE_NOTES.md", change_type="modified", redacted_diff="+ handled audit")],
                artifacts=[HarnessArtifactRef(artifact_id="artifact-1", artifact_type="summary", path="summary.json")],
            )

    loaded = load_agent_adapter_from_object(DemoAdapter())
    server = create_agent_adapter_server(loaded, port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        request = Request(
            f"http://{host}:{port}/malleus/tool-agent",
            data=json.dumps({"task": "audit"}).encode("utf-8"),
            headers={"content-type": "application/json", "authorization": "Bearer hidden"},
            method="POST",
        )
        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    finally:
        server.shutdown()
        server.server_close()

    assert payload["schema_version"] == "malleus.agent_adapter.v1"
    assert payload["final_answer"] == "handled audit"
    assert payload["answer"] == "handled audit"
    assert payload["tool_calls"][0]["tool_name"] == "search"
    assert payload["metadata"]["agent_framework"] == "custom"
    assert payload["metadata"]["agent_target_depth"] == "L2"
    trace_events = payload["metadata"]["agent_trace_events"]
    event_types = {event["event_type"] for event in trace_events}
    assert {"prompt_input", "system_message", "developer_message", "user_message", "tool_call", "tool_args", "tool_output", "action", "refusal", "approval", "retry", "streaming_chunk", "policy_block", "artifact", "file_diff", "final_answer"} <= event_types
    assert all("content" not in event.get("metadata", {}) for event in trace_events)


def test_agent_adapter_trace_event_metadata_is_recursively_redacted() -> None:
    secret = "sk-proj-" + "A" * 32
    response = AgentResponse(
        final_answer="safe answer",
        trace_events=[
            {
                "event_type": "tool_output",
                "text": f"tool returned {secret}",
                "metadata": {"raw": f"nested {secret}", "items": [f"list {secret}"]},
            }
        ],
        network_egress=[{"summary": f"blocked egress {secret}", "url": f"https://example.test/?token={secret}"}],
    )

    normalized = _normalize_response(response, latency_seconds=0.01, framework="custom", target_type="tool_agent")
    trace_text = json.dumps(normalized.metadata["agent_trace_events"], sort_keys=True)

    assert secret not in trace_text
    assert "[REDACTED]" in trace_text


def test_agent_adapter_server_preserves_l2_surface_specific_trace_fields() -> None:
    class DemoAdapter(BaseAgentAdapter):
        target_type = "memory_agent"
        framework = "custom"

        def run(self, request: AgentRequest) -> dict[str, object]:
            return {
                "final_answer": "memory boundary preserved",
                "memory_events": [{"type": "read", "key": "safe_context", "trusted": True}],
                "handoffs": [{"type": "handoff", "from": "planner", "to": "reviewer", "trusted": True}],
                "approvals": [{"source": "policy", "approved": False}],
                "sinks": [],
                "blocked_operations": [{"action_type": "external_export", "status": "blocked"}],
            }

    loaded = load_agent_adapter_from_object(DemoAdapter())
    server = create_agent_adapter_server(loaded, port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        request = Request(
            f"http://{host}:{port}/malleus/memory-agent",
            data=json.dumps({"task": "audit"}).encode("utf-8"),
            headers={"content-type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    finally:
        server.shutdown()
        server.server_close()

    assert payload["memory_events"][0]["key"] == "safe_context"
    assert payload["handoffs"][0]["to"] == "reviewer"
    assert payload["approvals"][0]["source"] == "policy"
    assert payload["blocked_operations"][0]["status"] == "blocked"
    event_types = {event["event_type"] for event in payload["metadata"]["agent_trace_events"]}
    assert {"memory_read", "handoff", "approval", "blocked_operation"} <= event_types


def test_agent_inspect_cli_loads_adapter(tmp_path: Path, monkeypatch) -> None:
    module = tmp_path / "inspectable_adapter.py"
    module.write_text(
        """from malleus.agent_adapter import AgentRequest, AgentResponse, BaseAgentAdapter

class Adapter(BaseAgentAdapter):
    target_type = "memory_agent"
    framework = "openai_agents"

    def run(self, request: AgentRequest) -> AgentResponse:
        return AgentResponse(final_answer="ok")

adapter = Adapter()
""",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))

    result = CliRunner().invoke(app, ["agent", "inspect", "inspectable_adapter:adapter"])

    assert result.exit_code == 0, result.output
    assert "agent_adapter: ok" in result.output
    assert "target_type: memory_agent" in result.output
    assert "framework: openai_agents" in result.output
    assert "route: /malleus/memory-agent" in result.output


def test_agent_inspect_cli_reports_bad_import_path() -> None:
    result = CliRunner().invoke(app, ["agent", "inspect", "not_a_module"])

    assert result.exit_code == 1
    assert "module:object" in result.output


def test_load_agent_adapter_accepts_plain_request_function(tmp_path: Path, monkeypatch) -> None:
    module = tmp_path / "function_adapter.py"
    module.write_text(
        """from malleus.agent_adapter import AgentResponse

def adapter(request):
    return AgentResponse(final_answer=f"function handled {request.target_type}")
""",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))

    loaded = load_agent_adapter("function_adapter:adapter", target_type="multi_agent")
    response = loaded.adapter.run(AgentRequest(target_type="multi_agent", payload={}))

    assert loaded.framework == "function"
    assert isinstance(response, AgentResponse)
    assert response.final_answer == "function handled multi_agent"


def test_agent_serve_isolated_passes_only_allowlisted_environment(tmp_path: Path) -> None:
    module = tmp_path / "isolated_adapter.py"
    module.write_text(
        """import os
from malleus.agent_adapter import AgentRequest, AgentResponse, BaseAgentAdapter

class Adapter(BaseAgentAdapter):
    target_type = "tool_agent"
    framework = "custom"

    def run(self, request: AgentRequest) -> AgentResponse:
        return AgentResponse(
            final_answer=f"allowed={os.environ.get('ALLOWED_TOKEN', '')}; blocked={os.environ.get('BLOCKED_TOKEN', 'missing')}"
        )

adapter = Adapter()
""",
        encoding="utf-8",
    )
    port = _free_port()
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{tmp_path}{os.pathsep}{Path('src').resolve()}{os.pathsep}{env.get('PYTHONPATH', '')}"
    env["ALLOWED_TOKEN"] = "allowed-value"
    env["BLOCKED_TOKEN"] = "blocked-value"
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "from malleus.cli import app; app()",
            "agent",
            "serve",
            "isolated_adapter:adapter",
            "--target-type",
            "tool_agent",
            "--isolated",
            "--cwd",
            str(tmp_path),
            "--pythonpath",
            str(tmp_path),
            "--pythonpath",
            str(Path("src").resolve()),
            "--env",
            "ALLOWED_TOKEN",
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
        request = Request(
            f"http://127.0.0.1:{port}/malleus/tool-agent",
            data=json.dumps({"task": "check env"}).encode("utf-8"),
            headers={"content-type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    assert payload["final_answer"] == "allowed=allowed-value; blocked=missing"
    assert payload["metadata"]["agent_framework"] == "custom"


def test_agent_serve_isolated_rejects_ephemeral_port() -> None:
    result = CliRunner().invoke(app, ["agent", "serve", "missing:adapter", "--isolated", "--port", "0"])

    assert result.exit_code == 1
    assert "explicit non-zero port" in result.output


def test_agent_serve_sandbox_requires_isolated() -> None:
    result = CliRunner().invoke(app, ["agent", "serve", "missing:adapter", "--sandbox", "bwrap"])

    assert result.exit_code == 1
    assert "--sandbox requires --isolated" in result.output


def test_agent_serve_bwrap_requires_network_allowlist(monkeypatch) -> None:
    monkeypatch.setattr("malleus.agent_adapter.shutil.which", lambda name: "/usr/bin/bwrap" if name == "bwrap" else None)
    result = CliRunner().invoke(app, ["agent", "serve", "missing:adapter", "--isolated", "--sandbox", "bwrap", "--port", "8787"])

    assert result.exit_code == 1
    assert "--network-allowlist" in result.output


def test_agent_serve_blocked_network_requires_bwrap() -> None:
    result = CliRunner().invoke(app, ["agent", "serve", "missing:adapter", "--isolated", "--network-mode", "blocked", "--port", "8787"])

    assert result.exit_code == 1
    assert "--network-mode blocked requires --sandbox bwrap" in result.output


def test_agent_serve_isolated_bwrap_passes_only_allowlisted_environment(tmp_path: Path) -> None:
    if shutil.which("bwrap") is None:
        return
    module = tmp_path / "bwrap_adapter.py"
    module.write_text(
        """import os
from malleus.agent_adapter import AgentRequest, AgentResponse, BaseAgentAdapter

class Adapter(BaseAgentAdapter):
    target_type = "tool_agent"
    framework = "custom"

    def run(self, request: AgentRequest) -> AgentResponse:
        return AgentResponse(
            final_answer=f"allowed={os.environ.get('ALLOWED_TOKEN', '')}; blocked={os.environ.get('BLOCKED_TOKEN', 'missing')}"
        )

adapter = Adapter()
""",
        encoding="utf-8",
    )
    port = _free_port()
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{tmp_path}{os.pathsep}{Path('src').resolve()}{os.pathsep}{env.get('PYTHONPATH', '')}"
    env["ALLOWED_TOKEN"] = "allowed-value"
    env["BLOCKED_TOKEN"] = "blocked-value"
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "from malleus.cli import app; app()",
            "agent",
            "serve",
            "bwrap_adapter:adapter",
            "--target-type",
            "tool_agent",
            "--isolated",
            "--sandbox",
            "bwrap",
            "--network-allowlist",
            f"tcp://127.0.0.1:{port}",
            "--cwd",
            str(tmp_path),
            "--pythonpath",
            str(tmp_path),
            "--pythonpath",
            str(Path("src").resolve()),
            "--env",
            "ALLOWED_TOKEN",
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
        request = Request(
            f"http://127.0.0.1:{port}/malleus/tool-agent",
            data=json.dumps({"task": "check env"}).encode("utf-8"),
            headers={"content-type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    assert payload["final_answer"] == "allowed=allowed-value; blocked=missing"
    assert payload["metadata"]["agent_framework"] == "custom"


def test_agent_serve_isolated_bwrap_blocked_network_uses_stdio_proxy(tmp_path: Path) -> None:
    if shutil.which("bwrap") is None:
        return
    egress_port = _free_port()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", egress_port))
    listener.listen(1)
    listener.settimeout(0.2)
    module = tmp_path / "blocked_network_adapter.py"
    module.write_text(
        """import os
import socket
from malleus.agent_adapter import AgentRequest, AgentResponse, BaseAgentAdapter

class Adapter(BaseAgentAdapter):
    target_type = "tool_agent"
    framework = "custom"

    def run(self, request: AgentRequest) -> AgentResponse:
        port = int(os.environ["EGRESS_TEST_PORT"])
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                status = "opened"
        except OSError as exc:
            status = f"blocked:{type(exc).__name__}"
        return AgentResponse(final_answer=f"egress={status}")

adapter = Adapter()
""",
        encoding="utf-8",
    )
    port = _free_port()
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{tmp_path}{os.pathsep}{Path('src').resolve()}{os.pathsep}{env.get('PYTHONPATH', '')}"
    env["EGRESS_TEST_PORT"] = str(egress_port)
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "from malleus.cli import app; app()",
            "agent",
            "serve",
            "blocked_network_adapter:adapter",
            "--target-type",
            "tool_agent",
            "--isolated",
            "--sandbox",
            "bwrap",
            "--network-mode",
            "blocked",
            "--cwd",
            str(tmp_path),
            "--pythonpath",
            str(tmp_path),
            "--pythonpath",
            str(Path("src").resolve()),
            "--env",
            "EGRESS_TEST_PORT",
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
        request = Request(
            f"http://127.0.0.1:{port}/malleus/tool-agent",
            data=json.dumps({"task": "check network"}).encode("utf-8"),
            headers={"content-type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        listener.close()

    assert payload["final_answer"].startswith("egress=blocked:")
    assert payload["metadata"]["sandbox_backend"] == "bwrap"
    assert payload["metadata"]["sandbox_network"] == "blocked"


def test_agent_serve_blocked_network_tool_gateway_intercepts_tool_calls(tmp_path: Path) -> None:
    if shutil.which("bwrap") is None:
        return
    module = tmp_path / "gateway_adapter.py"
    module.write_text(
        """from malleus.agent_adapter import AgentRequest, AgentResponse, BaseAgentAdapter
from malleus.agent_tools import tool_call

class Adapter(BaseAgentAdapter):
    target_type = "tool_agent"
    framework = "custom"

    def run(self, request: AgentRequest) -> AgentResponse:
        allowed = tool_call("search", {"query": "policy"})
        blocked = tool_call("send_email", {"to": "public@example.test", "body": "hello"})
        return AgentResponse(final_answer=f"allowed={allowed['decision']['action']}; blocked={blocked['decision']['action']}")

adapter = Adapter()
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
            "serve",
            "gateway_adapter:adapter",
            "--target-type",
            "tool_agent",
            "--isolated",
            "--sandbox",
            "bwrap",
            "--network-mode",
            "blocked",
            "--cwd",
            str(tmp_path),
            "--pythonpath",
            str(tmp_path),
            "--pythonpath",
            str(Path("src").resolve()),
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
        request = Request(
            f"http://127.0.0.1:{port}/malleus/tool-agent",
            data=json.dumps({"task": "check gateway"}).encode("utf-8"),
            headers={"content-type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    assert payload["final_answer"] == "allowed=allowed; blocked=blocked"
    assert payload["metadata"]["tool_gateway"]["calls"] == 2
    assert payload["metadata"]["tool_gateway"]["blocked"] == 1
    assert payload["tool_calls"][0]["tool_name"] == "search"
    assert payload["tool_calls"][1]["tool_name"] == "send_email"
    assert payload["tool_calls"][1]["metadata"]["gateway_decision"] == "blocked"
    assert "forbidden_tool" in payload["tool_calls"][1]["metadata"]["gateway_reason_codes"]


def test_agent_serve_blocked_network_accepts_tool_policy_file(tmp_path: Path) -> None:
    if shutil.which("bwrap") is None:
        return
    policy = tmp_path / "tool-policy.yaml"
    policy.write_text(
        """schema_version: malleus.tool_gateway.v1
trusted_approval_sources: [trusted_harness]
tools:
  send_email:
    name: send_email
    allowed: true
    sink: external
    result: {sent: true}
""",
        encoding="utf-8",
    )
    module = tmp_path / "policy_gateway_adapter.py"
    module.write_text(
        """from malleus.agent_adapter import AgentRequest, AgentResponse, BaseAgentAdapter
from malleus.agent_tools import tool_call

class Adapter(BaseAgentAdapter):
    target_type = "tool_agent"
    framework = "custom"

    def run(self, request: AgentRequest) -> AgentResponse:
        result = tool_call("send_email", {"to": "public@example.test"})
        return AgentResponse(final_answer=f"send_email={result['decision']['action']}")

adapter = Adapter()
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
            "serve",
            "policy_gateway_adapter:adapter",
            "--target-type",
            "tool_agent",
            "--isolated",
            "--sandbox",
            "bwrap",
            "--network-mode",
            "blocked",
            "--tool-policy",
            str(policy),
            "--cwd",
            str(tmp_path),
            "--pythonpath",
            str(tmp_path),
            "--pythonpath",
            str(Path("src").resolve()),
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
        request = Request(
            f"http://127.0.0.1:{port}/malleus/tool-agent",
            data=json.dumps({"task": "check policy"}).encode("utf-8"),
            headers={"content-type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    assert payload["final_answer"] == "send_email=allowed"
    assert payload["metadata"]["tool_gateway"]["blocked"] == 0
    assert payload["tool_calls"][0]["metadata"]["gateway_decision"] == "allowed"


def load_agent_adapter_from_object(adapter: BaseAgentAdapter):
    module_name = "_test_agent_adapter_runtime"
    module = type(sys)(module_name)
    module.adapter = adapter
    sys.modules[module_name] = module
    return load_agent_adapter(f"{module_name}:adapter")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_server(process: subprocess.Popen[str], port: int) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout is not None else ""
            raise AssertionError(f"isolated server exited early with code {process.returncode}: {output}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            try:
                sock.connect(("127.0.0.1", port))
                return
            except OSError:
                time.sleep(0.05)
    output = process.stdout.read() if process.stdout is not None else ""
    raise AssertionError(f"isolated server did not listen on port {port}: {output}")
