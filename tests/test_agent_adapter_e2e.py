from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

from typer.testing import CliRunner

from malleus.cli import app


def test_agent_serve_subprocess_runs_live_agentic_surface(tmp_path: Path) -> None:
    adapter_module = tmp_path / "e2e_adapter.py"
    adapter_module.write_text(
        """from malleus.agent_adapter import AgentRequest, AgentResponse, BaseAgentAdapter
from malleus.schemas import HarnessToolCall, HarnessTraceAction

class Adapter(BaseAgentAdapter):
    target_type = "tool_agent"
    framework = "custom"

    def run(self, request: AgentRequest) -> AgentResponse:
        allowed_tools = request.payload.get("allowed_tools") or ["summarize_document"]
        tool_name = allowed_tools[0]
        return AgentResponse(
            final_answer="completed with allowed tool only",
            tool_calls=[
                HarnessToolCall(
                    tool_name=tool_name,
                    arguments={"classification": "internal_only"},
                    result_preview="safe internal result",
                )
            ],
            actions=[HarnessTraceAction(action_type="tool_call", summary=f"called {tool_name}")],
            metadata={"agent_framework": "custom", "agent_target_depth": "L2"},
        )

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
            "e2e_adapter:adapter",
            "--target-type",
            "tool_agent",
            "--framework",
            "custom",
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
        target_path = tmp_path / "tool-agent-target.yaml"
        target_path.write_text(
            f"""name: e2e-tool-agent
target_type: tool_agent
metadata:
  agent_framework: custom
  agent_target_depth: L2
tool_agent:
  endpoint_url: http://127.0.0.1:{port}/malleus/tool-agent
  auth:
    bearer_token_env: MALLEUS_E2E_AGENT_TOKEN
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
            env={"MALLEUS_E2E_AGENT_TOKEN": "test-token"},
        )
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    assert result.exit_code == 0, result.output
    assert "Live surface evidence written" in result.output
    assert "Surface: agentic-injection-v1" in result.output
    assert "Evidence level: live_system_trace" in result.output

    report = json.loads((tmp_path / "reports" / "live-full-evidence.json").read_text(encoding="utf-8"))
    row = report["rows"][0]
    assert row["status"] == "passed"
    assert row["metadata"]["target_type"] == "tool_agent"
    assert row["metadata"]["target_call_count"] > 0
    assert row["metadata"]["target_trace_count"] > 0


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_server(process: subprocess.Popen[str], port: int) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout is not None else ""
            raise AssertionError(f"agent server exited early with code {process.returncode}: {output}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            try:
                sock.connect(("127.0.0.1", port))
                return
            except OSError:
                time.sleep(0.05)
    output = process.stdout.read() if process.stdout is not None else ""
    raise AssertionError(f"agent server did not listen on port {port}: {output}")
