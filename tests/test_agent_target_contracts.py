from __future__ import annotations

import json
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from contextlib import contextmanager
from typing import Any, Iterator

from typer.testing import CliRunner

from malleus.agent_target_contracts import doctor_agent_target, scaffold_agent_target, validate_agent_target
from malleus.cli import app
from malleus.datasets import load_target_config


def test_validate_l2_tool_agent_target_accepts_external_agent_contract(tmp_path: Path) -> None:
    target = tmp_path / "tool-agent.yaml"
    target.write_text(
        """name: Real Tool Agent
target_type: tool_agent
metadata:
  agent_framework: langgraph
  agent_target_depth: L2
tool_agent:
  endpoint_url: http://127.0.0.1:8787/malleus/tool-agent
  auth:
    bearer_token_env: TOOL_AGENT_TOKEN
  allowed_tools:
    - search
    - submit_result
""",
        encoding="utf-8",
    )

    result = validate_agent_target(target)

    assert result.valid
    assert result.target_type == "tool_agent"
    assert result.framework == "langgraph"
    assert result.required_endpoint_path == "/malleus/tool-agent"
    assert "tool_calls" in result.response_fields
    assert "malleus benchmark live-agentic" in result.live_command


def test_validate_chat_target_is_not_l2_agent_contract(tmp_path: Path) -> None:
    target = tmp_path / "chat.yaml"
    target.write_text(
        "name: chat\nadapter: openai_compatible\nmodel: m\nbase_url: https://example.test/v1\napi_key_env: CHAT_KEY\n",
        encoding="utf-8",
    )

    result = validate_agent_target(target)

    assert not result.valid
    assert "unsupported L2 agent target_type" in result.errors[0]


def test_validate_l2_tool_agent_requires_env_auth(tmp_path: Path) -> None:
    target = tmp_path / "tool-agent.yaml"
    target.write_text(
        """name: Tool Agent
target_type: tool_agent
metadata:
  agent_framework: custom
tool_agent:
  endpoint_url: http://127.0.0.1:8787/malleus/tool-agent
""",
        encoding="utf-8",
    )

    result = validate_agent_target(target)

    assert not result.valid
    assert "tool_agent auth config requires" in result.errors[0]


def test_scaffold_agent_target_writes_loadable_yaml_and_adapter(tmp_path: Path) -> None:
    result = scaffold_agent_target(name="Crew Tool Agent", target_type="tool_agent", framework="crewai", out_dir=tmp_path)

    assert result.target_path.exists()
    assert result.adapter_path.exists()
    assert result.readme_path.exists()
    assert "run_real_agent" in result.adapter_path.read_text(encoding="utf-8")

    config = load_target_config(result.target_path)
    assert config.target_type == "tool_agent"
    assert config.metadata["agent_framework"] == "crewai"
    assert config.tool_agent is not None
    assert config.tool_agent.endpoint_url.endswith("/malleus/tool-agent")

    validation = validate_agent_target(result.target_path)
    assert validation.valid


def test_target_scaffold_agent_cli_and_validate_agent_cli(tmp_path: Path) -> None:
    runner = CliRunner()
    scaffold = runner.invoke(
        app,
        [
            "target",
            "scaffold-agent",
            "--name",
            "LangGraph Memory",
            "--target-type",
            "memory_agent",
            "--framework",
            "langgraph",
            "--out-dir",
            str(tmp_path),
        ],
    )

    assert scaffold.exit_code == 0, scaffold.output
    assert "agent_scaffold: ok" in scaffold.output
    target_path = tmp_path / "langgraph-memory.yaml"
    assert target_path.exists()

    validation = runner.invoke(app, ["target", "validate-agent", str(target_path)])
    assert validation.exit_code == 0, validation.output
    assert "agent_contract: ok" in validation.output
    assert "framework: langgraph" in validation.output
    assert "endpoint_path: /malleus/memory-agent" in validation.output


def test_target_validate_agent_cli_fails_for_chat_target(tmp_path: Path) -> None:
    target = tmp_path / "chat.yaml"
    target.write_text(
        "name: chat\nadapter: openai_compatible\nmodel: m\nbase_url: https://example.test/v1\napi_key_env: CHAT_KEY\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["target", "validate-agent", str(target)])

    assert result.exit_code == 1
    assert "agent_contract: failed" in result.output
    assert "unsupported L2 agent target_type" in result.output


def test_target_doctor_reports_endpoint_auth_trace_safety_and_matrix(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "tool-agent.yaml"
    target.write_text(
        """name: Tool Agent
target_type: tool_agent
metadata:
  agent_framework: langgraph
  agent_target_depth: L2
  side_effect_safety: local_only
tool_agent:
  endpoint_url: http://127.0.0.1:8787/malleus/tool-agent
  auth:
    bearer_token_env: TOOL_AGENT_TOKEN
  allowed_tools:
    - classify_ticket
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("TOOL_AGENT_TOKEN", "synthetic-token")

    report = doctor_agent_target(target)

    assert report.valid
    assert {check.name for check in report.checks} == {"endpoint", "auth", "trace_fields", "side_effect_safety", "coverage_matrix"}
    assert any(row["area"] == "trace" and row["field"] == "tool_call" for row in report.coverage_matrix)
    assert any(check.name == "auth" and check.status == "passed" for check in report.checks)

    out_dir = tmp_path / "doctor"
    result = CliRunner().invoke(app, ["target", "doctor", str(target), "--out-dir", str(out_dir)])

    assert result.exit_code == 0, result.output
    assert "Malleus target doctor" in result.output
    assert "Status: ready" in result.output
    assert "Coverage:" in result.output
    assert (out_dir / "target-doctor.json").exists()
    assert (out_dir / "target-doctor.md").exists()


def test_rag_target_doctor_live_probe_checks_retrieval_citation_and_trace(tmp_path: Path, monkeypatch) -> None:
    seen: list[dict[str, Any]] = []

    def handler(payload: dict[str, Any]) -> dict[str, Any]:
        seen.append(payload)
        doc_id = payload["documents"][0]["id"]
        return {
            "answer": "The doctor should verify retrieval ids, citations, tenant metadata, and trace events.",
            "retrievals": [{"id": doc_id, "tenant_id": payload["tenant_id"]}],
            "citations": [{"id": doc_id}],
            "trace": [{"event_type": "retrieval", "document_id": doc_id}],
            "metadata": {"malleus_doctor_probe": True, "tenant_id": payload["tenant_id"]},
        }

    with _fake_json_service(handler) as endpoint:
        target = tmp_path / "rag.yaml"
        target.write_text(
            f"""name: Real RAG
target_type: rag_service
metadata:
  agent_framework: langchain
  side_effect_safety: local_only
rag_service:
  endpoint_url: {endpoint}/malleus/rag
  auth:
    bearer_token_env: RAG_TOKEN
""",
            encoding="utf-8",
        )
        monkeypatch.setenv("RAG_TOKEN", "synthetic-rag-token")

        report = doctor_agent_target(target, probe_endpoint=True)

    endpoint_check = next(check for check in report.checks if check.name == "endpoint")
    assert report.valid
    assert endpoint_check.status == "passed"
    assert endpoint_check.evidence["probe_method"] == "POST"
    assert endpoint_check.evidence["retrieval_ids"] == ["malleus-doctor-current-policy"]
    assert endpoint_check.evidence["citation_ids"] == ["malleus-doctor-current-policy"]
    assert endpoint_check.evidence["trace_present"] is True
    assert endpoint_check.evidence["tenant_metadata_preserved"] is True
    assert seen and seen[0]["documents"][0]["id"] == "malleus-doctor-current-policy"


@contextmanager
def _fake_json_service(handler: Any) -> Iterator[str]:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0") or 0)
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            response = json.dumps(handler(payload)).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
