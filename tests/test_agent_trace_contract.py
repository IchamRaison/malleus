from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from malleus.agent_trace import AGENT_TRACE_SCHEMA_VERSION, CANONICAL_AGENT_TRACE_EVENT_TYPES, build_agent_trace
from malleus.code_agent_harness import run_code_agent_harness
from malleus.datasets import load_target_config
from malleus.memory_agent_harness import run_memory_agent_harness
from malleus.multi_agent_harness import run_multi_agent_harness
from malleus.rag_service_harness import run_rag_service_harness
from malleus.schemas import HarnessResult
from malleus.tool_agent_harness import run_tool_agent_harness
from malleus.workflow_harness import run_workflow_harness


def test_agent_trace_schema_serializes_common_capability_gap_contract() -> None:
    trace = build_agent_trace(
        target_type="tool_agent",
        evidence_type="agent_trace",
        case_id="case-1",
        result_status="target_capability_gap",
        reason_codes=["missing_tool_trace"],
        harness_result=HarnessResult(target_type="tool_agent", metadata={"live_model_calls": 0}),
        target_call_count=1,
        target_trace_count=0,
        evidence_ref="tool-agent-report.json#/results/0",
        artifact_refs_list=[],
    )

    payload = trace.model_dump()
    assert payload["schema_version"] == AGENT_TRACE_SCHEMA_VERSION
    assert payload["status"] == "capability_gap"
    assert payload["capability_gaps"] == ["missing_tool_trace"]
    assert payload["target_type"] == "tool_agent"
    assert payload["evidence_type"] == "agent_trace"
    assert any(event["event_type"] == "capability_gap" for event in payload["events"])


def test_agent_trace_schema_captures_full_production_event_vocabulary() -> None:
    result = HarnessResult(
        target_type="tool_agent",
        output_text="Final safe answer.",
        tool_calls=[],
        metadata={
            "live_model_calls": 1,
            "agent_trace_events": [
                {"event_type": "prompt_input", "event_id": "prompt-1", "redacted_preview": "Summarize the support ticket.", "sha256": "a" * 64, "length": 29},
                {"event_type": "system_message", "event_id": "system-1", "role": "system", "redacted_preview": "[REDACTED]", "sha256": "0" * 64, "length": 42},
                {"event_type": "developer_message", "event_id": "developer-1", "redacted_preview": "[REDACTED]", "sha256": "1" * 64, "length": 43},
                {"event_type": "user_message", "event_id": "user-1", "redacted_preview": "user task", "sha256": "2" * 64, "length": 9},
                {"event_type": "message", "event_id": "assistant-message-1", "role": "assistant", "redacted_preview": "intermediate thought", "sha256": "3" * 64, "length": 20},
                {"event_type": "tool_call", "event_id": "tool-1", "name": "lookup"},
                {"event_type": "tool_args", "event_id": "tool-1-args", "parent_event_id": "tool-1"},
                {"event_type": "tool_output", "event_id": "tool-1-output", "parent_event_id": "tool-1", "redacted_preview": "ok"},
                {"event_type": "refusal", "event_id": "refusal-1"},
                {"event_type": "approval", "event_id": "approval-1"},
                {"event_type": "handoff", "event_id": "handoff-1"},
                {"event_type": "memory_read", "event_id": "memory-read-1"},
                {"event_type": "memory_write", "event_id": "memory-write-1"},
                {"event_type": "browser_action", "event_id": "browser-action-1"},
                {"event_type": "navigation", "event_id": "navigation-1"},
                {"event_type": "network_egress", "event_id": "egress-1"},
                {"event_type": "file_write", "event_id": "file-write-1"},
                {"event_type": "command_execution", "event_id": "cmd-1"},
                {"event_type": "retry", "event_id": "retry-1"},
                {"event_type": "streaming_chunk", "event_id": "chunk-1", "redacted_preview": "part"},
                {"event_type": "background_job", "event_id": "job-1"},
                {"event_type": "policy_block", "event_id": "block-1"},
                {"event_type": "sink", "event_id": "sink-1", "name": "internal_audit_log"},
                {"event_type": "blocked_operation", "event_id": "blocked-1", "status": "blocked"},
                {"event_type": "capability_gap", "event_id": "gap-1", "status": "gap"},
            ],
        },
    )

    trace = build_agent_trace(
        target_type="tool_agent",
        evidence_type="agent_trace",
        case_id="case-full-trace",
        result_status="passed",
        reason_codes=[],
        harness_result=result,
        target_call_count=1,
        target_trace_count=24,
        evidence_ref="tool-agent-report.json#/results/0",
        artifact_refs_list=[],
    )
    event_types = {event.event_type for event in trace.events}

    assert set(CANONICAL_AGENT_TRACE_EVENT_TYPES) - {"citation", "retrieval", "memory_event", "file_diff", "action", "artifact"} <= event_types
    assert trace.live_model_calls == 1
    assert trace.events[-1].event_type == "final_answer"


def test_agent_trace_explicit_events_are_recursively_redacted() -> None:
    secret = "sk-proj-" + "B" * 32
    # Bypass HarnessResult validation deliberately: this test exercises the
    # second-line redaction defense inside agent_trace for already-collected
    # explicit trace events.
    result = HarnessResult.model_construct(
        target_type="tool_agent",
        output_text="safe final",
        metadata={
            "agent_trace_events": [
                {
                    "event_type": "network_egress",
                    "event_id": "egress-1",
                    "summary": f"blocked {secret}",
                    "metadata": {"raw": f"nested {secret}", "items": [f"list {secret}"]},
                }
            ]
        },
    )

    trace = build_agent_trace(
        target_type="tool_agent",
        evidence_type="agent_trace",
        case_id="case-redaction",
        result_status="passed",
        reason_codes=[],
        harness_result=result,
        target_call_count=1,
        target_trace_count=1,
        evidence_ref=None,
        artifact_refs_list=[],
    )
    trace_text = json.dumps(trace.model_dump(mode="json"), sort_keys=True)

    assert secret not in trace_text
    assert "[REDACTED]" in trace_text


def test_rag_service_report_contains_canonical_agent_trace(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("MALLEUS_RAG_SERVICE_API_KEY", "rag-service-api-key-value-001")
    monkeypatch.setenv("MALLEUS_RAG_SERVICE_BEARER", "rag-service-bearer-token-value-002")
    monkeypatch.setenv("MALLEUS_RAG_SERVICE_CUSTOM", "rag-service-custom-header-value-003")

    def handler(payload, headers):
        return {
            "answer": "Tenant policy summary. Citations: [trusted-policy]",
            "retrieved_documents": [{"id": "trusted-policy", "title": "Tenant policy"}],
            "citations": ["trusted-policy"],
        }

    with _fake_json_service(handler) as endpoint:
        report = run_rag_service_harness(_rag_target(tmp_path, endpoint), _rag_fixture(tmp_path), tmp_path / "out")

    trace = report.agent_traces[0]
    assert trace.schema_version == AGENT_TRACE_SCHEMA_VERSION
    assert trace.target_type == "rag_service"
    assert trace.evidence_type == "service_trace"
    assert trace.status == "ok"
    assert trace.target_call_count == 1
    assert any(event.event_type == "retrieval" for event in trace.events)
    assert report.metadata["agent_trace_count"] == 1
    assert report.agent_trace_summary.total_traces == 1
    assert report.agent_trace_summary.evidence_type_counts == {"service_trace": 1}


def test_tool_agent_missing_trace_becomes_canonical_capability_gap(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("MALLEUS_TOOL_AGENT_API_KEY", "tool-agent-api-key-value-001")
    monkeypatch.setenv("MALLEUS_TOOL_AGENT_BEARER", "tool-agent-bearer-token-value-002")
    monkeypatch.setenv("MALLEUS_TOOL_AGENT_CUSTOM", "tool-agent-custom-header-value-003")

    with _fake_json_service(lambda payload, headers: {"final_answer": "No tool trace."}) as endpoint:
        report = run_tool_agent_harness(_tool_target(tmp_path, endpoint), Path("datasets/agentic/agentic_injection_smoke.yaml"), tmp_path / "out", limit=1)

    trace = report.agent_traces[0]
    assert trace.target_type == "tool_agent"
    assert trace.evidence_type == "agent_trace"
    assert trace.status == "capability_gap"
    assert trace.capability_gaps == ["missing_tool_trace"]
    assert report.agent_trace_summary.capability_gap_count == 1
    assert report.agent_trace_summary.capability_gaps == ["missing_tool_trace"]


def test_workflow_report_contains_canonical_workflow_trace(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("MALLEUS_WORKFLOW_API_KEY", "workflow-api-key-value-001")
    monkeypatch.setenv("MALLEUS_WORKFLOW_BEARER", "workflow-bearer-token-value-002")
    monkeypatch.setenv("MALLEUS_WORKFLOW_CUSTOM", "workflow-custom-header-value-003")

    def handler(payload, headers):
        return {
            "final_status": "planned",
            "planned_actions": [{"id": "step-1", "action_type": "lookup_ticket", "status": "ok"}],
            "approvals": [{"source": "policy", "trusted": True, "approved": True}],
            "sinks": [{"name": "internal_audit_log", "external": False}],
        }

    with _fake_json_service(handler) as endpoint:
        report = run_workflow_harness(_workflow_target(tmp_path, endpoint), _workflow_fixture(tmp_path), tmp_path / "out")

    trace = report.agent_traces[0]
    assert trace.target_type == "workflow_harness"
    assert trace.evidence_type == "workflow_trace"
    assert trace.status == "ok"
    assert trace.metadata["approval_count"] == 1
    assert any(event.event_type == "action" for event in trace.events)
    assert report.agent_trace_summary.event_type_counts["action"] >= 1


def test_code_agent_report_contains_canonical_code_agent_trace(tmp_path: Path) -> None:
    fixture = _code_fixture_repo(tmp_path)
    target = _code_target(
        tmp_path,
        _code_script(
            tmp_path,
            """
from pathlib import Path
Path('app.py').write_text('def answer():\\n    return 42\\n', encoding='utf-8')
print('safe edit complete')
""",
        ),
    )

    report = run_code_agent_harness(load_target_config(target), fixture, tmp_path / "out", sandbox_backend="fake_test")

    trace = report.agent_traces[0]
    assert trace.target_type == "code_agent"
    assert trace.evidence_type == "code_agent_trace"
    assert trace.status == "ok"
    assert trace.metadata["changed_files"] == ["app.py"]
    assert any(event.event_type == "file_diff" for event in trace.events)
    assert report.agent_trace_summary.event_type_counts["file_diff"] == 1


def test_memory_agent_report_contains_canonical_memory_trace(tmp_path: Path) -> None:
    def handler(payload, headers):
        return {
            "final_answer": "Kept memory unchanged.",
            "memory_events": [{"type": "read", "key": "safe_preference", "tenant_id": "tenant-a", "trusted": True}],
        }

    with _fake_json_service(handler) as endpoint:
        report = run_memory_agent_harness(_memory_target(tmp_path, endpoint), Path("tests/fixtures/memory/memory-agent-v1.yaml"), tmp_path / "out", limit=1)

    trace = report.agent_traces[0]
    assert trace.target_type == "memory_agent"
    assert trace.evidence_type == "memory_trace"
    assert trace.status == "ok"
    assert report.agent_trace_summary.event_type_counts["memory_read"] == 2


def test_multi_agent_missing_handoff_becomes_canonical_capability_gap(tmp_path: Path) -> None:
    with _fake_json_service(lambda payload, headers: {"final_answer": "No handoff trace."}) as endpoint:
        report = run_multi_agent_harness(_multi_agent_target(tmp_path, endpoint), Path("tests/fixtures/multi_agent/multi-agent-v1.yaml"), tmp_path / "out", limit=1)

    trace = report.agent_traces[0]
    assert trace.target_type == "multi_agent"
    assert trace.evidence_type == "multi_agent_trace"
    assert trace.status == "capability_gap"
    assert trace.capability_gaps == ["missing_multi_agent_handoff_trace"]


def _rag_fixture(tmp_path: Path) -> Path:
    fixture = tmp_path / "rag.yaml"
    fixture.write_text(
        """
name: rag-fixture
documents:
  - id: trusted-policy
    tenant: tenant-a
    title: Tenant policy
    body: Use account-help for notification preferences.
queries:
  - id: safe
    tenant: tenant-a
    question: Where should notification preference requests go?
    expected_citations: [trusted-policy]
""",
        encoding="utf-8",
    )
    return fixture


def _rag_target(tmp_path: Path, endpoint: str) -> Path:
    target = tmp_path / "rag-target.yaml"
    target.write_text(
        f"""name: local-rag-service
target_type: rag_service
rag_service:
  endpoint_url: {endpoint}
  index_name: test-index
  auth:
    api_key_env: MALLEUS_RAG_SERVICE_API_KEY
    bearer_token_env: MALLEUS_RAG_SERVICE_BEARER
    headers_env:
      x-custom-token: MALLEUS_RAG_SERVICE_CUSTOM
  request:
    timeout: 5
""",
        encoding="utf-8",
    )
    return target


def _tool_target(tmp_path: Path, endpoint: str) -> Path:
    target = tmp_path / "tool-target.yaml"
    target.write_text(
        f"""name: local-tool-agent
target_type: tool_agent
tool_agent:
  endpoint_url: {endpoint}
  auth:
    api_key_env: MALLEUS_TOOL_AGENT_API_KEY
    bearer_token_env: MALLEUS_TOOL_AGENT_BEARER
    headers_env:
      x-custom-token: MALLEUS_TOOL_AGENT_CUSTOM
  allowed_tools:
    - search
    - read_policy
    - no_tool_available
  request:
    timeout: 5
""",
        encoding="utf-8",
    )
    return target


def _workflow_target(tmp_path: Path, endpoint: str) -> Path:
    target = tmp_path / "workflow-target.yaml"
    target.write_text(
        f"""name: local-workflow
target_type: workflow_harness
metadata:
  workflow_harness_mode: dry_run
workflow_harness:
  endpoint_url: {endpoint}
  workflow_id: wf-test
  environment: sandbox
  auth:
    api_key_env: MALLEUS_WORKFLOW_API_KEY
    bearer_token_env: MALLEUS_WORKFLOW_BEARER
    headers_env:
      x-custom-token: MALLEUS_WORKFLOW_CUSTOM
  request:
    timeout: 5
""",
        encoding="utf-8",
    )
    return target


def _workflow_fixture(tmp_path: Path) -> Path:
    fixture = tmp_path / "workflow.yaml"
    fixture.write_text(
        """
name: workflow-fixture
workflow_id: wf-test
mode: dry_run
objective: Review support ticket.
input:
  ticket_id: T-100
allowed_actions:
  - lookup_ticket
allowed_sinks:
  - internal_audit_log
required_approvals:
  - policy
""",
        encoding="utf-8",
    )
    return fixture


def _code_fixture_repo(tmp_path: Path) -> Path:
    fixture = tmp_path / "fixture-repo"
    fixture.mkdir()
    fixture.joinpath("app.py").write_text("def answer():\n    return 1\n", encoding="utf-8")
    return fixture


def _code_script(tmp_path: Path, body: str) -> Path:
    script = tmp_path / "agent.py"
    script.write_text(body.strip() + "\n", encoding="utf-8")
    return script


def _code_target(tmp_path: Path, script: Path) -> Path:
    target = tmp_path / "code-target.yaml"
    target.write_text(
        f"""name: local-code-agent
target_type: code_agent
metadata:
  code_agent_command:
    - {json.dumps(sys.executable)}
    - {json.dumps(str(script))}
code_agent:
  workspace_path: fixture-placeholder
  request:
    timeout: 5
""",
        encoding="utf-8",
    )
    return target


def _memory_target(tmp_path: Path, endpoint: str) -> Path:
    target = tmp_path / "memory-target.yaml"
    target.write_text(
        f"""name: local-memory-agent
target_type: memory_agent
memory_agent:
  endpoint_url: {endpoint}
  namespace: test
  user_id: user-a
  request:
    timeout: 5
""",
        encoding="utf-8",
    )
    return target


def _multi_agent_target(tmp_path: Path, endpoint: str) -> Path:
    target = tmp_path / "multi-agent-target.yaml"
    target.write_text(
        f"""name: local-multi-agent
target_type: multi_agent
multi_agent:
  endpoint_url: {endpoint}
  team_id: team-a
  allowed_roles:
    - planner
    - reviewer
  request:
    timeout: 5
""",
        encoding="utf-8",
    )
    return target


class _fake_json_service:
    def __init__(self, handler: Callable[[dict[str, Any], dict[str, str]], dict[str, Any]]) -> None:
        self._handler = handler
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> str:
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                return

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("content-length") or "0")
                payload = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
                response = owner._handler(payload, dict(self.headers))
                body = json.dumps(response).encode("utf-8")
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        host, port = self._server.server_address
        return f"http://{host}:{port}/target"

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
