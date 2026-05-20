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

from malleus.agent_adapter import AgentRequest, create_agent_adapter_server
from malleus.agent_frameworks.rag import load_langchain_rag_adapter, load_llamaindex_rag_adapter
from malleus.cli import app


class _Document:
    def __init__(self, page_content: str, metadata: dict[str, object]) -> None:
        self.page_content = page_content
        self.metadata = metadata


class _SourceNode:
    def __init__(self, text: str, metadata: dict[str, object], score: float = 0.8) -> None:
        self.text = text
        self.metadata = metadata
        self.score = score


def test_langchain_rag_adapter_extracts_chain_answer_and_source_documents() -> None:
    class Chain:
        def invoke(self, payload: dict[str, object]) -> dict[str, object]:
            assert payload["query"] == "What is the policy?"
            return {
                "answer": "Use the trusted policy.",
                "source_documents": [_Document("trusted excerpt", {"source_id": "trusted-policy", "title": "Trusted policy"})],
            }

    adapter = load_langchain_rag_adapter_from_object(Chain()).adapter
    response = adapter.run(AgentRequest(target_type="rag_service", payload={"query": "What is the policy?"}))

    assert response.answer == "Use the trusted policy."
    assert response.retrievals[0].source_id == "trusted-policy"
    assert response.retrievals[0].redacted_preview == "trusted excerpt"
    assert response.citations == [{"source_id": "trusted-policy"}]
    assert response.metadata["agent_framework"] == "langchain"


def test_langchain_rag_mapping_mode_preserves_supplied_documents() -> None:
    seen: dict[str, object] = {}

    class Chain:
        def invoke(self, payload: dict[str, object]) -> dict[str, object]:
            seen.update(payload)
            documents = payload["documents"]
            assert isinstance(documents, list)
            return {
                "answer": "Answered from supplied documents.",
                "retrievals": documents,
            }

    adapter = load_langchain_rag_adapter_from_object(Chain()).adapter
    response = adapter.run(
        AgentRequest(
            target_type="rag_service",
            payload={
                "query_id": "safe",
                "query": "What is the policy?",
                "tenant": "tenant-a",
                "retrieved_ids": ["trusted-policy"],
                "documents": [{"id": "trusted-policy", "text": "trusted excerpt", "title": "Trusted policy"}],
                "retrieved_documents": [{"id": "trusted-policy", "text": "trusted excerpt", "title": "Trusted policy"}],
            },
        )
    )

    assert seen["retrieved_ids"] == ["trusted-policy"]
    assert seen["documents"] == [{"id": "trusted-policy", "text": "trusted excerpt", "title": "Trusted policy"}]
    assert response.retrievals[0].source_id == "trusted-policy"


def test_langchain_rag_adapter_can_wrap_retriever_directly() -> None:
    class Retriever:
        def get_relevant_documents(self, query: str):
            return [_Document("billing guide", {"id": "trusted-billing-guide", "title": "Billing guide"})]

    adapter = load_langchain_rag_adapter_from_object(Retriever(), run_mode="retrieve").adapter
    response = adapter.run(AgentRequest(target_type="rag_service", payload={"query": "billing"}))

    assert response.retrievals[0].source_id == "trusted-billing-guide"
    assert response.answer == ""


def test_llamaindex_rag_adapter_extracts_response_and_source_nodes() -> None:
    class QueryEngine:
        def query(self, query: str):
            return {
                "response": "Tenant policy wins.",
                "source_nodes": [_SourceNode("tenant policy excerpt", {"doc_id": "trusted-billing-guide", "title": "Billing"}, score=0.91)],
            }

    adapter = load_llamaindex_rag_adapter_from_object(QueryEngine()).adapter
    response = adapter.run(AgentRequest(target_type="rag_service", payload={"query": "policy priority"}))

    assert response.answer == "Tenant policy wins."
    assert response.retrievals[0].source_id == "trusted-billing-guide"
    assert response.retrievals[0].score == 0.91
    assert response.metadata["agent_framework"] == "llamaindex"


def test_langchain_rag_http_server_uses_rag_route() -> None:
    class Chain:
        def invoke(self, payload: dict[str, object]) -> dict[str, object]:
            return {"answer": "ok", "source_documents": [_Document("excerpt", {"source_id": "trusted-policy"})]}

    loaded = load_langchain_rag_adapter_from_object(Chain())
    server = create_agent_adapter_server(loaded, port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        request = Request(
            f"http://{host}:{port}/malleus/rag",
            data=json.dumps({"query": "policy"}).encode("utf-8"),
            headers={"content-type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    finally:
        server.shutdown()
        server.server_close()

    assert payload["answer"] == "ok"
    assert payload["retrievals"][0]["source_id"] == "trusted-policy"
    assert payload["citations"][0]["source_id"] == "trusted-policy"


def test_rag_adapter_inspect_cli_loads_langchain_and_llamaindex(tmp_path: Path, monkeypatch) -> None:
    module = tmp_path / "rag_app.py"
    module.write_text(
        """class Chain:
    def invoke(self, payload):
        return {"answer": "ok", "source_documents": [{"id": "doc"}]}

class QueryEngine:
    def query(self, query):
        return {"response": "ok", "source_nodes": [{"id": "node"}]}

chain = Chain()
query_engine = QueryEngine()
""",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))

    langchain = CliRunner().invoke(app, ["agent", "inspect-langchain-rag", "rag_app:chain"])
    llamaindex = CliRunner().invoke(app, ["agent", "inspect-llamaindex-rag", "rag_app:query_engine"])

    assert langchain.exit_code == 0, langchain.output
    assert "langchain_rag_adapter: ok" in langchain.output
    assert "target_type: rag_service" in langchain.output
    assert llamaindex.exit_code == 0, llamaindex.output
    assert "llamaindex_rag_adapter: ok" in llamaindex.output
    assert "route: /malleus/rag" in llamaindex.output


def test_serve_langchain_rag_subprocess_runs_live_rag_surface(tmp_path: Path) -> None:
    module = tmp_path / "rag_app.py"
    module.write_text(
        """class Document:
    def __init__(self, page_content, metadata):
        self.page_content = page_content
        self.metadata = metadata

class Chain:
    def invoke(self, payload):
        query_id = payload.get("query_id") or ""
        if "billing" in str(payload.get("query", "")).lower() or "source-priority" in query_id or "stale-authority" in query_id:
            doc_id = "trusted-billing-guide"
        elif "password" in str(payload.get("query", "")).lower() or "tenant-leak" in query_id:
            doc_id = "trusted-password-policy"
        else:
            doc_id = "public-policy"
        return {
            "answer": "Safe answer based only on trusted retrieved evidence.",
            "source_documents": [Document("trusted evidence excerpt", {"source_id": doc_id, "title": "Trusted evidence"})],
        }

chain = Chain()
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
            "serve-langchain-rag",
            "rag_app:chain",
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
        target_path = tmp_path / "langchain-rag-target.yaml"
        target_path.write_text(
            f"""name: langchain-rag
target_type: rag_service
metadata:
  agent_framework: langchain
  agent_target_depth: L2
rag_service:
  endpoint_url: http://127.0.0.1:{port}/malleus/rag
  auth:
    bearer_token_env: MALLEUS_LANGCHAIN_RAG_TOKEN
  request:
    timeout: 5
""",
            encoding="utf-8",
        )

        result = CliRunner().invoke(
            app,
            [
                "benchmark",
                "live-rag",
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
            env={"MALLEUS_LANGCHAIN_RAG_TOKEN": "test-token"},
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
    assert row["metadata"]["target_type"] == "rag_service"
    assert row["metadata"]["target_call_count"] > 0
    assert row["metadata"]["target_trace_count"] > 0


def load_langchain_rag_adapter_from_object(obj, *, run_mode: str = "auto"):
    module_name = f"_test_langchain_rag_runtime_{id(obj)}"
    module = type(sys)(module_name)
    module.obj = obj
    sys.modules[module_name] = module
    return load_langchain_rag_adapter(f"{module_name}:obj", run_mode=run_mode)  # type: ignore[arg-type]


def load_llamaindex_rag_adapter_from_object(obj, *, run_mode: str = "auto"):
    module_name = f"_test_llamaindex_rag_runtime_{id(obj)}"
    module = type(sys)(module_name)
    module.obj = obj
    sys.modules[module_name] = module
    return load_llamaindex_rag_adapter(f"{module_name}:obj", run_mode=run_mode)  # type: ignore[arg-type]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_server(process: subprocess.Popen[str], port: int) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout is not None else ""
            raise AssertionError(f"rag adapter server exited early with code {process.returncode}: {output}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            try:
                sock.connect(("127.0.0.1", port))
                return
            except OSError:
                time.sleep(0.05)
    output = process.stdout.read() if process.stdout is not None else ""
    raise AssertionError(f"rag adapter server did not listen on port {port}: {output}")
