from __future__ import annotations

import importlib
import inspect
import json
import os
import signal
import shutil
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from pydantic import BaseModel, Field

from malleus.agent_target_contracts import SURFACE_CONTRACTS
from malleus.schemas import HarnessArtifactRef, HarnessDiff, HarnessRetrieval, HarnessToolCall, HarnessTraceAction, TargetType
from malleus.system_harness_safety import build_bwrap_command
from malleus.tool_gateway import ToolDecision, ToolEvent, ToolGateway, ToolPolicy, ToolRequest, load_tool_policy
from malleus.utils.redact import redact_public_text, sha256_text


AGENT_ADAPTER_PROTOCOL_VERSION = "malleus.agent_adapter.v1"


class AgentAdapterError(ValueError):
    """Raised when an adapter cannot be loaded or executed."""


class AgentRequest(BaseModel):
    target_type: TargetType
    payload: dict[str, Any] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentResponse(BaseModel):
    final_answer: str = ""
    answer: str = ""
    prompts: list[dict[str, Any]] = Field(default_factory=list)
    messages: list[dict[str, Any]] = Field(default_factory=list)
    retrievals: list[HarnessRetrieval] = Field(default_factory=list)
    citations: list[dict[str, Any]] = Field(default_factory=list)
    tool_calls: list[HarnessToolCall] = Field(default_factory=list)
    actions: list[HarnessTraceAction] = Field(default_factory=list)
    trace: list[HarnessTraceAction] = Field(default_factory=list)
    memory_events: list[dict[str, Any]] = Field(default_factory=list)
    handoffs: list[dict[str, Any]] = Field(default_factory=list)
    approvals: list[dict[str, Any]] = Field(default_factory=list)
    refusals: list[dict[str, Any]] = Field(default_factory=list)
    browser_actions: list[dict[str, Any]] = Field(default_factory=list)
    navigation_events: list[dict[str, Any]] = Field(default_factory=list)
    network_egress: list[dict[str, Any]] = Field(default_factory=list)
    file_writes: list[dict[str, Any]] = Field(default_factory=list)
    subprocesses: list[dict[str, Any]] = Field(default_factory=list)
    retries: list[dict[str, Any]] = Field(default_factory=list)
    streaming_chunks: list[dict[str, Any]] = Field(default_factory=list)
    background_jobs: list[dict[str, Any]] = Field(default_factory=list)
    policy_blocks: list[dict[str, Any]] = Field(default_factory=list)
    capability_gaps: list[dict[str, Any]] = Field(default_factory=list)
    trace_events: list[dict[str, Any]] = Field(default_factory=list)
    sinks: list[dict[str, Any]] = Field(default_factory=list)
    blocked_operations: list[dict[str, Any]] = Field(default_factory=list)
    diffs: list[HarnessDiff] = Field(default_factory=list)
    artifacts: list[HarnessArtifactRef] = Field(default_factory=list)
    latency_seconds: float | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_http_payload(self) -> dict[str, Any]:
        payload = self.model_dump(mode="json", exclude_none=True)
        payload["schema_version"] = AGENT_ADAPTER_PROTOCOL_VERSION
        if not payload.get("answer"):
            payload["answer"] = payload.get("final_answer", "")
        if not payload.get("final_answer"):
            payload["final_answer"] = payload.get("answer", "")
        return payload


class BaseAgentAdapter:
    target_type: TargetType = "tool_agent"
    framework: str = "custom"

    def run(self, request: AgentRequest) -> AgentResponse | dict[str, Any]:
        raise NotImplementedError

    def health(self) -> dict[str, Any]:
        return {"ok": True, "target_type": self.target_type, "framework": self.framework}


@dataclass(frozen=True)
class LoadedAgentAdapter:
    import_path: str
    adapter: BaseAgentAdapter
    target_type: str
    framework: str
    route: str


def load_agent_adapter(import_path: str, *, target_type: str | None = None, framework: str | None = None, route: str | None = None) -> LoadedAgentAdapter:
    obj = _load_import_path(import_path)
    adapter = _coerce_adapter(obj)
    effective_target_type = target_type or str(getattr(adapter, "target_type", "tool_agent"))
    if effective_target_type not in SURFACE_CONTRACTS:
        raise AgentAdapterError(f"unsupported adapter target_type: {effective_target_type}")
    adapter.target_type = effective_target_type  # type: ignore[assignment]
    if framework:
        adapter.framework = framework
    contract = SURFACE_CONTRACTS[effective_target_type]
    return LoadedAgentAdapter(
        import_path=import_path,
        adapter=adapter,
        target_type=effective_target_type,
        framework=str(getattr(adapter, "framework", framework or "custom")),
        route=route or contract.default_endpoint_path or "/malleus/code-agent",
    )


def serve_agent_adapter(
    import_path: str,
    *,
    host: str = "127.0.0.1",
    port: int = 8787,
    target_type: str | None = None,
    framework: str | None = None,
    route: str | None = None,
) -> None:
    loaded = load_agent_adapter(import_path, target_type=target_type, framework=framework, route=route)
    serve_loaded_agent_adapter(loaded, host=host, port=port)


def serve_agent_adapter_isolated(
    import_path: str,
    *,
    host: str = "127.0.0.1",
    port: int = 8787,
    target_type: str | None = None,
    framework: str | None = None,
    route: str | None = None,
    cwd: str | Path | None = None,
    env_allowlist: list[str] | tuple[str, ...] = (),
    pythonpath: list[str | Path] | tuple[str | Path, ...] = (),
    startup_timeout: float = 10.0,
    sandbox: str = "none",
    network_allowlist: list[str] | tuple[str, ...] = (),
    network_mode: str = "shared",
    tool_policy: str | Path | ToolPolicy | None = None,
) -> None:
    if port <= 0:
        raise AgentAdapterError("isolated agent serving requires an explicit non-zero port")
    if sandbox not in {"none", "bwrap"}:
        raise AgentAdapterError("isolated agent sandbox must be none or bwrap")
    if network_mode not in {"shared", "blocked"}:
        raise AgentAdapterError("isolated agent network mode must be shared or blocked")
    if network_mode == "blocked" and sandbox != "bwrap":
        raise AgentAdapterError("--network-mode blocked requires --sandbox bwrap")
    gateway_policy = _resolve_tool_policy(tool_policy)
    child_env = _isolated_child_env(env_allowlist=env_allowlist, pythonpath=pythonpath)
    child_config = {
        "import_path": import_path,
        "host": host,
        "port": port,
        "target_type": target_type,
        "framework": framework,
        "route": route,
    }
    child_env["MALLEUS_AGENT_CHILD_CONFIG"] = json.dumps(child_config, sort_keys=True)
    if network_mode == "blocked":
        return _serve_agent_adapter_blocked_network(
            import_path,
            host=host,
            port=port,
            target_type=target_type,
            framework=framework,
            route=route,
            cwd=cwd,
            pythonpath=pythonpath,
            child_env=child_env,
            startup_timeout=startup_timeout,
            tool_policy=gateway_policy,
        )
    command = [
        sys.executable,
        "-c",
        "import json, os; from malleus.agent_adapter import serve_agent_adapter; serve_agent_adapter(**json.loads(os.environ['MALLEUS_AGENT_CHILD_CONFIG']))",
    ]
    if sandbox == "bwrap":
        command = _bwrap_isolated_command(
            command,
            cwd=cwd,
            pythonpath=pythonpath,
            host=host,
            port=port,
            network_allowlist=network_allowlist,
            allow_network=True,
        )
    process = subprocess.Popen(command, cwd=Path(cwd).expanduser() if cwd is not None else None, env=child_env)
    previous_sigterm = signal.getsignal(signal.SIGTERM)

    def handle_sigterm(signum: int, frame: Any) -> None:
        _terminate_process(process)
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, handle_sigterm)
    try:
        _wait_for_port(host, port, process, startup_timeout)
        print(f"Malleus isolated agent adapter child pid={process.pid} sandbox={sandbox} listening on http://{host}:{port}{route or ''}", flush=True)
        process.wait()
    except KeyboardInterrupt:
        _terminate_process(process)
        raise
    finally:
        signal.signal(signal.SIGTERM, previous_sigterm)
        if process.poll() is None:
            _terminate_process(process)


def serve_loaded_agent_adapter(loaded: LoadedAgentAdapter, *, host: str = "127.0.0.1", port: int = 8787) -> None:
    server = create_agent_adapter_server(loaded, host=host, port=port)
    print(f"Malleus agent adapter listening on http://{host}:{server.server_port}{loaded.route}", flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def create_agent_adapter_server(loaded: LoadedAgentAdapter, *, host: str = "127.0.0.1", port: int = 8787) -> ThreadingHTTPServer:
    handler = _handler_for(loaded)
    return ThreadingHTTPServer((host, port), handler)


class StdioAgentAdapter(BaseAgentAdapter):
    def __init__(self, process: subprocess.Popen[str], *, target_type: str, framework: str = "isolated_stdio", tool_gateway: ToolGateway | None = None) -> None:
        self._process = process
        self._lock = threading.Lock()
        self._next_id = 0
        self._tool_gateway = tool_gateway or ToolGateway()
        self.target_type = target_type  # type: ignore[assignment]
        self.framework = framework

    def health(self) -> dict[str, Any]:
        response = self._send({"kind": "health"})
        if not isinstance(response, dict):
            raise AgentAdapterError("stdio adapter health returned a non-object response")
        return response

    def run(self, request: AgentRequest) -> AgentResponse | dict[str, Any]:
        events: list[ToolEvent] = []
        response = self._send({"kind": "run", "request": request.model_dump(mode="json")}, tool_events=events)
        if not isinstance(response, dict):
            raise AgentAdapterError("stdio adapter run returned a non-object response")
        if events:
            response = _attach_tool_gateway_events(response, events)
        return response

    def _send(self, payload: dict[str, Any], *, tool_events: list[ToolEvent] | None = None) -> dict[str, Any]:
        if self._process.poll() is not None:
            raise AgentAdapterError(f"isolated stdio agent child exited; returncode={self._process.returncode}")
        if self._process.stdin is None or self._process.stdout is None:
            raise AgentAdapterError("isolated stdio agent pipes are unavailable")
        with self._lock:
            self._next_id += 1
            request_id = self._next_id
            outbound = {"id": request_id, **payload}
            self._process.stdin.write(json.dumps(outbound, sort_keys=True) + "\n")
            self._process.stdin.flush()
            while True:
                line = self._process.stdout.readline()
                if not line:
                    raise AgentAdapterError("isolated stdio agent child closed its response stream")
                inbound = _parse_stdio_message(line)
                if inbound.get("kind") == "tool_call":
                    event = self._handle_tool_call_message(inbound)
                    if tool_events is not None:
                        tool_events.append(event)
                    continue
                if inbound.get("id") != request_id:
                    raise AgentAdapterError("isolated stdio agent returned a mismatched response")
                break
        if inbound.get("ok") is not True:
            error = inbound.get("error", "AgentAdapterError")
            message = inbound.get("message", "isolated stdio agent request failed")
            raise AgentAdapterError(f"{error}: {message}")
        result = inbound.get("result", {})
        if not isinstance(result, dict):
            raise AgentAdapterError("isolated stdio agent response result must be an object")
        return result

    def _handle_tool_call_message(self, inbound: dict[str, Any]) -> ToolEvent:
        request_id = inbound.get("id")
        if self._process.stdin is None:
            raise AgentAdapterError("isolated stdio agent stdin pipe is unavailable")
        try:
            request = ToolRequest.model_validate(inbound.get("request") or {})
            result, event = self._tool_gateway.handle(request)
            payload = {"id": request_id, "ok": True, "result": result.model_dump(mode="json")}
        except Exception as exc:  # pragma: no cover - defensive protocol boundary
            event = ToolEvent(
                tool_name=str((inbound.get("request") or {}).get("tool_name", "unknown")) if isinstance(inbound.get("request"), dict) else "unknown",
                call_id=None,
                arguments={},
                decision=ToolDecision(
                    action="blocked",
                    allowed=False,
                    reason_codes=["gateway_error"],
                    reasons=[str(exc)],
                    policy_hash=self._tool_gateway.policy.policy_hash(),
                ),
                result_preview=str(exc),
            )
            payload = {"id": request_id, "ok": False, "error": type(exc).__name__, "message": str(exc)}
        self._process.stdin.write(json.dumps(payload, sort_keys=True) + "\n")
        self._process.stdin.flush()
        return event


def _parse_stdio_message(line: str) -> dict[str, Any]:
    try:
        inbound = json.loads(line)
    except json.JSONDecodeError as exc:
        raise AgentAdapterError("isolated stdio agent returned invalid JSON") from exc
    if not isinstance(inbound, dict):
        raise AgentAdapterError("isolated stdio agent returned a non-object response")
    return inbound


def _attach_tool_gateway_events(response: dict[str, Any], events: list[ToolEvent]) -> dict[str, Any]:
    merged = dict(response)
    existing_tool_calls = list(merged.get("tool_calls") or [])
    existing_actions = list(merged.get("actions") or [])
    existing_trace = list(merged.get("trace") or [])
    gateway_tool_calls = [event.to_tool_call().model_dump(mode="json", exclude_none=True) for event in events]
    gateway_actions = [event.to_trace_action().model_dump(mode="json", exclude_none=True) for event in events]
    merged["tool_calls"] = [*existing_tool_calls, *gateway_tool_calls]
    merged["actions"] = [*existing_actions, *gateway_actions]
    merged["trace"] = [*existing_trace, *gateway_actions]
    metadata = dict(merged.get("metadata") or {})
    metadata["tool_gateway"] = {
        "schema_version": "malleus.tool_gateway.v1",
        "policy_hash": events[-1].decision.policy_hash,
        "calls": len(events),
        "blocked": sum(1 for event in events if not event.decision.allowed),
        "reason_codes": sorted({code for event in events for code in event.decision.reason_codes}),
    }
    merged["metadata"] = metadata
    return merged


def load_import_object(import_path: str) -> Any:
    if ":" not in import_path:
        raise AgentAdapterError("adapter import path must use module:object syntax")
    module_name, object_path = import_path.split(":", 1)
    if not module_name or not object_path:
        raise AgentAdapterError("adapter import path must use module:object syntax")
    cwd = str(Path.cwd())
    if cwd not in sys.path:
        sys.path.insert(0, cwd)
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:  # pragma: no cover - importlib exception shape depends on user code
        raise AgentAdapterError(f"failed to import adapter module {module_name}: {exc}") from exc
    obj: Any = module
    for part in object_path.split("."):
        if not part:
            raise AgentAdapterError("adapter object path contains an empty segment")
        try:
            obj = getattr(obj, part)
        except AttributeError as exc:
            raise AgentAdapterError(f"adapter object not found: {import_path}") from exc
    return obj


def _load_import_path(import_path: str) -> Any:
    return load_import_object(import_path)


def _coerce_adapter(obj: Any) -> BaseAgentAdapter:
    if isinstance(obj, BaseAgentAdapter):
        return obj
    if isinstance(obj, type) and issubclass(obj, BaseAgentAdapter):
        return obj()
    if callable(obj):
        signature = inspect.signature(obj)
        required = [
            parameter
            for parameter in signature.parameters.values()
            if parameter.default is inspect.Parameter.empty
            and parameter.kind in {inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY}
        ]
        if len(required) == 1:
            return FunctionAgentAdapter(obj)
        produced = obj()
        if isinstance(produced, BaseAgentAdapter):
            return produced
        if callable(produced):
            return FunctionAgentAdapter(produced)
    raise AgentAdapterError("adapter must be a BaseAgentAdapter instance/class, factory, or zero-argument callable returning a callable")


class FunctionAgentAdapter(BaseAgentAdapter):
    def __init__(self, fn: Callable[[AgentRequest], AgentResponse | dict[str, Any]]) -> None:
        self._fn = fn
        self.framework = "function"

    def run(self, request: AgentRequest) -> AgentResponse | dict[str, Any]:
        return self._fn(request)


def _handler_for(loaded: LoadedAgentAdapter) -> type[BaseHTTPRequestHandler]:
    class AgentAdapterHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/health":
                self._json({**loaded.adapter.health(), "schema_version": AGENT_ADAPTER_PROTOCOL_VERSION, "route": loaded.route})
                return
            self.send_error(404)

        def do_POST(self) -> None:
            if self.path != loaded.route:
                self.send_error(404)
                return
            started = time.perf_counter()
            try:
                payload = self._read_json()
                request = AgentRequest(target_type=loaded.target_type, payload=payload, headers=_safe_headers(self.headers), metadata={"route": loaded.route, "import_path": loaded.import_path})
                response = _normalize_response(loaded.adapter.run(request), latency_seconds=time.perf_counter() - started, framework=loaded.framework, target_type=loaded.target_type)
            except Exception as exc:  # pragma: no cover - defensive HTTP boundary
                self._json({"schema_version": AGENT_ADAPTER_PROTOCOL_VERSION, "error": type(exc).__name__, "message": str(exc)}, status=500)
                return
            self._json(response.to_http_payload())

        def log_message(self, format: str, *args: object) -> None:
            return

        def _read_json(self) -> dict[str, Any]:
            length = int(self.headers.get("content-length", "0") or "0")
            if length <= 0:
                return {}
            parsed = json.loads(self.rfile.read(length))
            if not isinstance(parsed, dict):
                raise AgentAdapterError("adapter request body must be a JSON object")
            return parsed

        def _json(self, payload: dict[str, Any], status: int = 200) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return AgentAdapterHandler


def _serve_agent_adapter_blocked_network(
    import_path: str,
    *,
    host: str,
    port: int,
    target_type: str | None,
    framework: str | None,
    route: str | None,
    cwd: str | Path | None,
    pythonpath: list[str | Path] | tuple[str | Path, ...],
    child_env: dict[str, str],
    startup_timeout: float,
    tool_policy: ToolPolicy | None,
) -> None:
    effective_target_type = target_type or "tool_agent"
    if effective_target_type not in SURFACE_CONTRACTS:
        raise AgentAdapterError(f"unsupported adapter target_type: {effective_target_type}")
    effective_route = route or SURFACE_CONTRACTS[effective_target_type].default_endpoint_path or "/malleus/tool-agent"
    child_config = {
        "import_path": import_path,
        "target_type": effective_target_type,
        "framework": framework,
        "route": effective_route,
    }
    child_env["MALLEUS_AGENT_CHILD_CONFIG"] = json.dumps(child_config, sort_keys=True)
    command = [
        sys.executable,
        "-c",
        "from malleus.agent_adapter import run_agent_adapter_stdio_child; run_agent_adapter_stdio_child()",
    ]
    command = _bwrap_isolated_command(
        command,
        cwd=cwd,
        pythonpath=pythonpath,
        host=host,
        port=port,
        network_allowlist=(),
        allow_network=False,
    )
    process = subprocess.Popen(
        command,
        cwd=Path(cwd).expanduser() if cwd is not None else None,
        env=child_env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    loaded = LoadedAgentAdapter(
        import_path=import_path,
        adapter=StdioAgentAdapter(process, target_type=effective_target_type, framework=framework or "isolated_stdio", tool_gateway=ToolGateway(policy=tool_policy) if tool_policy is not None else None),
        target_type=effective_target_type,
        framework=framework or "isolated_stdio",
        route=effective_route,
    )
    previous_sigterm = signal.getsignal(signal.SIGTERM)

    def handle_sigterm(signum: int, frame: Any) -> None:
        _terminate_process(process)
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, handle_sigterm)
    server: ThreadingHTTPServer | None = None
    try:
        _wait_for_stdio_child(process, loaded.adapter, startup_timeout)
        server = create_agent_adapter_server(loaded, host=host, port=port)
        print(
            f"Malleus isolated agent adapter child pid={process.pid} sandbox=bwrap network=blocked proxy listening on http://{host}:{server.server_port}{effective_route}",
            flush=True,
        )
        server.serve_forever()
    except KeyboardInterrupt:
        _terminate_process(process)
        raise
    finally:
        signal.signal(signal.SIGTERM, previous_sigterm)
        if server is not None:
            server.server_close()
        if process.poll() is None:
            _terminate_process(process)


def run_agent_adapter_stdio_child() -> None:
    config = json.loads(os.environ["MALLEUS_AGENT_CHILD_CONFIG"])
    loaded = load_agent_adapter(
        config["import_path"],
        target_type=config.get("target_type"),
        framework=config.get("framework"),
        route=config.get("route"),
    )
    for line in sys.stdin:
        try:
            request = json.loads(line)
            if not isinstance(request, dict):
                raise AgentAdapterError("stdio request must be a JSON object")
            request_id = request.get("id")
            kind = request.get("kind")
            if kind == "health":
                result = {**loaded.adapter.health(), "schema_version": AGENT_ADAPTER_PROTOCOL_VERSION, "route": loaded.route}
            elif kind == "run":
                started = time.perf_counter()
                agent_request = AgentRequest.model_validate(request.get("request") or {})
                response = _normalize_response(
                    loaded.adapter.run(agent_request),
                    latency_seconds=time.perf_counter() - started,
                    framework=loaded.framework,
                    target_type=loaded.target_type,
                )
                metadata = dict(response.metadata)
                metadata.setdefault("sandbox_backend", "bwrap")
                metadata.setdefault("sandbox_network", "blocked")
                response.metadata = metadata
                result = response.to_http_payload()
            else:
                raise AgentAdapterError("stdio request kind must be health or run")
            _write_stdio_response({"id": request_id, "ok": True, "result": result})
        except Exception as exc:  # pragma: no cover - defensive protocol boundary
            request_id = request.get("id") if isinstance(locals().get("request"), dict) else None
            _write_stdio_response({"id": request_id, "ok": False, "error": type(exc).__name__, "message": str(exc)})


def _write_stdio_response(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")
    sys.stdout.flush()


def _resolve_tool_policy(policy: str | Path | ToolPolicy | None) -> ToolPolicy | None:
    if policy is None:
        return None
    if isinstance(policy, ToolPolicy):
        return policy
    try:
        return load_tool_policy(policy)
    except Exception as exc:
        raise AgentAdapterError(f"failed to load tool gateway policy: {exc}") from exc


def _normalize_response(response: AgentResponse | dict[str, Any], *, latency_seconds: float, framework: str, target_type: str) -> AgentResponse:
    if isinstance(response, AgentResponse):
        normalized = response
    elif isinstance(response, dict):
        normalized = AgentResponse.model_validate(response)
    else:
        raise AgentAdapterError("adapter run() must return AgentResponse or dict")
    metadata = dict(normalized.metadata)
    metadata.setdefault("agent_framework", framework)
    metadata.setdefault("agent_target_depth", "L2")
    metadata.setdefault("target_type", target_type)
    trace_events = _response_trace_events(normalized)
    if trace_events:
        existing = metadata.get("agent_trace_events")
        metadata["agent_trace_events"] = [*(existing if isinstance(existing, list) else []), *trace_events]
    normalized.metadata = metadata
    if normalized.latency_seconds is None:
        normalized.latency_seconds = latency_seconds
    return normalized


def _response_trace_events(response: AgentResponse) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    events.extend(_normalized_explicit_events(response.trace_events))
    events.extend(_events_from_text_items("prompt_input", response.prompts, direction="input"))
    events.extend(_message_events(response.messages))
    events.extend(_tool_call_events(response.tool_calls))
    events.extend(_events_from_items("retrieval", response.retrievals))
    events.extend(_events_from_items("citation", response.citations))
    events.extend(_events_from_items("action", response.actions))
    events.extend(_events_from_items("action", response.trace))
    events.extend(_events_from_text_items("refusal", response.refusals, direction="output"))
    events.extend(_events_from_items("approval", response.approvals))
    events.extend(_events_from_items("handoff", response.handoffs))
    events.extend(_memory_events(response.memory_events))
    events.extend(_events_from_items("browser_action", response.browser_actions))
    events.extend(_events_from_items("navigation", response.navigation_events))
    events.extend(_events_from_items("network_egress", response.network_egress))
    events.extend(_events_from_items("file_write", response.file_writes))
    events.extend(_events_from_items("command_execution", response.subprocesses))
    events.extend(_events_from_items("retry", response.retries))
    events.extend(_events_from_text_items("streaming_chunk", response.streaming_chunks, direction="output"))
    events.extend(_events_from_items("background_job", response.background_jobs))
    events.extend(_events_from_items("policy_block", response.policy_blocks))
    events.extend(_events_from_items("sink", response.sinks))
    events.extend(_events_from_items("blocked_operation", response.blocked_operations, status="blocked"))
    events.extend(_events_from_items("file_diff", response.diffs))
    events.extend(_events_from_items("artifact", response.artifacts))
    events.extend(_events_from_items("capability_gap", response.capability_gaps, status="gap"))
    if response.final_answer or response.answer:
        events.append(_text_event("final_answer", response.final_answer or response.answer, direction="output", event_id="adapter-final-answer"))
    return events


def _normalized_explicit_events(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        event = {key: _safe_trace_value(value) for key, value in item.items() if key != "text"}
        event.setdefault("event_type", str(item.get("event_type") or item.get("type") or "action"))
        event.setdefault("event_id", f"adapter-explicit-event-{index + 1}")
        if isinstance(item.get("text"), str):
            event.update(_text_fields(item["text"]))
        events.append(event)
    return events


def _message_events(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for index, item in enumerate(items):
        role = str(item.get("role") or "message").lower()
        event_type = {"system": "system_message", "developer": "developer_message", "user": "user_message"}.get(role, "message")
        text = str(item.get("content") or item.get("text") or item.get("message") or "")
        event = _text_event(event_type, text, direction="input", event_id=str(item.get("id") or f"message-{index + 1}")) if text else {"event_type": event_type, "event_id": str(item.get("id") or f"message-{index + 1}"), "direction": "input"}
        event["role"] = role
        event["metadata"] = _safe_item_metadata(item, skip={"content", "text", "message", "role", "id"})
        events.append(event)
    return events


def _memory_events(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for index, item in enumerate(items):
        item = _item_dict(item)
        if not item:
            continue
        operation = str(item.get("type") or item.get("operation") or item.get("action_type") or "memory_event").lower()
        if "read" in operation:
            event_type = "memory_read"
        elif any(token in operation for token in ("write", "store", "update", "delete")):
            event_type = "memory_write"
        else:
            event_type = "memory_event"
        events.append(_item_event(event_type, item, index=index))
    return events


def _events_from_text_items(event_type: str, items: list[dict[str, Any]], *, direction: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for index, item in enumerate(items):
        text = str(item.get("content") or item.get("text") or item.get("prompt") or item.get("chunk") or item.get("message") or "")
        event = _text_event(event_type, text, direction=direction, event_id=str(item.get("id") or f"{event_type}-{index + 1}")) if text else _item_event(event_type, item, index=index, direction=direction)
        event["metadata"] = _safe_item_metadata(item, skip={"content", "text", "prompt", "chunk", "message", "id"})
        events.append(event)
    return events


def _tool_call_events(items: list[HarnessToolCall]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for index, item in enumerate(items):
        data = _item_dict(item)
        if not data:
            continue
        tool_name = str(data.get("tool_name") or data.get("name") or f"tool-{index + 1}")
        event_id = str(data.get("call_id") or data.get("id") or f"tool-call-{index + 1}")
        events.append(
            {
                "event_type": "tool_call",
                "event_id": event_id,
                "summary": redact_public_text(f"called {tool_name}", limit=160).text,
                "status": str(data.get("status") or "ok"),
                "direction": "output",
                "name": tool_name,
                "metadata": _safe_item_metadata(data, skip={"tool_name", "name", "call_id", "id", "status", "arguments", "result_preview"}),
            }
        )
        arguments = data.get("arguments")
        if isinstance(arguments, dict) and arguments:
            events.append(
                {
                    "event_type": "tool_args",
                    "event_id": f"{event_id}:args",
                    "summary": redact_public_text(f"arguments for {tool_name}", limit=160).text,
                    "status": "ok",
                    "direction": "output",
                    "name": tool_name,
                    "metadata": {"arguments": _safe_trace_value(arguments)},
                }
            )
        result_preview = data.get("result_preview")
        if isinstance(result_preview, str) and result_preview:
            output_event = _text_event("tool_output", result_preview, direction="input", event_id=f"{event_id}:output")
            output_event["name"] = tool_name
            events.append(output_event)
    return events


def _events_from_items(event_type: str, items: list[Any], *, status: str = "ok") -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for index, item in enumerate(items):
        data = _item_dict(item)
        if data:
            events.append(_item_event(event_type, data, index=index, status=status))
    return events


def _item_event(event_type: str, item: dict[str, Any], *, index: int, status: str = "ok", direction: str = "internal") -> dict[str, Any]:
    label = str(item.get("id") or item.get("event_id") or item.get("call_id") or item.get("action_id") or f"{event_type}-{index + 1}")
    summary = str(item.get("summary") or item.get("rationale") or item.get("reason") or event_type.replace("_", " "))
    event = {
        "event_type": event_type,
        "event_id": label,
        "summary": redact_public_text(summary, limit=160).text,
        "status": str(item.get("status") or status),
        "direction": direction,
        "metadata": _safe_item_metadata(item, skip={"summary", "rationale", "reason", "id", "event_id", "call_id", "action_id", "status"}),
    }
    name = item.get("name") or item.get("tool_name") or item.get("artifact_type") or item.get("path")
    if isinstance(name, str) and name:
        event["name"] = redact_public_text(name, limit=120).text
    return event


def _text_event(event_type: str, value: str, *, direction: str, event_id: str) -> dict[str, Any]:
    return {"event_type": event_type, "event_id": event_id, "summary": event_type.replace("_", " "), "status": "ok", "direction": direction, **_text_fields(value)}


def _text_fields(value: str) -> dict[str, Any]:
    redacted = redact_public_text(value, limit=180)
    return {"redacted_preview": redacted.text, "sha256": sha256_text(value), "length": len(value)}


def _safe_item_metadata(item: dict[str, Any], *, skip: set[str]) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key, value in item.items():
        if key in skip:
            continue
        safe[str(key)] = _safe_trace_value(value)
    return safe


def _item_dict(item: Any) -> dict[str, Any]:
    if isinstance(item, dict):
        return item
    if isinstance(item, BaseModel):
        return item.model_dump(mode="json", exclude_none=True)
    return {}


def _safe_trace_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_public_text(value, limit=120).text
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        return [_safe_trace_value(entry) for entry in value[:20]]
    if isinstance(value, dict):
        return {str(k): _safe_trace_value(v) for k, v in list(value.items())[:20]}
    return redact_public_text(str(value), limit=120).text


def _safe_headers(headers: Any) -> dict[str, str]:
    blocked = {"authorization", "cookie", "set-cookie", "x-api-key"}
    safe: dict[str, str] = {}
    for key, value in headers.items():
        lower = str(key).lower()
        if lower in blocked:
            safe[str(key)] = "<redacted>"
        elif lower.startswith("x-malleus-"):
            safe[str(key)] = str(value)
    return safe


def _isolated_child_env(*, env_allowlist: list[str] | tuple[str, ...], pythonpath: list[str | Path] | tuple[str | Path, ...]) -> dict[str, str]:
    env: dict[str, str] = {}
    for name in ("PATH", "VIRTUAL_ENV", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"):
        value = os.environ.get(name)
        if value:
            env[name] = value
    for name in env_allowlist:
        if not name:
            continue
        value = os.environ.get(name)
        if value is not None:
            env[name] = value
    path_entries = [str(Path(entry).expanduser()) for entry in pythonpath]
    existing_pythonpath = os.environ.get("PYTHONPATH") if "PYTHONPATH" in env_allowlist else None
    if existing_pythonpath:
        path_entries.append(existing_pythonpath)
    if path_entries:
        env["PYTHONPATH"] = os.pathsep.join(path_entries)
    return env


def _bwrap_isolated_command(
    command: list[str],
    *,
    cwd: str | Path | None,
    pythonpath: list[str | Path] | tuple[str | Path, ...],
    host: str,
    port: int,
    network_allowlist: list[str] | tuple[str, ...],
    allow_network: bool,
) -> list[str]:
    bwrap = shutil.which("bwrap")
    if not bwrap:
        raise AgentAdapterError("bubblewrap sandbox is unavailable for isolated agent serving")
    if allow_network and not network_allowlist:
        raise AgentAdapterError("bwrap isolated agent serving requires --network-allowlist for explicit shared-network intent")
    bind_origin = f"tcp://{host}:{port}"
    if allow_network and bind_origin not in set(network_allowlist) and host not in set(network_allowlist):
        raise AgentAdapterError(f"bwrap isolated agent serving network allowlist must include {bind_origin}")
    workspace = Path(cwd).expanduser().resolve() if cwd is not None else Path.cwd().resolve()
    runtime_paths = [
        "/lib",
        "/lib64",
        "/usr/lib",
        "/usr/local/lib",
        "/etc/ld.so.cache",
        "/etc/resolv.conf",
        "/etc/nsswitch.conf",
        "/etc/hosts",
        "/etc/ssl/certs",
        "/usr/share/ca-certificates",
        *[str(Path(entry).expanduser().resolve()) for entry in pythonpath],
    ]
    for prefix in (sys.base_prefix, sys.prefix, sys.exec_prefix, sys.base_exec_prefix):
        if prefix:
            runtime_paths.extend([str(Path(prefix)), str(Path(prefix) / "lib"), str(Path(prefix) / "lib64")])
    return build_bwrap_command(
        command,
        workspace=workspace,
        executable_paths=(),
        runtime_bind_paths=tuple(dict.fromkeys(runtime_paths)),
        allow_network=allow_network,
        bwrap_path=bwrap,
    )


def _wait_for_stdio_child(process: subprocess.Popen[Any], adapter: BaseAgentAdapter, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last_error = ""
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AgentAdapterError(f"isolated stdio agent child exited before health check; returncode={process.returncode}")
        try:
            adapter.health()
            return
        except AgentAdapterError as exc:
            last_error = str(exc)
            time.sleep(0.05)
    raise AgentAdapterError(f"isolated stdio agent child did not pass health check within {timeout:.1f}s: {last_error}")


def _wait_for_port(host: str, port: int, process: subprocess.Popen[Any], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AgentAdapterError(f"isolated agent adapter child exited before serving; returncode={process.returncode}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            try:
                sock.connect((host, port))
                return
            except OSError:
                time.sleep(0.05)
    raise AgentAdapterError(f"isolated agent adapter child did not listen on {host}:{port} within {timeout:.1f}s")


def _terminate_process(process: subprocess.Popen[Any]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


__all__ = [
    "AGENT_ADAPTER_PROTOCOL_VERSION",
    "AgentAdapterError",
    "AgentRequest",
    "AgentResponse",
    "BaseAgentAdapter",
    "LoadedAgentAdapter",
    "create_agent_adapter_server",
    "load_agent_adapter",
    "load_import_object",
    "serve_agent_adapter",
    "serve_agent_adapter_isolated",
    "serve_loaded_agent_adapter",
]
