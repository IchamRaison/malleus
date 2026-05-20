from __future__ import annotations

from typing import Any, Literal

from malleus.agent_adapter import AgentAdapterError, AgentRequest, AgentResponse, BaseAgentAdapter, LoadedAgentAdapter, load_import_object, serve_loaded_agent_adapter
from malleus.agent_target_contracts import SURFACE_CONTRACTS
from malleus.schemas import HarnessDiff, HarnessRetrieval, HarnessToolCall, HarnessTraceAction, TargetType


GenericInputMode = Literal["payload", "text", "messages"]
GenericRunMode = Literal["auto", "run", "invoke", "call", "kickoff", "initiate_chat"]


class GenericCallableAgentAdapter(BaseAgentAdapter):
    """Dependency-free adapter for plain Python agent objects and callables."""

    framework = "generic_callable"

    def __init__(
        self,
        obj: Any,
        *,
        target_type: TargetType = "tool_agent",
        input_mode: GenericInputMode = "payload",
        run_mode: GenericRunMode = "auto",
    ) -> None:
        self.obj = obj
        self.target_type = target_type
        self.input_mode = input_mode
        self.run_mode = run_mode

    def run(self, request: AgentRequest) -> AgentResponse:
        agent_input = _agent_input(request.payload, self.input_mode)
        output = self._execute(agent_input, request)
        return _response_from_generic_output(output, target_type=str(self.target_type), input_mode=self.input_mode, run_mode=self.run_mode)

    def health(self) -> dict[str, Any]:
        return {
            "ok": True,
            "target_type": self.target_type,
            "framework": self.framework,
            "input_mode": self.input_mode,
            "run_mode": self.run_mode,
            "object_type": type(self.obj).__name__,
        }

    def _execute(self, agent_input: Any, request: AgentRequest) -> Any:
        if isinstance(self.obj, BaseAgentAdapter):
            return self.obj.run(request)
        candidates = []
        if self.run_mode == "auto":
            candidates = ["run", "invoke", "kickoff", "initiate_chat", "call"]
        else:
            candidates = [self.run_mode]
        for name in candidates:
            if name == "call" and callable(self.obj):
                return self.obj(agent_input)
            method = getattr(self.obj, name, None)
            if callable(method):
                return _call_with_best_input(method, agent_input=agent_input, request=request)
        raise AgentAdapterError("generic callable adapter requires run(), invoke(), kickoff(), initiate_chat(), or a callable object")


def load_generic_agent_adapter(
    import_path: str,
    *,
    target_type: str = "tool_agent",
    input_mode: GenericInputMode = "payload",
    run_mode: GenericRunMode = "auto",
    route: str | None = None,
) -> LoadedAgentAdapter:
    if target_type not in SURFACE_CONTRACTS:
        raise AgentAdapterError(f"unsupported generic adapter target_type: {target_type}")
    if input_mode not in {"payload", "text", "messages"}:
        raise AgentAdapterError("generic adapter input_mode must be payload, text, or messages")
    if run_mode not in {"auto", "run", "invoke", "call", "kickoff", "initiate_chat"}:
        raise AgentAdapterError("generic adapter run_mode must be auto, run, invoke, call, kickoff, or initiate_chat")
    obj = load_import_object(import_path)
    adapter = GenericCallableAgentAdapter(obj, target_type=target_type, input_mode=input_mode, run_mode=run_mode)  # type: ignore[arg-type]
    contract = SURFACE_CONTRACTS[target_type]
    return LoadedAgentAdapter(
        import_path=import_path,
        adapter=adapter,
        target_type=target_type,
        framework="generic_callable",
        route=route or contract.default_endpoint_path or "/malleus/tool-agent",
    )


def serve_generic_agent_adapter(
    import_path: str,
    *,
    target_type: str = "tool_agent",
    input_mode: GenericInputMode = "payload",
    run_mode: GenericRunMode = "auto",
    host: str = "127.0.0.1",
    port: int = 8787,
    route: str | None = None,
) -> None:
    loaded = load_generic_agent_adapter(import_path, target_type=target_type, input_mode=input_mode, run_mode=run_mode, route=route)
    serve_loaded_agent_adapter(loaded, host=host, port=port)


def _agent_input(payload: dict[str, Any], input_mode: str) -> Any:
    if input_mode == "payload":
        return dict(payload)
    text = _payload_to_text(payload)
    if input_mode == "messages":
        return [{"role": "user", "content": text}]
    return text


def _payload_to_text(payload: dict[str, Any]) -> str:
    parts: list[str] = []
    for label, key in (
        ("Objective", "objective"),
        ("Task", "user_task"),
        ("Query", "query"),
        ("Prompt", "prompt"),
        ("Page task", "fixture_prompt"),
        ("Untrusted context", "untrusted_context"),
    ):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            parts.append(f"{label}: {value.strip()}")
    for label, key in (("Allowed tools", "allowed_tools"), ("Available tools", "available_tools"), ("Forbidden tools", "forbidden_tools")):
        value = payload.get(key)
        if isinstance(value, list) and value:
            parts.append(f"{label}: {', '.join(str(item) for item in value)}")
    return "\n\n".join(parts) or str(payload)


def _response_from_generic_output(output: Any, *, target_type: str, input_mode: str, run_mode: str) -> AgentResponse:
    if isinstance(output, AgentResponse):
        metadata = dict(output.metadata)
        metadata.setdefault("agent_framework", "generic_callable")
        metadata.setdefault("agent_target_depth", "L2")
        metadata.setdefault("target_type", target_type)
        metadata.setdefault("input_mode", input_mode)
        metadata.setdefault("run_mode", run_mode)
        output.metadata = metadata
        return output
    raw = _model_dump(output)
    output_metadata = _metadata(raw)
    final = _answer(raw)
    tool_calls = [_tool_call(item, index) for index, item in enumerate(_nested_list_values(raw, ("tool_calls", "tools", "function_calls")))]
    actions = [_action(item, index) for index, item in enumerate(_nested_list_values(raw, ("actions", "trace", "events", "steps")))]
    retrievals = [_retrieval(item, index) for index, item in enumerate(_nested_list_values(raw, ("retrievals", "documents", "source_documents", "source_nodes", "citations")))]
    diffs = [_diff(item, index) for index, item in enumerate(_nested_list_values(raw, ("diffs", "patches", "changes")))]
    memory_events = _dict_items(raw, ("memory_events",))
    handoffs = _dict_items(raw, ("handoffs", "handoff_events"))
    approvals = _dict_items(raw, ("approvals",))
    refusals = _dict_items(raw, ("refusals",))
    browser_actions = _dict_items(raw, ("browser_actions",))
    navigation_events = _dict_items(raw, ("navigation_events", "navigations"))
    network_egress = _dict_items(raw, ("network_egress", "network_events"))
    file_writes = _dict_items(raw, ("file_writes",))
    subprocesses = _dict_items(raw, ("subprocesses", "commands", "command_executions"))
    retries = _dict_items(raw, ("retries",))
    streaming_chunks = _dict_items(raw, ("streaming_chunks",))
    background_jobs = _dict_items(raw, ("background_jobs",))
    policy_blocks = _dict_items(raw, ("policy_blocks",))
    sinks = _dict_items(raw, ("sinks",))
    blocked_operations = _dict_items(raw, ("blocked_operations", "blocks"))
    trace_events = _dict_items(raw, ("trace_events", "agent_trace_events"))
    return AgentResponse(
        final_answer=final,
        answer=final,
        retrievals=[item for item in retrievals if item is not None],
        citations=[{"source_id": item.source_id} for item in retrievals if item is not None],
        tool_calls=[item for item in tool_calls if item is not None],
        actions=[item for item in actions if item is not None],
        trace=[item for item in actions if item is not None],
        memory_events=memory_events,
        handoffs=handoffs,
        approvals=approvals,
        refusals=refusals,
        browser_actions=browser_actions,
        navigation_events=navigation_events,
        network_egress=network_egress,
        file_writes=file_writes,
        subprocesses=subprocesses,
        retries=retries,
        streaming_chunks=streaming_chunks,
        background_jobs=background_jobs,
        policy_blocks=policy_blocks,
        sinks=sinks,
        blocked_operations=blocked_operations,
        trace_events=trace_events,
        diffs=[item for item in diffs if item is not None],
        metadata={
            **output_metadata,
            "agent_framework": "generic_callable",
            "agent_target_depth": "L2",
            "target_type": target_type,
            "input_mode": input_mode,
            "run_mode": run_mode,
            "raw_type": type(output).__name__,
        },
    )


def _answer(value: Any) -> str:
    if isinstance(value, str):
        return value
    text = _first_string(value, ("final_answer", "answer", "final_output", "output", "response", "text", "content", "result"))
    if text:
        return text
    messages = _nested_list_values(value, ("messages",))
    for message in reversed(messages):
        text = _first_string(message, ("content", "text", "message"))
        if text:
            return text
    return ""


def _tool_call(value: Any, index: int) -> HarnessToolCall | None:
    raw = _model_dump(value)
    if not isinstance(raw, dict):
        return None
    function = raw.get("function") if isinstance(raw.get("function"), dict) else {}
    name = _first_string(raw, ("tool_name", "tool", "name", "function", "action")) or _first_string(function, ("name", "tool_name"))
    if not name:
        return None
    args = _first_dict(raw, ("arguments", "args", "input", "parameters")) or _first_dict(function, ("arguments", "args", "parameters"))
    status = str(raw.get("status") or "ok").lower()
    return HarnessToolCall(
        tool_name=name,
        call_id=_first_string(raw, ("call_id", "id", "tool_call_id")) or f"generic-tool-call-{index + 1}",
        arguments=args,
        result_preview=_first_string(raw, ("result", "output", "observation", "content")) or None,
        status="error" if status in {"error", "failed", "failure", "denied", "blocked"} else "ok",
        metadata={"source": "generic_callable"},
    )


def _action(value: Any, index: int) -> HarnessTraceAction | None:
    raw = _model_dump(value)
    if not isinstance(raw, dict):
        return None
    action_type = _first_string(raw, ("action_type", "action", "type", "event", "name")) or "generic_event"
    return HarnessTraceAction(
        action_type=action_type,
        action_id=_first_string(raw, ("action_id", "id", "event_id")) or f"generic-action-{index + 1}",
        summary=_first_string(raw, ("summary", "rationale", "description", "content", "message")) or f"Generic action observed: {action_type}",
        status="error" if str(raw.get("status") or "").lower() in {"error", "failed", "failure"} else "ok",
        metadata={"source": "generic_callable", "selector": _first_string(raw, ("selector",)) or None},
    )


def _retrieval(value: Any, index: int) -> HarnessRetrieval | None:
    raw = _model_dump(value)
    if isinstance(raw, str):
        return HarnessRetrieval(source_id=f"generic-source-{index + 1}", redacted_preview=raw, metadata={"source": "generic_callable"})
    if not isinstance(raw, dict):
        return None
    metadata = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}
    source_id = _first_string(raw, ("source_id", "id", "doc_id", "node_id", "citation")) or _first_string(metadata, ("source_id", "id", "doc_id")) or f"generic-source-{index + 1}"
    return HarnessRetrieval(
        source_id=source_id,
        title=_first_string(raw, ("title", "name")) or _first_string(metadata, ("title", "name")) or None,
        uri=_first_string(raw, ("uri", "url", "source")) or _first_string(metadata, ("uri", "url", "source")) or None,
        score=raw.get("score") if isinstance(raw.get("score"), (int, float)) else None,
        redacted_preview=_first_string(raw, ("redacted_preview", "preview", "excerpt", "text", "content")) or None,
        citation=_first_string(raw, ("citation",)) or source_id,
        metadata={"source": "generic_callable"},
    )


def _metadata(value: Any) -> dict[str, Any]:
    if isinstance(value, dict) and isinstance(value.get("metadata"), dict):
        return dict(value["metadata"])
    return {}


def _dict_items(value: Any, keys: tuple[str, ...]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for item in _nested_list_values(value, keys):
        raw = _model_dump(item)
        if isinstance(raw, dict):
            items.append(raw)
    return items


def _diff(value: Any, index: int) -> HarnessDiff | None:
    raw = _model_dump(value)
    if not isinstance(raw, dict):
        return None
    return HarnessDiff(
        path=_first_string(raw, ("path", "file", "filename")) or f"generic-diff-{index + 1}",
        change_type=_first_string(raw, ("change_type", "type", "operation")) or "modified",
        redacted_diff=_first_string(raw, ("redacted_diff", "diff", "patch")) or "",
        metadata={"source": "generic_callable"},
    )


def _nested_list_values(value: Any, keys: tuple[str, ...]) -> list[Any]:
    found: list[Any] = []

    def visit(item: Any) -> None:
        item = _model_dump(item)
        if isinstance(item, dict):
            for key in keys:
                raw = item.get(key)
                if isinstance(raw, list):
                    found.extend(raw)
            for nested in item.values():
                if isinstance(nested, (dict, list)) or hasattr(nested, "__dict__"):
                    visit(nested)
        elif isinstance(item, list):
            for nested in item:
                visit(nested)

    visit(value)
    return found


def _model_dump(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if hasattr(value, "dict") and callable(value.dict):
        return value.dict()
    if hasattr(value, "__dict__") and not isinstance(value, type):
        return dict(value.__dict__)
    return value


def _first_string(value: Any, keys: tuple[str, ...]) -> str:
    value = _model_dump(value)
    if not isinstance(value, dict):
        return str(value) if isinstance(value, str) else ""
    for key in keys:
        item = value.get(key)
        if isinstance(item, str) and item:
            return item
    return ""


def _first_dict(value: Any, keys: tuple[str, ...]) -> dict[str, Any]:
    value = _model_dump(value)
    if not isinstance(value, dict):
        return {}
    for key in keys:
        item = value.get(key)
        if isinstance(item, dict):
            return item
        if isinstance(item, str) and item.strip():
            return {"raw": item}
    return {}


def _call_with_best_input(method: Any, *, agent_input: Any, request: AgentRequest) -> Any:
    try:
        annotation = next(iter(getattr(method, "__annotations__", {}).values()))
    except StopIteration:
        annotation = None
    if annotation is AgentRequest:
        return method(request)
    try:
        import inspect

        signature = inspect.signature(method)
    except (TypeError, ValueError):
        signature = None
    if signature is not None:
        params = list(signature.parameters.values())
        if params:
            name = params[0].name.lower()
            if name in {"request", "agent_request", "malleus_request"}:
                return method(request)
    try:
        return method(agent_input)
    except AttributeError as exc:
        if "payload" in str(exc):
            return method(request)
        raise


__all__ = ["GenericCallableAgentAdapter", "load_generic_agent_adapter", "serve_generic_agent_adapter"]
