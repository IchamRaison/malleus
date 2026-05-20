from __future__ import annotations

import inspect
from typing import Any, Literal

from malleus.agent_adapter import AgentAdapterError, AgentRequest, AgentResponse, BaseAgentAdapter, LoadedAgentAdapter, load_import_object, serve_loaded_agent_adapter
from malleus.agent_target_contracts import SURFACE_CONTRACTS
from malleus.schemas import HarnessRetrieval, HarnessToolCall, HarnessTraceAction, TargetType


LangGraphInputMode = Literal["hybrid", "payload", "messages"]
LangGraphRunMode = Literal["invoke", "stream", "auto"]


class LangGraphAdapter(BaseAgentAdapter):
    """Malleus L2 adapter for LangGraph compiled graphs and graph-like callables."""

    framework = "langgraph"

    def __init__(
        self,
        graph: Any,
        *,
        target_type: TargetType = "tool_agent",
        input_mode: LangGraphInputMode = "hybrid",
        run_mode: LangGraphRunMode = "auto",
        config: dict[str, Any] | None = None,
    ) -> None:
        self.graph = graph
        self.target_type = target_type
        self.input_mode = input_mode
        self.run_mode = run_mode
        self.config = dict(config or {})

    def run(self, request: AgentRequest) -> AgentResponse:
        graph_input = self._graph_input(request.payload)
        events: list[dict[str, Any]] = []
        if self.run_mode == "stream" or (self.run_mode == "auto" and hasattr(self.graph, "stream")):
            output = self._stream(graph_input, events)
        else:
            output = self._invoke(graph_input)
        return _response_from_langgraph_output(
            output,
            events=events,
            target_type=str(self.target_type),
            input_mode=self.input_mode,
            run_mode="stream" if events else "invoke",
        )

    def health(self) -> dict[str, Any]:
        return {
            "ok": True,
            "target_type": self.target_type,
            "framework": self.framework,
            "input_mode": self.input_mode,
            "run_mode": self.run_mode,
            "graph_type": type(self.graph).__name__,
        }

    def _graph_input(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.input_mode == "payload":
            return dict(payload)
        message = _payload_to_user_message(payload)
        if self.input_mode == "messages":
            return {"messages": [{"role": "user", "content": message}]}
        graph_input = dict(payload)
        graph_input.setdefault("messages", [{"role": "user", "content": message}])
        graph_input.setdefault("malleus_context", _safe_context(payload))
        return graph_input

    def _invoke(self, graph_input: dict[str, Any]) -> Any:
        if hasattr(self.graph, "invoke"):
            return _call_with_optional_config(self.graph.invoke, graph_input, self.config)
        if callable(self.graph):
            return self.graph(graph_input)
        raise AgentAdapterError("LangGraph object must expose invoke(), stream(), or be callable")

    def _stream(self, graph_input: dict[str, Any], events: list[dict[str, Any]]) -> Any:
        if not hasattr(self.graph, "stream"):
            return self._invoke(graph_input)
        final_output: Any = None
        for chunk in _call_with_optional_config(self.graph.stream, graph_input, self.config):
            events.append(_safe_event(chunk))
            final_output = _merge_stream_output(final_output, chunk)
        return final_output if final_output is not None else {}


def load_langgraph_adapter(
    import_path: str,
    *,
    target_type: str = "tool_agent",
    input_mode: LangGraphInputMode = "hybrid",
    run_mode: LangGraphRunMode = "auto",
    config: dict[str, Any] | None = None,
    route: str | None = None,
) -> LoadedAgentAdapter:
    if target_type not in SURFACE_CONTRACTS:
        raise AgentAdapterError(f"unsupported LangGraph target_type: {target_type}")
    graph = load_import_object(import_path)
    if input_mode not in {"hybrid", "payload", "messages"}:
        raise AgentAdapterError("LangGraph input_mode must be hybrid, payload, or messages")
    if run_mode not in {"auto", "invoke", "stream"}:
        raise AgentAdapterError("LangGraph run_mode must be auto, invoke, or stream")
    adapter = LangGraphAdapter(graph, target_type=target_type, input_mode=input_mode, run_mode=run_mode, config=config)
    contract = SURFACE_CONTRACTS[target_type]
    return LoadedAgentAdapter(
        import_path=import_path,
        adapter=adapter,
        target_type=target_type,
        framework="langgraph",
        route=route or contract.default_endpoint_path or "/malleus/code-agent",
    )


def serve_langgraph_adapter(
    import_path: str,
    *,
    target_type: str = "tool_agent",
    input_mode: LangGraphInputMode = "hybrid",
    run_mode: LangGraphRunMode = "auto",
    host: str = "127.0.0.1",
    port: int = 8787,
    route: str | None = None,
    config: dict[str, Any] | None = None,
) -> None:
    loaded = load_langgraph_adapter(import_path, target_type=target_type, input_mode=input_mode, run_mode=run_mode, config=config, route=route)
    serve_loaded_agent_adapter(loaded, host=host, port=port)


def _payload_to_user_message(payload: dict[str, Any]) -> str:
    parts: list[str] = []
    for label, key in (
        ("Objective", "objective"),
        ("Task", "user_task"),
        ("Query", "query"),
        ("Page task", "task"),
        ("Untrusted context", "untrusted_context"),
    ):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            parts.append(f"{label}: {value.strip()}")
    for label, key in (("Allowed tools", "allowed_tools"), ("Available tools", "available_tools"), ("Forbidden tools", "forbidden_tools")):
        value = payload.get(key)
        if isinstance(value, list) and value:
            parts.append(f"{label}: {', '.join(str(item) for item in value)}")
    return "\n\n".join(parts) or str(payload.get("prompt") or payload.get("input") or "")


def _safe_context(payload: dict[str, Any]) -> dict[str, Any]:
    context: dict[str, Any] = {}
    for key in ("scenario_id", "prompt_id", "tenant_id", "namespace", "workflow_id", "allowed_tools", "available_tools", "forbidden_tools"):
        if key in payload:
            context[key] = payload[key]
    return context


def _call_with_optional_config(fn: Any, graph_input: dict[str, Any], config: dict[str, Any]) -> Any:
    try:
        signature = inspect.signature(fn)
    except (TypeError, ValueError):
        signature = None
    if config and signature is not None and "config" in signature.parameters:
        return fn(graph_input, config=config)
    return fn(graph_input)


def _response_from_langgraph_output(output: Any, *, events: list[dict[str, Any]], target_type: str, input_mode: str, run_mode: str) -> AgentResponse:
    messages = _extract_messages(output)
    final_answer = _final_answer(output, messages)
    tool_calls = _extract_tool_calls(output, messages)
    retrievals = _extract_retrievals(output)
    actions = _actions_from_events(events, output)
    output_metadata = _metadata(output)
    metadata = {
        **output_metadata,
        "agent_framework": "langgraph",
        "agent_target_depth": "L2",
        "target_type": target_type,
        "input_mode": input_mode,
        "run_mode": run_mode,
        "message_count": len(messages),
        "stream_event_count": len(events),
    }
    return AgentResponse(
        final_answer=final_answer,
        answer=final_answer,
        retrievals=retrievals,
        tool_calls=tool_calls,
        actions=actions,
        trace=actions,
        metadata=metadata,
    )


def _extract_messages(value: Any) -> list[Any]:
    messages: list[Any] = []

    def visit(item: Any) -> None:
        if item is None:
            return
        if _message_content(item) or _message_tool_calls(item):
            messages.append(item)
            return
        if isinstance(item, dict):
            raw = item.get("messages")
            if isinstance(raw, list):
                for message in raw:
                    visit(message)
            for nested in item.values():
                if isinstance(nested, (dict, list)):
                    visit(nested)
        elif isinstance(item, list):
            for nested in item:
                visit(nested)

    visit(value)
    return messages


def _final_answer(output: Any, messages: list[Any]) -> str:
    direct = _first_string_recursive(output, ("final_answer", "answer", "output", "output_text", "response", "text", "content"))
    if direct:
        return direct
    for message in reversed(messages):
        content = _message_content(message)
        if content:
            return content
    return ""


def _extract_tool_calls(output: Any, messages: list[Any]) -> list[HarnessToolCall]:
    raw_calls: list[Any] = []
    for message in messages:
        raw_calls.extend(_message_tool_calls(message))
    raw_calls.extend(_nested_list_values(output, ("tool_calls", "toolCalls", "tools")))
    calls: list[HarnessToolCall] = []
    for index, raw in enumerate(raw_calls):
        call = _tool_call(raw, index)
        if call is not None:
            calls.append(call)
    return calls


def _tool_call(raw: Any, index: int) -> HarnessToolCall | None:
    if not isinstance(raw, dict):
        raw = _model_dump(raw)
    if not isinstance(raw, dict):
        return None
    function = raw.get("function") if isinstance(raw.get("function"), dict) else {}
    name = _first_string(raw, ("name", "tool_name", "tool", "function", "action")) or _first_string(function, ("name", "tool_name"))
    if not name:
        return None
    args = _first_dict(raw, ("args", "arguments", "input", "parameters")) or _first_dict(function, ("arguments", "args", "parameters"))
    status = str(raw.get("status") or "ok")
    return HarnessToolCall(
        tool_name=name,
        call_id=str(raw.get("id") or raw.get("call_id") or raw.get("tool_call_id") or f"langgraph-tool-call-{index + 1}"),
        arguments=args,
        result_preview=_first_string(raw, ("result", "output", "observation", "content")),
        status="error" if status.lower() in {"error", "failed", "failure"} else "ok",
        metadata={"source": "langgraph", "raw_type": type(raw).__name__},
    )


def _extract_retrievals(output: Any) -> list[HarnessRetrieval]:
    retrievals: list[HarnessRetrieval] = []
    for index, raw in enumerate(_nested_list_values(output, ("retrievals", "retrieved_documents", "documents", "source_nodes", "citations"))):
        if not isinstance(raw, dict):
            raw = _model_dump(raw)
        if not isinstance(raw, dict):
            continue
        source_id = _first_string(raw, ("source_id", "id", "doc_id", "node_id", "citation")) or f"langgraph-source-{index + 1}"
        retrievals.append(
            HarnessRetrieval(
                source_id=source_id,
                title=_first_string(raw, ("title", "name")),
                uri=_first_string(raw, ("uri", "url", "source")),
                score=raw.get("score") if isinstance(raw.get("score"), (int, float)) else None,
                redacted_preview=_first_string(raw, ("redacted_preview", "preview", "text", "content")),
                citation=_first_string(raw, ("citation", "source_id", "id")),
                metadata={"source": "langgraph"},
            )
        )
    return retrievals


def _actions_from_events(events: list[dict[str, Any]], output: Any) -> list[HarnessTraceAction]:
    actions: list[HarnessTraceAction] = []
    for index, event in enumerate(events):
        actions.append(
            HarnessTraceAction(
                action_type=str(event.get("event_type") or event.get("type") or "langgraph_event"),
                action_id=str(event.get("event_id") or event.get("node") or f"langgraph-event-{index + 1}"),
                summary=str(event.get("summary") or event.get("node") or "LangGraph event observed"),
                metadata={key: value for key, value in event.items() if key in {"node", "event_type", "type", "keys"}},
            )
        )
    for index, raw in enumerate(_nested_list_values(output, ("actions", "steps", "events"))):
        if not isinstance(raw, dict):
            raw = _model_dump(raw)
        if not isinstance(raw, dict):
            continue
        actions.append(
            HarnessTraceAction(
                action_type=_first_string(raw, ("action_type", "type", "event", "name")) or "langgraph_action",
                action_id=_first_string(raw, ("action_id", "id")) or f"langgraph-action-{index + 1}",
                summary=_first_string(raw, ("summary", "description", "content", "message")) or "LangGraph action observed",
                metadata={"source": "langgraph"},
            )
        )
    return actions


def _merge_stream_output(current: Any, chunk: Any) -> Any:
    if current is None:
        return chunk
    if isinstance(current, dict) and isinstance(chunk, dict):
        merged = dict(current)
        for key, value in chunk.items():
            if key == "messages" and isinstance(value, list) and isinstance(merged.get(key), list):
                merged[key] = [*merged[key], *value]
            else:
                merged[key] = value
        return merged
    return chunk


def _safe_event(chunk: Any) -> dict[str, Any]:
    if isinstance(chunk, tuple) and len(chunk) == 2:
        node, value = chunk
        return {"event_type": "node_update", "node": str(node), "keys": _keys(value), "summary": f"LangGraph node update: {node}"}
    if isinstance(chunk, dict):
        return {"event_type": "state_update", "keys": sorted(str(key) for key in chunk.keys()), "summary": "LangGraph state update"}
    return {"event_type": "stream_chunk", "type": type(chunk).__name__, "summary": "LangGraph stream chunk"}


def _message_content(message: Any) -> str:
    if isinstance(message, dict):
        content = message.get("content")
    else:
        content = getattr(message, "content", None)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
            elif isinstance(item, str):
                parts.append(item)
        return "\n".join(parts)
    return ""


def _message_tool_calls(message: Any) -> list[Any]:
    if isinstance(message, dict):
        calls = message.get("tool_calls") or message.get("toolCalls") or []
        additional = message.get("additional_kwargs") if isinstance(message.get("additional_kwargs"), dict) else {}
    else:
        calls = getattr(message, "tool_calls", []) or []
        additional = getattr(message, "additional_kwargs", {}) if isinstance(getattr(message, "additional_kwargs", {}), dict) else {}
    extra = additional.get("tool_calls") if isinstance(additional.get("tool_calls"), list) else []
    return [*list(calls), *extra]


def _nested_list_values(value: Any, keys: tuple[str, ...]) -> list[Any]:
    found: list[Any] = []

    def visit(item: Any) -> None:
        if isinstance(item, dict):
            for key in keys:
                raw = item.get(key)
                if isinstance(raw, list):
                    found.extend(raw)
            for nested in item.values():
                if isinstance(nested, (dict, list)):
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
    if hasattr(value, "__dict__"):
        return dict(value.__dict__)
    return value


def _first_string(value: Any, keys: tuple[str, ...]) -> str:
    if not isinstance(value, dict):
        value = _model_dump(value)
    if not isinstance(value, dict):
        return ""
    for key in keys:
        item = value.get(key)
        if isinstance(item, str) and item:
            return item
    return ""


def _first_string_recursive(value: Any, keys: tuple[str, ...]) -> str:
    direct = _first_string(value, keys)
    if direct:
        return direct
    raw = _model_dump(value)
    if isinstance(raw, dict):
        for nested in raw.values():
            found = _first_string_recursive(nested, keys)
            if found:
                return found
    if isinstance(raw, list):
        for nested in raw:
            found = _first_string_recursive(nested, keys)
            if found:
                return found
    return ""


def _first_dict(value: Any, keys: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(value, dict):
        value = _model_dump(value)
    if not isinstance(value, dict):
        return {}
    for key in keys:
        item = value.get(key)
        if isinstance(item, dict):
            return item
        if isinstance(item, str) and item.strip().startswith("{"):
            return {"raw": item}
    return {}


def _metadata(value: Any) -> dict[str, Any]:
    raw = _model_dump(value)
    if isinstance(raw, dict) and isinstance(raw.get("metadata"), dict):
        return dict(raw["metadata"])
    if isinstance(raw, dict):
        for nested in raw.values():
            nested_metadata = _metadata(nested)
            if nested_metadata:
                return nested_metadata
    if isinstance(raw, list):
        for nested in raw:
            nested_metadata = _metadata(nested)
            if nested_metadata:
                return nested_metadata
    return {}


def _keys(value: Any) -> list[str]:
    if isinstance(value, dict):
        return sorted(str(key) for key in value.keys())
    return []


__all__ = ["LangGraphAdapter", "load_langgraph_adapter", "serve_langgraph_adapter"]
