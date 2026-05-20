from __future__ import annotations

import asyncio
import inspect
import json
from importlib.metadata import PackageNotFoundError, version
from typing import Any, Literal

from malleus.agent_adapter import AgentAdapterError, AgentRequest, AgentResponse, BaseAgentAdapter, LoadedAgentAdapter, load_import_object, serve_loaded_agent_adapter
from malleus.agent_target_contracts import SURFACE_CONTRACTS
from malleus.schemas import HarnessToolCall, HarnessTraceAction, TargetType


OpenAIAgentsInputMode = Literal["text", "payload", "messages"]
OpenAIAgentsRunMode = Literal["auto", "run_sync", "run", "invoke", "call"]


class OpenAIAgentsAdapter(BaseAgentAdapter):
    """Malleus L2 adapter for OpenAI Agents SDK agent objects and runners."""

    framework = "openai_agents"

    def __init__(
        self,
        agent: Any,
        *,
        runner: Any | None = None,
        target_type: TargetType = "tool_agent",
        input_mode: OpenAIAgentsInputMode = "text",
        run_mode: OpenAIAgentsRunMode = "auto",
        run_kwargs: dict[str, Any] | None = None,
    ) -> None:
        self.agent = agent
        self.runner = runner
        self.target_type = target_type
        self.input_mode = input_mode
        self.run_mode = run_mode
        self.run_kwargs = dict(run_kwargs or {})

    def run(self, request: AgentRequest) -> AgentResponse:
        agent_input = _agent_input(request.payload, self.input_mode)
        output = self._execute(agent_input)
        return _response_from_openai_agents_output(output, target_type=str(self.target_type), input_mode=self.input_mode, run_mode=self.run_mode)

    def health(self) -> dict[str, Any]:
        return {
            "ok": True,
            "target_type": self.target_type,
            "framework": self.framework,
            "official_sdk_available": _official_sdk_available(),
            "official_sdk_version": _official_sdk_version(),
            "input_mode": self.input_mode,
            "run_mode": self.run_mode,
            "agent_type": type(self.agent).__name__,
            "runner_type": type(self.runner).__name__ if self.runner is not None else "",
            "runner_contracts": _runner_contracts(self.runner, self.agent),
        }

    def _execute(self, agent_input: Any) -> Any:
        if self.runner is not None:
            if self.run_mode in {"auto", "run_sync"} and hasattr(self.runner, "run_sync"):
                return _call_runner(self.runner.run_sync, self.agent, agent_input, self.run_kwargs)
            if self.run_mode in {"auto", "run"} and hasattr(self.runner, "run"):
                return _resolve_awaitable(_call_runner(self.runner.run, self.agent, agent_input, self.run_kwargs))
        if self.run_mode in {"auto", "run_sync"} and hasattr(self.agent, "run_sync"):
            return _call_agent(self.agent.run_sync, agent_input, self.run_kwargs)
        if self.run_mode in {"auto", "run"} and hasattr(self.agent, "run"):
            return _resolve_awaitable(_call_agent(self.agent.run, agent_input, self.run_kwargs))
        if self.run_mode in {"auto", "invoke"} and hasattr(self.agent, "invoke"):
            return _call_agent(self.agent.invoke, agent_input, self.run_kwargs)
        if self.run_mode in {"auto", "call"} and callable(self.agent):
            return self.agent(agent_input)
        raise AgentAdapterError("OpenAI Agents object must be runnable through Runner.run_sync/run, agent.run_sync/run/invoke, or callable")


def load_openai_agents_adapter(
    import_path: str,
    *,
    runner_import_path: str | None = None,
    target_type: str = "tool_agent",
    input_mode: OpenAIAgentsInputMode = "text",
    run_mode: OpenAIAgentsRunMode = "auto",
    run_kwargs: dict[str, Any] | None = None,
    route: str | None = None,
) -> LoadedAgentAdapter:
    if target_type not in SURFACE_CONTRACTS:
        raise AgentAdapterError(f"unsupported OpenAI Agents target_type: {target_type}")
    if input_mode not in {"text", "payload", "messages"}:
        raise AgentAdapterError("OpenAI Agents input_mode must be text, payload, or messages")
    if run_mode not in {"auto", "run_sync", "run", "invoke", "call"}:
        raise AgentAdapterError("OpenAI Agents run_mode must be auto, run_sync, run, invoke, or call")
    agent = load_import_object(import_path)
    runner = load_import_object(runner_import_path) if runner_import_path else (_try_default_runner() if _should_use_default_runner(agent) else None)
    adapter = OpenAIAgentsAdapter(agent, runner=runner, target_type=target_type, input_mode=input_mode, run_mode=run_mode, run_kwargs=run_kwargs)
    contract = SURFACE_CONTRACTS[target_type]
    return LoadedAgentAdapter(
        import_path=import_path,
        adapter=adapter,
        target_type=target_type,
        framework="openai_agents",
        route=route or contract.default_endpoint_path or "/malleus/code-agent",
    )


def serve_openai_agents_adapter(
    import_path: str,
    *,
    runner_import_path: str | None = None,
    target_type: str = "tool_agent",
    input_mode: OpenAIAgentsInputMode = "text",
    run_mode: OpenAIAgentsRunMode = "auto",
    host: str = "127.0.0.1",
    port: int = 8787,
    route: str | None = None,
    run_kwargs: dict[str, Any] | None = None,
) -> None:
    loaded = load_openai_agents_adapter(
        import_path,
        runner_import_path=runner_import_path,
        target_type=target_type,
        input_mode=input_mode,
        run_mode=run_mode,
        run_kwargs=run_kwargs,
        route=route,
    )
    serve_loaded_agent_adapter(loaded, host=host, port=port)


def _try_default_runner() -> Any | None:
    try:
        module = __import__("agents", fromlist=["Runner"])
    except Exception:
        return None
    return getattr(module, "Runner", None)


def _should_use_default_runner(agent: Any) -> bool:
    if any(hasattr(agent, name) for name in ("run_sync", "run", "invoke")) or callable(agent):
        return False
    try:
        module = __import__("agents", fromlist=["Agent"])
        official_agent = getattr(module, "Agent", None)
    except Exception:
        official_agent = None
    return bool(official_agent is not None and isinstance(agent, official_agent))


def _official_sdk_available() -> bool:
    try:
        __import__("agents")
    except Exception:
        return False
    return True


def _official_sdk_version() -> str:
    for package_name in ("openai-agents", "agents"):
        try:
            return version(package_name)
        except PackageNotFoundError:
            continue
    return "unknown"


def _runner_contracts(runner: Any | None, agent: Any) -> list[str]:
    contracts: list[str] = []
    if runner is not None:
        for name in ("run_sync", "run", "run_streamed"):
            if hasattr(runner, name):
                contracts.append(f"runner.{name}")
    for name in ("run_sync", "run", "invoke", "__call__"):
        if name == "__call__":
            if callable(agent):
                contracts.append("agent.__call__")
        elif hasattr(agent, name):
            contracts.append(f"agent.{name}")
    return contracts


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


def _call_runner(fn: Any, agent: Any, agent_input: Any, kwargs: dict[str, Any]) -> Any:
    return _call_with_supported_kwargs(fn, (agent, agent_input), kwargs)


def _call_agent(fn: Any, agent_input: Any, kwargs: dict[str, Any]) -> Any:
    return _call_with_supported_kwargs(fn, (agent_input,), kwargs)


def _call_with_supported_kwargs(fn: Any, args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
    if not kwargs:
        return fn(*args)
    try:
        signature = inspect.signature(fn)
    except (TypeError, ValueError):
        return fn(*args, **kwargs)
    accepted = {key: value for key, value in kwargs.items() if key in signature.parameters}
    return fn(*args, **accepted)


def _resolve_awaitable(value: Any) -> Any:
    if inspect.isawaitable(value):
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(value)
        raise AgentAdapterError("async OpenAI Agents runner cannot be awaited inside an active event loop; use run_sync or serve in a sync process")
    return value


def _response_from_openai_agents_output(output: Any, *, target_type: str, input_mode: str, run_mode: str) -> AgentResponse:
    items = _extract_items(output)
    final_answer = _final_answer(output, items)
    tool_calls = _extract_tool_calls(output, items)
    actions = _extract_actions(output, items)
    output_metadata = _first_dict(output, ("metadata",))
    metadata = {
        **output_metadata,
        "agent_framework": "openai_agents",
        "agent_target_depth": "L2",
        "target_type": target_type,
        "input_mode": input_mode,
        "run_mode": run_mode,
        "item_count": len(items),
    }
    return AgentResponse(final_answer=final_answer, answer=final_answer, tool_calls=tool_calls, actions=actions, trace=actions, metadata=metadata)


def _extract_items(output: Any) -> list[Any]:
    items: list[Any] = []
    for attr in ("new_items", "items", "events", "steps", "trace"):
        value = _get(output, attr)
        if isinstance(value, list):
            items.extend(value)
    if isinstance(output, dict):
        for key in ("new_items", "items", "events", "steps", "trace"):
            value = output.get(key)
            if isinstance(value, list):
                items.extend(value)
    return items


def _final_answer(output: Any, items: list[Any]) -> str:
    direct = _first_string(output, ("final_output", "final_answer", "answer", "output", "response", "text", "content"))
    if direct:
        return direct
    final_output_as = getattr(output, "final_output_as", None)
    if callable(final_output_as):
        try:
            value = final_output_as(str)
            if isinstance(value, str):
                return value
        except Exception:
            pass
    for item in reversed(items):
        text = _first_string(_raw_item(item), ("content", "text", "output", "message", "final_output"))
        if text:
            return text
        text = _content_text(_raw_item(item))
        if text:
            return text
    return ""


def _extract_tool_calls(output: Any, items: list[Any]) -> list[HarnessToolCall]:
    raw_calls: list[Any] = []
    raw_calls.extend(_nested_list_values(output, ("tool_calls", "tools", "function_calls")))
    for item in items:
        item_type = _item_type(item)
        raw = _raw_item(item)
        if any(token in item_type for token in ("tool_call", "function_call")):
            raw_calls.append(raw)
        raw_calls.extend(_nested_list_values(raw, ("tool_calls", "tools", "function_calls")))
    calls: list[HarnessToolCall] = []
    for index, raw in enumerate(raw_calls):
        call = _tool_call(raw, index)
        if call is not None:
            calls.append(call)
    return calls


def _tool_call(raw: Any, index: int) -> HarnessToolCall | None:
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
        call_id=str(raw.get("id") or raw.get("call_id") or raw.get("tool_call_id") or f"openai-agents-tool-call-{index + 1}"),
        arguments=args,
        result_preview=_first_string(raw, ("result", "output", "observation", "content")),
        status="error" if status.lower() in {"error", "failed", "failure"} else "ok",
        metadata={"source": "openai_agents", "raw_type": type(raw).__name__},
    )


def _extract_actions(output: Any, items: list[Any]) -> list[HarnessTraceAction]:
    actions: list[HarnessTraceAction] = []
    for index, item in enumerate(items):
        item_type = _item_type(item)
        raw = _raw_item(item)
        if any(token in item_type for token in ("handoff", "tool", "message", "reasoning", "event", "step")):
            action_type = "handoff" if "handoff" in item_type else ("tool_call" if "tool" in item_type else item_type or "openai_agents_item")
            actions.append(
                HarnessTraceAction(
                    action_type=action_type,
                    action_id=_first_string(raw, ("id", "call_id", "item_id")) or f"openai-agents-item-{index + 1}",
                    summary=_summary_for_item(item, raw, item_type),
                    metadata={"source": "openai_agents", "item_type": item_type},
                )
            )
    for index, raw in enumerate(_nested_list_values(output, ("actions", "trace", "steps", "events"))):
        raw = _model_dump(raw)
        if not isinstance(raw, dict):
            continue
        actions.append(
            HarnessTraceAction(
                action_type=_first_string(raw, ("action_type", "type", "event", "name")) or "openai_agents_event",
                action_id=_first_string(raw, ("action_id", "id")) or f"openai-agents-event-{index + 1}",
                summary=_first_string(raw, ("summary", "description", "content", "message")) or "OpenAI Agents event observed",
                metadata={"source": "openai_agents"},
            )
        )
    return actions


def _summary_for_item(item: Any, raw: Any, item_type: str) -> str:
    for value in (
        _first_string(raw, ("summary", "content", "text", "output", "message")),
        _content_text(raw),
        _first_string(_model_dump(item), ("summary", "content", "text", "output", "message")),
    ):
        if value:
            return value
    if "handoff" in item_type:
        target = _first_string(raw, ("target_agent", "to_agent", "agent_name", "name"))
        return f"Handoff observed{': ' + target if target else ''}"
    if "tool" in item_type:
        name = _first_string(raw, ("name", "tool_name", "tool"))
        return f"Tool event observed{': ' + name if name else ''}"
    return "OpenAI Agents item observed"


def _item_type(item: Any) -> str:
    value = _get(item, "type") or _get(item, "item_type") or type(item).__name__
    return str(value).lower()


def _raw_item(item: Any) -> Any:
    return _get(item, "raw_item") or _get(item, "item") or _model_dump(item)


def _get(value: Any, key: str) -> Any:
    if isinstance(value, dict):
        return value.get(key)
    return getattr(value, key, None)


def _nested_list_values(value: Any, keys: tuple[str, ...]) -> list[Any]:
    found: list[Any] = []
    seen: set[int] = set()
    skip_keys = {
        "agent",
        "last_agent",
        "_last_agent",
        "_last_agent_ref",
        "context_wrapper",
        "model",
        "model_settings",
        "tools",
        "mcp_servers",
        "hooks",
        "run_config",
    }

    def visit(item: Any, depth: int = 0) -> None:
        if depth > 8:
            return
        item_id = id(item)
        if item_id in seen:
            return
        seen.add(item_id)
        item = _model_dump(item)
        if isinstance(item, dict):
            for key in keys:
                raw = item.get(key)
                if isinstance(raw, list):
                    found.extend(raw)
            for key, nested in item.items():
                key_text = str(key)
                if key_text in skip_keys or key_text.startswith("_"):
                    continue
                if isinstance(nested, (dict, list)) or hasattr(nested, "model_dump") or hasattr(nested, "__dict__"):
                    visit(nested, depth + 1)
        elif isinstance(item, list):
            for nested in item:
                visit(nested, depth + 1)

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
        if isinstance(item, str) and item.strip().startswith("{"):
            try:
                parsed = json.loads(item)
            except json.JSONDecodeError:
                return {"raw": item}
            return parsed if isinstance(parsed, dict) else {"raw": item}
    return {}


def _content_text(value: Any) -> str:
    raw = _model_dump(value)
    if not isinstance(raw, dict):
        return ""
    content = raw.get("content")
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts: list[str] = []
    for item in content:
        item = _model_dump(item)
        if isinstance(item, str):
            parts.append(item)
        elif isinstance(item, dict):
            text = item.get("text") or item.get("content") or item.get("refusal")
            if isinstance(text, str):
                parts.append(text)
    return "\n".join(part for part in parts if part)


__all__ = ["OpenAIAgentsAdapter", "load_openai_agents_adapter", "serve_openai_agents_adapter"]
