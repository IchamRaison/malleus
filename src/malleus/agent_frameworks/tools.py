from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

from malleus import agent_tools


@dataclass
class MalleusGatewayTool:
    """Framework-neutral callable that routes tool execution through Malleus."""

    name: str
    description: str = ""
    approval_source: str | None = None
    approved: bool = False
    route_source: str | None = None
    route_sink: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.__name__ = self.name
        if self.description:
            self.__doc__ = self.description

    def __call__(self, tool_input: Any = None, **kwargs: Any) -> dict[str, Any]:
        arguments = _arguments(tool_input, kwargs)
        return agent_tools.tool_call(
            self.name,
            arguments,
            approval_source=self.approval_source,
            approved=self.approved,
            route_source=self.route_source,
            route_sink=self.route_sink,
        )

    def invoke(self, tool_input: Any = None, config: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        return self(tool_input, **kwargs)

    def run(self, tool_input: Any = None, **kwargs: Any) -> dict[str, Any]:
        return self(tool_input, **kwargs)

    def as_openai_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description or f"Malleus gateway tool {self.name}",
                "parameters": {
                    "type": "object",
                    "additionalProperties": True,
                    "properties": {},
                },
            },
        }


def malleus_tool(
    name: str,
    *,
    description: str = "",
    approval_source: str | None = None,
    approved: bool = False,
    route_source: str | None = None,
    route_sink: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> MalleusGatewayTool:
    return MalleusGatewayTool(
        name=name,
        description=description,
        approval_source=approval_source,
        approved=approved,
        route_source=route_source,
        route_sink=route_sink,
        metadata=dict(metadata or {}),
    )


def malleus_tools(names: Sequence[str], **kwargs: Any) -> list[MalleusGatewayTool]:
    return [malleus_tool(name, **kwargs) for name in names]


def malleus_langchain_tools(names: Sequence[str], **kwargs: Any) -> list[Any]:
    tools = malleus_tools(names, **kwargs)
    try:
        from langchain_core.tools import StructuredTool
    except Exception:
        return tools
    wrapped: list[Any] = []
    for tool in tools:
        wrapped.append(
            StructuredTool.from_function(
                func=_callable_for_framework(tool),
                name=tool.name,
                description=tool.description or f"Malleus gateway tool {tool.name}",
            )
        )
    return wrapped


def malleus_langgraph_tools(names: Sequence[str], **kwargs: Any) -> list[Any]:
    return malleus_langchain_tools(names, **kwargs)


def malleus_openai_agent_tools(names: Sequence[str], **kwargs: Any) -> list[Any]:
    tools = malleus_tools(names, **kwargs)
    try:
        from agents import function_tool
    except Exception:
        return [_callable_for_framework(tool) for tool in tools]
    wrapped: list[Any] = []
    for tool in tools:
        callable_tool = _callable_for_framework(tool)
        try:
            wrapped.append(function_tool(callable_tool))
        except Exception:
            # Newer OpenAI Agents SDK releases enforce strict JSON schemas and
            # reject permissive **kwargs callables. Keep this helper
            # provider-free and version-tolerant by falling back to the plain
            # callable gateway; users can still export explicit OpenAI function
            # schemas with malleus_openai_function_schemas().
            wrapped.append(callable_tool)
    return wrapped


def malleus_openai_function_schemas(names: Sequence[str], **kwargs: Any) -> list[dict[str, Any]]:
    return [tool.as_openai_schema() for tool in malleus_tools(names, **kwargs)]


def _callable_for_framework(tool: MalleusGatewayTool) -> Callable[..., dict[str, Any]]:
    def run_tool(tool_input: Any = None, **kwargs: Any) -> dict[str, Any]:
        return tool(tool_input, **kwargs)

    run_tool.__name__ = tool.name
    run_tool.__doc__ = tool.description or f"Malleus gateway tool {tool.name}"
    return run_tool


def _arguments(tool_input: Any, kwargs: dict[str, Any]) -> dict[str, Any]:
    if isinstance(tool_input, dict):
        return {**tool_input, **kwargs}
    if tool_input is None:
        return dict(kwargs)
    return {"input": tool_input, **kwargs}


__all__ = [
    "MalleusGatewayTool",
    "malleus_langchain_tools",
    "malleus_langgraph_tools",
    "malleus_openai_agent_tools",
    "malleus_openai_function_schemas",
    "malleus_tool",
    "malleus_tools",
]
