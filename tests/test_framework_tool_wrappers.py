from __future__ import annotations

from typing import Any

from malleus.agent_frameworks.tools import (
    MalleusGatewayTool,
    malleus_langchain_tools,
    malleus_langgraph_tools,
    malleus_openai_agent_tools,
    malleus_openai_function_schemas,
    malleus_tool,
    malleus_tools,
)


def test_generic_gateway_tool_routes_arguments(monkeypatch) -> None:
    calls: list[dict[str, Any]] = []

    def fake_tool_call(name: str, arguments: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        calls.append({"name": name, "arguments": arguments, **kwargs})
        return {"decision": {"action": "allowed"}, "result": {"ok": True}}

    monkeypatch.setattr("malleus.agent_tools.tool_call", fake_tool_call)
    tool = malleus_tool("search", approval_source="trusted_harness", approved=True)

    result = tool({"query": "policy"}, limit=3)

    assert isinstance(tool, MalleusGatewayTool)
    assert result["decision"]["action"] == "allowed"
    assert calls == [
        {
            "name": "search",
            "arguments": {"query": "policy", "limit": 3},
            "approval_source": "trusted_harness",
            "approved": True,
            "route_source": None,
            "route_sink": None,
        }
    ]


def test_gateway_tool_supports_invoke_and_string_input(monkeypatch) -> None:
    observed: list[dict[str, Any]] = []
    monkeypatch.setattr("malleus.agent_tools.tool_call", lambda name, arguments, **kwargs: observed.append(arguments) or {"decision": {"action": "allowed"}})

    tool = malleus_tool("search")
    tool.invoke("policy query")

    assert observed == [{"input": "policy query"}]


def test_framework_factories_return_callable_tools(monkeypatch) -> None:
    monkeypatch.setattr("malleus.agent_tools.tool_call", lambda name, arguments, **kwargs: {"decision": {"action": "allowed"}, "tool": name, "args": arguments})

    generic = malleus_tools(["search"])[0]
    langchain = malleus_langchain_tools(["search"])[0]
    langgraph = malleus_langgraph_tools(["search"])[0]
    openai_tools = malleus_openai_agent_tools(["search"])

    assert generic({"query": "generic"})["tool"] == "search"
    if callable(langchain):
        assert langchain({"query": "langchain"})["tool"] == "search"
    else:
        assert langchain.invoke({"query": "langchain"})["tool"] == "search"
    if callable(langgraph):
        assert langgraph({"query": "langgraph"})["tool"] == "search"
    else:
        assert langgraph.invoke({"query": "langgraph"})["tool"] == "search"
    assert openai_tools


def test_openai_function_schemas_are_exportable() -> None:
    schemas = malleus_openai_function_schemas(["search"], description="Search through the gateway")

    assert schemas[0]["type"] == "function"
    assert schemas[0]["function"]["name"] == "search"
    assert schemas[0]["function"]["description"] == "Search through the gateway"
