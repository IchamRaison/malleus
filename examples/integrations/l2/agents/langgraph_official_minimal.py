from __future__ import annotations

from typing import Any, Iterator, TypedDict


OFFICIAL_SDK_STATUS = "langgraph package not installed; install langgraph to run the official StateGraph example path"


class GraphState(TypedDict, total=False):
    messages: list[dict[str, Any]]
    allowed_tools: list[str]
    malleus_context: dict[str, Any]
    answer: str
    tool_calls: list[dict[str, Any]]
    actions: list[dict[str, Any]]


def _policy_node(state: GraphState) -> GraphState:
    context = state.get("malleus_context") or {}
    allowed = state.get("allowed_tools") or context.get("allowed_tools") or ["classify_ticket"]
    tool_name = "classify_ticket" if "classify_ticket" in allowed else str(allowed[0])
    return {
        **state,
        "answer": "LangGraph official-minimal graph completed a safe tool route.",
        "messages": [
            *state.get("messages", []),
            {"role": "assistant", "content": "LangGraph official-minimal graph completed a safe tool route."},
        ],
        "tool_calls": [
            {
                "id": "langgraph-official-call-1",
                "name": tool_name,
                "args": {"classification": "safe_review"},
                "status": "ok",
                "result": "safe route selected",
            }
        ],
        "actions": [
            {"id": "langgraph-official-step-1", "type": "node", "summary": "policy node handled untrusted input"},
            {"id": "langgraph-official-step-2", "type": "node", "summary": "tool node stayed inside allowed tools"},
        ],
    }


try:
    from langgraph.graph import END, START, StateGraph
except Exception:
    StateGraph = None  # type: ignore[assignment]
else:
    OFFICIAL_SDK_STATUS = "official langgraph package available; using StateGraph"


if StateGraph is not None:
    builder = StateGraph(GraphState)
    builder.add_node("policy", _policy_node)
    builder.add_edge(START, "policy")
    builder.add_edge("policy", END)
    graph = builder.compile()
else:

    class FallbackGraph:
        def invoke(self, graph_input: dict[str, Any], config: dict[str, Any] | None = None) -> dict[str, Any]:
            return _policy_node(GraphState(**graph_input))

        def stream(self, graph_input: dict[str, Any], config: dict[str, Any] | None = None) -> Iterator[dict[str, Any]]:
            yield {"events": [{"id": "langgraph-official-stream-1", "type": "node_start", "summary": OFFICIAL_SDK_STATUS}]}
            yield self.invoke(graph_input, config=config)

    graph = FallbackGraph()
