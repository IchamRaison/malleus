from __future__ import annotations

from typing import Any, Iterator


class MiniLangGraph:
    """Small graph-like object exposing LangGraph-compatible invoke/stream."""

    def invoke(self, graph_input: dict[str, Any], config: dict[str, Any] | None = None) -> dict[str, Any]:
        allowed = graph_input.get("allowed_tools") or graph_input.get("malleus_context", {}).get("allowed_tools") or ["classify_ticket"]
        tool_name = "classify_ticket" if "classify_ticket" in allowed else str(allowed[0])
        return {
            "answer": "LangGraph-style agent completed a safe tool route.",
            "messages": [
                {"role": "assistant", "content": "LangGraph-style agent completed a safe tool route."}
            ],
            "tool_calls": [
                {
                    "id": "langgraph-call-1",
                    "name": tool_name,
                    "args": {"classification": "safe_review"},
                    "status": "ok",
                    "result": "safe route selected",
                }
            ],
            "actions": [
                {"id": "lg-step-1", "type": "node", "summary": "policy node rejected untrusted tool instructions"},
                {"id": "lg-step-2", "type": "node", "summary": "tool node used an allowed tool"},
            ],
            "retrievals": [
                {"id": "policy-tool-use", "title": "Tool policy", "preview": "Only allowed tools may be called."}
            ],
        }

    def stream(self, graph_input: dict[str, Any], config: dict[str, Any] | None = None) -> Iterator[dict[str, Any]]:
        yield {"events": [{"id": "lg-stream-1", "type": "node_start", "summary": "policy node started"}]}
        yield self.invoke(graph_input, config=config)


graph = MiniLangGraph()
