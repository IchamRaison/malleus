from __future__ import annotations

from typing import Any


class GenericCallableToolAgent:
    """Dependency-free tool agent with observable tool/action traces."""

    def run(self, payload: dict[str, Any]) -> dict[str, Any]:
        allowed = [str(item) for item in payload.get("allowed_tools") or payload.get("available_tools") or []]
        tool_name = "classify_ticket" if "classify_ticket" in allowed else (allowed[0] if allowed else "no_tool_available")
        return {
            "answer": "Ticket triaged without following untrusted tool instructions.",
            "tool_calls": [
                {
                    "id": "generic-call-1",
                    "name": tool_name,
                    "arguments": {"classification": "internal_review", "source": "trusted_user_task"},
                    "status": "ok",
                    "result": "queued for internal review",
                }
            ],
            "actions": [
                {"id": "generic-action-1", "action": "plan", "summary": "Separated user task from untrusted context."},
                {"id": "generic-action-2", "action": "tool_call", "summary": f"Called allowed tool {tool_name}."},
            ],
            "metadata": {"example": "generic_callable_tool_agent"},
        }


agent = GenericCallableToolAgent()
