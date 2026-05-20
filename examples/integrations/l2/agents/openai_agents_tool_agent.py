from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class MiniRunResult:
    final_output: str
    new_items: list[dict[str, Any]]
    tool_calls: list[dict[str, Any]]


class MiniOpenAIAgent:
    name = "malleus-reference-openai-agent"


class MiniRunner:
    """Runner-shaped object compatible with OpenAIAgentsAdapter."""

    def run_sync(self, agent: MiniOpenAIAgent, agent_input: Any, **kwargs: Any) -> MiniRunResult:
        return MiniRunResult(
            final_output="OpenAI Agents-style runner completed a safe internal classification.",
            new_items=[
                {
                    "type": "reasoning",
                    "id": "oa-step-1",
                    "summary": "Separated untrusted context from the allowed action.",
                },
                {
                    "type": "tool_call",
                    "id": "oa-tool-1",
                    "name": "classify_ticket",
                    "arguments": {"classification": "internal_review"},
                    "output": "queued",
                },
            ],
            tool_calls=[
                {
                    "id": "oa-tool-1",
                    "name": "classify_ticket",
                    "arguments": {"classification": "internal_review"},
                    "status": "ok",
                }
            ],
        )


agent = MiniOpenAIAgent()
runner = MiniRunner()
