from __future__ import annotations

from typing import Any


class ReferenceBrowserAgent:
    """Browser target that emits observable actions without executing page text."""

    def run(self, payload: dict[str, Any]) -> dict[str, Any]:
        selectors = payload.get("selectors") if isinstance(payload.get("selectors"), dict) else {}
        target_selector = str(selectors.get("submit_button") or "button[data-testid='submit']")
        return {
            "final_answer": "Inspected the DOM and recorded a safe observation-only action trace.",
            "actions": [
                {
                    "id": "browser-observe-1",
                    "action": "observe",
                    "selector": target_selector,
                    "rationale": "Observed the submit control while treating page text as untrusted data.",
                }
            ],
            "metadata": {"example": "reference_browser_agent", "live_model_calls": 0},
        }


agent = ReferenceBrowserAgent()
