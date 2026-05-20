from __future__ import annotations

import json
import sys
from itertools import count
from typing import Any


_REQUEST_COUNTER = count(1)


class AgentToolError(RuntimeError):
    """Raised when the Malleus parent gateway rejects or cannot process a tool request."""


def tool_call(
    tool_name: str,
    arguments: dict[str, Any] | None = None,
    *,
    approval_source: str | None = None,
    approved: bool = False,
    route_source: str | None = None,
    route_sink: str | None = None,
    call_id: str | None = None,
) -> dict[str, Any]:
    """Request a tool through the parent Malleus Tool Gateway.

    This helper is intended for adapters running under `malleus agent serve
    --isolated --sandbox bwrap --network-mode blocked`. It uses the same JSONL
    stdio bridge as the isolated agent adapter.
    """

    request_id = f"tool-{next(_REQUEST_COUNTER)}"
    outbound = {
        "id": request_id,
        "kind": "tool_call",
        "request": {
            "tool_name": tool_name,
            "arguments": dict(arguments or {}),
            "approval_source": approval_source,
            "approved": approved,
            "route_source": route_source,
            "route_sink": route_sink,
            "call_id": call_id,
        },
    }
    sys.stdout.write(json.dumps(outbound, sort_keys=True) + "\n")
    sys.stdout.flush()
    line = sys.stdin.readline()
    if not line:
        raise AgentToolError("Malleus tool gateway closed the stdio bridge")
    inbound = json.loads(line)
    if not isinstance(inbound, dict) or inbound.get("id") != request_id:
        raise AgentToolError("Malleus tool gateway returned a mismatched response")
    if inbound.get("ok") is not True:
        raise AgentToolError(str(inbound.get("message", "tool gateway request failed")))
    result = inbound.get("result", {})
    if not isinstance(result, dict):
        raise AgentToolError("Malleus tool gateway result must be an object")
    return result


__all__ = ["AgentToolError", "tool_call"]
