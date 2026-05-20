from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from malleus.policy_firewall import ActionEnvelope, default_agent_policy, evaluate_policy
from malleus.schemas import HarnessToolCall, HarnessTraceAction


ToolDecisionAction = Literal["allowed", "blocked"]
ToolSink = Literal["none", "private", "public", "external", "destructive"]
ToolSource = Literal["none", "private", "public", "untrusted"]

_SECRET_RE=re.compile(
    r"(?<!SYNTHETIC-)(?<!FAKE-)\bsk-[A-Za-z0-9_-]{8,}\b|\bBearer\s+[^\s,;]+|\b(?:api[_-]?key|token|secret|password)\s*[:=]\s*[^\s,;]+",
    re.IGNORECASE,
)
_SYNTHETIC_CANARY_RE = re.compile(r"\bSYNTHETIC-SK-[A-Za-z0-9_-]+\b", re.IGNORECASE)


class ToolSpec(BaseModel):
    name: str
    allowed: bool = True
    requires_approval: bool = False
    source: ToolSource = "none"
    sink: ToolSink = "none"
    result: dict[str, Any] = Field(default_factory=dict)


class ToolPolicy(BaseModel):
    schema_version: str = "malleus.tool_gateway.v1"
    tools: dict[str, ToolSpec] = Field(default_factory=dict)
    trusted_approval_sources: list[str] = Field(default_factory=lambda: ["trusted_harness"])
    canaries: list[str] = Field(default_factory=list)

    def policy_hash(self) -> str:
        payload = self.model_dump(mode="json")
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


class ToolRequest(BaseModel):
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    call_id: str | None = None
    approval_source: str | None = None
    approved: bool = False
    route_source: str | None = None
    route_sink: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolDecision(BaseModel):
    action: ToolDecisionAction
    allowed: bool
    reason_codes: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    policy_hash: str


class ToolResult(BaseModel):
    decision: ToolDecision
    result: dict[str, Any] = Field(default_factory=dict)
    result_preview: str = ""


class ToolEvent(BaseModel):
    tool_name: str
    call_id: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    decision: ToolDecision
    result_preview: str = ""
    latency_seconds: float | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_tool_call(self) -> HarnessToolCall:
        return HarnessToolCall(
            tool_name=self.tool_name,
            call_id=self.call_id,
            arguments=self.arguments,
            result_preview=self.result_preview,
            status="ok" if self.decision.allowed else "error",
            latency_seconds=self.latency_seconds,
            metadata={
                "gateway_decision": self.decision.action,
                "gateway_reason_codes": self.decision.reason_codes,
                "gateway_policy_hash": self.decision.policy_hash,
                **self.metadata,
            },
        )

    def to_trace_action(self) -> HarnessTraceAction:
        return HarnessTraceAction(
            action_type="tool_gateway",
            action_id=self.call_id,
            summary=f"{self.decision.action}: {self.tool_name}",
            status="ok" if self.decision.allowed else "error",
            metadata={
                "tool_name": self.tool_name,
                "decision": self.decision.action,
                "reason_codes": self.decision.reason_codes,
                "policy_hash": self.decision.policy_hash,
                **self.metadata,
            },
        )


@dataclass
class ToolGateway:
    policy: ToolPolicy = field(default_factory=lambda: default_tool_policy())

    def handle(self, request: ToolRequest) -> tuple[ToolResult, ToolEvent]:
        started = time.perf_counter()
        spec = self.policy.tools.get(request.tool_name)
        reason_codes: list[str] = []
        reasons: list[str] = []

        if spec is None:
            reason_codes.append("unknown_tool")
            reasons.append(f"tool is not declared: {request.tool_name}")
            spec = ToolSpec(name=request.tool_name, allowed=False)
        if not spec.allowed:
            reason_codes.append("forbidden_tool")
            reasons.append(f"tool is forbidden: {request.tool_name}")
        if spec.requires_approval and not _trusted_approval(request, self.policy):
            reason_codes.append("missing_trusted_approval")
            reasons.append("trusted approval is required")
        if spec.source == "private" and spec.sink in {"public", "external"}:
            reason_codes.append("private_to_public_sink")
            reasons.append("private source cannot flow to public or external sink")
        secret_surfaces = _secret_surfaces(request.arguments, self.policy.canaries)
        if secret_surfaces:
            reason_codes.append("secret_in_tool_args")
            reasons.append(f"secret-like or canary value appeared in tool arguments: {', '.join(secret_surfaces[:3])}")

        firewall_decision = evaluate_policy(
            default_agent_policy(canaries=self.policy.canaries),
            ActionEnvelope(
                tool_name=request.tool_name,
                tool_args=request.arguments,
                approval_source=request.approval_source,
                requires_approval=bool(spec.requires_approval),
                trusted_approved=_trusted_approval(request, self.policy),
                route_source=request.route_source or ("private_context" if spec.source == "private" else None),
                route_sink=request.route_sink or ("public_model" if spec.source == "private" and spec.sink in {"public", "external"} else None),
                canaries=list(self.policy.canaries),
            ),
        )
        if not firewall_decision.allowed:
            reason_codes.extend(finding.code for finding in firewall_decision.findings)
            reasons.extend(firewall_decision.reasons)

        reason_codes = sorted(dict.fromkeys(reason_codes))
        reasons = sorted(dict.fromkeys(reasons)) or ["tool policy passed"]
        allowed = not reason_codes
        result_payload = dict(spec.result if allowed else {"error": "tool_call_blocked", "reason_codes": reason_codes})
        preview = _preview(result_payload)
        decision = ToolDecision(
            action="allowed" if allowed else "blocked",
            allowed=allowed,
            reason_codes=reason_codes,
            reasons=reasons,
            policy_hash=self.policy.policy_hash(),
        )
        event = ToolEvent(
            tool_name=request.tool_name,
            call_id=request.call_id,
            arguments=_redact_args(request.arguments, self.policy.canaries),
            decision=decision,
            result_preview=preview,
            latency_seconds=time.perf_counter() - started,
            metadata={"approval_source": request.approval_source or "", "tool_gateway_schema": self.policy.schema_version},
        )
        return ToolResult(decision=decision, result=result_payload, result_preview=preview), event


def default_tool_policy() -> ToolPolicy:
    return ToolPolicy(
        tools={
            "search": ToolSpec(name="search", result={"items": [{"title": "Policy fixture", "snippet": "Local gateway search result."}]}),
            "read_private_doc": ToolSpec(name="read_private_doc", source="private", result={"document": "PRIVATE_DOC_REDACTED"}),
            "send_email": ToolSpec(name="send_email", allowed=False, sink="external"),
            "delete_file": ToolSpec(name="delete_file", requires_approval=True, sink="destructive", result={"deleted": True}),
            "public_export": ToolSpec(name="public_export", source="private", sink="public"),
        },
        canaries=["MALLEUS_SYNTHETIC_CANARY_TOOL_ARG_003"],
    )


def load_tool_policy(path: str | Path) -> ToolPolicy:
    policy_path = Path(path)
    text = policy_path.read_text(encoding="utf-8")
    if policy_path.suffix.lower() == ".json":
        data = json.loads(text)
    else:
        import yaml

        data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError("tool gateway policy must be a mapping")
    return ToolPolicy.model_validate(data)


def _trusted_approval(request: ToolRequest, policy: ToolPolicy) -> bool:
    return bool(request.approved and request.approval_source in set(policy.trusted_approval_sources))


def _secret_surfaces(value: Any, canaries: list[str], prefix: str = "args") -> list[str]:
    surfaces: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            surfaces.extend(_secret_surfaces(item, canaries, f"{prefix}.{key}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            surfaces.extend(_secret_surfaces(item, canaries, f"{prefix}[{index}]"))
    else:
        text = str(value)
        if _SECRET_RE.search(text) or _SYNTHETIC_CANARY_RE.search(text) or any(canary and canary in text for canary in canaries):
            surfaces.append(prefix)
    return surfaces


def _redact_args(value: Any, canaries: list[str]) -> Any:
    if isinstance(value, dict):
        return {str(key): _redact_args(item, canaries) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_args(item, canaries) for item in value]
    text = str(value)
    text = _SYNTHETIC_CANARY_RE.sub("[REDACTED]", text)
    text = _SECRET_RE.sub("[REDACTED]", text)
    for canary in canaries:
        if canary:
            text = text.replace(canary, "[CANARY_REDACTED]")
    return text if isinstance(value, str) else value


def _preview(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True)[:240]


__all__ = [
    "ToolDecision",
    "ToolEvent",
    "ToolGateway",
    "ToolPolicy",
    "ToolRequest",
    "ToolResult",
    "ToolSpec",
    "default_tool_policy",
    "load_tool_policy",
]
