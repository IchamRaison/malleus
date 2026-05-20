from __future__ import annotations

from typing import Any
from typing import Literal

from pydantic import BaseModel, Field

AgentRisk = Literal["low", "medium", "high", "critical"]
AttackSurface = Literal[
    "rag_context",
    "tool_output",
    "memory",
    "web_content",
    "support_ticket",
    "hidden_channel",
    "approval",
    "plugin",
    "hook",
    "multi_agent",
    "transcript",
    "artifact_workspace",
    "model_routing",
    "optimization",
    "autonomy",
    "vcs",
    "physical_world",
]


class AgentToolSpec(BaseModel):
    name: str
    description: str
    risk: AgentRisk
    requires_approval: bool = False
    protected: bool = False


class MockObservation(BaseModel):
    source: str
    content: str
    trusted: bool = False


class ToolDecisionRecord(BaseModel):
    tool: str | None = None
    args: dict[str, object] = Field(default_factory=dict)
    allowed_by_policy: bool = False
    reason: str


class ApprovalState(BaseModel):
    required: bool = False
    granted: bool = False
    source: str = "trusted_harness"


class PolicyJudgment(BaseModel):
    passed: bool
    risk: AgentRisk
    violations: list[str] = Field(default_factory=list)
    reason: str


class GateOutcome(BaseModel):
    status: Literal["pass", "warn", "fail"]
    reasons: list[str] = Field(default_factory=list)


class AgentTraceRecord(BaseModel):
    scenario_id: str
    trusted_task: str
    untrusted_context: str = ""
    untrusted_artifacts: list[str] = Field(default_factory=list)
    available_mock_tools: list[str] = Field(default_factory=list)
    observed_tool_decisions: list[ToolDecisionRecord] = Field(default_factory=list)
    mock_observations: list[MockObservation] = Field(default_factory=list)
    memory_writes: list[str] = Field(default_factory=list)
    session_writes: list[str] = Field(default_factory=list)
    approval_state: ApprovalState = Field(default_factory=ApprovalState)
    final_answer: str = ""
    policy_judgment: PolicyJudgment
    gate_outcome: GateOutcome
    canary_violations: list[str] = Field(default_factory=list)


class AgentScenario(BaseModel):
    id: str
    severity: AgentRisk
    attack_surface: AttackSurface
    objective: str
    user_task: str
    untrusted_context: str
    available_tools: list[str] = Field(min_length=1)
    allowed_tools: list[str] = Field(default_factory=list)
    forbidden_tools: list[str] = Field(default_factory=list)
    untrusted_artifacts: list[str] = Field(default_factory=list)
    approval_required: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentScenarioPack(BaseModel):
    name: str
    version: int
    scenarios: list[AgentScenario] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentScenarioResult(BaseModel):
    scenario_id: str
    severity: AgentRisk
    attack_surface: AttackSurface
    objective: str
    prompt: str
    response_text: str
    selected_tool: str | None = None
    selected_args: dict[str, object] = Field(default_factory=dict)
    passed: bool
    risk: AgentRisk
    violation: bool
    reason: str
    trace: AgentTraceRecord | None = None


class AgentLabSummary(BaseModel):
    total_scenarios: int
    passed: int
    violations: int
    highest_risk: AgentRisk | None = None


class AgentLabReport(BaseModel):
    run_id: str
    started_at: str
    finished_at: str
    target_name: str
    target_adapter: str
    target_model: str
    scenarios_path: str
    results: list[AgentScenarioResult] = Field(default_factory=list)
    summary: AgentLabSummary
