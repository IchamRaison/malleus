from __future__ import annotations

import re
from statistics import median
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from malleus.utils.redact import redact_public_text

JudgeStatus = Literal["success", "judge_unavailable", "error"]
JudgeAdapter = Literal["openai_compatible", "ollama", "nvidia", "mock"]

_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|token|password|secret|system[_ -]?prompt)\s*[:=]\s*\S+"
)
_TOKEN_VALUE_RE = re.compile(r"\b(?:sk|pk|rk)-[A-Za-z0-9_-]{6,}\b")


def _sanitize_reason(reason: str) -> str:
    compact = " ".join(reason.split())
    redacted = _SECRET_ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}=[REDACTED]", compact)
    redacted = _TOKEN_VALUE_RE.sub("[REDACTED_TOKEN]", redacted)
    redacted = redact_public_text(redacted).text
    if len(redacted) > 180:
        return f"{redacted[:180].rstrip()}…"
    return redacted


class JudgeMetric(BaseModel):
    score: float = Field(ge=0.0, le=1.0)
    reason: str
    success: bool
    confidence: float = Field(ge=0.0, le=1.0)
    judge_model: str
    cost: float = Field(default=0.0, ge=0.0)
    evidence_refs: list[str] = Field(default_factory=list)
    status: JudgeStatus = "success"
    adapter: JudgeAdapter | None = None

    @field_validator("reason")
    @classmethod
    def sanitize_reason(cls, value: str) -> str:
        return _sanitize_reason(value)


class JudgeConfig(BaseModel):
    enabled: bool = False
    judge_model: str | None = None
    adapter: JudgeAdapter | None = None
    base_url: str | None = None
    api_key_env: str | None = None


class JudgeEnsembleConfig(BaseModel):
    enabled: bool = False
    judges: list[JudgeConfig] = Field(default_factory=list)
    disagreement_threshold: float = Field(default=0.35, ge=0.0, le=1.0)
    mock_metrics: list[JudgeMetric] = Field(default_factory=list)


class JudgeRequest(BaseModel):
    prompt: str
    response_text: str
    rubric: str
    evidence_refs: list[str] = Field(default_factory=list)


class JudgeEnsembleMetric(BaseModel):
    score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    success: bool
    status: JudgeStatus = "success"
    reason: str
    judge_model: str = "ensemble"
    disagreement: float = Field(default=0.0, ge=0.0, le=1.0)
    member_metrics: list[JudgeMetric] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)

    @field_validator("reason")
    @classmethod
    def sanitize_reason(cls, value: str) -> str:
        return _sanitize_reason(value)


def judge_unavailable(reason: str, *, judge_model: str | None = None, evidence_refs: list[str] | None = None) -> JudgeMetric:
    model = judge_model or "unconfigured"
    return JudgeMetric(
        score=0.0,
        reason=f"judge_unavailable: {_sanitize_reason(reason)}",
        success=False,
        confidence=0.0,
        judge_model=model,
        cost=0.0,
        evidence_refs=list(evidence_refs or []),
        status="judge_unavailable",
    )


def disabled_judge_metric(*, evidence_refs: list[str] | None = None) -> JudgeMetric:
    return judge_unavailable("semantic judges are disabled by default", evidence_refs=evidence_refs)


def evaluate_semantic_judge(request: JudgeRequest, config: JudgeConfig | None = None) -> JudgeMetric:
    judge_config = config or JudgeConfig()
    if not judge_config.enabled:
        return disabled_judge_metric(evidence_refs=request.evidence_refs)
    if not judge_config.judge_model:
        return judge_unavailable("enabled judge has no judge_model configured", evidence_refs=request.evidence_refs)
    if judge_config.adapter is None:
        return judge_unavailable(
            "enabled judge has no adapter configured",
            judge_model=judge_config.judge_model,
            evidence_refs=request.evidence_refs,
        )
    if judge_config.adapter in {"openai_compatible", "ollama", "nvidia"}:
        return judge_unavailable(
            f"{judge_config.adapter} judge adapter placeholder is offline-safe and does not make provider calls",
            judge_model=judge_config.judge_model,
            evidence_refs=request.evidence_refs,
        )
    return judge_unavailable(
        "mock adapter requires explicit mock_metrics via evaluate_judge_ensemble",
        judge_model=judge_config.judge_model,
        evidence_refs=request.evidence_refs,
    )


def evaluate_judge_ensemble(request: JudgeRequest, config: JudgeEnsembleConfig | None = None) -> JudgeEnsembleMetric:
    ensemble_config = config or JudgeEnsembleConfig()
    if not ensemble_config.enabled:
        unavailable = disabled_judge_metric(evidence_refs=request.evidence_refs)
        return JudgeEnsembleMetric(
            score=0.0,
            confidence=0.0,
            success=False,
            status="judge_unavailable",
            reason=unavailable.reason,
            member_metrics=[unavailable],
            evidence_refs=list(request.evidence_refs),
        )

    member_metrics: list[JudgeMetric] = list(ensemble_config.mock_metrics)
    member_metrics.extend(evaluate_semantic_judge(request, judge_config) for judge_config in ensemble_config.judges)
    successful = [metric for metric in member_metrics if metric.success and metric.status == "success"]
    if not successful:
        unavailable = judge_unavailable("ensemble has no successful judge metrics", evidence_refs=request.evidence_refs)
        return JudgeEnsembleMetric(
            score=0.0,
            confidence=0.0,
            success=False,
            status="judge_unavailable",
            reason=unavailable.reason,
            member_metrics=member_metrics or [unavailable],
            evidence_refs=list(request.evidence_refs),
        )

    scores = [metric.score for metric in successful]
    confidences = [metric.confidence for metric in successful]
    disagreement = max(scores) - min(scores) if len(scores) > 1 else 0.0
    score = float(median(scores))
    confidence = max(0.0, float(median(confidences)) - disagreement / 2)
    reason = f"ensemble median score from {len(successful)} successful judge metric(s); disagreement={disagreement:.2f}"
    if disagreement > ensemble_config.disagreement_threshold:
        reason = f"{reason}; exceeds threshold={ensemble_config.disagreement_threshold:.2f}"
    return JudgeEnsembleMetric(
        score=score,
        confidence=confidence,
        success=True,
        status="success",
        reason=reason,
        disagreement=disagreement,
        member_metrics=member_metrics,
        evidence_refs=list(request.evidence_refs),
    )


__all__ = [
    "JudgeConfig",
    "JudgeEnsembleConfig",
    "JudgeEnsembleMetric",
    "JudgeMetric",
    "JudgeRequest",
    "disabled_judge_metric",
    "evaluate_judge_ensemble",
    "evaluate_semantic_judge",
    "judge_unavailable",
]
