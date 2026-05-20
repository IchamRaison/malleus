from __future__ import annotations

from malleus.judges import (
    JudgeConfig,
    JudgeEnsembleConfig,
    JudgeMetric,
    JudgeRequest,
    evaluate_judge_ensemble,
    evaluate_semantic_judge,
    judge_unavailable,
)


def test_judge_unavailable_metric_shape() -> None:
    metric = judge_unavailable("missing model", judge_model="judge-a", evidence_refs=["case:c1"])

    assert metric.score == 0.0
    assert metric.reason.startswith("judge_unavailable")
    assert metric.success is False
    assert metric.confidence == 0.0
    assert metric.judge_model == "judge-a"
    assert metric.cost == 0.0
    assert metric.evidence_refs == ["case:c1"]
    assert metric.status == "judge_unavailable"


def test_semantic_judges_disabled_by_default() -> None:
    metric = evaluate_semantic_judge(JudgeRequest(prompt="p", response_text="r", rubric="safe", evidence_refs=["report.json"]))

    assert metric.success is False
    assert metric.status == "judge_unavailable"
    assert "disabled by default" in metric.reason
    assert metric.evidence_refs == ["report.json"]


def test_enabled_judge_without_adapter_is_structured_unavailable() -> None:
    metric = evaluate_semantic_judge(
        JudgeRequest(prompt="p", response_text="r", rubric="safe"),
        JudgeConfig(enabled=True, judge_model="semantic-judge"),
    )

    assert metric.success is False
    assert metric.judge_model == "semantic-judge"
    assert metric.status == "judge_unavailable"


def test_provider_judge_placeholder_is_offline_safe_unavailable() -> None:
    metric = evaluate_semantic_judge(
        JudgeRequest(prompt="p", response_text="r", rubric="safe"),
        JudgeConfig(enabled=True, judge_model="judge-a", adapter="openai_compatible", base_url="https://example.invalid"),
    )

    assert metric.success is False
    assert metric.status == "judge_unavailable"
    assert "does not make provider calls" in metric.reason


def test_disabled_ensemble_returns_structured_unavailable_without_provider_calls() -> None:
    metric = evaluate_judge_ensemble(JudgeRequest(prompt="p", response_text="r", rubric="safe", evidence_refs=["case:c1"]))

    assert metric.success is False
    assert metric.status == "judge_unavailable"
    assert metric.evidence_refs == ["case:c1"]
    assert metric.member_metrics[0].status == "judge_unavailable"


def test_mock_ensemble_median_and_disagreement_without_provider_calls() -> None:
    request = JudgeRequest(prompt="p", response_text="r", rubric="safe", evidence_refs=["case:c1"])
    config = JudgeEnsembleConfig(
        enabled=True,
        mock_metrics=[
            JudgeMetric(score=0.2, reason="mock low", success=True, confidence=0.8, judge_model="mock-a", adapter="mock"),
            JudgeMetric(score=0.6, reason="mock mid", success=True, confidence=0.7, judge_model="mock-b", adapter="mock"),
            JudgeMetric(score=0.9, reason="mock high", success=True, confidence=0.9, judge_model="mock-c", adapter="mock"),
        ],
        disagreement_threshold=0.5,
    )

    metric = evaluate_judge_ensemble(request, config)

    assert metric.success is True
    assert metric.status == "success"
    assert metric.score == 0.6
    assert metric.disagreement == 0.7
    assert "exceeds threshold" in metric.reason
    assert len(metric.member_metrics) == 3


def test_judge_unavailable_redacts_secret_like_reason_in_serialized_json() -> None:
    metric = judge_unavailable(
        "failed with api_key=abc123 token: secret-token-value password=hunter2 system_prompt=hidden SYNTHETIC-SK-OPENAI-SECRET",
        judge_model="judge-a",
    )

    serialized = metric.model_dump_json()

    for raw in ["api_key=abc123", "secret-token-value", "password=hunter2", "system_prompt=hidden", "SYNTHETIC-SK-OPENAI-SECRET"]:
        assert raw not in serialized
    assert "[REDACTED]" in serialized
    assert "sha256=" in serialized
    assert "length=" in serialized


def test_direct_judge_metric_redacts_caller_provided_reason_in_serialized_json() -> None:
    metric = JudgeMetric(
        score=0.5,
        reason="mock reason secret=raw-secret and SYNTHETIC-SK-OPENAI-SECRET",
        success=True,
        confidence=0.5,
        judge_model="mock-a",
        adapter="mock",
    )

    serialized = metric.model_dump_json()

    assert "raw-secret" not in serialized
    assert "SYNTHETIC-SK-OPENAI-SECRET" not in serialized
    assert "[REDACTED]" in serialized
    assert "sha256=" in serialized
    assert "length=" in serialized


def test_ensemble_serialization_redacts_member_reasons_without_changing_median_behavior() -> None:
    request = JudgeRequest(prompt="p", response_text="r", rubric="safe")
    config = JudgeEnsembleConfig(
        enabled=True,
        mock_metrics=[
            JudgeMetric(score=0.2, reason="api_key=abc123", success=True, confidence=0.8, judge_model="mock-a", adapter="mock"),
            JudgeMetric(score=0.6, reason="token: secret-token-value", success=True, confidence=0.7, judge_model="mock-b", adapter="mock"),
            JudgeMetric(score=0.9, reason="password=hunter2 system_prompt=hidden SYNTHETIC-SK-OPENAI-SECRET", success=True, confidence=0.9, judge_model="mock-c", adapter="mock"),
        ],
        disagreement_threshold=0.5,
    )

    metric = evaluate_judge_ensemble(request, config)
    serialized = metric.model_dump_json()

    assert metric.score == 0.6
    assert metric.disagreement == 0.7
    for raw in ["api_key=abc123", "secret-token-value", "password=hunter2", "system_prompt=hidden", "SYNTHETIC-SK-OPENAI-SECRET"]:
        assert raw not in serialized
    assert "[REDACTED]" in serialized
    assert "sha256=" in serialized
    assert "length=" in serialized
