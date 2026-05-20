from __future__ import annotations

import pytest

from malleus.assessment_catalog import load_assessment_catalog
from malleus.assessment_schemas import ApplicabilityStatus, EvidenceStrength, ScoreInclusion
from malleus.assessment_scoring import AssessmentFinding, AssessmentPackResult, compute_assessment_scores


def _finding(
    finding_id: str,
    *,
    severity: str = "medium",
    category: str = "Instruction boundary",
    score_use: str = "primary",
    experimental: bool = False,
) -> AssessmentFinding:
    return AssessmentFinding(
        id=finding_id,
        title=f"Finding {finding_id}",
        severity=severity,
        category=category,
        score_use=score_use,
        experimental=experimental,
    )


def _pack_result(
    pack_id: str,
    *,
    category: str = "Instruction boundary",
    status: ApplicabilityStatus = ApplicabilityStatus.APPLICABLE,
    score_inclusion: ScoreInclusion | None = None,
    evidence_strength: EvidenceStrength = EvidenceStrength.MODEL_BEHAVIOR,
    score: int | None = 100,
    max_score: int | None = 100,
    findings: list[AssessmentFinding] | None = None,
    workflow_errors: list[str] | None = None,
) -> AssessmentPackResult:
    return AssessmentPackResult(
        pack_id=pack_id,
        category=category,
        status=status,
        score_inclusion=score_inclusion,
        evidence_strength=evidence_strength,
        score=score,
        max_score=max_score,
        findings=findings or [],
        workflow_errors=workflow_errors or [],
    )


def _score(profile: str, results: list[AssessmentPackResult]):
    return compute_assessment_scores(profile=profile, pack_results=results, catalog=load_assessment_catalog())


def test_primary_score_uses_only_included_and_applicable_profile_dependent_primary_evidence() -> None:
    scores = _score(
        "rag-agent",
        [
            _pack_result("core", score=90, max_score=100),
            _pack_result("anomaly", category="Output anomaly safety", score=80, max_score=100),
            _pack_result("rag", category="RAG context boundary", evidence_strength=EvidenceStrength.FIXTURE_BEHAVIOR, score=70, max_score=100),
            _pack_result("mutation", category="Mutation robustness", score=50, max_score=100),
            _pack_result("artifact", category="Artifact ingestion safety", evidence_strength=EvidenceStrength.FIXTURE_BEHAVIOR, score=40, max_score=100),
            _pack_result("taxonomy", category="Configuration stability", evidence_strength=EvidenceStrength.STATIC_ANALYSIS, score=0, max_score=100),
        ],
    )

    assert scores.primary_score.score == 66
    assert scores.primary_score.earned == 330
    assert scores.primary_score.possible == 500
    assert scores.primary_score.pack_ids == ["core", "anomaly", "rag", "mutation", "artifact"]
    assert scores.pack_score_uses["core"].score_use == "primary"
    assert scores.pack_score_uses["rag"].score_use == "primary"
    assert scores.pack_score_uses["taxonomy"].score_use == "excluded"
    assert scores.pack_score_uses["taxonomy"].reason == "score_inclusion_excluded"


@pytest.mark.parametrize(
    ("pack_id", "status", "score_inclusion", "evidence_strength", "expected_reason"),
    [
        ("core", ApplicabilityStatus.APPLICABLE, ScoreInclusion.INCLUDED, EvidenceStrength.PLANNING_ONLY, "planning_only_not_primary_evidence"),
        ("self_modification", ApplicabilityStatus.SCAFFOLD_ONLY, ScoreInclusion.EXCLUDED, EvidenceStrength.STATIC_ANALYSIS, "scaffold_or_experimental"),
        ("taxonomy", ApplicabilityStatus.APPLICABLE, ScoreInclusion.EXCLUDED, EvidenceStrength.STATIC_ANALYSIS, "score_inclusion_excluded"),
        ("artifact_challenge", ApplicabilityStatus.APPLICABLE, ScoreInclusion.ADVISORY, EvidenceStrength.FIXTURE_BEHAVIOR, "score_inclusion_advisory"),
        ("rag", ApplicabilityStatus.NOT_APPLICABLE, ScoreInclusion.PROFILE_DEPENDENT, EvidenceStrength.FIXTURE_BEHAVIOR, "not_applicable"),
    ],
)
def test_non_primary_score_uses_never_improve_primary_score(
    pack_id: str,
    status: ApplicabilityStatus,
    score_inclusion: ScoreInclusion,
    evidence_strength: EvidenceStrength,
    expected_reason: str,
) -> None:
    scores = _score(
        "chatbot",
        [
            _pack_result("core", score=50, max_score=100),
            _pack_result(pack_id, status=status, score_inclusion=score_inclusion, evidence_strength=evidence_strength, score=100, max_score=100),
        ],
    )

    assert scores.primary_score.score == 50
    assert scores.primary_score.earned == 50
    assert scores.primary_score.possible == 100
    assert scores.pack_score_uses[pack_id].score_use in {"advisory", "excluded", "coverage_gap"}
    assert scores.pack_score_uses[pack_id].reason == expected_reason


def test_not_tested_relevant_pack_lowers_coverage_confidence_not_primary_denominator() -> None:
    scores = _score(
        "rag-agent",
        [
            _pack_result("core", score=100, max_score=100),
            _pack_result("anomaly", score=100, max_score=100),
            _pack_result("rag", evidence_strength=EvidenceStrength.FIXTURE_BEHAVIOR, score=100, max_score=100),
            _pack_result("mutation", status=ApplicabilityStatus.NOT_TESTED, score=None, max_score=None),
            _pack_result("artifact", status=ApplicabilityStatus.REQUIRES_FIXTURE, evidence_strength=EvidenceStrength.FIXTURE_BEHAVIOR, score=None, max_score=None),
            _pack_result("taxonomy", status=ApplicabilityStatus.APPLICABLE, evidence_strength=EvidenceStrength.STATIC_ANALYSIS, score=100, max_score=100),
        ],
    )

    assert scores.primary_score.score == 100
    assert scores.primary_score.possible == 300
    assert scores.coverage_confidence.score == 60
    assert scores.coverage_confidence.tested_relevant_packs == 3
    assert scores.coverage_confidence.relevant_packs == 5
    assert scores.pack_score_uses["mutation"].score_use == "coverage_gap"
    assert scores.pack_score_uses["artifact"].score_use == "coverage_gap"


@pytest.mark.parametrize(
    ("status", "score_use"),
    [
        (ApplicabilityStatus.APPLICABLE, "primary"),
        (ApplicabilityStatus.NOT_APPLICABLE, "excluded"),
        (ApplicabilityStatus.NOT_TESTED, "coverage_gap"),
        (ApplicabilityStatus.REQUIRES_LIVE_PROVIDER, "coverage_gap"),
        (ApplicabilityStatus.REQUIRES_FIXTURE, "coverage_gap"),
        (ApplicabilityStatus.REQUIRES_CONFIGURATION, "coverage_gap"),
        (ApplicabilityStatus.SCAFFOLD_ONLY, "excluded"),
        (ApplicabilityStatus.PROVIDER_ERROR, "error"),
    ],
)
def test_all_applicability_statuses_have_explicit_pack_score_use_declarations(status: ApplicabilityStatus, score_use: str) -> None:
    pack_id = "core" if status is not ApplicabilityStatus.SCAFFOLD_ONLY else "ui_harness"
    scores = _score("chatbot", [_pack_result(pack_id, status=status, score=100 if status is ApplicabilityStatus.APPLICABLE else None)])

    assert scores.pack_score_uses[pack_id].status is status
    assert scores.pack_score_uses[pack_id].score_use == score_use


def test_evidence_mix_counts_all_strengths_but_planning_only_is_never_a_strength() -> None:
    scores = _score(
        "tool-agent",
        [
            _pack_result("core", evidence_strength=EvidenceStrength.MODEL_BEHAVIOR),
            _pack_result("rag", evidence_strength=EvidenceStrength.FIXTURE_BEHAVIOR),
            _pack_result("taxonomy", evidence_strength=EvidenceStrength.STATIC_ANALYSIS),
            _pack_result("tools", evidence_strength=EvidenceStrength.SIMULATED_BEHAVIOR),
            _pack_result("infrastructure", evidence_strength=EvidenceStrength.PLANNING_ONLY),
        ],
    )

    assert scores.evidence_mix == {
        "model_behavior": 1,
        "fixture_behavior": 1,
        "static_analysis": 1,
        "simulated_behavior": 1,
        "planning_only": 1,
    }
    assert scores.evidence_mix_strength_count == 4
    assert scores.pack_score_uses["infrastructure"].score_use == "excluded"


def test_advisory_and_experimental_scaffold_risk_counts_are_separate_from_primary_failures() -> None:
    scores = _score(
        "code-agent",
        [
            _pack_result("core", score=100, max_score=100, findings=[]),
            _pack_result(
                "artifact_challenge",
                score_inclusion=ScoreInclusion.ADVISORY,
                evidence_strength=EvidenceStrength.FIXTURE_BEHAVIOR,
                findings=[_finding("adv-1", score_use="advisory"), _finding("adv-2", score_use="advisory")],
            ),
            _pack_result(
                "self_modification",
                status=ApplicabilityStatus.SCAFFOLD_ONLY,
                score_inclusion=ScoreInclusion.EXCLUDED,
                evidence_strength=EvidenceStrength.STATIC_ANALYSIS,
                findings=[_finding("exp-1", score_use="advisory", experimental=True)],
            ),
        ],
    )

    assert scores.primary_score.score == 100
    assert scores.advisory_risk_count == 2
    assert scores.experimental_scaffold_risk_count == 1
    assert scores.pack_score_uses["artifact_challenge"].score_use == "advisory"
    assert scores.pack_score_uses["self_modification"].score_use == "excluded"


def test_category_scores_aggregate_only_primary_eligible_pack_results() -> None:
    scores = _score(
        "rag-agent",
        [
            _pack_result("core", category="Instruction boundary", score=100, max_score=100),
            _pack_result("mutation", category="Mutation robustness", score=50, max_score=100),
            _pack_result("rag", category="RAG context boundary", evidence_strength=EvidenceStrength.FIXTURE_BEHAVIOR, score=25, max_score=50),
            _pack_result("taxonomy", category="Configuration stability", evidence_strength=EvidenceStrength.STATIC_ANALYSIS, score=0, max_score=100),
            _pack_result("artifact", category="Artifact ingestion safety", status=ApplicabilityStatus.NOT_TESTED, evidence_strength=EvidenceStrength.FIXTURE_BEHAVIOR, score=None, max_score=None),
        ],
    )

    assert scores.category_scores["Instruction boundary"].score == 100
    assert scores.category_scores["Mutation robustness"].score == 50
    assert scores.category_scores["RAG context boundary"].score == 50
    assert "Configuration stability" not in scores.category_scores
    assert "Artifact ingestion safety" not in scores.category_scores


@pytest.mark.parametrize(
    ("score", "workflow_errors", "expected_posture"),
    [
        (95, [], "pass"),
        (75, [], "warn"),
        (45, [], "fail"),
        (95, ["provider timeout"], "error"),
    ],
)
def test_posture_labels_separate_model_security_failure_from_provider_or_workflow_error(
    score: int, workflow_errors: list[str], expected_posture: str
) -> None:
    scores = _score(
        "chatbot",
        [
            _pack_result(
                "core",
                score=score,
                max_score=100,
                workflow_errors=workflow_errors,
                status=ApplicabilityStatus.PROVIDER_ERROR if workflow_errors else ApplicabilityStatus.APPLICABLE,
            )
        ],
    )

    assert scores.posture == expected_posture
    if workflow_errors:
        assert scores.primary_score.score is None
        assert scores.error_count == 1
    elif expected_posture == "fail":
        assert scores.primary_score.score == score
        assert scores.error_count == 0


def test_no_included_packs_and_all_advisory_or_excluded_packs_have_no_primary_score() -> None:
    scores = _score(
        "model-selection",
        [
            _pack_result("comparison", score_inclusion=ScoreInclusion.EXCLUDED, evidence_strength=EvidenceStrength.MODEL_BEHAVIOR, score=100, max_score=100),
            _pack_result("taxonomy", score_inclusion=ScoreInclusion.EXCLUDED, evidence_strength=EvidenceStrength.STATIC_ANALYSIS, score=100, max_score=100),
            _pack_result("infrastructure", score_inclusion=ScoreInclusion.EXCLUDED, evidence_strength=EvidenceStrength.PLANNING_ONLY, score=100, max_score=100),
        ],
    )

    assert scores.primary_score.score is None
    assert scores.primary_score.earned == 0
    assert scores.primary_score.possible == 0
    assert scores.posture == "warn"
    assert all(declaration.score_use != "primary" for declaration in scores.pack_score_uses.values())


def test_mixed_evidence_strengths_and_partial_workflow_failure_preserve_trustworthy_denominators() -> None:
    scores = _score(
        "tool-agent",
        [
            _pack_result("core", score=100, max_score=100),
            _pack_result("anomaly", score=80, max_score=100),
            _pack_result("tools", evidence_strength=EvidenceStrength.SIMULATED_BEHAVIOR, score=100, max_score=100),
            _pack_result("plugin_manifest", evidence_strength=EvidenceStrength.FIXTURE_BEHAVIOR, status=ApplicabilityStatus.REQUIRES_CONFIGURATION, score=None, max_score=None),
            _pack_result("mutation", status=ApplicabilityStatus.PROVIDER_ERROR, score=None, max_score=None, workflow_errors=["adapter failed"]),
        ],
    )

    assert scores.primary_score.score == 90
    assert scores.primary_score.pack_ids == ["core", "anomaly"]
    assert scores.pack_score_uses["tools"].score_use == "advisory"
    assert scores.pack_score_uses["plugin_manifest"].score_use == "coverage_gap"
    assert scores.pack_score_uses["mutation"].score_use == "error"
    assert scores.coverage_confidence.score == 40
    assert scores.posture == "error"
