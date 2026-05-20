from __future__ import annotations

from collections import defaultdict
from typing import Literal

from pydantic import BaseModel, Field, model_validator

from malleus.assessment_schemas import (
    ApplicabilityStatus,
    AssessmentCatalog,
    AssessmentPack,
    EvidenceStrength,
    Maturity,
    PackTier,
    ScoreInclusion,
)


Posture = Literal["pass", "warn", "fail", "error"]
PackScoreUse = Literal["primary", "advisory", "excluded", "coverage_gap", "error"]

_COVERAGE_GAP_STATUSES = {
    ApplicabilityStatus.NOT_TESTED,
    ApplicabilityStatus.REQUIRES_FIXTURE,
    ApplicabilityStatus.REQUIRES_CONFIGURATION,
    ApplicabilityStatus.REQUIRES_LIVE_PROVIDER,
}
_PRIMARY_POSTURE_PASS_MIN = 90
_PRIMARY_POSTURE_WARN_MIN = 60


class AssessmentFinding(BaseModel):
    id: str
    title: str
    severity: str = "medium"
    category: str = ""
    score_use: str = "primary"
    experimental: bool = False
    ref: str | None = None

    @model_validator(mode="after")
    def populate_ref(self) -> "AssessmentFinding":
        if self.ref is None:
            self.ref = f"finding:{self.id}"
        return self


class AssessmentPackResult(BaseModel):
    pack_id: str
    category: str
    status: ApplicabilityStatus = ApplicabilityStatus.APPLICABLE
    score_inclusion: ScoreInclusion | None = None
    evidence_strength: EvidenceStrength = EvidenceStrength.MODEL_BEHAVIOR
    score: int | None = None
    max_score: int | None = None
    findings: list[AssessmentFinding] = Field(default_factory=list)
    workflow_errors: list[str] = Field(default_factory=list)
    ref: str | None = None

    @model_validator(mode="after")
    def populate_ref(self) -> "AssessmentPackResult":
        if self.ref is None:
            self.ref = f"assessment-pack:{self.pack_id}"
        return self


class AssessmentScoreAggregate(BaseModel):
    score: int | None = None
    earned: int = 0
    possible: int = 0
    pack_ids: list[str] = Field(default_factory=list)


class AssessmentCoverageConfidence(BaseModel):
    score: int | None = None
    tested_relevant_packs: int = 0
    relevant_packs: int = 0
    tested_pack_ids: list[str] = Field(default_factory=list)
    gap_pack_ids: list[str] = Field(default_factory=list)


class AssessmentPackScoreUseDeclaration(BaseModel):
    pack_id: str
    ref: str
    status: ApplicabilityStatus
    score_use: PackScoreUse
    reason: str
    score_inclusion: ScoreInclusion
    evidence_strength: EvidenceStrength


class AssessmentScores(BaseModel):
    profile: str
    posture: Posture
    primary_score: AssessmentScoreAggregate
    coverage_confidence: AssessmentCoverageConfidence
    category_scores: dict[str, AssessmentScoreAggregate] = Field(default_factory=dict)
    pack_score_uses: dict[str, AssessmentPackScoreUseDeclaration] = Field(default_factory=dict)
    evidence_mix: dict[str, int] = Field(default_factory=dict)
    evidence_mix_strength_count: int = 0
    advisory_risk_count: int = 0
    experimental_scaffold_risk_count: int = 0
    error_count: int = 0


def _packs_by_id(catalog: AssessmentCatalog) -> dict[str, AssessmentPack]:
    return {pack.id: pack for pack in catalog.packs}


def _profile_pack_ids(profile: str, catalog: AssessmentCatalog) -> list[str]:
    try:
        return list(catalog.profiles[profile])
    except KeyError as exc:
        raise ValueError(f"unknown profile: {profile}") from exc


def _pack_for_result(result: AssessmentPackResult, packs_by_id: dict[str, AssessmentPack]) -> AssessmentPack:
    try:
        return packs_by_id[result.pack_id]
    except KeyError as exc:
        raise ValueError(f"unknown pack: {result.pack_id}") from exc


def _effective_score_inclusion(result: AssessmentPackResult, pack: AssessmentPack) -> ScoreInclusion:
    return result.score_inclusion or pack.default_score_inclusion


def _is_scaffold_or_experimental(pack: AssessmentPack, result: AssessmentPackResult) -> bool:
    return (
        result.status is ApplicabilityStatus.SCAFFOLD_ONLY
        or pack.tier is PackTier.EXPERIMENTAL
        or pack.maturity is Maturity.SCAFFOLD
    )


def _has_primary_evidence(result: AssessmentPackResult, pack: AssessmentPack) -> bool:
    return (
        result.evidence_strength is not EvidenceStrength.PLANNING_ONLY
        and result.evidence_strength in pack.primary_score_evidence
    )


def _is_profile_dependent_primary(
    profile_pack_ids: set[str],
    result: AssessmentPackResult,
    pack: AssessmentPack,
) -> bool:
    return (
        result.pack_id in profile_pack_ids
        and pack.tier is PackTier.CORE
        and pack.maturity is Maturity.STABLE
        and not pack.advisory_when_profile_dependent
    )


def _is_coverage_relevant(pack_id: str, profile_pack_ids: set[str], pack: AssessmentPack) -> bool:
    if pack_id not in profile_pack_ids:
        return False
    if pack.default_score_inclusion is ScoreInclusion.EXCLUDED:
        return False
    if pack.default_score_inclusion is ScoreInclusion.ADVISORY:
        return False
    return bool(pack.primary_score_evidence)


def _valid_score(result: AssessmentPackResult) -> bool:
    return result.score is not None and result.max_score is not None and result.max_score > 0


def _score_value(earned: int, possible: int) -> int | None:
    if possible <= 0:
        return None
    return round((earned / possible) * 100)


def _declare_score_use(
    *,
    profile_pack_ids: set[str],
    result: AssessmentPackResult,
    pack: AssessmentPack,
) -> tuple[PackScoreUse, str]:
    score_inclusion = _effective_score_inclusion(result, pack)

    if result.status is ApplicabilityStatus.PROVIDER_ERROR or result.workflow_errors:
        return "error", "provider_or_workflow_error"
    if result.status is ApplicabilityStatus.NOT_APPLICABLE:
        return "excluded", "not_applicable"
    if result.status in _COVERAGE_GAP_STATUSES:
        return "coverage_gap", result.status.value
    if _is_scaffold_or_experimental(pack, result):
        return "excluded", "scaffold_or_experimental"
    if score_inclusion is ScoreInclusion.EXCLUDED:
        return "excluded", "score_inclusion_excluded"
    if score_inclusion is ScoreInclusion.ADVISORY:
        return "advisory", "score_inclusion_advisory"
    if result.pack_id not in profile_pack_ids:
        return "excluded", "not_applicable"
    if not _has_primary_evidence(result, pack):
        if result.evidence_strength is EvidenceStrength.PLANNING_ONLY:
            return "excluded", "planning_only_not_primary_evidence"
        return "advisory", "evidence_not_primary"
    if not _valid_score(result):
        return "coverage_gap", "missing_score"
    if score_inclusion is ScoreInclusion.INCLUDED:
        return "primary", "score_inclusion_included"
    if score_inclusion is ScoreInclusion.PROFILE_DEPENDENT:
        if _is_profile_dependent_primary(profile_pack_ids, result, pack):
            return "primary", "profile_dependent_primary"
        return "advisory", "profile_dependent_advisory"
    return "excluded", "score_inclusion_excluded"


def _posture(primary_score: int | None, error_count: int) -> Posture:
    if error_count:
        return "error"
    if primary_score is None:
        return "warn"
    if primary_score >= _PRIMARY_POSTURE_PASS_MIN:
        return "pass"
    if primary_score >= _PRIMARY_POSTURE_WARN_MIN:
        return "warn"
    return "fail"


def compute_assessment_scores(
    *,
    profile: str,
    pack_results: list[AssessmentPackResult],
    catalog: AssessmentCatalog,
) -> AssessmentScores:
    packs_by_id = _packs_by_id(catalog)
    profile_pack_id_list = _profile_pack_ids(profile, catalog)
    profile_pack_ids = set(profile_pack_id_list)

    evidence_mix = {strength.value: 0 for strength in EvidenceStrength}
    pack_score_uses: dict[str, AssessmentPackScoreUseDeclaration] = {}
    primary = AssessmentScoreAggregate()
    category_totals: dict[str, dict[str, int | list[str]]] = defaultdict(lambda: {"earned": 0, "possible": 0, "pack_ids": []})
    error_count = 0
    advisory_risk_count = 0
    experimental_scaffold_risk_count = 0
    tested_coverage_pack_ids: set[str] = set()
    coverage_gap_pack_ids: set[str] = set()

    for result in pack_results:
        pack = _pack_for_result(result, packs_by_id)
        score_inclusion = _effective_score_inclusion(result, pack)
        evidence_mix[result.evidence_strength.value] += 1

        score_use, reason = _declare_score_use(profile_pack_ids=profile_pack_ids, result=result, pack=pack)
        if score_use == "error":
            error_count += 1

        for finding in result.findings:
            if finding.experimental or _is_scaffold_or_experimental(pack, result):
                experimental_scaffold_risk_count += 1
            elif finding.score_use == "advisory" or score_use == "advisory":
                advisory_risk_count += 1

        if _is_coverage_relevant(result.pack_id, profile_pack_ids, pack):
            if score_use == "primary":
                tested_coverage_pack_ids.add(result.pack_id)
            elif score_use in {"coverage_gap", "error", "advisory"}:
                coverage_gap_pack_ids.add(result.pack_id)

        declaration = AssessmentPackScoreUseDeclaration(
            pack_id=result.pack_id,
            ref=result.ref or f"assessment-pack:{result.pack_id}",
            status=result.status,
            score_use=score_use,
            reason=reason,
            score_inclusion=score_inclusion,
            evidence_strength=result.evidence_strength,
        )
        pack_score_uses[result.pack_id] = declaration

        if score_use != "primary" or not _valid_score(result):
            continue

        earned = int(result.score or 0)
        possible = int(result.max_score or 0)
        primary.earned += earned
        primary.possible += possible
        primary.pack_ids.append(result.pack_id)

        category_total = category_totals[result.category]
        category_total["earned"] = int(category_total["earned"]) + earned
        category_total["possible"] = int(category_total["possible"]) + possible
        pack_ids = category_total["pack_ids"]
        assert isinstance(pack_ids, list)
        pack_ids.append(result.pack_id)

    primary.score = _score_value(primary.earned, primary.possible)

    relevant_pack_ids = [
        pack_id
        for pack_id in profile_pack_id_list
        if _is_coverage_relevant(pack_id, profile_pack_ids, packs_by_id[pack_id])
    ]
    coverage = AssessmentCoverageConfidence(
        tested_relevant_packs=len(tested_coverage_pack_ids),
        relevant_packs=len(relevant_pack_ids),
        tested_pack_ids=[pack_id for pack_id in profile_pack_id_list if pack_id in tested_coverage_pack_ids],
        gap_pack_ids=[pack_id for pack_id in profile_pack_id_list if pack_id in coverage_gap_pack_ids],
    )
    coverage.score = _score_value(coverage.tested_relevant_packs, coverage.relevant_packs)

    category_scores: dict[str, AssessmentScoreAggregate] = {}
    for category in sorted(category_totals):
        total = category_totals[category]
        earned = int(total["earned"])
        possible = int(total["possible"])
        pack_ids = total["pack_ids"]
        assert isinstance(pack_ids, list)
        category_scores[category] = AssessmentScoreAggregate(
            score=_score_value(earned, possible),
            earned=earned,
            possible=possible,
            pack_ids=[str(pack_id) for pack_id in pack_ids],
        )

    evidence_mix_strength_count = sum(
        1
        for strength, count in evidence_mix.items()
        if strength != EvidenceStrength.PLANNING_ONLY.value and count > 0
    )

    return AssessmentScores(
        profile=profile,
        posture=_posture(primary.score, error_count),
        primary_score=primary,
        coverage_confidence=coverage,
        category_scores=category_scores,
        pack_score_uses=pack_score_uses,
        evidence_mix=evidence_mix,
        evidence_mix_strength_count=evidence_mix_strength_count,
        advisory_risk_count=advisory_risk_count,
        experimental_scaffold_risk_count=experimental_scaffold_risk_count,
        error_count=error_count,
    )
