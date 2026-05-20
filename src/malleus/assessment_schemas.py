from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field, model_validator


class AssessmentMode(str, Enum):
    DRY_RUN = "dry_run"
    LOCAL_FIXTURE = "local_fixture"
    SIMULATED = "simulated"
    SCAFFOLD = "scaffold"
    LIVE_PROVIDER = "live_provider"


class EvidenceStrength(str, Enum):
    MODEL_BEHAVIOR = "model_behavior"
    FIXTURE_BEHAVIOR = "fixture_behavior"
    STATIC_ANALYSIS = "static_analysis"
    SIMULATED_BEHAVIOR = "simulated_behavior"
    PLANNING_ONLY = "planning_only"


class ScoreInclusion(str, Enum):
    INCLUDED = "included"
    ADVISORY = "advisory"
    EXCLUDED = "excluded"
    PROFILE_DEPENDENT = "profile_dependent"


class PackTier(str, Enum):
    CORE = "core"
    ADVANCED = "advanced"
    EXPERIMENTAL = "experimental"


class Maturity(str, Enum):
    STABLE = "stable"
    BETA = "beta"
    SCAFFOLD = "scaffold"


class ApplicabilityStatus(str, Enum):
    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not_applicable"
    NOT_TESTED = "not_tested"
    REQUIRES_FIXTURE = "requires_fixture"
    REQUIRES_CONFIGURATION = "requires_configuration"
    REQUIRES_LIVE_PROVIDER = "requires_live_provider"
    SCAFFOLD_ONLY = "scaffold_only"
    PROVIDER_ERROR = "provider_error"


class AssessmentPack(BaseModel):
    id: str
    title: str
    description: str = ""
    tier: PackTier
    maturity: Maturity
    default_score_inclusion: ScoreInclusion
    applicable_profiles: list[str] = Field(default_factory=list)
    surfaces: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    required_inputs: list[str] = Field(default_factory=list)
    expected_artifacts: list[str] = Field(default_factory=list)
    scoring_dimensions: list[str] = Field(default_factory=list)
    finding_categories: list[str] = Field(default_factory=list)
    remediation_themes: list[str] = Field(default_factory=list)
    supported_modes: list[AssessmentMode] = Field(default_factory=list)
    evidence_strengths: list[EvidenceStrength] = Field(default_factory=list)
    primary_score_evidence: list[EvidenceStrength] = Field(default_factory=list)
    advisory_when_profile_dependent: bool = False

    @property
    def primary_score_included_by_default(self) -> bool:
        return self.default_score_inclusion is ScoreInclusion.INCLUDED

    @model_validator(mode="after")
    def validate_primary_score_evidence(self) -> "AssessmentPack":
        if EvidenceStrength.PLANNING_ONLY in self.primary_score_evidence:
            raise ValueError("planning_only evidence cannot be primary score evidence")
        if self.primary_score_evidence and (self.maturity is Maturity.SCAFFOLD or self.supported_modes == [AssessmentMode.SCAFFOLD]):
            raise ValueError("scaffold packs cannot declare primary score evidence")
        return self


class AssessmentCatalog(BaseModel):
    packs: list[AssessmentPack]
    profiles: dict[str, list[str]] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_pack_references(self) -> "AssessmentCatalog":
        seen: set[str] = set()
        for pack in self.packs:
            if pack.id in seen:
                raise ValueError(f"duplicate pack id: {pack.id}")
            seen.add(pack.id)

        for profile, pack_ids in self.profiles.items():
            for pack_id in pack_ids:
                if pack_id not in seen:
                    raise ValueError(f"profile {profile} references unknown pack: {pack_id}")
        return self
