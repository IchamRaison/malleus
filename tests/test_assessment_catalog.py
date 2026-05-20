from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from malleus.assessment_catalog import AssessmentCatalog, classify_pack_applicability, load_assessment_catalog, resolve_packs, resolve_profile
from malleus.assessment_schemas import (
    ApplicabilityStatus,
    AssessmentMode,
    AssessmentPack,
    EvidenceStrength,
    Maturity,
    PackTier,
    ScoreInclusion,
)


EXPECTED_MODES = ["dry_run", "local_fixture", "simulated", "scaffold", "live_provider"]
EXPECTED_EVIDENCE_STRENGTHS = ["model_behavior", "fixture_behavior", "static_analysis", "simulated_behavior", "planning_only"]
EXPECTED_SCORE_INCLUSION = ["included", "advisory", "excluded", "profile_dependent"]
EXPECTED_PACK_IDS = [
    "core",
    "mutation",
    "rag",
    "tools",
    "artifact",
    "anomaly",
    "visual",
    "safety_tuning",
    "code_agent",
    "plugin_manifest",
    "artifact_challenge",
    "compound",
    "self_modification",
    "ui_harness",
    "taxonomy",
    "comparison",
    "infrastructure",
]
EXPECTED_PROFILE_PACKS = {
    "chatbot": ["core", "mutation", "anomaly", "taxonomy", "infrastructure"],
    "rag-agent": ["core", "mutation", "anomaly", "rag", "artifact", "taxonomy", "infrastructure"],
    "tool-agent": ["core", "mutation", "anomaly", "tools", "plugin_manifest", "compound", "taxonomy", "infrastructure"],
    "code-agent": ["core", "mutation", "anomaly", "code_agent", "plugin_manifest", "artifact_challenge", "self_modification", "taxonomy", "infrastructure"],
    "vision-agent": ["core", "mutation", "anomaly", "artifact", "visual", "ui_harness", "taxonomy", "infrastructure"],
    "model-selection": ["comparison", "safety_tuning", "taxonomy", "infrastructure"],
}


def test_assessment_enums_use_exact_public_values() -> None:
    assert [mode.value for mode in AssessmentMode] == EXPECTED_MODES
    assert [strength.value for strength in EvidenceStrength] == EXPECTED_EVIDENCE_STRENGTHS
    assert [policy.value for policy in ScoreInclusion] == EXPECTED_SCORE_INCLUSION
    assert [status.value for status in ApplicabilityStatus] == [
        "applicable",
        "not_applicable",
        "not_tested",
        "requires_fixture",
        "requires_configuration",
        "requires_live_provider",
        "scaffold_only",
        "provider_error",
    ]


def test_assessment_pack_schema_serializes_modes_evidence_and_score_policy() -> None:
    pack = AssessmentPack(
        id="visual",
        title="Visual Injection",
        description="Visual checks",
        tier=PackTier.ADVANCED,
        maturity=Maturity.BETA,
        default_score_inclusion=ScoreInclusion.PROFILE_DEPENDENT,
        applicable_profiles=["vision-agent"],
        surfaces=["image_text"],
        techniques=["low_contrast_text"],
        required_inputs=["local_visual_fixture"],
        expected_artifacts=["risk-report.json"],
        scoring_dimensions=["visual_ocr_injection_safety"],
        finding_categories=["visual_surface"],
        remediation_themes=["visual_context_labeling"],
        supported_modes=[AssessmentMode.LOCAL_FIXTURE, AssessmentMode.SCAFFOLD],
        evidence_strengths=[EvidenceStrength.FIXTURE_BEHAVIOR, EvidenceStrength.STATIC_ANALYSIS],
        primary_score_evidence=[EvidenceStrength.FIXTURE_BEHAVIOR],
        advisory_when_profile_dependent=True,
    )

    payload = pack.model_dump(mode="json")

    assert payload == {
        "id": "visual",
        "title": "Visual Injection",
        "description": "Visual checks",
        "tier": "advanced",
        "maturity": "beta",
        "default_score_inclusion": "profile_dependent",
        "applicable_profiles": ["vision-agent"],
        "surfaces": ["image_text"],
        "techniques": ["low_contrast_text"],
        "required_inputs": ["local_visual_fixture"],
        "expected_artifacts": ["risk-report.json"],
        "scoring_dimensions": ["visual_ocr_injection_safety"],
        "finding_categories": ["visual_surface"],
        "remediation_themes": ["visual_context_labeling"],
        "supported_modes": ["local_fixture", "scaffold"],
        "evidence_strengths": ["fixture_behavior", "static_analysis"],
        "primary_score_evidence": ["fixture_behavior"],
        "advisory_when_profile_dependent": True,
    }
    assert json.loads(pack.model_dump_json())["supported_modes"] == ["local_fixture", "scaffold"]


@pytest.mark.parametrize(
    ("bad_field", "bad_value", "expected_message"),
    [
        ("supported_modes", ["unknown_mode"], "unknown_mode"),
        ("evidence_strengths", ["unknown_strength"], "unknown_strength"),
        ("default_score_inclusion", "unknown_policy", "unknown_policy"),
    ],
)
def test_assessment_pack_schema_rejects_unknown_mode_evidence_and_score_policy(bad_field: str, bad_value: object, expected_message: str) -> None:
    data = {
        "id": "core",
        "title": "Core LLM Security",
        "description": "Core checks",
        "tier": "core",
        "maturity": "stable",
        "default_score_inclusion": "included",
        "applicable_profiles": ["chatbot"],
        "surfaces": ["model_interface"],
        "techniques": ["direct_override"],
        "required_inputs": ["target_config"],
        "expected_artifacts": ["risk-report.json"],
        "scoring_dimensions": ["instruction_boundary"],
        "finding_categories": ["instruction_boundary"],
        "remediation_themes": ["prompt_boundary_guidance"],
        "supported_modes": ["dry_run", "live_provider"],
        "evidence_strengths": ["model_behavior", "planning_only"],
        "primary_score_evidence": ["model_behavior"],
    }
    data[bad_field] = bad_value

    with pytest.raises(ValidationError, match=expected_message):
        AssessmentPack(**data)


def test_planning_only_and_scaffold_can_never_be_primary_score_evidence() -> None:
    with pytest.raises(ValidationError, match="planning_only.*primary score"):
        AssessmentPack(
            id="planning",
            title="Planning Only",
            description="Planning only",
            tier=PackTier.CORE,
            maturity=Maturity.STABLE,
            default_score_inclusion=ScoreInclusion.EXCLUDED,
            supported_modes=[AssessmentMode.DRY_RUN],
            evidence_strengths=[EvidenceStrength.PLANNING_ONLY],
            primary_score_evidence=[EvidenceStrength.PLANNING_ONLY],
        )

    with pytest.raises(ValidationError, match="scaffold.*primary score"):
        AssessmentPack(
            id="scaffold",
            title="Scaffold",
            description="Scaffold",
            tier=PackTier.EXPERIMENTAL,
            maturity=Maturity.SCAFFOLD,
            default_score_inclusion=ScoreInclusion.EXCLUDED,
            supported_modes=[AssessmentMode.SCAFFOLD],
            evidence_strengths=[EvidenceStrength.STATIC_ANALYSIS],
            primary_score_evidence=[EvidenceStrength.STATIC_ANALYSIS],
        )


def test_load_assessment_catalog_exposes_exact_pack_ids_and_plan_metadata() -> None:
    catalog = load_assessment_catalog()
    packs_by_id = {pack.id: pack for pack in catalog.packs}

    assert list(packs_by_id) == EXPECTED_PACK_IDS
    assert [(packs_by_id[pack_id].tier.value, packs_by_id[pack_id].maturity.value) for pack_id in EXPECTED_PACK_IDS] == [
        ("core", "stable"),
        ("core", "stable"),
        ("core", "stable"),
        ("core", "stable"),
        ("core", "stable"),
        ("core", "stable"),
        ("advanced", "beta"),
        ("advanced", "beta"),
        ("advanced", "beta"),
        ("advanced", "beta"),
        ("advanced", "beta"),
        ("advanced", "beta"),
        ("experimental", "scaffold"),
        ("experimental", "scaffold"),
        ("core", "stable"),
        ("advanced", "beta"),
        ("core", "stable"),
    ]
    assert {pack_id: packs_by_id[pack_id].default_score_inclusion.value for pack_id in ["artifact_challenge", "compound"]} == {
        "artifact_challenge": "advisory",
        "compound": "advisory",
    }
    assert {pack_id: packs_by_id[pack_id].default_score_inclusion.value for pack_id in ["self_modification", "ui_harness", "taxonomy", "comparison", "infrastructure"]} == {
        "self_modification": "excluded",
        "ui_harness": "excluded",
        "taxonomy": "excluded",
        "comparison": "excluded",
        "infrastructure": "excluded",
    }
    for pack in packs_by_id.values():
        assert pack.description
        assert pack.applicable_profiles
        assert pack.surfaces
        assert pack.techniques
        assert pack.required_inputs
        assert pack.expected_artifacts
        assert pack.scoring_dimensions
        assert pack.finding_categories
        assert pack.remediation_themes
    assert packs_by_id["rag"].surfaces == ["rag_context", "untrusted_document", "retrieval_metadata"]
    assert "context_boundary_labeling" in packs_by_id["rag"].remediation_themes


def test_default_profile_mappings_match_plan_lines_116_to_122() -> None:
    catalog = load_assessment_catalog()

    for profile, expected_pack_ids in EXPECTED_PROFILE_PACKS.items():
        resolved = resolve_profile(profile, catalog=catalog)
        assert resolved.profile == profile
        assert [pack.id for pack in resolved.packs] == expected_pack_ids


def test_resolve_packs_preserves_order_and_rejects_unknown_pack() -> None:
    catalog = load_assessment_catalog()

    assert [pack.id for pack in resolve_packs(["visual", "core", "taxonomy"], catalog=catalog)] == ["visual", "core", "taxonomy"]
    with pytest.raises(ValueError, match="unknown pack.*does-not-exist"):
        resolve_packs(["core", "does-not-exist"], catalog=catalog)


def test_resolve_profile_rejects_unknown_profile_without_fallback() -> None:
    with pytest.raises(ValueError, match="unknown profile.*unknown-agent"):
        resolve_profile("unknown-agent", catalog=load_assessment_catalog())


def test_assessment_catalog_rejects_duplicate_pack_ids() -> None:
    pack = AssessmentPack(
        id="core",
        title="Core LLM Security",
        description="Core checks",
        tier=PackTier.CORE,
        maturity=Maturity.STABLE,
        default_score_inclusion=ScoreInclusion.INCLUDED,
        supported_modes=[AssessmentMode.LIVE_PROVIDER],
        evidence_strengths=[EvidenceStrength.MODEL_BEHAVIOR],
        primary_score_evidence=[EvidenceStrength.MODEL_BEHAVIOR],
    )

    with pytest.raises(ValidationError, match="duplicate pack id.*core"):
        AssessmentCatalog(packs=[pack, pack], profiles={"chatbot": ["core"]})


def test_catalog_rejects_profiles_that_reference_unknown_packs() -> None:
    pack = AssessmentPack(
        id="core",
        title="Core LLM Security",
        description="Core checks",
        tier=PackTier.CORE,
        maturity=Maturity.STABLE,
        default_score_inclusion=ScoreInclusion.INCLUDED,
        supported_modes=[AssessmentMode.LIVE_PROVIDER],
        evidence_strengths=[EvidenceStrength.MODEL_BEHAVIOR],
        primary_score_evidence=[EvidenceStrength.MODEL_BEHAVIOR],
    )

    with pytest.raises(ValidationError, match="unknown pack.*missing"):
        AssessmentCatalog(packs=[pack], profiles={"chatbot": ["core", "missing"]})


def test_applicability_distinguishes_profile_relevance_from_run_readiness() -> None:
    catalog = load_assessment_catalog()

    assert classify_pack_applicability("rag-agent", "rag", mode=AssessmentMode.LOCAL_FIXTURE, catalog=catalog).status is ApplicabilityStatus.APPLICABLE
    assert classify_pack_applicability("chatbot", "rag", mode=AssessmentMode.LOCAL_FIXTURE, catalog=catalog).status is ApplicabilityStatus.NOT_APPLICABLE
    assert classify_pack_applicability("vision-agent", "ui_harness", mode=AssessmentMode.SCAFFOLD, catalog=catalog).status is ApplicabilityStatus.SCAFFOLD_ONLY
    assert classify_pack_applicability("vision-agent", "visual", mode=AssessmentMode.LIVE_PROVIDER, catalog=catalog).status is ApplicabilityStatus.REQUIRES_LIVE_PROVIDER


def test_all_advisory_and_excluded_packs_are_not_primary_score_included_by_default() -> None:
    catalog = load_assessment_catalog()
    packs_by_id = {pack.id: pack for pack in catalog.packs}
    advisory_or_excluded = [
        pack
        for pack in packs_by_id.values()
        if pack.default_score_inclusion in {ScoreInclusion.ADVISORY, ScoreInclusion.EXCLUDED}
    ]

    assert [pack.id for pack in advisory_or_excluded] == [
        "artifact_challenge",
        "compound",
        "self_modification",
        "ui_harness",
        "taxonomy",
        "comparison",
        "infrastructure",
    ]
    assert all(not pack.primary_score_included_by_default for pack in advisory_or_excluded)
