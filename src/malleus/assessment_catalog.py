from __future__ import annotations

from pydantic import BaseModel

from malleus.assessment_schemas import (
    ApplicabilityStatus,
    AssessmentCatalog,
    AssessmentMode,
    AssessmentPack,
    EvidenceStrength,
    Maturity,
    PackTier,
    ScoreInclusion,
)


class ResolvedAssessmentProfile(BaseModel):
    profile: str
    packs: list[AssessmentPack]


class PackApplicability(BaseModel):
    profile: str
    pack_id: str
    mode: AssessmentMode
    status: ApplicabilityStatus


_PROFILE_PACKS: dict[str, list[str]] = {
    "chatbot": ["core", "mutation", "anomaly", "taxonomy", "infrastructure"],
    "rag-agent": ["core", "mutation", "anomaly", "rag", "artifact", "taxonomy", "infrastructure"],
    "tool-agent": ["core", "mutation", "anomaly", "tools", "plugin_manifest", "compound", "taxonomy", "infrastructure"],
    "code-agent": ["core", "mutation", "anomaly", "code_agent", "plugin_manifest", "artifact_challenge", "self_modification", "taxonomy", "infrastructure"],
    "vision-agent": ["core", "mutation", "anomaly", "artifact", "visual", "ui_harness", "taxonomy", "infrastructure"],
    "model-selection": ["comparison", "safety_tuning", "taxonomy", "infrastructure"],
}

_PACK_METADATA: dict[str, dict[str, list[str] | str]] = {
    "core": {
        "description": "Core instruction-boundary, leakage, policy, refusal, and structured-output checks for chat-style model interfaces.",
        "surfaces": ["model_interface", "instruction_boundary", "structured_output"],
        "techniques": ["direct_override", "role_reassignment", "sensitive_context_leakage", "json_integrity"],
        "required_inputs": ["target_config", "benchmark_cases", "scoring_config"],
        "expected_artifacts": ["risk-report.json", "findings/findings.json", "raw/<pack-id>/planning-metadata.json"],
        "scoring_dimensions": ["instruction_boundary", "sensitive_context_leakage", "policy_robustness", "structured_output_integrity"],
        "finding_categories": ["instruction_boundary", "leakage", "policy_robustness", "output_integrity"],
        "remediation_themes": ["prompt_boundary_guidance", "sensitive_context_controls", "structured_output_validation"],
    },
    "mutation": {
        "description": "Mutation robustness checks for transformed prompt variants and consistency across representation changes.",
        "surfaces": ["model_interface", "prompt_transforms", "tokenization_boundary"],
        "techniques": ["unicode_transform", "encoding_transform", "structured_text_transform", "context_shift"],
        "required_inputs": ["target_config", "mutation_plan", "scoring_config"],
        "expected_artifacts": ["risk-report.json", "coverage/coverage.json", "raw/<pack-id>/planning-metadata.json"],
        "scoring_dimensions": ["mutation_robustness", "refusal_consistency", "policy_robustness"],
        "finding_categories": ["mutation_fragility", "policy_regression", "coverage_gap"],
        "remediation_themes": ["regression_tests", "prompt_hardening", "decoder_configuration_review"],
    },
    "rag": {
        "description": "RAG context-boundary checks for untrusted retrieved content, citation laundering, and canary movement.",
        "surfaces": ["rag_context", "untrusted_document", "retrieval_metadata"],
        "techniques": ["retrieved_instruction_confusion", "citation_laundering", "canary_leakage", "context_boundary_confusion"],
        "required_inputs": ["target_config", "local_rag_fixture", "scoring_config"],
        "expected_artifacts": ["risk-report.json", "findings/findings.json", "raw/<pack-id>/planning-metadata.json"],
        "scoring_dimensions": ["rag_context_boundary", "sensitive_context_leakage", "policy_robustness"],
        "finding_categories": ["rag_boundary", "canary_movement", "coverage_gap"],
        "remediation_themes": ["context_boundary_labeling", "rag_sanitization", "memory_write_policy"],
    },
    "tools": {
        "description": "Tool-use policy checks for untrusted tool output, fake approvals, forbidden selections, and argument routing.",
        "surfaces": ["tool_output", "approval_gate", "tool_arguments"],
        "techniques": ["tool_output_injection", "fake_approval", "forbidden_tool_selection", "argument_canary_check"],
        "required_inputs": ["target_config", "tool_policy", "scoring_config"],
        "expected_artifacts": ["risk-report.json", "findings/findings.json", "raw/<pack-id>/planning-metadata.json"],
        "scoring_dimensions": ["tool_use_policy", "approval_gate_integrity", "sensitive_context_leakage"],
        "finding_categories": ["tool_policy", "approval_bypass", "routing_leak"],
        "remediation_themes": ["tool_approval_policy", "least_privilege_tools", "argument_sanitization"],
    },
    "artifact": {
        "description": "Artifact ingestion checks for unsafe metadata, hidden instructions, archive risks, and extracted-context boundaries.",
        "surfaces": ["html", "svg", "pdf_metadata", "image_metadata", "archive", "notebook", "markdown"],
        "techniques": ["hidden_metadata_instruction", "archive_traversal_marker", "unsafe_extracted_context", "canary_pattern_detection"],
        "required_inputs": ["target_config", "local_artifact_fixture", "scoring_config"],
        "expected_artifacts": ["risk-report.json", "findings/findings.json", "raw/<pack-id>/planning-metadata.json"],
        "scoring_dimensions": ["artifact_ingestion_safety", "workspace_process_boundary_safety"],
        "finding_categories": ["artifact_channel", "unsafe_surface", "coverage_gap"],
        "remediation_themes": ["artifact_firewall_rule", "quarantine_policy", "canary_redaction"],
    },
    "anomaly": {
        "description": "Output anomaly and transcript-boundary checks for replay-like text, fake turns, and unsafe trace shapes.",
        "surfaces": ["model_output", "transcript_boundary", "logs"],
        "techniques": ["pseudo_role_delimiter", "fake_future_turn", "tool_trace_hallucination", "output_loop_detection"],
        "required_inputs": ["target_config", "benchmark_cases", "scoring_config"],
        "expected_artifacts": ["risk-report.json", "findings/findings.json", "raw/<pack-id>/planning-metadata.json"],
        "scoring_dimensions": ["output_anomaly_safety", "refusal_consistency"],
        "finding_categories": ["output_anomaly", "transcript_boundary", "log_safety"],
        "remediation_themes": ["log_sanitization", "transcript_boundary_controls", "regression_tests"],
    },
    "visual": {
        "description": "Visual and OCR-like injection checks for screenshot, image text, metadata, and visual-conflict surfaces.",
        "surfaces": ["image_text", "ocr_surface", "visual_metadata", "screenshot_context"],
        "techniques": ["low_contrast_text", "tiny_text", "overlay_instruction", "caption_conflict"],
        "required_inputs": ["target_config", "local_visual_fixture", "scoring_config"],
        "expected_artifacts": ["risk-report.json", "coverage/coverage.json", "raw/<pack-id>/planning-metadata.json"],
        "scoring_dimensions": ["visual_ocr_injection_safety", "artifact_ingestion_safety"],
        "finding_categories": ["visual_surface", "ocr_boundary", "coverage_gap"],
        "remediation_themes": ["visual_context_labeling", "artifact_firewall_rule", "human_review_gate"],
    },
    "safety_tuning": {
        "description": "Configuration risk-surface checks across decoding and sampling parameters.",
        "surfaces": ["model_configuration", "decoding_parameters", "sampling_variance"],
        "techniques": ["temperature_sweep", "top_p_review", "repeat_sampling", "risk_region_summary"],
        "required_inputs": ["target_config", "parameter_grid", "scoring_config"],
        "expected_artifacts": ["risk-report.json", "coverage/coverage.json", "raw/<pack-id>/planning-metadata.json"],
        "scoring_dimensions": ["configuration_stability", "policy_robustness"],
        "finding_categories": ["configuration_risk", "stability_gap", "coverage_gap"],
        "remediation_themes": ["decoder_configuration_review", "safe_default_policy", "regression_tests"],
    },
    "code_agent": {
        "description": "Code-agent workflow checks for VCS, generated-file, test, policy, and workspace boundary risks.",
        "surfaces": ["repository_workspace", "vcs_workflow", "ci_policy", "generated_files"],
        "techniques": ["commit_without_review", "test_weakening", "policy_modification", "workspace_escape"],
        "required_inputs": ["target_config", "workspace_fixture", "policy_config"],
        "expected_artifacts": ["risk-report.json", "findings/findings.json", "raw/<pack-id>/planning-metadata.json"],
        "scoring_dimensions": ["code_agent_workflow_safety", "workspace_process_boundary_safety", "self_modification_safety"],
        "finding_categories": ["workflow_violation", "policy_weakening", "secret_leakage"],
        "remediation_themes": ["review_gate_policy", "ci_gate_policy", "secret_hygiene"],
    },
    "plugin_manifest": {
        "description": "Plugin and tool manifest checks for excessive permissions, unsafe routes, and approval-contract drift.",
        "surfaces": ["plugin_manifest", "tool_route", "permission_model"],
        "techniques": ["dangerous_route_detection", "permission_review", "approval_field_check", "external_sink_review"],
        "required_inputs": ["target_config", "manifest_fixture", "policy_config"],
        "expected_artifacts": ["risk-report.json", "findings/findings.json", "raw/<pack-id>/planning-metadata.json"],
        "scoring_dimensions": ["plugin_tool_manifest_safety", "tool_use_policy"],
        "finding_categories": ["manifest_risk", "permission_risk", "approval_gap"],
        "remediation_themes": ["least_privilege_tools", "approval_policy", "manifest_review"],
    },
    "artifact_challenge": {
        "description": "Artifact challenge and agent-protocol checks for workspace boundaries, process logs, and expected output artifacts.",
        "surfaces": ["challenge_workspace", "process_log", "agent_protocol_artifact"],
        "techniques": ["path_boundary_check", "artifact_hash_review", "mock_process_supervision"],
        "required_inputs": ["target_config", "challenge_fixture", "workspace_policy"],
        "expected_artifacts": ["risk-report.json", "evidence-bundle/artifact-index.json", "raw/<pack-id>/planning-metadata.json"],
        "scoring_dimensions": ["workspace_process_boundary_safety", "artifact_ingestion_safety"],
        "finding_categories": ["workspace_violation", "artifact_diff", "process_evidence_gap"],
        "remediation_themes": ["workspace_boundary_policy", "artifact_review", "regression_tests"],
    },
    "compound": {
        "description": "Compound-risk checks that connect multiple local findings into realistic incident-chain summaries.",
        "surfaces": ["multi_surface_chain", "risk_triage", "linked_evidence"],
        "techniques": ["incident_chain_modeling", "likelihood_impact_detectability", "countermeasure_mapping"],
        "required_inputs": ["findings_report", "coverage_report", "risk_policy"],
        "expected_artifacts": ["risk-report.json", "findings/findings.json", "raw/<pack-id>/planning-metadata.json"],
        "scoring_dimensions": ["compound_risk", "coverage_confidence"],
        "finding_categories": ["compound_chain", "advisory_risk", "coverage_gap"],
        "remediation_themes": ["countermeasure_mapping", "risk_acceptance_review", "retest_plan"],
    },
    "self_modification": {
        "description": "Self-modification scaffold checks for prompt, policy, scoring, test, and tool weakening risks.",
        "surfaces": ["policy_files", "test_suite", "tool_configuration", "report_templates"],
        "techniques": ["guardrail_weakening_check", "hidden_change_review", "threshold_weakening_detection"],
        "required_inputs": ["target_config", "proposed_diff", "policy_config"],
        "expected_artifacts": ["risk-report.json", "remediation/remediation-board.md", "raw/<pack-id>/planning-metadata.json"],
        "scoring_dimensions": ["self_modification_safety", "code_agent_workflow_safety"],
        "finding_categories": ["self_modification_risk", "test_weakening", "policy_weakening"],
        "remediation_themes": ["human_review_gate", "ci_gate_policy", "policy_change_control"],
    },
    "ui_harness": {
        "description": "UI harness scaffold checks for local/staging planning, selector redaction, and browser-execution boundaries.",
        "surfaces": ["browser_ui", "local_staging_url", "selector_config"],
        "techniques": ["url_allowlist", "selector_redaction", "screenshot_placeholder", "third_party_url_rejection"],
        "required_inputs": ["ui_harness_config", "target_config", "redaction_policy"],
        "expected_artifacts": ["risk-report.json", "coverage/coverage.json", "raw/<pack-id>/planning-metadata.json"],
        "scoring_dimensions": ["ui_harness_scaffold", "artifact_ingestion_safety"],
        "finding_categories": ["ui_scaffold_gap", "redaction_gap", "network_boundary"],
        "remediation_themes": ["url_allowlist_policy", "selector_redaction", "browser_execution_gate"],
    },
    "taxonomy": {
        "description": "Taxonomy and coverage metadata checks that explain tested, missing, scaffold-only, and not-applicable surfaces.",
        "surfaces": ["assessment_taxonomy", "coverage_matrix", "dataset_snapshot"],
        "techniques": ["coverage_matrix", "taxonomy_snapshot", "missing_surface_declaration"],
        "required_inputs": ["catalog_metadata", "selected_profile", "selected_packs"],
        "expected_artifacts": ["coverage/coverage.json", "coverage/coverage.md", "raw/<pack-id>/planning-metadata.json"],
        "scoring_dimensions": ["coverage_confidence", "taxonomy_coverage"],
        "finding_categories": ["coverage_gap", "not_applicable", "scaffold_only"],
        "remediation_themes": ["coverage_expansion", "claim_support_review", "retest_plan"],
    },
    "comparison": {
        "description": "Model/configuration comparison metadata for provider-free leaderboard and shared-risk reporting.",
        "surfaces": ["model_selection", "configuration_comparison", "leaderboard"],
        "techniques": ["per_model_score_summary", "shared_failure_grouping", "model_specific_risk_mapping"],
        "required_inputs": ["primary_target_config", "compare_target_configs", "risk_reports"],
        "expected_artifacts": ["model-comparison/comparison.json", "model-comparison/leaderboard.html", "raw/<pack-id>/planning-metadata.json"],
        "scoring_dimensions": ["model_selection", "coverage_confidence", "configuration_stability"],
        "finding_categories": ["comparison_gap", "shared_failure", "model_specific_risk"],
        "remediation_themes": ["model_selection_review", "configuration_hardening", "retest_plan"],
    },
    "infrastructure": {
        "description": "Assessment infrastructure metadata for findings, remediation, regression, evidence bundle, studio, coverage, and gates.",
        "surfaces": ["reporting_pipeline", "remediation_pipeline", "regression_pipeline", "ci_gate"],
        "techniques": ["artifact_manifest", "issue_export", "replay_command_generation", "gate_summary"],
        "required_inputs": ["risk_report", "findings", "coverage", "policy_config"],
        "expected_artifacts": ["assessment-manifest.json", "remediation/remediation-board.md", "regression/replay-commands.md"],
        "scoring_dimensions": ["assessment_infrastructure", "coverage_confidence"],
        "finding_categories": ["workflow_error", "coverage_gap", "artifact_mapping"],
        "remediation_themes": ["triage_workflow", "regression_tests", "ci_gate_policy"],
    },
}


def _pack(
    pack_id: str,
    title: str,
    tier: PackTier,
    maturity: Maturity,
    default_score_inclusion: ScoreInclusion,
    supported_modes: list[AssessmentMode],
    evidence_strengths: list[EvidenceStrength],
    primary_score_evidence: list[EvidenceStrength] | None = None,
    advisory_when_profile_dependent: bool = False,
) -> AssessmentPack:
    metadata = _PACK_METADATA[pack_id]
    return AssessmentPack(
        id=pack_id,
        title=title,
        description=str(metadata["description"]),
        tier=tier,
        maturity=maturity,
        default_score_inclusion=default_score_inclusion,
        applicable_profiles=[profile for profile, profile_pack_ids in _PROFILE_PACKS.items() if pack_id in profile_pack_ids],
        surfaces=list(metadata["surfaces"]),
        techniques=list(metadata["techniques"]),
        required_inputs=list(metadata["required_inputs"]),
        expected_artifacts=list(metadata["expected_artifacts"]),
        scoring_dimensions=list(metadata["scoring_dimensions"]),
        finding_categories=list(metadata["finding_categories"]),
        remediation_themes=list(metadata["remediation_themes"]),
        supported_modes=supported_modes,
        evidence_strengths=evidence_strengths,
        primary_score_evidence=primary_score_evidence or [],
        advisory_when_profile_dependent=advisory_when_profile_dependent,
    )


def load_assessment_catalog() -> AssessmentCatalog:
    packs = [
        _pack(
            "core",
            "Core LLM Security",
            PackTier.CORE,
            Maturity.STABLE,
            ScoreInclusion.INCLUDED,
            [AssessmentMode.DRY_RUN, AssessmentMode.LIVE_PROVIDER],
            [EvidenceStrength.PLANNING_ONLY, EvidenceStrength.MODEL_BEHAVIOR],
            [EvidenceStrength.MODEL_BEHAVIOR],
        ),
        _pack(
            "mutation",
            "Mutation Robustness",
            PackTier.CORE,
            Maturity.STABLE,
            ScoreInclusion.PROFILE_DEPENDENT,
            [AssessmentMode.DRY_RUN, AssessmentMode.LIVE_PROVIDER],
            [EvidenceStrength.PLANNING_ONLY, EvidenceStrength.MODEL_BEHAVIOR],
            [EvidenceStrength.MODEL_BEHAVIOR],
        ),
        _pack(
            "rag",
            "RAG Injection",
            PackTier.CORE,
            Maturity.STABLE,
            ScoreInclusion.PROFILE_DEPENDENT,
            [AssessmentMode.LOCAL_FIXTURE, AssessmentMode.SCAFFOLD],
            [EvidenceStrength.FIXTURE_BEHAVIOR, EvidenceStrength.STATIC_ANALYSIS],
            [EvidenceStrength.FIXTURE_BEHAVIOR],
        ),
        _pack(
            "tools",
            "Tool-Use and Agent Policy",
            PackTier.CORE,
            Maturity.STABLE,
            ScoreInclusion.PROFILE_DEPENDENT,
            [AssessmentMode.SIMULATED, AssessmentMode.LIVE_PROVIDER],
            [EvidenceStrength.SIMULATED_BEHAVIOR, EvidenceStrength.MODEL_BEHAVIOR],
            [EvidenceStrength.MODEL_BEHAVIOR],
        ),
        _pack(
            "artifact",
            "Artifact Injection",
            PackTier.CORE,
            Maturity.STABLE,
            ScoreInclusion.PROFILE_DEPENDENT,
            [AssessmentMode.LOCAL_FIXTURE, AssessmentMode.SCAFFOLD],
            [EvidenceStrength.FIXTURE_BEHAVIOR, EvidenceStrength.STATIC_ANALYSIS],
            [EvidenceStrength.FIXTURE_BEHAVIOR],
        ),
        _pack(
            "anomaly",
            "Output Anomaly and Transcript Boundary",
            PackTier.CORE,
            Maturity.STABLE,
            ScoreInclusion.INCLUDED,
            [AssessmentMode.DRY_RUN, AssessmentMode.LIVE_PROVIDER],
            [EvidenceStrength.PLANNING_ONLY, EvidenceStrength.MODEL_BEHAVIOR],
            [EvidenceStrength.MODEL_BEHAVIOR],
        ),
        _pack(
            "visual",
            "Visual Injection",
            PackTier.ADVANCED,
            Maturity.BETA,
            ScoreInclusion.PROFILE_DEPENDENT,
            [AssessmentMode.LOCAL_FIXTURE, AssessmentMode.SCAFFOLD],
            [EvidenceStrength.FIXTURE_BEHAVIOR, EvidenceStrength.STATIC_ANALYSIS],
            [EvidenceStrength.FIXTURE_BEHAVIOR],
            advisory_when_profile_dependent=True,
        ),
        _pack(
            "safety_tuning",
            "Safety Tuning and Risk Surface",
            PackTier.ADVANCED,
            Maturity.BETA,
            ScoreInclusion.PROFILE_DEPENDENT,
            [AssessmentMode.DRY_RUN, AssessmentMode.LIVE_PROVIDER],
            [EvidenceStrength.PLANNING_ONLY, EvidenceStrength.MODEL_BEHAVIOR],
            [EvidenceStrength.MODEL_BEHAVIOR],
            advisory_when_profile_dependent=True,
        ),
        _pack(
            "code_agent",
            "Code-Agent Workflow Risk",
            PackTier.ADVANCED,
            Maturity.BETA,
            ScoreInclusion.PROFILE_DEPENDENT,
            [AssessmentMode.SIMULATED, AssessmentMode.LIVE_PROVIDER],
            [EvidenceStrength.SIMULATED_BEHAVIOR, EvidenceStrength.MODEL_BEHAVIOR],
            [EvidenceStrength.MODEL_BEHAVIOR],
            advisory_when_profile_dependent=True,
        ),
        _pack(
            "plugin_manifest",
            "Plugin and Tool Manifest Risk",
            PackTier.ADVANCED,
            Maturity.BETA,
            ScoreInclusion.PROFILE_DEPENDENT,
            [AssessmentMode.LOCAL_FIXTURE, AssessmentMode.SCAFFOLD],
            [EvidenceStrength.FIXTURE_BEHAVIOR, EvidenceStrength.STATIC_ANALYSIS],
            [EvidenceStrength.FIXTURE_BEHAVIOR],
            advisory_when_profile_dependent=True,
        ),
        _pack(
            "artifact_challenge",
            "Artifact Challenge / Agent Protocol",
            PackTier.ADVANCED,
            Maturity.BETA,
            ScoreInclusion.ADVISORY,
            [AssessmentMode.LOCAL_FIXTURE, AssessmentMode.SIMULATED],
            [EvidenceStrength.FIXTURE_BEHAVIOR, EvidenceStrength.SIMULATED_BEHAVIOR],
            [EvidenceStrength.FIXTURE_BEHAVIOR],
        ),
        _pack(
            "compound",
            "Compound Risk",
            PackTier.ADVANCED,
            Maturity.BETA,
            ScoreInclusion.ADVISORY,
            [AssessmentMode.LOCAL_FIXTURE, AssessmentMode.SIMULATED],
            [EvidenceStrength.FIXTURE_BEHAVIOR, EvidenceStrength.SIMULATED_BEHAVIOR, EvidenceStrength.STATIC_ANALYSIS],
            [EvidenceStrength.FIXTURE_BEHAVIOR],
        ),
        _pack(
            "self_modification",
            "Self-Modification Safety",
            PackTier.EXPERIMENTAL,
            Maturity.SCAFFOLD,
            ScoreInclusion.EXCLUDED,
            [AssessmentMode.SCAFFOLD],
            [EvidenceStrength.PLANNING_ONLY, EvidenceStrength.STATIC_ANALYSIS],
        ),
        _pack(
            "ui_harness",
            "UI Harness Scaffold",
            PackTier.EXPERIMENTAL,
            Maturity.SCAFFOLD,
            ScoreInclusion.EXCLUDED,
            [AssessmentMode.SCAFFOLD],
            [EvidenceStrength.PLANNING_ONLY, EvidenceStrength.STATIC_ANALYSIS],
        ),
        _pack(
            "taxonomy",
            "Taxonomy and Coverage",
            PackTier.CORE,
            Maturity.STABLE,
            ScoreInclusion.EXCLUDED,
            [AssessmentMode.LOCAL_FIXTURE, AssessmentMode.DRY_RUN],
            [EvidenceStrength.STATIC_ANALYSIS, EvidenceStrength.PLANNING_ONLY],
        ),
        _pack(
            "comparison",
            "Model Comparison",
            PackTier.ADVANCED,
            Maturity.BETA,
            ScoreInclusion.EXCLUDED,
            [AssessmentMode.DRY_RUN, AssessmentMode.LIVE_PROVIDER],
            [EvidenceStrength.PLANNING_ONLY, EvidenceStrength.MODEL_BEHAVIOR],
        ),
        _pack(
            "infrastructure",
            "Findings, Remediation, Regression, Coverage, Gates",
            PackTier.CORE,
            Maturity.STABLE,
            ScoreInclusion.EXCLUDED,
            [AssessmentMode.LOCAL_FIXTURE, AssessmentMode.DRY_RUN, AssessmentMode.SCAFFOLD],
            [EvidenceStrength.STATIC_ANALYSIS, EvidenceStrength.PLANNING_ONLY],
        ),
    ]
    return AssessmentCatalog(packs=packs, profiles=_PROFILE_PACKS)


def resolve_packs(pack_ids: list[str], catalog: AssessmentCatalog | None = None) -> list[AssessmentPack]:
    catalog = catalog or load_assessment_catalog()
    packs_by_id = {pack.id: pack for pack in catalog.packs}
    resolved = []
    for pack_id in pack_ids:
        try:
            resolved.append(packs_by_id[pack_id])
        except KeyError as exc:
            raise ValueError(f"unknown pack: {pack_id}") from exc
    return resolved


def resolve_profile(profile: str, catalog: AssessmentCatalog | None = None) -> ResolvedAssessmentProfile:
    catalog = catalog or load_assessment_catalog()
    try:
        pack_ids = catalog.profiles[profile]
    except KeyError as exc:
        raise ValueError(f"unknown profile: {profile}") from exc
    return ResolvedAssessmentProfile(profile=profile, packs=resolve_packs(pack_ids, catalog=catalog))


def classify_pack_applicability(
    profile: str,
    pack_id: str,
    mode: AssessmentMode,
    catalog: AssessmentCatalog | None = None,
) -> PackApplicability:
    catalog = catalog or load_assessment_catalog()
    profile_pack_ids = catalog.profiles.get(profile)
    if profile_pack_ids is None:
        raise ValueError(f"unknown profile: {profile}")
    pack = resolve_packs([pack_id], catalog=catalog)[0]

    if pack_id not in profile_pack_ids:
        status = ApplicabilityStatus.NOT_APPLICABLE
    elif pack.maturity is Maturity.SCAFFOLD or mode is AssessmentMode.SCAFFOLD:
        status = ApplicabilityStatus.SCAFFOLD_ONLY
    elif mode in pack.supported_modes:
        status = ApplicabilityStatus.APPLICABLE
    elif mode is AssessmentMode.LIVE_PROVIDER:
        status = ApplicabilityStatus.REQUIRES_LIVE_PROVIDER
    elif AssessmentMode.LOCAL_FIXTURE in pack.supported_modes:
        status = ApplicabilityStatus.REQUIRES_FIXTURE
    else:
        status = ApplicabilityStatus.NOT_TESTED

    return PackApplicability(profile=profile, pack_id=pack_id, mode=mode, status=status)
