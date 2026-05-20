from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from malleus.assessment_catalog import classify_pack_applicability, load_assessment_catalog, resolve_packs, resolve_profile
from malleus.assessment_compare_gate import write_assessment_gate_artifacts, write_model_comparison_artifacts
from malleus.assessment_reporting import AssessmentEvidenceRef, AssessmentReportInput, write_assessment_reports
from malleus.assessment_schemas import ApplicabilityStatus, AssessmentMode, AssessmentPack, EvidenceStrength
from malleus.assessment_scoring import AssessmentPackResult, compute_assessment_scores
from malleus.datasets import load_target_config


ASSESSMENT_MANIFEST_SCHEMA_VERSION = "malleus.assessment_manifest.v1"
PROVIDER_CALLS_ENABLED = False
NETWORK_ENABLED = False
PROVIDER_DISABLED_CAVEAT = "provider and network calls are disabled for assessment orchestration"
LIVE_PROVIDER_FAIL_CLOSED_CAVEAT = "live_provider assessment mode is fail-closed scaffold behavior; no adapters are instantiated and no provider response evidence is collected"
CANONICAL_ASSESSMENT_DIRS = (
    "coverage",
    "findings",
    "remediation",
    "remediation/patches",
    "regression",
    "evidence-bundle",
    "studio",
    "raw",
    "gate",
)


def _expanded_packs(profile: str, packs: list[str]) -> list[AssessmentPack]:
    catalog = load_assessment_catalog()
    if packs == ["default"]:
        return list(resolve_profile(profile, catalog=catalog).packs)
    if packs == ["all"]:
        return list(catalog.packs)
    return list(resolve_packs(packs, catalog=catalog))


def _optional_path(path: Path | None) -> str | None:
    return str(path) if path is not None else None


def _json_bytes(data: dict[str, Any]) -> bytes:
    return (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _target_config_hash(target: Any) -> str:
    return _sha256_bytes(
        _json_bytes(
            {
                "name": target.name,
                "adapter": target.adapter,
                "model": target.model,
                "base_url": target.base_url,
            }
        )
    )


def _file_sha256(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _safe_manifest_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(Path.cwd().resolve()))
    except ValueError:
        return path.name


def _git_commit() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except Exception:
        return "unknown"
    commit = result.stdout.strip()
    return commit if commit else "unknown"


def _case_filter_hashes(case_ids: list[str]) -> list[str]:
    return [hashlib.sha256(case_id.encode("utf-8")).hexdigest() for case_id in case_ids]


def _score_use_label(result: AssessmentPackResult, score_use: str) -> str:
    if result.status is ApplicabilityStatus.NOT_APPLICABLE:
        return "not_applicable"
    if result.status in {
        ApplicabilityStatus.NOT_TESTED,
        ApplicabilityStatus.REQUIRES_FIXTURE,
        ApplicabilityStatus.REQUIRES_CONFIGURATION,
        ApplicabilityStatus.REQUIRES_LIVE_PROVIDER,
        ApplicabilityStatus.SCAFFOLD_ONLY,
        ApplicabilityStatus.PROVIDER_ERROR,
    }:
        return "not_tested"
    if score_use == "primary":
        return "included"
    if score_use == "advisory":
        return "advisory"
    return "excluded"


def _status_for_mode(
    *,
    profile: str,
    pack: AssessmentPack,
    mode: AssessmentMode,
    compare_targets: list[Path],
    catalog: Any,
) -> ApplicabilityStatus:
    catalog_status = classify_pack_applicability(profile, pack.id, mode, catalog=catalog).status
    if pack.id == "comparison" and mode is not AssessmentMode.SCAFFOLD and not compare_targets:
        return ApplicabilityStatus.REQUIRES_CONFIGURATION
    if mode is AssessmentMode.DRY_RUN:
        if AssessmentMode.DRY_RUN in pack.supported_modes:
            return ApplicabilityStatus.APPLICABLE
        return catalog_status
    if mode is AssessmentMode.LOCAL_FIXTURE:
        if AssessmentMode.LOCAL_FIXTURE in pack.supported_modes:
            if EvidenceStrength.FIXTURE_BEHAVIOR in pack.evidence_strengths:
                return ApplicabilityStatus.REQUIRES_FIXTURE
            return ApplicabilityStatus.APPLICABLE
        if AssessmentMode.LIVE_PROVIDER in pack.supported_modes:
            return ApplicabilityStatus.REQUIRES_LIVE_PROVIDER
        return catalog_status
    if mode is AssessmentMode.SIMULATED:
        if AssessmentMode.SIMULATED in pack.supported_modes:
            return ApplicabilityStatus.APPLICABLE
        if AssessmentMode.LOCAL_FIXTURE in pack.supported_modes:
            return ApplicabilityStatus.REQUIRES_FIXTURE
        if AssessmentMode.LIVE_PROVIDER in pack.supported_modes:
            return ApplicabilityStatus.REQUIRES_LIVE_PROVIDER
        return catalog_status
    if mode is AssessmentMode.SCAFFOLD:
        return ApplicabilityStatus.SCAFFOLD_ONLY
    if mode is AssessmentMode.LIVE_PROVIDER:
        if AssessmentMode.LIVE_PROVIDER in pack.supported_modes:
            return ApplicabilityStatus.REQUIRES_LIVE_PROVIDER
        return catalog_status
    return catalog_status


def _evidence_strength_for_mode(pack: AssessmentPack, mode: AssessmentMode, status: ApplicabilityStatus) -> EvidenceStrength:
    if status is ApplicabilityStatus.SCAFFOLD_ONLY:
        return EvidenceStrength.PLANNING_ONLY
    if mode is AssessmentMode.DRY_RUN:
        return EvidenceStrength.PLANNING_ONLY
    if mode is AssessmentMode.LOCAL_FIXTURE:
        if status is ApplicabilityStatus.APPLICABLE and EvidenceStrength.STATIC_ANALYSIS in pack.evidence_strengths:
            return EvidenceStrength.STATIC_ANALYSIS
        return EvidenceStrength.FIXTURE_BEHAVIOR if EvidenceStrength.FIXTURE_BEHAVIOR in pack.evidence_strengths else EvidenceStrength.PLANNING_ONLY
    if mode is AssessmentMode.SIMULATED:
        return EvidenceStrength.SIMULATED_BEHAVIOR if EvidenceStrength.SIMULATED_BEHAVIOR in pack.evidence_strengths else EvidenceStrength.PLANNING_ONLY
    if mode is AssessmentMode.SCAFFOLD:
        return EvidenceStrength.PLANNING_ONLY
    if mode is AssessmentMode.LIVE_PROVIDER:
        return EvidenceStrength.PLANNING_ONLY
    return EvidenceStrength.MODEL_BEHAVIOR if EvidenceStrength.MODEL_BEHAVIOR in pack.evidence_strengths else EvidenceStrength.PLANNING_ONLY


def _workflow_notes(status: ApplicabilityStatus, mode: AssessmentMode) -> list[str]:
    if status is ApplicabilityStatus.REQUIRES_FIXTURE:
        return ["local fixture evidence is required but no fixture input is configured for this assessment seam"]
    if status is ApplicabilityStatus.REQUIRES_CONFIGURATION:
        return ["additional local configuration is required before this pack can be assessed"]
    if status is ApplicabilityStatus.REQUIRES_LIVE_PROVIDER:
        notes = ["live provider evidence is required; provider calls are not made by this provider-free orchestrator"]
        if mode is AssessmentMode.LIVE_PROVIDER:
            notes.append(LIVE_PROVIDER_FAIL_CLOSED_CAVEAT)
        return notes
    if status is ApplicabilityStatus.NOT_TESTED:
        return [f"pack is unsupported in {mode.value} mode and was not tested"]
    if status is ApplicabilityStatus.SCAFFOLD_ONLY:
        return ["scaffold planning artifact only; no behavioral evidence was collected"]
    return []


def _mode_caveats(mode: AssessmentMode) -> list[str]:
    caveats = [PROVIDER_DISABLED_CAVEAT]
    if mode is AssessmentMode.DRY_RUN:
        caveats.append("dry_run mode records planning metadata only; no model responses are collected")
    elif mode is AssessmentMode.LOCAL_FIXTURE:
        caveats.append("local_fixture mode uses local/static evidence only; missing fixtures remain coverage gaps")
    elif mode is AssessmentMode.SIMULATED:
        caveats.append("simulated mode uses deterministic simulated evidence only; provider behavior is not tested")
    elif mode is AssessmentMode.SCAFFOLD:
        caveats.append("scaffold mode writes integration shape only; behavioral evidence is not collected")
    elif mode is AssessmentMode.LIVE_PROVIDER:
        caveats.append(LIVE_PROVIDER_FAIL_CLOSED_CAVEAT)
    return caveats


def _public_primary_score_evidence(pack: AssessmentPack, mode: AssessmentMode) -> list[str]:
    if mode is AssessmentMode.LIVE_PROVIDER:
        return []
    return [strength.value for strength in pack.primary_score_evidence]


def _augment_manifest_guardrails(manifest_path: Path, *, caveats: list[str], posture: str) -> None:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["provider_calls_enabled"] = PROVIDER_CALLS_ENABLED
    manifest["network_enabled"] = NETWORK_ENABLED
    manifest["posture"] = posture
    manifest["caveats"] = caveats
    manifest["provider_guardrails"] = {
        "provider_calls_enabled": PROVIDER_CALLS_ENABLED,
        "network_enabled": NETWORK_ENABLED,
        "adapter_instantiation": "disabled",
        "live_provider_behavior": "fail_closed",
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _pack_category(pack: AssessmentPack) -> str:
    if pack.id in {"core", "mutation", "anomaly", "safety_tuning"}:
        return "Model security"
    if pack.id in {"rag", "artifact", "visual", "plugin_manifest", "artifact_challenge"}:
        return "Context and artifact security"
    if pack.id in {"tools", "code_agent", "compound", "self_modification", "ui_harness"}:
        return "Agent workflow security"
    return "Assessment infrastructure"


def _pack_score(result: AssessmentPackResult) -> dict[str, Any]:
    if result.score is None or result.max_score is None or result.max_score <= 0:
        return {"earned": 0, "possible": 0, "pass_rate": None}
    return {"earned": result.score, "possible": result.max_score, "pass_rate": result.score / result.max_score}


def _coverage_row(pack: AssessmentPack, result: AssessmentPackResult, evidence: AssessmentEvidenceRef) -> dict[str, Any]:
    if result.status is ApplicabilityStatus.APPLICABLE:
        status = "planned" if result.evidence_strength is EvidenceStrength.PLANNING_ONLY else "covered"
    else:
        status = result.status.value
    return {
        "dimension": "assessment_pack",
        "value": pack.id,
        "status": status,
        "pack_ids": [pack.id],
        "evidence_refs": [evidence],
    }


def _finding_surface(pack_id: str) -> str:
    surfaces = {
        "rag": "retrieval_context",
        "artifact": "artifact_ingestion",
        "artifact_challenge": "artifact_ingestion",
        "visual": "visual_context",
        "tools": "tool_use",
        "plugin_manifest": "tool_manifest",
        "code_agent": "code_workspace",
        "ui_harness": "browser_ui",
        "comparison": "model_selection",
        "safety_tuning": "safety_configuration",
        "taxonomy": "taxonomy_coverage",
        "infrastructure": "assessment_infrastructure",
    }
    return surfaces.get(pack_id, "model_interface")


def _finding_id(*, profile: str, pack_id: str, status: ApplicabilityStatus) -> str:
    slug_status = status.value.replace("_", "-")
    digest = hashlib.sha256(f"{profile}:{pack_id}:{status.value}".encode("utf-8")).hexdigest()[:12]
    return f"finding-{profile}-{pack_id}-{slug_status}-{digest}"


def _finding_category(status: ApplicabilityStatus) -> str:
    if status in {
        ApplicabilityStatus.NOT_TESTED,
        ApplicabilityStatus.REQUIRES_FIXTURE,
        ApplicabilityStatus.REQUIRES_CONFIGURATION,
        ApplicabilityStatus.REQUIRES_LIVE_PROVIDER,
    }:
        return "coverage_gap"
    return "informational"


def _finding_status(status: ApplicabilityStatus) -> str:
    if _finding_category(status) == "coverage_gap":
        return "coverage_gap"
    return "informational"


def _finding_remediation(status: ApplicabilityStatus, pack: AssessmentPack) -> str:
    if status is ApplicabilityStatus.REQUIRES_FIXTURE:
        return f"Add reviewed local fixture evidence for {pack.id} before using it in primary assessment decisions."
    if status is ApplicabilityStatus.REQUIRES_CONFIGURATION:
        return f"Configure the local assessment prerequisites for {pack.id} and rerun provider-free assessment."
    if status is ApplicabilityStatus.REQUIRES_LIVE_PROVIDER:
        return f"Collect reviewed provider evidence for {pack.id} only through an explicitly approved live workflow; keep this scaffold out of model-security failure counts."
    if status is ApplicabilityStatus.NOT_TESTED:
        return f"Select a supported provider-free mode or fixture path for {pack.id} and rerun assessment."
    return f"Track {pack.id} as informational scaffold coverage until executable evidence is available."


def _normalized_finding(
    *,
    profile: str,
    mode: AssessmentMode,
    pack: AssessmentPack,
    status: ApplicabilityStatus,
    evidence: AssessmentEvidenceRef,
    workflow_notes: list[str],
) -> dict[str, Any] | None:
    if status in {ApplicabilityStatus.APPLICABLE, ApplicabilityStatus.NOT_APPLICABLE}:
        return None
    category = _finding_category(status)
    finding_status = _finding_status(status)
    summary = "; ".join(workflow_notes) or f"{pack.id} is {status.value} in {mode.value} mode."
    return {
        "finding_id": _finding_id(profile=profile, pack_id=pack.id, status=status),
        "pack_id": pack.id,
        "case_id": f"{pack.id}:assessment-coverage",
        "severity": "info",
        "category": category,
        "technique": pack.title,
        "surface": _finding_surface(pack.id),
        "profile": profile,
        "status": finding_status,
        "owner": "unassigned",
        "title": f"{pack.title} {category.replace('_', ' ')}",
        "summary": summary,
        "redacted_preview": f"[REDACTED evidence sha256={evidence.sha256[:16]} length={evidence.source_length}] {category} for {pack.id} {status.value}",
        "impact": "Assessment coverage is incomplete; this is not a model security failure.",
        "likelihood": "unknown",
        "confidence": "medium",
        "remediation": _finding_remediation(status, pack),
        "evidence_refs": [evidence],
        "remediation_ref": "remediation/remediation-board.md",
        "regression": {
            "pack_id": pack.id,
            "expected_fixed_behavior": f"{pack.id} has reviewed executable evidence or an explicit accepted gap disposition.",
            "replay_mode": "provider_free_required",
            "replay_command_ref": "regression/replay-commands.md",
            "tags": [category, pack.id, status.value, mode.value],
        },
    }


def _write_raw_pack_artifact(
    *,
    out_dir: Path,
    pack: AssessmentPack,
    mode: AssessmentMode,
    status: ApplicabilityStatus,
    evidence_strength: EvidenceStrength,
    generated_at: str,
    target_config_hash: str,
    filters: dict[str, Any],
    workflow_notes: list[str],
    caveats: list[str],
) -> AssessmentEvidenceRef:
    relative_path = f"raw/{pack.id}/planning-metadata.json"
    payload = {
        "schema_version": "malleus.assessment_raw_pack.v1",
        "generated_at": generated_at,
        "pack": {
            "id": pack.id,
            "title": pack.title,
            "description": pack.description,
            "tier": pack.tier.value,
            "maturity": pack.maturity.value,
            "applicable_profiles": pack.applicable_profiles,
            "surfaces": pack.surfaces,
            "techniques": pack.techniques,
            "required_inputs": pack.required_inputs,
            "expected_artifacts": pack.expected_artifacts,
            "scoring_dimensions": pack.scoring_dimensions,
            "finding_categories": pack.finding_categories,
            "remediation_themes": pack.remediation_themes,
            "supported_modes": [supported_mode.value for supported_mode in pack.supported_modes],
            "primary_score_evidence": _public_primary_score_evidence(pack, mode),
        },
        "mode": mode.value,
        "status": status.value,
        "evidence_strength": evidence_strength.value,
        "target_config_hash": target_config_hash,
        "filters": filters,
        "workflow_notes": workflow_notes,
        "caveats": caveats,
        "provider_calls_enabled": PROVIDER_CALLS_ENABLED,
        "network_enabled": NETWORK_ENABLED,
        "provider_calls_made": False,
    }
    artifact_bytes = _json_bytes(payload)
    artifact_path = out_dir / relative_path
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_bytes(artifact_bytes)
    artifact_hash = _sha256_bytes(artifact_bytes)
    return AssessmentEvidenceRef(
        evidence_id=f"ev-{pack.id}-planning",
        artifact_path=relative_path,
        artifact_type="provider_free_pack_metadata",
        sha256=artifact_hash,
        source_length=len(artifact_bytes),
        redacted_length=len(artifact_bytes),
        redacted_preview=f"pack {pack.id} {status.value} {evidence_strength.value} [REDACTED evidence sha256={artifact_hash[:16]} length={len(artifact_bytes)}]",
        metadata={"pack_id": pack.id, "mode": mode.value, "status": status.value, "evidence_strength": evidence_strength.value},
    )


def run_assessment(
    *,
    target_path: Path,
    profile: str,
    packs: list[str],
    mode: str,
    out_dir: Path,
    compare_targets: list[Path],
    regression_pack: Path | None,
    policy_path: Path | None,
    baseline_path: Path | None,
    include_experimental: bool,
    limit: int | None,
    case_ids: list[str],
    allow_live_provider: bool,
    provider_calls_enabled: bool,
) -> dict[str, Any]:
    """Run provider-free assessment pack orchestration and write canonical reports."""

    target = load_target_config(target_path)
    assessment_mode = AssessmentMode(mode)
    catalog = load_assessment_catalog()
    selected_packs = _expanded_packs(profile, packs)
    provider_calls_requested = bool(provider_calls_enabled)
    provider_calls_enabled = PROVIDER_CALLS_ENABLED
    mode_caveats = _mode_caveats(assessment_mode)

    out_dir.mkdir(parents=True, exist_ok=True)
    for directory in CANONICAL_ASSESSMENT_DIRS:
        (out_dir / directory).mkdir(exist_ok=True)

    generated_at = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    run_id = f"assessment-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{uuid4().hex[:8]}"
    target_config_hash = _target_config_hash(target)
    filters = {
        "include_experimental": include_experimental,
        "limit": limit,
        "case_filter_hashes": _case_filter_hashes(case_ids),
    }

    pack_results: list[AssessmentPackResult] = []
    evidence_refs: list[AssessmentEvidenceRef] = []
    coverage: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    pack_artifact_refs: dict[str, str] = {}

    for pack in selected_packs:
        status = _status_for_mode(
            profile=profile,
            pack=pack,
            mode=assessment_mode,
            compare_targets=compare_targets,
            catalog=catalog,
        )
        evidence_strength = _evidence_strength_for_mode(pack, assessment_mode, status)
        workflow_notes = _workflow_notes(status, assessment_mode)
        evidence = _write_raw_pack_artifact(
            out_dir=out_dir,
            pack=pack,
            mode=assessment_mode,
            status=status,
            evidence_strength=evidence_strength,
            generated_at=generated_at,
            target_config_hash=target_config_hash,
            filters=filters,
            workflow_notes=workflow_notes,
            caveats=mode_caveats,
        )
        evidence_refs.append(evidence)
        pack_artifact_refs[pack.id] = evidence.artifact_path
        coverage.append(_coverage_row(pack, AssessmentPackResult(pack_id=pack.id, category=_pack_category(pack), status=status, evidence_strength=evidence_strength), evidence))
        finding = _normalized_finding(profile=profile, mode=assessment_mode, pack=pack, status=status, evidence=evidence, workflow_notes=workflow_notes)
        if finding is not None:
            findings.append(finding)
        pack_results.append(
            AssessmentPackResult(
                pack_id=pack.id,
                category=_pack_category(pack),
                status=status,
                score_inclusion=pack.default_score_inclusion,
                evidence_strength=evidence_strength,
                score=None,
                max_score=None,
                findings=[],
                workflow_errors=mode_caveats if assessment_mode is AssessmentMode.LIVE_PROVIDER else ([] if status is not ApplicabilityStatus.PROVIDER_ERROR else workflow_notes),
                ref=evidence.artifact_path,
            )
        )

    scores = compute_assessment_scores(profile=profile, pack_results=pack_results, catalog=catalog)
    packs_for_report = []
    for pack, result in zip(selected_packs, pack_results, strict=True):
        declaration = scores.pack_score_uses[pack.id]
        packs_for_report.append(
            {
                "id": pack.id,
                "title": pack.title,
                "description": pack.description,
                "tier": pack.tier.value,
                "maturity": pack.maturity.value,
                "applicable_profiles": pack.applicable_profiles,
                "surfaces": pack.surfaces,
                "techniques": pack.techniques,
                "required_inputs": pack.required_inputs,
                "expected_artifacts": pack.expected_artifacts,
                "scoring_dimensions": pack.scoring_dimensions,
                "finding_categories": pack.finding_categories,
                "remediation_themes": pack.remediation_themes,
                "score_use": _score_use_label(result, declaration.score_use),
                "applicability": result.status.value,
                "mode": assessment_mode.value,
                "evidence_strengths": [result.evidence_strength.value],
                "primary_score_evidence": _public_primary_score_evidence(pack, assessment_mode),
                "score": {
                    **_pack_score(result),
                    "score_declaration": declaration.model_dump(mode="json"),
                    "raw_ref": pack_artifact_refs[pack.id],
                    "caveats": mode_caveats,
                },
            }
        )

    score_payload = scores.model_dump(mode="json")
    score_payload["evidence_mix"] = {strength: count for strength, count in score_payload.get("evidence_mix", {}).items() if count}
    report_input = AssessmentReportInput(
        assessment_id=run_id,
        generated_at=generated_at,
        target={"name": target.name, "adapter": target.adapter, "base_url": target.base_url},
        provider={"name": target.adapter, "model": target.model, "config_hash": target_config_hash},
        profile=profile,
        mode=assessment_mode.value,
        packs=packs_for_report,
        scores=score_payload,
        findings=findings,
        coverage=coverage,
        evidence_refs=evidence_refs,
        gate={"status": scores.posture, "reasons": ["provider-free assessment generated normalized pack planning artifacts", *mode_caveats], "policy": "default"},
        remediation_refs=[{"finding_id": finding["finding_id"], "path": finding["remediation_ref"]} for finding in findings],
        regression_refs=[{"pack_id": finding["pack_id"], "path": "regression/regression-pack.yaml", "case_ids": [finding["case_id"]]} for finding in findings],
        metadata={
            "target_config": {
                "path": _safe_manifest_path(target_path),
                "sha256": _file_sha256(target_path),
                "config_hash": target_config_hash,
            },
            "requested_packs": packs,
            "expanded_packs": [pack.id for pack in selected_packs],
            "profile": profile,
            "mode": assessment_mode.value,
            "command_summary": {
                "entrypoint": "malleus assess",
                "target": _safe_manifest_path(target_path),
                "profile": profile,
                "packs": packs,
                "expanded_packs": [pack.id for pack in selected_packs],
                "mode": assessment_mode.value,
                "include_experimental": include_experimental,
                "limit": limit,
                "case_filter_count": len(case_ids),
                "compare_target_count": len(compare_targets),
                "allow_live_provider": allow_live_provider,
            },
            "provider_calls_enabled": PROVIDER_CALLS_ENABLED,
            "network_enabled": NETWORK_ENABLED,
            "browser_enabled": False,
            "provider_calls_requested": provider_calls_requested,
            "allow_live_provider": allow_live_provider,
            "caveats": mode_caveats,
            "compare_target_count": len(compare_targets),
            "git_commit": _git_commit(),
            "schema_versions": {
                "manifest": ASSESSMENT_MANIFEST_SCHEMA_VERSION,
                "raw_pack": "malleus.assessment_raw_pack.v1",
            },
            "raw_artifact_mapping": "raw/<pack-id>/planning-metadata.json is the PRD-compatible per-workflow artifact layout for selected assessment packs",
            "remediation_patch_mapping": "remediation/patches/README.md documents the safe no-op patch scaffold; executable patches are not auto-generated",
            "optional_inputs": {
                "regression_pack": _optional_path(regression_pack),
                "policy_path": _optional_path(policy_path),
                "baseline_path": _optional_path(baseline_path),
                "regression_pack_configured": regression_pack is not None,
                "policy_configured": policy_path is not None,
                "baseline_configured": baseline_path is not None,
            },
        },
    )
    report_result = write_assessment_reports(report_input, out_dir)
    _augment_manifest_guardrails(report_result.manifest_path, caveats=mode_caveats, posture=score_payload["posture"])
    risk_report = json.loads(report_result.risk_report_path.read_text(encoding="utf-8"))
    comparison_result = write_model_comparison_artifacts(
        out_dir=out_dir,
        risk_report=risk_report,
        target_path=target_path,
        compare_targets=compare_targets,
    )
    gate_result = write_assessment_gate_artifacts(
        out_dir=out_dir,
        risk_report=risk_report,
        policy_path=policy_path,
        baseline_path=baseline_path,
    )

    return {
        "run_id": run_id,
        "mode": assessment_mode.value,
        "manifest_path": str(report_result.manifest_path),
        "risk_report_path": str(report_result.risk_report_path),
        "summary_path": str(out_dir / "executive-summary.md"),
        "output_dir": str(out_dir),
        "provider_calls_enabled": PROVIDER_CALLS_ENABLED,
        "network_enabled": NETWORK_ENABLED,
        "provider_calls_requested": provider_calls_requested,
        "caveats": mode_caveats,
        "live_provider_fail_closed": assessment_mode is AssessmentMode.LIVE_PROVIDER,
        "expanded_packs": [pack.id for pack in selected_packs],
        "raw_refs": pack_artifact_refs,
        "findings": [finding["finding_id"] for finding in findings],
        "scores": score_payload,
        "assessment_gate": {
            "status": gate_result.status,
            "ci_exit_code": gate_result.ci_exit_code,
            "summary_path": str(gate_result.json_path),
            "markdown_path": str(gate_result.markdown_path),
            "sarif_path": str(gate_result.sarif_path),
            "junit_path": str(gate_result.junit_path),
        },
        "model_comparison": None
        if comparison_result is None
        else {
            "comparison_path": str(comparison_result.json_path),
            "summary_path": str(comparison_result.summary_path),
            "leaderboard_path": str(comparison_result.leaderboard_path),
            "strengths_path": str(comparison_result.strengths_path),
            "shared_failures_path": str(comparison_result.shared_failures_path),
            "risks_path": str(comparison_result.risks_path),
        },
        "optional_inputs": {
            "regression_pack": _optional_path(regression_pack),
            "policy_path": _optional_path(policy_path),
            "baseline_path": _optional_path(baseline_path),
        },
    }
