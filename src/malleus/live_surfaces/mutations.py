from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Any, Callable

from malleus.ir import ArtifactRef
from malleus.live_evidence import LiveEvidenceRow, LiveEvidenceStatus, LiveTargetMetadata
from malleus.live_preflight import LivePreflightReport
from malleus.live_surfaces.common import public_path, safe_output_segment, sanitize_metadata
from malleus.resources import resource_path
from malleus.schemas import MutationProfile, MutationRunReport, ReleaseMatrix, ReleaseMatrixMutationProfileRef, ReleaseMatrixPackRef
from malleus.surface_names import public_profile_name
from malleus.utils.redact import redact_public_text


DEFAULT_CLASSIC_SCORING_PATH = resource_path("configs/scoring-default.yaml")


def run_mutation_profile_row(
    profile: MutationProfile,
    profile_ref: ReleaseMatrixMutationProfileRef | None,
    *,
    run_id: str,
    timestamp: str,
    command: str,
    target: LiveTargetMetadata,
    target_path: str | Path,
    matrix: ReleaseMatrix,
    matrix_path: str | Path,
    out_dir: str | Path,
    preflight: LivePreflightReport,
    run_mutation_benchmark_fn: Callable[..., Any],
    matrix_reference_path_fn: Callable[[str | Path, Path], Path],
    sha256_file_fn: Callable[[Path], str],
) -> LiveEvidenceRow:
    mutation_input = mutation_input_pack(matrix)
    if mutation_input is None:
        return mutation_operational_row(
            profile,
            profile_ref,
            run_id=run_id,
            timestamp=timestamp,
            command=command,
            target=target,
            status="infra_error",
            reason=f"mutation profile {profile.id} has no live text input pack in the release matrix",
            metadata={"preflight_text_status": preflight.text_status},
        )

    profile_output_id = safe_output_segment(profile.id)
    profile_out = Path(out_dir) / "mutations" / profile_output_id
    input_path = matrix_reference_path_fn(mutation_input.path, Path(matrix_path).resolve())
    scoring_path = (Path.cwd() / DEFAULT_CLASSIC_SCORING_PATH).resolve()
    public_input_path = public_path(mutation_input.path)
    public_profile_path = profile_public_path(profile, profile_ref) or profile.id
    mutation_command = f"{command} # mutation profile {profile.id} via malleus mutate-run --input {shlex.quote(public_input_path)} --mutation-profile {shlex.quote(public_profile_path)}"

    try:
        runner_report = run_mutation_benchmark_fn(
            target_path,
            input_path,
            scoring_path,
            profile_out,
            mutations=list(profile.mutations),
            dry_run=False,
            continue_on_provider_error=True,
            provider_min_delay=0.25,
        )
    except Exception as exc:
        return mutation_operational_row(
            profile,
            profile_ref,
            run_id=run_id,
            timestamp=timestamp,
            command=mutation_command,
            target=target,
            status="provider_error",
            reason=f"mutation profile {profile.id} failed during provider execution: {type(exc).__name__}: {exc}",
            metadata={"input_pack_id": mutation_input.id, "input_path": public_input_path, "output_dir": f"mutations/{profile_output_id}", "profile_output_id": profile_output_id, "runner_error_type": type(exc).__name__, "preflight_text_status": preflight.text_status},
        )

    report_path = profile_out / "mutation-report.json"
    dry_run_path = profile_out / "mutation-dry-run.json"
    invalid_live_artifact = dry_run_path.exists() or runner_report.report_mode == "dry_run"
    if not report_path.exists() or invalid_live_artifact:
        return mutation_operational_row(
            profile,
            profile_ref,
            run_id=run_id,
            timestamp=timestamp,
            command=mutation_command,
            target=target,
            status="infra_error",
            reason=f"mutation profile {profile.id} did not produce a valid live mutation-report.json artifact" + ("; dry-run artifacts cannot satisfy live-full evidence" if invalid_live_artifact else ""),
            metadata={"input_pack_id": mutation_input.id, "input_path": public_input_path, "output_dir": f"mutations/{profile_output_id}", "profile_output_id": profile_output_id, "mutation_report_json_exists": report_path.exists(), "mutation_dry_run_json_exists": dry_run_path.exists(), "runner_report_mode": runner_report.report_mode, "invalid_live_artifact": invalid_live_artifact, "preflight_text_status": preflight.text_status},
        )

    report = MutationRunReport.model_validate(json.loads(report_path.read_text(encoding="utf-8")))
    if report.report_mode == "dry_run" or report.metadata.get("provider_calls_enabled") is False:
        return mutation_operational_row(
            profile,
            profile_ref,
            run_id=run_id,
            timestamp=timestamp,
            command=mutation_command,
            target=target,
            status="infra_error",
            reason=f"mutation profile {profile.id} report was not live-provider evidence; dry-run or provider-disabled artifacts cannot satisfy live-full evidence",
            metadata={"input_pack_id": mutation_input.id, "input_path": public_input_path, "output_dir": f"mutations/{profile_output_id}", "profile_output_id": profile_output_id, "report_mode": report.report_mode, "provider_calls_enabled": report.metadata.get("provider_calls_enabled"), "invalid_live_artifact": True, "preflight_text_status": preflight.text_status},
        )

    report = sanitize_mutation_report(report, target_path=target_path, input_path=public_input_path, scoring_path=DEFAULT_CLASSIC_SCORING_PATH)
    report_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    attempted_provider_calls = int(report.metadata.get("attempted_provider_calls") or (report.summary.total_original_items + report.summary.total_mutated_items))
    provider_error_count = int(report.metadata.get("provider_error_count") or 0)
    live_calls = attempted_provider_calls
    if provider_error_count and report.summary.total_mutated_items == 0:
        status = "provider_error"
    else:
        status = "passed" if report.summary.regression_count == 0 and report.summary.negative_delta_count == 0 and provider_error_count == 0 else "failed"
    reason = None
    if provider_error_count:
        reason = f"mutation profile {profile.id} completed partial live evidence with {provider_error_count} provider errors"
    return LiveEvidenceRow(
        row_id=f"mutation-profile:{profile.id}",
        run_id=run_id,
        case_id=profile.id,
        surface_id=f"mutation-profile:{profile.id}",
        timestamp=timestamp,
        command=mutation_command,
        git_commit="unknown",
        target=target,
        status=status,
        evidence_level="live_text_model",
        dry_run=False,
        provider_calls_enabled=True,
        live_model_calls=live_calls,
        reason=redact_public_text(reason).text if reason else None,
        artifacts=mutation_artifact_refs(profile_out, sha256_file_fn=sha256_file_fn),
        metadata=sanitize_metadata(
            {
                **profile_metadata(profile, profile_ref),
                "input_pack_id": mutation_input.id,
                "input_path": public_input_path,
                "output_dir": f"mutations/{profile_output_id}",
                "profile_output_id": profile_output_id,
                "runner_run_id": report.run_id,
                "adapter_call_count": live_calls,
                "provider_error": status == "provider_error",
                "original_items": report.summary.total_original_items,
                "mutated_items": report.summary.total_mutated_items,
                "planned_mutated_items": report.metadata.get("planned_mutated_items"),
                "completed_mutated_items": report.metadata.get("completed_mutated_items"),
                "provider_error_count": provider_error_count,
                "provider_error_examples": report.metadata.get("provider_errors", [])[:3],
                "regression_count": report.summary.regression_count,
                "negative_delta_count": report.summary.negative_delta_count,
                "worst_delta": report.summary.worst_delta,
                "worst_mutation": report.summary.worst_mutation,
                "report_json": f"mutations/{profile_output_id}/mutation-report.json",
                "preflight_text_status": preflight.text_status,
            }
        ),
    )


def mutation_operational_row(
    profile: MutationProfile,
    profile_ref: ReleaseMatrixMutationProfileRef | None,
    *,
    run_id: str,
    timestamp: str,
    command: str,
    target: LiveTargetMetadata,
    status: LiveEvidenceStatus,
    reason: str,
    metadata: dict[str, Any],
) -> LiveEvidenceRow:
    return LiveEvidenceRow(
        row_id=f"mutation-profile:{profile.id}",
        run_id=run_id,
        case_id=profile.id,
        surface_id=f"mutation-profile:{profile.id}",
        timestamp=timestamp,
        command=command,
        git_commit="unknown",
        target=target,
        status=status,
        evidence_level="live_text_model",
        dry_run=False,
        provider_calls_enabled=True,
        live_model_calls=0,
        reason=redact_public_text(reason).text,
        metadata=sanitize_metadata({**profile_metadata(profile, profile_ref), **metadata, "provider_error": status in {"provider_error", "timeout", "infra_error"}, "model_behavior_failure": False}),
    )


def profile_metadata(profile: MutationProfile, profile_ref: ReleaseMatrixMutationProfileRef | None) -> dict[str, Any]:
    return {
        "profile_name": profile_display_name(profile, profile_ref),
        "path": profile_public_path(profile, profile_ref),
        "mutation_count": len(profile.mutations),
        "deep": profile.deep,
        "optional": profile.optional,
        "matrix_status": profile_ref.status if profile_ref else None,
        "matrix_evidence_level": profile_ref.evidence_level if profile_ref else None,
    }


def profile_display_name(profile: MutationProfile, profile_ref: ReleaseMatrixMutationProfileRef | None = None) -> str:
    if profile_ref is not None and profile_ref.profile_name.strip():
        return profile_ref.profile_name.strip()
    return public_profile_name(profile.id, fallback=profile.name)


def mutation_input_pack(matrix: ReleaseMatrix) -> ReleaseMatrixPackRef | None:
    for pack in canonical_live_packs(matrix):
        if pack.id == "smoke-v1" and pack.live_model_evidence and not pack.scaffold_only:
            return pack
    for pack in canonical_live_packs(matrix):
        if pack.live_model_evidence and not pack.scaffold_only:
            return pack
    return None


def sanitize_mutation_report(report: MutationRunReport, *, target_path: str | Path, input_path: str, scoring_path: str | Path) -> MutationRunReport:
    metadata = sanitize_metadata({**report.metadata, "target_path": public_path(target_path)})
    return report.model_copy(
        update={
            "target_name": redact_public_text(report.target_name).text,
            "target_model": redact_public_text(report.target_model).text,
            "input_path": input_path,
            "scoring_path": public_path(scoring_path),
            "metadata": metadata,
        },
        deep=True,
    )


def mutation_artifact_refs(output_dir: Path, *, sha256_file_fn: Callable[[Path], str]) -> list[ArtifactRef]:
    refs: list[ArtifactRef] = []
    artifact_types = {"mutation-report.json": "mutation_report_json", "mutation-report.md": "mutation_report_markdown"}
    for name, artifact_type in artifact_types.items():
        path = output_dir / name
        if not path.exists():
            continue
        refs.append(
            ArtifactRef(
                path=name,
                kind=path.suffix.lstrip(".") or "artifact",
                artifact_type=artifact_type,
                sha256=sha256_file_fn(path),
                relative_path=name,
                redaction_status="redacted",
            )
        )
    return refs


def profile_public_path(profile: MutationProfile, profile_ref: ReleaseMatrixMutationProfileRef | None) -> str | None:
    if profile_ref is not None:
        return sanitize_metadata(public_path(profile_ref.path))
    if profile.source_path is None:
        return None
    return sanitize_metadata(public_path(profile.source_path))


def canonical_live_packs(matrix: ReleaseMatrix) -> list[ReleaseMatrixPackRef]:
    return [pack for pack in matrix.packs if pack.id != "ui-browser-scaffold-v1"]
