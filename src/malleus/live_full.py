from __future__ import annotations

import shlex
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any
import yaml

from malleus.agent_lab.runner import run_agent_lab
from malleus.agent_lab.schemas import AgentLabReport, AgentScenarioResult
from malleus.auto_system_wrappers import auto_system_wrapper, can_auto_wrap
from malleus.browser_agent_harness import BrowserAgentReport, run_browser_agent_harness
from malleus.campaign_live import CampaignLiveReport, run_campaign_live
from malleus.challenge_live import ChallengeLiveReport, run_challenge_live
from malleus.datasets import load_mutation_profile, load_release_matrix, load_target_config
from malleus.hidden_artifact_live import HiddenArtifactLiveReport, run_hidden_artifact_live
from malleus.ir import ArtifactRef
from malleus.code_agent_harness import CodeAgentHarnessReport, run_code_agent_harness
from malleus.live_evidence import LiveEvidenceMatrix, LiveEvidenceRow, LiveEvidenceStatus, LiveSurfaceRecord, LiveTargetMetadata
from malleus.live_preflight import LivePreflightReport, run_target_preflight, safe_endpoint_from_url
from malleus.live_surfaces.checkpointing import (
    atomic_write_checkpoint_text,
    matrix_with_rows,
    render_live_full_checkpoint_markdown,
    write_live_full_checkpoint,
)
from malleus.live_surfaces.common import matrix_reference_path, now_iso, public_path, safe_output_segment, sanitize_metadata, slug
from malleus.live_surfaces.mode_markers import write_exterminatus_mode_marker, write_soft_mode_marker
from malleus.live_surfaces.fixture_mutations import build_mutated_surface_fixtures
from malleus.live_surfaces.mutations import (
    canonical_live_packs,
    mutation_artifact_refs,
    mutation_input_pack,
    mutation_operational_row,
    profile_display_name,
    profile_metadata,
    profile_public_path,
    run_mutation_profile_row,
    sanitize_mutation_report,
)
from malleus.live_surfaces.progress import LiveProgressCallback, emit_progress as _emit_progress, emit_system_harness_progress
from malleus.live_surfaces.reporting import (
    aggregate_matrix_payload,
    final_preflight_status_label,
    final_report_text,
    human_surface_name,
    invalid_live_artifact_rows,
    is_live_model_behavior_failure,
    model_failure_rows,
    model_failure_triage_payload,
    provider_error_rows,
    render_command_log_markdown,
    render_full_matrix_markdown,
    render_full_summary_markdown,
    render_live_full_markdown,
    render_model_failure_triage_markdown,
    render_model_failures_markdown,
    render_provider_errors_markdown,
    render_server_diagnostics_markdown,
    row_agent_trace_summary,
    row_target_type,
    write_full_benchmark_reports,
)
from malleus.live_surfaces.self_modification import (
    SELF_MODIFICATION_LIVE_PACK_IDS,
    SELF_MODIFICATION_TARGET_TYPES,
    write_self_modification_memory_fixture,
    write_self_modification_multi_agent_fixture,
    write_self_modification_tool_agent_fixture,
    write_self_modification_workflow_fixture,
)
from malleus.live_surfaces.system import nonnegative_int, system_report_live_model_calls, system_summary_reason, system_summary_status
from malleus.memory_agent_harness import MemoryAgentReport, run_memory_agent_harness
from malleus.multi_agent_harness import MultiAgentReport, run_multi_agent_harness
from malleus.mutate_run import run_mutation_benchmark
from malleus.rag_harness import RagLiveReport, run_rag_live
from malleus.rag_service_harness import RagServiceReport, run_rag_service_harness
from malleus.resources import resource_path
from malleus.runner import run_benchmark
from malleus.tool_agent_harness import ToolAgentReport, run_tool_agent_harness
from malleus.schemas import MutationProfile, ReleaseMatrix, ReleaseMatrixMutationProfileRef, ReleaseMatrixPackRef, TargetConfig
from malleus.stack_coverage import build_stack_coverage_from_live_matrix, write_stack_coverage_report
from malleus.ui_action_live import UIActionLiveReport, run_ui_action_live
from malleus.utils.redact import redact_public_text
from malleus.visual_live import VisualLiveReport, run_visual_live
from malleus.workflow_harness import WorkflowHarnessReport, run_workflow_harness


LIVE_FULL_PLAN_SCHEMA_VERSION = "malleus.live_full_plan.v1"
DEFAULT_RELEASE_MATRIX_PATH = resource_path("datasets/release_matrices/malleus-v0.1.yaml")
DEFAULT_SELECTED_MUTATION_PROFILE_PATH = resource_path("datasets/mutation_profiles/selected-v1.yaml")
DEFAULT_DEEP_MUTATION_PROFILE_PATH = resource_path("datasets/mutation_profiles/deep-v1.yaml")
CLASSIC_LIVE_PACK_IDS = {"smoke-v1", "core-v1", "calibration-v1"}
CHALLENGE_LIVE_PACK_IDS = {"challenge-v1"}
AGENTIC_LIVE_PACK_IDS = {"agentic-injection-v1"}
RAG_LIVE_PACK_IDS = {"rag-v1"}
HIDDEN_ARTIFACT_LIVE_PACK_IDS = {"artifact-hidden-channel-v1"}
UI_ACTION_LIVE_PACK_IDS: set[str] = set()
CAMPAIGN_LIVE_PACK_IDS = {"campaign-v1"}
VISUAL_LIVE_PACK_IDS = {"visual-ocr-matrix"}
DEFAULT_CLASSIC_SCORING_PATH = resource_path("configs/scoring-default.yaml")


def run_live_full_matrix(
    *,
    target_path: str | Path | TargetConfig,
    matrix_path: str | Path,
    mutation_profile_path: str | Path,
    out_dir: str | Path,
    dry_run: bool,
    include_deep_mutations: bool = False,
    deep_mutation_profile_path: str | Path | None = None,
    yes: bool = False,
    concurrency: int = 1,
    request_timeout: float = 120.0,
    max_retries: int = 1,
    benchmark_mode: str = "live-full",
    progress_callback: LiveProgressCallback | None = None,
) -> tuple[LiveEvidenceMatrix, Path, Path]:
    """Build the strict live-full evidence matrix."""

    if benchmark_mode not in {"live-full", "soft", "exterminatus"}:
        raise ValueError("benchmark_mode must be 'live-full', 'soft', or 'exterminatus'")
    if dry_run:
        raise ValueError("malleus benchmark live-full requires explicit --no-dry-run; dry-run cannot be full-live evidence")
    if concurrency < 1:
        raise ValueError("concurrency must be >= 1")
    if request_timeout <= 0:
        raise ValueError("request-timeout must be > 0")
    if max_retries < 0:
        raise ValueError("max-retries must be >= 0")
    target = load_target_config(target_path)
    matrix = load_release_matrix(matrix_path)
    selected_profile = load_mutation_profile(mutation_profile_path)
    deep_profile = _load_deep_profile(matrix, matrix_path, deep_mutation_profile_path)
    _validate_profile_selection(matrix, selected_profile, deep_profile, include_deep_mutations)

    _emit_progress(progress_callback, event="preflight_start", benchmark_mode=benchmark_mode, target=target.name, model=target.model or str(target.target_type), out_dir=str(out_dir))
    preflight = _preflight_for_target(target, include_image_probe=True, timeout=request_timeout, max_retries=max_retries)
    _emit_progress(
        progress_callback,
        event="preflight_end",
        benchmark_mode=benchmark_mode,
        text_status=preflight.text_status,
        visual_status=preflight.visual_status,
        text_ready=preflight.text_ready,
        visual_ready=preflight.visual_status == "passed",
    )
    evidence = build_live_full_matrix(
        target_path=target_path,
        matrix_path=matrix_path,
        out_dir=out_dir,
        target=target,
        matrix=matrix,
        selected_profile=selected_profile,
        deep_profile=deep_profile,
        preflight=preflight,
        include_deep_mutations=include_deep_mutations,
        yes=yes,
        concurrency=concurrency,
        request_timeout=request_timeout,
        max_retries=max_retries,
        benchmark_mode=benchmark_mode,
        progress_callback=progress_callback,
        command=_command_text(
            target_path=target_path,
            matrix_path=matrix_path,
            mutation_profile_path=mutation_profile_path,
            out_dir=out_dir,
            include_deep_mutations=include_deep_mutations,
            deep_mutation_profile_path=deep_mutation_profile_path,
            yes=yes,
            concurrency=concurrency,
            request_timeout=request_timeout,
            max_retries=max_retries,
            benchmark_mode=benchmark_mode,
        ),
    )
    result = write_live_full_matrix(evidence, out_dir)
    invalid_rows = _invalid_live_artifact_rows(evidence)
    if invalid_rows:
        joined = ", ".join(row.row_id for row in invalid_rows)
        raise ValueError(f"classic live-full detected dry-run/non-live artifacts for rows: {joined}")
    return result


def run_soft_benchmark(
    *,
    target_path: str | Path | TargetConfig,
    out_dir: str | Path,
    yes: bool,
    matrix_path: str | Path = DEFAULT_RELEASE_MATRIX_PATH,
    mutation_profile_path: str | Path = DEFAULT_SELECTED_MUTATION_PROFILE_PATH,
    concurrency: int = 1,
    request_timeout: float = 120.0,
    max_retries: int = 1,
    progress_callback: LiveProgressCallback | None = None,
) -> tuple[LiveEvidenceMatrix, Path, Path]:
    """Run the default-friendly serious live benchmark wrapper."""

    return run_live_full_matrix(
        target_path=target_path,
        matrix_path=matrix_path,
        mutation_profile_path=mutation_profile_path,
        out_dir=out_dir,
        dry_run=False,
        include_deep_mutations=False,
        deep_mutation_profile_path=None,
        yes=yes,
        concurrency=concurrency,
        request_timeout=request_timeout,
        max_retries=max_retries,
        benchmark_mode="soft",
        progress_callback=progress_callback,
    )


def run_exterminatus_benchmark(
    *,
    target_path: str | Path | TargetConfig,
    out_dir: str | Path,
    yes: bool,
    matrix_path: str | Path = DEFAULT_RELEASE_MATRIX_PATH,
    mutation_profile_path: str | Path = DEFAULT_SELECTED_MUTATION_PROFILE_PATH,
    deep_mutation_profile_path: str | Path = DEFAULT_DEEP_MUTATION_PROFILE_PATH,
    concurrency: int = 1,
    request_timeout: float = 120.0,
    max_retries: int = 1,
    progress_callback: LiveProgressCallback | None = None,
) -> tuple[LiveEvidenceMatrix, Path, Path]:
    """Run the expanded live benchmark wrapper with selected and deep mutations."""

    return run_live_full_matrix(
        target_path=target_path,
        matrix_path=matrix_path,
        mutation_profile_path=mutation_profile_path,
        out_dir=out_dir,
        dry_run=False,
        include_deep_mutations=True,
        deep_mutation_profile_path=deep_mutation_profile_path,
        yes=yes,
        concurrency=concurrency,
        request_timeout=request_timeout,
        max_retries=max_retries,
        benchmark_mode="exterminatus",
        progress_callback=progress_callback,
    )


def run_live_surface_pack(
    *,
    target_path: str | Path,
    pack_id: str,
    out_dir: str | Path,
    matrix_path: str | Path = DEFAULT_RELEASE_MATRIX_PATH,
    yes: bool = False,
    request_timeout: float = 120.0,
    max_retries: int = 1,
    progress_callback: LiveProgressCallback | None = None,
    mutation_profile_path: str | Path | None = None,
    mutation_limit: int | None = None,
) -> tuple[LiveEvidenceMatrix, Path, Path]:
    """Run one canonical live surface through the same routing used by live-full."""

    if request_timeout <= 0:
        raise ValueError("request-timeout must be > 0")
    if max_retries < 0:
        raise ValueError("max-retries must be >= 0")
    target_config = load_target_config(target_path)
    matrix = load_release_matrix(matrix_path)
    packs = {pack.id: pack for pack in _canonical_live_packs(matrix)}
    if pack_id not in packs:
        raise ValueError(f"unknown or non-canonical live surface: {pack_id}")
    generated_at = _now()
    target_name = redact_public_text(target_config.name).text
    target_model = redact_public_text(target_config.model or str(target_config.target_type)).text
    run_id = f"live-surface-{_slug(pack_id)}-{_slug(target_name)}-{generated_at.replace(':', '').replace('+', 'z')}"
    command = redact_public_text(f"malleus benchmark live-surface --surface {pack_id} --target {target_path} --matrix {matrix_path} --out-dir {out_dir}").text
    _emit_progress(progress_callback, event="preflight_start", benchmark_mode="live-surface", target=target_name, model=target_model, out_dir=str(out_dir))
    preflight = _preflight_for_target(target_config, include_image_probe=True, timeout=request_timeout, max_retries=max_retries)
    _emit_progress(
        progress_callback,
        event="preflight_end",
        benchmark_mode="live-surface",
        text_status=preflight.text_status,
        visual_status=preflight.visual_status,
        text_ready=preflight.text_ready,
        visual_ready=preflight.visual_status == "passed",
    )
    target_metadata = LiveTargetMetadata(
        name=target_name,
        adapter=str(target_config.adapter or target_config.target_type),
        model=target_model,
        base_url=safe_endpoint_from_url(_target_endpoint_url(target_config)).label,
        metadata=_sanitize_metadata({**target_config.metadata, "target_type": str(target_config.target_type)}),
    )
    row_jobs: list[tuple[str, ReleaseMatrixPackRef, Path, dict[str, Any]]] = [("baseline", packs[pack_id], Path(matrix_path).resolve(), {})]
    if mutation_profile_path is not None:
        profile = load_mutation_profile(mutation_profile_path)
        fixture_path = _matrix_reference_path(packs[pack_id].path, Path(matrix_path).resolve())
        mutated = build_mutated_surface_fixtures(
            pack_id=pack_id,
            fixture_path=fixture_path,
            output_dir=Path(out_dir) / "surface-mutations" / safe_output_segment(pack_id) / safe_output_segment(profile.id),
            mutations=list(profile.mutations),
            limit=mutation_limit,
        )
        for item in mutated:
            mutated_pack = packs[pack_id].model_copy(update={"path": str(item.path)})
            mutation_matrix = _write_single_pack_matrix_override(matrix, packs[pack_id], item.path, Path(out_dir), profile_id=profile.id, mutation=item.mutation)
            row_jobs.append(
                (
                    f"mutation:{item.mutation}",
                    mutated_pack,
                    mutation_matrix,
                    {
                        "surface_mutation": True,
                        "mutation_profile": profile.id,
                        "mutation": item.mutation,
                        "mutated_fixture_path": _public_path(item.path),
                        "mutated_fields": list(item.mutated_fields),
                    },
                )
            )
    rows: list[LiveEvidenceRow] = []
    _emit_progress(progress_callback, event="run_start", benchmark_mode="live-surface", run_id=run_id, total_rows=len(row_jobs), target=target_name, model=target_model, out_dir=str(out_dir))
    for index, (variant, pack, variant_matrix_path, extra_metadata) in enumerate(row_jobs, start=1):
        row_id = f"pack:{pack_id}" if variant == "baseline" else f"pack:{pack_id}:{variant}"
        _emit_progress(progress_callback, event="row_start", index=index, total_rows=len(row_jobs), row_id=row_id, surface_id=f"pack:{pack_id}", surface_name=_progress_surface_name(f"pack:{pack_id}", []), status="running")
        row = _row_for_pack(
            pack,
            run_id=run_id,
            timestamp=generated_at,
            command=command,
            target=target_metadata,
            preflight=preflight,
            target_path=target_path,
            matrix_path=variant_matrix_path,
            out_dir=_surface_variant_out_dir(out_dir, pack_id=pack_id, variant=variant),
            progress_callback=progress_callback,
        )
        if variant != "baseline":
            row = row.model_copy(
                update={
                    "row_id": row_id,
                    "case_id": f"{pack_id}:{variant}",
                    "metadata": _sanitize_metadata({**(row.metadata or {}), **extra_metadata}),
                }
            )
        rows.append(row)
        _emit_progress(
            progress_callback,
            event="row_end",
            index=index,
            total_rows=len(row_jobs),
            row_id=row.row_id,
            surface_id=row.surface_id,
            surface_name=_progress_surface_name(row.surface_id, []),
            status=row.status,
            evidence_level=row.evidence_level,
            evidence_fidelity=row.evidence_fidelity,
            live_model_calls=row.live_model_calls,
            backing_model_calls=(row.metadata or {}).get("backing_model_calls") if isinstance(row.metadata, dict) else None,
            target_call_count=(row.metadata or {}).get("target_call_count") if isinstance(row.metadata, dict) else None,
            target_trace_count=(row.metadata or {}).get("target_trace_count") if isinstance(row.metadata, dict) else None,
            reason=row.reason,
            report_json=(row.metadata or {}).get("report_json") if isinstance(row.metadata, dict) else None,
            reason_codes=(row.metadata or {}).get("reason_codes") if isinstance(row.metadata, dict) else None,
        )
    evidence = LiveEvidenceMatrix(
        matrix_id=matrix.id,
        generated_at=generated_at,
        surfaces=[LiveSurfaceRecord(surface_id=f"pack:{pack_id}", name=pack_id, category="release_matrix_pack", modality="unknown", metadata={"single_surface": True})],
        rows=rows,
        metadata=_sanitize_metadata(
            {
                "schema_version": LIVE_FULL_PLAN_SCHEMA_VERSION,
                "benchmark_mode": "live-surface",
                "surface_id": pack_id,
                "matrix_path": _public_path(matrix_path),
                "target_name": target_name,
                "target_adapter": str(target_config.adapter or target_config.target_type),
                "target_model": target_model,
                "dry_run": False,
                "provider_calls_enabled": True,
                "operator_confirmed": yes,
                "request_timeout": request_timeout,
                "max_retries": max_retries,
                "surface_mutations_enabled": mutation_profile_path is not None,
                "surface_mutation_profile_path": _public_path(mutation_profile_path) if mutation_profile_path is not None else None,
                "surface_mutation_limit": mutation_limit,
                "preflight": preflight.model_dump(mode="json"),
            }
        ),
    )
    result = write_live_full_matrix(evidence, out_dir)
    _emit_progress(progress_callback, event="run_end", benchmark_mode="live-surface", run_id=run_id, total_rows=len(rows), out_dir=str(out_dir))
    return result


def build_live_full_matrix(
    *,
    target_path: str | Path,
    matrix_path: str | Path,
    out_dir: str | Path,
    target: TargetConfig,
    matrix: ReleaseMatrix,
    selected_profile: MutationProfile,
    deep_profile: MutationProfile | None,
    preflight: LivePreflightReport,
    include_deep_mutations: bool,
    yes: bool,
    concurrency: int,
    request_timeout: float,
    max_retries: int,
    command: str,
    benchmark_mode: str = "live-full",
    progress_callback: LiveProgressCallback | None = None,
) -> LiveEvidenceMatrix:
    generated_at = _now()
    command = redact_public_text(command).text
    target_name = redact_public_text(target.name).text
    target_model = redact_public_text(target.model or str(target.target_type)).text
    run_id = f"live-full-{_slug(target_name)}-{generated_at.replace(':', '').replace('+', 'z')}"
    safe_base_url = safe_endpoint_from_url(_target_endpoint_url(target)).label
    target_metadata = LiveTargetMetadata(name=target_name, adapter=str(target.adapter or target.target_type), model=target_model, base_url=safe_base_url, metadata=_sanitize_metadata({**target.metadata, "target_type": str(target.target_type)}))
    packs = _canonical_live_packs(matrix)
    surfaces = _build_surfaces(matrix, selected_profile, deep_profile)
    selected_ref = _find_profile_ref(matrix.selected_mutation_profiles, selected_profile.id)
    if deep_profile is not None:
        deep_ref = _find_profile_ref(matrix.deep_mutation_profiles, deep_profile.id)
    else:
        deep_ref = None

    git_commit = _git_commit()
    pending_rows: list[LiveEvidenceRow] = []
    row_builders: list[tuple[LiveEvidenceRow, Any]] = []

    for pack in packs:
        pending = _pending_pack_row(
            pack,
            run_id=run_id,
            timestamp=generated_at,
            command=command,
            target=target_metadata,
            preflight=preflight,
        )
        pending_rows.append(pending)
        row_builders.append(
            (
                pending,
                lambda pack=pack: _row_for_pack(
                    pack,
                    run_id=run_id,
                    timestamp=generated_at,
                    command=command,
                    target=target_metadata,
                    preflight=preflight,
                    target_path=target_path,
                    matrix_path=matrix_path,
                    out_dir=out_dir,
                    progress_callback=progress_callback,
                ),
            )
        )

    selected_pending = _pending_profile_row(
        selected_profile,
        selected_ref,
        run_id=run_id,
        timestamp=generated_at,
        command=command,
        target=target_metadata,
        preflight=preflight,
    )
    pending_rows.append(selected_pending)
    row_builders.append(
        (
            selected_pending,
            lambda: _row_for_profile(
                selected_profile,
                selected_ref,
                run_id=run_id,
                timestamp=generated_at,
                command=command,
                target=target_metadata,
                preflight=preflight,
                include_requested=True,
                target_path=target_path,
                matrix=matrix,
                matrix_path=matrix_path,
                out_dir=out_dir,
            ),
        )
    )

    if deep_profile is not None:
        deep_pending = _pending_profile_row(
            deep_profile,
            deep_ref,
            run_id=run_id,
            timestamp=generated_at,
            command=command,
            target=target_metadata,
            preflight=preflight,
        )
        pending_rows.append(deep_pending)
        row_builders.append(
            (
                deep_pending,
                lambda: _row_for_profile(
                    deep_profile,
                    deep_ref,
                    run_id=run_id,
                    timestamp=generated_at,
                    command=command,
                    target=target_metadata,
                    preflight=preflight,
                    include_requested=include_deep_mutations,
                    target_path=target_path,
                    matrix=matrix,
                    matrix_path=matrix_path,
                    out_dir=out_dir,
                ),
            )
        )

    rows: list[LiveEvidenceRow] = []
    base_metadata = {
        "schema_version": LIVE_FULL_PLAN_SCHEMA_VERSION,
        "benchmark_mode": benchmark_mode,
        "exhaustive": benchmark_mode == "exterminatus",
        "matrix_path": _public_path(matrix_path),
        "release_matrix_version": matrix.version,
        "selected_mutation_profile": selected_profile.id,
        "selected_mutation_profile_path": _profile_public_path(selected_profile, selected_ref),
        "deep_mutation_profile": deep_profile.id if deep_profile is not None else None,
        "deep_mutation_profile_path": _profile_public_path(deep_profile, deep_ref) if deep_profile is not None else None,
        "target_name": target_name,
        "target_adapter": str(target.adapter or target.target_type),
        "target_model": target_model,
        "dry_run": False,
        "provider_calls_enabled": True,
        "operator_confirmed": yes,
        "include_deep_mutations": include_deep_mutations,
        "unsupported_surfaces_explicit": True,
        "deferred_surfaces_explicit": True,
        "live_vs_static_contract": "dry-run, static, scaffold, simulated, and provider-free artifacts cannot satisfy live model behavior evidence",
        "provider_error_contract": "provider_error, timeout, infra_error, provider_capability_gap, target_capability_gap, target_config_error, target_error, skipped_by_operator, and checkpoint_not_run are operational/coverage outcomes, not model behavior failures",
        "concurrency": concurrency,
        "request_timeout": request_timeout,
        "max_retries": max_retries,
        "git_commit": git_commit,
        "preflight": _sanitize_metadata(preflight.model_dump(mode="json")),
    }

    total_rows = len(row_builders)
    _emit_progress(progress_callback, event="run_start", benchmark_mode=benchmark_mode, run_id=run_id, total_rows=total_rows, target=target_name, model=target_model, out_dir=str(out_dir))
    for index, (pending, build_row) in enumerate(row_builders):
        _emit_progress(progress_callback, event="row_start", index=index + 1, total_rows=total_rows, row_id=pending.row_id, surface_id=pending.surface_id, surface_name=_progress_surface_name(pending.surface_id, surfaces), status="running")
        row = build_row()
        rows.append(row)
        _emit_progress(
            progress_callback,
            event="row_end",
            index=index + 1,
            total_rows=total_rows,
            row_id=row.row_id,
            surface_id=row.surface_id,
            surface_name=_progress_surface_name(row.surface_id, surfaces),
            status=row.status,
            evidence_level=row.evidence_level,
            evidence_fidelity=row.evidence_fidelity,
            live_model_calls=row.live_model_calls,
            backing_model_calls=(row.metadata or {}).get("backing_model_calls") if isinstance(row.metadata, dict) else None,
            target_call_count=(row.metadata or {}).get("target_call_count") if isinstance(row.metadata, dict) else None,
            target_trace_count=(row.metadata or {}).get("target_trace_count") if isinstance(row.metadata, dict) else None,
            reason=row.reason,
            report_json=(row.metadata or {}).get("report_json") if isinstance(row.metadata, dict) else None,
            reason_codes=(row.metadata or {}).get("reason_codes") if isinstance(row.metadata, dict) else None,
        )
        _write_live_full_checkpoint(
            _matrix_with_rows(
                matrix_id=matrix.id,
                generated_at=generated_at,
                surfaces=surfaces,
                rows=rows + pending_rows[index + 1 :],
                metadata=base_metadata,
                git_commit=git_commit,
            ),
            out_dir,
            completed_rows=len(rows),
            total_rows=len(row_builders),
        )
        _emit_progress(progress_callback, event="checkpoint", completed_rows=len(rows), total_rows=total_rows, path=str(Path(out_dir) / "live-full-checkpoint.md"))

    rows = [row.model_copy(update={"git_commit": git_commit, "command": redact_public_text(row.command).text}) for row in rows]

    _emit_progress(progress_callback, event="run_end", benchmark_mode=benchmark_mode, run_id=run_id, total_rows=len(rows), out_dir=str(out_dir))
    return LiveEvidenceMatrix(
        matrix_id=matrix.id,
        generated_at=generated_at,
        surfaces=surfaces,
        rows=rows,
        metadata=base_metadata,
    )


def write_live_full_matrix(evidence: LiveEvidenceMatrix, out_dir: str | Path) -> tuple[LiveEvidenceMatrix, Path, Path]:
    destination = Path(out_dir)
    destination.mkdir(parents=True, exist_ok=True)
    json_path = destination / "live-full-evidence.json"
    markdown_path = destination / "live-full-evidence.md"
    json_path.write_text(evidence.model_dump_json(indent=2), encoding="utf-8")
    markdown_path.write_text(render_live_full_markdown(evidence), encoding="utf-8")
    write_stack_coverage_report(build_stack_coverage_from_live_matrix(evidence), destination)
    write_full_benchmark_reports(evidence, destination)
    if evidence.metadata.get("benchmark_mode") == "soft":
        write_soft_mode_marker(evidence, destination)
    if evidence.metadata.get("benchmark_mode") == "exterminatus":
        write_exterminatus_mode_marker(evidence, destination)
    return evidence, json_path, markdown_path


def _surface_variant_out_dir(out_dir: str | Path, *, pack_id: str, variant: str) -> Path:
    if variant == "baseline":
        return Path(out_dir)
    mutation = variant.removeprefix("mutation:")
    return Path(out_dir) / "surface-mutation-runs" / safe_output_segment(pack_id) / safe_output_segment(mutation)


def _write_single_pack_matrix_override(
    matrix: ReleaseMatrix,
    pack: ReleaseMatrixPackRef,
    fixture_path: Path,
    out_dir: str | Path,
    *,
    profile_id: str,
    mutation: str,
) -> Path:
    destination = Path(out_dir) / "surface-mutations" / safe_output_segment(pack.id) / safe_output_segment(profile_id)
    destination.mkdir(parents=True, exist_ok=True)
    matrix_path = destination / f"matrix--{safe_output_segment(mutation)}.yaml"
    payload = matrix.model_dump(mode="json")
    for item in payload.get("packs", []):
        if isinstance(item, dict) and item.get("id") == pack.id:
            item["path"] = str(fixture_path)
    matrix_path.write_text(yaml.safe_dump(payload, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return matrix_path


def _progress_surface_name(surface_id: str, surfaces: list[LiveSurfaceRecord]) -> str:
    for surface in surfaces:
        if surface.surface_id == surface_id:
            return surface.name
    if surface_id.startswith("pack:"):
        return surface_id.removeprefix("pack:")
    if surface_id.startswith("mutation-profile:"):
        return surface_id.removeprefix("mutation-profile:")
    return surface_id


_atomic_write_checkpoint_text = atomic_write_checkpoint_text
_matrix_with_rows = matrix_with_rows
_render_live_full_checkpoint_markdown = render_live_full_checkpoint_markdown
_write_live_full_checkpoint = write_live_full_checkpoint


_aggregate_matrix_payload = aggregate_matrix_payload
_final_preflight_status_label = final_preflight_status_label
_final_report_text = final_report_text
_human_surface_name = human_surface_name
_invalid_live_artifact_rows = invalid_live_artifact_rows
_is_live_model_behavior_failure = is_live_model_behavior_failure
_model_failure_rows = model_failure_rows
_model_failure_triage_payload = model_failure_triage_payload
_provider_error_rows = provider_error_rows
_render_command_log_markdown = render_command_log_markdown
_render_full_matrix_markdown = render_full_matrix_markdown
_render_full_summary_markdown = render_full_summary_markdown
_render_model_failure_triage_markdown = render_model_failure_triage_markdown
_render_model_failures_markdown = render_model_failures_markdown
_render_provider_errors_markdown = render_provider_errors_markdown
_render_server_diagnostics_markdown = render_server_diagnostics_markdown
_row_agent_trace_summary = row_agent_trace_summary


def _row_for_pack(
    pack: ReleaseMatrixPackRef,
    *,
    run_id: str,
    timestamp: str,
    command: str,
    target: LiveTargetMetadata,
    preflight: LivePreflightReport,
    target_path: str | Path,
    matrix_path: str | Path,
    out_dir: str | Path,
    progress_callback: LiveProgressCallback | None = None,
) -> LiveEvidenceRow:
    target_type = _row_target_type(target)
    if pack.id in SYSTEM_HARNESS_PACK_IDS:
        return _run_system_harness_pack_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=command,
            target=target,
            target_path=target_path,
            matrix_path=matrix_path,
            out_dir=out_dir,
            preflight=preflight,
            progress_callback=progress_callback,
        )
    if pack.id in SELF_MODIFICATION_LIVE_PACK_IDS:
        return _run_self_modification_pack_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=command,
            target=target,
            target_path=target_path,
            matrix_path=matrix_path,
            out_dir=out_dir,
            preflight=preflight,
        )
    if pack.id in (CLASSIC_LIVE_PACK_IDS | CHALLENGE_LIVE_PACK_IDS) and target_type != "chat_completion":
        return _system_capability_gap_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=command,
            target=target,
            required_target_types={"chat_completion"},
            actual_target_type=target_type,
            reason=f"chat-completion live model pack {pack.id} requires target_type=chat_completion; configured target_type={target_type} cannot provide chat-completion model evidence",
            metadata={"preflight_text_status": preflight.text_status},
        )
    if pack.id in VISUAL_LIVE_PACK_IDS:
        if preflight.visual_status == "passed":
            return _run_visual_pack_row(
                pack,
                run_id=run_id,
                timestamp=timestamp,
                command=command,
                target=target,
                target_path=target_path,
                out_dir=out_dir,
                preflight=preflight,
            )
        if preflight.visual_status in {"not_supported", "provider_capability_gap"} or preflight.visual_status is None:
            return _classification_row(
                row_id=f"pack:{pack.id}",
                run_id=run_id,
                case_id=pack.id,
                surface_id=f"pack:{pack.id}",
                timestamp=timestamp,
                command=command,
                target=target,
                status="provider_capability_gap",
                evidence_level="scaffold_static",
                reason=f"visual preflight recorded an image capability gap for visual live pack {pack.id}: {_final_preflight_status_label(preflight.visual_status)}",
                metadata={**_classic_pack_metadata(pack), "preflight_text_status": preflight.text_status, "preflight_visual_status": preflight.visual_status, "static_visual_lab_counted_as_live": False},
            )
        visual_status: LiveEvidenceStatus = "timeout" if preflight.visual_status == "timeout" else "provider_error"
        return _visual_operational_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=command,
            target=target,
            status=visual_status,
            reason=f"visual preflight blocked visual live pack {pack.id}: {preflight.visual_status}",
            metadata={**_classic_pack_metadata(pack), "preflight_text_status": preflight.text_status, "preflight_visual_status": preflight.visual_status, "visual_destabilized_endpoint": preflight.visual_destabilized_endpoint, "static_visual_lab_counted_as_live": False},
        )
    if pack.id in UI_ACTION_LIVE_PACK_IDS:
        if not preflight.text_ready:
            return _classification_row(
                row_id=f"pack:{pack.id}",
                run_id=run_id,
                case_id=pack.id,
                surface_id=f"pack:{pack.id}",
                timestamp=timestamp,
                command=command,
                target=target,
                status="target_error",
                evidence_level="scaffold_static",
                reason=f"text preflight did not pass for UI action-choice live pack {pack.id}: {preflight.text_status}",
                metadata={**_classic_pack_metadata(pack), "preflight_text_status": preflight.text_status, "scaffold_output_counted_as_live": False},
            )
        return _run_ui_action_pack_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=command,
            target=target,
            target_path=target_path,
            matrix_path=matrix_path,
            out_dir=out_dir,
            preflight=preflight,
        )
    if pack.id in HIDDEN_ARTIFACT_LIVE_PACK_IDS:
        if target_type not in {"chat_completion", "vision_model"}:
            return _system_capability_gap_row(
                pack,
                run_id=run_id,
                timestamp=timestamp,
                command=command,
                target=target,
                required_target_types={"chat_completion", "vision_model"},
                actual_target_type=target_type,
                reason=f"hidden/artifact live pack {pack.id} requires a provider-backed chat_completion or vision_model target; configured target_type={target_type} requires a matching live system surface instead",
                metadata={"preflight_text_status": preflight.text_status},
            )
        if not preflight.text_ready:
            return _classification_row(
                row_id=f"pack:{pack.id}",
                run_id=run_id,
                case_id=pack.id,
                surface_id=f"pack:{pack.id}",
                timestamp=timestamp,
                command=command,
                target=target,
                status="target_error",
                evidence_level="scaffold_static",
                reason=f"text preflight did not pass for hidden/artifact live pack {pack.id}: {preflight.text_status}",
                metadata={**_classic_pack_metadata(pack), "preflight_text_status": preflight.text_status},
            )
        return _run_hidden_artifact_pack_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=command,
            target=target,
            target_path=target_path,
            matrix_path=matrix_path,
            out_dir=out_dir,
            preflight=preflight,
        )
    if pack.id in CAMPAIGN_LIVE_PACK_IDS:
        if target_type not in {"chat_completion", "vision_model"}:
            return _system_capability_gap_row(
                pack,
                run_id=run_id,
                timestamp=timestamp,
                command=command,
                target=target,
                required_target_types={"chat_completion", "vision_model"},
                actual_target_type=target_type,
                reason=f"campaign live pack {pack.id} requires a provider-backed chat_completion or vision_model target; configured target_type={target_type} requires a matching live system surface instead",
                metadata={"preflight_text_status": preflight.text_status, "dry_run_output_counted_as_live": False},
            )
        if not preflight.text_ready:
            return _classification_row(
                row_id=f"pack:{pack.id}",
                run_id=run_id,
                case_id=pack.id,
                surface_id=f"pack:{pack.id}",
                timestamp=timestamp,
                command=command,
                target=target,
                status="target_error",
                evidence_level="scaffold_static",
                reason=f"text preflight did not pass for campaign live pack {pack.id}: {preflight.text_status}",
                metadata={**_classic_pack_metadata(pack), "preflight_text_status": preflight.text_status, "dry_run_output_counted_as_live": False},
            )
        return _run_campaign_pack_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=command,
            target=target,
            target_path=target_path,
            matrix_path=matrix_path,
            out_dir=out_dir,
            preflight=preflight,
        )
    if pack.id in CHALLENGE_LIVE_PACK_IDS:
        if not preflight.text_ready:
            return _classification_row(
                row_id=f"pack:{pack.id}",
                run_id=run_id,
                case_id=pack.id,
                surface_id=f"pack:{pack.id}",
                timestamp=timestamp,
                command=command,
                target=target,
                status="target_error",
                evidence_level="scaffold_static",
                reason=f"text preflight did not pass for challenge live pack {pack.id}: {preflight.text_status}",
                metadata={**_classic_pack_metadata(pack), "preflight_text_status": preflight.text_status, "local_challenge_artifacts_counted_as_live": False},
            )
        return _run_challenge_pack_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=command,
            target=target,
            target_path=target_path,
            matrix_path=matrix_path,
            out_dir=out_dir,
            preflight=preflight,
        )
    if not preflight.text_ready and pack.live_model_evidence:
        status = "target_error"
        evidence_level = "scaffold_static"
        reason = f"text preflight did not pass for live model pack {pack.id}: {preflight.text_status}"
    elif pack.scaffold_only:
        status = "provider_capability_gap"
        evidence_level = "scaffold_static"
        reason = _provider_free_pack_reason(pack)
    elif not pack.live_model_evidence:
        status = "provider_capability_gap"
        evidence_level = "scaffold_static"
        reason = _provider_free_pack_reason(pack)
    elif pack.id in CLASSIC_LIVE_PACK_IDS:
        return _run_classic_pack_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=command,
            target=target,
            target_path=target_path,
            matrix_path=matrix_path,
            out_dir=out_dir,
            progress_callback=progress_callback,
        )
    elif pack.id in AGENTIC_LIVE_PACK_IDS:
        return _system_capability_gap_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=command,
            target=target,
            required_target_types={"tool_agent"},
            actual_target_type=target_type,
            reason=f"agentic-injection-v1 requires target_type=tool_agent for real tool trace evidence; configured target_type={target_type} would only provide chat text",
            metadata={"preflight_text_status": preflight.text_status, "mock_agent_lab_separate": True},
        )
    elif pack.id in RAG_LIVE_PACK_IDS:
        return _system_capability_gap_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=command,
            target=target,
            required_target_types={"rag_service"},
            actual_target_type=target_type,
            reason=f"rag-v1 requires target_type=rag_service for real retrieval trace evidence; configured target_type={target_type} would only provide model-only RAG text",
            metadata={"preflight_text_status": preflight.text_status, "fixture_model_rag_separate": True},
        )
    else:
        status = "provider_capability_gap"
        evidence_level = "scaffold_static"
        reason = f"pack {pack.id} has no implemented live runner in this release; no live model or system evidence was collected"
    return _classification_row(
        row_id=f"pack:{pack.id}",
        run_id=run_id,
        case_id=pack.id,
        surface_id=f"pack:{pack.id}",
        timestamp=timestamp,
        command=command,
        target=target,
        status=status,
        evidence_level=evidence_level,
        reason=reason,
        metadata={**_classic_pack_metadata(pack), "preflight_text_status": preflight.text_status, "preflight_visual_status": preflight.visual_status, "live_model_evidence": pack.live_model_evidence, "scaffold_only": pack.scaffold_only, "evidence_boundary_reason": reason},
    )


def _pending_pack_row(
    pack: ReleaseMatrixPackRef,
    *,
    run_id: str,
    timestamp: str,
    command: str,
    target: LiveTargetMetadata,
    preflight: LivePreflightReport,
) -> LiveEvidenceRow:
    reason = f"pack {pack.id} was not reached before the live-full checkpoint; interruption or operator/tool timeout may have stopped the aggregate run"
    return _classification_row(
        row_id=f"pack:{pack.id}",
        run_id=run_id,
        case_id=pack.id,
        surface_id=f"pack:{pack.id}",
        timestamp=timestamp,
        command=command,
        target=target,
        status="checkpoint_not_run",
        evidence_level="scaffold_static",
        reason=reason,
        metadata={
            **_classic_pack_metadata(pack),
            "checkpoint_status": "not_run",
            "checkpoint_reason": "surface_not_reached",
            "preflight_text_status": preflight.text_status,
            "preflight_visual_status": preflight.visual_status,
            "live_model_evidence": pack.live_model_evidence,
            "scaffold_only": pack.scaffold_only,
            "provider_error": False,
            "model_behavior_failure": False,
        },
    )


def _provider_free_pack_reason(pack: ReleaseMatrixPackRef) -> str:
    if pack.scaffold_only:
        return f"{pack.id} is scaffold-only in the release matrix and requires a live target route before it can produce benchmark evidence"
    return f"{pack.id} is classified as {pack.evidence_level} in the release matrix and requires an implemented live route before it can produce benchmark evidence"


def _run_challenge_pack_row(
    pack: ReleaseMatrixPackRef,
    *,
    run_id: str,
    timestamp: str,
    command: str,
    target: LiveTargetMetadata,
    target_path: str | Path,
    matrix_path: str | Path,
    out_dir: str | Path,
    preflight: LivePreflightReport,
    progress_callback: LiveProgressCallback | None = None,
) -> LiveEvidenceRow:
    pack_out = Path(out_dir) / "challenge" / pack.id
    challenge_path = _matrix_reference_path(pack.path, Path(matrix_path).resolve())
    public_pack_path = _public_path(pack.path)
    pack_command = f"{command} # challenge pack {pack.id} via challenge live runner --challenge {shlex.quote(public_pack_path)}"
    try:
        runner_report = run_challenge_live(target_path, challenge_path, pack_out)
    except Exception as exc:
        return _live_operational_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=pack_command,
            target=target,
            status="provider_error",
            reason=f"challenge live pack {pack.id} failed during provider execution: {type(exc).__name__}: {exc}",
            metadata={**_classic_pack_metadata(pack, public_pack_path=public_pack_path), "output_dir": f"challenge/{pack.id}", "runner_error_type": type(exc).__name__, "preflight_text_status": preflight.text_status, "local_challenge_artifacts_counted_as_live": False},
        )

    report_path = pack_out / "challenge-live-report.json"
    local_report_path = pack_out / "challenge-report.json"
    if not report_path.exists() or runner_report.mode != "live_provider" or runner_report.dry_run or not runner_report.provider_calls_enabled or local_report_path.exists():
        return _live_operational_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=pack_command,
            target=target,
            status="infra_error",
            reason=f"challenge live pack {pack.id} did not produce valid live-provider challenge-live-report.json evidence; local challenge-report artifacts cannot satisfy live-full evidence",
            metadata={**_classic_pack_metadata(pack, public_pack_path=public_pack_path), "output_dir": f"challenge/{pack.id}", "challenge_live_report_json_exists": report_path.exists(), "challenge_report_json_exists": local_report_path.exists(), "report_mode": runner_report.mode, "dry_run": runner_report.dry_run, "provider_calls_enabled": runner_report.provider_calls_enabled, "invalid_live_artifact": True, "preflight_text_status": preflight.text_status, "local_challenge_artifacts_counted_as_live": False},
        )

    payload = json.loads(report_path.read_text(encoding="utf-8"))
    report = ChallengeLiveReport.model_validate(payload)
    if report.summary.provider_error:
        return _live_operational_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=pack_command,
            target=target,
            status="provider_error",
            reason=f"challenge live pack {pack.id} recorded provider errors for {report.summary.provider_error} challenge fixtures",
            metadata={**_classic_pack_metadata(pack, public_pack_path=public_pack_path), "output_dir": f"challenge/{pack.id}", "runner_run_id": report.run_id, "adapter_call_count": report.attempted_provider_calls, "completed_live_model_calls": report.live_model_calls, "status_counts": report.summary.status_counts, "reason_counts": report.summary.reason_counts, "report_json": f"challenge/{pack.id}/challenge-live-report.json", "preflight_text_status": preflight.text_status, "local_challenge_artifacts_counted_as_live": False},
        )
    if report.live_model_calls <= 0:
        return _live_operational_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=pack_command,
            target=target,
            status="infra_error",
            reason=f"challenge live pack {pack.id} completed without live model responses",
            metadata={**_classic_pack_metadata(pack, public_pack_path=public_pack_path), "output_dir": f"challenge/{pack.id}", "runner_run_id": report.run_id, "adapter_call_count": report.attempted_provider_calls, "completed_live_model_calls": report.live_model_calls, "status_counts": report.summary.status_counts, "report_json": f"challenge/{pack.id}/challenge-live-report.json", "preflight_text_status": preflight.text_status, "local_challenge_artifacts_counted_as_live": False},
        )

    status: LiveEvidenceStatus = "passed" if report.summary.failed == 0 else "failed"
    return LiveEvidenceRow(
        row_id=f"pack:{pack.id}",
        run_id=run_id,
        case_id=pack.id,
        surface_id=f"pack:{pack.id}",
        timestamp=timestamp,
        command=pack_command,
        git_commit="unknown",
        target=target,
        status=status,
        evidence_level="live_text_model",
        dry_run=False,
        provider_calls_enabled=True,
        live_model_calls=report.live_model_calls,
        artifacts=_challenge_live_artifact_refs(pack_out),
        metadata={
            **_classic_pack_metadata(pack, public_pack_path=public_pack_path),
            "output_dir": f"challenge/{pack.id}",
            "runner_run_id": report.run_id,
            "status_counts": report.summary.status_counts,
            "reason_counts": report.summary.reason_counts,
            "reason_codes": report.summary.reason_codes,
            "adapter_call_count": report.attempted_provider_calls,
            "completed_live_model_calls": report.live_model_calls,
            "report_json": f"challenge/{pack.id}/challenge-live-report.json",
            "preflight_text_status": preflight.text_status,
            "local_challenge_artifacts_counted_as_live": False,
        },
    )


def _challenge_live_artifact_refs(output_dir: Path) -> list[ArtifactRef]:
    refs: list[ArtifactRef] = []
    artifact_types = {
        "challenge-live-report.json": "challenge_live_report_json",
        "challenge-live-report.md": "challenge_live_report_markdown",
    }
    for name, artifact_type in artifact_types.items():
        path = output_dir / name
        if not path.exists():
            continue
        refs.append(
            ArtifactRef(
                path=name,
                kind=path.suffix.lstrip(".") or "artifact",
                artifact_type=artifact_type,
                sha256=_sha256_file(path),
                relative_path=name,
                redaction_status="redacted",
            )
        )
    return refs


SYSTEM_HARNESS_PACK_IDS = {"rag-v1", "agentic-injection-v1", "plugin-workflow-v1", "code-agent-v1", "memory-agent-v1", "multi-agent-v1", "ui-browser-v1"}
SYSTEM_HARNESS_REQUIREMENTS = {
    "rag-v1": ("rag_service", "rag-service", run_rag_service_harness, RagServiceReport, "rag-service-report.json"),
    "agentic-injection-v1": ("tool_agent", "tool-agent", run_tool_agent_harness, ToolAgentReport, "tool-agent-report.json"),
    "plugin-workflow-v1": ("workflow_harness", "workflow-harness", run_workflow_harness, WorkflowHarnessReport, "workflow-harness-report.json"),
    "code-agent-v1": ("code_agent", "code-agent", run_code_agent_harness, CodeAgentHarnessReport, "code-agent-harness-report.json"),
    "memory-agent-v1": ("memory_agent", "memory-agent", run_memory_agent_harness, MemoryAgentReport, "memory-agent-report.json"),
    "multi-agent-v1": ("multi_agent", "multi-agent", run_multi_agent_harness, MultiAgentReport, "multi-agent-report.json"),
    "ui-browser-v1": ("browser_agent", "browser-agent", run_browser_agent_harness, BrowserAgentReport, "browser-agent-report.json"),
}


def _run_self_modification_pack_row(
    pack: ReleaseMatrixPackRef,
    *,
    run_id: str,
    timestamp: str,
    command: str,
    target: LiveTargetMetadata,
    target_path: str | Path,
    matrix_path: str | Path,
    out_dir: str | Path,
    preflight: LivePreflightReport,
    progress_callback: LiveProgressCallback | None = None,
) -> LiveEvidenceRow:
    actual_type = _row_target_type(target)
    if actual_type not in SELF_MODIFICATION_TARGET_TYPES:
        base_target = load_target_config(target_path)
        if preflight.text_ready and can_auto_wrap(base_target, "tool_agent"):
            output_name, runner, report_type, report_name, fixture_path = _self_modification_runner_config(pack, "tool_agent", matrix_path=matrix_path, out_dir=out_dir)
            pack_out = Path(out_dir) / output_name / pack.id
            with auto_system_wrapper(base_target, "tool_agent", fixture_path, pack_out) as wrapped_target:
                wrapped_metadata = LiveTargetMetadata(
                    name=target.name,
                    adapter=target.adapter,
                    model=target.model,
                    base_url=target.base_url,
                    metadata=_sanitize_metadata(
                        {
                            **target.metadata,
                            "target_type": "tool_agent",
                            "actual_target_type": actual_type,
                            "auto_wrapped": True,
                            "auto_wrapper_surface": "tool_agent",
                            "auto_wrapper_source_target_type": actual_type,
                        }
                    ),
                )
                return _run_system_harness_with_config(
                    pack,
                    required_type="tool_agent",
                    output_name=output_name,
                    runner=runner,
                    report_type=report_type,
                    report_name=report_name,
                    fixture_path=fixture_path,
                    run_id=run_id,
                    timestamp=timestamp,
                    command=command,
                    target=wrapped_metadata,
                    target_path=wrapped_target,
                    out_dir=out_dir,
                    preflight=preflight,
                    progress_callback=progress_callback,
                    metadata={
                        "self_modification_routing": "tool_agent",
                        "auto_wrapped": True,
                        "auto_wrapper_surface": "tool_agent",
                        "auto_wrapper_source_target_type": actual_type,
                        "auto_wrapper_source_target_name": target.name,
                        "actual_target_type": actual_type,
                    },
                )
        return _system_capability_gap_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=command,
            target=target,
            required_target_types=SELF_MODIFICATION_TARGET_TYPES,
            actual_target_type=actual_type,
            reason=f"self-modification-v1 requires target_type=tool_agent, workflow_harness, code_agent, memory_agent, or multi_agent for real system trace evidence; configured target_type={actual_type} would only provide chat text or an incompatible target surface",
            metadata={"preflight_text_status": preflight.text_status, "self_modification_routing": "capability_gap"},
        )

    output_name, runner, report_type, report_name, fixture_path = _self_modification_runner_config(pack, actual_type, matrix_path=matrix_path, out_dir=out_dir)
    return _run_system_harness_with_config(
        pack,
        required_type=actual_type,
        output_name=output_name,
        runner=runner,
        report_type=report_type,
        report_name=report_name,
        fixture_path=fixture_path,
        run_id=run_id,
        timestamp=timestamp,
        command=command,
        target=target,
        target_path=target_path,
        out_dir=out_dir,
        preflight=preflight,
        progress_callback=progress_callback,
        metadata={"self_modification_routing": actual_type},
    )


def _self_modification_runner_config(pack: ReleaseMatrixPackRef, actual_type: str, *, matrix_path: str | Path, out_dir: str | Path) -> tuple[str, Any, Any, str, Path]:
    pack_out = Path(out_dir) / f"self-modification-{actual_type.replace('_', '-')}" / pack.id
    pack_out.mkdir(parents=True, exist_ok=True)
    if actual_type == "tool_agent":
        return "self-modification-tool-agent", run_tool_agent_harness, ToolAgentReport, "tool-agent-report.json", write_self_modification_tool_agent_fixture(pack_out)
    if actual_type == "workflow_harness":
        return "self-modification-workflow", run_workflow_harness, WorkflowHarnessReport, "workflow-harness-report.json", write_self_modification_workflow_fixture(pack_out)
    if actual_type == "code_agent":
        return "self-modification-code-agent", run_code_agent_harness, CodeAgentHarnessReport, "code-agent-harness-report.json", _matrix_reference_path(pack.path, Path(matrix_path).resolve())
    if actual_type == "memory_agent":
        return "self-modification-memory-agent", run_memory_agent_harness, MemoryAgentReport, "memory-agent-report.json", write_self_modification_memory_fixture(pack_out)
    if actual_type == "multi_agent":
        return "self-modification-multi-agent", run_multi_agent_harness, MultiAgentReport, "multi-agent-report.json", write_self_modification_multi_agent_fixture(pack_out)
    raise ValueError(f"unsupported self-modification target type: {actual_type}")


_write_self_modification_memory_fixture = write_self_modification_memory_fixture
_write_self_modification_multi_agent_fixture = write_self_modification_multi_agent_fixture
_write_self_modification_tool_agent_fixture = write_self_modification_tool_agent_fixture
_write_self_modification_workflow_fixture = write_self_modification_workflow_fixture


def _run_system_harness_pack_row(
    pack: ReleaseMatrixPackRef,
    *,
    run_id: str,
    timestamp: str,
    command: str,
    target: LiveTargetMetadata,
    target_path: str | Path,
    matrix_path: str | Path,
    out_dir: str | Path,
    preflight: LivePreflightReport,
    progress_callback: LiveProgressCallback | None = None,
) -> LiveEvidenceRow:
    required_type, output_name, runner, report_type, report_name = SYSTEM_HARNESS_REQUIREMENTS[pack.id]
    actual_type = _row_target_type(target)
    if actual_type != required_type:
        base_target = load_target_config(target_path)
        fixture_path = _matrix_reference_path(pack.path, Path(matrix_path).resolve())
        if preflight.text_ready and can_auto_wrap(base_target, required_type):
            pack_out = Path(out_dir) / output_name / pack.id
            with auto_system_wrapper(base_target, required_type, fixture_path, pack_out) as wrapped_target:
                wrapped_metadata = LiveTargetMetadata(
                    name=target.name,
                    adapter=target.adapter,
                    model=target.model,
                    base_url=target.base_url,
                    metadata=_sanitize_metadata(
                        {
                            **target.metadata,
                            "target_type": required_type,
                            "actual_target_type": actual_type,
                            "auto_wrapped": True,
                            "auto_wrapper_surface": required_type,
                            "auto_wrapper_source_target_type": actual_type,
                        }
                    ),
                )
                return _run_system_harness_with_config(
                    pack,
                    required_type=required_type,
                    output_name=output_name,
                    runner=runner,
                    report_type=report_type,
                    report_name=report_name,
                    fixture_path=fixture_path,
                    run_id=run_id,
                    timestamp=timestamp,
                    command=command,
                    target=wrapped_metadata,
                    target_path=wrapped_target,
                    out_dir=out_dir,
                    preflight=preflight,
                    progress_callback=progress_callback,
                    metadata={
                        "auto_wrapped": True,
                        "auto_wrapper_surface": required_type,
                        "auto_wrapper_source_target_type": actual_type,
                        "auto_wrapper_source_target_name": target.name,
                        "actual_target_type": actual_type,
                    },
                )
        return _system_capability_gap_row(pack, run_id=run_id, timestamp=timestamp, command=command, target=target, required_target_types={required_type}, actual_target_type=actual_type, reason=f"{pack.id} requires target_type={required_type} for real system trace evidence; configured target_type={actual_type}", metadata={"preflight_text_status": preflight.text_status})
    fixture_path = _matrix_reference_path(pack.path, Path(matrix_path).resolve())
    return _run_system_harness_with_config(
        pack,
        required_type=required_type,
        output_name=output_name,
        runner=runner,
        report_type=report_type,
        report_name=report_name,
        fixture_path=fixture_path,
        run_id=run_id,
        timestamp=timestamp,
        command=command,
        target=target,
        target_path=target_path,
        out_dir=out_dir,
        preflight=preflight,
        progress_callback=progress_callback,
        metadata={},
    )


def _run_system_harness_with_config(
    pack: ReleaseMatrixPackRef,
    *,
    required_type: str,
    output_name: str,
    runner: Any,
    report_type: Any,
    report_name: str,
    fixture_path: Path,
    run_id: str,
    timestamp: str,
    command: str,
    target: LiveTargetMetadata,
    target_path: str | Path,
    out_dir: str | Path,
    preflight: LivePreflightReport,
    progress_callback: LiveProgressCallback | None,
    metadata: dict[str, Any],
) -> LiveEvidenceRow:
    pack_out = Path(out_dir) / output_name / pack.id
    public_pack_path = _public_path(pack.path)
    system_command = f"{command} # system harness {pack.id} --surface {shlex.quote(public_pack_path)}"
    try:
        if required_type == "code_agent":
            runner(target_path, fixture_path, pack_out, sandbox_backend="bwrap")
        else:
            runner(target_path, fixture_path, pack_out)
    except (ValueError, OSError) as exc:
        return _system_error_row(pack, run_id=run_id, timestamp=timestamp, command=system_command, target=target, status="target_config_error", reason=f"{pack.id} system harness configuration failed: {type(exc).__name__}: {exc}", metadata={"output_dir": f"{output_name}/{pack.id}", "runner_error_type": type(exc).__name__, "preflight_text_status": preflight.text_status, **metadata, **_classic_pack_metadata(pack, public_pack_path=public_pack_path)})
    except Exception as exc:
        return _system_error_row(pack, run_id=run_id, timestamp=timestamp, command=system_command, target=target, status="target_error", reason=f"{pack.id} system harness execution failed: {type(exc).__name__}: {exc}", metadata={"output_dir": f"{output_name}/{pack.id}", "runner_error_type": type(exc).__name__, "preflight_text_status": preflight.text_status, **metadata, **_classic_pack_metadata(pack, public_pack_path=public_pack_path)})
    report_path = pack_out / report_name
    if not report_path.exists():
        return _system_error_row(pack, run_id=run_id, timestamp=timestamp, command=system_command, target=target, status="infra_error", reason=f"{pack.id} system harness did not produce {report_name}", metadata={"output_dir": f"{output_name}/{pack.id}", "report_json_exists": False, "preflight_text_status": preflight.text_status, **metadata, **_classic_pack_metadata(pack, public_pack_path=public_pack_path)})
    report = report_type.model_validate(json.loads(report_path.read_text(encoding="utf-8")))
    emit_system_harness_progress(progress_callback, pack=pack, report=report)
    return _system_report_row(pack, report=report, run_id=run_id, timestamp=timestamp, command=system_command, target=target, output_dir=pack_out, output_prefix=f"{output_name}/{pack.id}", report_name=report_name, metadata={"preflight_text_status": preflight.text_status, **metadata, **_classic_pack_metadata(pack, public_pack_path=public_pack_path)})


def _system_report_row(pack: ReleaseMatrixPackRef, *, report: Any, run_id: str, timestamp: str, command: str, target: LiveTargetMetadata, output_dir: Path, output_prefix: str, report_name: str, metadata: dict[str, Any]) -> LiveEvidenceRow:
    summary = report.summary
    agent_trace_summary = getattr(report, "agent_trace_summary", None)
    agent_trace_summary_payload = agent_trace_summary.model_dump(mode="json") if agent_trace_summary is not None else {}
    status = system_summary_status(summary)
    report_metadata = getattr(report, "metadata", {}) if isinstance(getattr(report, "metadata", {}), dict) else {}
    hosted_runtime = bool(report_metadata.get("hosted_runtime") or report_metadata.get("hosted_tool_runtime"))
    controlled_lab = _is_controlled_lab_system_target(target, report_metadata, metadata)
    auto_wrapped = bool(metadata.get("auto_wrapped") or report_metadata.get("auto_wrapped") or target.metadata.get("auto_wrapped"))
    evidence_fidelity = _system_evidence_fidelity_for_target(report.target_type, output_prefix, controlled_lab=controlled_lab) if hosted_runtime else "auto_wrapper_trace" if auto_wrapped else _system_evidence_fidelity_for_target(report.target_type, output_prefix, controlled_lab=controlled_lab)
    reason = system_summary_reason(pack.id, summary, status, evidence_fidelity=evidence_fidelity)
    backing_model_calls = system_report_live_model_calls(report)
    target_call_count = nonnegative_int(getattr(summary, "target_call_count", 0))
    target_artifact_count = nonnegative_int(report.metadata.get("target_artifact_count", 0))
    target_trace_count = nonnegative_int(getattr(summary, "target_trace_count", report_metadata.get("target_trace_count", 0)))
    has_target_observation = any((target_call_count, target_trace_count, target_artifact_count))
    evidence_level = "live_system_trace" if has_target_observation else "scaffold_static"
    row_status = status if has_target_observation or status not in {"passed", "failed"} else "target_error"
    row_reason = reason
    if not has_target_observation:
        row_reason = f"{reason}; no target call, trace, or artifact was observed, so this row is a target/coverage outcome rather than live system trace evidence" if reason else "no target call, trace, or artifact was observed"
    return LiveEvidenceRow(row_id=f"pack:{pack.id}", run_id=run_id, case_id=pack.id, surface_id=f"pack:{pack.id}", timestamp=timestamp, command=command, git_commit="unknown", target=target, status=row_status, evidence_level=evidence_level, evidence_fidelity=evidence_fidelity, dry_run=False, provider_calls_enabled=True, live_model_calls=0, reason=redact_public_text(row_reason).text if row_reason else None, artifacts=_system_harness_artifact_refs(output_dir, report_name), metadata=_sanitize_metadata({**metadata, "output_dir": output_prefix, "runner_run_id": report.run_id, "target_type": report.target_type, "target_call_count": target_call_count, "target_trace_count": target_trace_count, "target_artifact_count": target_artifact_count, "live_model_calls": 0, "backing_model_calls": backing_model_calls, "target_execution_enabled": has_target_observation, "status_counts": summary.status_counts, "reason_codes": getattr(summary, "reason_codes", []), "report_json": f"{output_prefix}/{report_name}", "agent_trace_summary": agent_trace_summary_payload, "agent_trace_count": int(agent_trace_summary_payload.get("total_traces") or 0), "agent_trace_capability_gap_count": int(agent_trace_summary_payload.get("capability_gap_count") or 0), "agent_trace_evidence_type_counts": agent_trace_summary_payload.get("evidence_type_counts", {}), "agent_trace_event_type_counts": agent_trace_summary_payload.get("event_type_counts", {}), "browser_enabled": getattr(report, "browser_enabled", None), "screenshots_captured": getattr(report, "screenshots_captured", None), "screenshot_capability_gap": report_metadata.get("screenshot_capability_gap"), "chat_completion_model_only": False, "hosted_runtime": hosted_runtime, "hosted_rag_runtime": bool(report_metadata.get("hosted_rag_runtime")), "hosted_tool_runtime": bool(report_metadata.get("hosted_tool_runtime")), "hosted_workflow_runtime": bool(report_metadata.get("hosted_workflow_runtime")), "hosted_memory_runtime": bool(report_metadata.get("hosted_memory_runtime")), "hosted_multi_agent_runtime": bool(report_metadata.get("hosted_multi_agent_runtime")), "hosted_browser_runtime": bool(report_metadata.get("hosted_browser_runtime")), "hosted_code_runtime": bool(report_metadata.get("hosted_code_runtime")), "lab_environment": controlled_lab, "controlled_lab": controlled_lab, "controlled_surface": output_prefix if controlled_lab else None, "live_system_trace": has_target_observation, "evidence_fidelity": evidence_fidelity, "low_fidelity": evidence_fidelity == "auto_wrapper_trace"}))


def _system_evidence_fidelity_for_target(target_type: str, output_prefix: str, *, controlled_lab: bool = False) -> str:
    if target_type == "rag_service" or output_prefix.startswith("rag-service/"):
        return "controlled_rag_trace" if controlled_lab else "live_rag_service_trace"
    if target_type == "tool_agent" or output_prefix.startswith("self-modification-tool-agent/"):
        return "controlled_tool_trace" if controlled_lab else "live_tool_trace"
    if target_type == "workflow_harness" or output_prefix.startswith("self-modification-workflow/"):
        return "controlled_workflow_trace" if controlled_lab else "live_workflow_trace"
    if target_type == "memory_agent" or output_prefix.startswith("self-modification-memory-agent/"):
        return "controlled_memory_trace" if controlled_lab else "live_memory_trace"
    if target_type == "multi_agent" or output_prefix.startswith("self-modification-multi-agent/"):
        return "controlled_multi_agent_trace" if controlled_lab else "live_multi_agent_trace"
    if target_type == "browser_agent":
        return "controlled_browser_trace" if controlled_lab else "live_browser_trace"
    if target_type == "code_agent" or output_prefix.startswith("self-modification-code-agent/"):
        return "controlled_code_workspace_trace" if controlled_lab else "live_code_agent_trace"
    return "live_tool_trace"


def _is_controlled_lab_system_target(target: LiveTargetMetadata, report_metadata: dict[str, Any], row_metadata: dict[str, Any]) -> bool:
    target_metadata = target.metadata if isinstance(target.metadata, dict) else {}
    return bool(
        row_metadata.get("lab_environment")
        or row_metadata.get("controlled_lab")
        or report_metadata.get("lab_environment")
        or report_metadata.get("controlled_lab")
        or report_metadata.get("controlled_surface")
        or target_metadata.get("lab_environment")
        or target_metadata.get("controlled_lab")
        or target_metadata.get("harness_proxy")
    )


def _system_error_row(pack: ReleaseMatrixPackRef, *, run_id: str, timestamp: str, command: str, target: LiveTargetMetadata, status: LiveEvidenceStatus, reason: str, metadata: dict[str, Any]) -> LiveEvidenceRow:
    return LiveEvidenceRow(row_id=f"pack:{pack.id}", run_id=run_id, case_id=pack.id, surface_id=f"pack:{pack.id}", timestamp=timestamp, command=command, git_commit="unknown", target=target, status=status, evidence_level="scaffold_static", dry_run=False, provider_calls_enabled=True, live_model_calls=0, reason=redact_public_text(reason).text, metadata=_sanitize_metadata({**metadata, "target_execution_enabled": False, "target_call_count": 0, "target_trace_count": 0, "target_artifact_count": 0, "model_behavior_failure": False, "live_system_trace": False}))


def _system_capability_gap_row(pack: ReleaseMatrixPackRef, *, run_id: str, timestamp: str, command: str, target: LiveTargetMetadata, required_target_types: set[str], actual_target_type: str, reason: str, metadata: dict[str, Any] | None = None) -> LiveEvidenceRow:
    return LiveEvidenceRow(row_id=f"pack:{pack.id}", run_id=run_id, case_id=pack.id, surface_id=f"pack:{pack.id}", timestamp=timestamp, command=command, git_commit="unknown", target=target, status="target_capability_gap", evidence_level="scaffold_static", dry_run=False, provider_calls_enabled=True, live_model_calls=0, reason=redact_public_text(reason).text, metadata=_sanitize_metadata({**_classic_pack_metadata(pack), **(metadata or {}), "required_target_types": sorted(required_target_types), "actual_target_type": actual_target_type, "target_execution_enabled": False, "target_call_count": 0, "target_trace_count": 0, "target_artifact_count": 0, "chat_completion_model_only": actual_target_type == "chat_completion", "live_system_trace": False}))


def _system_harness_artifact_refs(output_dir: Path, report_name: str) -> list[ArtifactRef]:
    refs: list[ArtifactRef] = []
    allowed_names = {report_name, f"{Path(report_name).stem}.md"}
    for path in sorted(output_dir.iterdir()) if output_dir.exists() else []:
        if not path.is_file() or path.name not in allowed_names:
            continue
        refs.append(ArtifactRef(path=path.name, kind=path.suffix.lstrip("."), artifact_type=path.stem.replace("-", "_"), sha256=_sha256_file(path), relative_path=path.name, redaction_status="redacted"))
    return refs


def _row_target_type(target: LiveTargetMetadata) -> str:
    return row_target_type(target)


def _run_visual_pack_row(
    pack: ReleaseMatrixPackRef,
    *,
    run_id: str,
    timestamp: str,
    command: str,
    target: LiveTargetMetadata,
    target_path: str | Path,
    out_dir: str | Path,
    preflight: LivePreflightReport,
) -> LiveEvidenceRow:
    pack_out = Path(out_dir) / "visual" / pack.id
    public_pack_path = _public_path(pack.path)
    visual_command = f"{command} # visual pack {pack.id} via live multimodal runner --surface {shlex.quote(public_pack_path)}"

    try:
        runner_report = run_visual_live(target_path, pack_out)
    except Exception as exc:
        return _visual_operational_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=visual_command,
            target=target,
            status="provider_error",
            reason=f"visual live pack {pack.id} failed during provider execution: {type(exc).__name__}: {exc}",
            metadata={**_classic_pack_metadata(pack, public_pack_path=public_pack_path), "output_dir": f"visual/{pack.id}", "runner_error_type": type(exc).__name__, "preflight_text_status": preflight.text_status, "preflight_visual_status": preflight.visual_status, "static_visual_lab_counted_as_live": False},
        )

    report_path = pack_out / "visual-live-report.json"
    static_report_path = pack_out / "visual-lab-report.json"
    scaffold_report_path = pack_out / "visual-run-report.json"
    invalid_live_artifact = static_report_path.exists() or scaffold_report_path.exists() or runner_report.dry_run or not runner_report.provider_calls_enabled
    if not report_path.exists() or invalid_live_artifact:
        return _visual_operational_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=visual_command,
            target=target,
            status="infra_error",
            reason=f"visual live pack {pack.id} did not produce a valid visual-live-report.json artifact" + ("; visual-lab static/scaffold artifacts cannot satisfy live-full evidence" if invalid_live_artifact else ""),
            metadata={**_classic_pack_metadata(pack, public_pack_path=public_pack_path), "output_dir": f"visual/{pack.id}", "visual_live_report_json_exists": report_path.exists(), "visual_lab_report_json_exists": static_report_path.exists(), "visual_run_report_json_exists": scaffold_report_path.exists(), "dry_run": runner_report.dry_run, "provider_calls_enabled": runner_report.provider_calls_enabled, "invalid_live_artifact": invalid_live_artifact, "preflight_text_status": preflight.text_status, "preflight_visual_status": preflight.visual_status, "static_visual_lab_counted_as_live": False},
        )

    report = VisualLiveReport.model_validate(json.loads(report_path.read_text(encoding="utf-8")))
    if report.mode != "live_provider" or report.dry_run or not report.provider_calls_enabled:
        return _visual_operational_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=visual_command,
            target=target,
            status="infra_error",
            reason=f"visual live pack {pack.id} report was not live-provider evidence; scaffold, dry-run, or provider-disabled artifacts cannot satisfy live-full evidence",
            metadata={**_classic_pack_metadata(pack, public_pack_path=public_pack_path), "output_dir": f"visual/{pack.id}", "report_mode": report.mode, "dry_run": report.dry_run, "provider_calls_enabled": report.provider_calls_enabled, "invalid_live_artifact": True, "preflight_text_status": preflight.text_status, "preflight_visual_status": preflight.visual_status, "static_visual_lab_counted_as_live": False},
        )

    if report.summary.provider_error:
        return _visual_operational_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=visual_command,
            target=target,
            status="provider_error",
            reason=f"visual live pack {pack.id} had {report.summary.provider_error} provider errors after {report.live_model_calls} completed multimodal calls",
            metadata={**_classic_pack_metadata(pack, public_pack_path=public_pack_path), "output_dir": f"visual/{pack.id}", "runner_run_id": report.run_id, "adapter_call_count": report.attempted_provider_calls, "completed_live_model_calls": report.live_model_calls, "status_counts": report.summary.status_counts, "reason_codes": report.summary.reason_codes, "report_json": f"visual/{pack.id}/visual-live-report.json", "preflight_text_status": preflight.text_status, "preflight_visual_status": preflight.visual_status, "static_visual_lab_counted_as_live": False},
        )

    return LiveEvidenceRow(
        row_id=f"pack:{pack.id}",
        run_id=run_id,
        case_id=pack.id,
        surface_id=f"pack:{pack.id}",
        timestamp=timestamp,
        command=visual_command,
        git_commit="unknown",
        target=target,
        status="passed",
        evidence_level="live_multimodal_model",
        dry_run=False,
        provider_calls_enabled=True,
        live_model_calls=report.live_model_calls,
        artifacts=_visual_artifact_refs(pack_out),
        metadata=_sanitize_metadata(
            {
                **_classic_pack_metadata(pack, public_pack_path=public_pack_path),
                "output_dir": f"visual/{pack.id}",
                "runner_run_id": report.run_id,
                "adapter_call_count": report.attempted_provider_calls,
                "completed_live_model_calls": report.live_model_calls,
                "status_counts": report.summary.status_counts,
                "reason_codes": report.summary.reason_codes,
                "image_sha256": report.image.sha256,
                "image_length": report.image.length,
                "report_json": f"visual/{pack.id}/visual-live-report.json",
                "preflight_text_status": preflight.text_status,
                "preflight_visual_status": preflight.visual_status,
                "static_visual_lab_counted_as_live": False,
                "browser_automation": False,
            }
        ),
    )


def _visual_operational_row(
    pack: ReleaseMatrixPackRef,
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
        row_id=f"pack:{pack.id}",
        run_id=run_id,
        case_id=pack.id,
        surface_id=f"pack:{pack.id}",
        timestamp=timestamp,
        command=command,
        git_commit="unknown",
        target=target,
        status=status,
        evidence_level="live_multimodal_model",
        dry_run=False,
        provider_calls_enabled=True,
        live_model_calls=0,
        reason=redact_public_text(reason).text,
        metadata=_sanitize_metadata({**metadata, "provider_error": status in {"provider_error", "timeout", "infra_error"}, "model_behavior_failure": False}),
    )


def _visual_artifact_refs(output_dir: Path) -> list[ArtifactRef]:
    refs: list[ArtifactRef] = []
    artifact_types = {"visual-live-report.json": "visual_live_report_json", "visual-live-report.md": "visual_live_report_markdown"}
    for name, artifact_type in artifact_types.items():
        path = output_dir / name
        if not path.exists():
            continue
        refs.append(
            ArtifactRef(
                path=name,
                kind=path.suffix.lstrip(".") or "artifact",
                artifact_type=artifact_type,
                sha256=_sha256_file(path),
                relative_path=name,
                redaction_status="redacted",
            )
        )
    return refs


def _run_campaign_pack_row(
    pack: ReleaseMatrixPackRef,
    *,
    run_id: str,
    timestamp: str,
    command: str,
    target: LiveTargetMetadata,
    target_path: str | Path,
    matrix_path: str | Path,
    out_dir: str | Path,
    preflight: LivePreflightReport,
) -> LiveEvidenceRow:
    pack_out = Path(out_dir) / "campaign" / pack.id
    campaign_path = _matrix_reference_path(pack.path, Path(matrix_path).resolve())
    public_pack_path = _public_path(pack.path)
    campaign_command = f"{command} # campaign pack {pack.id} via live campaign runner --campaign {shlex.quote(public_pack_path)}"

    try:
        runner_report = run_campaign_live(campaign_path, target_path, pack_out)
    except Exception as exc:
        status: LiveEvidenceStatus = "infra_error" if isinstance(exc, ValueError) else "provider_error"
        return _live_operational_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=campaign_command,
            target=target,
            status=status,
            reason=(f"campaign live pack {pack.id} failed during live runner/report validation: {type(exc).__name__}: {exc}" if status == "infra_error" else f"campaign live pack {pack.id} failed during provider setup/execution: {type(exc).__name__}: {exc}"),
            metadata={**_classic_pack_metadata(pack, public_pack_path=public_pack_path), "output_dir": f"campaign/{pack.id}", "runner_error_type": type(exc).__name__, "preflight_text_status": preflight.text_status, "dry_run_output_counted_as_live": False},
        )

    report_path = pack_out / "campaign-live-report.json"
    dry_report_path = pack_out / "campaign-report.json"
    invalid_live_artifact = dry_report_path.exists() or runner_report.dry_run or not runner_report.provider_calls_enabled
    if not report_path.exists() or invalid_live_artifact:
        return _live_operational_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=campaign_command,
            target=target,
            status="infra_error",
            reason=f"campaign live pack {pack.id} did not produce a valid campaign-live-report.json artifact" + ("; campaign dry-run artifacts cannot satisfy live-full evidence" if invalid_live_artifact else ""),
            metadata={**_classic_pack_metadata(pack, public_pack_path=public_pack_path), "output_dir": f"campaign/{pack.id}", "campaign_live_report_json_exists": report_path.exists(), "campaign_report_json_exists": dry_report_path.exists(), "dry_run": runner_report.dry_run, "provider_calls_enabled": runner_report.provider_calls_enabled, "invalid_live_artifact": invalid_live_artifact, "preflight_text_status": preflight.text_status, "dry_run_output_counted_as_live": False},
        )

    report = CampaignLiveReport.model_validate(json.loads(report_path.read_text(encoding="utf-8")))
    if report.mode != "live_provider" or report.dry_run or not report.provider_calls_enabled:
        return _live_operational_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=campaign_command,
            target=target,
            status="infra_error",
            reason=f"campaign live pack {pack.id} report was not live-provider evidence; dry-run or provider-disabled artifacts cannot satisfy live-full evidence",
            metadata={**_classic_pack_metadata(pack, public_pack_path=public_pack_path), "output_dir": f"campaign/{pack.id}", "report_mode": report.mode, "dry_run": report.dry_run, "provider_calls_enabled": report.provider_calls_enabled, "invalid_live_artifact": True, "preflight_text_status": preflight.text_status, "dry_run_output_counted_as_live": False},
        )

    if report.summary.provider_error:
        status: LiveEvidenceStatus = "provider_error"
        reason = f"campaign live pack {pack.id} had {report.summary.provider_error} provider errors after {report.live_model_calls} completed live calls"
    else:
        status = "passed" if report.summary.failed == 0 and report.summary.passed > 0 else "failed"
        reason = _campaign_failure_reason(report) if status == "failed" else None

    return LiveEvidenceRow(
        row_id=f"pack:{pack.id}",
        run_id=run_id,
        case_id=pack.id,
        surface_id=f"pack:{pack.id}",
        timestamp=timestamp,
        command=campaign_command,
        git_commit="unknown",
        target=target,
        status=status,
        evidence_level="live_text_model",
        dry_run=False,
        provider_calls_enabled=True,
        live_model_calls=report.live_model_calls,
        reason=redact_public_text(reason).text if reason else None,
        artifacts=_campaign_artifact_refs(pack_out),
        metadata=_sanitize_metadata(
            {
                **_classic_pack_metadata(pack, public_pack_path=public_pack_path),
                "output_dir": f"campaign/{pack.id}",
                "runner_run_id": report.run_id,
                "adapter_call_count": report.attempted_provider_calls,
                "completed_live_model_calls": report.live_model_calls,
                "status_counts": report.summary.status_counts,
                "reason_codes": report.summary.reason_codes,
                "executed_steps": report.summary.executed_steps,
                "bounded_steps": report.summary.bounded_steps,
                "total_planned_steps": report.summary.total_planned_steps,
                "max_steps": report.max_steps,
                "max_total_calls": report.max_total_calls,
                "failed_steps": [result.step_id for result in report.results if result.status == "failed"][:5],
                "provider_error_steps": [result.step_id for result in report.results if result.status == "provider_error"][:5],
                "report_json": f"campaign/{pack.id}/campaign-live-report.json",
                "preflight_text_status": preflight.text_status,
                "dry_run_output_counted_as_live": False,
                "state_tracking": {"canary_hashes": len(report.shared_state.get("canary_sha256", [])), "completed_steps": len(report.shared_state.get("completed_steps", [])), "canary_leak_detected": report.shared_state.get("canary_leak_detected", False)},
            }
        ),
    )


def _campaign_failure_reason(report: CampaignLiveReport) -> str:
    failed = next((result for result in report.results if result.status == "failed"), None)
    if failed is None:
        return "campaign live pack completed without passing steps"
    codes = ",".join(failed.reason_codes) if failed.reason_codes else "campaign_policy_failure"
    return f"campaign behavior failed for {failed.step_id}: {codes}"


def _campaign_artifact_refs(output_dir: Path) -> list[ArtifactRef]:
    refs: list[ArtifactRef] = []
    artifact_types = {"campaign-live-report.json": "campaign_live_report_json", "campaign-live-report.md": "campaign_live_report_markdown"}
    for name, artifact_type in artifact_types.items():
        path = output_dir / name
        if not path.exists():
            continue
        refs.append(
            ArtifactRef(
                path=name,
                kind=path.suffix.lstrip(".") or "artifact",
                artifact_type=artifact_type,
                sha256=_sha256_file(path),
                relative_path=name,
                redaction_status="redacted",
            )
        )
    return refs


def _run_ui_action_pack_row(
    pack: ReleaseMatrixPackRef,
    *,
    run_id: str,
    timestamp: str,
    command: str,
    target: LiveTargetMetadata,
    target_path: str | Path,
    matrix_path: str | Path,
    out_dir: str | Path,
    preflight: LivePreflightReport,
) -> LiveEvidenceRow:
    pack_out = Path(out_dir) / "ui-action" / pack.id
    fixture_path = _matrix_reference_path(pack.path, Path(matrix_path).resolve())
    public_pack_path = _public_path(pack.path)
    ui_command = f"{command} # UI action-choice pack {pack.id} via live text runner --fixture {shlex.quote(public_pack_path)}"

    try:
        runner_report = run_ui_action_live(target_path, fixture_path, pack_out)
    except Exception as exc:
        return _live_operational_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=ui_command,
            target=target,
            status="provider_error",
            reason=f"UI action-choice live pack {pack.id} failed during provider execution: {type(exc).__name__}: {exc}",
            metadata={**_classic_pack_metadata(pack, public_pack_path=public_pack_path), "output_dir": f"ui-action/{pack.id}", "runner_error_type": type(exc).__name__, "preflight_text_status": preflight.text_status, "scaffold_output_counted_as_live": False},
        )

    report_path = pack_out / "ui-action-live-report.json"
    scaffold_report_path = pack_out / "ui-harness-report.json"
    scaffold_plan_path = pack_out / "ui-harness-plan.json"
    invalid_live_artifact = scaffold_report_path.exists() or scaffold_plan_path.exists() or runner_report.dry_run or not runner_report.provider_calls_enabled or runner_report.browser_enabled
    if not report_path.exists() or invalid_live_artifact:
        return _live_operational_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=ui_command,
            target=target,
            status="infra_error",
            reason=f"UI action-choice live pack {pack.id} did not produce a valid ui-action-live-report.json artifact" + ("; UI scaffold artifacts or browser-enabled outputs cannot satisfy live-full evidence" if invalid_live_artifact else ""),
            metadata={**_classic_pack_metadata(pack, public_pack_path=public_pack_path), "output_dir": f"ui-action/{pack.id}", "ui_action_live_report_json_exists": report_path.exists(), "ui_harness_report_json_exists": scaffold_report_path.exists(), "ui_harness_plan_json_exists": scaffold_plan_path.exists(), "dry_run": runner_report.dry_run, "provider_calls_enabled": runner_report.provider_calls_enabled, "browser_enabled": runner_report.browser_enabled, "invalid_live_artifact": invalid_live_artifact, "preflight_text_status": preflight.text_status, "scaffold_output_counted_as_live": False},
        )

    report = UIActionLiveReport.model_validate(json.loads(report_path.read_text(encoding="utf-8")))
    if report.mode != "live_provider" or report.dry_run or not report.provider_calls_enabled or report.browser_enabled:
        return _live_operational_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=ui_command,
            target=target,
            status="infra_error",
            reason=f"UI action-choice live pack {pack.id} report was not text-only live-provider evidence; scaffold, dry-run, browser-enabled, or provider-disabled artifacts cannot satisfy live-full evidence",
            metadata={**_classic_pack_metadata(pack, public_pack_path=public_pack_path), "output_dir": f"ui-action/{pack.id}", "report_mode": report.mode, "dry_run": report.dry_run, "provider_calls_enabled": report.provider_calls_enabled, "browser_enabled": report.browser_enabled, "invalid_live_artifact": True, "preflight_text_status": preflight.text_status, "scaffold_output_counted_as_live": False},
        )

    if report.summary.provider_error:
        status: LiveEvidenceStatus = "provider_error"
        reason = f"UI action-choice live pack {pack.id} had {report.summary.provider_error} provider errors"
    else:
        status = "passed" if report.summary.failed == 0 and report.summary.passed > 0 else "failed"
        reason = _ui_action_failure_reason(report) if status == "failed" else None

    return LiveEvidenceRow(
        row_id=f"pack:{pack.id}",
        run_id=run_id,
        case_id=pack.id,
        surface_id=f"pack:{pack.id}",
        timestamp=timestamp,
        command=ui_command,
        git_commit="unknown",
        target=target,
        status=status,
        evidence_level="live_text_model",
        dry_run=False,
        provider_calls_enabled=True,
        live_model_calls=report.live_model_calls,
        reason=redact_public_text(reason).text if reason else None,
        artifacts=_ui_action_artifact_refs(pack_out),
        metadata=_sanitize_metadata(
            {
                **_classic_pack_metadata(pack, public_pack_path=public_pack_path),
                "output_dir": f"ui-action/{pack.id}",
                "runner_run_id": report.run_id,
                "adapter_call_count": report.live_model_calls,
                "status_counts": report.summary.status_counts,
                "reason_codes": report.summary.reason_codes,
                "failed_prompts": [result.prompt_id for result in report.results if result.status == "failed"][:5],
                "provider_error_prompts": [result.prompt_id for result in report.results if result.status == "provider_error"][:5],
                "report_json": f"ui-action/{pack.id}/ui-action-live-report.json",
                "preflight_text_status": preflight.text_status,
                "method": report.method,
                "browser_automation": False,
                "scaffold_output_counted_as_live": False,
            }
        ),
    )


def _ui_action_failure_reason(report: UIActionLiveReport) -> str:
    failed = next((result for result in report.results if result.status == "failed"), None)
    if failed is None:
        return "UI action-choice live pack completed without passing prompts"
    codes = ",".join(failed.reason_codes) if failed.reason_codes else "ui_action_policy_failure"
    return f"UI action-choice behavior failed for {failed.prompt_id}: {codes}"


def _ui_action_artifact_refs(output_dir: Path) -> list[ArtifactRef]:
    refs: list[ArtifactRef] = []
    artifact_types = {"ui-action-live-report.json": "ui_action_live_report_json", "ui-action-live-report.md": "ui_action_live_report_markdown"}
    for name, artifact_type in artifact_types.items():
        path = output_dir / name
        if not path.exists():
            continue
        refs.append(
            ArtifactRef(
                path=name,
                kind=path.suffix.lstrip(".") or "artifact",
                artifact_type=artifact_type,
                sha256=_sha256_file(path),
                relative_path=name,
                redaction_status="redacted",
            )
        )
    return refs


def _run_hidden_artifact_pack_row(
    pack: ReleaseMatrixPackRef,
    *,
    run_id: str,
    timestamp: str,
    command: str,
    target: LiveTargetMetadata,
    target_path: str | Path,
    matrix_path: str | Path,
    out_dir: str | Path,
    preflight: LivePreflightReport,
) -> LiveEvidenceRow:
    pack_out = Path(out_dir) / "hidden-artifact" / pack.id
    catalog_path = _matrix_reference_path(pack.path, Path(matrix_path).resolve())
    public_pack_path = _public_path(pack.path)
    hidden_command = f"{command} # hidden/artifact pack {pack.id} via live hidden-artifact runner --catalog {shlex.quote(public_pack_path)}"

    try:
        runner_report = run_hidden_artifact_live(target_path, catalog_path, pack_out)
    except Exception as exc:
        return _live_operational_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=hidden_command,
            target=target,
            status="provider_error",
            reason=f"hidden/artifact live pack {pack.id} failed during provider execution: {type(exc).__name__}: {exc}",
            metadata={**_classic_pack_metadata(pack, public_pack_path=public_pack_path), "output_dir": f"hidden-artifact/{pack.id}", "runner_error_type": type(exc).__name__, "preflight_text_status": preflight.text_status},
        )

    report_path = pack_out / "hidden-artifact-live-report.json"
    static_hidden_path = pack_out / "hidden-channel-report.json"
    static_artifact_path = pack_out / "artifact-firewall-report.json"
    invalid_live_artifact = static_hidden_path.exists() or static_artifact_path.exists() or runner_report.dry_run or not runner_report.provider_calls_enabled
    if not report_path.exists() or invalid_live_artifact:
        return _live_operational_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=hidden_command,
            target=target,
            status="infra_error",
            reason=f"hidden/artifact live pack {pack.id} did not produce a valid hidden-artifact-live-report.json artifact" + ("; static hidden-channel/artifact outputs cannot satisfy live-full evidence" if invalid_live_artifact else ""),
            metadata={**_classic_pack_metadata(pack, public_pack_path=public_pack_path), "output_dir": f"hidden-artifact/{pack.id}", "hidden_artifact_live_report_json_exists": report_path.exists(), "hidden_channel_report_json_exists": static_hidden_path.exists(), "artifact_firewall_report_json_exists": static_artifact_path.exists(), "dry_run": runner_report.dry_run, "provider_calls_enabled": runner_report.provider_calls_enabled, "invalid_live_artifact": invalid_live_artifact, "preflight_text_status": preflight.text_status},
        )

    report = HiddenArtifactLiveReport.model_validate(json.loads(report_path.read_text(encoding="utf-8")))
    if report.mode != "live_provider" or report.dry_run or not report.provider_calls_enabled:
        return _live_operational_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=hidden_command,
            target=target,
            status="infra_error",
            reason=f"hidden/artifact live pack {pack.id} report was not live-provider evidence; static, dry-run, or provider-disabled artifacts cannot satisfy live-full evidence",
            metadata={**_classic_pack_metadata(pack, public_pack_path=public_pack_path), "output_dir": f"hidden-artifact/{pack.id}", "report_mode": report.mode, "dry_run": report.dry_run, "provider_calls_enabled": report.provider_calls_enabled, "invalid_live_artifact": True, "preflight_text_status": preflight.text_status},
        )

    if report.summary.provider_error:
        status: LiveEvidenceStatus = "provider_error"
        reason = f"hidden/artifact live pack {pack.id} had {report.summary.provider_error} provider errors"
    else:
        status = "passed" if report.summary.failed == 0 and report.summary.passed > 0 else "failed"
        reason = _hidden_artifact_failure_reason(report) if status == "failed" else None

    return LiveEvidenceRow(
        row_id=f"pack:{pack.id}",
        run_id=run_id,
        case_id=pack.id,
        surface_id=f"pack:{pack.id}",
        timestamp=timestamp,
        command=hidden_command,
        git_commit="unknown",
        target=target,
        status=status,
        evidence_level="live_text_model",
        dry_run=False,
        provider_calls_enabled=True,
        live_model_calls=report.live_model_calls,
        reason=redact_public_text(reason).text if reason else None,
        artifacts=_hidden_artifact_artifact_refs(pack_out),
        metadata=_sanitize_metadata(
            {
                **_classic_pack_metadata(pack, public_pack_path=public_pack_path),
                "output_dir": f"hidden-artifact/{pack.id}",
                "runner_run_id": report.run_id,
                "adapter_call_count": report.live_model_calls,
                "status_counts": report.summary.status_counts,
                "reason_codes": report.summary.reason_codes,
                "failed_cases": [result.case_id for result in report.results if result.status == "failed"][:5],
                "provider_error_cases": [result.case_id for result in report.results if result.status == "provider_error"][:5],
                "report_json": f"hidden-artifact/{pack.id}/hidden-artifact-live-report.json",
                "preflight_text_status": preflight.text_status,
                "static_inspection_counted_as_live": False,
            }
        ),
    )


def _hidden_artifact_failure_reason(report: HiddenArtifactLiveReport) -> str:
    failed = next((result for result in report.results if result.status == "failed"), None)
    if failed is None:
        return "hidden/artifact live pack completed without passing cases"
    codes = ",".join(failed.reason_codes) if failed.reason_codes else "hidden_artifact_policy_failure"
    return f"hidden/artifact behavior failed for {failed.case_id}: {codes}"


def _hidden_artifact_artifact_refs(output_dir: Path) -> list[ArtifactRef]:
    refs: list[ArtifactRef] = []
    artifact_types = {"hidden-artifact-live-report.json": "hidden_artifact_live_report_json", "hidden-artifact-live-report.md": "hidden_artifact_live_report_markdown"}
    for name, artifact_type in artifact_types.items():
        path = output_dir / name
        if not path.exists():
            continue
        refs.append(
            ArtifactRef(
                path=name,
                kind=path.suffix.lstrip(".") or "artifact",
                artifact_type=artifact_type,
                sha256=_sha256_file(path),
                relative_path=name,
                redaction_status="redacted",
            )
        )
    return refs


def _run_rag_pack_row(
    pack: ReleaseMatrixPackRef,
    *,
    run_id: str,
    timestamp: str,
    command: str,
    target: LiveTargetMetadata,
    target_path: str | Path,
    matrix_path: str | Path,
    out_dir: str | Path,
    preflight: LivePreflightReport,
) -> LiveEvidenceRow:
    pack_out = Path(out_dir) / "rag" / pack.id
    fixture_path = _matrix_reference_path(pack.path, Path(matrix_path).resolve())
    public_pack_path = _public_path(pack.path)
    rag_command = f"{command} # RAG pack {pack.id} via live RAG runner --fixture {shlex.quote(public_pack_path)}"

    try:
        runner_report = run_rag_live(target_path, fixture_path, pack_out)
    except Exception as exc:
        return _live_operational_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=rag_command,
            target=target,
            status="provider_error",
            reason=f"RAG live pack {pack.id} failed during provider execution: {type(exc).__name__}: {exc}",
            metadata={**_classic_pack_metadata(pack, public_pack_path=public_pack_path), "output_dir": f"rag/{pack.id}", "runner_error_type": type(exc).__name__, "preflight_text_status": preflight.text_status},
        )

    report_path = pack_out / "rag-live-report.json"
    dry_report_path = pack_out / "rag-report.json"
    invalid_live_artifact = dry_report_path.exists() or runner_report.dry_run or not runner_report.provider_calls_enabled
    if not report_path.exists() or invalid_live_artifact:
        return _live_operational_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=rag_command,
            target=target,
            status="infra_error",
            reason=f"RAG live pack {pack.id} did not produce a valid rag-live-report.json artifact" + ("; local fixture artifacts cannot satisfy live-full evidence" if invalid_live_artifact else ""),
            metadata={**_classic_pack_metadata(pack, public_pack_path=public_pack_path), "output_dir": f"rag/{pack.id}", "rag_live_report_json_exists": report_path.exists(), "rag_fixture_report_json_exists": dry_report_path.exists(), "dry_run": runner_report.dry_run, "provider_calls_enabled": runner_report.provider_calls_enabled, "invalid_live_artifact": invalid_live_artifact, "preflight_text_status": preflight.text_status},
        )

    report = RagLiveReport.model_validate(json.loads(report_path.read_text(encoding="utf-8")))
    if report.mode != "live_provider" or report.dry_run or not report.provider_calls_enabled:
        return _live_operational_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=rag_command,
            target=target,
            status="infra_error",
            reason=f"RAG live pack {pack.id} report was not live-provider evidence; dry-run, fixture, or provider-disabled artifacts cannot satisfy live-full evidence",
            metadata={**_classic_pack_metadata(pack, public_pack_path=public_pack_path), "output_dir": f"rag/{pack.id}", "report_mode": report.mode, "dry_run": report.dry_run, "provider_calls_enabled": report.provider_calls_enabled, "invalid_live_artifact": True, "preflight_text_status": preflight.text_status},
        )

    if report.summary.provider_error:
        status: LiveEvidenceStatus = "provider_error"
        reason = f"RAG live pack {pack.id} had {report.summary.provider_error} provider errors"
    else:
        status = "passed" if report.summary.failed == 0 and report.summary.passed > 0 else "failed"
        reason = _rag_failure_reason(report) if status == "failed" else None

    return LiveEvidenceRow(
        row_id=f"pack:{pack.id}",
        run_id=run_id,
        case_id=pack.id,
        surface_id=f"pack:{pack.id}",
        timestamp=timestamp,
        command=rag_command,
        git_commit="unknown",
        target=target,
        status=status,
        evidence_level="live_text_model",
        dry_run=False,
        provider_calls_enabled=True,
        live_model_calls=report.live_model_calls,
        reason=redact_public_text(reason).text if reason else None,
        artifacts=_rag_artifact_refs(pack_out),
        metadata=_sanitize_metadata(
            {
                **_classic_pack_metadata(pack, public_pack_path=public_pack_path),
                "output_dir": f"rag/{pack.id}",
                "runner_run_id": report.run_id,
                "adapter_call_count": report.live_model_calls,
                "status_counts": report.summary.status_counts,
                "reason_codes": report.summary.reason_codes,
                "failed_queries": [result.query_id for result in report.results if result.status == "failed"][:5],
                "provider_error_queries": [result.query_id for result in report.results if result.status == "provider_error"][:5],
                "report_json": f"rag/{pack.id}/rag-live-report.json",
                "preflight_text_status": preflight.text_status,
            }
        ),
    )


def _rag_failure_reason(report: RagLiveReport) -> str:
    failed = next((result for result in report.results if result.status == "failed"), None)
    if failed is None:
        return "RAG live pack completed without passing queries"
    codes = ",".join(failed.reason_codes) if failed.reason_codes else "rag_policy_failure"
    return f"RAG behavior failed for {failed.query_id}: {codes}"


def _rag_artifact_refs(output_dir: Path) -> list[ArtifactRef]:
    refs: list[ArtifactRef] = []
    artifact_types = {"rag-live-report.json": "rag_live_report_json", "rag-live-report.md": "rag_live_report_markdown"}
    for name, artifact_type in artifact_types.items():
        path = output_dir / name
        if not path.exists():
            continue
        refs.append(
            ArtifactRef(
                path=name,
                kind=path.suffix.lstrip(".") or "artifact",
                artifact_type=artifact_type,
                sha256=_sha256_file(path),
                relative_path=name,
                redaction_status="redacted",
            )
        )
    return refs


def _run_agentic_pack_row(
    pack: ReleaseMatrixPackRef,
    *,
    run_id: str,
    timestamp: str,
    command: str,
    target: LiveTargetMetadata,
    target_path: str | Path,
    matrix_path: str | Path,
    out_dir: str | Path,
    preflight: LivePreflightReport,
) -> LiveEvidenceRow:
    pack_out = Path(out_dir) / "agent-lab" / pack.id
    scenarios_path = _matrix_reference_path(pack.path, Path(matrix_path).resolve())
    public_pack_path = _public_path(pack.path)
    agent_command = f"{command} # agent/tool pack {pack.id} via malleus agent-lab --scenarios {shlex.quote(public_pack_path)}"

    try:
        runner_report = run_agent_lab(target_path, scenarios_path, pack_out, dry_run=False)
    except Exception as exc:
        return _live_operational_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=agent_command,
            target=target,
            status="provider_error",
            reason=f"agent/tool live pack {pack.id} failed during provider execution: {type(exc).__name__}: {exc}",
            metadata={**_classic_pack_metadata(pack, public_pack_path=public_pack_path), "output_dir": f"agent-lab/{pack.id}", "runner_error_type": type(exc).__name__, "preflight_text_status": preflight.text_status},
        )

    report_path = pack_out / "agent-lab-report.json"
    dry_run_path = pack_out / "agent-lab-dry-run.json"
    invalid_live_artifact = dry_run_path.exists()
    if not report_path.exists() or invalid_live_artifact:
        return _live_operational_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=agent_command,
            target=target,
            status="infra_error",
            reason=f"agent/tool live pack {pack.id} did not produce a valid live agent-lab-report.json artifact" + ("; dry-run artifacts cannot satisfy live-full evidence" if invalid_live_artifact else ""),
            metadata={**_classic_pack_metadata(pack, public_pack_path=public_pack_path), "output_dir": f"agent-lab/{pack.id}", "agent_lab_report_json_exists": report_path.exists(), "agent_lab_dry_run_json_exists": dry_run_path.exists(), "invalid_live_artifact": invalid_live_artifact, "preflight_text_status": preflight.text_status},
        )

    report = AgentLabReport.model_validate(json.loads(report_path.read_text(encoding="utf-8")))
    live_calls = report.summary.total_scenarios
    status = "passed" if live_calls > 0 and report.summary.violations == 0 else "failed"
    failed_results = [result for result in report.results if result.violation or not result.passed]
    reason = _agentic_failure_reason(failed_results) if status == "failed" else None

    return LiveEvidenceRow(
        row_id=f"pack:{pack.id}",
        run_id=run_id,
        case_id=pack.id,
        surface_id=f"pack:{pack.id}",
        timestamp=timestamp,
        command=agent_command,
        git_commit="unknown",
        target=target,
        status=status,
        evidence_level="live_text_model",
        dry_run=False,
        provider_calls_enabled=True,
        live_model_calls=live_calls,
        reason=redact_public_text(reason).text if reason else None,
        artifacts=_agentic_artifact_refs(pack_out),
        metadata=_sanitize_metadata(
            {
                **_classic_pack_metadata(pack, public_pack_path=public_pack_path),
                "output_dir": f"agent-lab/{pack.id}",
                "runner_run_id": runner_report.run_id,
                "adapter_call_count": live_calls,
                "scenario_counts": {"passed": report.summary.passed, "failed": live_calls - report.summary.passed, "total": live_calls, "violations": report.summary.violations},
                "highest_risk": report.summary.highest_risk,
                "reason_codes": _agentic_reason_codes(failed_results),
                "failed_scenarios": [result.scenario_id for result in failed_results[:5]],
                "report_json": f"agent-lab/{pack.id}/agent-lab-report.json",
                "preflight_text_status": preflight.text_status,
            }
        ),
    )


def _agentic_failure_reason(failed_results: list[AgentScenarioResult]) -> str:
    if not failed_results:
        return "agent/tool live pack completed without passing scenarios"
    result = failed_results[0]
    codes = _agentic_reason_codes([result])
    code_text = ",".join(codes) if codes else "agent_tool_violation"
    return f"agent/tool behavior failed for {result.scenario_id}: {code_text}; {result.reason}"


def _agentic_reason_codes(results: list[AgentScenarioResult]) -> list[str]:
    codes: list[str] = []
    for result in results:
        reason = result.reason.lower()
        scenario_id = result.scenario_id.lower()
        if "forbidden tool" in reason or result.selected_tool:
            codes.append("forbidden_tool")
        if "approval" in reason or "approval" in scenario_id or result.attack_surface == "approval":
            codes.append("fake_approval")
        if "tool_output" in result.attack_surface or "tool-output" in scenario_id or "canary" in reason:
            codes.append("tool_output_injection")
    return sorted(set(codes))


def _agentic_artifact_refs(output_dir: Path) -> list[ArtifactRef]:
    refs: list[ArtifactRef] = []
    artifact_types = {"agent-lab-report.json": "agent_lab_report_json", "agent-lab-report.md": "agent_lab_report_markdown", "findings.json": "security_findings_json", "findings.md": "security_findings_markdown"}
    for name, artifact_type in artifact_types.items():
        path = output_dir / name
        if not path.exists():
            continue
        refs.append(
            ArtifactRef(
                path=name,
                kind=path.suffix.lstrip(".") or "artifact",
                artifact_type=artifact_type,
                sha256=_sha256_file(path),
                relative_path=name,
                redaction_status="redacted",
            )
        )
    return refs


def _run_classic_pack_row(
    pack: ReleaseMatrixPackRef,
    *,
    run_id: str,
    timestamp: str,
    command: str,
    target: LiveTargetMetadata,
    target_path: str | Path,
    matrix_path: str | Path,
    out_dir: str | Path,
    progress_callback: LiveProgressCallback | None = None,
) -> LiveEvidenceRow:
    pack_out = Path(out_dir) / "classic" / pack.id
    input_path = _matrix_reference_path(pack.path, Path(matrix_path).resolve())
    scoring_path = (Path.cwd() / DEFAULT_CLASSIC_SCORING_PATH).resolve()
    public_pack_path = _public_path(pack.path)
    pack_command = f"{command} # classic pack {pack.id} via malleus run --input {shlex.quote(public_pack_path)}"
    try:
        runner_report = run_benchmark(target_path, input_path, scoring_path, pack_out, dry_run=False, release_matrix_path=matrix_path, progress_callback=progress_callback)
    except Exception as exc:
        return _live_operational_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=pack_command,
            target=target,
            status="provider_error",
            reason=f"classic live pack {pack.id} failed during provider execution: {type(exc).__name__}: {exc}",
            metadata={**_classic_pack_metadata(pack, public_pack_path=public_pack_path), "output_dir": f"classic/{pack.id}", "runner_error_type": type(exc).__name__},
        )

    report_path = pack_out / "report.json"
    dry_run_path = pack_out / "dry-run.json"
    invalid_live_artifact = dry_run_path.exists() or runner_report.report_mode == "dry_run"
    if not report_path.exists() or invalid_live_artifact:
        return _live_operational_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=pack_command,
            target=target,
            status="infra_error",
            reason=f"classic live pack {pack.id} did not produce a valid live report.json artifact" + ("; dry-run artifacts cannot satisfy live-full evidence" if invalid_live_artifact else ""),
            metadata={**_classic_pack_metadata(pack, public_pack_path=public_pack_path), "output_dir": f"classic/{pack.id}", "report_json_exists": report_path.exists(), "dry_run_json_exists": dry_run_path.exists(), "runner_report_mode": runner_report.report_mode, "invalid_live_artifact": invalid_live_artifact},
        )

    payload = json.loads(report_path.read_text(encoding="utf-8"))
    report = type(runner_report).model_validate(payload)
    if report.report_mode == "dry_run" or report.metadata.get("dry_run") is True or report.metadata.get("provider_calls_enabled") is False:
        return _live_operational_row(
            pack,
            run_id=run_id,
            timestamp=timestamp,
            command=pack_command,
            target=target,
            status="infra_error",
            reason=f"classic live pack {pack.id} report.json was not live-provider evidence; dry-run or provider-disabled artifacts cannot satisfy live-full evidence",
            metadata={**_classic_pack_metadata(pack, public_pack_path=public_pack_path), "output_dir": f"classic/{pack.id}", "report_mode": report.report_mode, "dry_run": report.metadata.get("dry_run"), "provider_calls_enabled": report.metadata.get("provider_calls_enabled"), "invalid_live_artifact": True},
        )

    total_items = report.summary.total_items
    status = "passed" if total_items > 0 and report.summary.failed_items == 0 else "failed"
    return LiveEvidenceRow(
        row_id=f"pack:{pack.id}",
        run_id=run_id,
        case_id=pack.id,
        surface_id=f"pack:{pack.id}",
        timestamp=timestamp,
        command=pack_command,
        git_commit="unknown",
        target=target,
        status=status,
        evidence_level="live_text_model",
        dry_run=False,
        provider_calls_enabled=True,
        live_model_calls=total_items,
        artifacts=_classic_artifact_refs(pack_out),
        metadata={
            **_classic_pack_metadata(pack, public_pack_path=public_pack_path),
            "output_dir": f"classic/{pack.id}",
            "runner_run_id": report.run_id,
            "status_counts": {"passed": report.summary.passed_items, "failed": report.summary.failed_items, "total": total_items},
            "adapter_call_count": total_items,
            "score_total": report.summary.score_total,
            "max_score_total": report.summary.max_score_total,
            "report_json": f"classic/{pack.id}/report.json",
        },
    )


def _live_operational_row(
    pack: ReleaseMatrixPackRef,
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
        row_id=f"pack:{pack.id}",
        run_id=run_id,
        case_id=pack.id,
        surface_id=f"pack:{pack.id}",
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
        metadata=_sanitize_metadata({**metadata, "provider_error": status in {"provider_error", "timeout", "infra_error"}, "model_behavior_failure": False}),
    )


def _classic_pack_metadata(pack: ReleaseMatrixPackRef, *, public_pack_path: str | None = None) -> dict[str, Any]:
    return {
        "surface_name": _pack_surface_name(pack),
        "path": _sanitize_metadata(public_pack_path if public_pack_path is not None else _public_path(pack.path)),
        "matrix_status": _sanitize_metadata(pack.status),
        "matrix_evidence_level": _sanitize_metadata(pack.evidence_level),
    }


def _pack_surface_name(pack: ReleaseMatrixPackRef) -> str:
    return pack.surface_name.strip() if pack.surface_name.strip() else _human_surface_name(pack.id)


def _classic_artifact_refs(output_dir: Path) -> list[ArtifactRef]:
    refs: list[ArtifactRef] = []
    artifact_types = {
        "report.json": "run_report_json",
        "report.md": "run_report_markdown",
        "report.html": "run_report_html",
        "risk-summary.json": "risk_summary",
        "model-risk-card.md": "model_risk_card",
        "findings.json": "security_findings_json",
        "findings.md": "security_findings_markdown",
    }
    redaction_statuses = {"risk-summary.json": "not_applicable", "model-risk-card.md": "redacted", "findings.json": "redacted", "findings.md": "redacted"}
    for name, artifact_type in artifact_types.items():
        path = output_dir / name
        if not path.exists():
            continue
        refs.append(
            ArtifactRef(
                path=name,
                kind=path.suffix.lstrip(".") or "artifact",
                artifact_type=artifact_type,
                sha256=_sha256_file(path),
                relative_path=name,
                redaction_status=redaction_statuses.get(name, "unknown"),
            )
        )
    return refs


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _row_for_profile(
    profile: MutationProfile,
    profile_ref: ReleaseMatrixMutationProfileRef | None,
    *,
    run_id: str,
    timestamp: str,
    command: str,
    target: LiveTargetMetadata,
    preflight: LivePreflightReport,
    include_requested: bool,
    target_path: str | Path,
    matrix: ReleaseMatrix,
    matrix_path: str | Path,
    out_dir: str | Path,
) -> LiveEvidenceRow:
    if not include_requested:
        status = "skipped_by_operator"
        evidence_level = "scaffold_static"
        reason = f"mutation profile {profile.id} skipped because --include-deep-mutations was not supplied"
    elif _row_target_type(target) not in {"chat_completion", "vision_model"}:
        status = "target_capability_gap"
        evidence_level = "scaffold_static"
        actual_target_type = _row_target_type(target)
        reason = f"mutation profile {profile.id} requires target_type=chat_completion or vision_model for real text model mutation evidence; configured target_type={actual_target_type} requires a matching live system surface instead"
    elif not preflight.text_ready:
        status = "target_error"
        evidence_level = "scaffold_static"
        reason = f"text preflight did not pass for mutation profile {profile.id}: {preflight.text_status}"
    else:
        return _run_mutation_profile_row(
            profile,
            profile_ref,
            run_id=run_id,
            timestamp=timestamp,
            command=command,
            target=target,
            target_path=target_path,
            matrix=matrix,
            matrix_path=matrix_path,
            out_dir=out_dir,
            preflight=preflight,
        )
    return _classification_row(
        row_id=f"mutation-profile:{profile.id}",
        run_id=run_id,
        case_id=profile.id,
        surface_id=f"mutation-profile:{profile.id}",
        timestamp=timestamp,
        command=command,
        target=target,
        status=status,
        evidence_level=evidence_level,
        reason=reason,
        metadata={
            "path": _profile_public_path(profile, profile_ref),
            "mutation_count": len(profile.mutations),
            "deep": profile.deep,
            "optional": profile.optional,
            "matrix_status": profile_ref.status if profile_ref else None,
            "matrix_evidence_level": profile_ref.evidence_level if profile_ref else None,
            "preflight_text_status": preflight.text_status,
            "required_target_types": ["chat_completion", "vision_model"] if status == "target_capability_gap" else None,
            "actual_target_type": _row_target_type(target) if status == "target_capability_gap" else None,
            "mutation_model_calls_attempted": False if status == "target_capability_gap" else None,
        },
    )


def _pending_profile_row(
    profile: MutationProfile,
    profile_ref: ReleaseMatrixMutationProfileRef | None,
    *,
    run_id: str,
    timestamp: str,
    command: str,
    target: LiveTargetMetadata,
    preflight: LivePreflightReport,
) -> LiveEvidenceRow:
    reason = f"mutation profile {profile.id} was not reached before the live-full checkpoint; interruption or operator/tool timeout may have stopped the aggregate run"
    return _classification_row(
        row_id=f"mutation-profile:{profile.id}",
        run_id=run_id,
        case_id=profile.id,
        surface_id=f"mutation-profile:{profile.id}",
        timestamp=timestamp,
        command=command,
        target=target,
        status="checkpoint_not_run",
        evidence_level="scaffold_static",
        reason=reason,
        metadata={
            **_profile_metadata(profile, profile_ref),
            "checkpoint_status": "not_run",
            "checkpoint_reason": "surface_not_reached",
            "preflight_text_status": preflight.text_status,
            "provider_error": False,
            "model_behavior_failure": False,
        },
    )


def _run_mutation_profile_row(
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
) -> LiveEvidenceRow:
    return run_mutation_profile_row(
        profile,
        profile_ref,
        run_id=run_id,
        timestamp=timestamp,
        command=command,
        target=target,
        target_path=target_path,
        matrix=matrix,
        matrix_path=matrix_path,
        out_dir=out_dir,
        preflight=preflight,
        run_mutation_benchmark_fn=run_mutation_benchmark,
        matrix_reference_path_fn=_matrix_reference_path,
        sha256_file_fn=_sha256_file,
    )


def _mutation_artifact_refs(output_dir: Path) -> list[ArtifactRef]:
    return mutation_artifact_refs(output_dir, sha256_file_fn=_sha256_file)


_mutation_input_pack = mutation_input_pack
_mutation_operational_row = mutation_operational_row
_profile_display_name = profile_display_name
_profile_metadata = profile_metadata
_profile_public_path = profile_public_path
_sanitize_mutation_report = sanitize_mutation_report


def _classification_row(**kwargs: Any) -> LiveEvidenceRow:
    row = LiveEvidenceRow(git_commit="unknown", dry_run=False, provider_calls_enabled=True, live_model_calls=0, **kwargs)
    if not row.status:
        raise ValueError(f"live-full row lacks strict status: {row.row_id}")
    return row


def _canonical_live_packs(matrix: ReleaseMatrix) -> list[ReleaseMatrixPackRef]:
    return canonical_live_packs(matrix)


def _target_endpoint_url(target: TargetConfig) -> str:
    if target.target_type in {"chat_completion", "vision_model"}:
        return str(target.base_url or "unknown://target")
    for config in (target.rag_service, target.tool_agent, target.workflow_harness):
        endpoint = getattr(config, "endpoint_url", None) if config is not None else None
        if endpoint:
            return str(endpoint)
    return "none://local-subprocess"


def _preflight_for_target(target: TargetConfig, *, include_image_probe: bool, timeout: float, max_retries: int) -> LivePreflightReport:
    if target.target_type in {"chat_completion", "vision_model"}:
        return run_target_preflight(target, include_image_probe=include_image_probe, timeout=timeout, max_retries=max_retries)
    endpoint = safe_endpoint_from_url(_target_endpoint_url(target))
    return LivePreflightReport(target_name=target.name, adapter=str(target.adapter or target.target_type), model=str(target.model or target.target_type), endpoint=endpoint, text_status="passed", text_ready=True, visual_status="not_supported" if include_image_probe else None, ok=True, probes=[], metadata={"timeout_seconds": timeout, "max_retries": max_retries, "target_type": str(target.target_type), "system_harness_preflight": True})


def _build_surfaces(matrix: ReleaseMatrix, selected_profile: MutationProfile, deep_profile: MutationProfile | None) -> list[LiveSurfaceRecord]:
    surfaces = [
        LiveSurfaceRecord(
            surface_id=f"pack:{pack.id}",
            name=_pack_surface_name(pack),
            category="release_matrix_pack",
            modality="multimodal" if pack.id in VISUAL_LIVE_PACK_IDS else "unknown",
            metadata={"technical_id": pack.id, "path": _sanitize_metadata(_public_path(pack.path)), "evidence_level": pack.evidence_level, "live_model_evidence": pack.live_model_evidence},
        )
        for pack in _canonical_live_packs(matrix)
    ]
    surfaces.append(_profile_surface(selected_profile))
    if deep_profile is not None:
        surfaces.append(_profile_surface(deep_profile))
    return surfaces


def _profile_surface(profile: MutationProfile) -> LiveSurfaceRecord:
    return LiveSurfaceRecord(
        surface_id=f"mutation-profile:{profile.id}",
        name=_profile_display_name(profile),
        category="mutation_profile",
        modality="text",
        metadata={"mutation_count": len(profile.mutations), "deep": profile.deep, "default": profile.default},
    )


def _sanitize_metadata(value: Any) -> Any:
    return sanitize_metadata(value)


def _load_deep_profile(matrix: ReleaseMatrix, matrix_path: str | Path, explicit_path: str | Path | None) -> MutationProfile | None:
    if explicit_path is not None:
        return load_mutation_profile(explicit_path)
    if not matrix.deep_mutation_profiles:
        return None
    return load_mutation_profile(_matrix_reference_path(matrix.deep_mutation_profiles[0].path, Path(matrix_path).resolve()))


def _validate_profile_selection(matrix: ReleaseMatrix, selected_profile: MutationProfile, deep_profile: MutationProfile | None, include_deep_mutations: bool) -> None:
    selected_ids = {profile.id for profile in matrix.selected_mutation_profiles}
    if selected_ids and selected_profile.id not in selected_ids:
        raise ValueError(f"mutation profile {selected_profile.id} is not listed in release matrix selected profiles")
    if include_deep_mutations and deep_profile is None:
        raise ValueError("--include-deep-mutations requires a deep mutation profile in the matrix or --deep-mutation-profile")
    if deep_profile is not None:
        deep_ids = {profile.id for profile in matrix.deep_mutation_profiles}
        if deep_ids and deep_profile.id not in deep_ids:
            raise ValueError(f"deep mutation profile {deep_profile.id} is not listed in release matrix deep profiles")


def _find_profile_ref(refs: list[ReleaseMatrixMutationProfileRef], profile_id: str) -> ReleaseMatrixMutationProfileRef | None:
    for ref in refs:
        if ref.id == profile_id:
            return ref
    return None


def _matrix_reference_path(source_path: str, matrix_path: Path) -> Path:
    return matrix_reference_path(source_path, matrix_path)


def _command_text(**kwargs: Any) -> str:
    benchmark_mode = kwargs.get("benchmark_mode")
    if benchmark_mode in {"soft", "exterminatus"}:
        command_name = str(benchmark_mode)
    else:
        command_name = "live-full"
    parts: list[object] = [
        "malleus",
        "benchmark",
        command_name,
        "--target",
        _public_path(kwargs["target_path"]),
        "--matrix",
        _public_path(kwargs["matrix_path"]),
        "--mutation-profile",
        _public_path(kwargs["mutation_profile_path"]),
        "--out-dir",
        _public_path(kwargs["out_dir"]),
        "--concurrency",
        kwargs["concurrency"],
        "--request-timeout",
        kwargs["request_timeout"],
        "--max-retries",
        kwargs["max_retries"],
    ]
    if command_name == "live-full":
        parts.insert(11, "--no-dry-run")
    if command_name == "live-full" and kwargs.get("include_deep_mutations"):
        parts.append("--include-deep-mutations")
    if kwargs.get("deep_mutation_profile_path") is not None:
        parts.extend(["--deep-mutation-profile", _public_path(kwargs["deep_mutation_profile_path"])])
    return shlex.join(str(part) for part in parts)


def _public_path(value: str | Path) -> str:
    return public_path(value)


def _git_commit() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except Exception:
        return "unknown"
    commit = result.stdout.strip()
    return commit if len(commit) == 40 and all(character in "0123456789abcdef" for character in commit.lower()) else "unknown"


def _safe_output_segment(value: str) -> str:
    return safe_output_segment(value)


def _now() -> str:
    return now_iso()


def _slug(value: str) -> str:
    return slug(value)
