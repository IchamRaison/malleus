from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from malleus.live_evidence import LiveEvidenceMatrix
from malleus.live_surfaces.common import sanitize_metadata


def write_soft_mode_marker(evidence: LiveEvidenceMatrix, out_dir: str | Path) -> dict[str, Path]:
    destination = Path(out_dir)
    destination.mkdir(parents=True, exist_ok=True)
    payload = sanitize_metadata(
        {
            "schema_version": "malleus.soft_benchmark_mode.v1",
            "benchmark_mode": "soft",
            "mode": "soft",
            "dry_run": False,
            "provider_calls_enabled": True,
            "operator_confirmed": bool(evidence.metadata.get("operator_confirmed", False)),
            "matrix_id": evidence.matrix_id,
            "matrix_path": evidence.metadata.get("matrix_path"),
            "release_matrix_version": evidence.metadata.get("release_matrix_version"),
            "mutation_profile": evidence.metadata.get("selected_mutation_profile", "selected-v1"),
            "mutation_profile_path": evidence.metadata.get("selected_mutation_profile_path"),
            "include_deep_mutations": False,
            "visual_requires_preflight_support": True,
            "browser_automation": False,
            "live_vs_static_contract": "dry-run, static, scaffold, simulated, and provider-free artifacts cannot satisfy live model behavior evidence",
            "provider_error_contract": "provider_error, timeout, infra_error, provider_capability_gap, target_capability_gap, target_config_error, target_error, skipped_by_operator, and checkpoint_not_run are operational/coverage outcomes, not model behavior failures",
            "preflight": evidence.metadata.get("preflight", {}),
            "total_rows": len(evidence.rows),
        }
    )
    json_path = destination / "SOFT_BENCHMARK_MODE.json"
    markdown_path = destination / "SOFT_BENCHMARK_MODE.md"
    json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    markdown_path.write_text(render_soft_mode_marker_markdown(payload), encoding="utf-8")
    return {"json": json_path, "markdown": markdown_path}


def render_soft_mode_marker_markdown(payload: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Malleus soft benchmark mode",
            "",
            "- Benchmark mode: soft",
            f"- Dry run: {str(payload.get('dry_run', False)).lower()}",
            f"- Provider calls enabled: {str(payload.get('provider_calls_enabled', True)).lower()}",
            f"- Operator confirmed: {str(payload.get('operator_confirmed', False)).lower()}",
            f"- Include deep mutations: {str(payload.get('include_deep_mutations', False)).lower()}",
            f"- Visual requires preflight support: {str(payload.get('visual_requires_preflight_support', True)).lower()}",
            f"- Browser automation: {str(payload.get('browser_automation', False)).lower()}",
            "",
            "Soft mode is the serious/default live benchmark wrapper. It reuses the live-full evidence contract while excluding optional deep mutations by default.",
            "Dry-run, static, scaffold, simulated, and provider-free artifacts do not count as live model behavior evidence.",
            "Provider/server problems remain operational outcomes and are not counted as model safety failures.",
            "",
        ]
    )


def write_exterminatus_mode_marker(evidence: LiveEvidenceMatrix, out_dir: str | Path) -> dict[str, Path]:
    destination = Path(out_dir)
    destination.mkdir(parents=True, exist_ok=True)
    payload = sanitize_metadata(
        {
            "schema_version": "malleus.exterminatus_benchmark_mode.v1",
            "benchmark_mode": "exterminatus",
            "mode": "exhaustive_live_full",
            "exhaustive": True,
            "dry_run": False,
            "provider_calls_enabled": True,
            "operator_confirmed": bool(evidence.metadata.get("operator_confirmed", False)),
            "matrix_id": evidence.matrix_id,
            "matrix_path": evidence.metadata.get("matrix_path"),
            "release_matrix_version": evidence.metadata.get("release_matrix_version"),
            "mutation_profile": evidence.metadata.get("selected_mutation_profile", "selected-v1"),
            "mutation_profile_path": evidence.metadata.get("selected_mutation_profile_path"),
            "include_deep_mutations": True,
            "deep_mutation_profile": evidence.metadata.get("deep_mutation_profile"),
            "deep_mutation_profile_path": evidence.metadata.get("deep_mutation_profile_path"),
            "unsupported_surfaces_explicit": True,
            "deferred_surfaces_explicit": True,
            "visual_requires_preflight_support": True,
            "browser_automation": False,
            "live_vs_static_contract": evidence.metadata.get("live_vs_static_contract"),
            "provider_error_contract": evidence.metadata.get("provider_error_contract"),
            "preflight": evidence.metadata.get("preflight", {}),
            "total_rows": len(evidence.rows),
        }
    )
    json_path = destination / "EXTERMINATUS_BENCHMARK_MODE.json"
    markdown_path = destination / "EXTERMINATUS_BENCHMARK_MODE.md"
    json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    markdown_path.write_text(render_exterminatus_mode_marker_markdown(payload), encoding="utf-8")
    return {"json": json_path, "markdown": markdown_path}


def render_exterminatus_mode_marker_markdown(payload: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Malleus exhaustive benchmark mode",
            "",
            "- Benchmark mode: exterminatus",
            f"- Exhaustive: {str(payload.get('exhaustive', True)).lower()}",
            f"- Dry run: {str(payload.get('dry_run', False)).lower()}",
            f"- Provider calls enabled: {str(payload.get('provider_calls_enabled', True)).lower()}",
            f"- Operator confirmed: {str(payload.get('operator_confirmed', False)).lower()}",
            f"- Include deep mutations: {str(payload.get('include_deep_mutations', True)).lower()}",
            f"- Unsupported surfaces explicit: {str(payload.get('unsupported_surfaces_explicit', True)).lower()}",
            f"- Deferred surfaces explicit: {str(payload.get('deferred_surfaces_explicit', True)).lower()}",
            "",
            "This exhaustive mode reuses the live-full evidence contract with the canonical release matrix, selected mutation profile, and deep mutation profile enabled.",
            "Dry-run, static, scaffold, simulated, and provider-free artifacts do not count as live model behavior evidence.",
            "Provider/server problems remain operational outcomes and are not counted as model safety failures.",
            "",
        ]
    )
