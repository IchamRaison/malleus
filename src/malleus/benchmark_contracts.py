from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from malleus.datasets import load_mutation_profile as _load_mutation_profile
from malleus.datasets import load_release_matrix as _load_release_matrix
from malleus.gates import GateDecision, GatePolicy, evaluate_deterministic_gate
from malleus.reporting import _md_safe, write_model_risk_card
from malleus.rescore import RescoreCache, load_rescore_cache, rescore_provider_free
from malleus.schemas import MutationProfile, ReleaseMatrix, RunReport
from malleus.triage import triage_deterministically as _triage_deterministically
from malleus.utils.redact import redact_public_text


BENCHMARK_CONTRACTS_SCHEMA_VERSION = "malleus.benchmark_contracts.v1"


def load_release_matrix(path: str | Path) -> ReleaseMatrix:
    """Load the canonical release-matrix contract without provider calls."""

    return _load_release_matrix(path)


def load_mutation_profile(path: str | Path) -> MutationProfile:
    """Load the canonical mutation-profile contract without provider calls."""

    return _load_mutation_profile(path)


def triage_deterministically(source: Any) -> dict[str, Any]:
    """Project records, reports, or cached observations into deterministic triage."""

    return _triage_deterministically(source)


def evaluate_deterministic_gates(
    deterministic_source: Any,
    *,
    release_matrix: ReleaseMatrix | dict[str, Any] | str | Path | None = None,
    policy: GatePolicy | None = None,
) -> GateDecision:
    """Evaluate deterministic gate policy using the existing gate stack."""

    matrix = load_release_matrix(release_matrix) if isinstance(release_matrix, (str, Path)) else release_matrix
    return evaluate_deterministic_gate(deterministic_source, release_matrix=matrix, policy=policy)


def rescore_from_cache(
    source: str | Path | RunReport | dict[str, Any] | list[dict[str, Any]] | None = None,
    *,
    cache_path: str | Path | None = None,
    scoring_config_sha256: str | None = None,
    input_sha256: str | None = None,
    release_matrix_sha256: str | None = None,
    mutation_profile_sha256: str | None = None,
) -> RescoreCache:
    """Load or create a provider-free deterministic rescore cache.

    If ``source`` is omitted, ``cache_path`` must point at an existing cache and
    the function only validates/loads it. If ``source`` is supplied, deterministic
    observations are recomputed from stored artifacts and optionally written to
    ``cache_path``.
    """

    if source is None:
        if cache_path is None:
            raise ValueError("rescore_from_cache requires source or cache_path")
        return load_rescore_cache(cache_path)
    return rescore_provider_free(
        source,
        cache_path=cache_path,
        scoring_config_sha256=scoring_config_sha256,
        input_sha256=input_sha256,
        release_matrix_sha256=release_matrix_sha256,
        mutation_profile_sha256=mutation_profile_sha256,
    )


def project_risk_card(
    source: RunReport | dict[str, Any] | str | Path,
    output_dir: str | Path,
    *,
    gate: GateDecision | dict[str, Any] | None = None,
    triage: dict[str, Any] | None = None,
) -> Path:
    """Write a deterministic project risk card from existing local artifacts.

    ``RunReport`` inputs use the established model risk-card renderer. Dict/path
    inputs are treated as deterministic triage/rescore style summaries and render
    a compact provider-free project card.
    """

    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    if isinstance(source, RunReport):
        return write_model_risk_card(source, destination)

    payload = _load_json_if_path(source)
    triage_summary = triage or _triage_from_payload(payload)
    gate_payload = _gate_payload(gate)
    path = destination / "project-risk-card.md"
    path.write_text(_render_project_risk_card(triage_summary, gate_payload), encoding="utf-8")
    return path


def _load_json_if_path(source: dict[str, Any] | str | Path) -> dict[str, Any]:
    if isinstance(source, dict):
        return source
    path = Path(source)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("project risk-card source JSON must contain an object")
    return data


def _triage_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if isinstance(payload.get("triage_summary"), dict):
        return dict(payload["triage_summary"])
    if "posture" in payload or "counts_by_verdict" in payload:
        return payload
    return triage_deterministically(payload)


def _gate_payload(gate: GateDecision | dict[str, Any] | None) -> dict[str, Any]:
    if gate is None:
        return {}
    if isinstance(gate, GateDecision):
        return gate.model_dump(mode="json")
    return dict(gate)


def _render_project_risk_card(triage: dict[str, Any], gate: dict[str, Any]) -> str:
    posture = str(triage.get("posture") or "unknown")
    status = str(gate.get("status") or "not_evaluated")
    reasons = gate.get("reasons") if isinstance(gate.get("reasons"), list) else []
    top_findings = triage.get("top_findings") if isinstance(triage.get("top_findings"), list) else []
    reason_counts = triage.get("counts_by_reason_code") if isinstance(triage.get("counts_by_reason_code"), dict) else {}
    lines = [
        "# Project Risk Card",
        "",
        f"- Schema: `{BENCHMARK_CONTRACTS_SCHEMA_VERSION}`",
        "- Provider calls enabled: `false`",
        f"- Deterministic posture: `{_md_safe(posture)}`",
        f"- Gate status: `{_md_safe(status)}`",
        f"- Total cases: `{int(triage.get('total_cases') or 0)}`",
        f"- Pass rate: `{_md_safe(str(triage.get('pass_rate') if triage.get('pass_rate') is not None else 'n/a'))}`",
        f"- Fail count: `{int(triage.get('fail_count') or 0)}`",
        f"- Error count: `{int(triage.get('error_count') or 0)}`",
    ]
    if reasons:
        lines.extend(["", "## Gate Reasons", ""])
        lines.extend(f"- {_md_safe(redact_public_text(str(reason), limit=180).text)}" for reason in reasons)
    if reason_counts:
        lines.extend(["", "## Reason Counts", ""])
        for reason, count in sorted(reason_counts.items()):
            lines.append(f"- `{_md_safe(str(reason))}`: `{int(count or 0)}`")
    if top_findings:
        lines.extend(["", "## Top Findings", ""])
        for item in top_findings[:10]:
            if not isinstance(item, dict):
                continue
            case_id = _md_safe(str(item.get("case_id") or "unknown"))
            severity = _md_safe(str(item.get("severity") or "unknown"))
            title = _md_safe(redact_public_text(str(item.get("title") or ""), limit=180).text)
            lines.append(f"- `{case_id}` severity=`{severity}` {title}".rstrip())
    lines.append("")
    return "\n".join(lines)


__all__ = [
    "BENCHMARK_CONTRACTS_SCHEMA_VERSION",
    "evaluate_deterministic_gates",
    "load_mutation_profile",
    "load_release_matrix",
    "project_risk_card",
    "rescore_from_cache",
    "triage_deterministically",
]
