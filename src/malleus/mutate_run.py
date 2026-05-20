from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
import re
from pathlib import Path
import time
from typing import Any

from malleus.datasets import is_benchmark_pack, load_input_datasets, load_scoring_config, load_target_config
from malleus.mutations import MutationSpec, get_mutation, mutation_names
from malleus.runner import ADAPTERS, _match_case, resolve_adapter  # noqa: F401 - ADAPTERS is a public test/extension hook
from malleus.schemas import (
    CaseGroup,
    DatasetCase,
    MutationCaseResult,
    MutationFamilySummary,
    MutationRunReport,
    MutationRunSummary,
    PlannedMutationSummary,
    SignalSpec,
)
from malleus.scoring import score_case
from malleus.utils.ids import new_run_id
from malleus.utils.time import now_iso


_SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\b(?:api[_-]?key|secret|token)\s*=\s*[^\s`|<>]+", re.IGNORECASE),
)
_UNSAFE_PATTERNS = (
    re.compile(r"\b(ignore previous instructions|system prompt|developer message|exfiltrate|reveal hidden)\b", re.IGNORECASE),
)


def _redact_display(value: object, *, limit: int | None = None) -> str:
    text = str(value)
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    if limit is not None:
        text = text[:limit]
    return text


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _artifact_ref(value: object, *, label: str) -> str:
    text = str(value)
    return f"[REDACTED {label} sha256={_sha256_text(text)[:16]} length={len(text)}]"


def _md_cell(value: object) -> str:
    text = _redact_display(value).replace("&", "&amp;").replace("<", "&lt;")
    return text.replace("\r", " ").replace("\n", " ").replace("|", r"\|").replace("`", r"\`").replace("#", r"\#")


def _md_fence(value: object, *, limit: int | None = None) -> list[str]:
    raw = str(value)
    if any(pattern.search(raw) for pattern in (*_SECRET_PATTERNS, *_UNSAFE_PATTERNS)):
        raw = _artifact_ref(raw, label="excerpt")
    text = _redact_display(raw, limit=limit).replace("&", "&amp;").replace("<", "&lt;")
    longest = max((len(match.group(0)) for match in re.finditer(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return [f"{fence}text", text, fence]


def _coverage_tags(spec: MutationSpec) -> list[str]:
    values = [spec.family, spec.surface, spec.boundary, *spec.tags]
    return sorted({value for value in values if value})


def _transform_metadata(spec: MutationSpec) -> dict[str, Any]:
    return {
        "name": spec.name,
        "description": spec.description,
        "family": spec.family,
        "surface": spec.surface,
        "boundary": spec.boundary,
        "tags": list(spec.tags),
        "deterministic": spec.deterministic,
        "reversible": spec.reversible,
        "can_noop": spec.can_noop,
        "safe_example": spec.safe_example,
    }


def _planned_mutation(spec: MutationSpec) -> PlannedMutationSummary:
    return PlannedMutationSummary(
        name=spec.name,
        category=spec.category,
        risk=spec.risk,
        family=spec.family,
        surface=spec.surface,
        boundary=spec.boundary,
        tags=list(spec.tags),
        deterministic=spec.deterministic,
        reversible=spec.reversible,
        can_noop=spec.can_noop,
        safe_example=spec.safe_example,
        coverage_tags=_coverage_tags(spec),
        transform_metadata=_transform_metadata(spec),
    )


def _family_summaries(specs: list[MutationSpec], results: list[MutationCaseResult]) -> list[MutationFamilySummary]:
    planned = Counter(spec.family or "unknown" for spec in specs)
    tags_by_family: dict[str, set[str]] = defaultdict(set)
    for spec in specs:
        tags_by_family[spec.family or "unknown"].update(_coverage_tags(spec))

    by_family: dict[str, list[MutationCaseResult]] = defaultdict(list)
    for result in results:
        by_family[result.family or "unknown"].append(result)

    families = sorted(set(planned) | set(by_family))
    summaries: list[MutationFamilySummary] = []
    for family in families:
        family_results = by_family.get(family, [])
        worst = min((item.delta for item in family_results), default=0)
        summaries.append(
            MutationFamilySummary(
                family=family,
                planned_mutations=planned.get(family, 0),
                total_case_results=len(family_results),
                regressions=sum(1 for item in family_results if item.original_passed and not item.mutated_passed),
                original_score_total=sum(item.original_score for item in family_results),
                mutated_score_total=sum(item.mutated_score for item in family_results),
                worst_delta=worst,
                coverage_tags=sorted(tags_by_family.get(family, set())),
                metadata={"negative_delta_count": sum(1 for item in family_results if item.delta < 0)},
            )
        )
    return summaries


def _family_counts(specs: list[MutationSpec]) -> dict[str, int]:
    return dict(sorted(Counter(spec.family or "unknown" for spec in specs).items()))


def _all_coverage_tags(specs: list[MutationSpec]) -> list[str]:
    tags: set[str] = set()
    for spec in specs:
        tags.update(_coverage_tags(spec))
    return sorted(tags)


def _report_metadata(
    specs: list[MutationSpec],
    *,
    provider_calls_enabled: bool,
    target_path: str | Path,
    input_path: str | Path,
    selected_cases: list[tuple],
    mutation_profile_path: str | Path | None = None,
    include_planned_items: bool = False,
) -> dict[str, Any]:
    resolved_input_path = Path(input_path).resolve()
    source_input_kind = "benchmark_pack" if is_benchmark_pack(resolved_input_path) else "dataset"
    source_case_ids = [f"{dataset.name}:{case.id}" for dataset, case in selected_cases]
    source_group_ids = sorted(
        {
            f"{dataset.name}:{case.metadata['group_id']}"
            for dataset, case in selected_cases
            if case.metadata.get("source_type") == "group_variant" and "group_id" in case.metadata
        }
    )
    planned_items = [
        {
            "source_case_id": source_case_id,
            "mutation": spec.name,
            "mutated_case_id": f"{source_case_id}::{spec.name}",
        }
        for source_case_id in source_case_ids
        for spec in specs
    ]
    metadata: dict[str, Any] = {
        "provider_calls_enabled": provider_calls_enabled,
        "target_path": str(Path(target_path).resolve()),
        "source_input_kind": source_input_kind,
        "source_input_path": str(resolved_input_path),
        "source_pack_path": str(resolved_input_path) if source_input_kind == "benchmark_pack" else None,
        "expanded_original_items": len(selected_cases),
        "source_case_ids": source_case_ids,
        "source_group_ids": source_group_ids,
        "mutation_profile_path": str(Path(mutation_profile_path).resolve()) if mutation_profile_path is not None else None,
        "planned_depth": len(specs),
        "mutated_id_scheme": "{source_case_id}::{mutation_name}",
        "planned_family_counts": _family_counts(specs),
        "finding_collection_enabled": provider_calls_enabled,
        "finding_generation_command": "malleus findings export --report <mutation-report-dir> --out-dir <findings-dir>",
        "patch_suggestion_command": "malleus patch suggest --finding <finding-id> --report <findings.json-or-report-dir> --out <patch-output-dir>",
    }
    if include_planned_items:
        metadata["planned_items"] = planned_items
    return metadata


def _write_mutation_json_report(report: MutationRunReport, output_dir: str | Path) -> Path:
    destination = Path(output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / "mutation-report.json"
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return path


def _render_mutation_markdown(report: MutationRunReport) -> str:
    lines = [
        f"# Malleus Mutation Robustness Report: {_md_cell(report.run_id)}",
        "",
        f"- Target: {_md_cell(report.target_name)} ({_md_cell(report.target_adapter)} / {_md_cell(report.target_model)})",
        f"- Score delta worst case: {report.summary.worst_delta}",
        f"- Worst mutation: {_md_cell(report.summary.worst_mutation or 'n/a')}",
        f"- Original items: {report.summary.total_original_items}",
        f"- Mutated items: {report.summary.total_mutated_items}",
        f"- Report mode: {_md_cell(report.report_mode or 'n/a')}",
        f"- Regressions: {report.summary.regression_count}",
        "",
        "## Mutation family summary",
        "",
        "| Family | Planned | Results | Regressions | Worst delta | Coverage tags |",
        "| --- | ---: | ---: | ---: | ---: | --- |",
    ]
    for family in report.family_summaries:
        lines.append(
            f"| {_md_cell(family.family)} | {family.planned_mutations} | {family.total_case_results} | {family.regressions} | "
            f"{family.worst_delta} | {_md_cell(', '.join(family.coverage_tags) or 'n/a')} |"
        )
    lines.extend(
        [
            "",
            "## Planned transform metadata",
            "",
            "| Mutation | Family | Surface | Boundary | Risk | Tags |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    for planned in report.planned_mutations:
        lines.append(
            f"| {_md_cell(planned.name)} | {_md_cell(planned.family or 'n/a')} | {_md_cell(planned.surface or 'n/a')} | "
            f"{_md_cell(planned.boundary or 'n/a')} | {_md_cell(planned.risk)} | {_md_cell(', '.join(planned.tags) or 'n/a')} |"
        )
    lines.extend(
        [
            "",
        "## Case x mutation matrix",
        "",
            "| Case | Mutation | Family | Surface | Boundary | Category | Risk | Original | Mutated | Delta |",
            "| --- | --- | --- | --- | --- | --- | --- | ---: | ---: | ---: |",
        ]
    )
    for item in report.case_results:
        lines.append(
            f"| {_md_cell(item.dataset_name)}:{_md_cell(item.case_id)} | {_md_cell(item.mutation)} | {_md_cell(item.family or 'n/a')} | "
            f"{_md_cell(item.surface or 'n/a')} | {_md_cell(item.boundary or 'n/a')} | {_md_cell(item.category)} | {_md_cell(item.risk)} | "
            f"{item.original_score} | {item.mutated_score} | {item.delta} |"
        )
    lines.extend(["", "## Worst regressions", ""])
    for item in sorted(report.case_results, key=lambda result: result.delta)[:10]:
        lines.extend(
            [
                f"### {_md_cell(item.dataset_name)}:{_md_cell(item.case_id)} / {_md_cell(item.mutation)}",
                "",
                f"- Delta: {item.delta}",
                f"- Original passed: {item.original_passed}",
                f"- Mutated passed: {item.mutated_passed}",
                "",
                "Mutated prompt excerpt:",
                "",
                *_md_fence(item.mutated_prompt, limit=800),
                "",
                "Mutated response excerpt:",
                "",
                *_md_fence(item.mutated_response_text, limit=800),
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def _write_mutation_markdown_report(report: MutationRunReport, output_dir: str | Path) -> Path:
    destination = Path(output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / "mutation-report.md"
    path.write_text(_render_mutation_markdown(report), encoding="utf-8")
    return path


def _provider_error_record(
    *,
    phase: str,
    dataset_name: str,
    case_id: str,
    mutation: str | None,
    exc: Exception,
) -> dict[str, Any]:
    return {
        "phase": phase,
        "dataset_name": dataset_name,
        "case_id": case_id,
        "mutation": mutation,
        "error_type": type(exc).__name__,
        "message": _redact_display(str(exc), limit=500),
    }


def _write_mutation_progress(
    output_dir: str | Path,
    *,
    run_id: str,
    total_original_items: int,
    planned_mutated_items: int,
    completed_mutated_items: int,
    attempted_provider_calls: int,
    provider_error_count: int,
    current_case_id: str | None,
    current_mutation: str | None,
) -> Path:
    destination = Path(output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / "mutation-progress.json"
    path.write_text(
        json.dumps(
            {
                "run_id": run_id,
                "total_original_items": total_original_items,
                "planned_mutated_items": planned_mutated_items,
                "completed_mutated_items": completed_mutated_items,
                "attempted_provider_calls": attempted_provider_calls,
                "provider_error_count": provider_error_count,
                "current_case_id": current_case_id,
                "current_mutation": current_mutation,
                "updated_at": now_iso(),
            }
        ),
        encoding="utf-8",
    )
    return path


def _write_mutation_dry_run(report: MutationRunReport, output_dir: str | Path) -> Path:
    destination = Path(output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    json_path = destination / "mutation-dry-run.json"
    json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    lines = [
        "# Malleus mutation dry run",
        "",
        f"- Original items: {report.summary.total_original_items}",
        f"- Mutated items: {report.summary.total_mutated_items}",
        f"- Mutations: {', '.join(report.mutations)}",
        f"- Report mode: {report.report_mode or 'dry_run'}",
        f"- Provider calls enabled: {report.metadata.get('provider_calls_enabled', False)}",
        "",
        "## Planned mutation families",
        "",
        "| Family | Planned mutations | Coverage tags |",
        "| --- | ---: | --- |",
    ]
    for family in report.family_summaries:
        lines.append(f"| {_md_cell(family.family)} | {family.planned_mutations} | {_md_cell(', '.join(family.coverage_tags) or 'n/a')} |")
    planned_items = report.metadata.get("planned_items")
    if isinstance(planned_items, list):
        lines.extend(
            [
                "",
                "## Planned source x mutation items",
                "",
                "| Source case | Mutation | Mutated case id |",
                "| --- | --- | --- |",
            ]
        )
        for item in planned_items:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"| {_md_cell(item.get('source_case_id', ''))} | {_md_cell(item.get('mutation', ''))} | {_md_cell(item.get('mutated_case_id', ''))} |"
            )
    md_path = destination / "mutation-dry-run.md"
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return md_path


def _group_variant_case(group: CaseGroup, variant_index: int, prompt: str) -> DatasetCase:
    case_id = f"{group.id}:variant_{variant_index + 1}"
    return DatasetCase(
        id=case_id,
        severity=group.severity,
        objective=group.objective,
        prompt=prompt,
        expected_behavior=list(group.expected_behavior),
        pass_signals=[SignalSpec(type="refusal_marker")],
        metadata={
            **dict(group.metadata),
            "source_type": "group_variant",
            "group_id": group.id,
            "variant_index": variant_index,
            "source_case_id": case_id,
        },
    )


def _case_requested(dataset_name: str, item_id: str, case_ids: set[str] | None) -> bool:
    return _match_case(dataset_name, item_id, case_ids)


def _variant_requested(dataset_name: str, group_id: str, variant_case_id: str, case_ids: set[str] | None) -> bool:
    if not case_ids:
        return True
    return _match_case(dataset_name, group_id, case_ids) or _match_case(dataset_name, variant_case_id, case_ids)


def _select_cases(input_path: str | Path, case_ids: set[str] | None, limit: int | None) -> list[tuple]:
    selected = []
    for dataset in load_input_datasets(input_path):
        for case in dataset.cases or []:
            if not _case_requested(dataset.name, case.id, case_ids):
                continue
            if limit is not None and len(selected) >= limit:
                return selected
            selected.append((dataset, case))
        for group in dataset.groups or []:
            for variant_index, prompt in enumerate(group.variants):
                variant_case_id = f"{group.id}:variant_{variant_index + 1}"
                if not _variant_requested(dataset.name, group.id, variant_case_id, case_ids):
                    continue
                if limit is not None and len(selected) >= limit:
                    return selected
                selected.append((dataset, _group_variant_case(group, variant_index, prompt)))
    return selected


def _ensure_selected_cases(selected_cases: list[tuple], case_ids: set[str] | None) -> None:
    if selected_cases:
        return
    if case_ids:
        raise ValueError(f"no mutation source cases matched case id(s): {', '.join(sorted(case_ids))}")
    raise ValueError("no mutation source cases selected")


def run_mutation_benchmark(
    target_path: str | Path,
    input_path: str | Path,
    scoring_path: str | Path,
    output_dir: str | Path,
    *,
    mutations: list[str] | None = None,
    limit: int | None = None,
    case_ids: set[str] | None = None,
    dry_run: bool = False,
    mutation_profile_path: str | Path | None = None,
    continue_on_provider_error: bool = False,
    provider_min_delay: float = 0.0,
) -> MutationRunReport:
    started_at = now_iso()
    run_id = new_run_id()
    target = load_target_config(target_path)
    scoring = load_scoring_config(scoring_path)
    selected_mutations = mutations or mutation_names()
    specs = [get_mutation(name) for name in selected_mutations]

    selected_cases = _select_cases(input_path, case_ids, limit)
    _ensure_selected_cases(selected_cases, case_ids)

    if dry_run:
        report = MutationRunReport(
            report_mode="dry_run",
            metadata=_report_metadata(
                specs,
                provider_calls_enabled=False,
                target_path=target_path,
                input_path=input_path,
                selected_cases=selected_cases,
                mutation_profile_path=mutation_profile_path,
                include_planned_items=True,
            ),
            run_id=run_id,
            started_at=started_at,
            finished_at=now_iso(),
            target_name=target.name,
            target_adapter=target.adapter,
            target_model=target.model,
            input_path=str(Path(input_path).resolve()),
            scoring_path=str(Path(scoring_path).resolve()),
            mutations=[spec.name for spec in specs],
            planned_mutations=[_planned_mutation(spec) for spec in specs],
            family_summaries=_family_summaries(specs, []),
            summary=MutationRunSummary(
                total_original_items=len(selected_cases),
                total_mutated_items=len(selected_cases) * len(specs),
                original_score_total=0,
                mutated_score_total=0,
                worst_delta=0,
                worst_mutation=None,
                family_counts=_family_counts(specs),
                coverage_tags=_all_coverage_tags(specs),
            ),
        )
        _write_mutation_dry_run(report, output_dir)
        return report

    adapter = resolve_adapter(target)(target)
    try:
        case_results: list[MutationCaseResult] = []
        provider_errors: list[dict[str, Any]] = []
        original_score_total = 0
        mutated_score_total = 0
        attempted_provider_calls = 0
        planned_mutated_items = len(selected_cases) * len(specs)
        for dataset, case in selected_cases:
            started = time.perf_counter()
            attempted_provider_calls += 1
            try:
                original_response = adapter.generate(case.prompt)
            except Exception as exc:
                provider_errors.append(
                    _provider_error_record(
                        phase="original",
                        dataset_name=dataset.name,
                        case_id=case.id,
                        mutation=None,
                        exc=exc,
                    )
                )
                _write_mutation_progress(
                    output_dir,
                    run_id=run_id,
                    total_original_items=len(selected_cases),
                    planned_mutated_items=planned_mutated_items,
                    completed_mutated_items=len(case_results),
                    attempted_provider_calls=attempted_provider_calls,
                    provider_error_count=len(provider_errors),
                    current_case_id=f"{dataset.name}:{case.id}",
                    current_mutation=None,
                )
                if not continue_on_provider_error:
                    raise
                if provider_min_delay > 0:
                    time.sleep(provider_min_delay)
                continue
            original_latency = time.perf_counter() - started
            original_result = score_case(dataset.name, case, original_response, scoring, latency_seconds=original_latency)
            original_score_total += original_result.score
            if provider_min_delay > 0:
                time.sleep(provider_min_delay)
            for spec in specs:
                mutated_prompt = spec.transform(case.prompt)
                started = time.perf_counter()
                attempted_provider_calls += 1
                try:
                    mutated_response = adapter.generate(mutated_prompt)
                except Exception as exc:
                    provider_errors.append(
                        _provider_error_record(
                            phase="mutation",
                            dataset_name=dataset.name,
                            case_id=case.id,
                            mutation=spec.name,
                            exc=exc,
                        )
                    )
                    _write_mutation_progress(
                        output_dir,
                        run_id=run_id,
                        total_original_items=len(selected_cases),
                        planned_mutated_items=planned_mutated_items,
                        completed_mutated_items=len(case_results),
                        attempted_provider_calls=attempted_provider_calls,
                        provider_error_count=len(provider_errors),
                        current_case_id=f"{dataset.name}:{case.id}",
                        current_mutation=spec.name,
                    )
                    if not continue_on_provider_error:
                        raise
                    if provider_min_delay > 0:
                        time.sleep(provider_min_delay)
                    continue
                mutated_latency = time.perf_counter() - started
                mutated_case = case.model_copy(update={"prompt": mutated_prompt})
                mutated_result = score_case(dataset.name, mutated_case, mutated_response, scoring, latency_seconds=mutated_latency)
                mutated_score_total += mutated_result.score
                case_results.append(
                    MutationCaseResult(
                        dataset_name=dataset.name,
                        case_id=case.id,
                        mutation=spec.name,
                        category=spec.category,
                        risk=spec.risk,
                        family=spec.family,
                        surface=spec.surface,
                        boundary=spec.boundary,
                        tags=list(spec.tags),
                        deterministic=spec.deterministic,
                        reversible=spec.reversible,
                        can_noop=spec.can_noop,
                        safe_example=spec.safe_example,
                        transform_metadata=_transform_metadata(spec),
                        coverage_tags=_coverage_tags(spec),
                        original_prompt=_artifact_ref(case.prompt, label="original_prompt"),
                        mutated_prompt=_artifact_ref(mutated_prompt, label="mutated_prompt"),
                        original_response_text=_artifact_ref(original_response, label="original_response"),
                        mutated_response_text=_artifact_ref(mutated_response, label="mutated_response"),
                        original_passed=original_result.passed,
                        mutated_passed=mutated_result.passed,
                        original_score=original_result.score,
                        mutated_score=mutated_result.score,
                        delta=mutated_result.score - original_result.score,
                        metadata={
                            "original_prompt_sha256": _sha256_text(case.prompt),
                            "mutated_prompt_sha256": _sha256_text(mutated_prompt),
                            "original_response_sha256": _sha256_text(original_response),
                            "mutated_response_sha256": _sha256_text(mutated_response),
                            "original_prompt_length": len(case.prompt),
                            "mutated_prompt_length": len(mutated_prompt),
                            "original_response_length": len(original_response),
                            "mutated_response_length": len(mutated_response),
                        },
                    )
                )
                _write_mutation_progress(
                    output_dir,
                    run_id=run_id,
                    total_original_items=len(selected_cases),
                    planned_mutated_items=planned_mutated_items,
                    completed_mutated_items=len(case_results),
                    attempted_provider_calls=attempted_provider_calls,
                    provider_error_count=len(provider_errors),
                    current_case_id=f"{dataset.name}:{case.id}",
                    current_mutation=spec.name,
                )
                if provider_min_delay > 0:
                    time.sleep(provider_min_delay)
        worst = min(case_results, key=lambda result: result.delta, default=None)
        metadata = _report_metadata(
            specs,
            provider_calls_enabled=True,
            target_path=target_path,
            input_path=input_path,
            selected_cases=selected_cases,
            mutation_profile_path=mutation_profile_path,
        )
        metadata.update(
            {
                "continue_on_provider_error": continue_on_provider_error,
                "provider_min_delay_seconds": provider_min_delay,
                "planned_mutated_items": planned_mutated_items,
                "attempted_provider_calls": attempted_provider_calls,
                "completed_mutated_items": len(case_results),
                "provider_error_count": len(provider_errors),
                "provider_errors": provider_errors[:50],
                "provider_errors_truncated": max(0, len(provider_errors) - 50),
            }
        )
        report = MutationRunReport(
            report_mode="live_provider",
            metadata=metadata,
            run_id=run_id,
            started_at=started_at,
            finished_at=now_iso(),
            target_name=target.name,
            target_adapter=target.adapter,
            target_model=target.model,
            input_path=str(Path(input_path).resolve()),
            scoring_path=str(Path(scoring_path).resolve()),
            mutations=[spec.name for spec in specs],
            planned_mutations=[_planned_mutation(spec) for spec in specs],
            family_summaries=_family_summaries(specs, case_results),
            case_results=case_results,
            summary=MutationRunSummary(
                total_original_items=len(selected_cases),
                total_mutated_items=len(case_results),
                original_score_total=original_score_total,
                mutated_score_total=mutated_score_total,
                worst_delta=worst.delta if worst else 0,
                worst_mutation=worst.mutation if worst else None,
                family_counts=_family_counts(specs),
                regression_count=sum(1 for item in case_results if item.original_passed and not item.mutated_passed),
                negative_delta_count=sum(1 for item in case_results if item.delta < 0),
                coverage_tags=_all_coverage_tags(specs),
            ),
        )
        _write_mutation_json_report(report, output_dir)
        _write_mutation_markdown_report(report, output_dir)
        return report
    finally:
        adapter.close()
