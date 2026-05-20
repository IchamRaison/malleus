from __future__ import annotations

import json
import hashlib
import re
import subprocess
from pathlib import Path
import time
from typing import Any, Callable, Iterable
from urllib.parse import urlparse

from malleus.adapters.base import BaseAdapter
from malleus.events import EventLogger
from malleus.findings import collect_findings, write_finding_artifacts
from malleus.gates import write_risk_summary
from malleus.ir import ArtifactRef, CaseRef, ProviderError, ReportManifest, RunManifest, SuiteRef
from malleus.compare import write_comparison_report
from malleus.datasets import load_input_datasets, load_scoring_config, load_target_config
from malleus.registry import adapter_registry
from malleus.reporting import _md_safe, write_html_report, write_json_report, write_markdown_report, write_model_risk_card, write_report_manifest
from malleus.schemas import CaseResult, DatasetFile, DatasetReport, DatasetSummary, GroupResult, RunReport, RunSummary, TargetConfig
from malleus.scoring import score_case, score_group
from malleus.statistics import RepeatedCaseSummary, summarize_case_samples, summarize_repeated_run
from malleus.utils.ids import new_run_id
from malleus.utils.time import now_iso

ADAPTERS: dict[str, type[BaseAdapter]] = adapter_registry.items()


def resolve_adapter(target: TargetConfig) -> type[BaseAdapter]:
    try:
        return adapter_registry.get(target.adapter)
    except ValueError as exc:
        raise NotImplementedError(str(exc)) from exc


def _summarize_dataset(case_count: int, group_count: int, passed: int, score_total: int, max_score: int) -> DatasetSummary:
    total_items = case_count + group_count
    return DatasetSummary(
        total_items=total_items,
        passed_items=passed,
        failed_items=total_items - passed,
        score_total=score_total,
        max_score_total=total_items * max_score,
    )


def _match_case(dataset_name: str, item_id: str, case_ids: set[str] | None) -> bool:
    return not case_ids or item_id in case_ids or f"{dataset_name}:{item_id}" in case_ids


def _limit_reached(processed: int, limit: int | None) -> bool:
    return limit is not None and processed >= limit


def _write_manifest(manifest: RunManifest, output_dir: str | Path) -> Path:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "manifest.json"
    path.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")
    return path


_ARTIFACT_TYPES = {
    "events.jsonl": "event_log",
    "dry-run.json": "dry_run_report",
    "dry-run.md": "dry_run_markdown",
    "report.json": "run_report_json",
    "report.md": "run_report_markdown",
    "report.html": "run_report_html",
    "risk-summary.json": "risk_summary",
    "model-risk-card.md": "model_risk_card",
    "findings.json": "security_findings_json",
    "findings.md": "security_findings_markdown",
    "report-manifest.json": "report_manifest",
    "repeated-summary.json": "repeated_run_summary",
}

_REDACTION_STATUSES = {
    "events.jsonl": "not_applicable",
    "risk-summary.json": "not_applicable",
    "report-manifest.json": "not_applicable",
    "model-risk-card.md": "redacted",
    "findings.json": "redacted",
    "findings.md": "redacted",
    "repeated-summary.json": "redacted",
}

_SECRET_VALUE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{12,}\b"),
    re.compile(r"\bMALLEUS-CANARY-[A-Za-z0-9_-]+\b", re.IGNORECASE),
    re.compile(r"\bWOWPP-CANARY-[A-Za-z0-9_-]+\b", re.IGNORECASE),
    re.compile(r"\bWOWPPSECRET\b", re.IGNORECASE),
    re.compile(r"\b(?:api[_ -]?key|secret|token|password|credential|bearer|canary)\s*[:=]\s*[^\s`|<>]+", re.IGNORECASE),
)
_SECRET_ARG_NAMES = re.compile(r"(?:api[_-]?key|secret|token|password|credential|bearer|canary|access[_-]?key)", re.IGNORECASE)


def _sha256(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _json_hash(payload: dict[str, Any]) -> str:
    data = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    return hashlib.sha256(data).hexdigest()


def _base_url_metadata(base_url: str) -> dict[str, str]:
    parsed = urlparse(base_url)
    host = parsed.netloc or urlparse(f"//{base_url}").netloc or "unknown"
    return {"host": host, "sha256": _sha256_text(base_url)}


def _target_config_hash(target: TargetConfig) -> str:
    return _json_hash(
        {
            "name": target.name,
            "adapter": target.adapter,
            "model": target.model,
            "base_url": target.base_url,
        }
    )


def _safe_scalar(value: object) -> object:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    text = str(value)
    for pattern in _SECRET_VALUE_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    text = text.replace("\r", " ").replace("\n", " ")
    return text[:240] + ("…" if len(text) > 240 else "")


def _sanitize_cli_argv(argv: Iterable[object] | None) -> list[str]:
    if argv is None:
        return []
    sanitized: list[str] = []
    redact_next = False
    for raw in argv:
        arg = str(raw)
        if redact_next:
            sanitized.append("[REDACTED]")
            redact_next = False
            continue
        if arg.startswith("--"):
            name, sep, value = arg.partition("=")
            if _SECRET_ARG_NAMES.search(name):
                sanitized.append(f"{name}=[REDACTED]" if sep else name)
                redact_next = not sep
                continue
        redacted = str(_safe_scalar(arg))
        if redacted != arg:
            sanitized.append(redacted)
        elif _SECRET_ARG_NAMES.fullmatch(arg.lstrip("-")):
            sanitized.append(arg)
            redact_next = True
        else:
            sanitized.append(arg)
    return sanitized


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
    return commit if re.fullmatch(r"[0-9a-f]{40}", commit) else "unknown"


def _path_hash_metadata(path: str | Path | None) -> dict[str, str | None] | None:
    if path is None:
        return None
    resolved = Path(path).resolve()
    return {
        "path_sha256": _sha256_text(str(resolved)),
        "sha256": _sha256(resolved),
    }


def _release_matrix_metadata(path: str | Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    resolved = Path(path).resolve()
    payload: dict[str, Any] = {"path_sha256": _sha256_text(str(resolved)), "sha256": _sha256(resolved)}
    if resolved.exists() and resolved.is_file():
        try:
            import yaml

            data = yaml.safe_load(resolved.read_text(encoding="utf-8")) or {}
        except Exception:
            data = {}
        if isinstance(data, dict):
            for source, destination in (("id", "id"), ("matrix_id", "id"), ("version", "version")):
                if data.get(source) is not None and destination not in payload:
                    payload[destination] = _safe_scalar(data[source])
    return payload


def _run_metadata(
    *,
    target: TargetConfig,
    input_path: str | Path,
    scoring_path: str | Path,
    dry_run: bool,
    cli_argv: Iterable[object] | None = None,
    mutation_profile_path: str | Path | None = None,
    release_matrix_path: str | Path | None = None,
) -> dict[str, Any]:
    request = target.request
    seed = target.metadata.get("seed", getattr(request, "seed", None)) if isinstance(target.metadata, dict) else getattr(request, "seed", None)
    metadata: dict[str, Any] = {
        "model_id": _safe_scalar(target.model),
        "adapter": _safe_scalar(target.adapter),
        "provider": _safe_scalar(target.adapter),
        "base_url": _base_url_metadata(target.base_url),
        "request": {
            "temperature": request.temperature,
            "top_p": request.top_p,
            "max_tokens": request.max_tokens,
        },
        "git_commit": _git_commit(),
        "target_config_hash": _target_config_hash(target),
        "scoring_config": _path_hash_metadata(scoring_path),
        "scenario_input": _path_hash_metadata(input_path),
        "timestamp": now_iso(),
        "dry_run": dry_run,
        "provider_calls_enabled": not dry_run,
    }
    if seed is not None:
        metadata["request"]["seed"] = _safe_scalar(seed)
    sanitized_argv = _sanitize_cli_argv(cli_argv)
    if sanitized_argv:
        metadata["cli_argv"] = sanitized_argv
    mutation_profile = _path_hash_metadata(mutation_profile_path)
    if mutation_profile is not None:
        metadata["mutation_profile"] = mutation_profile
    release_matrix = _release_matrix_metadata(release_matrix_path)
    if release_matrix is not None:
        metadata["release_matrix"] = release_matrix
    return metadata


def _artifact_refs(paths: Iterable[str], output_dir: str | Path | None = None) -> list[ArtifactRef]:
    refs: list[ArtifactRef] = []
    base = Path(output_dir).resolve() if output_dir is not None else None
    for path in paths:
        artifact_path = Path(path)
        absolute_path = (base / artifact_path).resolve() if base is not None and not artifact_path.is_absolute() else artifact_path.resolve()
        relative_path = str(artifact_path) if not artifact_path.is_absolute() else str(absolute_path.relative_to(base)) if base and absolute_path.is_relative_to(base) else str(artifact_path)
        refs.append(
            ArtifactRef(
                path=relative_path,
                kind=artifact_path.suffix.lstrip(".") or "artifact",
                artifact_type=_ARTIFACT_TYPES.get(relative_path, artifact_path.stem.replace("-", "_") or "artifact"),
                sha256=_sha256(absolute_path),
                relative_path=relative_path,
                redaction_status=_REDACTION_STATUSES.get(relative_path, "unknown"),
            )
        )
    return refs


def _write_report_manifest(run_id: str, output_dir: str | Path, artifact_paths: Iterable[str]) -> Path:
    artifact_refs = _artifact_refs(artifact_paths, output_dir)
    report_manifest = ReportManifest(run_id=run_id, report_type="malleus_run", artifacts=artifact_refs)
    return write_report_manifest(report_manifest, output_dir)


def _case_ref(dataset: DatasetFile, item: object, item_type: str) -> CaseRef:
    return CaseRef(
        dataset_name=dataset.name,
        item_id=getattr(item, "id"),
        item_type=item_type,  # type: ignore[arg-type]
        severity=getattr(item, "severity", None),
        objective=getattr(item, "objective", None),
    )


def _suite_refs(datasets: list[DatasetFile]) -> list[SuiteRef]:
    return [
        SuiteRef(
            dataset_name=dataset.name,
            category=dataset.category,
            subcategory=dataset.subcategory,
            source_path=dataset.source_path,
        )
        for dataset in datasets
    ]


def _selected_case_refs(datasets: list[DatasetFile], case_ids: set[str] | None, limit: int | None) -> list[CaseRef]:
    selected: list[CaseRef] = []
    processed_total = 0
    for dataset in datasets:
        remaining = None if limit is None else max(limit - processed_total, 0)
        cases, groups, processed = _filtered_dataset(dataset, case_ids, remaining)
        selected.extend(_case_ref(dataset, case, "case") for case in cases)
        selected.extend(_case_ref(dataset, group, "group") for group in groups)
        processed_total += processed
        if _limit_reached(processed_total, limit):
            break
    return selected


def _new_manifest(
    *,
    run_id: str,
    target: TargetConfig,
    input_path: str | Path,
    scoring_path: str | Path,
    output_dir: str | Path,
    dry_run: bool,
    datasets: list[DatasetFile],
    selected_cases: list[CaseRef],
    metadata: dict[str, Any] | None = None,
) -> RunManifest:
    return RunManifest(
        run_id=run_id,
        target_name=target.name,
        target_adapter=target.adapter,
        target_model=target.model,
        input_path=str(Path(input_path).resolve()),
        scoring_path=str(Path(scoring_path).resolve()),
        output_dir=str(Path(output_dir).resolve()),
        dry_run=dry_run,
        selected_item_count=len(selected_cases),
        suites=_suite_refs(datasets),
        selected_cases=selected_cases,
        artifacts=_artifact_refs(["events.jsonl"], output_dir),
        metadata=dict(metadata or {}),
    )


def _emit_selected_cases(events: EventLogger, run_id: str, selected_cases: list[CaseRef]) -> None:
    for ref in selected_cases:
        events.emit("case_selected", run_id, case=ref.model_dump())


def enumerate_items(input_path: str | Path) -> list[str]:
    items: list[str] = []
    for dataset in load_input_datasets(input_path):
        for case in dataset.cases or []:
            items.append(f"{dataset.name}:{case.id}")
        for group in dataset.groups or []:
            items.append(f"{dataset.name}:{group.id}")
    return items


def _filtered_dataset(dataset: DatasetFile, case_ids: set[str] | None, remaining: int | None) -> tuple[list, list, int]:
    cases = []
    groups = []
    processed = 0
    for case in dataset.cases or []:
        if _match_case(dataset.name, case.id, case_ids):
            if _limit_reached(processed, remaining):
                break
            cases.append(case)
            processed += 1
    if remaining is None or processed < remaining:
        for group in dataset.groups or []:
            if _match_case(dataset.name, group.id, case_ids):
                if _limit_reached(processed, remaining):
                    break
                groups.append(group)
                processed += 1
    return cases, groups, processed


def _write_dry_run_plan(
    run_id: str,
    target: TargetConfig,
    input_path: str | Path,
    scoring_path: str | Path,
    output_dir: str | Path,
    datasets: list[DatasetFile],
    case_ids: set[str] | None,
    limit: int | None,
    *,
    repeats: int = 1,
    temperature_schedule: list[float] | None = None,
    run_metadata: dict[str, Any] | None = None,
) -> RunReport:
    started_at = now_iso()
    dataset_reports: list[DatasetReport] = []
    selected_items: list[str] = []
    processed_total = 0
    scoring = load_scoring_config(scoring_path)
    for dataset in datasets:
        remaining = None if limit is None else max(limit - processed_total, 0)
        cases, groups, processed = _filtered_dataset(dataset, case_ids, remaining)
        selected_items.extend([f"{dataset.name}:{case.id}" for case in cases])
        selected_items.extend([f"{dataset.name}:{group.id}" for group in groups])
        processed_total += processed
        dataset_reports.append(
            DatasetReport(
                dataset_name=dataset.name,
                category=dataset.category,
                subcategory=dataset.subcategory,
                source_path=dataset.source_path,
                summary=_summarize_dataset(len(cases), len(groups), 0, 0, scoring.max_score),
            )
        )
        if _limit_reached(processed_total, limit):
            break
    total_items = sum(item.summary.total_items for item in dataset_reports)
    metadata = {
        "dry_run": True,
        "report_mode": "dry_run",
        "provider_calls_enabled": False,
        "network_enabled": False,
        "scoring_note": "planning-only dry run; selected items are not executed and are not counted as pass/fail evidence",
        "repeated_sampling": {"repeats": repeats, "temperature_schedule": list(temperature_schedule or [])},
    }
    if run_metadata:
        metadata["run"] = run_metadata
    report = RunReport(
        report_mode="dry_run",
        run_id=run_id,
        started_at=started_at,
        finished_at=now_iso(),
        target_name=target.name,
        target_adapter=target.adapter,
        target_model=target.model,
        input_path=str(Path(input_path).resolve()),
        scoring_path=str(Path(scoring_path).resolve()),
        datasets=dataset_reports,
        summary=RunSummary(total_items=total_items, passed_items=0, failed_items=total_items, score_total=0, max_score_total=total_items * scoring.max_score),
        metadata=metadata,
    )
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "dry-run.json").write_text(report.model_dump_json(indent=2), encoding="utf-8")
    run_meta = metadata.get("run") if isinstance(metadata.get("run"), dict) else {}
    plan_lines = [
        "# Malleus dry run",
        "",
        "## Run metadata",
        "",
        f"- Model: {_md_safe(run_meta.get('model_id', target.model))}",
        f"- Adapter/provider: {_md_safe(run_meta.get('adapter', target.adapter))}",
        f"- Base URL host: {_md_safe((run_meta.get('base_url') or {}).get('host', 'unknown') if isinstance(run_meta.get('base_url'), dict) else 'unknown')}",
        f"- Scoring config SHA-256: {_md_safe(((run_meta.get('scoring_config') or {}).get('sha256') or 'unknown') if isinstance(run_meta.get('scoring_config'), dict) else 'unknown')}",
        f"- Scenario input SHA-256: {_md_safe(((run_meta.get('scenario_input') or {}).get('sha256') or 'unknown') if isinstance(run_meta.get('scenario_input'), dict) else 'unknown')}",
        "",
        "## Selected items",
        "",
        *[f"- {_md_safe(item)}" for item in selected_items],
    ]
    (out / "dry-run.md").write_text("\n".join(plan_lines) + "\n", encoding="utf-8")
    return report


def _temperature_for_sample(schedule: list[float], sample_index: int) -> float | None:
    if not schedule:
        return None
    if sample_index <= len(schedule):
        return schedule[sample_index - 1]
    return schedule[-1]


def _generate_with_temperature(adapter: BaseAdapter, prompt: str, target: TargetConfig, temperature: float | None) -> str:
    if temperature is None:
        return adapter.generate(prompt)
    scheduled_target = target.model_copy(
        update={"request": target.request.model_copy(update={"temperature": temperature})}
    )
    original_target = adapter.target
    adapter.target = scheduled_target
    try:
        return adapter.generate(prompt)
    finally:
        adapter.target = original_target


def _write_repeated_summary(
    run_id: str,
    output_dir: str | Path,
    *,
    repeats: int,
    temperature_schedule: list[float],
    case_summaries: list[RepeatedCaseSummary],
) -> Path:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    summary = summarize_repeated_run(
        run_id=run_id,
        repeats=repeats,
        temperature_schedule=temperature_schedule,
        case_summaries=case_summaries,
    )
    path = out / "repeated-summary.json"
    path.write_text(summary.model_dump_json(indent=2), encoding="utf-8")
    return path


def run_benchmark(
    target_path: str | Path,
    input_path: str | Path,
    scoring_path: str | Path,
    output_dir: str | Path,
    *,
    limit: int | None = None,
    case_ids: set[str] | None = None,
    dry_run: bool = False,
    repeats: int = 1,
    temperature_schedule: list[float] | None = None,
    cli_argv: Iterable[object] | None = None,
    mutation_profile_path: str | Path | None = None,
    release_matrix_path: str | Path | None = None,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
) -> RunReport:
    started_at = now_iso()
    run_id = new_run_id()
    if repeats < 1:
        raise ValueError("repeats must be at least 1")
    schedule = list(temperature_schedule or [])
    target = load_target_config(target_path)
    if target.target_type not in {"chat_completion", "vision_model"}:
        raise ValueError(
            f"classic malleus run only supports chat_completion or vision_model targets; "
            f"use the matching live surface command for target_type={target.target_type}"
        )
    scoring = load_scoring_config(scoring_path)
    datasets = load_input_datasets(input_path)
    run_metadata = _run_metadata(
        target=target,
        input_path=input_path,
        scoring_path=scoring_path,
        dry_run=dry_run,
        cli_argv=cli_argv,
        mutation_profile_path=mutation_profile_path,
        release_matrix_path=release_matrix_path,
    )
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    events = EventLogger(out / "events.jsonl")
    selected_cases = _selected_case_refs(datasets, case_ids, limit)
    manifest = _new_manifest(
        run_id=run_id,
        target=target,
        input_path=input_path,
        scoring_path=scoring_path,
        output_dir=output_dir,
        dry_run=dry_run,
        datasets=datasets,
        selected_cases=selected_cases,
        metadata={"run": run_metadata},
    )
    manifest.metadata["repeated_sampling"] = {"repeats": repeats, "temperature_schedule": schedule}
    _write_manifest(manifest, output_dir)
    events.emit("run_started", run_id, dry_run=dry_run, selected_item_count=len(selected_cases), repeats=repeats)
    _emit_selected_cases(events, run_id, selected_cases)
    if dry_run:
        report = _write_dry_run_plan(
            run_id,
            target,
            input_path,
            scoring_path,
            output_dir,
            datasets,
            case_ids,
            limit,
            repeats=repeats,
            temperature_schedule=schedule,
            run_metadata=run_metadata,
        )
        write_risk_summary(output_dir, report_path=out / "dry-run.json")
        write_model_risk_card(report, output_dir)
        artifact_paths = ["events.jsonl", "dry-run.json", "dry-run.md", "risk-summary.json", "model-risk-card.md"]
        events.emit("run_finished", run_id, status="dry_run", total_items=report.summary.total_items)
        _write_report_manifest(run_id, output_dir, artifact_paths)
        manifest.artifacts = _artifact_refs([*artifact_paths, "report-manifest.json"], output_dir)
        _write_manifest(manifest, output_dir)
        return report
    adapter: BaseAdapter | None = None
    processed_total = 0
    try:
        adapter = resolve_adapter(target)(target)
        dataset_reports: list[DatasetReport] = []
        repeated_case_summaries: list[RepeatedCaseSummary] = []
        for dataset in datasets:
            remaining = None if limit is None else max(limit - processed_total, 0)
            selected_cases, selected_groups, processed = _filtered_dataset(dataset, case_ids, remaining)
            processed_total += processed
            case_results: list[CaseResult] = []
            group_results: list[GroupResult] = []
            for case in selected_cases:
                case_ref = _case_ref(dataset, case, "case")
                events.emit("case_started", run_id, case=case_ref.model_dump())
                _emit_progress(progress_callback, event="case_start", dataset=dataset.name, case_id=case.id, kind="case", severity=case.severity, objective=case.objective, prompt=case.prompt)
                samples: list[CaseResult] = []
                for sample_index in range(1, repeats + 1):
                    events.emit("sample_started", run_id, case=case_ref.model_dump(), sample_index=sample_index)
                    started = time.perf_counter()
                    try:
                        response_text = _generate_with_temperature(adapter, case.prompt, target, _temperature_for_sample(schedule, sample_index))
                    except Exception as exc:
                        provider_error = ProviderError(error_type=type(exc).__name__, message=str(exc), case=case_ref)
                        manifest.provider_errors.append(provider_error)
                        _write_manifest(manifest, output_dir)
                        events.emit("provider_error", run_id, error=provider_error.model_dump())
                        raise
                    latency_seconds = time.perf_counter() - started
                    result = score_case(dataset.name, case, response_text, scoring, latency_seconds=latency_seconds)
                    samples.append(result)
                    events.emit("sample_finished", run_id, case=case_ref.model_dump(), sample_index=sample_index, passed=result.passed, score=result.score)
                result = samples[0]
                case_results.append(result)
                if repeats > 1:
                    repeated_case_summaries.append(summarize_case_samples(dataset.name, case.id, samples))
                events.emit("case_finished", run_id, case=case_ref.model_dump(), passed=result.passed, score=result.score)
                _emit_progress(progress_callback, event="case_end", dataset=dataset.name, case_id=case.id, kind="case", passed=result.passed, score=result.score, max_score=scoring.max_score, latency_seconds=result.latency_seconds, response=result.response_text, failure_checks=[item.detail for item in [*result.failure_checks, *result.pass_checks] if not item.passed], pass_checks=[item.detail for item in result.pass_checks if item.passed])
            for group in selected_groups:
                group_ref = _case_ref(dataset, group, "group")
                events.emit("case_started", run_id, case=group_ref.model_dump())
                _emit_progress(progress_callback, event="case_start", dataset=dataset.name, case_id=group.id, kind="group", severity=group.severity, objective=group.objective, prompt=group.variants[0] if group.variants else "")
                responses: list[str] = []
                latencies_seconds: list[float] = []
                for variant in group.variants:
                    started = time.perf_counter()
                    try:
                        responses.append(_generate_with_temperature(adapter, variant, target, _temperature_for_sample(schedule, 1)))
                    except Exception as exc:
                        provider_error = ProviderError(error_type=type(exc).__name__, message=str(exc), case=group_ref)
                        manifest.provider_errors.append(provider_error)
                        _write_manifest(manifest, output_dir)
                        events.emit("provider_error", run_id, error=provider_error.model_dump())
                        raise
                    latencies_seconds.append(time.perf_counter() - started)
                group_result = score_group(dataset.name, group, responses, scoring, latencies_seconds=latencies_seconds)
                group_results.append(group_result)
                events.emit("case_finished", run_id, case=group_ref.model_dump(), passed=group_result.passed, score=group_result.score)
                _emit_progress(progress_callback, event="case_end", dataset=dataset.name, case_id=group.id, kind="group", passed=group_result.passed, score=group_result.score, max_score=scoring.max_score, latency_seconds=sum(latencies_seconds), response=responses[0] if responses else "", failure_checks=group_result.warnings, pass_checks=[])
            passed_items = sum(1 for item in case_results if item.passed) + sum(1 for item in group_results if item.passed)
            score_total = sum(item.score for item in case_results) + sum(item.score for item in group_results)
            dataset_reports.append(
                DatasetReport(
                    dataset_name=dataset.name,
                    category=dataset.category,
                    subcategory=dataset.subcategory,
                    source_path=dataset.source_path,
                    case_results=case_results,
                    group_results=group_results,
                    summary=_summarize_dataset(len(case_results), len(group_results), passed_items, score_total, scoring.max_score),
                )
            )
            if _limit_reached(processed_total, limit):
                break
        total_items = sum(item.summary.total_items for item in dataset_reports)
        passed_items = sum(item.summary.passed_items for item in dataset_reports)
        score_total = sum(item.summary.score_total for item in dataset_reports)
        report = RunReport(
            report_mode="live_provider",
            run_id=run_id,
            started_at=started_at,
            finished_at=now_iso(),
            target_name=target.name,
            target_adapter=target.adapter,
            target_model=target.model,
            input_path=str(Path(input_path).resolve()),
            scoring_path=str(Path(scoring_path).resolve()),
            datasets=dataset_reports,
            summary=RunSummary(total_items=total_items, passed_items=passed_items, failed_items=total_items - passed_items, score_total=score_total, max_score_total=total_items * scoring.max_score),
            metadata={
                "dry_run": False,
                "report_mode": "live_provider",
                "provider_calls_enabled": True,
                "repeated_sampling": {"repeats": repeats, "temperature_schedule": schedule},
                "run": run_metadata,
            },
        )
        repeated_artifact = None
        if repeated_case_summaries:
            repeated_artifact = _write_repeated_summary(
                run_id, output_dir, repeats=repeats, temperature_schedule=schedule, case_summaries=repeated_case_summaries
            )
        write_json_report(report, output_dir)
        write_markdown_report(report, output_dir)
        write_html_report(report, output_dir)
        write_risk_summary(output_dir, report_path=out / "report.json")
        write_model_risk_card(report, output_dir)
        findings_bundle = collect_findings(output_dir)
        write_finding_artifacts(findings_bundle, output_dir)
        artifact_paths = ["events.jsonl", "report.json", "report.md", "report.html", "risk-summary.json", "model-risk-card.md", "findings.json", "findings.md"]
        if repeated_artifact is not None:
            artifact_paths.append("repeated-summary.json")
        events.emit("run_finished", run_id, status="completed", total_items=report.summary.total_items)
        _write_report_manifest(run_id, output_dir, artifact_paths)
        manifest.artifacts = _artifact_refs([*artifact_paths, "report-manifest.json"], output_dir)
        _write_manifest(manifest, output_dir)
        return report
    except Exception as exc:
        if not manifest.provider_errors:
            provider_error = ProviderError(error_type=type(exc).__name__, message=str(exc))
            manifest.provider_errors.append(provider_error)
            _write_manifest(manifest, output_dir)
            events.emit("provider_error", run_id, error=provider_error.model_dump())
        events.emit("run_finished", run_id, status="error", error_type=type(exc).__name__, message=str(exc))
        write_risk_summary(output_dir, report_path=None)
        artifact_paths = ["events.jsonl", "risk-summary.json"]
        _write_report_manifest(run_id, output_dir, artifact_paths)
        manifest.artifacts = _artifact_refs([*artifact_paths, "report-manifest.json"], output_dir)
        _write_manifest(manifest, output_dir)
        raise
    finally:
        if adapter is not None:
            adapter.close()


def compare_models(
    target_path: str | Path,
    input_path: str | Path,
    scoring_path: str | Path,
    output_dir: str | Path,
    models: list[str],
    *,
    limit: int | None = None,
    dry_run: bool = True,
) -> Path:
    base_target = load_target_config(target_path)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    target_files: list[Path] = []
    report_paths: list[Path] = []
    for model in models:
        target_data = base_target.model_dump()
        target_data["name"] = f"{base_target.name}-{model.replace('/', '-') }"
        target_data["model"] = model
        target_file = out / f"target-{model.replace('/', '__')}.json"
        target_file.write_text(json.dumps(target_data, indent=2), encoding="utf-8")
        target_files.append(target_file)
        model_out = out / model.replace('/', '__')
        run_benchmark(target_file, input_path, scoring_path, model_out, limit=limit, dry_run=dry_run)
        report_paths.append(model_out / ("dry-run.json" if dry_run else "report.json"))
    return write_comparison_report(report_paths, out)


def _emit_progress(callback: Callable[[dict[str, Any]], None] | None, **event: Any) -> None:
    if callback is not None:
        callback(event)
