from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from pydantic import BaseModel, Field

from malleus.datasets import load_release_matrix, load_target_config
from malleus.live_full import run_live_surface_pack
from malleus.reporting import _md_safe
from malleus.utils.ids import new_run_id


class BenchmarkSuitePack(BaseModel):
    pack_id: str
    path: str
    evidence_level: str
    target_types: list[str] = Field(default_factory=list)
    status: str = "selected"
    output_dir: str | None = None
    row_status: str | None = None
    reason_codes: list[str] = Field(default_factory=list)
    reason: str | None = None


class BenchmarkSuiteReport(BaseModel):
    schema_version: str = "malleus.benchmark_suite.v1"
    run_id: str = Field(default_factory=new_run_id)
    started_at: str
    finished_at: str | None = None
    target_name: str
    target_type: str
    matrix_id: str
    matrix_path: str
    dry_run: bool = False
    packs: list[BenchmarkSuitePack]
    status_counts: dict[str, int] = Field(default_factory=dict)
    report_paths: list[str] = Field(default_factory=list)


def build_benchmark_suite_plan(
    target_path: str | Path,
    matrix_path: str | Path,
    *,
    pack_ids: list[str] | tuple[str, ...] = (),
    include_scaffold: bool = False,
) -> BenchmarkSuiteReport:
    target = load_target_config(target_path)
    matrix = load_release_matrix(matrix_path)
    selected_ids = set(pack_ids)
    packs: list[BenchmarkSuitePack] = []
    for pack in matrix.packs:
        if selected_ids and pack.id not in selected_ids:
            continue
        if pack.status in {"planned", "scaffold"} and not include_scaffold:
            continue
        if pack.target_types and target.target_type not in pack.target_types:
            continue
        packs.append(
            BenchmarkSuitePack(
                pack_id=pack.id,
                path=pack.path,
                evidence_level=pack.evidence_level,
                target_types=[str(item) for item in pack.target_types],
            )
        )
    return BenchmarkSuiteReport(
        started_at=_now(),
        target_name=target.name,
        target_type=str(target.target_type),
        matrix_id=matrix.id,
        matrix_path=str(Path(matrix_path)),
        dry_run=True,
        packs=packs,
        status_counts={"selected": len(packs)},
    )


def run_benchmark_suite(
    target_path: str | Path,
    matrix_path: str | Path,
    out_dir: str | Path,
    *,
    yes: bool = False,
    pack_ids: list[str] | tuple[str, ...] = (),
    include_scaffold: bool = False,
    dry_run: bool = False,
    runner: Callable[..., Any] = run_live_surface_pack,
) -> BenchmarkSuiteReport:
    destination = Path(out_dir)
    destination.mkdir(parents=True, exist_ok=True)
    report = build_benchmark_suite_plan(target_path, matrix_path, pack_ids=pack_ids, include_scaffold=include_scaffold)
    report.dry_run = dry_run
    if not report.packs:
        report.finished_at = _now()
        _write_suite_report(report, destination)
        return report
    if dry_run:
        report.finished_at = _now()
        _write_suite_report(report, destination)
        return report
    rows: list[dict[str, Any]] = []
    for pack in report.packs:
        pack_out = destination / "surfaces" / pack.pack_id
        evidence, _, _ = runner(target_path=target_path, pack_id=pack.pack_id, matrix_path=matrix_path, out_dir=pack_out, yes=yes)
        row = evidence.rows[0] if getattr(evidence, "rows", None) else None
        pack.output_dir = str(pack_out.relative_to(destination))
        if row is not None:
            row_payload = row.model_dump(mode="json") if hasattr(row, "model_dump") else dict(row)
            rows.append(row_payload)
            pack.row_status = str(row_payload.get("status") or "")
            pack.reason = row_payload.get("reason")
            metadata = row_payload.get("metadata") if isinstance(row_payload.get("metadata"), dict) else {}
            codes = row_payload.get("reason_codes") or metadata.get("reason_codes") or []
            pack.reason_codes = [str(code) for code in codes] if isinstance(codes, list) else []
            report_path = metadata.get("report_json")
            if isinstance(report_path, str) and report_path:
                report.report_paths.append(str(Path(pack.output_dir) / report_path))
    report.status_counts = dict(Counter(pack.row_status or pack.status for pack in report.packs))
    report.finished_at = _now()
    _write_suite_report(report, destination, rows=rows)
    return report


def _write_suite_report(report: BenchmarkSuiteReport, destination: Path, *, rows: list[dict[str, Any]] | None = None) -> None:
    payload = report.model_dump(mode="json")
    if rows is not None:
        payload["rows"] = rows
    (destination / "benchmark-suite-report.json").write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    (destination / "benchmark-suite-report.md").write_text(_render_markdown(report), encoding="utf-8")


def _render_markdown(report: BenchmarkSuiteReport) -> str:
    lines = [
        f"# Malleus Benchmark Suite: {_md_safe(report.target_name)}",
        "",
        f"- Target type: `{_md_safe(report.target_type)}`",
        f"- Matrix: `{_md_safe(report.matrix_id)}`",
        f"- Dry run: `{str(report.dry_run).lower()}`",
        f"- Packs: {len(report.packs)}",
        "",
        "| Pack | Status | Evidence | Reason codes | Output |",
        "| --- | --- | --- | --- | --- |",
    ]
    for pack in report.packs:
        lines.append(
            f"| `{_md_safe(pack.pack_id)}` | {_md_safe(pack.row_status or pack.status)} | {_md_safe(pack.evidence_level)} | "
            f"{_md_safe(', '.join(pack.reason_codes) or 'none')} | {_md_safe(pack.output_dir or '')} |"
        )
    return "\n".join(lines).rstrip() + "\n"


def _now() -> str:
    return datetime.now(UTC).isoformat()


__all__ = ["BenchmarkSuitePack", "BenchmarkSuiteReport", "build_benchmark_suite_plan", "run_benchmark_suite"]
