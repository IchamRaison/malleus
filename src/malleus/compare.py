from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


_SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\b(?:api[_-]?key|secret|token)\s*=\s*[^\s`|<>]+", re.IGNORECASE),
)


def _load_report(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _md_cell(value: object) -> str:
    text = str(value)
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    text = text.replace("&", "&amp;").replace("<", "&lt;")
    return text.replace("\r", " ").replace("\n", " ").replace("|", r"\|").replace("`", r"\`").replace("#", r"\#")


def write_comparison_report(report_paths: list[str | Path], output_dir: str | Path) -> Path:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    for path in report_paths:
        report = _load_report(path)
        summary = report["summary"]
        report_mode = report.get("report_mode") or "unknown"
        run_metadata = report.get("metadata", {}).get("run", {}) if isinstance(report.get("metadata"), dict) else {}
        provider_calls_enabled = bool(run_metadata.get("provider_calls_enabled")) if isinstance(run_metadata, dict) else False
        dry_run = report_mode == "dry_run" or not provider_calls_enabled
        score = int(summary["score_total"])
        max_score = int(summary["max_score_total"])
        pct = 0.0 if max_score == 0 else (score / max_score) * 100
        rows.append(
            {
                "model": report["target_model"],
                "report_mode": report_mode,
                "dry_run": dry_run,
                "provider_calls_enabled": provider_calls_enabled,
                "evidence_label": "planning_only" if dry_run else "model_behavior",
                "score": score,
                "max_score": max_score,
                "pct": pct,
                "passed": int(summary["passed_items"]),
                "total": int(summary["total_items"]),
                "path": str(Path(path)),
            }
        )
    rows.sort(key=lambda item: item["pct"], reverse=True)
    (out / "comparison.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    lines = [
        "# Malleus model comparison",
        "",
        "Dry-run/provider-free rows are comparison plans only and are not model behavior evidence.",
        "",
        "| Model | Mode | Evidence | Provider calls | Score | Pass rate | Items | Report |",
        "|---|---|---|---:|---:|---:|---:|---|",
    ]
    for row in rows:
        lines.append(
            f"| {_md_cell(row['model'])} | {_md_cell(row['report_mode'])} | {_md_cell(row['evidence_label'])} | {str(row['provider_calls_enabled']).lower()} | {row['score']}/{row['max_score']} | {row['pct']:.1f}% | {row['passed']}/{row['total']} | {_md_cell(row['path'])} |"
        )
    (out / "comparison.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out
