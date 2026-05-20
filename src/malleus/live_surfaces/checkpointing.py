from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import Any

from malleus.live_evidence import LiveEvidenceMatrix, LiveEvidenceRow, LiveSurfaceRecord
from malleus.live_surfaces.common import sanitize_metadata
from malleus.reporting import _md_safe
from malleus.utils.redact import redact_public_text


LIVE_FULL_CHECKPOINT_SCHEMA_VERSION = "malleus.live_full_checkpoint.v1"


def write_live_full_checkpoint(evidence: LiveEvidenceMatrix, out_dir: str | Path, *, completed_rows: int, total_rows: int) -> tuple[Path, Path]:
    destination = Path(out_dir)
    destination.mkdir(parents=True, exist_ok=True)
    checkpoint = evidence.model_copy(
        update={
            "metadata": sanitize_metadata(
                {
                    **evidence.metadata,
                    "schema_version": LIVE_FULL_CHECKPOINT_SCHEMA_VERSION,
                    "checkpoint": True,
                    "partial": completed_rows < total_rows,
                    "completed_rows": completed_rows,
                    "total_rows": total_rows,
                    "not_run_rows": max(total_rows - completed_rows, 0),
                    "checkpoint_contract": "completed rows are live evidence rows already returned by their surface runner; not-run rows are placeholders for surfaces not reached before interruption or timeout",
                }
            )
        },
        deep=True,
    )
    json_path = destination / "live-full-checkpoint.json"
    markdown_path = destination / "live-full-checkpoint.md"
    atomic_write_checkpoint_text(json_path, checkpoint.model_dump_json(indent=2))
    atomic_write_checkpoint_text(markdown_path, render_live_full_checkpoint_markdown(checkpoint))
    return json_path, markdown_path


def atomic_write_checkpoint_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex[:12]}.tmp")
    try:
        with tmp_path.open("w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        tmp_path.replace(path)
        fsync_directory(path.parent)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def fsync_directory(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def render_live_full_checkpoint_markdown(evidence: LiveEvidenceMatrix) -> str:
    metadata = evidence.metadata
    lines = [
        "# Malleus live-full checkpoint",
        "",
        f"- Matrix: {_md_safe(evidence.matrix_id)}",
        f"- Benchmark mode: {_md_safe(metadata.get('benchmark_mode', 'live-full'))}",
        f"- Partial: {str(metadata.get('partial', True)).lower()}",
        f"- Completed rows: {int(metadata.get('completed_rows') or 0)} / {int(metadata.get('total_rows') or len(evidence.rows))}",
        f"- Live model calls: {sum(int(row.live_model_calls or 0) for row in evidence.rows)}",
        "",
        "This checkpoint is written during live-full execution so completed live evidence is not stranded if the operator, shell, cron, or tool interrupts the outer command before the final aggregate is written.",
        "Rows marked `checkpoint_not_run` with `checkpoint_status=not_run` were not reached before the checkpoint and are not model safety failures.",
        "",
        "| Row | Surface | Status | Live calls | Checkpoint status | Reason |",
        "|---|---|---:|---:|---|---|",
    ]
    for row in evidence.rows:
        checkpoint_status = row.metadata.get("checkpoint_status") if isinstance(row.metadata, dict) else None
        lines.append(f"| `{_md_safe(row.row_id)}` | `{_md_safe(row.surface_id)}` | {_md_safe(row.status)} | {int(row.live_model_calls or 0)} | {_md_safe(checkpoint_status or 'completed')} | {_md_safe(row.reason or '')} |")
    return "\n".join(lines).rstrip() + "\n"


def matrix_with_rows(
    *,
    matrix_id: str,
    generated_at: str,
    surfaces: list[LiveSurfaceRecord],
    rows: list[LiveEvidenceRow],
    metadata: dict[str, Any],
    git_commit: str,
) -> LiveEvidenceMatrix:
    sanitized_rows = [row.model_copy(update={"git_commit": git_commit, "command": redact_public_text(row.command).text}) for row in rows]
    return LiveEvidenceMatrix(matrix_id=matrix_id, generated_at=generated_at, surfaces=surfaces, rows=sanitized_rows, metadata=sanitize_metadata(metadata))
