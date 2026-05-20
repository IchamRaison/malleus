from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from malleus.resources import resource_path
from malleus.utils.redact import redact_public_text


def public_path(value: str | Path) -> str:
    path = Path(value)
    text = str(value)
    if not path.is_absolute():
        return text
    try:
        return str(path.resolve().relative_to(Path.cwd().resolve()))
    except ValueError:
        return path.name or "[external-path]"


def sanitize_metadata(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return redact_public_text(value).text
    if isinstance(value, (list, tuple, set)):
        return [sanitize_metadata(item) for item in value]
    if isinstance(value, dict):
        return {redact_public_text(str(key)).text: sanitize_metadata(item) for key, item in value.items()}
    return redact_public_text(str(value)).text


def matrix_reference_path(source_path: str, matrix_path: Path) -> Path:
    candidate = Path(source_path)
    if candidate.is_absolute():
        return candidate.resolve()
    matrix_relative = (matrix_path.parent / candidate).resolve()
    if matrix_relative.exists():
        return matrix_relative
    return resource_path(candidate)


def safe_output_segment(value: str) -> str:
    segment = slug(value)
    if not segment:
        raise ValueError("profile id must produce a non-empty output path segment")
    return segment


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def slug(value: str) -> str:
    slugged = "".join(character.lower() if character.isalnum() else "-" for character in value).strip("-")
    return slugged or "target"
