from __future__ import annotations

import filecmp
import shutil
from pathlib import Path


def dataset_drift(source: Path, destination: Path) -> list[str]:
    source_files = {path.relative_to(source) for path in source.rglob("*") if path.is_file()}
    destination_files = {
        path.relative_to(destination) for path in destination.rglob("*") if path.is_file()
    }
    drift = [f"missing: {path}" for path in sorted(source_files - destination_files)]
    drift.extend(f"extra: {path}" for path in sorted(destination_files - source_files))
    drift.extend(
        f"changed: {path}"
        for path in sorted(source_files & destination_files)
        if not filecmp.cmp(source / path, destination / path, shallow=False)
    )
    return drift


def sync_datasets(source: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    source_files = {path.relative_to(source) for path in source.rglob("*") if path.is_file()}
    destination_files = {
        path.relative_to(destination) for path in destination.rglob("*") if path.is_file()
    }
    for relative_path in sorted(destination_files - source_files):
        (destination / relative_path).unlink()
    for relative_path in sorted(source_files):
        target = destination / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / relative_path, target)
    for directory in sorted(destination.rglob("*"), reverse=True):
        if directory.is_dir() and not any(directory.iterdir()):
            directory.rmdir()
