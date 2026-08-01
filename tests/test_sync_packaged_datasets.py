from pathlib import Path

from malleus.dataset_assets import dataset_drift, sync_datasets


def _write(root: Path, relative_path: str, content: str) -> None:
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_dataset_drift_reports_missing_changed_and_extra_files(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    _write(source, "missing.yaml", "canonical")
    _write(source, "changed.yaml", "canonical")
    _write(destination, "changed.yaml", "stale")
    _write(destination, "extra.yaml", "obsolete")

    assert dataset_drift(source, destination) == [
        "missing: missing.yaml",
        "extra: extra.yaml",
        "changed: changed.yaml",
    ]


def test_sync_datasets_makes_destination_an_exact_copy(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    _write(source, "nested/case.yaml", "canonical")
    _write(destination, "old/extra.yaml", "obsolete")

    sync_datasets(source, destination)

    assert dataset_drift(source, destination) == []
    assert (destination / "nested/case.yaml").read_text(encoding="utf-8") == "canonical"
    assert not (destination / "old").exists()
