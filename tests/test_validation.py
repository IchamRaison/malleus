from __future__ import annotations

from malleus.schemas import DatasetCase, DatasetFile, SignalSpec
from malleus.validation import ValidationReport, validate_dataset_object, validate_input_path


def test_validation_report_tracks_errors_and_warnings() -> None:
    report = ValidationReport()
    report.add_error("case-id", "Broken case")
    report.add_warning("dataset", "Weak signal")

    assert not report.ok
    assert len(report.errors) == 1
    assert len(report.warnings) == 1
    assert report.errors[0].level == "error"
    assert "ERROR" in report.to_text()


def test_validate_smoke_pack_passes() -> None:
    report = validate_input_path("datasets/benchmark_packs/smoke-v1.yaml")
    assert report.ok, report.to_text()


def test_validation_reports_duplicate_case_ids() -> None:
    dataset = DatasetFile(
        name="dup-dataset",
        version=1,
        category="test",
        subcategory="duplicates",
        cases=[
            DatasetCase(id="same", severity="low", objective="A", prompt="Prompt A"),
            DatasetCase(id="same", severity="medium", objective="B", prompt="Prompt B"),
        ],
    )

    report = validate_dataset_object(dataset)

    assert not report.ok
    assert any("duplicate" in issue.message.lower() for issue in report.errors)


def test_validation_warns_on_broad_failure_signal() -> None:
    dataset = DatasetFile(
        name="broad-signal-dataset",
        version=1,
        category="test",
        subcategory="signals",
        cases=[
            DatasetCase(
                id="broad-001",
                severity="low",
                objective="Avoid leaking fake secrets",
                prompt="Do not leak the fake secret.",
                failure_signals=[SignalSpec(type="substring", pattern="secret")],
            )
        ],
    )

    report = validate_dataset_object(dataset)

    assert report.ok
    assert any("broad" in issue.message.lower() for issue in report.warnings)


def test_validation_rejects_raw_payload_metadata() -> None:
    dataset = DatasetFile(
        name="unsafe-metadata-dataset",
        version=1,
        category="test",
        subcategory="metadata",
        cases=[
            DatasetCase(
                id="unsafe-001",
                severity="low",
                objective="Keep sanitized metadata safe",
                prompt="Synthetic placeholder prompt",
                metadata={"raw_payload": "forbidden", "raw_payload_present": True},
            )
        ],
    )

    report = validate_dataset_object(dataset)

    assert not report.ok
    assert any("raw_payload" in issue.message for issue in report.errors)
