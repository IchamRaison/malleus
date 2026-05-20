from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from malleus.datasets import is_benchmark_pack, load_benchmark_pack, load_input_datasets
from malleus.schemas import DatasetFile, SignalSpec

IssueLevel = Literal["error", "warning"]

_BROAD_FAILURE_PATTERNS = {
    "secret",
    "password",
    "token",
    "key",
    "hidden instructions",
    "system prompt",
    "internal context",
    "confidential",
}
_TAXONOMY_KEYS = {"owasp", "nist", "malleus_surface", "malleus_technique", "malleus_boundary", "avid_effect"}
_SCALAR_TAXONOMY_KEYS = {"malleus_surface", "malleus_technique", "malleus_boundary", "avid_effect", "maps_to"}


class ValidationIssue(BaseModel):
    level: IssueLevel
    location: str
    message: str


class ValidationReport(BaseModel):
    errors: list[ValidationIssue] = Field(default_factory=list)
    warnings: list[ValidationIssue] = Field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def add_error(self, location: str, message: str) -> None:
        self.errors.append(ValidationIssue(level="error", location=location, message=message))

    def add_warning(self, location: str, message: str) -> None:
        self.warnings.append(ValidationIssue(level="warning", location=location, message=message))

    def merge(self, other: "ValidationReport") -> None:
        self.errors.extend(other.errors)
        self.warnings.extend(other.warnings)

    def to_text(self) -> str:
        lines = ["Validation passed" if self.ok else "Validation failed"]
        if self.errors:
            lines.append("Errors:")
            lines.extend(f"ERROR {issue.location}: {issue.message}" for issue in self.errors)
        if self.warnings:
            lines.append("Warnings:")
            lines.extend(f"WARNING {issue.location}: {issue.message}" for issue in self.warnings)
        return "\n".join(lines)

    def to_json(self) -> str:
        return json.dumps(self.model_dump() | {"ok": self.ok}, indent=2, sort_keys=True)


def _signal_is_broad(signal: SignalSpec) -> bool:
    if signal.type not in {"substring", "regex"} or not signal.pattern:
        return False
    normalized = signal.pattern.strip().lower()
    if normalized in _BROAD_FAILURE_PATTERNS:
        return True
    return len(normalized) <= 5 and normalized.isalpha()


def _validate_taxonomy_metadata(metadata: dict[str, object], location: str, report: ValidationReport, *, allow_scalar_lists: bool = False) -> None:
    for key in _TAXONOMY_KEYS:
        if key not in metadata:
            continue
        value = metadata[key]
        if isinstance(value, str):
            if not value.strip():
                report.add_error(location, f"Taxonomy metadata {key} must not be empty")
            continue
        if isinstance(value, list) and all(isinstance(item, str) and item.strip() for item in value):
            continue
        report.add_error(location, f"Taxonomy metadata {key} must be a non-empty string or list of non-empty strings")
    for key in _SCALAR_TAXONOMY_KEYS:
        value = metadata.get(key)
        if isinstance(value, list) and not allow_scalar_lists:
            report.add_error(location, f"Taxonomy metadata {key} must be a string on individual cases/groups")
    maps_to = metadata.get("maps_to")
    if maps_to is not None and (not isinstance(maps_to, str) or maps_to.count("/") != 1 or not all(part.strip() for part in maps_to.split("/"))):
        report.add_error(location, "Taxonomy metadata maps_to must use '<boundary>/<technique>'")


def _validate_case_signals(dataset: DatasetFile, report: ValidationReport) -> None:
    for case in dataset.cases or []:
        location = f"{dataset.name}:{case.id}"
        if not case.id.strip():
            report.add_error(location, "Case id must not be empty")
        if not case.objective.strip():
            report.add_error(location, "Case objective must not be empty")
        if not case.prompt.strip():
            report.add_error(location, "Case prompt must not be empty")
        if not case.failure_signals and not case.pass_signals and case.output_constraints is None:
            report.add_error(location, "Case must define failure signals, pass signals, or output constraints")
        for signal in case.failure_signals:
            if _signal_is_broad(signal):
                report.add_warning(
                    location,
                    f"Failure signal pattern {signal.pattern!r} looks broad and may cause false positives",
                )
        if "raw_payload" in case.metadata:
            report.add_error(location, "Case metadata must not include a raw_payload field")
        if case.metadata.get("raw_payload_present") is True:
            report.add_error(location, "Sanitized corpus cases must set raw_payload_present to false")
        _validate_taxonomy_metadata(case.metadata, location, report)


def _validate_group_shape(dataset: DatasetFile, report: ValidationReport) -> None:
    for group in dataset.groups or []:
        location = f"{dataset.name}:{group.id}"
        if not group.id.strip():
            report.add_error(location, "Group id must not be empty")
        if not group.objective.strip():
            report.add_error(location, "Group objective must not be empty")
        if not group.variants:
            report.add_error(location, "Group must define at least one variant")
        if any(not variant.strip() for variant in group.variants):
            report.add_error(location, "Group variants must not be empty")
        _validate_taxonomy_metadata(group.metadata, location, report)


def validate_dataset_object(dataset: DatasetFile) -> ValidationReport:
    report = ValidationReport()
    seen: dict[str, str] = {}

    for case in dataset.cases or []:
        location = f"{dataset.name}:{case.id}"
        if case.id in seen:
            report.add_error(location, f"Duplicate item id {case.id!r}; first seen at {seen[case.id]}")
        else:
            seen[case.id] = location

    for group in dataset.groups or []:
        location = f"{dataset.name}:{group.id}"
        if group.id in seen:
            report.add_error(location, f"Duplicate item id {group.id!r}; first seen at {seen[group.id]}")
        else:
            seen[group.id] = location

    _validate_case_signals(dataset, report)
    _validate_group_shape(dataset, report)
    return report


def validate_input_path(path: str | Path) -> ValidationReport:
    report = ValidationReport()
    try:
        if is_benchmark_pack(path):
            pack = load_benchmark_pack(path)
            _validate_taxonomy_metadata(pack.metadata, str(path), report, allow_scalar_lists=True)
    except Exception as exc:
        report.add_error(str(path), f"Failed to load benchmark pack metadata: {exc}")
        return report
    try:
        datasets = load_input_datasets(path)
    except Exception as exc:
        report.add_error(str(path), f"Failed to load input: {exc}")
        return report

    seen_global: dict[str, str] = {}
    for dataset in datasets:
        dataset_report = validate_dataset_object(dataset)
        report.merge(dataset_report)
        for case in dataset.cases or []:
            location = f"{dataset.name}:{case.id}"
            if case.id in seen_global:
                report.add_error(location, f"Duplicate item id {case.id!r} across input; first seen at {seen_global[case.id]}")
            else:
                seen_global[case.id] = location
        for group in dataset.groups or []:
            location = f"{dataset.name}:{group.id}"
            if group.id in seen_global:
                report.add_error(location, f"Duplicate item id {group.id!r} across input; first seen at {seen_global[group.id]}")
            else:
                seen_global[group.id] = location

    return report
