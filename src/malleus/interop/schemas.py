from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

INTEROP_SCHEMA_VERSION = "malleus.interop.v1"
ImportSource = Literal["promptfoo", "garak", "pyrit", "inspect"]
ExportFormat = Literal["sarif", "junit", "promptfoo", "inspect", "github"]


class InteropArtifactRef(BaseModel):
    kind: str
    path: str


class InteropImportReport(BaseModel):
    schema_version: str = INTEROP_SCHEMA_VERSION
    source: ImportSource
    source_path: str
    warnings: list[str] = Field(default_factory=list)
    unsupported_field_warnings: list[str] = Field(default_factory=list)
    output_artifacts: dict[str, str] = Field(default_factory=dict)
    normalized_finding_count: int = 0
    gate: dict[str, Any] = Field(default_factory=dict)


class InteropExportReport(BaseModel):
    schema_version: str = INTEROP_SCHEMA_VERSION
    format: ExportFormat
    findings_path: str
    output_artifact: str
    warnings: list[str] = Field(default_factory=list)
    unsupported_field_warnings: list[str] = Field(default_factory=list)
    exported_finding_count: int = 0
