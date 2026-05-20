from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


IR_SCHEMA_VERSION = "malleus.ir.v1"
ARTIFACT_SCHEMA_VERSION = "malleus.artifact.v1"
REPORT_MANIFEST_SCHEMA_VERSION = "malleus.report_manifest.v1"
REPORT_MODE_LOCAL_FIXTURE = "local_fixture"
REPORT_MODE_SIMULATED = "simulated"
REPORT_MODE_DRY_RUN = "dry_run"
REPORT_MODE_SCAFFOLD = "scaffold"
REPORT_MODE_LIVE_PROVIDER = "live_provider"


class VersionedModel(BaseModel):
    schema_version: str = IR_SCHEMA_VERSION


class SuiteRef(VersionedModel):
    dataset_name: str
    category: str | None = None
    subcategory: str | None = None
    source_path: str | None = None


class CaseRef(VersionedModel):
    dataset_name: str
    item_id: str
    item_type: Literal["case", "group"] = "case"
    severity: str | None = None
    objective: str | None = None


class Invocation(VersionedModel):
    run_id: str
    case: CaseRef
    prompt: str
    variant_index: int | None = None


class Observation(VersionedModel):
    invocation: Invocation
    response_text: str | None = None
    latency_seconds: float | None = None


class ScorerResult(VersionedModel):
    case: CaseRef
    passed: bool
    score: int
    penalty: int
    warnings: list[str] = Field(default_factory=list)


class ProviderError(VersionedModel):
    error_type: str
    message: str
    case: CaseRef | None = None


class ArtifactRef(VersionedModel):
    path: str
    kind: str
    artifact_type: str | None = None
    artifact_schema_version: str = ARTIFACT_SCHEMA_VERSION
    sha256: str | None = None
    relative_path: str | None = None
    redaction_status: Literal["redacted", "not_applicable", "unknown"] = "unknown"
    redacted_preview: str | None = None
    evidence_refs: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ReportManifest(VersionedModel):
    schema_version: str = REPORT_MANIFEST_SCHEMA_VERSION
    run_id: str
    report_type: str
    mode: str | None = None
    artifacts: list[ArtifactRef] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class GateDecisionInput(VersionedModel):
    manifest_path: str
    events_path: str
    report_path: str | None = None


class RunManifest(VersionedModel):
    run_id: str
    target_name: str
    target_adapter: str
    target_model: str
    input_path: str
    scoring_path: str
    output_dir: str
    dry_run: bool
    mode: str | None = None
    provider_calls_enabled: bool | None = None
    selected_item_count: int | None = None
    suites: list[SuiteRef] = Field(default_factory=list)
    selected_cases: list[CaseRef] = Field(default_factory=list)
    artifacts: list[ArtifactRef] = Field(default_factory=list)
    provider_errors: list[ProviderError] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
