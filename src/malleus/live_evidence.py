from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

from malleus.ir import ArtifactRef
from malleus.schemas import (
    REPORT_MODE_DRY_RUN,
    REPORT_MODE_LIVE_PROVIDER,
    REPORT_MODE_LOCAL_FIXTURE,
    REPORT_MODE_SCAFFOLD,
    REPORT_MODE_SIMULATED,
    RedactionMetadata,
    _reject_raw_evidence_fields,
)
from malleus.utils.redact import redact_public_text, redacted_preview


LIVE_EVIDENCE_SCHEMA_VERSION = "malleus.live_evidence.v1"
LIVE_EVIDENCE_MATRIX_SCHEMA_VERSION = "malleus.live_evidence_matrix.v1"

LiveEvidenceStatus = Literal[
    "passed",
    "failed",
    "provider_error",
    "provider_capability_gap",
    "target_capability_gap",
    "target_config_error",
    "target_error",
    "skipped_by_operator",
    "checkpoint_not_run",
    "not_supported",
    "not_implemented",
    "preflight_failed",
    "skipped_by_flag",
    "timeout",
    "infra_error",
]
LiveEvidenceLevel = Literal[
    "live_text_model",
    "live_multimodal_model",
    "live_system",
    "live_system_trace",
    "dry_run",
    "scaffold_static",
    "local_fixture",
    "simulated",
    "not_supported",
    "not_implemented",
]
LiveEvidenceFidelity = Literal[
    "prompt_model_trace",
    "fixture_rag_trace",
    "live_rag_service_trace",
    "auto_wrapper_trace",
    "controlled_rag_trace",
    "controlled_tool_trace",
    "controlled_workflow_trace",
    "controlled_memory_trace",
    "controlled_multi_agent_trace",
    "controlled_browser_trace",
    "controlled_code_workspace_trace",
    "live_tool_trace",
    "live_workflow_trace",
    "live_memory_trace",
    "live_multi_agent_trace",
    "live_browser_trace",
    "live_code_agent_trace",
    "target_error",
    "provider_capability_gap",
]

LIVE_MODEL_STATUSES: tuple[str, ...] = ("passed", "failed")
LIVE_OPERATIONAL_STATUSES: tuple[str, ...] = ("provider_error", "timeout", "infra_error")
LIVE_SYSTEM_STATUSES: tuple[str, ...] = ("target_config_error", "target_error")
CAPABILITY_GAP_STATUSES: tuple[str, ...] = ("provider_capability_gap", "target_capability_gap")
NON_LIVE_CLASSIFICATION_STATUSES: tuple[str, ...] = (
    "skipped_by_operator",
    "checkpoint_not_run",
    "not_supported",
    "not_implemented",
    "preflight_failed",
    "skipped_by_flag",
)
LIVE_EVIDENCE_LEVELS: tuple[str, ...] = ("live_text_model", "live_multimodal_model")
LIVE_SYSTEM_EVIDENCE_LEVELS: tuple[str, ...] = ("live_system", "live_system_trace")
NON_LIVE_CLASSIFICATION_LEVELS: tuple[str, ...] = ("not_supported", "not_implemented", "scaffold_static")
FORBIDDEN_LIVE_REPORT_MODES: tuple[str, ...] = (
    REPORT_MODE_DRY_RUN,
    REPORT_MODE_SCAFFOLD,
    REPORT_MODE_LOCAL_FIXTURE,
    REPORT_MODE_SIMULATED,
)
FORBIDDEN_LIVE_EVIDENCE_LEVELS: tuple[str, ...] = (
    "dry_run",
    "scaffold_static",
    "local_fixture",
    "simulated",
)
FORBIDDEN_LIVE_ARTIFACT_NAME_FRAGMENTS: tuple[str, ...] = ("dry-run", "dry_run", "fixture", "scaffold")
MANIFEST_ONLY_ARTIFACT_TYPES: tuple[str, ...] = ("manifest", "report_manifest", "run_manifest")


class VersionedLiveEvidenceModel(BaseModel):
    schema_version: str = LIVE_EVIDENCE_SCHEMA_VERSION

    @model_validator(mode="before")
    @classmethod
    def validate_no_raw_payload_fields(cls, data: Any) -> Any:
        return _reject_raw_evidence_fields(data)


class LiveTargetMetadata(VersionedLiveEvidenceModel):
    name: str
    adapter: str
    model: str
    base_url: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class RedactedResponseSummary(VersionedLiveEvidenceModel):
    sha256: str
    length: int
    redacted_excerpt: str
    redaction: RedactionMetadata


class LiveSurfaceRecord(VersionedLiveEvidenceModel):
    surface_id: str
    name: str
    category: str | None = None
    modality: Literal["text", "multimodal", "unknown"] = "unknown"
    metadata: dict[str, Any] = Field(default_factory=dict)


class LiveEvidenceRow(VersionedLiveEvidenceModel):
    row_id: str
    run_id: str
    case_id: str
    surface_id: str
    timestamp: str
    command: str
    git_commit: str
    target: LiveTargetMetadata
    status: LiveEvidenceStatus
    evidence_level: LiveEvidenceLevel
    evidence_fidelity: LiveEvidenceFidelity
    dry_run: bool
    provider_calls_enabled: bool
    live_model_calls: int | None = None
    report_mode: str = REPORT_MODE_LIVE_PROVIDER
    artifacts: list[ArtifactRef] = Field(default_factory=list)
    response_summary: RedactedResponseSummary | None = None
    reason: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def populate_evidence_fidelity(cls, data: Any) -> Any:
        if not isinstance(data, dict) or data.get("evidence_fidelity"):
            return data
        values = dict(data)
        values["evidence_fidelity"] = _infer_evidence_fidelity(values)
        return values

    @model_validator(mode="after")
    def validate_live_evidence_contract(self) -> "LiveEvidenceRow":
        if self.dry_run:
            raise ValueError("live evidence rows must not have dry_run=true")

        if self.status in LIVE_MODEL_STATUSES:
            self._validate_live_model_row()
        elif self.status in LIVE_OPERATIONAL_STATUSES:
            if self.evidence_level in LIVE_SYSTEM_EVIDENCE_LEVELS:
                self._validate_live_system_row()
            elif self.evidence_level in LIVE_EVIDENCE_LEVELS:
                self._validate_live_operational_row()
            else:
                self._validate_non_live_outcome_row()
        elif self.status in LIVE_SYSTEM_STATUSES:
            if self.evidence_level in LIVE_SYSTEM_EVIDENCE_LEVELS:
                self._validate_live_system_row()
            else:
                self._validate_non_live_outcome_row()
        elif self.status in CAPABILITY_GAP_STATUSES:
            self._validate_capability_gap_row()
        else:
            self._validate_non_live_classification_row()
        return self

    def _validate_live_model_row(self) -> None:
        if self.evidence_level in LIVE_SYSTEM_EVIDENCE_LEVELS:
            self._validate_live_system_row()
            return
        if self.evidence_level not in LIVE_EVIDENCE_LEVELS:
            raise ValueError("passed/failed live rows must use live evidence levels")
        if self.report_mode in FORBIDDEN_LIVE_REPORT_MODES:
            raise ValueError(f"{self.report_mode} report mode cannot be claimed as live evidence")
        if self.evidence_level in FORBIDDEN_LIVE_EVIDENCE_LEVELS:
            raise ValueError(f"{self.evidence_level} evidence cannot be claimed as live evidence")
        if not self.provider_calls_enabled:
            raise ValueError("live rows require provider_calls_enabled=true")
        if not self.live_model_calls or self.live_model_calls <= 0:
            raise ValueError("passed/failed live rows require live_model_calls > 0")
        if not self.artifacts:
            raise ValueError("live rows require at least one artifact reference")
        _validate_artifacts_not_dry_run_or_scaffold(self.artifacts)
        _validate_artifacts_not_manifest_only(self.artifacts)

    def _validate_live_operational_row(self) -> None:
        if self.evidence_level not in (*LIVE_EVIDENCE_LEVELS, *LIVE_SYSTEM_EVIDENCE_LEVELS):
            raise ValueError("live operational rows must use live or live system evidence levels")
        if self.report_mode in FORBIDDEN_LIVE_REPORT_MODES:
            raise ValueError(f"{self.report_mode} report mode cannot be claimed as live evidence")
        if not self.provider_calls_enabled:
            raise ValueError("live operational rows require provider_calls_enabled=true")
        if not self.reason or not self.reason.strip():
            raise ValueError("live operational rows require an explicit reason")
        _validate_artifacts_not_dry_run_or_scaffold(self.artifacts)

    def _validate_live_system_row(self) -> None:
        if self.evidence_level not in LIVE_SYSTEM_EVIDENCE_LEVELS:
            raise ValueError("live system rows must use live system evidence levels")
        if self.live_model_calls not in (0, None):
            raise ValueError("live system rows must not count model behavior calls")
        if self.live_model_calls is None:
            raise ValueError("live system rows must record live_model_calls=0")
        if not (self.provider_calls_enabled or bool(self.metadata.get("target_execution_enabled"))):
            raise ValueError("live system rows require provider_calls_enabled=true or target_execution_enabled=true")
        if not self.reason or not self.reason.strip():
            raise ValueError("live system rows require an explicit reason")
        if not _has_live_system_observation(self.metadata):
            raise ValueError("live system rows require an observed target call, trace, or target artifact count")
        _validate_artifacts_not_dry_run_or_scaffold(self.artifacts)

    def _validate_capability_gap_row(self) -> None:
        if self.evidence_level in LIVE_SYSTEM_EVIDENCE_LEVELS:
            self._validate_live_system_row()
            return
        if self.evidence_level not in NON_LIVE_CLASSIFICATION_LEVELS:
            raise ValueError("capability gap rows must use live system or classification evidence levels")
        if self.live_model_calls not in (0, None):
            raise ValueError("capability gap rows must have live_model_calls=0")
        if self.live_model_calls is None:
            raise ValueError("capability gap rows must record live_model_calls=0")
        if not self.reason or not self.reason.strip():
            raise ValueError("capability gap rows require an explicit reason")

    def _validate_non_live_outcome_row(self) -> None:
        if self.evidence_level not in NON_LIVE_CLASSIFICATION_LEVELS:
            raise ValueError("non-live target/operational outcome rows must use classification evidence levels")
        if self.live_model_calls not in (0, None):
            raise ValueError("non-live target/operational outcome rows must have live_model_calls=0")
        if self.live_model_calls is None:
            raise ValueError("non-live target/operational outcome rows must record live_model_calls=0")
        if not self.reason or not self.reason.strip():
            raise ValueError("non-live target/operational outcome rows require an explicit reason")
        _validate_artifacts_not_dry_run_or_scaffold(self.artifacts)

    def _validate_non_live_classification_row(self) -> None:
        if self.status not in NON_LIVE_CLASSIFICATION_STATUSES:
            raise ValueError(f"unsupported live evidence status: {self.status}")
        if self.evidence_level not in NON_LIVE_CLASSIFICATION_LEVELS:
            raise ValueError("non-live classification rows must use non-live classification evidence levels")
        if self.live_model_calls not in (0, None):
            raise ValueError("non-live classification rows must have live_model_calls=0")
        if self.live_model_calls is None:
            raise ValueError("non-live classification rows must record live_model_calls=0")
        if not self.reason or not self.reason.strip():
            raise ValueError("non-live classification rows require an explicit reason")
        _validate_artifacts_not_dry_run_or_scaffold(self.artifacts)


class LiveEvidenceMatrix(VersionedLiveEvidenceModel):
    schema_version: str = LIVE_EVIDENCE_MATRIX_SCHEMA_VERSION
    matrix_id: str
    generated_at: str
    surfaces: list[LiveSurfaceRecord] = Field(default_factory=list)
    rows: list[LiveEvidenceRow] = Field(min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_matrix_rows(self) -> "LiveEvidenceMatrix":
        row_ids: set[str] = set()
        surface_ids = {surface.surface_id for surface in self.surfaces}
        for row in self.rows:
            if row.row_id in row_ids:
                raise ValueError(f"duplicate live evidence row id: {row.row_id}")
            row_ids.add(row.row_id)
            if surface_ids and row.surface_id not in surface_ids:
                raise ValueError(f"row {row.row_id} references unknown surface: {row.surface_id}")
            if row.status in NON_LIVE_CLASSIFICATION_STATUSES and not row.reason:
                raise ValueError(f"row {row.row_id} requires a reason")
            if row.status in (*LIVE_SYSTEM_STATUSES, *CAPABILITY_GAP_STATUSES) and not row.reason:
                raise ValueError(f"row {row.row_id} requires a reason")
        return self


def summarize_response(response_text: str, *, excerpt_limit: int = 240) -> RedactedResponseSummary:
    redacted = redact_public_text(response_text)
    return RedactedResponseSummary(
        sha256=redacted.sha256,
        length=redacted.length,
        redacted_excerpt=redacted_preview(response_text, limit=excerpt_limit),
        redaction=RedactionMetadata(
            status="redacted" if redacted.redacted else "not_applicable",
            sha256=redacted.sha256,
            length=redacted.length,
            marker="[REDACTED]" if redacted.redacted else None,
            matched_labels=redacted.matched_labels,
        ),
    )


def _artifact_name(value: str | None) -> str:
    if not value:
        return ""
    return PurePosixPath(str(value).replace("\\", "/")).name


def _validate_artifacts_not_dry_run_or_scaffold(artifacts: list[ArtifactRef]) -> None:
    for artifact in artifacts:
        names = {_artifact_name(artifact.path), _artifact_name(artifact.relative_path)}
        lowered_names = {name.lower() for name in names if name}
        if any(fragment in name for name in lowered_names for fragment in FORBIDDEN_LIVE_ARTIFACT_NAME_FRAGMENTS):
            raise ValueError("dry-run/scaffold/fixture artifacts cannot be used as live evidence")
        values = {
            str(artifact.kind or "").lower(),
            str(artifact.artifact_type or "").lower(),
            str(artifact.metadata.get("mode", "")).lower(),
            str(artifact.metadata.get("report_mode", "")).lower(),
            str(artifact.metadata.get("evidence_level", "")).lower(),
        }
        if values & set(FORBIDDEN_LIVE_REPORT_MODES):
            raise ValueError("dry-run/scaffold/fixture/simulated artifacts cannot be used as live evidence")
        if "scaffold_only" in values:
            raise ValueError("scaffold-only artifacts cannot be used as live evidence")


def _validate_artifacts_not_manifest_only(artifacts: list[ArtifactRef]) -> None:
    values: set[str] = set()
    for artifact in artifacts:
        values.add(str(artifact.kind or "").lower())
        values.add(str(artifact.artifact_type or "").lower())
    if values and values <= set(MANIFEST_ONLY_ARTIFACT_TYPES):
        raise ValueError("manifest-only artifacts cannot be used as live evidence")


def _has_live_system_observation(metadata: dict[str, Any]) -> bool:
    for key in ("target_calls", "target_call_count", "target_traces", "target_trace_count", "target_artifacts", "target_artifact_count"):
        value = metadata.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, int | float) and value > 0:
            return True
        if isinstance(value, (list, tuple, set, dict)) and len(value) > 0:
            return True
    return False


def _infer_evidence_fidelity(row: dict[str, Any]) -> LiveEvidenceFidelity:
    status = str(row.get("status") or "")
    if status == "provider_capability_gap":
        return "provider_capability_gap"
    if status in {"target_capability_gap", "target_config_error", "target_error", "checkpoint_not_run", "not_supported", "not_implemented", "preflight_failed", "skipped_by_operator", "skipped_by_flag", "infra_error", "timeout"}:
        return "target_error"

    metadata = row.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    if metadata.get("auto_wrapped") is True or metadata.get("auto_wrapper_surface"):
        return "auto_wrapper_trace"

    target = row.get("target")
    target_metadata: dict[str, Any] = {}
    if isinstance(target, dict):
        raw_meta = target.get("metadata")
        target_metadata = raw_meta if isinstance(raw_meta, dict) else {}
    target_type = str(metadata.get("target_type") or target_metadata.get("target_type") or "")
    output_dir = str(metadata.get("output_dir") or "")
    surface_id = str(row.get("surface_id") or "")
    evidence_level = str(row.get("evidence_level") or "")
    controlled_lab = bool(
        metadata.get("lab_environment")
        or metadata.get("controlled_lab")
        or metadata.get("controlled_surface")
        or target_metadata.get("lab_environment")
        or target_metadata.get("controlled_lab")
        or target_metadata.get("harness_proxy")
    )

    if evidence_level in {"live_text_model", "live_multimodal_model"}:
        return "prompt_model_trace"
    if target_type == "rag_service" or output_dir.startswith("rag-service/") or surface_id == "pack:rag-v1":
        return "controlled_rag_trace" if controlled_lab else "live_rag_service_trace"
    if output_dir.startswith("rag/"):
        return "fixture_rag_trace"
    if target_type == "tool_agent" or output_dir.startswith(("tool-agent/", "self-modification-tool-agent/")):
        return "controlled_tool_trace" if controlled_lab else "live_tool_trace"
    if target_type == "workflow_harness" or output_dir.startswith(("workflow-harness/", "self-modification-workflow/")):
        return "controlled_workflow_trace" if controlled_lab else "live_workflow_trace"
    if target_type == "memory_agent" or output_dir.startswith(("memory-agent/", "self-modification-memory-agent/")):
        return "controlled_memory_trace" if controlled_lab else "live_memory_trace"
    if target_type == "multi_agent" or output_dir.startswith(("multi-agent/", "self-modification-multi-agent/")):
        return "controlled_multi_agent_trace" if controlled_lab else "live_multi_agent_trace"
    if target_type == "browser_agent" or output_dir.startswith("browser-agent/"):
        return "controlled_browser_trace" if controlled_lab else "live_browser_trace"
    if target_type == "code_agent" or output_dir.startswith(("code-agent/", "self-modification-code-agent/")):
        return "controlled_code_workspace_trace" if controlled_lab else "live_code_agent_trace"
    if evidence_level in {"live_system", "live_system_trace"}:
        return "live_tool_trace"
    return "target_error"
