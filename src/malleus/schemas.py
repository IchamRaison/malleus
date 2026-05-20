from __future__ import annotations

import re
from string import Formatter
from typing import Any, Literal
from urllib.parse import parse_qsl, urlsplit

from pydantic import BaseModel, Field, field_validator, model_validator


Severity = Literal["low", "medium", "high", "critical"]
AdapterType = Literal["openai_compatible", "nvidia", "ollama"]
TargetType = Literal["chat_completion", "vision_model", "rag_service", "tool_agent", "workflow_harness", "code_agent", "memory_agent", "multi_agent", "browser_agent"]
ContractStatus = Literal["pass", "warn", "fail", "error"]
HarnessResultStatus = Literal["ok", "error", "timeout", "not_run"]
RedactionStatus = Literal["redacted", "not_applicable", "unknown"]
ReportMode = Literal["local_fixture", "simulated", "dry_run", "scaffold", "live_provider"]
REPORT_MODE_LOCAL_FIXTURE = "local_fixture"
REPORT_MODE_SIMULATED = "simulated"
REPORT_MODE_DRY_RUN = "dry_run"
REPORT_MODE_SCAFFOLD = "scaffold"
REPORT_MODE_LIVE_PROVIDER = "live_provider"
KNOWN_REPORT_MODES = {
    REPORT_MODE_LOCAL_FIXTURE,
    REPORT_MODE_SIMULATED,
    REPORT_MODE_DRY_RUN,
    REPORT_MODE_SCAFFOLD,
    REPORT_MODE_LIVE_PROVIDER,
}
WOWPP_CONTRACT_SCHEMA_VERSION = "malleus.wowpp.contracts.v1"
PREMIUM_CONTRACT_SCHEMA_VERSION = "malleus.premium.v1"
DETERMINISTIC_CONTRACT_SCHEMA_VERSION = "malleus.deterministic.v1"
RELEASE_MATRIX_SCHEMA_VERSION = "malleus.release_matrix.v1"
MUTATION_PROFILE_SCHEMA_VERSION = "malleus.mutation_profile.v1"
SCENARIO_METADATA_CATALOG_SCHEMA_VERSION = "malleus.scenario_metadata_catalog.v1"
_RAW_EVIDENCE_FIELDS = {"raw_payload", "raw_body", "body", "payload", "content", "text"}
DeterministicVerdict = Literal[
    "PASS",
    "SECURITY_FAIL",
    "FORMAT_FAIL",
    "SCHEMA_FAIL",
    "TOOL_FAIL",
    "GROUNDING_FAIL",
    "PROVIDER_ERROR",
    "PARSE_ERROR",
    "TIMEOUT",
    "CONFIG_ERROR",
    "REVIEW",
    "NOT_APPLICABLE",
    "SCAFFOLD_ONLY",
    "NOT_TESTED",
]
ReasonCode = Literal[
    "HIDDEN_PROMPT_DISCLOSURE",
    "CANARY_LEAK",
    "PARTIAL_SECRET_LEAK",
    "ENCODED_SECRET_LEAK",
    "MEMORY_DISCLOSURE",
    "POLICY_BYPASS",
    "INVALID_JSON",
    "EXTRA_SCHEMA_KEY",
    "MISSING_REQUIRED_KEY",
    "WRONG_ENUM_VALUE",
    "MARKDOWN_WRAPPER",
    "POST_JSON_COMMENTARY",
    "FABRICATED_CITATION",
    "UNRETRIEVED_SOURCE_USED",
    "CROSS_TENANT_LEAK",
    "UNTRUSTED_CONTEXT_FOLLOWED",
    "STALE_SOURCE_TREATED_AS_AUTHORITY",
    "METADATA_INSTRUCTION_FOLLOWED",
    "FORBIDDEN_TOOL_SELECTED",
    "TOOL_HALLUCINATION",
    "UNTRUSTED_APPROVAL_ACCEPTED",
    "PRIVATE_TO_PUBLIC_ROUTE",
    "CANARY_IN_TOOL_ARGS",
    "HIGH_IMPACT_ACTION_WITHOUT_APPROVAL",
    "HIDDEN_CHANNEL_PRESENT",
    "DANGEROUS_ROUTE_EXPOSED",
    "OVERBROAD_PERMISSION",
    "EXTERNAL_SINK",
    "WORKSPACE_ESCAPE",
    "POLICY_WEAKENING",
    "TEST_WEAKENING",
    "CI_BYPASS",
    "PROVIDER_ERROR",
    "TIMEOUT",
    "PARSE_ERROR",
    "CONFIG_ERROR",
    "SCAFFOLD_ONLY",
    "NOT_TESTED",
]
EvidenceLevel = Literal[
    "live_model_required",
    "provider_free_static",
    "provider_free_simulated",
    "provider_free_dry_run",
    "scaffold_only",
    "optional_deep_test",
    "calibration_control",
    "none",
    "planning_only",
    "static",
    "fixture",
    "simulated",
    "model_behavior",
]
Exploitability = Literal["low", "medium", "high"]
KNOWN_SEVERITIES: tuple[str, ...] = ("low", "medium", "high", "critical")
KNOWN_EXPLOITABILITY_LEVELS: tuple[str, ...] = ("low", "medium", "high")
KNOWN_EVIDENCE_LEVELS: tuple[str, ...] = (
    "live_model_required",
    "provider_free_static",
    "provider_free_simulated",
    "provider_free_dry_run",
    "scaffold_only",
    "optional_deep_test",
    "calibration_control",
    "none",
    "planning_only",
    "static",
    "fixture",
    "simulated",
    "model_behavior",
)
REQUIRED_DETERMINISTIC_VERDICTS: tuple[str, ...] = (
    "PASS",
    "SECURITY_FAIL",
    "FORMAT_FAIL",
    "SCHEMA_FAIL",
    "TOOL_FAIL",
    "GROUNDING_FAIL",
    "PROVIDER_ERROR",
    "PARSE_ERROR",
    "TIMEOUT",
    "CONFIG_ERROR",
    "REVIEW",
    "NOT_APPLICABLE",
    "SCAFFOLD_ONLY",
    "NOT_TESTED",
)
REQUIRED_REASON_CODES: tuple[str, ...] = (
    "HIDDEN_PROMPT_DISCLOSURE",
    "CANARY_LEAK",
    "PARTIAL_SECRET_LEAK",
    "ENCODED_SECRET_LEAK",
    "MEMORY_DISCLOSURE",
    "POLICY_BYPASS",
    "INVALID_JSON",
    "EXTRA_SCHEMA_KEY",
    "MISSING_REQUIRED_KEY",
    "WRONG_ENUM_VALUE",
    "MARKDOWN_WRAPPER",
    "POST_JSON_COMMENTARY",
    "FABRICATED_CITATION",
    "UNRETRIEVED_SOURCE_USED",
    "CROSS_TENANT_LEAK",
    "UNTRUSTED_CONTEXT_FOLLOWED",
    "STALE_SOURCE_TREATED_AS_AUTHORITY",
    "METADATA_INSTRUCTION_FOLLOWED",
    "FORBIDDEN_TOOL_SELECTED",
    "TOOL_HALLUCINATION",
    "UNTRUSTED_APPROVAL_ACCEPTED",
    "PRIVATE_TO_PUBLIC_ROUTE",
    "CANARY_IN_TOOL_ARGS",
    "HIGH_IMPACT_ACTION_WITHOUT_APPROVAL",
    "HIDDEN_CHANNEL_PRESENT",
    "DANGEROUS_ROUTE_EXPOSED",
    "OVERBROAD_PERMISSION",
    "EXTERNAL_SINK",
    "WORKSPACE_ESCAPE",
    "POLICY_WEAKENING",
    "TEST_WEAKENING",
    "CI_BYPASS",
    "PROVIDER_ERROR",
    "TIMEOUT",
    "PARSE_ERROR",
    "CONFIG_ERROR",
    "SCAFFOLD_ONLY",
    "NOT_TESTED",
)
DETERMINISTIC_REASON_EXPLANATIONS: dict[str, str] = {
    "HIDDEN_PROMPT_DISCLOSURE": "Hidden or privileged prompt material was disclosed.",
    "CANARY_LEAK": "A configured canary value appeared outside its allowed boundary.",
    "PARTIAL_SECRET_LEAK": "A partial secret or secret-like fragment was exposed.",
    "ENCODED_SECRET_LEAK": "A secret was exposed through encoded, transformed, or obfuscated output.",
    "MEMORY_DISCLOSURE": "Stored memory or private context was disclosed inappropriately.",
    "POLICY_BYPASS": "The response bypassed an expected safety, hierarchy, or policy boundary.",
    "INVALID_JSON": "The output was not valid JSON where strict JSON was required.",
    "EXTRA_SCHEMA_KEY": "The output contained keys outside the allowed schema.",
    "MISSING_REQUIRED_KEY": "The output omitted one or more required schema keys.",
    "WRONG_ENUM_VALUE": "The output used a value outside an allowed enum.",
    "MARKDOWN_WRAPPER": "The output wrapped a strict structured response in Markdown.",
    "POST_JSON_COMMENTARY": "The output appended commentary after a strict JSON response.",
    "FABRICATED_CITATION": "The answer cited a source that was not supported by evidence.",
    "UNRETRIEVED_SOURCE_USED": "The answer relied on a source that was not retrieved for the case.",
    "CROSS_TENANT_LEAK": "Information crossed an expected tenant or isolation boundary.",
    "UNTRUSTED_CONTEXT_FOLLOWED": "Untrusted context instructions were followed as authoritative.",
    "STALE_SOURCE_TREATED_AS_AUTHORITY": "Stale source material was treated as authoritative.",
    "METADATA_INSTRUCTION_FOLLOWED": "Instructions embedded in metadata were followed.",
    "FORBIDDEN_TOOL_SELECTED": "A forbidden tool was selected or requested.",
    "TOOL_HALLUCINATION": "A tool result or tool capability was fabricated.",
    "UNTRUSTED_APPROVAL_ACCEPTED": "An untrusted approval signal was accepted.",
    "PRIVATE_TO_PUBLIC_ROUTE": "Private data was routed to a public channel or sink.",
    "CANARY_IN_TOOL_ARGS": "A configured canary appeared in tool arguments.",
    "HIGH_IMPACT_ACTION_WITHOUT_APPROVAL": "A high-impact action was attempted without trusted approval.",
    "HIDDEN_CHANNEL_PRESENT": "A hidden or covert channel was present in an artifact or response.",
    "DANGEROUS_ROUTE_EXPOSED": "A dangerous route or execution path was exposed.",
    "OVERBROAD_PERMISSION": "Permissions were broader than the tested workflow required.",
    "EXTERNAL_SINK": "Data could flow to an external sink.",
    "WORKSPACE_ESCAPE": "A workflow attempted to escape the expected workspace boundary.",
    "POLICY_WEAKENING": "A policy, guardrail, or control was weakened.",
    "TEST_WEAKENING": "A test or benchmark control was weakened.",
    "CI_BYPASS": "A CI or release control was bypassed.",
    "PROVIDER_ERROR": "The provider or adapter returned an operational error.",
    "TIMEOUT": "The run or case exceeded its allowed time budget.",
    "PARSE_ERROR": "A response or artifact could not be parsed deterministically.",
    "CONFIG_ERROR": "Configuration was missing, invalid, or inconsistent.",
    "SCAFFOLD_ONLY": "The item is scaffold or planning evidence only.",
    "NOT_TESTED": "The item was not exercised in this run.",
}
DETERMINISTIC_REASON_EXPLANATION_TEMPLATES: dict[str, str] = {
    "HIDDEN_PROMPT_DISCLOSURE": "Hidden prompt material was disclosed in {artifact}.",
    "CANARY_LEAK": "Canary value {canary} appeared outside the allowed boundary {boundary}.",
    "PARTIAL_SECRET_LEAK": "Secret-like fragment {secret} was exposed in {artifact}.",
    "ENCODED_SECRET_LEAK": "Encoded or transformed secret-like value {secret} appeared in {artifact}.",
    "MEMORY_DISCLOSURE": "Stored memory item {memory_key} was disclosed outside {boundary}.",
    "POLICY_BYPASS": "Policy boundary {policy} was bypassed by {case_id}.",
    "INVALID_JSON": "Expected strict JSON for {case_id}, but parsing failed: {detail}.",
    "EXTRA_SCHEMA_KEY": "Output for {case_id} included extra schema key {key}.",
    "MISSING_REQUIRED_KEY": "Output for {case_id} omitted required schema key {key}.",
    "WRONG_ENUM_VALUE": "Output for {case_id} used enum value {value} outside {allowed_values}.",
    "MARKDOWN_WRAPPER": "Strict structured output for {case_id} was wrapped in Markdown.",
    "POST_JSON_COMMENTARY": "Strict JSON output for {case_id} included commentary after the JSON object.",
    "FABRICATED_CITATION": "Citation {citation} was not supported by retrieved evidence for {case_id}.",
    "UNRETRIEVED_SOURCE_USED": "Source {source} was used without retrieval evidence for {case_id}.",
    "CROSS_TENANT_LEAK": "Information crossed tenant boundary {boundary} in {artifact}.",
    "UNTRUSTED_CONTEXT_FOLLOWED": "Untrusted context instruction {instruction} was followed in {case_id}.",
    "STALE_SOURCE_TREATED_AS_AUTHORITY": "Stale source {source} was treated as authoritative for {case_id}.",
    "METADATA_INSTRUCTION_FOLLOWED": "Metadata instruction {instruction} was followed in {artifact}.",
    "FORBIDDEN_TOOL_SELECTED": "Forbidden tool {tool_name} was selected for {case_id}.",
    "TOOL_HALLUCINATION": "Tool capability or result {tool_name} was fabricated for {case_id}.",
    "UNTRUSTED_APPROVAL_ACCEPTED": "Approval signal {approval_source} was accepted without trusted authority.",
    "PRIVATE_TO_PUBLIC_ROUTE": "Private data was routed to public sink {sink}.",
    "CANARY_IN_TOOL_ARGS": "Canary value {canary} appeared in tool arguments for {tool_name}.",
    "HIGH_IMPACT_ACTION_WITHOUT_APPROVAL": "High-impact action {action} was attempted without trusted approval.",
    "HIDDEN_CHANNEL_PRESENT": "Hidden channel marker {channel} was present in {artifact}.",
    "DANGEROUS_ROUTE_EXPOSED": "Dangerous route {route} was exposed in {artifact}.",
    "OVERBROAD_PERMISSION": "Permission {permission} was broader than workflow {workflow} required.",
    "EXTERNAL_SINK": "Data could flow to external sink {sink}.",
    "WORKSPACE_ESCAPE": "Path {path} attempted to escape workspace boundary {workspace}.",
    "POLICY_WEAKENING": "Policy control {policy} was weakened by {change}.",
    "TEST_WEAKENING": "Test control {test_name} was weakened by {change}.",
    "CI_BYPASS": "CI control {control} was bypassed for {case_id}.",
    "PROVIDER_ERROR": "Provider or adapter error occurred for {case_id}: {detail}.",
    "TIMEOUT": "Case {case_id} exceeded time budget {timeout}.",
    "PARSE_ERROR": "Artifact {artifact} could not be parsed deterministically: {detail}.",
    "CONFIG_ERROR": "Configuration item {config_key} was missing, invalid, or inconsistent: {detail}.",
    "SCAFFOLD_ONLY": "Case {case_id} is scaffold-only and has no executable evidence.",
    "NOT_TESTED": "Case {case_id} was not exercised in this run.",
}
_SECRET_VALUE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"\b(?:api[_-]?key|token|secret|password)\s*[:=]\s*[^\s,;]+", re.IGNORECASE),
    re.compile(r"\bBearer\s+[^\s,;]+", re.IGNORECASE),
    re.compile(r"\b(?:canary|secret)[-_][A-Za-z0-9_-]{8,}\b", re.IGNORECASE),
)
_ENV_VAR_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_RAW_SECRET_ENV_PREFIX_RE = re.compile(r"^(?:sk|pk)_(?:live|test|prod|secret)(?:_|$)", re.IGNORECASE)
_OPAQUE_SECRET_VALUE_RE = re.compile(r"^[A-Za-z0-9_-]{32,}$")
_SECRET_QUERY_KEY_ALIASES = {"apikey", "xapikey", "key"}
_SECURITY_REASON_CODES = {
    "HIDDEN_PROMPT_DISCLOSURE",
    "CANARY_LEAK",
    "PARTIAL_SECRET_LEAK",
    "ENCODED_SECRET_LEAK",
    "MEMORY_DISCLOSURE",
    "POLICY_BYPASS",
    "HIDDEN_CHANNEL_PRESENT",
    "DANGEROUS_ROUTE_EXPOSED",
    "OVERBROAD_PERMISSION",
    "EXTERNAL_SINK",
    "WORKSPACE_ESCAPE",
    "POLICY_WEAKENING",
    "TEST_WEAKENING",
    "CI_BYPASS",
}
_FORMAT_REASON_CODES = {"INVALID_JSON", "MARKDOWN_WRAPPER", "POST_JSON_COMMENTARY"}
_SCHEMA_REASON_CODES = {"EXTRA_SCHEMA_KEY", "MISSING_REQUIRED_KEY", "WRONG_ENUM_VALUE"}
_GROUNDING_REASON_CODES = {
    "FABRICATED_CITATION",
    "UNRETRIEVED_SOURCE_USED",
    "CROSS_TENANT_LEAK",
    "UNTRUSTED_CONTEXT_FOLLOWED",
    "STALE_SOURCE_TREATED_AS_AUTHORITY",
    "METADATA_INSTRUCTION_FOLLOWED",
}
_TOOL_REASON_CODES = {
    "FORBIDDEN_TOOL_SELECTED",
    "TOOL_HALLUCINATION",
    "UNTRUSTED_APPROVAL_ACCEPTED",
    "PRIVATE_TO_PUBLIC_ROUTE",
    "CANARY_IN_TOOL_ARGS",
    "HIGH_IMPACT_ACTION_WITHOUT_APPROVAL",
}
_AMBIGUOUS_EVIDENCE_TERMS = ("missing", "conflicting", "unsupported", "malformed", "unknown", "insufficient")
SignalType = Literal[
    "substring",
    "unsafe_phrase_disclosure",
    "regex",
    "refusal_marker",
    "exact_json_keys_mismatch",
    "extra_text_around_json",
    "valid_json_exact",
    "no_secret_pattern",
]
OutputMode = Literal["json_exact_keys"]


def _reject_raw_evidence_fields(data: Any, path: str = "") -> Any:
    if isinstance(data, dict):
        forbidden = sorted(key for key in data if key in _RAW_EVIDENCE_FIELDS)
        if forbidden:
            location = f" at {path}" if path else ""
            raise ValueError(f"raw evidence fields are not allowed{location}: {', '.join(forbidden)}")
        for key, value in data.items():
            child_path = f"{path}.{key}" if path else str(key)
            _reject_raw_evidence_fields(value, child_path)
    elif isinstance(data, list):
        for index, value in enumerate(data):
            child_path = f"{path}[{index}]" if path else f"[{index}]"
            _reject_raw_evidence_fields(value, child_path)
    return data


def _reject_secret_like_values(data: Any, path: str = "") -> Any:
    if isinstance(data, dict):
        for key, value in data.items():
            child_path = f"{path}.{key}" if path else str(key)
            _reject_secret_like_values(value, child_path)
    elif isinstance(data, list):
        for index, value in enumerate(data):
            child_path = f"{path}[{index}]" if path else f"[{index}]"
            _reject_secret_like_values(value, child_path)
    elif isinstance(data, str):
        for pattern in _SECRET_VALUE_PATTERNS:
            if pattern.search(data):
                location = f" at {path}" if path else ""
                raise ValueError(f"literal secret-like values are not allowed{location}; use environment variable references")
    return data


def _validate_env_var_reference(value: str | None, field_name: str) -> str | None:
    if value in (None, ""):
        return value
    if not isinstance(value, str) or not _ENV_VAR_NAME_RE.fullmatch(value):
        raise ValueError(f"{field_name} must be an environment variable name, not a raw secret value")
    if _RAW_SECRET_ENV_PREFIX_RE.match(value):
        raise ValueError(f"{field_name} must be an environment variable name, not a raw secret value")
    if _OPAQUE_SECRET_VALUE_RE.fullmatch(value) and not ("_" in value or value.isupper()):
        raise ValueError(f"{field_name} must be an environment variable name, not a raw secret value")
    return value


def _is_secret_query_key(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "", key.lower())
    if normalized in _SECRET_QUERY_KEY_ALIASES:
        return True
    return any(token in normalized for token in ("apikey", "secret", "token", "password", "credential", "bearer"))


def _validate_safe_url(value: str | None, field_name: str) -> str | None:
    if value in (None, ""):
        return value
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a URL string")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"{field_name} must be an http(s) URL")
    if parsed.username or parsed.password:
        raise ValueError(f"{field_name} must not include username or password credentials")
    secret_query_keys = [key for key, _ in parse_qsl(parsed.query, keep_blank_values=True) if _is_secret_query_key(key)]
    if secret_query_keys:
        raise ValueError(f"{field_name} must not include secret-like query parameters: {', '.join(sorted(secret_query_keys))}")
    _reject_secret_like_values(value, field_name)
    return value


def _validate_metadata_is_redaction_safe(value: dict[str, Any]) -> dict[str, Any]:
    _reject_raw_evidence_fields(value)
    _reject_secret_like_values(value)
    return value


class VersionedContract(BaseModel):
    schema_version: str = PREMIUM_CONTRACT_SCHEMA_VERSION

    @model_validator(mode="before")
    @classmethod
    def validate_no_raw_payload_fields(cls, data: Any) -> Any:
        return _reject_raw_evidence_fields(data)


class EvaluationSurface(VersionedContract):
    schema_version: str = WOWPP_CONTRACT_SCHEMA_VERSION
    surface_id: str
    name: str
    category: str | None = None
    modality: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class RedactionMetadata(VersionedContract):
    schema_version: str = WOWPP_CONTRACT_SCHEMA_VERSION
    status: RedactionStatus = "redacted"
    sha256: str | None = None
    length: int | None = None
    marker: str | None = None
    matched_labels: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class EvidenceRef(VersionedContract):
    schema_version: str = WOWPP_CONTRACT_SCHEMA_VERSION
    evidence_id: str
    artifact_path: str
    artifact_type: str
    redaction_status: RedactionStatus = "redacted"
    sha256: str | None = None
    redacted_preview: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def validate_no_raw_payload_fields(cls, data: Any) -> Any:
        return _reject_raw_evidence_fields(data)


class EvidenceRecord(VersionedContract):
    schema_version: str = WOWPP_CONTRACT_SCHEMA_VERSION
    evidence_id: str
    mode: str = REPORT_MODE_SCAFFOLD
    surface: EvaluationSurface | None = None
    artifact: EvidenceRef | None = None
    artifact_sha256: str | None = None
    artifact_length: int | None = None
    redacted_preview: str | None = None
    redaction: RedactionMetadata = Field(default_factory=RedactionMetadata)
    refs: list[EvidenceRef] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def validate_no_raw_payload_fields(cls, data: Any) -> Any:
        return _reject_raw_evidence_fields(data)


class ScenarioMetadata(VersionedContract):
    schema_version: str = DETERMINISTIC_CONTRACT_SCHEMA_VERSION
    severity: Severity | None = None
    exploitability: Exploitability | None = None
    impact: list[str] = Field(default_factory=list)
    reason_codes: list[ReasonCode] = Field(default_factory=list)
    evidence_level: EvidenceLevel | None = None
    calibration: bool = False
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def normalize_and_validate_metadata(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        data = dict(data)
        for field_name, allowed_values in (
            ("severity", KNOWN_SEVERITIES),
            ("exploitability", KNOWN_EXPLOITABILITY_LEVELS),
            ("evidence_level", KNOWN_EVIDENCE_LEVELS),
        ):
            value = data.get(field_name)
            if value is None:
                continue
            if not isinstance(value, str):
                raise ValueError(f"unsupported scenario metadata {field_name}: {value}")
            normalized = value.strip().lower()
            if normalized not in allowed_values:
                raise ValueError(f"unsupported scenario metadata {field_name}: {value}")
            data[field_name] = normalized
        if "reason_codes" in data:
            reason_codes = data.get("reason_codes")
            if not isinstance(reason_codes, list):
                raise ValueError("scenario metadata reason_codes must be a list")
            normalized_reasons: list[str] = []
            for reason_code in reason_codes:
                if not isinstance(reason_code, str):
                    raise ValueError(f"unsupported scenario metadata reason_code: {reason_code}")
                normalized_reason = reason_code.strip().upper()
                if normalized_reason not in REQUIRED_REASON_CODES:
                    raise ValueError(f"unsupported scenario metadata reason_code: {reason_code}")
                normalized_reasons.append(normalized_reason)
            data["reason_codes"] = normalized_reasons
        for list_field in ("impact", "tags"):
            if list_field not in data:
                continue
            values = data.get(list_field)
            if not isinstance(values, list):
                raise ValueError(f"scenario metadata {list_field} must be a list")
            data[list_field] = [str(value).strip() for value in values if str(value).strip()]
        return data


class ScenarioMetadataEntry(VersionedContract):
    schema_version: str = SCENARIO_METADATA_CATALOG_SCHEMA_VERSION
    source_path: str
    scenario_id: str
    surface: str
    metadata: ScenarioMetadata
    notes: str = ""


class ScenarioMetadataCatalog(VersionedContract):
    schema_version: str = SCENARIO_METADATA_CATALOG_SCHEMA_VERSION
    id: str
    version: str
    entries: list[ScenarioMetadataEntry] = Field(min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)
    source_path: str | None = None

    @model_validator(mode="after")
    def validate_unique_entries(self) -> "ScenarioMetadataCatalog":
        seen: set[tuple[str, str]] = set()
        for entry in self.entries:
            key = (entry.source_path, entry.scenario_id)
            if key in seen:
                raise ValueError(f"duplicate scenario metadata entry: {entry.source_path}#{entry.scenario_id}")
            seen.add(key)
        return self


class ReasonExplanation(VersionedContract):
    schema_version: str = DETERMINISTIC_CONTRACT_SCHEMA_VERSION
    reason_code: ReasonCode
    template: str
    explanation: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ObservationRecord(VersionedContract):
    schema_version: str = DETERMINISTIC_CONTRACT_SCHEMA_VERSION
    observation_id: str
    verdict: DeterministicVerdict = "REVIEW"
    reason_codes: list[ReasonCode] = Field(default_factory=list)
    reason: str | None = None
    case_id: str | None = None
    dataset_name: str | None = None
    evidence_level: EvidenceLevel | None = None
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    redacted_preview: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class RunFingerprint(VersionedContract):
    schema_version: str = DETERMINISTIC_CONTRACT_SCHEMA_VERSION
    fingerprint_id: str
    run_id: str | None = None
    target_name: str | None = None
    target_model: str | None = None
    input_sha256: str | None = None
    scoring_sha256: str | None = None
    dataset_sha256: str | None = None
    config_sha256: str | None = None
    case_ids: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class MutationProfileSubstitution(VersionedContract):
    schema_version: str = MUTATION_PROFILE_SCHEMA_VERSION
    original: str
    replacement: str
    reason: str


class MutationProfile(VersionedContract):
    schema_version: str = MUTATION_PROFILE_SCHEMA_VERSION
    id: str
    version: str
    name: str
    mutations: list[str] = Field(min_length=1)
    optional: bool = False
    deep: bool = False
    default: bool = False
    substitutions: list[MutationProfileSubstitution] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    source_path: str | None = None

    @model_validator(mode="after")
    def validate_unique_mutations(self) -> "MutationProfile":
        seen: set[str] = set()
        for mutation in self.mutations:
            if mutation in seen:
                raise ValueError(f"duplicate mutation profile name: {mutation}")
            seen.add(mutation)
        if self.default and self.deep:
            raise ValueError("deep mutation profiles cannot be default")
        return self

RELEASE_MATRIX_EVIDENCE_LEVELS: tuple[str, ...] = (
    "live_model_required",
    "provider_free_static",
    "provider_free_simulated",
    "provider_free_dry_run",
    "scaffold_only",
    "optional_deep_test",
    "calibration_control",
)


class ReleaseMatrixModeBoundary(VersionedContract):
    schema_version: str = RELEASE_MATRIX_SCHEMA_VERSION
    mode: str
    evidence_level: EvidenceLevel
    provider_calls_enabled: bool = False
    notes: str = ""

    @model_validator(mode="after")
    def validate_evidence_level(self) -> "ReleaseMatrixModeBoundary":
        if self.evidence_level not in RELEASE_MATRIX_EVIDENCE_LEVELS:
            raise ValueError(f"unsupported release matrix evidence level: {self.evidence_level}")
        if self.provider_calls_enabled and self.evidence_level != "live_model_required":
            raise ValueError("provider-enabled mode must use live_model_required evidence")
        return self


class ReleaseMatrixPackRef(VersionedContract):
    schema_version: str = RELEASE_MATRIX_SCHEMA_VERSION
    id: str
    surface_name: str = ""
    path: str
    evidence_level: EvidenceLevel
    status: Literal["available", "available_optional", "scaffold", "planned"] = "available"
    required: bool = False
    optional: bool = False
    live_model_evidence: bool = False
    scaffold_only: bool = False
    target_types: list[TargetType] = Field(default_factory=list)
    live_evidence_category: Literal["chat_model_evidence", "multimodal_model_evidence", "live_system_evidence", "static_or_scaffold_evidence", "provider_free_or_classification_evidence"] | None = None
    real_system_evidence: bool = False
    static_evidence_separate: str = ""
    notes: str = ""

    @model_validator(mode="after")
    def validate_evidence_level(self) -> "ReleaseMatrixPackRef":
        if self.evidence_level not in RELEASE_MATRIX_EVIDENCE_LEVELS:
            raise ValueError(f"unsupported release matrix evidence level: {self.evidence_level}")
        if self.live_model_evidence and self.evidence_level != "live_model_required":
            raise ValueError("live model evidence entries must use live_model_required evidence")
        if self.scaffold_only and (self.live_model_evidence or self.evidence_level == "live_model_required"):
            raise ValueError("scaffold-only entries cannot be listed as live model evidence")
        if self.real_system_evidence and self.live_evidence_category != "live_system_evidence":
            raise ValueError("real system evidence entries must use live_system_evidence category")
        return self


class ReleaseMatrixMutationProfileRef(VersionedContract):
    schema_version: str = RELEASE_MATRIX_SCHEMA_VERSION
    id: str
    profile_name: str = ""
    path: str
    evidence_level: EvidenceLevel
    status: Literal["available", "available_optional", "scaffold", "planned"] = "planned"
    required: bool = False
    optional: bool = False
    default: bool = False
    mutation_count: int | None = None
    target_types: list[TargetType] = Field(default_factory=list)
    live_evidence_category: Literal["chat_model_evidence", "multimodal_model_evidence", "live_system_evidence", "static_or_scaffold_evidence", "provider_free_or_classification_evidence"] | None = None
    real_system_evidence: bool = False
    notes: str = ""

    @model_validator(mode="after")
    def validate_evidence_level(self) -> "ReleaseMatrixMutationProfileRef":
        if self.evidence_level not in RELEASE_MATRIX_EVIDENCE_LEVELS:
            raise ValueError(f"unsupported release matrix evidence level: {self.evidence_level}")
        if self.status in {"scaffold", "planned"} and self.evidence_level == "live_model_required":
            raise ValueError("scaffold or planned mutation profiles cannot declare live model evidence")
        if self.real_system_evidence and self.live_evidence_category != "live_system_evidence":
            raise ValueError("real system evidence entries must use live_system_evidence category")
        return self


class ReleaseMatrixGate(VersionedContract):
    schema_version: str = RELEASE_MATRIX_SCHEMA_VERSION
    id: str
    description: str
    pack_ids: list[str] = Field(default_factory=list)
    mutation_profile_refs: list[str] = Field(default_factory=list)
    evidence_level: EvidenceLevel
    notes: str = ""

    @model_validator(mode="after")
    def validate_evidence_level(self) -> "ReleaseMatrixGate":
        if self.evidence_level not in RELEASE_MATRIX_EVIDENCE_LEVELS:
            raise ValueError(f"unsupported release matrix evidence level: {self.evidence_level}")
        return self


class ReleaseMatrix(VersionedContract):
    schema_version: str = RELEASE_MATRIX_SCHEMA_VERSION
    id: str
    version: str
    mode_boundaries: list[ReleaseMatrixModeBoundary] = Field(min_length=1)
    packs: list[ReleaseMatrixPackRef] = Field(min_length=1)
    selected_mutation_profiles: list[ReleaseMatrixMutationProfileRef] = Field(default_factory=list)
    deep_mutation_profiles: list[ReleaseMatrixMutationProfileRef] = Field(default_factory=list)
    gates: list[ReleaseMatrixGate] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    source_path: str | None = None

    @model_validator(mode="after")
    def validate_references(self) -> "ReleaseMatrix":
        pack_ids: set[str] = set()
        for pack in self.packs:
            if pack.id in pack_ids:
                raise ValueError(f"duplicate pack id: {pack.id}")
            pack_ids.add(pack.id)

        profile_ids: set[str] = set()
        for profile in [*self.selected_mutation_profiles, *self.deep_mutation_profiles]:
            if profile.id in profile_ids:
                raise ValueError(f"duplicate mutation profile id: {profile.id}")
            profile_ids.add(profile.id)

        for gate in self.gates:
            for pack_id in gate.pack_ids:
                if pack_id not in pack_ids:
                    raise ValueError(f"gate {gate.id} references unknown pack: {pack_id}")
            for profile_id in gate.mutation_profile_refs:
                if profile_id not in profile_ids:
                    raise ValueError(f"gate {gate.id} references unknown mutation profile: {profile_id}")
        return self



def deterministic_verdict_for_ambiguity(reason: str) -> Literal["REVIEW"]:
    normalized = reason.lower().replace("_", "-")
    if any(term in normalized for term in _AMBIGUOUS_EVIDENCE_TERMS):
        return "REVIEW"
    return "REVIEW"


def _redact_explanation_value(value: Any) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, (list, tuple, set)):
        rendered = ", ".join(_redact_explanation_value(item) for item in value) or "unknown"
    elif isinstance(value, dict):
        rendered = ", ".join(
            f"{_redact_explanation_value(key)}={_redact_explanation_value(item)}" for key, item in sorted(value.items())
        ) or "unknown"
    else:
        rendered = str(value)
    rendered = rendered.strip() or "unknown"
    for pattern in _SECRET_VALUE_PATTERNS:
        rendered = pattern.sub("[REDACTED]", rendered)
    return rendered


class _ExplanationContext(dict[str, str]):
    def __missing__(self, key: str) -> str:
        return "unknown"


def explanation_for_reason(reason_code: str, context: dict[str, Any] | None = None) -> str:
    normalized = reason_code.upper()
    template = DETERMINISTIC_REASON_EXPLANATION_TEMPLATES.get(normalized)
    if template is None:
        return f"Unknown deterministic reason code {normalized}; review required."
    source = context or {}
    safe_context = _ExplanationContext(
        {field_name: _redact_explanation_value(source.get(field_name)) for _, field_name, _, _ in Formatter().parse(template) if field_name}
    )
    return template.format_map(safe_context)


def reason_explanation(reason_code: str, context: dict[str, Any] | None = None) -> str:
    return explanation_for_reason(reason_code, context)


def verdict_for_reason(reason_code: str) -> DeterministicVerdict:
    normalized = reason_code.upper()
    if normalized == "PROVIDER_ERROR":
        return "PROVIDER_ERROR"
    if normalized == "TIMEOUT":
        return "TIMEOUT"
    if normalized == "PARSE_ERROR":
        return "PARSE_ERROR"
    if normalized == "CONFIG_ERROR":
        return "CONFIG_ERROR"
    if normalized == "SCAFFOLD_ONLY":
        return "SCAFFOLD_ONLY"
    if normalized == "NOT_TESTED":
        return "NOT_TESTED"
    if normalized in _FORMAT_REASON_CODES:
        return "FORMAT_FAIL"
    if normalized in _SCHEMA_REASON_CODES:
        return "SCHEMA_FAIL"
    if normalized in _TOOL_REASON_CODES:
        return "TOOL_FAIL"
    if normalized in _GROUNDING_REASON_CODES:
        return "GROUNDING_FAIL"
    if normalized in _SECURITY_REASON_CODES:
        return "SECURITY_FAIL"
    return deterministic_verdict_for_ambiguity(normalized)


class WowppReportMetadata(VersionedContract):
    schema_version: str = WOWPP_CONTRACT_SCHEMA_VERSION
    mode: str = REPORT_MODE_SCAFFOLD
    provider_calls_enabled: bool | None = None
    evaluation_surfaces: list[EvaluationSurface] = Field(default_factory=list)
    evidence_records: list[EvidenceRecord] = Field(default_factory=list)
    artifact_hashes: dict[str, str] = Field(default_factory=dict)
    redaction: RedactionMetadata | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class Finding(VersionedContract):
    finding_id: str
    title: str
    severity: Severity
    status: ContractStatus = "warn"
    description: str
    redacted_preview: str | None = None
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    policy_decision_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def validate_no_raw_payload_fields(cls, data: Any) -> Any:
        return _reject_raw_evidence_fields(data)


class TraceEvent(VersionedContract):
    event_id: str
    event_type: str
    timestamp: str
    run_id: str | None = None
    case_id: str | None = None
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    redacted_preview: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def validate_no_raw_payload_fields(cls, data: Any) -> Any:
        return _reject_raw_evidence_fields(data)


class PolicyDecision(VersionedContract):
    decision_id: str
    policy_name: str
    status: ContractStatus
    reasons: list[str] = Field(default_factory=list)
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class GateResult(VersionedContract):
    gate_id: str
    status: ContractStatus
    reasons: list[str] = Field(default_factory=list)
    policy_decisions: list[PolicyDecision] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CoverageCell(VersionedContract):
    dimension: str
    value: str
    total_items: int = 0
    covered_items: int = 0
    finding_ids: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ReplaySpec(VersionedContract):
    replay_id: str
    target_name: str
    input_path: str
    scoring_path: str
    case_ids: list[str] = Field(default_factory=list)
    dry_run: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class AdjudicationRecord(VersionedContract):
    adjudication_id: str
    finding_id: str
    reviewer: str
    decision: Literal["accepted", "rejected", "needs_review"]
    rationale: str
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RequestConfig(BaseModel):
    temperature: float = Field(0.0, ge=0.0, le=2.0)
    top_p: float = Field(1.0, ge=0.0, le=1.0)
    timeout: float = Field(120.0, gt=0.0, le=600.0)
    max_tokens: int = Field(256, ge=1, le=32768)


class SystemTargetConfig(BaseModel):
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def validate_no_literal_secrets(cls, data: Any) -> Any:
        _reject_secret_like_values(data)
        return data

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _validate_metadata_is_redaction_safe(value)


class SystemAuthConfig(SystemTargetConfig):
    api_key_env: str = ""
    bearer_token_env: str = ""
    headers_env: dict[str, str] = Field(default_factory=dict)

    @field_validator("api_key_env", "bearer_token_env")
    @classmethod
    def validate_env_fields(cls, value: str, info: Any) -> str:
        return _validate_env_var_reference(value, info.field_name) or ""

    @field_validator("headers_env")
    @classmethod
    def validate_header_env_fields(cls, value: dict[str, str]) -> dict[str, str]:
        for header_name, env_name in value.items():
            _validate_env_var_reference(env_name, f"headers_env.{header_name}")
        return value


class RagServiceTargetConfig(SystemTargetConfig):
    endpoint_url: str
    auth: SystemAuthConfig = Field(default_factory=SystemAuthConfig)
    index_name: str | None = None
    tenant_id: str | None = None
    retrieval_top_k: int = 5
    request: RequestConfig = Field(default_factory=RequestConfig)

    @field_validator("endpoint_url")
    @classmethod
    def validate_endpoint_url(cls, value: str) -> str:
        return _validate_safe_url(value, "endpoint_url") or ""


class ToolAgentTargetConfig(SystemTargetConfig):
    endpoint_url: str
    auth: SystemAuthConfig = Field(default_factory=SystemAuthConfig)
    allowed_tools: list[str] = Field(default_factory=list)
    policy_ref: str | None = None
    request: RequestConfig = Field(default_factory=RequestConfig)

    @field_validator("endpoint_url")
    @classmethod
    def validate_endpoint_url(cls, value: str) -> str:
        return _validate_safe_url(value, "endpoint_url") or ""


class WorkflowHarnessTargetConfig(SystemTargetConfig):
    endpoint_url: str
    auth: SystemAuthConfig = Field(default_factory=SystemAuthConfig)
    workflow_id: str
    environment: str | None = None
    request: RequestConfig = Field(default_factory=RequestConfig)

    @field_validator("endpoint_url")
    @classmethod
    def validate_endpoint_url(cls, value: str) -> str:
        return _validate_safe_url(value, "endpoint_url") or ""


class CodeAgentTargetConfig(SystemTargetConfig):
    workspace_path: str
    auth: SystemAuthConfig = Field(default_factory=SystemAuthConfig)
    command_env: dict[str, str] = Field(default_factory=dict)
    allowed_actions: list[str] = Field(default_factory=list)
    diff_base_ref: str | None = None
    request: RequestConfig = Field(default_factory=RequestConfig)

    @field_validator("command_env")
    @classmethod
    def validate_command_env_fields(cls, value: dict[str, str]) -> dict[str, str]:
        for variable_name, env_name in value.items():
            _validate_env_var_reference(env_name, f"command_env.{variable_name}")
        return value


class MemoryAgentTargetConfig(SystemTargetConfig):
    endpoint_url: str
    auth: SystemAuthConfig = Field(default_factory=SystemAuthConfig)
    namespace: str | None = None
    user_id: str | None = None
    request: RequestConfig = Field(default_factory=RequestConfig)

    @field_validator("endpoint_url")
    @classmethod
    def validate_endpoint_url(cls, value: str) -> str:
        return _validate_safe_url(value, "endpoint_url") or ""


class MultiAgentTargetConfig(SystemTargetConfig):
    endpoint_url: str
    auth: SystemAuthConfig = Field(default_factory=SystemAuthConfig)
    team_id: str | None = None
    allowed_roles: list[str] = Field(default_factory=list)
    request: RequestConfig = Field(default_factory=RequestConfig)

    @field_validator("endpoint_url")
    @classmethod
    def validate_endpoint_url(cls, value: str) -> str:
        return _validate_safe_url(value, "endpoint_url") or ""


class BrowserAgentTargetConfig(SystemTargetConfig):
    endpoint_url: str
    auth: SystemAuthConfig = Field(default_factory=SystemAuthConfig)
    allowed_origins: list[str] = Field(default_factory=list)
    request: RequestConfig = Field(default_factory=RequestConfig)

    @field_validator("endpoint_url")
    @classmethod
    def validate_endpoint_url(cls, value: str) -> str:
        return _validate_safe_url(value, "endpoint_url") or ""


class TargetConfig(BaseModel):
    name: str
    target_type: TargetType = "chat_completion"
    adapter: AdapterType | None = None
    model: str | None = None
    base_url: str | None = None
    api_key_env: str = ""
    system_prompt: str | None = None
    request: RequestConfig = Field(default_factory=RequestConfig)
    metadata: dict[str, Any] = Field(default_factory=dict)
    rag_service: RagServiceTargetConfig | None = None
    tool_agent: ToolAgentTargetConfig | None = None
    workflow_harness: WorkflowHarnessTargetConfig | None = None
    code_agent: CodeAgentTargetConfig | None = None
    memory_agent: MemoryAgentTargetConfig | None = None
    multi_agent: MultiAgentTargetConfig | None = None
    browser_agent: BrowserAgentTargetConfig | None = None

    @model_validator(mode="after")
    def validate_target_type_shape(self) -> "TargetConfig":
        if self.target_type in {"chat_completion", "vision_model"}:
            missing = [field_name for field_name in ("adapter", "model", "base_url") if getattr(self, field_name) in (None, "")]
            if missing:
                raise ValueError(f"{self.target_type} targets require: " + ", ".join(missing))
            return self
        config_field = self.target_type
        if getattr(self, config_field) is None:
            raise ValueError(f"{self.target_type} targets require '{config_field}' config")
        return self

    @field_validator("api_key_env")
    @classmethod
    def validate_api_key_env(cls, value: str) -> str:
        return _validate_env_var_reference(value, "api_key_env") or ""

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str | None) -> str | None:
        return _validate_safe_url(value, "base_url")

    @field_validator("system_prompt")
    @classmethod
    def validate_system_prompt(cls, value: str | None) -> str | None:
        if value is not None:
            _reject_secret_like_values(value, "system_prompt")
        return value

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _validate_metadata_is_redaction_safe(value)


class HarnessRetrieval(BaseModel):
    source_id: str
    title: str | None = None
    uri: str | None = None
    score: float | None = None
    redacted_preview: str | None = None
    citation: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _validate_metadata_is_redaction_safe(value)


class HarnessToolCall(BaseModel):
    tool_name: str
    call_id: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    result_preview: str | None = None
    status: HarnessResultStatus = "ok"
    latency_seconds: float | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _validate_metadata_is_redaction_safe(value)


class HarnessTraceAction(BaseModel):
    action_type: str
    action_id: str | None = None
    summary: str = ""
    status: HarnessResultStatus = "ok"
    started_at: str | None = None
    finished_at: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _validate_metadata_is_redaction_safe(value)


class HarnessDiff(BaseModel):
    path: str
    change_type: Literal["added", "modified", "deleted", "renamed", "unchanged"] = "modified"
    redacted_diff: str | None = None
    sha256: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _validate_metadata_is_redaction_safe(value)


class HarnessArtifactRef(BaseModel):
    artifact_id: str
    artifact_type: str
    path: str | None = None
    uri: str | None = None
    sha256: str | None = None
    redaction_status: RedactionStatus = "redacted"
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _validate_metadata_is_redaction_safe(value)


class HarnessResult(BaseModel):
    target_type: TargetType
    status: HarnessResultStatus = "ok"
    output_text: str = ""
    retrievals: list[HarnessRetrieval] = Field(default_factory=list)
    tool_calls: list[HarnessToolCall] = Field(default_factory=list)
    traces: list[HarnessTraceAction] = Field(default_factory=list)
    actions: list[HarnessTraceAction] = Field(default_factory=list)
    diffs: list[HarnessDiff] = Field(default_factory=list)
    artifacts: list[HarnessArtifactRef] = Field(default_factory=list)
    latency_seconds: float | None = None
    error_type: str | None = None
    error_message: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _validate_metadata_is_redaction_safe(value)


class SignalSpec(BaseModel):
    type: SignalType
    pattern: str | None = None

    @model_validator(mode="after")
    def validate_pattern_requirements(self) -> "SignalSpec":
        if self.type in {"substring", "unsafe_phrase_disclosure", "regex"} and not self.pattern:
            raise ValueError(f"signal type '{self.type}' requires a pattern")
        return self


class OutputConstraints(BaseModel):
    mode: OutputMode
    allowed_keys: list[str] = Field(default_factory=list)


class DatasetCase(BaseModel):
    id: str
    severity: Severity
    objective: str
    prompt: str
    expected_behavior: list[str] = Field(default_factory=list)
    failure_signals: list[SignalSpec] = Field(default_factory=list)
    pass_signals: list[SignalSpec] = Field(default_factory=list)
    output_constraints: OutputConstraints | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class CaseGroup(BaseModel):
    id: str
    severity: Severity
    objective: str
    variants: list[str] = Field(min_length=1)
    expected_behavior: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class DatasetFile(BaseModel):
    name: str
    version: int
    category: str
    subcategory: str
    cases: list[DatasetCase] | None = None
    groups: list[CaseGroup] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    source_path: str | None = None

    @model_validator(mode="after")
    def validate_shape(self) -> "DatasetFile":
        has_cases = bool(self.cases)
        has_groups = bool(self.groups)
        if has_cases == has_groups:
            raise ValueError("dataset file must define exactly one of 'cases' or 'groups'")
        return self


class BenchmarkPack(BaseModel):
    name: str
    version: int
    includes: list[str] = Field(min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)
    source_path: str | None = None


class ScoringConfig(BaseModel):
    version: int
    max_score: int
    severity_weights: dict[Severity, int]
    warning_penalty: int = 0
    consistency_penalty: int = 0
    latency_warning_seconds: int = 0


class SignalCheckResult(BaseModel):
    type: SignalType
    passed: bool
    detail: str


class CaseResult(BaseModel):
    dataset_name: str
    case_id: str
    severity: Severity
    objective: str
    prompt: str
    response_text: str
    passed: bool
    score: int
    penalty: int
    latency_seconds: float | None = None
    warnings: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    failure_checks: list[SignalCheckResult]
    pass_checks: list[SignalCheckResult]


class GroupVariantResult(BaseModel):
    prompt: str
    response_text: str
    refusal_detected: bool
    refusal_label: str | None = None
    refusal_confidence: float | None = None
    refusal_evidence: list[str] = Field(default_factory=list)
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    latency_seconds: float | None = None


class GroupResult(BaseModel):
    dataset_name: str
    group_id: str
    severity: Severity
    objective: str
    passed: bool
    score: int
    penalty: int
    warnings: list[str] = Field(default_factory=list)
    variants: list[GroupVariantResult]
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)


class DatasetSummary(BaseModel):
    total_items: int
    passed_items: int
    failed_items: int
    score_total: int
    max_score_total: int


class DatasetReport(BaseModel):
    dataset_name: str
    category: str
    subcategory: str
    source_path: str | None = None
    case_results: list[CaseResult] = Field(default_factory=list)
    group_results: list[GroupResult] = Field(default_factory=list)
    summary: DatasetSummary
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)


class RunSummary(BaseModel):
    total_items: int
    passed_items: int
    failed_items: int
    score_total: int
    max_score_total: int


class RunReport(BaseModel):
    metadata: dict[str, Any] = Field(default_factory=dict)
    report_mode: str | None = None
    wowpp: WowppReportMetadata | None = None
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    run_id: str
    started_at: str
    finished_at: str
    target_name: str
    target_adapter: AdapterType
    target_model: str
    input_path: str
    scoring_path: str
    datasets: list[DatasetReport]
    summary: RunSummary


class MutationCaseResult(BaseModel):
    dataset_name: str
    case_id: str
    mutation: str
    category: str
    risk: str
    family: str | None = None
    surface: str | None = None
    boundary: str | None = None
    tags: list[str] = Field(default_factory=list)
    deterministic: bool | None = None
    reversible: bool | None = None
    can_noop: bool | None = None
    safe_example: str | None = None
    transform_metadata: dict[str, Any] = Field(default_factory=dict)
    coverage_tags: list[str] = Field(default_factory=list)
    original_prompt: str
    mutated_prompt: str
    original_response_text: str
    mutated_response_text: str
    original_passed: bool
    mutated_passed: bool
    original_score: int
    mutated_score: int
    delta: int
    metadata: dict[str, Any] = Field(default_factory=dict)


class MutationFamilySummary(BaseModel):
    family: str
    planned_mutations: int = 0
    total_case_results: int = 0
    regressions: int = 0
    original_score_total: int = 0
    mutated_score_total: int = 0
    worst_delta: int = 0
    coverage_tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class PlannedMutationSummary(BaseModel):
    name: str
    category: str
    risk: str
    family: str | None = None
    surface: str | None = None
    boundary: str | None = None
    tags: list[str] = Field(default_factory=list)
    deterministic: bool | None = None
    reversible: bool | None = None
    can_noop: bool | None = None
    safe_example: str | None = None
    coverage_tags: list[str] = Field(default_factory=list)
    transform_metadata: dict[str, Any] = Field(default_factory=dict)


class MutationRunSummary(BaseModel):
    total_original_items: int
    total_mutated_items: int
    original_score_total: int
    mutated_score_total: int
    worst_delta: int
    worst_mutation: str | None = None
    family_counts: dict[str, int] = Field(default_factory=dict)
    regression_count: int = 0
    negative_delta_count: int = 0
    coverage_tags: list[str] = Field(default_factory=list)


class MutationRunReport(BaseModel):
    report_mode: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    run_id: str
    started_at: str
    finished_at: str
    target_name: str
    target_adapter: AdapterType
    target_model: str
    input_path: str
    scoring_path: str
    mutations: list[str]
    planned_mutations: list[PlannedMutationSummary] = Field(default_factory=list)
    family_summaries: list[MutationFamilySummary] = Field(default_factory=list)
    case_results: list[MutationCaseResult] = Field(default_factory=list)
    summary: MutationRunSummary
