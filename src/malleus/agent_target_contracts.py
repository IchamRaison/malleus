from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from textwrap import dedent
from typing import Any, Literal
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import yaml
from pydantic import BaseModel, Field

from malleus.datasets import load_target_config
from malleus.agent_trace import CANONICAL_AGENT_TRACE_EVENT_TYPES
from malleus.schemas import TargetConfig
from malleus.target_store import sanitize_target_name


AGENT_TARGET_CONTRACT_SCHEMA_VERSION = "malleus.agent_target_contract.v1"
AgentFramework = Literal["generic", "langgraph", "openai_agents", "crewai", "autogen", "custom"]

L2_TARGET_TYPES: tuple[str, ...] = (
    "rag_service",
    "tool_agent",
    "workflow_harness",
    "code_agent",
    "memory_agent",
    "multi_agent",
    "browser_agent",
)

AGENT_FRAMEWORKS: tuple[str, ...] = ("generic", "langgraph", "openai_agents", "crewai", "autogen", "custom")


@dataclass(frozen=True)
class AgentSurfaceContract:
    target_type: str
    default_endpoint_path: str | None
    live_command: str
    request_fields: tuple[str, ...]
    response_fields: tuple[str, ...]
    trace_fields: tuple[str, ...]
    config_field: str


SURFACE_CONTRACTS: dict[str, AgentSurfaceContract] = {
    "rag_service": AgentSurfaceContract(
        target_type="rag_service",
        default_endpoint_path="/malleus/rag",
        live_command="malleus benchmark live-rag --target <target.yaml> --out-dir reports/l2-rag",
        request_fields=("scenario_id", "messages", "query", "documents", "tenant_id", "metadata"),
        response_fields=("answer", "retrievals", "citations", "trace", "metadata"),
        trace_fields=("retrievals", "citations", "actions", "trace_events", "metadata.agent_trace_events", *CANONICAL_AGENT_TRACE_EVENT_TYPES),
        config_field="rag_service",
    ),
    "tool_agent": AgentSurfaceContract(
        target_type="tool_agent",
        default_endpoint_path="/malleus/tool-agent",
        live_command="malleus benchmark live-agentic --target <target.yaml> --out-dir reports/l2-tool-agent",
        request_fields=("scenario_id", "messages", "tools", "policy", "metadata"),
        response_fields=("final_answer", "tool_calls", "actions", "trace", "metadata"),
        trace_fields=("tool_calls", "actions", "trace_events", "metadata.agent_trace_events", *CANONICAL_AGENT_TRACE_EVENT_TYPES),
        config_field="tool_agent",
    ),
    "workflow_harness": AgentSurfaceContract(
        target_type="workflow_harness",
        default_endpoint_path="/malleus/workflow",
        live_command="malleus benchmark live-workflow --target <target.yaml> --out-dir reports/l2-workflow",
        request_fields=("scenario_id", "workflow_id", "messages", "approval", "metadata"),
        response_fields=("final_answer", "actions", "approvals", "trace", "metadata"),
        trace_fields=("actions", "approvals", "trace_events", "metadata.agent_trace_events", *CANONICAL_AGENT_TRACE_EVENT_TYPES),
        config_field="workflow_harness",
    ),
    "code_agent": AgentSurfaceContract(
        target_type="code_agent",
        default_endpoint_path=None,
        live_command="malleus benchmark live-code-agent --target <target.yaml> --out-dir reports/l2-code-agent",
        request_fields=("fixture_path", "workspace_path", "instructions", "metadata"),
        response_fields=("final_answer", "diffs", "actions", "artifacts", "trace", "metadata"),
        trace_fields=("diffs", "actions", "artifacts", "trace_events", "metadata.agent_trace_events", *CANONICAL_AGENT_TRACE_EVENT_TYPES),
        config_field="code_agent",
    ),
    "memory_agent": AgentSurfaceContract(
        target_type="memory_agent",
        default_endpoint_path="/malleus/memory-agent",
        live_command="malleus benchmark live-memory-agent --target <target.yaml> --out-dir reports/l2-memory-agent",
        request_fields=("scenario_id", "messages", "memory", "namespace", "user_id", "metadata"),
        response_fields=("final_answer", "memory_events", "actions", "trace", "metadata"),
        trace_fields=("memory_events", "actions", "trace_events", "metadata.agent_trace_events", *CANONICAL_AGENT_TRACE_EVENT_TYPES),
        config_field="memory_agent",
    ),
    "multi_agent": AgentSurfaceContract(
        target_type="multi_agent",
        default_endpoint_path="/malleus/multi-agent",
        live_command="malleus benchmark live-multi-agent --target <target.yaml> --out-dir reports/l2-multi-agent",
        request_fields=("scenario_id", "objective", "agents", "messages", "metadata"),
        response_fields=("final_answer", "handoffs", "actions", "trace", "metadata"),
        trace_fields=("handoffs", "actions", "trace_events", "metadata.agent_trace_events", *CANONICAL_AGENT_TRACE_EVENT_TYPES),
        config_field="multi_agent",
    ),
    "browser_agent": AgentSurfaceContract(
        target_type="browser_agent",
        default_endpoint_path="/malleus/browser-agent",
        live_command="malleus benchmark live-browser-agent --target <target.yaml> --out-dir reports/l2-browser-agent",
        request_fields=("prompt_id", "task", "page_url", "dom", "screenshot", "metadata"),
        response_fields=("final_answer", "actions", "trace", "metadata"),
        trace_fields=("actions", "trace_events", "metadata.agent_trace_events", *CANONICAL_AGENT_TRACE_EVENT_TYPES),
        config_field="browser_agent",
    ),
}


class AgentContractValidationResult(BaseModel):
    schema_version: str = AGENT_TARGET_CONTRACT_SCHEMA_VERSION
    target_name: str
    target_type: str
    framework: str = "unspecified"
    valid: bool
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    required_endpoint_path: str | None = None
    request_fields: list[str] = Field(default_factory=list)
    response_fields: list[str] = Field(default_factory=list)
    trace_fields: list[str] = Field(default_factory=list)
    live_command: str = ""


class AgentScaffoldResult(BaseModel):
    schema_version: str = AGENT_TARGET_CONTRACT_SCHEMA_VERSION
    target_type: str
    framework: str
    target_path: Path
    adapter_path: Path
    readme_path: Path
    live_command: str


class AgentDoctorCheck(BaseModel):
    name: str
    status: Literal["passed", "warning", "failed", "skipped"]
    message: str
    evidence: dict[str, Any] = Field(default_factory=dict)


class AgentDoctorReport(BaseModel):
    schema_version: str = "malleus.agent_target_doctor.v1"
    target_name: str
    target_type: str
    framework: str = "unspecified"
    valid: bool
    checks: list[AgentDoctorCheck] = Field(default_factory=list)
    coverage_matrix: list[dict[str, Any]] = Field(default_factory=list)
    live_command: str = ""


def validate_agent_target(target: TargetConfig | str | Path, *, surface: str | None = None) -> AgentContractValidationResult:
    config = load_target_config(target) if isinstance(target, (str, Path)) else target
    errors: list[str] = []
    warnings: list[str] = []
    target_type = str(surface or config.target_type)
    contract = SURFACE_CONTRACTS.get(target_type)
    framework = str(config.metadata.get("agent_framework") or "unspecified")

    if contract is None:
        errors.append(f"unsupported L2 agent target_type: {target_type}")
        return AgentContractValidationResult(target_name=config.name, target_type=str(config.target_type), framework=framework, valid=False, errors=errors)
    if config.target_type != target_type:
        errors.append(f"target_type must be {target_type} for this L2 surface; configured target_type={config.target_type}")

    system_config = getattr(config, contract.config_field, None)
    if system_config is None:
        errors.append(f"{target_type} target requires '{contract.config_field}' config")
    elif target_type == "code_agent":
        workspace_path = getattr(system_config, "workspace_path", "")
        command = config.metadata.get("code_agent_command")
        if not workspace_path:
            errors.append("code_agent.workspace_path is required")
        if not isinstance(command, list) or not all(isinstance(item, str) and item for item in command):
            errors.append("metadata.code_agent_command must be a non-empty argv list for L2 code agents")
        if not config.metadata.get("agent_framework"):
            warnings.append("metadata.agent_framework is recommended for real external-agent compatibility reporting")
    else:
        endpoint_url = getattr(system_config, "endpoint_url", "")
        if not endpoint_url:
            errors.append(f"{target_type}.{contract.config_field}.endpoint_url is required")
        if not _has_env_auth(getattr(system_config, "auth", None)):
            if target_type == "tool_agent":
                errors.append("tool_agent auth config requires at least one environment-variable credential reference")
            else:
                warnings.append("no env auth configured; only use unauthenticated endpoints for local/staging adapters")
        if not config.metadata.get("agent_framework"):
            warnings.append("metadata.agent_framework is recommended for real external-agent compatibility reporting")

    return AgentContractValidationResult(
        target_name=config.name,
        target_type=str(config.target_type),
        framework=framework,
        valid=not errors,
        errors=errors,
        warnings=warnings,
        required_endpoint_path=contract.default_endpoint_path,
        request_fields=list(contract.request_fields),
        response_fields=list(contract.response_fields),
        trace_fields=list(contract.trace_fields),
        live_command=contract.live_command.replace("<target.yaml>", f"{sanitize_target_name(config.name)}.yaml"),
    )


def doctor_agent_target(
    target: TargetConfig | str | Path,
    *,
    surface: str | None = None,
    probe_endpoint: bool = False,
    timeout: float = 3.0,
) -> AgentDoctorReport:
    config = load_target_config(target) if isinstance(target, (str, Path)) else target
    validation = validate_agent_target(config, surface=surface)
    contract = SURFACE_CONTRACTS.get(str(surface or config.target_type))
    checks: list[AgentDoctorCheck] = []

    if not validation.valid:
        for error in validation.errors:
            checks.append(AgentDoctorCheck(name="contract", status="failed", message=error))
        return AgentDoctorReport(
            target_name=config.name,
            target_type=str(config.target_type),
            framework=validation.framework,
            valid=False,
            checks=checks,
            coverage_matrix=[],
            live_command=validation.live_command,
        )

    assert contract is not None
    system_config = getattr(config, contract.config_field, None)
    checks.append(_endpoint_check(contract, system_config, probe_endpoint=probe_endpoint, timeout=timeout))
    checks.append(_auth_check(system_config))
    checks.append(_trace_fields_check(contract))
    checks.append(_side_effect_safety_check(config, contract, system_config))
    checks.append(_coverage_matrix_check(contract))
    valid = not any(check.status == "failed" for check in checks)
    return AgentDoctorReport(
        target_name=config.name,
        target_type=str(config.target_type),
        framework=validation.framework,
        valid=valid,
        checks=checks,
        coverage_matrix=_doctor_coverage_matrix(contract),
        live_command=validation.live_command,
    )


def scaffold_agent_target(
    *,
    name: str,
    target_type: str,
    out_dir: str | Path,
    framework: str = "generic",
    endpoint_url: str | None = None,
    auth_env: str = "MALLEUS_AGENT_TOKEN",
    force: bool = False,
) -> AgentScaffoldResult:
    if target_type not in SURFACE_CONTRACTS:
        raise ValueError(f"unsupported L2 agent target_type: {target_type}")
    if framework not in AGENT_FRAMEWORKS:
        raise ValueError(f"unsupported agent framework: {framework}")
    contract = SURFACE_CONTRACTS[target_type]
    root = Path(out_dir).expanduser()
    slug = sanitize_target_name(name)
    target_path = root / f"{slug}.yaml"
    adapter_path = root / f"{slug}_adapter.py"
    readme_path = root / "README.md"
    existing = [path for path in (target_path, adapter_path, readme_path) if path.exists()]
    if existing and not force:
        names = ", ".join(str(path) for path in existing)
        raise FileExistsError(f"refusing to overwrite existing scaffold files: {names}")

    root.mkdir(parents=True, exist_ok=True)
    endpoint = endpoint_url or f"http://127.0.0.1:8787{contract.default_endpoint_path or '/malleus/code-agent'}"
    target_payload = _target_payload(name=name, target_type=target_type, framework=framework, endpoint_url=endpoint, auth_env=auth_env)
    target_path.write_text(yaml.safe_dump(target_payload, sort_keys=False), encoding="utf-8")
    adapter_path.write_text(_adapter_template(name=name, target_type=target_type, framework=framework), encoding="utf-8")
    readme_path.write_text(_readme_template(name=name, target_type=target_type, framework=framework, target_path=target_path.name, adapter_path=adapter_path.name), encoding="utf-8")
    return AgentScaffoldResult(
        target_type=target_type,
        framework=framework,
        target_path=target_path,
        adapter_path=adapter_path,
        readme_path=readme_path,
        live_command=contract.live_command.replace("<target.yaml>", str(target_path)),
    )


def _endpoint_check(contract: AgentSurfaceContract, system_config: Any, *, probe_endpoint: bool, timeout: float) -> AgentDoctorCheck:
    if contract.target_type == "code_agent":
        workspace_path = getattr(system_config, "workspace_path", "")
        exists = bool(workspace_path) and Path(workspace_path).exists()
        status: Literal["passed", "warning", "failed", "skipped"] = "passed" if workspace_path else "failed"
        if workspace_path and not exists:
            status = "warning"
        return AgentDoctorCheck(
            name="endpoint",
            status=status,
            message="code agent uses local workspace/subprocess instead of an HTTP endpoint",
            evidence={"workspace_path": workspace_path, "workspace_exists": exists},
        )

    endpoint_url = str(getattr(system_config, "endpoint_url", "") or "")
    if not endpoint_url:
        return AgentDoctorCheck(name="endpoint", status="failed", message="missing endpoint_url")
    parsed = urlparse(endpoint_url)
    expected_path = contract.default_endpoint_path or ""
    path_matches = not expected_path or parsed.path.endswith(expected_path)
    if not path_matches:
        return AgentDoctorCheck(
            name="endpoint",
            status="warning",
            message=f"endpoint path does not match canonical {expected_path}",
            evidence={"endpoint_host": parsed.hostname, "endpoint_path": parsed.path, "expected_path": expected_path},
        )
    if not probe_endpoint:
        return AgentDoctorCheck(
            name="endpoint",
            status="passed",
            message="endpoint URL is structurally valid; live probe skipped",
            evidence={"endpoint_host": parsed.hostname, "endpoint_path": parsed.path, "probe_endpoint": False},
        )

    headers = _auth_headers_from_env(getattr(system_config, "auth", None))
    if contract.target_type == "rag_service":
        return _rag_service_live_contract_probe(endpoint_url, headers=headers, timeout=timeout, parsed_host=parsed.hostname, parsed_path=parsed.path)

    request = Request(endpoint_url, headers=headers, method="GET")
    try:
        with urlopen(request, timeout=timeout) as response:  # noqa: S310 - operator-requested local/staging doctor probe
            status_code = int(getattr(response, "status", 0) or 0)
    except HTTPError as exc:
        status_code = int(exc.code)
    except (OSError, URLError) as exc:
        return AgentDoctorCheck(
            name="endpoint",
            status="failed",
            message=f"endpoint probe failed: {type(exc).__name__}",
            evidence={"endpoint_host": parsed.hostname, "endpoint_path": parsed.path, "probe_endpoint": True},
        )
    status = "passed" if 100 <= status_code < 500 else "warning"
    return AgentDoctorCheck(
        name="endpoint",
        status=status,
        message="endpoint responded to doctor probe",
        evidence={"endpoint_host": parsed.hostname, "endpoint_path": parsed.path, "http_status": status_code, "probe_endpoint": True},
    )


def _rag_service_live_contract_probe(endpoint_url: str, *, headers: dict[str, str], timeout: float, parsed_host: str | None, parsed_path: str) -> AgentDoctorCheck:
    probe_document_id = "malleus-doctor-current-policy"
    payload = {
        "scenario_id": "malleus-doctor-rag-contract",
        "query": "According to the provided current policy document, what should the doctor verify?",
        "tenant_id": "malleus-doctor-tenant",
        "documents": [
            {
                "id": probe_document_id,
                "title": "Malleus doctor current policy",
                "tenant_id": "malleus-doctor-tenant",
                "source_type": "trusted",
                "body": "Current policy: the RAG service must preserve retrieval ids, citations, tenant metadata, and trace events.",
                "metadata": {"malleus_doctor_probe": True, "priority": "current"},
            }
        ],
        "metadata": {"malleus_doctor_probe": True, "expected_retrieval_id": probe_document_id},
    }
    body = json.dumps(payload).encode("utf-8")
    request_headers = {"Content-Type": "application/json", **headers}
    request = Request(endpoint_url, data=body, headers=request_headers, method="POST")
    response_data: dict[str, Any] = {}
    status_code = 0
    try:
        with urlopen(request, timeout=timeout) as response:  # noqa: S310 - operator-requested local/staging doctor probe
            status_code = int(getattr(response, "status", 0) or 0)
            raw = response.read(512_000)
    except HTTPError as exc:
        status_code = int(exc.code)
        raw = exc.read(64_000)
    except (OSError, URLError) as exc:
        return AgentDoctorCheck(
            name="endpoint",
            status="failed",
            message=f"RAG contract probe failed before response: {type(exc).__name__}",
            evidence={"endpoint_host": parsed_host, "endpoint_path": parsed_path, "probe_endpoint": True, "probe_method": "POST"},
        )
    try:
        parsed = json.loads(raw.decode("utf-8")) if raw else {}
    except (UnicodeDecodeError, json.JSONDecodeError):
        parsed = {}
    if isinstance(parsed, dict):
        response_data = parsed

    if not 200 <= status_code < 300:
        return AgentDoctorCheck(
            name="endpoint",
            status="failed",
            message=f"RAG contract probe returned HTTP {status_code}",
            evidence={"endpoint_host": parsed_host, "endpoint_path": parsed_path, "http_status": status_code, "probe_endpoint": True, "probe_method": "POST"},
        )

    answer_present = bool(str(response_data.get("answer") or response_data.get("final_answer") or "").strip())
    retrievals = response_data.get("retrievals", response_data.get("retrieved_documents"))
    citations = response_data.get("citations", response_data.get("cited_documents"))
    trace = response_data.get("trace", response_data.get("trace_events", response_data.get("actions")))
    metadata = response_data.get("metadata") if isinstance(response_data.get("metadata"), dict) else {}
    retrieval_ids = _ids_from_items(retrievals)
    citation_ids = _ids_from_items(citations)
    tenant_preserved = _contains_value(response_data, "malleus-doctor-tenant")
    metadata_preserved = _contains_value(metadata, "malleus_doctor_probe") or _contains_value(response_data, "malleus_doctor_probe")
    missing = []
    if not answer_present:
        missing.append("answer")
    if not retrieval_ids:
        missing.append("retrievals")
    if not citation_ids:
        missing.append("citations")
    if not trace:
        missing.append("trace")
    if probe_document_id not in retrieval_ids:
        missing.append("expected_retrieval_id")
    if not tenant_preserved:
        missing.append("tenant_metadata")
    if not metadata_preserved:
        missing.append("probe_metadata")
    status: Literal["passed", "warning", "failed", "skipped"] = "passed" if not missing else "warning"
    message = "RAG endpoint accepted corpus probe and exposed retrieval/citation/trace evidence" if not missing else "RAG endpoint responded, but coverage fields are incomplete"
    return AgentDoctorCheck(
        name="endpoint",
        status=status,
        message=message,
        evidence={
            "endpoint_host": parsed_host,
            "endpoint_path": parsed_path,
            "http_status": status_code,
            "probe_endpoint": True,
            "probe_method": "POST",
            "answer_present": answer_present,
            "retrieval_ids": retrieval_ids[:20],
            "citation_ids": citation_ids[:20],
            "trace_present": bool(trace),
            "tenant_metadata_preserved": tenant_preserved,
            "probe_metadata_preserved": metadata_preserved,
            "missing_contract_fields": missing,
        },
    )


def _ids_from_items(value: Any) -> list[str]:
    if isinstance(value, dict):
        iterable: list[Any] = list(value.values())
    elif isinstance(value, list):
        iterable = value
    else:
        return []
    ids: list[str] = []
    for item in iterable:
        if isinstance(item, str):
            ids.append(item)
        elif isinstance(item, dict):
            for key in ("id", "doc_id", "document_id", "source_id"):
                raw = item.get(key)
                if raw:
                    ids.append(str(raw))
                    break
    return ids


def _contains_value(value: Any, needle: str) -> bool:
    if isinstance(value, dict):
        return any(_contains_value(key, needle) or _contains_value(item, needle) for key, item in value.items())
    if isinstance(value, list):
        return any(_contains_value(item, needle) for item in value)
    return needle in str(value)


def _auth_check(system_config: Any) -> AgentDoctorCheck:
    env_names = _auth_env_names(getattr(system_config, "auth", None))
    command_env = getattr(system_config, "command_env", {})
    if isinstance(command_env, dict):
        env_names.extend(str(value) for value in command_env.values() if value)
    if not env_names:
        return AgentDoctorCheck(name="auth", status="warning", message="no environment-backed auth configured")
    present = [name for name in env_names if name in os.environ]
    missing = [name for name in env_names if name not in os.environ]
    status: Literal["passed", "warning", "failed", "skipped"] = "passed" if not missing else "warning"
    return AgentDoctorCheck(
        name="auth",
        status=status,
        message="auth environment references resolved" if not missing else "some auth environment references are not set",
        evidence={"configured_env": sorted(set(env_names)), "present_env": sorted(set(present)), "missing_env": sorted(set(missing))},
    )


def _trace_fields_check(contract: AgentSurfaceContract) -> AgentDoctorCheck:
    core = {"metadata.agent_trace_events", *CANONICAL_AGENT_TRACE_EVENT_TYPES}
    trace_fields = set(contract.trace_fields)
    missing = sorted(core - trace_fields)
    status: Literal["passed", "warning", "failed", "skipped"] = "passed" if not missing else "failed"
    return AgentDoctorCheck(
        name="trace_fields",
        status=status,
        message="canonical trace fields are declared" if not missing else "canonical trace fields are missing from contract",
        evidence={"declared_trace_fields": list(contract.trace_fields), "missing": missing},
    )


def _side_effect_safety_check(config: TargetConfig, contract: AgentSurfaceContract, system_config: Any) -> AgentDoctorCheck:
    metadata = {**(config.metadata if isinstance(config.metadata, dict) else {}), **(getattr(system_config, "metadata", {}) if isinstance(getattr(system_config, "metadata", {}), dict) else {})}
    declared = str(metadata.get("side_effect_safety") or metadata.get("safety_mode") or "").strip().lower()
    safe_values = {"dry_run", "staging", "sandbox", "read_only", "disposable_fixture", "isolated", "local_only"}
    if declared in safe_values:
        return AgentDoctorCheck(name="side_effect_safety", status="passed", message="side-effect safety mode is declared", evidence={"side_effect_safety": declared})
    if contract.target_type == "code_agent":
        workspace_path = str(getattr(system_config, "workspace_path", "") or "")
        allowed_actions = list(getattr(system_config, "allowed_actions", []) or [])
        status: Literal["passed", "warning", "failed", "skipped"] = "passed" if workspace_path and allowed_actions else "warning"
        return AgentDoctorCheck(
            name="side_effect_safety",
            status=status,
            message="code-agent safety inferred from workspace and allowed_actions; declare metadata.side_effect_safety=sandbox for publication",
            evidence={"workspace_path": workspace_path, "allowed_actions": allowed_actions, "side_effect_safety": declared or None},
        )
    endpoint_url = str(getattr(system_config, "endpoint_url", "") or "")
    parsed = urlparse(endpoint_url)
    localhost = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    status = "passed" if localhost else "warning"
    return AgentDoctorCheck(
        name="side_effect_safety",
        status=status,
        message="local endpoint treated as safe for tests; declare side_effect_safety for staging/production endpoints" if localhost else "side-effect safety cannot be inferred for non-local endpoint",
        evidence={"endpoint_host": parsed.hostname, "side_effect_safety": declared or None},
    )


def _coverage_matrix_check(contract: AgentSurfaceContract) -> AgentDoctorCheck:
    matrix = _doctor_coverage_matrix(contract)
    required = sum(1 for row in matrix if row.get("required"))
    return AgentDoctorCheck(
        name="coverage_matrix",
        status="passed",
        message="target doctor generated production-stack coverage expectations",
        evidence={"required_rows": required, "total_rows": len(matrix)},
    )


def _doctor_coverage_matrix(contract: AgentSurfaceContract) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for field in contract.request_fields:
        rows.append({"area": "request", "field": field, "required": True, "status": "must_expose"})
    for field in contract.response_fields:
        rows.append({"area": "response", "field": field, "required": True, "status": "must_expose"})
    for field in contract.trace_fields:
        rows.append({"area": "trace", "field": field, "required": field in CANONICAL_AGENT_TRACE_EVENT_TYPES or field == "metadata.agent_trace_events", "status": "must_expose"})
    rows.append({"area": "side_effect_safety", "field": "metadata.side_effect_safety", "required": True, "status": "must_declare"})
    return rows


def _auth_env_names(auth: Any) -> list[str]:
    if auth is None:
        return []
    names: list[str] = []
    for attr in ("api_key_env", "bearer_token_env"):
        value = getattr(auth, attr, "")
        if isinstance(value, str) and value:
            names.append(value)
    headers_env = getattr(auth, "headers_env", {})
    if isinstance(headers_env, dict):
        names.extend(str(value) for value in headers_env.values() if value)
    return names


def _auth_headers_from_env(auth: Any) -> dict[str, str]:
    headers: dict[str, str] = {}
    if auth is None:
        return headers
    api_key_env = getattr(auth, "api_key_env", "")
    if api_key_env and os.environ.get(api_key_env):
        headers["X-API-Key"] = os.environ[api_key_env]
    bearer_token_env = getattr(auth, "bearer_token_env", "")
    if bearer_token_env and os.environ.get(bearer_token_env):
        headers["Authorization"] = f"Bearer {os.environ[bearer_token_env]}"
    headers_env = getattr(auth, "headers_env", {})
    if isinstance(headers_env, dict):
        for header_name, env_name in headers_env.items():
            if env_name and os.environ.get(env_name):
                headers[str(header_name)] = os.environ[str(env_name)]
    return headers


def _has_env_auth(auth: Any) -> bool:
    if auth is None:
        return False
    if getattr(auth, "api_key_env", "") or getattr(auth, "bearer_token_env", ""):
        return True
    headers_env = getattr(auth, "headers_env", {})
    return isinstance(headers_env, dict) and any(headers_env.values())


def _target_payload(*, name: str, target_type: str, framework: str, endpoint_url: str, auth_env: str) -> dict[str, Any]:
    metadata = {
        "agent_framework": framework,
        "agent_target_depth": "L2",
        "agent_contract_schema": AGENT_TARGET_CONTRACT_SCHEMA_VERSION,
    }
    if target_type == "code_agent":
        return {
            "name": name,
            "target_type": "code_agent",
            "metadata": {**metadata, "code_agent_command": ["python", "YOUR_AGENT_BRIDGE.py"]},
            "code_agent": {
                "workspace_path": "tests/fixtures/code_agent_workspace",
                "command_env": {"AGENT_TOKEN": auth_env},
                "allowed_actions": ["read", "write", "diff", "test"],
            },
        }
    config: dict[str, Any] = {"endpoint_url": endpoint_url, "auth": {"bearer_token_env": auth_env}}
    if target_type == "workflow_harness":
        config["workflow_id"] = "malleus-l2-workflow"
    if target_type == "rag_service":
        config["retrieval_top_k"] = 5
    if target_type == "tool_agent":
        config["allowed_tools"] = ["search", "read_file", "submit_result"]
    if target_type == "multi_agent":
        config["allowed_roles"] = ["planner", "executor", "reviewer"]
    if target_type == "browser_agent":
        config["allowed_origins"] = ["http://127.0.0.1", "http://localhost"]
    return {"name": name, "target_type": target_type, "metadata": metadata, target_type: config}


def _adapter_template(*, name: str, target_type: str, framework: str) -> str:
    return dedent(
        f'''\
        """Malleus L2 adapter for {name}.

        Serve with:
            malleus agent serve {sanitize_target_name(name)}_adapter:adapter --target-type {target_type} --framework {framework}
        """
        from __future__ import annotations

        from malleus.agent_adapter import AgentRequest, AgentResponse, BaseAgentAdapter
        from malleus.schemas import HarnessTraceAction


        class Adapter(BaseAgentAdapter):
            target_type = "{target_type}"
            framework = "{framework}"

            def run(self, request: AgentRequest) -> AgentResponse:
                result = run_real_agent(request.payload)
                final_answer = str(result.get("final_answer") or result.get("answer") or "")
                return AgentResponse(
                    final_answer=final_answer,
                    answer=final_answer,
                    actions=[
                        HarnessTraceAction(
                            action_type="adapter_bridge",
                            summary="called real {framework} agent entrypoint",
                            metadata={{"agent_framework": self.framework}},
                        )
                    ],
                    trace=[
                        HarnessTraceAction(
                            action_type="adapter_bridge",
                            summary="normalized framework result for Malleus",
                            metadata={{"agent_framework": self.framework}},
                        )
                    ],
                    metadata={{"agent_framework": self.framework, "agent_target_depth": "L2"}},
                )


        def run_real_agent(payload: dict) -> dict:
            # Replace this with LangGraph, OpenAI Agents SDK, CrewAI, AutoGen,
            # LlamaIndex, LangChain, or your custom orchestrator.
            user_text = payload.get("query") or payload.get("task") or payload.get("objective") or payload.get("prompt") or ""
            return {{
                "final_answer": f"adapter stub received {target_type} request: {{user_text}}",
            }}


        adapter = Adapter()
        '''
    )


def _readme_template(*, name: str, target_type: str, framework: str, target_path: str, adapter_path: str) -> str:
    contract = SURFACE_CONTRACTS[target_type]
    return dedent(
        f"""\
        # {name} Malleus L2 adapter

        This scaffold exposes a real external agent as a Malleus `{target_type}` target.

        - Framework label: `{framework}`
        - Target YAML: `{target_path}`
        - Adapter stub: `{adapter_path}`
        - Endpoint path: `{contract.default_endpoint_path or "local subprocess"}`
        - Validation: `malleus target validate-agent {target_path}`
        - Benchmark: `{contract.live_command.replace("<target.yaml>", target_path)}`

        Replace `run_real_agent()` in `{adapter_path}` with your framework entrypoint and preserve redacted trace fields.
        Serve locally with `malleus agent serve {adapter_path.removesuffix(".py")}:adapter --target-type {target_type} --framework {framework}` from this directory.
        """
    )


__all__ = [
    "AGENT_FRAMEWORKS",
    "AGENT_TARGET_CONTRACT_SCHEMA_VERSION",
    "L2_TARGET_TYPES",
    "AgentContractValidationResult",
    "AgentDoctorCheck",
    "AgentDoctorReport",
    "AgentScaffoldResult",
    "SURFACE_CONTRACTS",
    "doctor_agent_target",
    "scaffold_agent_target",
    "validate_agent_target",
]
