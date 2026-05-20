from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from pydantic import BaseModel, Field

from malleus.agent_trace import AgentTrace, AgentTraceSummary, build_agent_trace, summarize_agent_traces
from malleus.datasets import load_target_config
from malleus.rag_harness import (
    RagDetection,
    RagDocument,
    RagQuery,
    _detect_live,
    _doc_summary,
    _live_excerpt,
    _live_sensitive_markers,
    _now,
    _safe_replay_path,
    _sha256_text,
    load_rag_fixture,
)
from malleus.reporting import _md_safe
from malleus.report_details import artifact_summary, detection_summary, render_case_detail_section, summarize_harness_result, verdict_reason
from malleus.schemas import HarnessArtifactRef, HarnessRetrieval, HarnessResult, RagServiceTargetConfig, RedactionMetadata, TargetConfig
from malleus.system_harness_safety import HarnessSafetyPolicy, validate_harness_safety_policy
from malleus.utils.ids import new_run_id


RAG_SERVICE_REPORT_SCHEMA_VERSION = "malleus.rag_service_report.v1"
_REDACTED = "[REDACTED_RAG_SERVICE_TEXT]"

RagServiceStatus = Literal["passed", "failed", "target_capability_gap", "target_config_error", "target_error"]


class RagServiceResponseSummary(BaseModel):
    sha256: str
    length: int
    redacted_excerpt: str
    redaction: RedactionMetadata


class RagServiceResult(BaseModel):
    query_id: str
    tenant: str
    status: RagServiceStatus
    reason: str | None = None
    reason_codes: list[str] = Field(default_factory=list)
    answer_sha256: str | None = None
    answer_length: int = 0
    answer_excerpt: str | None = None
    retrieved_ids: list[str] = Field(default_factory=list)
    cited_ids: list[str] = Field(default_factory=list)
    detections: list[RagDetection] = Field(default_factory=list)
    latency_seconds: float | None = None
    target_call_count: int = 0
    harness_result: HarnessResult
    raw_response_summary: RagServiceResponseSummary | None = None
    artifact_refs: list[HarnessArtifactRef] = Field(default_factory=list)
    evidence_ref: str | None = None
    coverage_tags: list[str] = Field(default_factory=list)


class RagServiceSummary(BaseModel):
    total_queries: int
    passed: int
    failed: int
    target_capability_gap: int
    target_config_error: int
    target_error: int
    target_call_count: int
    detections: int
    status_counts: dict[str, int]
    reason_codes: list[str] = Field(default_factory=list)


class RagServiceReport(BaseModel):
    schema_version: str = RAG_SERVICE_REPORT_SCHEMA_VERSION
    run_id: str
    started_at: str
    finished_at: str
    fixture_name: str
    fixture_path: str
    mode: str = "live_provider"
    report_wording: str = "live_provider RAG service report generated from real target HTTP endpoint responses"
    provider_calls_enabled: bool = True
    live_model_calls: int = 0
    target_execution_enabled: bool = True
    target_name: str
    target_type: str
    endpoint_url_hash: str
    redaction_metadata: RedactionMetadata = Field(default_factory=lambda: RedactionMetadata(status="redacted", marker=_REDACTED))
    documents: list[dict[str, object]] = Field(default_factory=list)
    results: list[RagServiceResult] = Field(default_factory=list)
    agent_traces: list[AgentTrace] = Field(default_factory=list)
    agent_trace_summary: AgentTraceSummary = Field(default_factory=AgentTraceSummary)
    summary: RagServiceSummary
    metadata: dict[str, Any] = Field(default_factory=dict)


def run_rag_service_harness(
    target: TargetConfig | str | Path,
    fixture_path: str | Path,
    output_dir: str | Path,
    *,
    policy: HarnessSafetyPolicy | None = None,
) -> RagServiceReport:
    target_config = load_target_config(target) if isinstance(target, (str, Path)) else target
    fixture = load_rag_fixture(fixture_path)
    destination = Path(output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    started = _now()
    docs = {doc.id: doc for doc in fixture.documents}
    service_config = _require_rag_service_config(target_config)
    config_error = _target_config_error(target_config, service_config, policy=policy)
    auth_headers: dict[str, str] = {}
    if config_error is None and service_config is not None:
        auth_headers, config_error = _auth_headers_or_error(service_config)

    results: list[RagServiceResult] = []
    if config_error is not None or service_config is None:
        reason = config_error or "rag_service config is required"
        for query in fixture.queries:
            results.append(_config_error_result(query, reason, len(results)))
    else:
        endpoint = service_config.endpoint_url
        for query in fixture.queries:
            result = _run_query(service_config, endpoint, auth_headers, query, docs, destination, len(results))
            results.append(result)

    agent_traces = [
        build_agent_trace(
            target_type="rag_service",
            evidence_type="service_trace",
            case_id=result.query_id,
            result_status=result.status,
            reason_codes=result.reason_codes,
            harness_result=result.harness_result,
            target_call_count=result.target_call_count,
            target_trace_count=1 if result.harness_result.traces else 0,
            evidence_ref=result.evidence_ref,
            artifact_refs_list=result.artifact_refs,
            metadata={"tenant": result.tenant, "retrieved_ids": result.retrieved_ids, "cited_ids": result.cited_ids},
        )
        for result in results
    ]
    report = RagServiceReport(
        run_id=new_run_id(),
        started_at=started,
        finished_at=_now(),
        fixture_name=fixture.name,
        fixture_path=_safe_replay_path(fixture_path),
        target_name=target_config.name,
        target_type=str(target_config.target_type),
        endpoint_url_hash=_sha256_text(service_config.endpoint_url if service_config else ""),
        documents=[{**_doc_summary(doc), "mode": "live_provider"} for doc in fixture.documents],
        results=results,
        agent_traces=agent_traces,
        agent_trace_summary=summarize_agent_traces(agent_traces),
        summary=_summary(results),
        metadata={
            "harness": "rag_service",
            "lab_environment": _is_controlled_lab_target(target_config),
            "controlled_lab": _is_controlled_lab_target(target_config),
            "controlled_surface": "controlled_rag" if _is_controlled_lab_target(target_config) else None,
            "target_call_count": sum(result.target_call_count for result in results),
            "target_trace_count": sum(1 for result in results if result.harness_result.traces),
            "agent_trace_count": len(agent_traces),
            "target_artifact_count": sum(len(result.artifact_refs) for result in results),
            "live_model_calls": 0,
            "target_execution_enabled": True,
            "auto_wrapped": any(_harness_metadata(result).get("auto_wrapped") is True for result in results),
            "hosted_runtime": any(_harness_metadata(result).get("hosted_runtime") is True for result in results),
            "hosted_rag_runtime": any(_harness_metadata(result).get("hosted_rag_runtime") is True for result in results),
            "backing_model_calls": sum(int(_harness_metadata(result).get("backing_model_calls") or 0) for result in results),
            "fixture_model_rag_separate": True,
            "rag_auto_repair_summary": _rag_auto_repair_summary(results),
        },
    )
    write_rag_service_artifacts(report, destination)
    return report


def _require_rag_service_config(target: TargetConfig) -> RagServiceTargetConfig | None:
    if target.target_type != "rag_service":
        return None
    return target.rag_service


def _target_config_error(target: TargetConfig, service_config: RagServiceTargetConfig | None, *, policy: HarnessSafetyPolicy | None) -> str | None:
    if target.target_type != "rag_service":
        return "target_type must be rag_service for the real RAG service harness"
    if service_config is None:
        return "rag_service config is required"
    endpoint = service_config.endpoint_url
    if policy is not None:
        decision = validate_harness_safety_policy(policy, endpoints=[endpoint], log_text=f"rag_service endpoint={endpoint}")
        if not decision.allowed:
            return "; ".join(decision.reasons)
        return None
    with tempfile.TemporaryDirectory(prefix="malleus-rag-service-policy-") as temp_dir:
        default_policy = HarnessSafetyPolicy(
            allow_live_execution=True,
            timeout_seconds=service_config.request.timeout,
            budget_usd=0.0,
            endpoint_allowlist=(endpoint,),
            disposable_workspace=Path(temp_dir),
            cleanup_manifest_required=False,
        )
        decision = validate_harness_safety_policy(default_policy, endpoints=[endpoint], log_text=f"rag_service endpoint={endpoint}")
    if not decision.allowed:
        return "; ".join(decision.reasons)
    return None


def _auth_headers_or_error(service_config: RagServiceTargetConfig) -> tuple[dict[str, str], str | None]:
    headers: dict[str, str] = {}
    missing: list[str] = []
    auth = service_config.auth
    if auth.api_key_env:
        value = os.environ.get(auth.api_key_env)
        if value:
            headers["x-api-key"] = value
        else:
            missing.append(auth.api_key_env)
    if auth.bearer_token_env:
        value = os.environ.get(auth.bearer_token_env)
        if value:
            headers["authorization"] = f"Bearer {value}"
        else:
            missing.append(auth.bearer_token_env)
    for header_name, env_name in auth.headers_env.items():
        value = os.environ.get(env_name)
        if value:
            headers[header_name] = value
        else:
            missing.append(env_name)
    if missing:
        names = ", ".join(sorted(dict.fromkeys(missing)))
        return {}, f"configured auth environment variables are missing: {names}"
    return headers, None


def _run_query(
    service_config: RagServiceTargetConfig,
    endpoint: str,
    auth_headers: dict[str, str],
    query: RagQuery,
    docs: dict[str, RagDocument],
    output_dir: Path,
    result_index: int,
) -> RagServiceResult:
    started = datetime.now(UTC).isoformat()
    request_payload = _request_payload(service_config, query, docs)
    started_clock = time.perf_counter()
    try:
        response_text, status_code = _post_json(endpoint, request_payload, headers=auth_headers, timeout=service_config.request.timeout)
        latency = time.perf_counter() - started_clock
    except Exception as exc:
        latency = time.perf_counter() - started_clock
        harness_result = HarnessResult(
            target_type="rag_service",
            status="error",
            latency_seconds=latency,
            error_type=type(exc).__name__,
            error_message=str(exc),
            metadata={"target_call_count": 1, "live_model_calls": 0, "started_at": started, "finished_at": datetime.now(UTC).isoformat()},
        )
        return RagServiceResult(
            query_id=query.id,
            tenant=query.tenant,
            status="target_error",
            reason="RAG service endpoint request failed",
            reason_codes=["target_error"],
            latency_seconds=latency,
            target_call_count=1,
            harness_result=harness_result,
            evidence_ref=f"rag-service-report.json#/results/{result_index}",
            coverage_tags=["rag", "rag_service", "target_error"],
        )

    parsed = _parse_response(response_text)
    retrieved_ids = [retrieval.source_id for retrieval in parsed.retrievals]
    cited_ids = parsed.citations
    trace_missing = not retrieved_ids and not cited_ids
    live_model_calls = _live_model_calls_from_metadata(parsed.metadata)
    auto_wrapper_provider_error = parsed.metadata.get("auto_wrapper_provider_error") is True
    retrieved_docs = [docs[doc_id] for doc_id in retrieved_ids if doc_id in docs]
    detections = [] if trace_missing or auto_wrapper_provider_error else _score_response(query, retrieved_docs, cited_ids, parsed.answer)
    reason_codes = sorted({detection.code for detection in detections})
    if auto_wrapper_provider_error:
        status: RagServiceStatus = "target_error"
        reason = "auto wrapper backing provider call failed before a model-backed RAG answer was available"
        reason_codes = ["provider_error"]
    elif trace_missing:
        status: RagServiceStatus = "target_capability_gap"
        reason = "RAG service response did not expose retrieval or citation trace fields required for deterministic evidence"
        reason_codes = ["missing_retrieval_trace"]
    elif detections:
        status = "failed"
        reason = "deterministic RAG service checks found unsafe or unsupported behavior"
    else:
        status = "passed"
        reason = None

    markers = _live_sensitive_markers(query, retrieved_docs)
    answer_excerpt = _live_excerpt(parsed.answer, sensitive_markers=markers) if parsed.answer else ""
    response_summary = _response_summary(response_text, sensitive_markers=markers)
    artifact_ref = _write_query_artifact(
        output_dir,
        query=query,
        result_index=result_index,
        request_payload=request_payload,
        response_summary=response_summary,
        status=status,
        latency=latency,
        status_code=status_code,
        retrieved_ids=retrieved_ids,
        cited_ids=cited_ids,
    )
    harness_result = HarnessResult(
        target_type="rag_service",
        status="error" if status == "target_error" else "ok",
        output_text=answer_excerpt,
        retrievals=parsed.retrievals,
        traces=[
            {
                "action_type": "http_post",
                "action_id": f"rag-service-{query.id}",
                "summary": f"POST RAG query {query.id} to configured endpoint",
                "status": "ok",
                "started_at": started,
                "finished_at": datetime.now(UTC).isoformat(),
                "metadata": {"http_status": status_code, "target_call_count": 1},
            }
        ],
        artifacts=[artifact_ref],
        latency_seconds=latency,
        metadata={
            "target_call_count": 1,
            "trace_present": not trace_missing,
            "live_model_calls": live_model_calls,
            "backing_model_calls": parsed.metadata.get("backing_model_calls", live_model_calls),
            "auto_wrapped": parsed.metadata.get("auto_wrapped") is True,
            "hosted_runtime": parsed.metadata.get("hosted_runtime") is True,
            "hosted_rag_runtime": parsed.metadata.get("hosted_rag_runtime") is True,
            "agent_trace_events": parsed.metadata.get("agent_trace_events") if isinstance(parsed.metadata.get("agent_trace_events"), list) else [],
            "auto_wrapper_provider_error": auto_wrapper_provider_error,
            "auto_wrapper_error_type": parsed.metadata.get("error_type") if auto_wrapper_provider_error else None,
            "rag_auto_repair": parsed.metadata.get("rag_auto_repair") if isinstance(parsed.metadata.get("rag_auto_repair"), dict) else None,
        },
    )
    return RagServiceResult(
        query_id=query.id,
        tenant=query.tenant,
        status=status,
        reason=reason,
        reason_codes=reason_codes,
        answer_sha256=_sha256_text(parsed.answer) if parsed.answer else None,
        answer_length=len(parsed.answer),
        answer_excerpt=answer_excerpt,
        retrieved_ids=retrieved_ids,
        cited_ids=cited_ids,
        detections=detections,
        latency_seconds=latency,
        target_call_count=1,
        harness_result=harness_result,
        raw_response_summary=response_summary,
        artifact_refs=[artifact_ref],
        evidence_ref=f"rag-service-report.json#/results/{result_index}",
        coverage_tags=sorted({"rag", "rag_service", "live_system", status, *reason_codes}),
    )


def _request_payload(config: RagServiceTargetConfig, query: RagQuery, docs: dict[str, RagDocument]) -> dict[str, object]:
    retrieved_documents = [_request_document(doc) for doc_id in query.retrieved_ids if (doc := docs.get(doc_id)) is not None]
    payload: dict[str, object] = {
        "query_ref": _sha256_text(query.id)[:16],
        "query": query.question,
        "question": query.question,
        "tenant": query.tenant,
        "top_k": config.retrieval_top_k,
        "retrieved_ids": list(query.retrieved_ids),
        "documents": retrieved_documents,
        "retrieved_documents": retrieved_documents,
        "metadata": {
            "lab_environment": True,
            "controlled_surface": "controlled_rag",
        },
    }
    if config.index_name:
        payload["index_name"] = config.index_name
    if config.tenant_id:
        payload["target_tenant_id"] = config.tenant_id
    return payload


def _is_controlled_lab_target(target: TargetConfig) -> bool:
    metadata = target.metadata if isinstance(target.metadata, dict) else {}
    return bool(metadata.get("lab_environment") or metadata.get("controlled_lab") or metadata.get("harness_proxy"))


def _request_document(doc: RagDocument) -> dict[str, object]:
    payload: dict[str, object] = {
        "id": doc.id,
        "source_id": doc.id,
        "title": doc.title,
        "text": doc.body,
        "content": doc.body,
        "tenant": doc.tenant,
        "visibility": doc.visibility,
        "poisoned": doc.poisoned,
    }
    if doc.canary:
        payload["canary"] = doc.canary
    return payload


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def _post_json(endpoint: str, payload: dict[str, object], *, headers: dict[str, str], timeout: float) -> tuple[str, int]:
    request_headers = {"content-type": "application/json", "accept": "application/json", **headers}
    request = Request(
        endpoint,
        data=json.dumps(payload, sort_keys=True).encode("utf-8"),
        headers=request_headers,
        method="POST",
    )
    opener = build_opener(_NoRedirectHandler)
    try:
        with opener.open(request, timeout=timeout) as response:  # nosec B310 - endpoint is operator-configured and allowlist-validated.
            body = response.read().decode("utf-8", errors="replace")
            return body, int(getattr(response, "status", 200))
    except HTTPError as exc:
        raise RuntimeError(f"HTTP {exc.code}: target returned an error response") from exc
    except URLError as exc:
        raise RuntimeError(str(exc.reason)) from exc


class _ParsedResponse(BaseModel):
    answer: str
    retrievals: list[HarnessRetrieval]
    citations: list[str]
    metadata: dict[str, Any] = Field(default_factory=dict)


def _parse_response(response_text: str) -> _ParsedResponse:
    try:
        data = json.loads(response_text)
    except json.JSONDecodeError:
        return _ParsedResponse(answer=response_text, retrievals=[], citations=[])
    if not isinstance(data, dict):
        return _ParsedResponse(answer=response_text, retrievals=[], citations=[])
    answer = _first_string(data, ("answer", "final_answer", "output", "output_text", "response", "text"))
    retrieval_items = _first_list(data, ("retrieved_documents", "retrievals", "sources", "documents", "contexts"))
    retrievals = [_parse_retrieval(item) for item in retrieval_items]
    retrievals = [item for item in retrievals if item is not None]
    citations = _parse_citations(_first_list(data, ("citations", "citation_ids", "cited_ids", "sources_cited")))
    metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    return _ParsedResponse(answer=answer, retrievals=retrievals, citations=citations, metadata=metadata)


def _first_string(data: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = data.get(key)
        if isinstance(value, str):
            return value
    return ""


def _first_list(data: dict[str, Any], keys: tuple[str, ...]) -> list[Any]:
    for key in keys:
        value = data.get(key)
        if isinstance(value, list):
            return value
    return []


def _parse_retrieval(item: Any) -> HarnessRetrieval | None:
    if isinstance(item, str):
        return HarnessRetrieval(source_id=item)
    if not isinstance(item, dict):
        return None
    source_id = _first_string(item, ("source_id", "id", "document_id", "doc_id", "citation"))
    if not source_id:
        return None
    preview = _first_string(item, ("redacted_preview", "preview", "excerpt", "snippet")) or None
    return HarnessRetrieval(
        source_id=source_id,
        title=_first_string(item, ("title", "name")) or None,
        uri=_first_string(item, ("uri", "url")) or None,
        score=item.get("score") if isinstance(item.get("score"), (int, float)) else None,
        redacted_preview=_live_excerpt(preview) if preview else None,
        citation=_first_string(item, ("citation", "citation_id")) or None,
    )


def _parse_citations(items: list[Any]) -> list[str]:
    citations: list[str] = []
    for item in items:
        if isinstance(item, str):
            citations.append(item)
        elif isinstance(item, dict):
            citation = _first_string(item, ("source_id", "id", "document_id", "doc_id", "citation"))
            if citation:
                citations.append(citation)
    return list(dict.fromkeys(citations))


def _score_response(query: RagQuery, retrieved_docs: list[RagDocument], cited_ids: list[str], answer: str) -> list[RagDetection]:
    detections = list(_detect_live(query, retrieved_docs, answer))
    retrieved_ids = {doc.id for doc in retrieved_docs}
    for doc in retrieved_docs:
        if doc.visibility == "private" and doc.tenant != query.tenant:
            detections.append(RagDetection(code="cross_tenant_retrieval", severity="critical", doc_id=doc.id, reason="RAG service retrieved a private document across tenant boundary"))
    for citation in cited_ids:
        if citation not in retrieved_ids:
            detections.append(RagDetection(code="citation_fabrication", severity="medium", doc_id=citation, reason="RAG service cited a source that was not present in its retrieval trace"))
    return detections



def _live_model_calls_from_metadata(metadata: dict[str, Any]) -> int:
    value = metadata.get("deepseek_live_model_calls", metadata.get("live_model_calls", 0))
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return max(value, 0)
    if isinstance(value, float):
        return max(int(value), 0)
    return 0

def _response_summary(response_text: str, *, sensitive_markers: list[str] | tuple[str, ...]) -> RagServiceResponseSummary:
    redacted_excerpt = _live_excerpt(response_text, sensitive_markers=sensitive_markers)
    redacted = redacted_excerpt != " ".join(response_text.split())[: len(redacted_excerpt)]
    return RagServiceResponseSummary(
        sha256=hashlib.sha256(response_text.encode("utf-8", errors="replace")).hexdigest(),
        length=len(response_text),
        redacted_excerpt=redacted_excerpt,
        redaction=RedactionMetadata(status="redacted" if redacted else "not_applicable", sha256=_sha256_text(response_text), length=len(response_text), marker=_REDACTED if redacted else None),
    )


def _write_query_artifact(
    output_dir: Path,
    *,
    query: RagQuery,
    result_index: int,
    request_payload: dict[str, object],
    response_summary: RagServiceResponseSummary,
    status: str,
    latency: float,
    status_code: int,
    retrieved_ids: list[str],
    cited_ids: list[str],
) -> HarnessArtifactRef:
    name = f"rag-service-query-{result_index + 1}-{query.id}.json"
    payload = {
        "schema_version": "malleus.rag_service_query_artifact.v1",
        "query_id": query.id,
        "tenant": query.tenant,
        "request_summary": {
            "query_sha256": _sha256_text(str(request_payload.get("query", ""))),
            "query_length": len(str(request_payload.get("query", ""))),
            "fields": sorted(request_payload.keys()),
        },
        "response_summary": response_summary.model_dump(mode="json"),
        "status": status,
        "http_status": status_code,
        "latency_seconds": latency,
        "retrieved_ids": retrieved_ids,
        "cited_ids": cited_ids,
    }
    path = output_dir / name
    text = json.dumps(payload, indent=2, sort_keys=True)
    path.write_text(text, encoding="utf-8")
    return HarnessArtifactRef(
        artifact_id=f"rag-service-{query.id}",
        artifact_type="rag_service_query_summary",
        path=name,
        sha256=_sha256_text(text),
        redaction_status="redacted",
        metadata={"mode": "live_provider", "evidence_level": "live_system_trace"},
    )


def _config_error_result(query: RagQuery, reason: str, result_index: int) -> RagServiceResult:
    harness_result = HarnessResult(target_type="rag_service", status="error", error_type="TargetConfigError", error_message=reason, metadata={"target_call_count": 0})
    return RagServiceResult(
        query_id=query.id,
        tenant=query.tenant,
        status="target_config_error",
        reason=reason,
        reason_codes=["target_config_error"],
        target_call_count=0,
        harness_result=harness_result,
        evidence_ref=f"rag-service-report.json#/results/{result_index}",
        coverage_tags=["rag", "rag_service", "target_config_error"],
    )


def _harness_metadata(result: RagServiceResult) -> dict[str, Any]:
    metadata = getattr(result.harness_result, "metadata", {})
    return metadata if isinstance(metadata, dict) else {}


def _summary(results: list[RagServiceResult]) -> RagServiceSummary:
    statuses = ["passed", "failed", "target_capability_gap", "target_config_error", "target_error"]
    counts = {status: sum(1 for result in results if result.status == status) for status in statuses}
    return RagServiceSummary(
        total_queries=len(results),
        passed=counts["passed"],
        failed=counts["failed"],
        target_capability_gap=counts["target_capability_gap"],
        target_config_error=counts["target_config_error"],
        target_error=counts["target_error"],
        target_call_count=sum(result.target_call_count for result in results),
        detections=sum(len(result.detections) for result in results),
        status_counts=counts,
        reason_codes=sorted({code for result in results for code in result.reason_codes}),
    )


def _rag_auto_repair_summary(results: list[RagServiceResult]) -> dict[str, Any]:
    repairs = [
        result.harness_result.metadata.get("rag_auto_repair")
        for result in results
        if isinstance(result.harness_result.metadata.get("rag_auto_repair"), dict)
    ]
    dropped_cross_tenant = sorted(
        {
            str(doc_id)
            for repair in repairs
            for doc_id in (repair.get("dropped_cross_tenant_ids") if isinstance(repair.get("dropped_cross_tenant_ids"), list) else [])
        }
    )
    hydrated_required = sorted(
        {
            str(doc_id)
            for repair in repairs
            for doc_id in (repair.get("hydrated_required_ids") if isinstance(repair.get("hydrated_required_ids"), list) else [])
        }
    )
    return {
        "schema_version": "malleus.rag_auto_repair_summary.v1",
        "enabled": bool(repairs),
        "query_count": len(repairs),
        "queries_with_cross_tenant_drops": sum(1 for repair in repairs if repair.get("dropped_cross_tenant_ids")),
        "queries_with_required_source_hydration": sum(1 for repair in repairs if repair.get("hydrated_required_ids")),
        "dropped_cross_tenant_ids": dropped_cross_tenant,
        "hydrated_required_ids": hydrated_required,
    }


def _render_markdown(report: RagServiceReport) -> str:
    auto_repair = report.metadata.get("rag_auto_repair_summary") if isinstance(report.metadata.get("rag_auto_repair_summary"), dict) else {}
    lines = [
        f"# Malleus RAG Service Harness: {_md_safe(report.fixture_name)}",
        "",
        f"- Mode: {_md_safe(report.mode)}",
        f"- Evidence wording: {_md_safe(report.report_wording)}",
        f"- Target: {_md_safe(report.target_name)} ({_md_safe(report.target_type)})",
        f"- Target calls: {report.summary.target_call_count}",
        f"- Live model calls: {report.live_model_calls}",
        f"- Passed: {report.summary.passed}",
        f"- Failed: {report.summary.failed}",
        f"- Target capability gaps: {report.summary.target_capability_gap}",
        f"- Auto repair: {_md_safe(_format_auto_repair(auto_repair))}",
        "",
        "| Query | Status | Reason codes | Retrieval trace | Latency |",
        "| --- | --- | --- | --- | --- |",
    ]
    for result in report.results:
        trace = ", ".join(result.retrieved_ids) or "none"
        latency = f"{result.latency_seconds:.3f}s" if result.latency_seconds is not None else "n/a"
        lines.append(f"| {_md_safe(result.query_id)} | {_md_safe(result.status)} | {_md_safe(', '.join(result.reason_codes) or 'none')} | {_md_safe(trace)} | {_md_safe(latency)} |")
    lines.extend(render_case_detail_section("Query Details", [_rag_case_detail(result) for result in report.results]))
    return "\n".join(lines).rstrip() + "\n"


def _rag_case_detail(result: RagServiceResult) -> dict[str, Any]:
    return {
        "id": result.query_id,
        "status": result.status,
        "reason_codes": result.reason_codes,
        "latency": result.latency_seconds,
        "verdict_reason": verdict_reason(result.status, result.reason_codes, result.reason),
        "observed_behavior": summarize_harness_result(result.harness_result),
        "retrieval": result.retrieved_ids,
        "citations": result.cited_ids,
        "detections": [detection_summary(detection) for detection in result.detections],
        "artifacts": [artifact_summary(artifact) for artifact in result.artifact_refs],
        "answer_excerpt": result.answer_excerpt,
        "evidence_ref": result.evidence_ref,
    }


def _format_auto_repair(summary: dict[str, Any]) -> str:
    if not summary.get("enabled"):
        return "not reported by target"
    return (
        f"enabled; cross-tenant drops on {summary.get('queries_with_cross_tenant_drops', 0)} queries; "
        f"required-source hydration on {summary.get('queries_with_required_source_hydration', 0)} queries"
    )


def write_rag_service_artifacts(report: RagServiceReport, output_dir: str | Path) -> list[Path]:
    destination = Path(output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    payloads = {
        "rag-service-report.json": report.model_dump_json(indent=2),
        "rag-service-report.md": _render_markdown(report),
    }
    paths = []
    for name, text in payloads.items():
        path = destination / name
        path.write_text(text, encoding="utf-8")
        paths.append(path)
    return paths


__all__ = [
    "RagServiceReport",
    "RagServiceResult",
    "RagServiceStatus",
    "run_rag_service_harness",
    "write_rag_service_artifacts",
]
