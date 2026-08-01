from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, model_validator

from malleus.agent_trace import AgentTrace, AgentTraceCollection
from malleus.utils.ids import new_run_id
from malleus.utils.time import now_iso


FLIGHT_EVENT_SCHEMA_VERSION = "malleus.flight_event.v1"
FLIGHT_RECORDING_SCHEMA_VERSION = "malleus.flight_recording.v1"
INVARIANT_SCHEMA_VERSION = "malleus.security_invariants.v1"

EventKind = Literal[
    "prompt",
    "model",
    "retrieval",
    "tool",
    "approval",
    "memory",
    "handoff",
    "browser",
    "file",
    "command",
    "network",
    "policy",
    "artifact",
    "output",
    "other",
]
InvariantRule = Literal[
    "forbid_event",
    "requires_approval",
    "forbid_transition",
    "deny_cross_tenant",
]


class FlightEvent(BaseModel):
    schema_version: str = FLIGHT_EVENT_SCHEMA_VERSION
    event_id: str
    trace_id: str
    sequence: int = Field(ge=0)
    timestamp: str | None = None
    kind: EventKind
    event_type: str
    actor: str = "agent"
    trust_zone: str = "unknown"
    parent_ids: list[str] = Field(default_factory=list)
    summary: str = ""
    status: str = "ok"
    attributes: dict[str, Any] = Field(default_factory=dict)
    content_sha256: str | None = None


class SecurityInvariant(BaseModel):
    id: str
    title: str
    severity: Literal["low", "medium", "high", "critical"] = "high"
    rule: InvariantRule
    event_types: list[str] = Field(default_factory=list)
    source_event_types: list[str] = Field(default_factory=list)
    target_event_types: list[str] = Field(default_factory=list)
    attribute: str | None = None
    expected: Any = True
    description: str = ""

    @model_validator(mode="after")
    def validate_rule_fields(self) -> "SecurityInvariant":
        if self.rule in {"forbid_event", "requires_approval"} and not self.event_types:
            raise ValueError(f"{self.rule} requires event_types")
        if self.rule == "forbid_transition" and (
            not self.source_event_types or not self.target_event_types
        ):
            raise ValueError("forbid_transition requires source_event_types and target_event_types")
        return self


class InvariantSet(BaseModel):
    schema_version: str = INVARIANT_SCHEMA_VERSION
    name: str
    invariants: list[SecurityInvariant]


class InvariantViolation(BaseModel):
    violation_id: str
    invariant_id: str
    invariant_title: str
    severity: str
    trace_id: str
    event_id: str
    event_type: str
    reason: str
    causal_event_ids: list[str] = Field(default_factory=list)
    reproducible: bool = True


class FlightRecording(BaseModel):
    schema_version: str = FLIGHT_RECORDING_SCHEMA_VERSION
    recording_id: str = Field(default_factory=new_run_id)
    created_at: str = Field(default_factory=now_iso)
    source: str
    events: list[FlightEvent]
    violations: list[InvariantViolation] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SignedManifestEntry(BaseModel):
    path: str
    sha256: str
    size_bytes: int


class SignedEvidenceManifest(BaseModel):
    schema_version: str = "malleus.signed_evidence_manifest.v1"
    algorithm: Literal["hmac-sha256"] = "hmac-sha256"
    key_id: str
    created_at: str = Field(default_factory=now_iso)
    entries: list[SignedManifestEntry]
    signature: str


def load_invariant_set(path: str | Path) -> InvariantSet:
    payload = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return InvariantSet.model_validate(payload)


def ingest_trace(path: str | Path, *, source_format: str = "auto") -> FlightRecording:
    source_path = Path(path)
    payloads = _load_payloads(source_path)
    resolved_format = _detect_format(payloads, source_format)
    events: list[FlightEvent] = []
    if resolved_format == "agent_trace":
        for payload in payloads:
            events.extend(_events_from_agent_payload(payload))
    elif resolved_format in {"generic", "otel"}:
        if resolved_format == "otel":
            payloads = _flatten_otel_payloads(payloads)
        events = [
            _event_from_mapping(payload, sequence=index, otel=resolved_format == "otel")
            for index, payload in enumerate(payloads)
        ]
    else:
        raise ValueError(f"unsupported trace format: {resolved_format}")
    events = _normalize_causality(events)
    return FlightRecording(
        source=str(source_path),
        events=events,
        metadata={"source_format": resolved_format, "event_count": len(events)},
    )


def evaluate_invariants(
    recording: FlightRecording, invariant_set: InvariantSet
) -> FlightRecording:
    by_id = {event.event_id: event for event in recording.events}
    violations: list[InvariantViolation] = []
    for invariant in invariant_set.invariants:
        for event in recording.events:
            reason = _violation_reason(event, invariant, by_id)
            if reason is None:
                continue
            causal_ids = causal_chain(event.event_id, by_id)
            digest = hashlib.sha256(
                f"{invariant.id}:{event.trace_id}:{event.event_id}".encode()
            ).hexdigest()[:16]
            violations.append(
                InvariantViolation(
                    violation_id=f"vio-{digest}",
                    invariant_id=invariant.id,
                    invariant_title=invariant.title,
                    severity=invariant.severity,
                    trace_id=event.trace_id,
                    event_id=event.event_id,
                    event_type=event.event_type,
                    reason=reason,
                    causal_event_ids=causal_ids,
                )
            )
    return recording.model_copy(update={"violations": violations}, deep=True)


def causal_chain(event_id: str, events: dict[str, FlightEvent]) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()

    def visit(current_id: str) -> None:
        if current_id in seen or current_id not in events:
            return
        seen.add(current_id)
        for parent_id in events[current_id].parent_ids:
            visit(parent_id)
        ordered.append(current_id)

    visit(event_id)
    return ordered


def build_replay_bundle(
    recording: FlightRecording,
    invariant_set: InvariantSet,
    violation_id: str,
) -> dict[str, Any]:
    violation = next(
        (item for item in recording.violations if item.violation_id == violation_id), None
    )
    if violation is None:
        raise ValueError(f"unknown violation: {violation_id}")
    event_ids = set(violation.causal_event_ids)
    events = [event for event in recording.events if event.event_id in event_ids]
    invariant = next(
        item for item in invariant_set.invariants if item.id == violation.invariant_id
    )
    return {
        "schema_version": "malleus.causal_replay.v1",
        "recording_id": recording.recording_id,
        "violation": violation.model_dump(mode="json"),
        "invariant": invariant.model_dump(mode="json"),
        "events": [event.model_dump(mode="json") for event in events],
        "expected_violation_ids": [violation.violation_id],
    }


def write_recording(recording: FlightRecording, path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(recording.model_dump_json(indent=2), encoding="utf-8")
    return destination


def sign_evidence_directory(
    directory: str | Path, *, key: str, key_id: str, output: str | Path | None = None
) -> SignedEvidenceManifest:
    root = Path(directory).resolve()
    output_path = Path(output).resolve() if output else root / "signed-manifest.json"
    entries = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        if path.resolve() == output_path:
            continue
        entries.append(
            SignedManifestEntry(
                path=path.relative_to(root).as_posix(),
                sha256=_sha256_file(path),
                size_bytes=path.stat().st_size,
            )
        )
    signature = hmac.new(
        key.encode(), _manifest_bytes(key_id, entries), hashlib.sha256
    ).hexdigest()
    manifest = SignedEvidenceManifest(key_id=key_id, entries=entries, signature=signature)
    output_path.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")
    return manifest


def verify_evidence_directory(
    directory: str | Path, manifest_path: str | Path, *, key: str
) -> tuple[bool, list[str]]:
    root = Path(directory).resolve()
    manifest = SignedEvidenceManifest.model_validate_json(
        Path(manifest_path).read_text(encoding="utf-8")
    )
    errors: list[str] = []
    for entry in manifest.entries:
        path = (root / entry.path).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            errors.append(f"missing:{entry.path}")
            continue
        if _sha256_file(path) != entry.sha256 or path.stat().st_size != entry.size_bytes:
            errors.append(f"changed:{entry.path}")
    expected = hmac.new(
        key.encode(), _manifest_bytes(manifest.key_id, manifest.entries), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, manifest.signature):
        errors.append("invalid_signature")
    return not errors, errors


def _load_payloads(path: Path) -> list[dict[str, Any]]:
    if path.suffix == ".jsonl":
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        return [payload]
    raise ValueError("trace input must be an object, array, or JSONL records")


def _detect_format(payloads: list[dict[str, Any]], requested: str) -> str:
    if requested != "auto":
        return requested
    first = payloads[0] if payloads else {}
    schema = str(first.get("schema_version", ""))
    if schema.startswith("malleus.agent_trace") or "traces" in first:
        return "agent_trace"
    if "spanId" in first or "span_id" in first or "resourceSpans" in first:
        return "otel"
    return "generic"


def _flatten_otel_payloads(payloads: list[dict[str, Any]]) -> list[dict[str, Any]]:
    flattened: list[dict[str, Any]] = []
    for payload in payloads:
        resource_spans = payload.get("resourceSpans")
        if not isinstance(resource_spans, list):
            flattened.append(payload)
            continue
        for resource_span in resource_spans:
            if not isinstance(resource_span, dict):
                continue
            resource = resource_span.get("resource", {})
            resource_attributes = _otel_attributes(resource.get("attributes", [])) if isinstance(resource, dict) else {}
            scope_spans = resource_span.get("scopeSpans") or resource_span.get("instrumentationLibrarySpans") or []
            for scope_span in scope_spans if isinstance(scope_spans, list) else []:
                if not isinstance(scope_span, dict):
                    continue
                for span in scope_span.get("spans", []):
                    if not isinstance(span, dict):
                        continue
                    flattened.append(
                        {
                            **span,
                            "attributes": {
                                **resource_attributes,
                                **_otel_attributes(span.get("attributes", [])),
                            },
                        }
                    )
    return flattened


def _otel_attributes(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    result: dict[str, Any] = {}
    for item in value if isinstance(value, list) else []:
        if not isinstance(item, dict) or "key" not in item:
            continue
        raw = item.get("value")
        if isinstance(raw, dict) and len(raw) == 1:
            raw = next(iter(raw.values()))
        result[str(item["key"])] = raw
    return result


def _events_from_agent_payload(payload: dict[str, Any]) -> list[FlightEvent]:
    if "traces" in payload:
        collection = AgentTraceCollection.model_validate(payload)
        traces = collection.traces
    else:
        traces = [AgentTrace.model_validate(payload)]
    output: list[FlightEvent] = []
    for trace in traces:
        for index, event in enumerate(trace.events):
            event_id = event.event_id or f"{trace.trace_id}-{index}"
            output.append(
                FlightEvent(
                    event_id=event_id,
                    trace_id=trace.trace_id,
                    sequence=index,
                    timestamp=event.timestamp,
                    kind=_event_kind(event.event_type),
                    event_type=event.event_type,
                    actor=event.role or event.name or "agent",
                    trust_zone=str(event.metadata.get("trust_zone", "unknown")),
                    parent_ids=[event.parent_event_id] if event.parent_event_id else [],
                    summary=event.summary,
                    status=event.status,
                    attributes=dict(event.metadata),
                    content_sha256=event.sha256,
                )
            )
    return output


def _event_from_mapping(payload: dict[str, Any], *, sequence: int, otel: bool) -> FlightEvent:
    attributes = payload.get("attributes") if isinstance(payload.get("attributes"), dict) else {}
    event_type = str(
        payload.get("event_type")
        or payload.get("event")
        or payload.get("name")
        or payload.get("type")
        or "event"
    )
    trace_id = str(payload.get("trace_id") or payload.get("traceId") or "trace-imported")
    event_id = str(payload.get("event_id") or payload.get("span_id") or payload.get("spanId") or f"event-{sequence}")
    parent = payload.get("parent_event_id") or payload.get("parent_span_id") or payload.get("parentSpanId")
    return FlightEvent(
        event_id=event_id,
        trace_id=trace_id,
        sequence=int(payload.get("sequence", sequence)),
        timestamp=str(payload.get("timestamp") or payload.get("startTime") or "") or None,
        kind=_event_kind(event_type),
        event_type=event_type,
        actor=str(payload.get("actor") or attributes.get("gen_ai.agent.name") or "agent"),
        trust_zone=str(payload.get("trust_zone") or attributes.get("malleus.trust_zone") or "unknown"),
        parent_ids=[str(parent)] if parent else [],
        summary=str(payload.get("summary") or payload.get("description") or event_type),
        status=str(payload.get("status") or "ok"),
        attributes={**attributes, **({"otel": True} if otel else {})},
    )


def _normalize_causality(events: list[FlightEvent]) -> list[FlightEvent]:
    previous_by_trace: dict[str, str] = {}
    normalized: list[FlightEvent] = []
    for event in sorted(events, key=lambda item: (item.trace_id, item.sequence)):
        parents = event.parent_ids
        if not parents and event.trace_id in previous_by_trace:
            parents = [previous_by_trace[event.trace_id]]
        normalized_event = event.model_copy(update={"parent_ids": parents})
        normalized.append(normalized_event)
        previous_by_trace[event.trace_id] = event.event_id
    return normalized


def _violation_reason(
    event: FlightEvent,
    invariant: SecurityInvariant,
    events: dict[str, FlightEvent],
) -> str | None:
    if invariant.rule == "forbid_event" and event.event_type in invariant.event_types:
        return f"forbidden event observed: {event.event_type}"
    if invariant.rule == "requires_approval" and event.event_type in invariant.event_types:
        attribute = invariant.attribute or "approved"
        if event.attributes.get(attribute) != invariant.expected:
            return f"{event.event_type} requires {attribute}={invariant.expected!r}"
    if invariant.rule == "forbid_transition" and event.event_type in invariant.target_event_types:
        chain = causal_chain(event.event_id, events)
        if any(events[item].event_type in invariant.source_event_types for item in chain[:-1]):
            return (
                f"forbidden causal transition from {invariant.source_event_types} "
                f"to {event.event_type}"
            )
    if invariant.rule == "deny_cross_tenant" and event.event_type in invariant.event_types:
        source_tenant = event.attributes.get("source_tenant")
        target_tenant = event.attributes.get("target_tenant")
        if source_tenant and target_tenant and source_tenant != target_tenant:
            return f"cross-tenant transition {source_tenant!r} -> {target_tenant!r}"
    return None


def _event_kind(event_type: str) -> EventKind:
    lowered = event_type.lower()
    mappings: list[tuple[tuple[str, ...], EventKind]] = [
        (("prompt", "user_message", "system_message"), "prompt"),
        (("model", "assistant", "generation"), "model"),
        (("retrieval", "citation", "rag"), "retrieval"),
        (("tool", "sink", "action"), "tool"),
        (("approval",), "approval"),
        (("memory",), "memory"),
        (("handoff", "delegate"), "handoff"),
        (("browser", "navigation"), "browser"),
        (("file", "diff"), "file"),
        (("command", "shell"), "command"),
        (("network", "egress"), "network"),
        (("policy", "blocked"), "policy"),
        (("artifact",), "artifact"),
        (("output", "final_answer"), "output"),
    ]
    for markers, kind in mappings:
        if any(marker in lowered for marker in markers):
            return kind
    return "other"


def _manifest_bytes(key_id: str, entries: list[SignedManifestEntry]) -> bytes:
    payload = {"key_id": key_id, "entries": [entry.model_dump(mode="json") for entry in entries]}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
