import json
from pathlib import Path

from malleus.flight_recorder import (
    FlightEvent,
    FlightRecording,
    InvariantSet,
    SecurityInvariant,
    build_replay_bundle,
    evaluate_invariants,
    ingest_trace,
    sign_evidence_directory,
    verify_evidence_directory,
)


def test_ingest_evaluate_and_replay_causal_trace(tmp_path: Path) -> None:
    trace_path = tmp_path / "trace.jsonl"
    trace_path.write_text(
        "\n".join(
            [
                json.dumps({"event_id": "r1", "trace_id": "t1", "event_type": "retrieval"}),
                json.dumps(
                    {
                        "event_id": "p1",
                        "trace_id": "t1",
                        "event_type": "payment",
                        "attributes": {"approved": False},
                    }
                ),
            ]
        ),
        encoding="utf-8",
    )
    invariants = InvariantSet(
        name="test",
        invariants=[
            SecurityInvariant(
                id="approval",
                title="Payment requires approval",
                severity="critical",
                rule="requires_approval",
                event_types=["payment"],
                attribute="approved",
            ),
            SecurityInvariant(
                id="retrieval-authority",
                title="Retrieval cannot authorize payment",
                rule="forbid_transition",
                source_event_types=["retrieval"],
                target_event_types=["payment"],
            ),
        ],
    )

    recording = evaluate_invariants(ingest_trace(trace_path), invariants)

    assert [event.parent_ids for event in recording.events] == [[], ["r1"]]
    assert {item.invariant_id for item in recording.violations} == {
        "approval",
        "retrieval-authority",
    }
    replay = build_replay_bundle(recording, invariants, recording.violations[0].violation_id)
    assert replay["schema_version"] == "malleus.causal_replay.v1"
    assert replay["events"][-1]["event_id"] == "p1"


def test_cross_tenant_invariant() -> None:
    recording = FlightRecording(
        source="fixture",
        events=[
            FlightEvent(
                event_id="memory",
                trace_id="trace",
                sequence=0,
                kind="memory",
                event_type="memory_read",
                attributes={"source_tenant": "tenant-a", "target_tenant": "tenant-b"},
            )
        ],
    )
    invariants = InvariantSet(
        name="tenants",
        invariants=[
            SecurityInvariant(
                id="tenant",
                title="Tenant isolation",
                rule="deny_cross_tenant",
                event_types=["memory_read"],
            )
        ],
    )

    evaluated = evaluate_invariants(recording, invariants)

    assert evaluated.violations[0].reason == "cross-tenant transition 'tenant-a' -> 'tenant-b'"


def test_signed_manifest_detects_artifact_tampering(tmp_path: Path) -> None:
    (tmp_path / "evidence.json").write_text('{"status":"passed"}', encoding="utf-8")
    manifest = sign_evidence_directory(tmp_path, key="secret", key_id="test-key")
    manifest_path = tmp_path / "signed-manifest.json"

    assert manifest.key_id == "test-key"
    assert verify_evidence_directory(tmp_path, manifest_path, key="secret") == (True, [])

    (tmp_path / "evidence.json").write_text('{"status":"failed"}', encoding="utf-8")
    valid, errors = verify_evidence_directory(tmp_path, manifest_path, key="secret")
    assert valid is False
    assert errors == ["changed:evidence.json"]


def test_ingests_nested_otlp_spans(tmp_path: Path) -> None:
    trace_path = tmp_path / "otlp.json"
    trace_path.write_text(
        json.dumps(
            {
                "resourceSpans": [
                    {
                        "resource": {
                            "attributes": [
                                {"key": "service.name", "value": {"stringValue": "agent-api"}}
                            ]
                        },
                        "scopeSpans": [
                            {
                                "spans": [
                                    {
                                        "traceId": "trace-1",
                                        "spanId": "span-1",
                                        "name": "tool_call",
                                        "attributes": [
                                            {
                                                "key": "gen_ai.agent.name",
                                                "value": {"stringValue": "planner"},
                                            }
                                        ],
                                    }
                                ]
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    recording = ingest_trace(trace_path)

    assert recording.metadata["source_format"] == "otel"
    assert recording.events[0].actor == "planner"
    assert recording.events[0].attributes["service.name"] == "agent-api"
