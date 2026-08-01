from pathlib import Path

from malleus.attack_graph import (
    build_public_leaderboard,
    build_adaptive_attack_graph,
    load_public_benchmark,
    score_public_benchmark,
)
from malleus.flight_recorder import FlightEvent, FlightRecording, InvariantViolation
from malleus.organization import OrganizationEvidenceStore


def _recording(identifier: str, violations: int) -> FlightRecording:
    return FlightRecording(
        recording_id=identifier,
        created_at=f"2026-01-0{identifier[-1]}T00:00:00Z",
        source="fixture",
        events=[
            FlightEvent(
                event_id="retrieval",
                trace_id=identifier,
                sequence=0,
                kind="retrieval",
                event_type="retrieval",
            ),
            FlightEvent(
                event_id="tool",
                trace_id=identifier,
                sequence=1,
                kind="tool",
                event_type="tool_call",
                parent_ids=["retrieval"],
            ),
        ],
        violations=[
            InvariantViolation(
                violation_id=f"v-{index}",
                invariant_id="approval",
                invariant_title="Approval",
                severity="critical",
                trace_id=identifier,
                event_id="tool",
                event_type="tool_call",
                reason="missing approval",
                causal_event_ids=["retrieval", "tool"],
            )
            for index in range(violations)
        ],
    )


def test_adaptive_graph_recommends_observed_surfaces() -> None:
    graph = build_adaptive_attack_graph(_recording("run-1", 1))
    assert graph.recommended_scenarios == ["rag-indirect-injection", "tool-approval-bypass"]
    assert any(node.node_type == "violation" for node in graph.nodes)


def test_organization_store_tracks_security_trend(tmp_path: Path) -> None:
    store = OrganizationEvidenceStore(tmp_path / "organization.db")
    store.add_recording("acme", "assistant", _recording("run-1", 2))
    store.add_recording("acme", "assistant", _recording("run-2", 1))

    assert len(store.list_runs("acme", project="assistant")) == 2
    assert store.get_recording("run-2").recording_id == "run-2"
    trend = store.trend("acme", project="assistant")
    assert trend.direction == "improving"
    assert trend.total_violations == 3


def test_public_benchmark_catalog_is_valid() -> None:
    benchmark = load_public_benchmark("datasets/public_benchmark/agent-security-v1.yaml")
    assert benchmark.id == "malleus-agent-security-v1"
    assert len(benchmark.scenarios) == 6
    assert {scenario.surface for scenario in benchmark.scenarios} >= {
        "rag_service",
        "tool_agent",
        "memory_agent",
        "multi_agent",
        "browser_agent",
        "code_agent",
    }
    report = score_public_benchmark(_recording("run-1", 0), benchmark)
    assert report.operational_completion_rate == 1.0
    assert report.trace_coverage_rate > 0
    assert any(result.status == "capability_gap" for result in report.results)
    weaker = report.model_copy(update={"invariant_preservation_rate": 0.0})
    leaderboard = build_public_leaderboard(
        [("strong", "strong.json", report), ("weak", "weak.json", weaker)]
    )
    assert [entry.target for entry in leaderboard.entries] == ["strong", "weak"]
