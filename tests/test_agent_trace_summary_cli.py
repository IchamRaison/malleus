import json

from typer.testing import CliRunner

from malleus.agent_trace import AgentTrace, collect_agent_traces_from_payload, load_agent_trace_collection
from malleus.cli import app
from malleus.live_full import _render_full_summary_markdown


def _trace(case_id: str = "case-1") -> AgentTrace:
    return AgentTrace(
        target_type="tool_agent",
        evidence_type="agent_trace",
        status="capability_gap",
        case_id=case_id,
        target_call_count=1,
        target_trace_count=0,
        capability_gaps=["missing_tool_trace"],
        reason_codes=["missing_tool_trace"],
    )


def test_collect_agent_traces_from_nested_report_payload() -> None:
    payload = {
        "agent_traces": [_trace("top").model_dump(mode="json")],
        "rows": [
            {
                "metadata": {
                    "agent_trace_summary": {
                        "total_traces": 1,
                        "capability_gap_count": 1,
                    }
                }
            }
        ],
    }

    traces, summaries = collect_agent_traces_from_payload(payload)

    assert [trace.case_id for trace in traces] == ["top"]
    assert summaries == [{"total_traces": 1, "capability_gap_count": 1}]


def test_trace_summary_command_writes_collection(tmp_path) -> None:
    report = tmp_path / "report.json"
    out = tmp_path / "agent-traces.json"
    report.write_text(json.dumps({"agent_traces": [_trace().model_dump(mode="json")]}), encoding="utf-8")

    result = CliRunner().invoke(app, ["trace-summary", "--report", str(report), "--out", str(out)])

    assert result.exit_code == 0, result.output
    assert "Traces: 1" in result.output
    assert "Capability gaps: 1" in result.output
    collection = load_agent_trace_collection([report])
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["summary"] == collection.summary.model_dump(mode="json")


def test_live_full_summary_lists_agent_trace_rows() -> None:
    matrix = {
        "target": {"model": "model-a", "adapter": "openai_compatible"},
        "live_model_calls": 0,
        "rows": [
            {
                "surface": "pack:tool-agent-v1",
                "runner": "tool-agent-harness",
                "target_type": "tool_agent",
                "evidence_type": "live_system_trace",
                "evidence_level": "live_system_trace",
                "status": "passed",
                "live_model_calls": 0,
                "metadata": {
                    "agent_trace_summary": {
                        "total_traces": 2,
                        "capability_gap_count": 0,
                        "target_call_count": 2,
                        "target_trace_count": 4,
                        "evidence_type_counts": {"agent_trace": 2},
                        "event_type_counts": {"tool_call": 4},
                    }
                },
            }
        ],
    }

    markdown = _render_full_summary_markdown(matrix)

    assert "canonical AgentTrace evidence" in markdown
    assert "`pack:tool-agent-v1`, traces=2" in markdown
    assert "events=tool_call=4" in markdown
