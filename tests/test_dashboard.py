from __future__ import annotations

import json
from pathlib import Path

from malleus.dashboard import write_dashboard


def _report(path: Path, model: str, score: int, passed: int = 1) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "target_model": model,
                "summary": {"score_total": score, "max_score_total": 500, "passed_items": passed, "total_items": 5},
                "datasets": [
                    {
                        "dataset_name": "smoke-v1-cases",
                        "case_results": [
                            {"case_id": "smoke-ib-001", "passed": score == 500, "score": score, "penalty": 0, "severity": "high", "objective": "test", "response_text": "safe excerpt"}
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_write_dashboard_renders_model_scores(tmp_path: Path) -> None:
    reports = [_report(tmp_path / "a" / "report.json", "model/a", 500, 5), _report(tmp_path / "b" / "report.json", "model/b", 350, 1)]
    output = write_dashboard(reports, tmp_path / "dashboard")
    html = (output / "index.html").read_text(encoding="utf-8")
    assert "Malleus Benchmark Dashboard" in html
    assert "Executive security summary" in html
    assert "Risk cards by surface" in html
    assert "model/a" in html
    assert "500/500" in html
    assert "model/b" in html
    assert "70.0%" in html


def test_write_dashboard_escapes_hostile_report_fields(tmp_path: Path) -> None:
    reports = [
        _report(
            tmp_path / "hostile" / "report.json",
            "model | <script>alert(1)</script> api_key=SYNTHETIC-SK-OPENAI-SECRET",
            0,
            0,
        )
    ]

    output = write_dashboard(reports, tmp_path / "dashboard")
    html = (output / "index.html").read_text(encoding="utf-8")

    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<script>" not in html
    assert "SYNTHETIC-SK-OPENAI-SECRET" not in html
    assert "[REDACTED]" in html


def test_write_dashboard_renders_live_evidence_surface_cards(tmp_path: Path) -> None:
    live_report = tmp_path / "live" / "live-full-evidence.json"
    live_report.parent.mkdir(parents=True, exist_ok=True)
    live_report.write_text(
        json.dumps(
            {
                "schema_version": "malleus.live_evidence_matrix.v1",
                "metadata": {"target_name": "deepseek-code-agent"},
                "rows": [
                    {
                        "surface_id": "code-agent:dependency-confusion",
                        "case_id": "code-dep-001",
                        "status": "failed",
                        "evidence_level": "live_system_trace",
                        "reason": "dependency confusion path accepted",
                        "metadata": {"target_type": "code_agent", "reason_codes": ["dependency_confusion", "sandbox_review"]},
                    },
                    {
                        "surface_id": "rag:tenant-leakage",
                        "case_id": "rag-tenant-001",
                        "status": "passed",
                        "evidence_level": "live_system_trace",
                        "metadata": {"target_type": "rag_service", "reason_codes": ["tenant_leakage"]},
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    output = write_dashboard([live_report], tmp_path / "dashboard")
    html = (output / "index.html").read_text(encoding="utf-8")

    assert "deepseek-code-agent" in html
    assert "code-agent:dependency-confusion" in html
    assert "rag:tenant-leakage" in html
    assert "live_system_trace" in html
    assert "dependency_confusion" in html
    assert "Failure replay cards" in html


def test_write_dashboard_renders_tool_gateway_evidence(tmp_path: Path) -> None:
    report = tmp_path / "tool" / "tool-agent-report.json"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(
        json.dumps(
            {
                "schema_version": "malleus.tool_agent_report.v1",
                "target_name": "local-tool-agent",
                "summary": {
                    "total_scenarios": 1,
                    "passed": 0,
                    "failed": 1,
                    "target_capability_gap": 0,
                    "target_config_error": 0,
                    "target_error": 0,
                    "target_call_count": 1,
                    "target_trace_count": 2,
                    "detections": 2,
                    "tool_gateway_calls": 2,
                    "tool_gateway_blocked": 1,
                    "status_counts": {"failed": 1},
                    "reason_codes": ["tool_gateway_blocked", "private_to_public_sink"],
                },
                "results": [
                    {
                        "scenario_id": "gateway-private-public",
                        "attack_surface": "tool_gateway",
                        "status": "failed",
                        "reason": "gateway blocked unsafe tool route",
                        "reason_codes": ["tool_gateway_blocked", "private_to_public_sink"],
                        "tool_calls": [
                            {
                                "tool_name": "send_email",
                                "status": "error",
                                "metadata": {
                                    "gateway_decision": "blocked",
                                    "gateway_reason_codes": ["private_to_public_sink"],
                                    "gateway_policy_hash": "abcdef1234567890",
                                },
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    output = write_dashboard([report], tmp_path / "dashboard")
    html = (output / "index.html").read_text(encoding="utf-8")

    assert "Tool Gateway evidence" in html
    assert "1/2" in html
    assert "private_to_public_sink" in html
    assert "policy abcdef123456" in html
    assert "local-tool-agent" in html
