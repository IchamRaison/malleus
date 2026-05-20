from __future__ import annotations

import json
from pathlib import Path

import pytest

from malleus.ir import ArtifactRef, ReportManifest
from malleus.reporting import write_html_report, write_json_report, write_markdown_report, write_model_risk_card
from malleus.schemas import (
    AdjudicationRecord,
    CaseResult,
    CoverageCell,
    DatasetReport,
    DatasetSummary,
    EvidenceRef,
    Finding,
    GateResult,
    PolicyDecision,
    ReplaySpec,
    RunReport,
    RunSummary,
    SignalCheckResult,
    TraceEvent,
)


FIXTURES = Path(__file__).parent / "fixtures"


def _hostile_text() -> str:
    return (FIXTURES / "hostile_artifact_content.txt").read_text(encoding="utf-8")


def test_premium_contracts_are_versioned_and_instantiable() -> None:
    evidence = EvidenceRef(
        evidence_id="ev-1",
        artifact_path="evidence/redacted.json",
        artifact_type="redacted_preview",
        sha256="0" * 64,
        redacted_preview="[REDACTED] safe preview",
    )
    finding = Finding(
        finding_id="finding-1",
        title="Unsafe behavior detected",
        severity="high",
        status="fail",
        description="Synthetic finding with evidence references only.",
        redacted_preview="[REDACTED] preview",
        evidence_refs=[evidence],
    )
    trace_event = TraceEvent(event_id="trace-1", event_type="case_finished", timestamp="2026-01-01T00:00:00Z", evidence_refs=[evidence])
    decision = PolicyDecision(decision_id="policy-1", policy_name="default", status="fail", reasons=["unsafe"], evidence_refs=[evidence])
    gate = GateResult(gate_id="gate-1", status="fail", reasons=["policy_failed"], policy_decisions=[decision])
    coverage = CoverageCell(dimension="surface", value="rag_context", total_items=2, covered_items=1, finding_ids=[finding.finding_id])
    replay = ReplaySpec(replay_id="replay-1", target_name="target", input_path="input.yaml", scoring_path="scoring.yaml", case_ids=["case-1"])
    adjudication = AdjudicationRecord(
        adjudication_id="adj-1",
        finding_id=finding.finding_id,
        reviewer="analyst",
        decision="accepted",
        rationale="Evidence reference is sufficient.",
        evidence_refs=[evidence],
    )
    manifest = ReportManifest(
        run_id="run-1",
        report_type="malleus_run",
        artifacts=[ArtifactRef(path="report.json", kind="json", artifact_type="run_report_json", relative_path="report.json", sha256="1" * 64, redaction_status="unknown")],
    )

    contracts = [evidence, finding, trace_event, decision, gate, coverage, replay, adjudication, manifest]

    assert all(contract.schema_version for contract in contracts)
    assert manifest.schema_version == "malleus.report_manifest.v1"


def test_premium_evidence_contracts_reject_raw_payload_fields() -> None:
    allowed = EvidenceRef(
        evidence_id="ev-redacted",
        artifact_path="evidence/redacted.json",
        artifact_type="redacted_preview",
        redacted_preview="[REDACTED] preview only",
    )

    assert allowed.redacted_preview == "[REDACTED] preview only"
    with pytest.raises(ValueError, match="raw evidence fields"):
        EvidenceRef(evidence_id="ev-raw", artifact_path="raw.json", artifact_type="raw", raw_payload="unsafe")
    with pytest.raises(ValueError, match="raw evidence fields"):
        Finding(finding_id="finding-raw", title="raw", severity="high", description="bad", body="unsafe")


def _premium_contract_kwargs() -> dict[type, dict]:
    evidence = EvidenceRef(evidence_id="ev-safe", artifact_path="evidence/redacted.json", artifact_type="redacted_preview")
    decision = PolicyDecision(decision_id="policy-safe", policy_name="default", status="pass")
    return {
        EvidenceRef: {"evidence_id": "ev", "artifact_path": "evidence/redacted.json", "artifact_type": "redacted_preview"},
        Finding: {"finding_id": "finding", "title": "Finding", "severity": "high", "description": "Redacted finding", "evidence_refs": [evidence]},
        TraceEvent: {"event_id": "trace", "event_type": "case_finished", "timestamp": "2026-01-01T00:00:00Z", "evidence_refs": [evidence]},
        PolicyDecision: {"decision_id": "policy", "policy_name": "default", "status": "warn", "evidence_refs": [evidence]},
        GateResult: {"gate_id": "gate", "status": "warn", "policy_decisions": [decision]},
        CoverageCell: {"dimension": "surface", "value": "rag_context"},
        ReplaySpec: {"replay_id": "replay", "target_name": "target", "input_path": "input.yaml", "scoring_path": "scoring.yaml"},
        AdjudicationRecord: {"adjudication_id": "adj", "finding_id": "finding", "reviewer": "analyst", "decision": "accepted", "rationale": "References only", "evidence_refs": [evidence]},
    }


def test_premium_contracts_reject_raw_payload_keys_recursively_in_metadata() -> None:
    for contract, kwargs in _premium_contract_kwargs().items():
        valid = contract(**kwargs, metadata={"safe": {"notes": ["redacted preview only"]}})
        assert valid.metadata["safe"]["notes"] == ["redacted preview only"]

        with pytest.raises(ValueError, match="raw evidence fields"):
            contract(**kwargs, metadata={"raw_payload": "unsafe"})
        with pytest.raises(ValueError, match="raw evidence fields"):
            contract(**kwargs, metadata={"nested": {"items": [{"raw_body": "unsafe"}]}})


def test_write_model_risk_card_links_deployment_artifacts(tmp_path: Path) -> None:
    report = RunReport(
        run_id="run-risk",
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
        target_name="target",
        target_adapter="openai_compatible",
        target_model="model-a",
        input_path="input.yaml",
        scoring_path="scoring.yaml",
        datasets=[DatasetReport(dataset_name="campaign", category="defensive-campaign", subcategory="synthetic", summary=DatasetSummary(total_items=2, passed_items=2, failed_items=0, score_total=200, max_score_total=200))],
        summary=RunSummary(total_items=2, passed_items=2, failed_items=0, score_total=200, max_score_total=200),
    )
    (tmp_path / "manifest.json").write_text("{}", encoding="utf-8")
    (tmp_path / "events.jsonl").write_text("", encoding="utf-8")
    (tmp_path / "risk-summary.json").write_text(json.dumps({"status": "pass", "reasons": ["policy_passed"]}), encoding="utf-8")

    path = write_model_risk_card(report, tmp_path)
    markdown = path.read_text(encoding="utf-8")

    assert path.name == "model-risk-card.md"
    assert "Status: pass" in markdown
    assert "[manifest.json](manifest.json)" in markdown
    assert "[events.jsonl](events.jsonl)" in markdown
    assert "[risk-summary.json](risk-summary.json)" in markdown
    assert "campaign: 2 campaign items" in markdown


def test_run_report_artifacts_have_stable_contract_and_safe_display(tmp_path: Path) -> None:
    hostile = _hostile_text()
    report = RunReport(
        run_id="run|hostile\n# heading",
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
        target_name="target<script>",
        target_adapter="openai_compatible",
        target_model="model|`x`<script>alert(1)</script>",
        input_path="datasets/benchmark_packs/smoke-v1.yaml",
        scoring_path="configs/scoring-default.yaml",
        datasets=[
            DatasetReport(
                dataset_name="dataset|name\n# injected",
                category="policy|robustness",
                subcategory="html<script>",
                source_path="../../fixtures/hostile.yaml",
                case_results=[
                    CaseResult(
                        dataset_name="dataset|name",
                        case_id="case`1|x",
                        severity="high",
                        objective=hostile,
                        prompt="prompt",
                        response_text=hostile,
                        passed=False,
                        score=0,
                        penalty=100,
                        warnings=[hostile],
                        failure_checks=[SignalCheckResult(type="substring", passed=False, detail=hostile)],
                        pass_checks=[SignalCheckResult(type="substring", passed=False, detail=hostile)],
                    )
                ],
                summary=DatasetSummary(total_items=1, passed_items=0, failed_items=1, score_total=0, max_score_total=100),
            )
        ],
        summary=RunSummary(total_items=1, passed_items=0, failed_items=1, score_total=0, max_score_total=100),
    )

    json_path = write_json_report(report, tmp_path)
    md_path = write_markdown_report(report, tmp_path)
    html_path = write_html_report(report, tmp_path)

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["summary"] == {"total_items": 1, "passed_items": 0, "failed_items": 1, "score_total": 0, "max_score_total": 100}
    assert payload["datasets"][0]["case_results"][0]["case_id"] == "case`1|x"

    markdown = md_path.read_text(encoding="utf-8")
    assert "# Malleus Report:" in markdown
    assert "dataset\\|name \\# injected" in markdown
    assert "case\\`1\\|x" in markdown
    assert "&lt;script>alert" in markdown
    assert "<script>" not in markdown
    assert "SYNTHETIC-SK-OPENAI-SECRET" not in markdown
    assert "[REDACTED]" in markdown
    assert "````text" in markdown

    html = html_path.read_text(encoding="utf-8")
    assert "&lt;script&gt;alert" in html
    assert "<script>" not in html
    assert "SYNTHETIC-SK-OPENAI-SECRET" not in html

def _case_result(case_id: str, *, order: int, step_id: str, tactic: str, passed: bool = True, penalty: int = 0, metadata_extra: dict | None = None) -> CaseResult:
    metadata = {
        "campaign_id": "campaign-fixture",
        "campaign_title": "Synthetic campaign",
        "replay_seed": 777,
        "step_id": step_id,
        "order": order,
        "surface": "chat",
        "tactic": tactic,
        "depends_on": ["setup"] if order > 1 else [],
        "adaptive_branches": [],
        "covert_channel_checks": [],
        "repeated_attempts": 1,
        "raw_payload_present": False,
    }
    metadata.update(metadata_extra or {})
    return CaseResult(
        dataset_name="campaign",
        case_id=case_id,
        severity="medium",
        objective=f"Exercise {tactic}",
        prompt="Synthetic safe prompt",
        response_text="Synthetic safe response",
        passed=passed,
        score=100 - penalty,
        penalty=penalty,
        metadata=metadata,
        failure_checks=[SignalCheckResult(type="substring", passed=True, detail="not present")],
        pass_checks=[SignalCheckResult(type="substring", passed=passed, detail="safe signal")],
    )


def test_model_risk_card_aggregates_campaign_details(tmp_path: Path) -> None:
    report = RunReport(
        run_id="run-campaign-risk",
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
        target_name="target",
        target_adapter="openai_compatible",
        target_model="model-a",
        input_path="input.yaml",
        scoring_path="scoring.yaml",
        datasets=[
            DatasetReport(
                dataset_name="campaign",
                category="defensive-campaign",
                subcategory="synthetic",
                case_results=[
                    _case_result("campaign-01-setup", order=1, step_id="setup", tactic="long-context setup"),
                    _case_result(
                        "campaign-02-branch",
                        order=2,
                        step_id="branch",
                        tactic="adaptive branch",
                        passed=False,
                        penalty=20,
                        metadata_extra={
                            "adaptive_branches": [{"when": "unsafe_request_detected", "next_step_id": "covert", "rationale": "Inspect channels."}],
                            "covert_channel_checks": [{"kind": "zero-width", "description": "synthetic check", "expected_absent": ["ZW-CANARY"]}],
                            "repeated_attempts": 2,
                        },
                    ),
                ],
                summary=DatasetSummary(total_items=2, passed_items=1, failed_items=1, score_total=180, max_score_total=200),
            )
        ],
        summary=RunSummary(total_items=2, passed_items=1, failed_items=1, score_total=180, max_score_total=200),
    )
    (tmp_path / "risk-summary.json").write_text(json.dumps({"status": "fail", "reasons": ["critical_failure"]}), encoding="utf-8")

    path = write_model_risk_card(report, tmp_path)
    markdown = path.read_text(encoding="utf-8")

    assert "Replay seed: 777" in markdown
    assert "Kill-chain order: 1:setup(root) -> 2:branch(setup)" in markdown
    assert "Tactic coverage: adaptive branch=1, long-context setup=1" in markdown
    assert "Adapted branch: branch when=unsafe_request_detected next=covert" in markdown
    assert "Covert-channel checks: zero-width" in markdown
    assert "Repeated attempts: branch x2" in markdown
    assert "Failed step: 2:branch penalty=20" in markdown


def test_model_risk_card_escapes_hostile_markdown_fields(tmp_path: Path) -> None:
    hostile = _hostile_text()
    report = RunReport(
        run_id="risk|run\n# injected",
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
        target_name="target|name",
        target_adapter="openai_compatible",
        target_model="model`x`<script>alert(1)</script>",
        input_path="input.yaml",
        scoring_path="scoring.yaml",
        datasets=[
            DatasetReport(
                dataset_name="d",
                category="policy_robustness",
                subcategory="hostile",
                case_results=[
                    CaseResult(
                        dataset_name="d",
                        case_id="case|`x`",
                        severity="critical",
                        objective=hostile,
                        prompt="prompt",
                        response_text="response",
                        passed=False,
                        score=0,
                        penalty=100,
                        failure_checks=[],
                        pass_checks=[],
                    )
                ],
                summary=DatasetSummary(total_items=1, passed_items=0, failed_items=1, score_total=0, max_score_total=100),
            )
        ],
        summary=RunSummary(total_items=1, passed_items=0, failed_items=1, score_total=0, max_score_total=100),
    )
    (tmp_path / "risk-summary.json").write_text(json.dumps({"status": "fail", "reasons": [hostile]}), encoding="utf-8")

    path = write_model_risk_card(report, tmp_path)
    markdown = path.read_text(encoding="utf-8")

    assert "model\\`x\\`&lt;script>alert(1)&lt;/script>" in markdown
    assert "case\\|\\`x\\`" in markdown
    assert "<script>" not in markdown
    assert "SYNTHETIC-SK-OPENAI-SECRET" not in markdown
    assert "[REDACTED]" in markdown


def test_model_risk_card_escapes_optional_summaries(tmp_path: Path) -> None:
    hostile = _hostile_text()
    report = RunReport(
        run_id="run-risk-summary",
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
        target_name="target",
        target_adapter="openai_compatible",
        target_model="model-a",
        input_path="input.yaml",
        scoring_path="scoring.yaml",
        datasets=[],
        summary=RunSummary(total_items=0, passed_items=0, failed_items=0, score_total=0, max_score_total=0),
    )

    path = write_model_risk_card(report, tmp_path, regression_summary=hostile, agent_summary=hostile)
    markdown = path.read_text(encoding="utf-8")

    assert "&lt;script>alert" in markdown
    assert "<script>" not in markdown
    assert "SYNTHETIC-SK-OPENAI-SECRET" not in markdown
    assert "[REDACTED]" in markdown
    assert r"\#\# injected heading \| table pipe" in markdown


def test_model_risk_card_aggregates_agent_report_details(tmp_path: Path) -> None:
    report = RunReport(
        run_id="run-agent-risk",
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
        target_name="target",
        target_adapter="openai_compatible",
        target_model="model-a",
        input_path="input.yaml",
        scoring_path="scoring.yaml",
        datasets=[],
        summary=RunSummary(total_items=0, passed_items=0, failed_items=0, score_total=0, max_score_total=0),
    )
    (tmp_path / "agent-lab-report.json").write_text(
        json.dumps(
            {
                "summary": {"total_scenarios": 1, "violations": 1, "highest_risk": "critical"},
                "results": [
                    {
                        "scenario_id": "approval-vcs",
                        "trace": {
                            "approval_state": {"required": True, "granted": False, "source": "trusted_harness"},
                            "observed_tool_decisions": [
                                {"tool": "mock_vcs_workflow", "args": {"push": True}, "allowed_by_policy": False, "reason": "vcs_push_without_review"}
                            ],
                            "memory_writes": ["synthetic-memory-marker"],
                            "session_writes": [],
                            "canary_violations": ["canary_leak:session"],
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    path = write_model_risk_card(report, tmp_path, agent_summary="Agent lab supplied")
    markdown = path.read_text(encoding="utf-8")

    assert "Agent lab supplied" in markdown
    assert "Agent report: scenarios=1, violations=1, highest_risk=critical" in markdown
    assert "Approval timeline: approval-vcs required=True granted=False source=trusted_harness" in markdown
    assert "Tool audit: approval-vcs tool=mock_vcs_workflow allowed=False reason=vcs_push_without_review" in markdown
    assert "Memory/canary ledger: approval-vcs writes=1 violations=canary_leak:session" in markdown
