from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from malleus.adjudication import adjudicate_finding, finding_hash, load_adjudications_for_report
from malleus.cli import app
from malleus.findings import FindingEvidenceRef, FindingsBundle, FindingsSummary, ReplaySpec, SecurityFinding, write_finding_artifacts


def _finding() -> SecurityFinding:
    return SecurityFinding(
        finding_id="mf-adj-test",
        title="High test finding",
        source_type="run_report",
        affected_model={"name": "target", "adapter": "openai_compatible", "model": "model-a", "config": "target"},
        severity="high",
        attack_surface="prompt",
        technique="role_bypass",
        violated_boundary="instruction_boundary",
        taxonomy_refs=["instruction-boundary"],
        reproduction_command="malleus run --dry-run",
        evidence_refs=[FindingEvidenceRef(evidence_id="e1", artifact_path="report.json", artifact_type="run_report_json", sha256="1" * 64, redacted_excerpt="safe excerpt")],
        redacted_excerpts=["safe excerpt"],
        patch_recommendation="Harden the boundary.",
        regression_case_link="dataset:case-1",
        replay_spec=ReplaySpec(replay_id="replay-mf-adj-test", finding_id="mf-adj-test", command="malleus run --dry-run", target_name="target"),
        metadata={"score": 25, "penalty": 75},
    )


def _write_findings(tmp_path: Path) -> tuple[Path, str]:
    finding = _finding()
    bundle = FindingsBundle(
        generated_at="2026-04-24T00:00:00+00:00",
        source_report="report.json",
        run_id="run-1",
        findings=[finding],
        summary=FindingsSummary(total_findings=1, counts_by_severity={"high": 1}, counts_by_source={"run_report": 1}, highest_severity="high"),
    )
    json_path, _ = write_finding_artifacts(bundle, tmp_path / "report")
    return json_path, finding_hash(finding)


def test_adjudication_appends_records_and_preserves_original_findings(tmp_path: Path) -> None:
    findings, original_hash = _write_findings(tmp_path)
    before = findings.read_text(encoding="utf-8")

    first, _, _ = adjudicate_finding(
        "mf-adj-test",
        findings,
        status="false_positive",
        reviewer="analyst@example.test",
        reason_code="fixture_mismatch",
        note="Safe false-positive fixture note.",
        timestamp="2026-04-24T00:00:01+00:00",
    )
    second, json_path, markdown_path = adjudicate_finding(
        "mf-adj-test",
        findings,
        status="fixed",
        reviewer="analyst@example.test",
        reason_code="regression_added",
        note="Regression added and verified.",
        timestamp="2026-04-24T00:00:02+00:00",
    )

    assert findings.read_text(encoding="utf-8") == before
    assert first.summary.false_positive_findings == 1
    assert second.summary.total_records == 2
    assert second.summary.latest_status_by_finding["mf-adj-test"] == "fixed"
    assert second.records[0].finding_hash == original_hash
    assert second.records[0].original_severity == "high"
    assert second.records[0].original_score == 25
    assert json_path.name == "adjudications.json"
    assert markdown_path.name == "adjudications.md"
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert len(payload["records"]) == 2
    assert "Adjudications are append-only" in markdown_path.read_text(encoding="utf-8")


def test_adjudication_cli_rejects_unknown_finding(tmp_path: Path) -> None:
    findings, _ = _write_findings(tmp_path)
    result = CliRunner().invoke(
        app,
        [
            "adjudicate",
            "--finding",
            "missing",
            "--report",
            str(findings),
            "--status",
            "confirmed",
            "--reviewer",
            "analyst",
            "--reason-code",
            "reviewed",
        ],
    )

    assert result.exit_code == 1
    assert "finding not found: missing" in result.output


def test_accepted_risk_waiver_expiration_reopens_finding(tmp_path: Path) -> None:
    findings, _ = _write_findings(tmp_path)
    bundle, json_path, markdown_path = adjudicate_finding(
        "mf-adj-test",
        findings,
        status="accepted_risk",
        reviewer="analyst",
        reason_code="temporary_exception",
        note="Temporary waiver.",
        expires_at="2020-01-01T00:00:00+00:00",
    )

    assert bundle.summary.accepted_risk_findings == 1
    assert bundle.summary.expired_accepted_risk_findings == 1
    assert bundle.summary.open_findings == 1
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["records"][0]["expires_at"] == "2020-01-01T00:00:00+00:00"
    assert "Expired accepted risk: 1" in markdown_path.read_text(encoding="utf-8")


def test_review_cli_alias_writes_append_only_artifact(tmp_path: Path) -> None:
    findings, _ = _write_findings(tmp_path)
    result = CliRunner().invoke(
        app,
        [
            "review",
            "--finding",
            "mf-adj-test",
            "--report",
            str(findings),
            "--status",
            "needs_review",
            "--reviewer",
            "analyst",
            "--reason-code",
            "triage",
            "--note",
            "Needs second reviewer.",
        ],
    )

    assert result.exit_code == 0
    bundle = load_adjudications_for_report(findings)
    assert bundle is not None
    assert bundle.summary.total_records == 1
    assert bundle.records[0].status == "needs_review"


def test_adjudication_redacts_secret_like_reviewer_controlled_fields(tmp_path: Path) -> None:
    findings, _ = _write_findings(tmp_path)
    result = CliRunner().invoke(
        app,
        [
            "adjudicate",
            "--finding",
            "mf-adj-test",
            "--report",
            str(findings),
            "--status",
            "false_positive",
            "--reviewer",
            "analyst token=REVIEWER_SECRET",
            "--reason-code",
            "reason secret=REASON_SECRET",
            "--note",
            "review note token=ADJUDICATION_SECRET should redact",
        ],
    )

    assert result.exit_code == 0
    json_text = (findings.parent / "adjudications.json").read_text(encoding="utf-8")
    markdown_text = (findings.parent / "adjudications.md").read_text(encoding="utf-8")
    combined = json_text + markdown_text
    assert "ADJUDICATION_SECRET" not in combined
    assert "token=ADJUDICATION_SECRET" not in combined
    assert "REVIEWER_SECRET" not in combined
    assert "REASON_SECRET" not in combined
    assert "[REDACTED sensitive sha256=" in combined
    payload = json.loads(json_text)
    record = payload["records"][0]
    assert record["reviewer"].startswith("analyst [REDACTED sensitive")
    assert record["reason_code"].startswith("reason [REDACTED sensitive")
    assert record["note"].startswith("review note [REDACTED sensitive")
