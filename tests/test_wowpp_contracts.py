from __future__ import annotations

import json
from typing import get_args

import pytest

from malleus.benchmark_workflow import summarize_benchmark_reports
from malleus.schemas import (
    EvidenceRecord,
    EvidenceRef,
    EvaluationSurface,
    KNOWN_REPORT_MODES,
    REPORT_MODE_DRY_RUN,
    REPORT_MODE_LIVE_PROVIDER,
    REPORT_MODE_LOCAL_FIXTURE,
    REPORT_MODE_SCAFFOLD,
    REPORT_MODE_SIMULATED,
    RedactionMetadata,
    ReportMode,
    WowppReportMetadata,
)
from malleus.utils.redact import redact_public_text, scan_public_artifact_text


def test_legacy_benchmark_report_fixture_still_loads_through_existing_summary_path(tmp_path) -> None:
    summary, json_path, markdown_path = summarize_benchmark_reports("tests/fixtures/benchmark_reports", tmp_path / "summary")

    assert json_path.exists()
    assert markdown_path.exists()
    assert any(row.model == "fixture/model-a" for row in summary.leaderboard)
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["leaderboard"][0]["model"] == "fixture/model-a"


def test_wowpp_contract_json_contains_mode_hash_and_redaction_metadata() -> None:
    raw = "token=WOWPPSECRET"
    redacted = redact_public_text(raw)
    record = EvidenceRecord(
        evidence_id="ev-wowpp-1",
        mode=REPORT_MODE_LOCAL_FIXTURE,
        surface=EvaluationSurface(surface_id="surface-report", name="Report JSON", category="artifact", modality="json"),
        artifact=EvidenceRef(
            evidence_id="artifact-report",
            artifact_path="report.json",
            artifact_type="run_report_json",
            sha256=redacted.sha256,
            redacted_preview=redacted.text,
        ),
        artifact_sha256=redacted.sha256,
        artifact_length=redacted.length,
        redacted_preview=redacted.text,
        redaction=RedactionMetadata(
            status="redacted",
            sha256=redacted.sha256,
            length=redacted.length,
            marker="[REDACTED]",
            matched_labels=redacted.matched_labels,
        ),
    )
    metadata = WowppReportMetadata(
        mode=REPORT_MODE_DRY_RUN,
        provider_calls_enabled=False,
        evaluation_surfaces=[record.surface],
        evidence_records=[record],
        artifact_hashes={"report.json": redacted.sha256},
    )

    data = json.loads(metadata.model_dump_json())
    serialized = json.dumps(data)

    assert data["schema_version"] == "malleus.wowpp.contracts.v1"
    assert data["mode"] == "dry_run"
    assert data["evidence_records"][0]["mode"] == "local_fixture"
    assert data["artifact_hashes"]["report.json"] == redacted.sha256
    assert data["evidence_records"][0]["redaction"]["marker"] == "[REDACTED]"
    assert data["evidence_records"][0]["redaction"]["sha256"] == redacted.sha256
    assert raw not in serialized
    assert "WOWPPSECRET" not in serialized


def test_report_modes_include_required_labels_and_allow_future_values() -> None:
    expected_modes = {
        REPORT_MODE_LOCAL_FIXTURE,
        REPORT_MODE_SIMULATED,
        REPORT_MODE_DRY_RUN,
        REPORT_MODE_SCAFFOLD,
        REPORT_MODE_LIVE_PROVIDER,
    }

    assert expected_modes <= KNOWN_REPORT_MODES
    assert expected_modes == set(get_args(ReportMode))

    future = WowppReportMetadata.model_validate({"mode": "future_mode", "metadata": {"kept": True}})

    assert future.mode == "future_mode"
    assert future.metadata["kept"] is True


def test_public_redaction_scan_blocks_real_looking_secret_and_raw_canaries() -> None:
    raw = "token=WOWPPSECRET"
    redacted = redact_public_text(raw).text

    assert raw not in redacted
    assert "WOWPPSECRET" not in redacted
    assert "[REDACTED]" in redacted
    assert "sha256=" in redacted
    assert "length=" in redacted
    assert scan_public_artifact_text(redacted, require_redaction_markers=True).passed

    wowpp_secret = scan_public_artifact_text("WOWPPSECRET")
    malleus_canary = scan_public_artifact_text("MALLEUS-CANARY-PUBLIC-001")
    real_secret = scan_public_artifact_text("credential SYNTHETIC-SK-OPENAI-SECRET should not ship")

    assert not wowpp_secret.passed
    assert "raw_synthetic_canary" in wowpp_secret.findings
    assert not malleus_canary.passed
    assert "raw_synthetic_canary" in malleus_canary.findings
    assert not real_secret.passed
    assert "raw_synthetic_canary" in real_secret.findings


def test_public_redaction_masks_schema_secret_like_canary_fragments() -> None:
    raw = "Retrieved placeholder RAG-CANARY-PLACEHOLDER should stay opaque."
    redacted = redact_public_text(raw).text

    assert "CANARY-PLACEHOLDER" not in redacted
    assert "[REDACTED]" in redacted
    assert scan_public_artifact_text(redacted, require_redaction_markers=True).passed


def test_public_redaction_scan_allows_redacted_synthetic_canary_artifact() -> None:
    artifact = "MALLEUS-CANARY-PUBLIC-001 [REDACTED] canary sha256=abc123 length=25"

    result = scan_public_artifact_text(artifact, require_redaction_markers=True)

    assert result.passed


def test_public_redaction_scan_does_not_treat_escaped_regex_boundaries_as_unc_paths() -> None:
    regex_excerpt = r"regex matched: (?i)\\b(execute|run)\\b.{0,40}\\b(delete|tool)\\b"
    unc_path = "artifact came from \\\\fileserver\\share\\private.txt"

    assert scan_public_artifact_text(regex_excerpt).passed
    assert not scan_public_artifact_text(unc_path).passed


def test_evidence_contract_rejects_raw_payload_fields() -> None:
    with pytest.raises(ValueError, match="raw evidence fields"):
        EvidenceRecord.model_validate({"evidence_id": "bad", "raw_payload": "do not serialize"})
