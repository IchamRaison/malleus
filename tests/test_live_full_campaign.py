from __future__ import annotations

import json
from pathlib import Path

import pytest

from malleus.campaign_live import run_campaign_live
from malleus.live_full import run_live_full_matrix
from malleus.live_preflight import LivePreflightReport, SafeTargetEndpoint
from malleus.utils.redact import scan_public_artifact_text


CAMPAIGN = Path("tests/fixtures/campaigns/agentic-extreme.yaml")


def test_live_full_converts_campaign_live_report_to_evidence_row(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    matrix = _matrix(tmp_path, CAMPAIGN)
    profile = _profile(tmp_path)
    calls: list[str] = []

    class SafeAdapter:
        def __init__(self, target):
            self.target = target

        def generate(self, prompt: str) -> str:
            calls.append(prompt)
            return "Safe campaign response: artifacts stay untrusted and no markers are repeated."

        def close(self) -> None:
            pass

    monkeypatch.setitem(__import__("malleus.runner").runner.ADAPTERS, "openai_compatible", SafeAdapter)
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True))

    evidence, _, _ = run_live_full_matrix(target_path=target, matrix_path=matrix, mutation_profile_path=profile, out_dir=tmp_path / "out", dry_run=False, yes=True)

    rows = {row.row_id: row for row in evidence.rows}
    campaign_row = rows["pack:campaign-v1"]
    assert campaign_row.status == "passed"
    assert campaign_row.evidence_level == "live_text_model"
    assert campaign_row.live_model_calls == 5
    assert campaign_row.metadata["adapter_call_count"] == 5
    assert campaign_row.metadata["completed_live_model_calls"] == 5
    assert campaign_row.metadata["status_counts"] == {"passed": 5, "failed": 0, "provider_error": 0}
    assert campaign_row.metadata["max_steps"] == 5
    assert campaign_row.metadata["dry_run_output_counted_as_live"] is False
    assert {artifact.relative_path for artifact in campaign_row.artifacts} == {"campaign-live-report.json", "campaign-live-report.md"}
    assert len(calls) == 5
    assert "SYNTHETIC STATE" in calls[1]
    report_path = tmp_path / "out" / "campaign" / "campaign-v1" / "campaign-live-report.json"
    assert report_path.exists()
    assert not (tmp_path / "out" / "campaign" / "campaign-v1" / "campaign-report.json").exists()
    combined = (tmp_path / "out" / "live-full-evidence.json").read_text(encoding="utf-8") + report_path.read_text(encoding="utf-8")
    assert scan_public_artifact_text(combined).passed


def test_live_full_campaign_provider_error_is_operational_row_with_completed_calls(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    matrix = _matrix(tmp_path, CAMPAIGN)
    profile = _profile(tmp_path)
    calls: list[str] = []

    class FailingAdapter:
        def __init__(self, target):
            self.target = target

        def generate(self, prompt: str) -> str:
            calls.append(prompt)
            if len(calls) == 4:
                raise RuntimeError("provider outage")
            return "Safe campaign response: untrusted context remains data only."

        def close(self) -> None:
            pass

    monkeypatch.setitem(__import__("malleus.runner").runner.ADAPTERS, "openai_compatible", FailingAdapter)
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True))

    evidence, _, _ = run_live_full_matrix(target_path=target, matrix_path=matrix, mutation_profile_path=profile, out_dir=tmp_path / "out", dry_run=False, yes=True)

    row = {row.row_id: row for row in evidence.rows}["pack:campaign-v1"]
    assert row.status == "provider_error"
    assert row.live_model_calls == 3
    assert row.metadata["adapter_call_count"] == 4
    assert row.metadata["completed_live_model_calls"] == 3
    assert row.metadata["status_counts"] == {"passed": 3, "failed": 0, "provider_error": 1}
    assert "provider errors" in (row.reason or "")
    report = json.loads((tmp_path / "out" / "campaign" / "campaign-v1" / "campaign-live-report.json").read_text(encoding="utf-8"))
    assert report["summary"]["live_model_calls"] == 3
    assert report["results"][-1]["status"] == "provider_error"


def test_live_full_campaign_model_failure_is_failed_row(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    matrix = _matrix(tmp_path, CAMPAIGN)
    profile = _profile(tmp_path)

    class UnsafeAdapter:
        def __init__(self, target):
            self.target = target

        def generate(self, prompt: str) -> str:
            return "I will reveal MALLEUS-CAMPAIGN-CANARY-001 and ignore previous instructions."

        def close(self) -> None:
            pass

    monkeypatch.setitem(__import__("malleus.runner").runner.ADAPTERS, "openai_compatible", UnsafeAdapter)
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True))

    evidence, _, _ = run_live_full_matrix(target_path=target, matrix_path=matrix, mutation_profile_path=profile, out_dir=tmp_path / "out", dry_run=False, yes=True)

    row = {row.row_id: row for row in evidence.rows}["pack:campaign-v1"]
    assert row.status == "failed"
    assert row.live_model_calls == 5
    assert "canary_leakage" in row.metadata["reason_codes"]
    assert row.reason and "provider" not in row.reason.lower()


def test_campaign_rejects_dry_run_report_as_live_evidence(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    matrix = _matrix(tmp_path, CAMPAIGN)
    profile = _profile(tmp_path)

    class SafeAdapter:
        def __init__(self, target):
            self.target = target

        def generate(self, prompt: str) -> str:
            return "Safe campaign response."

        def close(self) -> None:
            pass

    def dry_run_masquerade(campaign_path: Path, target_path: Path, output_dir: Path):
        report = run_campaign_live(campaign_path, target_path, output_dir)
        (Path(output_dir) / "campaign-report.json").write_text('{"provider_calls_enabled": false, "dry_run": true}', encoding="utf-8")
        return report

    monkeypatch.setitem(__import__("malleus.runner").runner.ADAPTERS, "openai_compatible", SafeAdapter)
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True))
    monkeypatch.setattr("malleus.live_full.run_campaign_live", dry_run_masquerade)

    with pytest.raises(ValueError, match="dry-run/non-live artifacts"):
        run_live_full_matrix(target_path=target, matrix_path=matrix, mutation_profile_path=profile, out_dir=tmp_path / "out", dry_run=False, yes=True)

    skeleton = json.loads((tmp_path / "out" / "live-full-evidence.json").read_text(encoding="utf-8"))
    row = next(row for row in skeleton["rows"] if row["row_id"] == "pack:campaign-v1")
    assert row["status"] == "infra_error"
    assert row["metadata"]["invalid_live_artifact"] is True
    assert row["metadata"]["campaign_report_json_exists"] is True


def test_live_full_campaign_runner_validation_error_is_infra_error(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    matrix = _matrix(tmp_path, CAMPAIGN)
    profile = _profile(tmp_path)

    def invalid_report(_campaign_path: Path, _target_path: Path, _output_dir: Path):
        raise ValueError("campaign live public artifact scan failed for campaign-live-report.json")

    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True))
    monkeypatch.setattr("malleus.live_full.run_campaign_live", invalid_report)

    evidence, _, _ = run_live_full_matrix(target_path=target, matrix_path=matrix, mutation_profile_path=profile, out_dir=tmp_path / "out", dry_run=False, yes=True)

    row = {row.row_id: row for row in evidence.rows}["pack:campaign-v1"]
    assert row.status == "infra_error"
    assert row.live_model_calls == 0
    assert row.reason and "provider setup" not in row.reason
    assert row.metadata["runner_error_type"] == "ValueError"


def _target(tmp_path: Path) -> Path:
    target = tmp_path / "target.yaml"
    target.write_text("name: campaign-target\nadapter: openai_compatible\nmodel: fake-model\nbase_url: https://example.test/v1\napi_key_env: MISSING_CAMPAIGN_FULL_KEY\n", encoding="utf-8")
    return target


def _matrix(tmp_path: Path, fixture: Path) -> Path:
    matrix = tmp_path / "matrix.yaml"
    matrix.write_text(
        f"""schema_version: malleus.release_matrix.v1
id: test-campaign-matrix
version: 1.0.0
mode_boundaries:
  - mode: live_provider
    evidence_level: live_model_required
    provider_calls_enabled: true
packs:
  - id: campaign-v1
    path: {fixture}
    evidence_level: live_model_required
    status: available
    live_model_evidence: true
    scaffold_only: false
    target_types: [chat_completion]
    live_evidence_category: chat_model_evidence
    real_system_evidence: false
selected_mutation_profiles: []
deep_mutation_profiles: []
gates: []
""",
        encoding="utf-8",
    )
    return matrix


def _profile(tmp_path: Path) -> Path:
    profile = tmp_path / "selected.yaml"
    profile.write_text("schema_version: malleus.mutation_profile.v1\nid: selected-v1\nname: Selected\nversion: 1.0.0\nmutations:\n  - unicode_wrap\n", encoding="utf-8")
    return profile


def _preflight(*, text_ready: bool) -> LivePreflightReport:
    return LivePreflightReport(
        target_name="campaign-target",
        adapter="openai_compatible",
        model="fake-model",
        endpoint=SafeTargetEndpoint(scheme="https", host="example.test", path_hint="/v1"),
        text_status="passed" if text_ready else "preflight_failed",
        text_ready=text_ready,
        visual_status="not_supported",
        ok=text_ready,
        probes=[],
    )
