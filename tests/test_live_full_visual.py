from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from malleus.live_full import run_live_full_matrix
from malleus.live_preflight import LivePreflightReport, SafeTargetEndpoint
from malleus.utils.redact import scan_public_artifact_text
from malleus.visual_live import VisualLiveImageSummary, VisualLivePromptSummary, VisualLiveReport, VisualLiveResult, VisualLiveSummary, write_visual_live_artifacts


def test_live_full_converts_visual_live_report_to_multimodal_row(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    matrix = _matrix(tmp_path)
    profile = _profile(tmp_path)
    visual_payloads: list[dict] = []

    class FakeVisualClient:
        def __init__(self, *args, **kwargs):
            pass

        def post(self, url: str, *, json: dict, timeout: float):
            visual_payloads.append(json)
            return httpx.Response(200, json={"choices": [{"message": {"content": "Safe image description."}}]})

        def request(self, method: str, url: str, *, json=None, timeout: float):
            return httpx.Response(200, json={"status": "ok"})

        def close(self) -> None:
            pass

    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(visual_status="passed"))
    monkeypatch.setattr("malleus.visual_live.httpx.Client", FakeVisualClient)

    evidence, _, _ = run_live_full_matrix(target_path=target, matrix_path=matrix, mutation_profile_path=profile, out_dir=tmp_path / "out", dry_run=False, yes=True)

    row = {row.row_id: row for row in evidence.rows}["pack:visual-ocr-matrix"]
    assert row.status == "passed"
    assert row.evidence_level == "live_multimodal_model"
    assert row.live_model_calls == 1
    aggregate = json.loads((tmp_path / "out" / "FULL_BENCHMARK_MATRIX.json").read_text(encoding="utf-8"))
    aggregate_row = next(row for row in aggregate["rows"] if row["row_id"] == "pack:visual-ocr-matrix")
    assert aggregate_row["evidence_type"] == "multimodal_model_evidence"
    assert aggregate_row["live_evidence_category"] == "multimodal_model_evidence"
    assert aggregate_row["evidence_type"] != "chat_model_evidence"
    assert row.metadata["adapter_call_count"] == 1
    assert row.metadata["static_visual_lab_counted_as_live"] is False
    assert row.metadata["browser_automation"] is False
    assert {artifact.relative_path for artifact in row.artifacts} == {"visual-live-report.json", "visual-live-report.md"}
    assert len(visual_payloads) == 1
    content = visual_payloads[0]["messages"][0]["content"]
    assert content[0]["type"] == "text"
    assert "TRUSTED TASK" in content[0]["text"]
    assert content[1]["type"] == "image_url"
    assert content[1]["image_url"]["url"].startswith("data:image/png;base64,")
    report_path = tmp_path / "out" / "visual" / "visual-ocr-matrix" / "visual-live-report.json"
    combined = (tmp_path / "out" / "live-full-evidence.json").read_text(encoding="utf-8") + report_path.read_text(encoding="utf-8")
    assert scan_public_artifact_text(combined).passed


def test_live_full_visual_unsupported_is_provider_capability_gap_without_runner(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    matrix = _matrix(tmp_path)
    profile = _profile(tmp_path)
    called = False

    def unexpected_visual_live(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("visual runner should not run when image preflight is unsupported")

    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(visual_status="not_supported"))
    monkeypatch.setattr("malleus.live_full.run_visual_live", unexpected_visual_live)

    evidence, _, _ = run_live_full_matrix(target_path=target, matrix_path=matrix, mutation_profile_path=profile, out_dir=tmp_path / "out", dry_run=False, yes=True)

    row = {row.row_id: row for row in evidence.rows}["pack:visual-ocr-matrix"]
    assert row.status == "provider_capability_gap"
    assert row.evidence_level == "scaffold_static"
    assert row.live_model_calls == 0
    assert called is False


def test_live_full_visual_provider_capability_gap_status_is_not_provider_error(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    matrix = _matrix(tmp_path)
    profile = _profile(tmp_path)

    def unexpected_visual_live(*args, **kwargs):
        raise AssertionError("visual runner should not run when image preflight is a capability gap")

    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(visual_status="provider_capability_gap"))
    monkeypatch.setattr("malleus.live_full.run_visual_live", unexpected_visual_live)

    evidence, _, _ = run_live_full_matrix(target_path=target, matrix_path=matrix, mutation_profile_path=profile, out_dir=tmp_path / "out", dry_run=False, yes=True)

    row = {row.row_id: row for row in evidence.rows}["pack:visual-ocr-matrix"]
    assert row.status == "provider_capability_gap"
    assert row.evidence_level == "scaffold_static"
    assert row.live_model_calls == 0


def test_live_full_vision_model_target_uses_provider_preflight(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path, target_type="vision_model")
    matrix = _matrix(tmp_path)
    profile = _profile(tmp_path)
    captured: dict[str, object] = {}

    def fake_preflight(target, **kwargs):
        captured["target_type"] = target.target_type
        captured["include_image_probe"] = kwargs["include_image_probe"]
        return _preflight(visual_status="not_supported")

    monkeypatch.setattr("malleus.live_full.run_target_preflight", fake_preflight)

    evidence, _, _ = run_live_full_matrix(target_path=target, matrix_path=matrix, mutation_profile_path=profile, out_dir=tmp_path / "out", dry_run=False, yes=True)

    row = {row.row_id: row for row in evidence.rows}["pack:visual-ocr-matrix"]
    assert captured == {"target_type": "vision_model", "include_image_probe": True}
    assert row.status == "provider_capability_gap"


def test_live_full_visual_provider_error_is_visual_only_row(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    matrix = _matrix(tmp_path)
    profile = _profile(tmp_path)

    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(visual_status="provider_error"))

    evidence, _, _ = run_live_full_matrix(target_path=target, matrix_path=matrix, mutation_profile_path=profile, out_dir=tmp_path / "out", dry_run=False, yes=True)

    row = {row.row_id: row for row in evidence.rows}["pack:visual-ocr-matrix"]
    assert row.status == "provider_error"
    assert row.evidence_level == "live_multimodal_model"
    assert row.live_model_calls == 0
    assert "visual preflight blocked" in (row.reason or "")


def test_live_full_rejects_visual_scaffold_outputs_as_live_evidence(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    matrix = _matrix(tmp_path)
    profile = _profile(tmp_path)

    def scaffold_masquerade(target_path: Path, output_dir: Path):
        report = _visual_report(provider_error=False)
        write_visual_live_artifacts(report, output_dir)
        (Path(output_dir) / "visual-run-report.json").write_text('{"provider_calls_enabled": false}', encoding="utf-8")
        return report

    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(visual_status="passed"))
    monkeypatch.setattr("malleus.live_full.run_visual_live", scaffold_masquerade)

    with pytest.raises(ValueError, match="dry-run/non-live artifacts"):
        run_live_full_matrix(target_path=target, matrix_path=matrix, mutation_profile_path=profile, out_dir=tmp_path / "out", dry_run=False, yes=True)

    skeleton = json.loads((tmp_path / "out" / "live-full-evidence.json").read_text(encoding="utf-8"))
    row = next(row for row in skeleton["rows"] if row["row_id"] == "pack:visual-ocr-matrix")
    assert row["status"] == "infra_error"
    assert row["metadata"]["invalid_live_artifact"] is True
    assert row["metadata"]["visual_run_report_json_exists"] is True


def _target(tmp_path: Path, *, target_type: str | None = None) -> Path:
    target = tmp_path / "target.yaml"
    target_type_line = f"target_type: {target_type}\n" if target_type else ""
    target.write_text(f"name: visual-target\n{target_type_line}adapter: openai_compatible\nmodel: fake-vision\nbase_url: https://example.test/v1\napi_key_env: MISSING_VISUAL_FULL_KEY\n", encoding="utf-8")
    return target


def _matrix(tmp_path: Path) -> Path:
    matrix = tmp_path / "matrix.yaml"
    matrix.write_text(
        """schema_version: malleus.release_matrix.v1
id: test-visual-matrix
version: 1.0.0
mode_boundaries:
  - mode: live_provider
    evidence_level: live_model_required
    provider_calls_enabled: true
packs:
  - id: visual-ocr-matrix
    path: src/malleus/visual_lab.py
    evidence_level: live_model_required
    status: available
    live_model_evidence: true
    scaffold_only: false
    target_types: [vision_model]
    live_evidence_category: multimodal_model_evidence
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


def _preflight(*, visual_status: str) -> LivePreflightReport:
    return LivePreflightReport(
        target_name="visual-target",
        adapter="openai_compatible",
        model="fake-vision",
        endpoint=SafeTargetEndpoint(scheme="https", host="example.test", path_hint="/v1"),
        text_status="passed",
        text_ready=True,
        visual_status=visual_status,
        ok=visual_status in {"passed", "not_supported"},
        probes=[],
    )


def _visual_report(*, provider_error: bool) -> VisualLiveReport:
    result = VisualLiveResult(
        case_id="synthetic-minimal-image",
        status="provider_error" if provider_error else "passed",
        reason_codes=["provider_error"] if provider_error else [],
        prompt_sha256="a" * 64,
        image_sha256="b" * 64,
        response_sha256=None if provider_error else "c" * 64,
        response_length=0 if provider_error else 22,
        response_excerpt=None if provider_error else "Safe image description.",
        error_type="ProviderError" if provider_error else None,
        evidence_ref="visual-live-report.json#/results/0",
        post_image_health_status="passed",
        coverage_tags=["visual", "visual_live"],
    )
    summary = VisualLiveSummary(
        total_cases=1,
        passed=0 if provider_error else 1,
        provider_error=1 if provider_error else 0,
        live_model_calls=0 if provider_error else 1,
        attempted_provider_calls=1,
        status_counts={"passed": 0 if provider_error else 1, "provider_error": 1 if provider_error else 0},
        reason_codes=["provider_error"] if provider_error else [],
    )
    return VisualLiveReport(
        run_id="run-visual-test",
        started_at="2026-04-27T00:00:00+00:00",
        finished_at="2026-04-27T00:00:01+00:00",
        target_name="visual-target",
        target_adapter="openai_compatible",
        target_model="fake-vision",
        target_base_url="https://example.test",
        live_model_calls=summary.live_model_calls,
        attempted_provider_calls=1,
        max_visual_calls=1,
        prompt=VisualLivePromptSummary(sha256="a" * 64, length=32, redacted_excerpt="[REDACTED_VISUAL_LIVE_TEXT] prompt"),
        image=VisualLiveImageSummary(sha256="b" * 64, length=68, redacted_preview="[REDACTED_VISUAL_LIVE_TEXT] image"),
        results=[result],
        summary=summary,
        metadata={"static_visual_lab_counted_as_live": False, "browser_automation": False},
    )
