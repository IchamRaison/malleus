from __future__ import annotations

import json
from pathlib import Path

import pytest

from malleus.live_full import run_live_full_matrix
from malleus.live_preflight import LivePreflightReport, SafeTargetEndpoint
from malleus.runner import run_benchmark as real_run_benchmark
from malleus.utils.redact import scan_public_artifact_text


def test_live_full_runs_classic_smoke_and_core_with_fake_adapter(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    smoke = _dataset(tmp_path, "smoke-pack", ["s1", "s2"])
    core = _dataset(tmp_path, "core-pack", ["c1", "c2", "c3"])
    matrix = _matrix(tmp_path, smoke, core)
    profile = _profile(tmp_path)
    calls: list[str] = []

    class FakeAdapter:
        def __init__(self, target):
            self.target = target

        def generate(self, prompt: str) -> str:
            calls.append(prompt)
            return "I cannot help with that request."

        def close(self) -> None:
            pass

    monkeypatch.setitem(__import__("malleus.runner").runner.ADAPTERS, "openai_compatible", FakeAdapter)
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True))

    evidence, _, _ = run_live_full_matrix(target_path=target, matrix_path=matrix, mutation_profile_path=profile, out_dir=tmp_path / "out", dry_run=False, yes=True)

    rows = {row.row_id: row for row in evidence.rows}
    smoke_row = rows["pack:smoke-v1"]
    core_row = rows["pack:core-v1"]
    assert smoke_row.evidence_level == "live_text_model"
    assert core_row.evidence_level == "live_text_model"
    assert smoke_row.dry_run is False
    assert core_row.provider_calls_enabled is True
    assert smoke_row.live_model_calls == 2
    assert core_row.live_model_calls == 3
    assert rows["mutation-profile:selected-v1"].live_model_calls == 4
    assert len(calls) == smoke_row.live_model_calls + core_row.live_model_calls + rows["mutation-profile:selected-v1"].live_model_calls
    assert smoke_row.metadata["adapter_call_count"] == 2
    assert core_row.metadata["adapter_call_count"] == 3
    assert smoke_row.metadata["status_counts"] == {"passed": 2, "failed": 0, "total": 2}
    assert core_row.metadata["status_counts"] == {"passed": 3, "failed": 0, "total": 3}
    assert {artifact.relative_path for artifact in smoke_row.artifacts} >= {"report.json", "report.md", "report.html"}
    assert {artifact.relative_path for artifact in core_row.artifacts} >= {"report.json", "report.md", "report.html"}
    assert (tmp_path / "out" / "classic" / "smoke-v1" / "report.json").exists()
    assert (tmp_path / "out" / "classic" / "core-v1" / "report.json").exists()
    assert not (tmp_path / "out" / "classic" / "smoke-v1" / "dry-run.json").exists()


def test_live_full_rejects_classic_dry_run_artifact(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    smoke = _dataset(tmp_path, "smoke-pack", ["s1"])
    core = _dataset(tmp_path, "core-pack", ["c1"])
    matrix = _matrix(tmp_path, smoke, core)
    profile = _profile(tmp_path)

    def fake_dry_run(target_path, input_path, scoring_path, output_dir, **kwargs):
        return real_run_benchmark(target_path, input_path, scoring_path, output_dir, dry_run=True)

    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True))
    monkeypatch.setattr("malleus.live_full.run_benchmark", fake_dry_run)

    out = tmp_path / "out"
    with pytest.raises(ValueError, match="dry-run/non-live artifacts"):
        run_live_full_matrix(target_path=target, matrix_path=matrix, mutation_profile_path=profile, out_dir=out, dry_run=False, yes=True)

    payload = json.loads((out / "live-full-evidence.json").read_text(encoding="utf-8"))
    rows = {row["row_id"]: row for row in payload["rows"]}
    assert rows["pack:smoke-v1"]["status"] == "infra_error"
    assert rows["pack:core-v1"]["status"] == "infra_error"
    assert rows["pack:smoke-v1"]["live_model_calls"] == 0
    assert rows["pack:smoke-v1"]["metadata"]["invalid_live_artifact"] is True
    assert rows["pack:smoke-v1"]["reason"]
    assert (out / "classic" / "smoke-v1" / "dry-run.json").exists()
    assert not (out / "classic" / "smoke-v1" / "report.json").exists()


def test_live_full_keeps_classic_rows_preflight_failed_without_calls(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    matrix = _matrix(tmp_path, _dataset(tmp_path, "smoke-pack", ["s1"]), _dataset(tmp_path, "core-pack", ["c1"]))
    profile = _profile(tmp_path)

    class ExplodingAdapter:
        def __init__(self, target):
            raise AssertionError("preflight failure must not instantiate adapters")

    monkeypatch.setitem(__import__("malleus.runner").runner.ADAPTERS, "openai_compatible", ExplodingAdapter)
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=False))

    evidence, _, _ = run_live_full_matrix(target_path=target, matrix_path=matrix, mutation_profile_path=profile, out_dir=tmp_path / "out", dry_run=False, yes=True)

    rows = {row.row_id: row for row in evidence.rows}
    assert rows["pack:smoke-v1"].status == "target_error"
    assert rows["pack:core-v1"].status == "target_error"
    assert rows["pack:smoke-v1"].live_model_calls == 0
    assert not (tmp_path / "out" / "classic").exists()


def test_live_full_redacts_classic_pack_paths_and_operational_errors(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    smoke = _dataset(tmp_path, "smoke-pack", ["s1"])
    core = _dataset(tmp_path, "core-pack", ["c1"])
    raw_private_path = "/home/alice/private/token=supersecret123/core-pack.yaml"
    matrix = _matrix(tmp_path, smoke, core, core_path=raw_private_path)
    profile = _profile(tmp_path)

    def fake_provider_error(target_path, input_path, scoring_path, output_dir, **kwargs):
        raise RuntimeError(f"provider failed while reading {raw_private_path} with token=supersecret123")

    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True))
    monkeypatch.setattr("malleus.live_full.run_benchmark", fake_provider_error)

    out = tmp_path / "out"
    evidence, _, _ = run_live_full_matrix(target_path=target, matrix_path=matrix, mutation_profile_path=profile, out_dir=out, dry_run=False, yes=True)

    rows = {row.row_id: row for row in evidence.rows}
    assert rows["pack:core-v1"].status == "provider_error"
    combined = (out / "live-full-evidence.json").read_text(encoding="utf-8") + (out / "live-full-evidence.md").read_text(encoding="utf-8")
    assert raw_private_path not in combined
    assert "/home/alice" not in combined
    assert "token=supersecret123" not in combined
    assert scan_public_artifact_text(combined).passed


def test_live_full_redacts_release_matrix_mutation_profile_ref_paths(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    smoke = _dataset(tmp_path, "smoke-pack", ["s1"])
    core = _dataset(tmp_path, "core-pack", ["c1"])
    selected_raw_path = "/home/alice/private/token=supersecret123/selected.yaml"
    deep_raw_path = "/home/alice/private/token=supersecret123/deep.yaml"
    matrix = _matrix(tmp_path, smoke, core, selected_path=selected_raw_path, deep_path=deep_raw_path)
    selected_profile = _profile(tmp_path)
    deep_profile = _deep_profile(tmp_path)

    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=False))

    out = tmp_path / "out"
    evidence, _, _ = run_live_full_matrix(
        target_path=target,
        matrix_path=matrix,
        mutation_profile_path=selected_profile,
        deep_mutation_profile_path=deep_profile,
        include_deep_mutations=True,
        out_dir=out,
        dry_run=False,
        yes=True,
    )

    rows = {row.row_id: row for row in evidence.rows}
    assert rows["mutation-profile:selected-v1"].metadata["path"] != selected_raw_path
    assert rows["mutation-profile:deep-v1"].metadata["path"] != deep_raw_path
    combined = (out / "live-full-evidence.json").read_text(encoding="utf-8") + (out / "live-full-evidence.md").read_text(encoding="utf-8")
    assert selected_raw_path not in combined
    assert deep_raw_path not in combined
    assert "/home/alice" not in combined
    assert "token=supersecret123" not in combined
    assert scan_public_artifact_text(combined).passed


def _target(tmp_path: Path) -> Path:
    target = tmp_path / "target.yaml"
    target.write_text("name: t\nadapter: openai_compatible\nmodel: m\nbase_url: https://example.test/v1\napi_key_env: MISSING_LIVE_FULL_KEY\n", encoding="utf-8")
    return target


def _dataset(tmp_path: Path, name: str, case_ids: list[str]) -> Path:
    dataset = tmp_path / f"{name}.yaml"
    cases = "".join(
        f"  - id: {case_id}\n    severity: low\n    objective: refuse unsafe request\n    prompt: unsafe request {case_id}\n    pass_signals:\n      - type: refusal_marker\n"
        for case_id in case_ids
    )
    dataset.write_text(f"name: {name}\nversion: 1\ncategory: c\nsubcategory: s\ncases:\n{cases}", encoding="utf-8")
    return dataset


def _matrix(
    tmp_path: Path,
    smoke: Path,
    core: Path,
    *,
    smoke_path: str | Path | None = None,
    core_path: str | Path | None = None,
    selected_path: str | Path | None = None,
    deep_path: str | Path | None = None,
) -> Path:
    matrix = tmp_path / "matrix.yaml"
    smoke_ref = smoke_path if smoke_path is not None else smoke
    core_ref = core_path if core_path is not None else core
    selected_ref = selected_path if selected_path is not None else _profile(tmp_path)
    deep_section = "deep_mutation_profiles: []"
    if deep_path is not None:
        deep_section = f"""deep_mutation_profiles:
  - id: deep-v1
    path: {deep_path}
    status: available_optional
    default: false
    optional: true
    mutation_count: 1
    evidence_level: optional_deep_test"""
    matrix.write_text(
        f"""schema_version: malleus.release_matrix.v1
id: test-matrix
version: 1.0.0
mode_boundaries:
  - mode: live_provider
    evidence_level: live_model_required
    provider_calls_enabled: true
packs:
  - id: smoke-v1
    path: {smoke_ref}
    evidence_level: live_model_required
    status: available
    live_model_evidence: true
    scaffold_only: false
  - id: core-v1
    path: {core_ref}
    evidence_level: live_model_required
    status: available
    live_model_evidence: true
    scaffold_only: false
selected_mutation_profiles:
  - id: selected-v1
    path: {selected_ref}
    status: available
    default: true
    mutation_count: 0
    evidence_level: live_model_required
{deep_section}
gates: []
""",
        encoding="utf-8",
    )
    return matrix


def _profile(tmp_path: Path) -> Path:
    profile = tmp_path / "selected.yaml"
    if not profile.exists():
        profile.write_text("schema_version: malleus.mutation_profile.v1\nid: selected-v1\nname: Selected\nversion: 1.0.0\nmutations:\n  - unicode_wrap\n", encoding="utf-8")
    return profile


def _deep_profile(tmp_path: Path) -> Path:
    profile = tmp_path / "deep.yaml"
    if not profile.exists():
        profile.write_text("schema_version: malleus.mutation_profile.v1\nid: deep-v1\nname: Deep\nversion: 1.0.0\ndeep: true\nmutations:\n  - unicode_wrap\n", encoding="utf-8")
    return profile


def _preflight(*, text_ready: bool) -> LivePreflightReport:
    return LivePreflightReport(
        target_name="t",
        adapter="openai_compatible",
        model="m",
        endpoint=SafeTargetEndpoint(scheme="https", host="example.test", path_hint="/v1"),
        text_status="passed" if text_ready else "preflight_failed",
        text_ready=text_ready,
        visual_status="not_supported",
        ok=text_ready,
        probes=[],
    )
