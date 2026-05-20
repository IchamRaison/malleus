from __future__ import annotations

import json
from pathlib import Path

import pytest

from malleus.live_full import run_live_full_matrix
from malleus.live_preflight import LivePreflightReport, SafeTargetEndpoint
from malleus.mutate_run import run_mutation_benchmark as real_run_mutation_benchmark
from malleus.utils.redact import scan_public_artifact_text


def test_live_full_runs_selected_v1_mutations_by_default(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    smoke = _dataset(tmp_path, "smoke-pack", ["s1"])
    core = _dataset(tmp_path, "core-pack", ["c1"])
    matrix = _matrix(tmp_path, smoke, core, selected_path="datasets/mutation_profiles/selected-v1.yaml")
    calls: list[str] = []

    class FakeAdapter:
        def __init__(self, target):
            pass

        def generate(self, prompt: str) -> str:
            calls.append(prompt)
            return "I cannot help with that request."

        def close(self) -> None:
            pass

    monkeypatch.setitem(__import__("malleus.runner").runner.ADAPTERS, "openai_compatible", FakeAdapter)
    monkeypatch.setitem(__import__("malleus.mutate_run").mutate_run.ADAPTERS, "openai_compatible", FakeAdapter)
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True))

    evidence, _, _ = run_live_full_matrix(
        target_path=target,
        matrix_path=matrix,
        mutation_profile_path="datasets/mutation_profiles/selected-v1.yaml",
        out_dir=tmp_path / "out",
        dry_run=False,
        yes=True,
    )

    rows = {row.row_id: row for row in evidence.rows}
    selected = rows["mutation-profile:selected-v1"]
    assert selected.status == "passed"
    assert selected.evidence_level == "live_text_model"
    assert selected.metadata["mutation_count"] == 25
    assert selected.metadata["mutated_items"] == 25
    assert selected.live_model_calls == 26
    assert selected.metadata["adapter_call_count"] == 26
    assert selected.metadata["input_pack_id"] == "smoke-v1"
    assert {artifact.relative_path for artifact in selected.artifacts} == {"mutation-report.json", "mutation-report.md"}
    mutation_report = tmp_path / "out" / "mutations" / "selected-v1" / "mutation-report.json"
    assert mutation_report.exists()
    assert not (tmp_path / "out" / "mutations" / "selected-v1" / "mutation-dry-run.json").exists()
    mutation_report_text = mutation_report.read_text(encoding="utf-8")
    assert str(target.resolve()) not in mutation_report_text
    assert str(core.resolve()) not in mutation_report_text
    assert str((Path.cwd() / "configs/scoring-default.yaml").resolve()) not in mutation_report_text
    assert scan_public_artifact_text(mutation_report_text).passed
    assert len(calls) == rows["pack:smoke-v1"].live_model_calls + rows["pack:core-v1"].live_model_calls + selected.live_model_calls


def test_live_full_skips_deep_v1_without_explicit_flag(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    smoke = _dataset(tmp_path, "smoke-pack", ["s1"])
    core = _dataset(tmp_path, "core-pack", ["c1"])
    selected = _profile(tmp_path, "selected-v1", ["unicode_wrap"])
    deep = _profile(tmp_path, "deep-v1", ["unicode_wrap"], deep=True)
    matrix = _matrix(tmp_path, smoke, core, selected_path=selected, deep_path=deep)

    class FakeAdapter:
        def __init__(self, target):
            pass

        def generate(self, prompt: str) -> str:
            return "I cannot help with that request."

        def close(self) -> None:
            pass

    monkeypatch.setitem(__import__("malleus.runner").runner.ADAPTERS, "openai_compatible", FakeAdapter)
    monkeypatch.setitem(__import__("malleus.mutate_run").mutate_run.ADAPTERS, "openai_compatible", FakeAdapter)
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True))

    evidence, _, _ = run_live_full_matrix(target_path=target, matrix_path=matrix, mutation_profile_path=selected, deep_mutation_profile_path=deep, out_dir=tmp_path / "out", dry_run=False, yes=True)

    rows = {row.row_id: row for row in evidence.rows}
    assert rows["mutation-profile:selected-v1"].status == "passed"
    assert rows["mutation-profile:deep-v1"].status == "skipped_by_operator"
    assert rows["mutation-profile:deep-v1"].live_model_calls == 0
    assert not (tmp_path / "out" / "mutations" / "deep-v1").exists()


def test_live_full_runs_deep_v1_with_explicit_flag(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    smoke = _dataset(tmp_path, "smoke-pack", ["s1"])
    core = _dataset(tmp_path, "core-pack", ["c1"])
    selected = _profile(tmp_path, "selected-v1", ["unicode_wrap"])
    deep = _profile(tmp_path, "deep-v1", ["unicode_wrap", "uppercase_text"], deep=True)
    matrix = _matrix(tmp_path, smoke, core, selected_path=selected, deep_path=deep)

    class FakeAdapter:
        def __init__(self, target):
            pass

        def generate(self, prompt: str) -> str:
            return "I cannot help with that request."

        def close(self) -> None:
            pass

    monkeypatch.setitem(__import__("malleus.runner").runner.ADAPTERS, "openai_compatible", FakeAdapter)
    monkeypatch.setitem(__import__("malleus.mutate_run").mutate_run.ADAPTERS, "openai_compatible", FakeAdapter)
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True))

    evidence, _, _ = run_live_full_matrix(
        target_path=target,
        matrix_path=matrix,
        mutation_profile_path=selected,
        deep_mutation_profile_path=deep,
        include_deep_mutations=True,
        out_dir=tmp_path / "out",
        dry_run=False,
        yes=True,
    )

    rows = {row.row_id: row for row in evidence.rows}
    deep_row = rows["mutation-profile:deep-v1"]
    assert deep_row.status == "passed"
    assert deep_row.live_model_calls == 3
    assert deep_row.metadata["mutation_count"] == 2
    assert deep_row.metadata["adapter_call_count"] == 3
    assert (tmp_path / "out" / "mutations" / "deep-v1" / "mutation-report.json").exists()
    assert "skipped" not in (deep_row.reason or "")


def test_live_full_rejects_mutation_dry_run_artifact(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    smoke = _dataset(tmp_path, "smoke-pack", ["s1"])
    core = _dataset(tmp_path, "core-pack", ["c1"])
    selected = _profile(tmp_path, "selected-v1", ["unicode_wrap"])
    matrix = _matrix(tmp_path, smoke, core, selected_path=selected)

    class FakeAdapter:
        def __init__(self, target):
            pass

        def generate(self, prompt: str) -> str:
            return "I cannot help with that request."

        def close(self) -> None:
            pass

    def fake_mutation_dry_run(target_path, input_path, scoring_path, output_dir, **kwargs):
        return real_run_mutation_benchmark(target_path, input_path, scoring_path, output_dir, mutations=kwargs.get("mutations"), limit=kwargs.get("limit"), dry_run=True)

    monkeypatch.setitem(__import__("malleus.runner").runner.ADAPTERS, "openai_compatible", FakeAdapter)
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True))
    monkeypatch.setattr("malleus.live_full.run_mutation_benchmark", fake_mutation_dry_run)

    out = tmp_path / "out"
    with pytest.raises(ValueError, match="dry-run/non-live artifacts"):
        run_live_full_matrix(target_path=target, matrix_path=matrix, mutation_profile_path=selected, out_dir=out, dry_run=False, yes=True)

    payload = json.loads((out / "live-full-evidence.json").read_text(encoding="utf-8"))
    row = {item["row_id"]: item for item in payload["rows"]}["mutation-profile:selected-v1"]
    assert row["status"] == "infra_error"
    assert row["live_model_calls"] == 0
    assert row["metadata"]["invalid_live_artifact"] is True
    assert (out / "mutations" / "selected-v1" / "mutation-dry-run.json").exists()
    assert not (out / "mutations" / "selected-v1" / "mutation-report.json").exists()


def test_live_full_uses_safe_mutation_output_segment(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    smoke = _dataset(tmp_path, "smoke-pack", ["s1"])
    core = _dataset(tmp_path, "core-pack", ["c1"])
    selected = _profile(tmp_path, "selected/evil", ["unicode_wrap"])
    matrix = _matrix(tmp_path, smoke, core, selected_path=selected, selected_id="selected/evil")

    class FakeAdapter:
        def __init__(self, target):
            pass

        def generate(self, prompt: str) -> str:
            return "I cannot help with that request."

        def close(self) -> None:
            pass

    monkeypatch.setitem(__import__("malleus.runner").runner.ADAPTERS, "openai_compatible", FakeAdapter)
    monkeypatch.setitem(__import__("malleus.mutate_run").mutate_run.ADAPTERS, "openai_compatible", FakeAdapter)
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True))

    evidence, _, _ = run_live_full_matrix(target_path=target, matrix_path=matrix, mutation_profile_path=selected, out_dir=tmp_path / "out", dry_run=False, yes=True)

    row = {item.row_id: item for item in evidence.rows}["mutation-profile:selected/evil"]
    assert row.metadata["output_dir"] == "mutations/selected-evil"
    assert (tmp_path / "out" / "mutations" / "selected-evil" / "mutation-report.json").exists()
    assert not (tmp_path / "out" / "mutations" / "selected" / "evil").exists()


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


def _profile(tmp_path: Path, profile_id: str, mutations: list[str], *, deep: bool = False) -> Path:
    profile = tmp_path / f"{profile_id.replace('/', '-')}.yaml"
    mutation_lines = "".join(f"  - {name}\n" for name in mutations)
    profile.write_text(f"schema_version: malleus.mutation_profile.v1\nid: {profile_id}\nname: {profile_id}\nversion: 1.0.0\ndeep: {str(deep).lower()}\nmutations:\n{mutation_lines}", encoding="utf-8")
    return profile


def _matrix(tmp_path: Path, smoke: Path, core: Path, *, selected_path: str | Path, selected_id: str = "selected-v1", deep_path: str | Path | None = None) -> Path:
    matrix = tmp_path / "matrix.yaml"
    deep_section = "deep_mutation_profiles: []"
    if deep_path is not None:
        deep_section = f"""deep_mutation_profiles:
  - id: deep-v1
    path: {deep_path}
    status: available_optional
    default: false
    optional: true
    mutation_count: 0
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
    path: {smoke}
    evidence_level: live_model_required
    status: available
    live_model_evidence: true
    scaffold_only: false
  - id: core-v1
    path: {core}
    evidence_level: live_model_required
    status: available
    live_model_evidence: true
    scaffold_only: false
selected_mutation_profiles:
  - id: {selected_id}
    path: {selected_path}
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
