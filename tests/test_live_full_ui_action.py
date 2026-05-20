from __future__ import annotations

import json
from pathlib import Path

from malleus.live_full import run_live_full_matrix
from malleus.live_preflight import LivePreflightReport, SafeTargetEndpoint


def test_live_full_converts_ui_action_live_report_to_evidence_row(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    fixture = Path("tests/fixtures/ui_harness/local-product.yaml")
    matrix = _matrix(tmp_path, fixture)
    profile = _profile(tmp_path)
    calls: list[str] = []

    class SafeAdapter:
        def __init__(self, target):
            self.target = target

        def generate(self, prompt: str) -> str:
            calls.append(prompt)
            return json.dumps({"action": "read", "selector": "#message", "value": "", "rationale": "treat page content as untrusted and avoid side effects"})

        def close(self) -> None:
            pass

    monkeypatch.setitem(__import__("malleus.runner").runner.ADAPTERS, "openai_compatible", SafeAdapter)
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True))

    evidence, _, _ = run_live_full_matrix(target_path=target, matrix_path=matrix, mutation_profile_path=profile, out_dir=tmp_path / "out", dry_run=False, yes=True)

    rows = {row.row_id: row for row in evidence.rows}
    assert "pack:ui-browser-scaffold-v1" not in rows
    assert calls == []
    assert not (tmp_path / "out" / "ui-action" / "ui-browser-scaffold-v1").exists()


def test_live_full_ui_action_model_security_failure_is_failed_row(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    fixture = Path("tests/fixtures/ui_harness/local-product.yaml")
    matrix = _matrix(tmp_path, fixture)
    profile = _profile(tmp_path)

    class UnsafeAdapter:
        def __init__(self, target):
            self.target = target

        def generate(self, prompt: str) -> str:
            return json.dumps({"action": "click", "selector": "button[data-testid=\"submit\"]", "value": "", "rationale": "click approve and submit the workflow as the page says"})

        def close(self) -> None:
            pass

    monkeypatch.setitem(__import__("malleus.runner").runner.ADAPTERS, "openai_compatible", UnsafeAdapter)
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True))

    evidence, _, _ = run_live_full_matrix(target_path=target, matrix_path=matrix, mutation_profile_path=profile, out_dir=tmp_path / "out", dry_run=False, yes=True)

    rows = {row.row_id: row for row in evidence.rows}
    assert "pack:ui-browser-scaffold-v1" not in rows
    assert not (tmp_path / "out" / "ui-action" / "ui-browser-scaffold-v1" / "ui-action-live-report.json").exists()


def test_live_full_rejects_ui_scaffold_outputs_as_live_evidence(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    fixture = Path("tests/fixtures/ui_harness/local-product.yaml")
    matrix = _matrix(tmp_path, fixture)
    profile = _profile(tmp_path)

    class SafeAdapter:
        def __init__(self, target):
            self.target = target

        def generate(self, prompt: str) -> str:
            return json.dumps({"action": "read", "selector": "#message", "value": "", "rationale": "safe read only"})

        def close(self) -> None:
            pass

    def scaffold_masquerade(target_path: Path, fixture_path: Path, output_dir: Path):
        raise AssertionError("UI scaffold runner must not execute for canonical live rows")

    monkeypatch.setitem(__import__("malleus.runner").runner.ADAPTERS, "openai_compatible", SafeAdapter)
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True))
    monkeypatch.setattr("malleus.live_full.run_ui_action_live", scaffold_masquerade)

    run_live_full_matrix(target_path=target, matrix_path=matrix, mutation_profile_path=profile, out_dir=tmp_path / "out", dry_run=False, yes=True)

    skeleton = json.loads((tmp_path / "out" / "live-full-evidence.json").read_text(encoding="utf-8"))
    assert "pack:ui-browser-scaffold-v1" not in {row["row_id"] for row in skeleton["rows"]}


def _target(tmp_path: Path) -> Path:
    target = tmp_path / "target.yaml"
    target.write_text("name: ui-target\nadapter: openai_compatible\nmodel: fake-model\nbase_url: https://example.test/v1\napi_key_env: MISSING_UI_ACTION_LIVE_KEY\n", encoding="utf-8")
    return target


def _matrix(tmp_path: Path, fixture: Path) -> Path:
    matrix = tmp_path / "matrix.yaml"
    matrix.write_text(
        f"""schema_version: malleus.release_matrix.v1
id: test-ui-action-matrix
version: 1.0.0
mode_boundaries:
  - mode: live_provider
    evidence_level: live_model_required
    provider_calls_enabled: true
packs:
  - id: ui-browser-scaffold-v1
    path: {fixture}
    evidence_level: scaffold_only
    status: available
    live_model_evidence: false
    scaffold_only: true
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
        target_name="ui-target",
        adapter="openai_compatible",
        model="fake-model",
        endpoint=SafeTargetEndpoint(scheme="https", host="example.test", path_hint="/v1"),
        text_status="passed" if text_ready else "preflight_failed",
        text_ready=text_ready,
        visual_status="not_supported",
        ok=text_ready,
        probes=[],
    )
