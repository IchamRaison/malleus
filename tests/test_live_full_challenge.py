from __future__ import annotations

import json
from pathlib import Path

from malleus.live_full import run_live_surface_pack
from malleus.live_preflight import LivePreflightReport, SafeTargetEndpoint


MATRIX_PATH = Path("datasets/release_matrices/malleus-v0.1.yaml")


def test_live_full_routes_challenge_to_live_runner(monkeypatch, tmp_path: Path) -> None:
    calls: list[str] = []

    class FakeAdapter:
        def __init__(self, target):
            self.target = target

        def generate(self, prompt: str) -> str:
            calls.append(prompt)
            return "Safe response: untrusted inert artifact only; no unsafe action is performed."

        def close(self) -> None:
            pass

    monkeypatch.setitem(__import__("malleus.runner").runner.ADAPTERS, "openai_compatible", FakeAdapter)
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True))

    evidence, _, _ = run_live_surface_pack(target_path=_target(tmp_path), pack_id="challenge-v1", matrix_path=MATRIX_PATH, out_dir=tmp_path / "out", yes=True)
    row = evidence.rows[0]

    assert row.status == "passed"
    assert row.evidence_level == "live_text_model"
    assert row.live_model_calls == len(calls) == 24
    assert row.metadata["report_json"] == "challenge/challenge-v1/challenge-live-report.json"
    assert row.metadata["local_challenge_artifacts_counted_as_live"] is False
    assert (tmp_path / "out" / "challenge" / "challenge-v1" / "challenge-live-report.json").exists()
    assert not (tmp_path / "out" / "challenge" / "challenge-v1" / "challenge-report.json").exists()


def test_live_full_challenge_preflight_failure_makes_no_model_calls(monkeypatch, tmp_path: Path) -> None:
    class ExplodingAdapter:
        def __init__(self, target):
            raise AssertionError("preflight failure must not instantiate adapter")

    monkeypatch.setitem(__import__("malleus.runner").runner.ADAPTERS, "openai_compatible", ExplodingAdapter)
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=False))

    evidence, _, _ = run_live_surface_pack(target_path=_target(tmp_path), pack_id="challenge-v1", matrix_path=MATRIX_PATH, out_dir=tmp_path / "out", yes=True)
    row = evidence.rows[0]

    assert row.status == "target_error"
    assert row.evidence_level == "scaffold_static"
    assert row.live_model_calls == 0
    assert not (tmp_path / "out" / "challenge").exists()


def test_live_full_challenge_provider_error_is_operational(monkeypatch, tmp_path: Path) -> None:
    class ProviderErrorAdapter:
        def __init__(self, target):
            self.target = target

        def generate(self, prompt: str) -> str:
            raise RuntimeError("provider unavailable")

        def close(self) -> None:
            pass

    monkeypatch.setitem(__import__("malleus.runner").runner.ADAPTERS, "openai_compatible", ProviderErrorAdapter)
    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight(text_ready=True))

    evidence, _, _ = run_live_surface_pack(target_path=_target(tmp_path), pack_id="challenge-v1", matrix_path=MATRIX_PATH, out_dir=tmp_path / "out", yes=True)
    row = evidence.rows[0]

    assert row.status == "provider_error"
    assert row.live_model_calls == 0
    assert row.metadata["completed_live_model_calls"] == 0
    payload = json.loads((tmp_path / "out" / "challenge" / "challenge-v1" / "challenge-live-report.json").read_text(encoding="utf-8"))
    assert payload["summary"]["provider_error"] == 24


def _target(tmp_path: Path) -> Path:
    target = tmp_path / "target.yaml"
    target.write_text("name: t\nadapter: openai_compatible\nmodel: m\nbase_url: https://example.test/v1\n", encoding="utf-8")
    return target


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
