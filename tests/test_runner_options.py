from __future__ import annotations

import json
import hashlib
from pathlib import Path

import pytest

from malleus.adapters.base import AdapterError
from malleus.runner import enumerate_items, run_benchmark


def _write_common_files(tmp_path: Path) -> tuple[Path, Path, Path]:
    target = tmp_path / "target.yaml"
    target.write_text(
        "name: t\nadapter: openai_compatible\nmodel: m\nbase_url: https://example.test/v1\napi_key_env: OPENAI_API_KEY\n",
        encoding="utf-8",
    )
    scoring = tmp_path / "scoring.yaml"
    scoring.write_text(
        "version: 1\nmax_score: 100\nseverity_weights:\n  low: 10\n  medium: 20\n  high: 35\n  critical: 50\n",
        encoding="utf-8",
    )
    dataset = tmp_path / "dataset.yaml"
    dataset.write_text(
        """name: d
version: 1
category: c
subcategory: s
cases:
  - id: c1
    severity: low
    objective: first
    prompt: first prompt
    pass_signals:
      - type: refusal_marker
  - id: c2
    severity: low
    objective: second
    prompt: second prompt
    pass_signals:
      - type: refusal_marker
""",
        encoding="utf-8",
    )
    return target, scoring, dataset


def test_enumerate_items_lists_case_ids(tmp_path: Path) -> None:
    _, _, dataset = _write_common_files(tmp_path)
    items = enumerate_items(dataset)
    assert items == ["d:c1", "d:c2"]


def test_run_benchmark_filters_by_case_id_and_limit(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "token")
    target, scoring, dataset = _write_common_files(tmp_path)

    class FakeAdapter:
        def __init__(self, target):
            self.prompts = []
        def generate(self, prompt: str) -> str:
            self.prompts.append(prompt)
            return "I cannot help with that."
        def close(self) -> None:
            pass

    monkeypatch.setitem(__import__("malleus.runner").runner.ADAPTERS, "openai_compatible", FakeAdapter)
    report = run_benchmark(target, dataset, scoring, tmp_path / "out", case_ids={"c2"}, limit=1)
    assert report.summary.total_items == 1
    assert report.datasets[0].case_results[0].case_id == "c2"
    payload = json.loads((tmp_path / "out" / "report.json").read_text(encoding="utf-8"))
    assert payload["summary"]["total_items"] == 1
    risk_summary = json.loads((tmp_path / "out" / "risk-summary.json").read_text(encoding="utf-8"))
    assert risk_summary["status"] == "pass"


def test_run_benchmark_dry_run_writes_plan_without_model_calls(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "token")
    target, scoring, dataset = _write_common_files(tmp_path)

    class ExplodingAdapter:
        def __init__(self, target):
            pass
        def generate(self, prompt: str) -> str:
            raise AssertionError("dry-run must not call adapter")
        def close(self) -> None:
            pass

    monkeypatch.setitem(__import__("malleus.runner").runner.ADAPTERS, "openai_compatible", ExplodingAdapter)
    plan = run_benchmark(target, dataset, scoring, tmp_path / "dry", dry_run=True)
    assert plan.summary.total_items == 2
    assert plan.report_mode == "dry_run"
    assert plan.metadata["dry_run"] is True
    assert plan.metadata["provider_calls_enabled"] is False
    assert plan.summary.failed_items == 2
    assert (tmp_path / "dry" / "dry-run.json").exists()
    assert (tmp_path / "dry" / "manifest.json").exists()
    assert (tmp_path / "dry" / "events.jsonl").exists()
    assert (tmp_path / "dry" / "risk-summary.json").exists()
    assert not (tmp_path / "dry" / "findings.json").exists()
    assert not (tmp_path / "dry" / "repeated-summary.json").exists()
    manifest = json.loads((tmp_path / "dry" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["metadata"]["repeated_sampling"] == {"repeats": 1, "temperature_schedule": []}
    payload = json.loads((tmp_path / "dry" / "dry-run.json").read_text(encoding="utf-8"))
    assert payload["report_mode"] == "dry_run"
    assert payload["metadata"]["network_enabled"] is False
    assert payload["summary"]["failed_items"] == payload["summary"]["total_items"]


def test_run_benchmark_live_rejects_system_target_types(tmp_path: Path) -> None:
    target = tmp_path / "rag-target.yaml"
    target.write_text(
        "name: rag\ntarget_type: rag_service\nrag_service:\n  endpoint_url: https://rag.example.test/query\n",
        encoding="utf-8",
    )
    _, scoring, dataset = _write_common_files(tmp_path)

    with pytest.raises(ValueError, match="use the matching live surface command for target_type=rag_service"):
        run_benchmark(target, dataset, scoring, tmp_path / "out")


def test_run_benchmark_dry_run_rejects_system_target_types(tmp_path: Path) -> None:
    target = tmp_path / "rag-target.yaml"
    target.write_text(
        "name: rag\ntarget_type: rag_service\nrag_service:\n  endpoint_url: https://rag.example.test/query\n",
        encoding="utf-8",
    )
    _, scoring, dataset = _write_common_files(tmp_path)

    with pytest.raises(ValueError, match="use the matching live surface command for target_type=rag_service"):
        run_benchmark(target, dataset, scoring, tmp_path / "dry", dry_run=True)



def test_run_benchmark_accepts_qualified_case_id(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "token")
    target, scoring, dataset = _write_common_files(tmp_path)

    class FakeAdapter:
        def __init__(self, target):
            pass
        def generate(self, prompt: str) -> str:
            return "I cannot help with that."
        def close(self) -> None:
            pass

    monkeypatch.setitem(__import__("malleus.runner").runner.ADAPTERS, "openai_compatible", FakeAdapter)
    report = run_benchmark(target, dataset, scoring, tmp_path / "out-qualified", case_ids={"d:c2"})
    assert report.summary.total_items == 1
    assert report.datasets[0].case_results[0].case_id == "c2"


def test_dry_run_markdown_respects_limit_and_case_id(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "token")
    target, scoring, dataset = _write_common_files(tmp_path)
    run_benchmark(target, dataset, scoring, tmp_path / "dry-filtered", dry_run=True, case_ids={"d:c2"}, limit=1)
    text = (tmp_path / "dry-filtered" / "dry-run.md").read_text(encoding="utf-8")
    assert "d:c2" in text
    assert "d:c1" not in text


def test_dry_run_markdown_escapes_selected_items(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "token")
    target, scoring, _dataset = _write_common_files(tmp_path)
    hostile = "case|`x`<script>alert(1)</script>"
    dataset = tmp_path / "hostile.yaml"
    dataset.write_text(
        f"""name: dataset|name
version: 1
category: c
subcategory: s
cases:
  - id: {hostile!r}
    severity: low
    objective: hostile id
    prompt: safe prompt
    pass_signals:
      - type: refusal_marker
""",
        encoding="utf-8",
    )

    run_benchmark(target, dataset, scoring, tmp_path / "dry-hostile", dry_run=True)
    text = (tmp_path / "dry-hostile" / "dry-run.md").read_text(encoding="utf-8")

    assert "dataset\\|name:case\\|\\`x\\`&lt;script>alert(1)&lt;/script>" in text
    assert "<script>" not in text


def test_smoke_dry_run_writes_manifest_and_selected_case_events(tmp_path: Path) -> None:
    out = tmp_path / "smoke-dry"
    report = run_benchmark(
        Path("examples/targets/openai.yaml"),
        Path("datasets/benchmark_packs/smoke-v1.yaml"),
        Path("configs/scoring-default.yaml"),
        out,
        dry_run=True,
    )

    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    events = [json.loads(line) for line in (out / "events.jsonl").read_text(encoding="utf-8").splitlines()]

    assert report.summary.total_items == 5
    assert manifest["schema_version"] == "malleus.ir.v1"
    assert manifest["dry_run"] is True
    assert manifest["selected_item_count"] == 5
    assert manifest["target_adapter"] == "openai_compatible"
    assert [event["event_type"] for event in events].count("run_started") == 1
    assert [event["event_type"] for event in events].count("case_selected") == 5
    assert [event["event_type"] for event in events].count("run_finished") == 1
    assert all(event["schema_version"] == "malleus.events.v1" for event in events)

    risk_summary = json.loads((out / "risk-summary.json").read_text(encoding="utf-8"))
    assert risk_summary["schema_version"] == "malleus.gates.v1"
    assert risk_summary["run_id"] == report.run_id
    assert risk_summary["status"] == "warn"
    assert "thresholds" in risk_summary
    assert "summary" in risk_summary
    assert risk_summary["reasons"] == ["dry_run_no_model_execution"]
    assert not (out / "findings.json").exists()
    assert not (out / "repeated-summary.json").exists()

    report_manifest = json.loads((out / "report-manifest.json").read_text(encoding="utf-8"))
    assert report_manifest["schema_version"] == "malleus.report_manifest.v1"
    assert report_manifest["run_id"] == report.run_id
    manifest_artifacts = {artifact["relative_path"]: artifact for artifact in manifest["artifacts"]}
    report_artifacts = {artifact["relative_path"]: artifact for artifact in report_manifest["artifacts"]}
    for artifact_name in ["events.jsonl", "dry-run.json", "dry-run.md", "risk-summary.json", "model-risk-card.md"]:
        artifact = report_artifacts[artifact_name]
        assert artifact["artifact_schema_version"] == "malleus.artifact.v1"
        assert artifact["path"] == artifact_name
        assert not Path(artifact["relative_path"]).is_absolute()
        assert artifact["artifact_type"]
        assert artifact["redaction_status"] in {"redacted", "not_applicable", "unknown"}
        assert artifact["sha256"] == hashlib.sha256((out / artifact_name).read_bytes()).hexdigest()
        assert manifest_artifacts[artifact_name]["sha256"] == artifact["sha256"]
    assert manifest_artifacts["report-manifest.json"]["sha256"] == hashlib.sha256((out / "report-manifest.json").read_bytes()).hexdigest()


def test_provider_config_failure_writes_manifest_and_error_event(monkeypatch, tmp_path: Path) -> None:
    missing_env = "MALLEUS_TEST_MISSING_API_KEY"
    monkeypatch.delenv(missing_env, raising=False)
    target = tmp_path / "target.yaml"
    target.write_text(
        f"name: t\nadapter: openai_compatible\nmodel: m\nbase_url: https://example.test/v1\napi_key_env: {missing_env}\n",
        encoding="utf-8",
    )
    _, scoring, dataset = _write_common_files(tmp_path)
    out = tmp_path / "provider-error"

    with pytest.raises(AdapterError, match="missing API key"):
        run_benchmark(target, dataset, scoring, out)

    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    events = [json.loads(line) for line in (out / "events.jsonl").read_text(encoding="utf-8").splitlines()]

    assert manifest["provider_errors"][0]["error_type"] == "AdapterError"
    assert "missing API key" in manifest["provider_errors"][0]["message"]
    assert any(event["event_type"] == "provider_error" for event in events)
    assert events[-1]["event_type"] == "run_finished"
    assert events[-1]["payload"]["status"] == "error"
    risk_summary = json.loads((out / "risk-summary.json").read_text(encoding="utf-8"))
    assert risk_summary["status"] == "error"
    assert risk_summary["summary"]["provider_error_count"] == 1
