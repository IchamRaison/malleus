from __future__ import annotations

import json
from pathlib import Path

from malleus.compare import write_comparison_report
from malleus.runner import compare_models


def test_write_comparison_report(tmp_path: Path) -> None:
    report_paths = []
    for model, score in [("a", 90), ("b", 70)]:
        path = tmp_path / model / "report.json"
        path.parent.mkdir()
        path.write_text(
            json.dumps(
                {
                    "report_mode": "live_provider",
                    "target_model": model,
                    "metadata": {"run": {"provider_calls_enabled": True}},
                    "summary": {"score_total": score, "max_score_total": 100, "passed_items": 1, "total_items": 1},
                }
            ),
            encoding="utf-8",
        )
        report_paths.append(path)
    out = write_comparison_report(report_paths, tmp_path / "comparison")
    text = (out / "comparison.md").read_text(encoding="utf-8")
    assert "| a | live_provider | model_behavior | true | 90/100 | 90.0% |" in text
    assert "| b | live_provider | model_behavior | true | 70/100 | 70.0% |" in text


def test_write_comparison_report_escapes_markdown_cells(tmp_path: Path) -> None:
    hostile_model = "model | `x` <script>alert(1)</script> api_key=SYNTHETIC-SK-OPENAI-SECRET"
    path = tmp_path / "hostile" / "report.json"
    path.parent.mkdir()
    path.write_text(
        json.dumps(
            {
                "report_mode": "dry_run",
                "target_model": hostile_model,
                "metadata": {"run": {"provider_calls_enabled": False}},
                "summary": {"score_total": 50, "max_score_total": 100, "passed_items": 1, "total_items": 2},
            }
        ),
        encoding="utf-8",
    )

    out = write_comparison_report([path], tmp_path / "comparison")

    rows = json.loads((out / "comparison.json").read_text(encoding="utf-8"))
    assert rows[0]["model"] == hostile_model
    assert rows[0]["report_mode"] == "dry_run"
    assert rows[0]["evidence_label"] == "planning_only"
    assert rows[0]["provider_calls_enabled"] is False
    markdown = (out / "comparison.md").read_text(encoding="utf-8")
    assert "model \\| \\`x\\` &lt;script>alert(1)&lt;/script> [REDACTED]" in markdown
    assert "<script>" not in markdown
    assert "SYNTHETIC-SK-OPENAI-SECRET" not in markdown

def test_compare_models_defaults_to_provider_free_dry_run(monkeypatch, tmp_path: Path) -> None:
    target = tmp_path / "target.yaml"
    target.write_text(
        "name: t\nadapter: openai_compatible\nmodel: base\nbase_url: https://example.test/v1\napi_key_env: MISSING_COMPARE_KEY\n",
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
    objective: provider-free compare
    prompt: hello
    pass_signals:
      - type: refusal_marker
""",
        encoding="utf-8",
    )
    monkeypatch.delenv("MISSING_COMPARE_KEY", raising=False)

    out = compare_models(target, dataset, scoring, tmp_path / "cmp", ["model-a", "model-b"], limit=1)

    assert out == tmp_path / "cmp"
    assert (tmp_path / "cmp" / "model-a" / "dry-run.json").exists()
    assert (tmp_path / "cmp" / "model-b" / "dry-run.json").exists()
    assert not (tmp_path / "cmp" / "model-a" / "report.json").exists()
    rows = json.loads((tmp_path / "cmp" / "comparison.json").read_text(encoding="utf-8"))
    assert {row["model"] for row in rows} == {"model-a", "model-b"}
    assert all(row["total"] == 1 for row in rows)
    assert all(row["report_mode"] == "dry_run" for row in rows)
    assert all(row["dry_run"] is True for row in rows)
    assert all(row["provider_calls_enabled"] is False for row in rows)
    assert all(row["evidence_label"] == "planning_only" for row in rows)
    markdown = (tmp_path / "cmp" / "comparison.md").read_text(encoding="utf-8")
    assert "not model behavior evidence" in markdown
