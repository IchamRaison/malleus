from __future__ import annotations

import json
from pathlib import Path

from malleus.diff_runs import diff_run_reports, render_diff_markdown, write_diff_report


def _case(case_id: str, *, passed: bool, score: int, category: str = "instruction_boundary", severity: str = "high") -> dict:
    return {
        "dataset_name": f"{category}-cases",
        "case_id": case_id,
        "severity": severity,
        "objective": f"Objective {case_id}",
        "prompt": "prompt",
        "response_text": "response",
        "passed": passed,
        "score": score,
        "penalty": 100 - score,
        "latency_seconds": 0.1,
        "warnings": [],
        "failure_checks": [],
        "pass_checks": [],
    }


def _group(group_id: str, *, passed: bool, score: int, category: str = "refusal_consistency") -> dict:
    return {
        "dataset_name": f"{category}-groups",
        "group_id": group_id,
        "severity": "medium",
        "objective": f"Objective {group_id}",
        "passed": passed,
        "score": score,
        "penalty": 100 - score,
        "warnings": [],
        "variants": [],
    }


def _report(path: Path, *, run_id: str, model: str, datasets: list[dict]) -> Path:
    total = 0
    passed = 0
    score = 0
    max_score = 0
    normalized = []
    for dataset in datasets:
        cases = dataset.get("case_results", [])
        groups = dataset.get("group_results", [])
        items = cases + groups
        ds_total = len(items)
        ds_passed = sum(1 for item in items if item["passed"])
        ds_score = sum(item["score"] for item in items)
        ds_max = ds_total * 100
        total += ds_total
        passed += ds_passed
        score += ds_score
        max_score += ds_max
        normalized.append({**dataset, "summary": {"total_items": ds_total, "passed_items": ds_passed, "failed_items": ds_total - ds_passed, "score_total": ds_score, "max_score_total": ds_max}})
    payload = {
        "run_id": run_id,
        "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:00:01Z",
        "target_name": "target",
        "target_adapter": "nvidia",
        "target_model": model,
        "input_path": "datasets/benchmark_packs/core-v1.yaml",
        "scoring_path": "configs/scoring-default.yaml",
        "datasets": normalized,
        "summary": {"total_items": total, "passed_items": passed, "failed_items": total - passed, "score_total": score, "max_score_total": max_score},
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_diff_run_reports_identifies_regressions_improvements_and_score_deltas(tmp_path: Path) -> None:
    old = _report(
        tmp_path / "old.json",
        run_id="old-run",
        model="model-a",
        datasets=[
            {"dataset_name": "instruction-boundary", "category": "instruction_boundary", "subcategory": "direct", "case_results": [_case("same-pass", passed=True, score=100), _case("regressed", passed=True, score=100), _case("improved", passed=False, score=0), _case("removed", passed=True, score=100)], "group_results": []},
            {"dataset_name": "refusal", "category": "refusal_consistency", "subcategory": "groups", "case_results": [], "group_results": [_group("group-regressed", passed=True, score=100)]},
        ],
    )
    new = _report(
        tmp_path / "new.json",
        run_id="new-run",
        model="model-b",
        datasets=[
            {"dataset_name": "instruction-boundary", "category": "instruction_boundary", "subcategory": "direct", "case_results": [_case("same-pass", passed=True, score=100), _case("regressed", passed=False, score=0), _case("improved", passed=True, score=100), _case("added", passed=False, score=0)], "group_results": []},
            {"dataset_name": "refusal", "category": "refusal_consistency", "subcategory": "groups", "case_results": [], "group_results": [_group("group-regressed", passed=False, score=0)]},
        ],
    )

    diff = diff_run_reports(old, new)

    assert diff.old_run_id == "old-run"
    assert diff.new_run_id == "new-run"
    assert diff.summary.score_delta == -200
    assert diff.summary.pass_rate_delta == -40.0
    assert diff.summary.newly_failing == 2
    assert diff.summary.newly_passing == 1
    assert diff.summary.added_items == 1
    assert diff.summary.removed_items == 1
    assert {item.item_id for item in diff.newly_failing} == {"case:instruction_boundary:regressed", "group:refusal_consistency:group-regressed"}
    assert [item.item_id for item in diff.newly_passing] == ["case:instruction_boundary:improved"]
    assert diff.category_deltas["instruction_boundary"].score_delta == -100
    assert diff.category_deltas["refusal_consistency"].score_delta == -100


def test_write_diff_report_outputs_json_and_markdown(tmp_path: Path) -> None:
    old = _report(tmp_path / "old.json", run_id="old-run", model="model-a", datasets=[{"dataset_name": "d", "category": "policy_robustness", "subcategory": "s", "case_results": [_case("c1", passed=True, score=100, category="policy_robustness")], "group_results": []}])
    new = _report(tmp_path / "new.json", run_id="new-run", model="model-a", datasets=[{"dataset_name": "d", "category": "policy_robustness", "subcategory": "s", "case_results": [_case("c1", passed=False, score=0, category="policy_robustness")], "group_results": []}])
    diff = diff_run_reports(old, new)

    json_path, md_path = write_diff_report(diff, tmp_path / "out")

    assert json_path.name == "diff-runs-report.json"
    assert md_path.name == "diff-runs-report.md"
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["summary"]["newly_failing"] == 1
    markdown = md_path.read_text(encoding="utf-8")
    assert "# Malleus run diff" in markdown
    assert "case:policy_robustness:c1" in markdown
    assert "Score delta: -100" in markdown


def test_render_diff_markdown_escapes_untrusted_report_values(tmp_path: Path) -> None:
    old = _report(
        tmp_path / "old.json",
        run_id="old | run\n# injected",
        model="model `x` <b>bad</b>",
        datasets=[{"dataset_name": "d", "category": "policy|robustness\nrow", "subcategory": "s", "case_results": [_case("c`1|x\nrow", passed=True, score=100, category="policy|robustness\nrow")], "group_results": []}],
    )
    new = _report(
        tmp_path / "new.json",
        run_id="new | run",
        model="model-b",
        datasets=[{"dataset_name": "d", "category": "policy|robustness\nrow", "subcategory": "s", "case_results": [_case("c`1|x\nrow", passed=False, score=0, category="policy|robustness\nrow")], "group_results": []}],
    )

    markdown = render_diff_markdown(diff_run_reports(old, new))

    assert "\n# injected" not in markdown
    assert r"\# injected" in markdown
    assert "<b>bad</b>" not in markdown
    assert "policy|robustness" not in markdown
    assert "policy\\|robustness row" in markdown
    assert "case:policy\\|robustness row:c\\`1\\|x row" in markdown
    assert "`case:policy" not in markdown


def test_render_diff_markdown_handles_no_changes(tmp_path: Path) -> None:
    old = _report(tmp_path / "old.json", run_id="old-run", model="model-a", datasets=[{"dataset_name": "d", "category": "output_integrity", "subcategory": "s", "case_results": [_case("c1", passed=True, score=100, category="output_integrity")], "group_results": []}])
    new = _report(tmp_path / "new.json", run_id="new-run", model="model-a", datasets=[{"dataset_name": "d", "category": "output_integrity", "subcategory": "s", "case_results": [_case("c1", passed=True, score=100, category="output_integrity")], "group_results": []}])

    markdown = render_diff_markdown(diff_run_reports(old, new))

    assert "No pass/fail transitions detected." in markdown
    assert "Score delta: 0" in markdown
