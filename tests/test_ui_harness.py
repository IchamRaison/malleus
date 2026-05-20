from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from malleus.cli import app
from malleus.ui_harness import build_ui_harness_plan, write_ui_harness_report
from malleus.utils.redact import scan_public_artifact_text
from malleus.ui_action_live import load_ui_action_fixture

FIXTURE = Path("tests/fixtures/ui_harness/local-product.yaml")
EXTERNAL_FIXTURE = Path("tests/fixtures/ui_harness/external-product.yaml")
RAW_SECRET_STRINGS = [
    "RAW-COOKIE-TOKEN-12345",
    "SYNTHETIC-SK-UIHARNESS-SECRET-12345",
    "RAW-EXPECTED-TOKEN-999",
    "RAW-SESSION-COOKIE-SECRET",
    "RAWCOOKIE123",
    "Summarize the visible support ticket",
    "Check whether the UI leaks",
]


def _artifact_text(out: Path) -> str:
    return "\n".join(
        (out / name).read_text(encoding="utf-8")
        for name in ["ui-harness-plan.json", "ui-harness-plan.md", "ui-harness-report.json", "ui-harness-report.md"]
        if (out / name).exists()
    )


def test_ui_harness_plan_dry_run_writes_safe_scaffold_artifacts(tmp_path: Path) -> None:
    plan = build_ui_harness_plan(FIXTURE, tmp_path / "plan", dry_run=True)
    expected_prompts = len(load_ui_action_fixture(FIXTURE).prompts)

    assert plan.schema_version == "malleus.ui_harness.plan.v1"
    assert plan.provider_calls_enabled is False
    assert plan.browser_enabled is False
    assert plan.summary.planned_submissions == expected_prompts
    assert plan.selectors
    assert plan.planned_prompt_submissions[0].sha256
    assert plan.planned_prompt_submissions[0].length > 0
    assert plan.expected_extraction["session_cookie"].startswith("[REDACTED]")
    assert all(shot.real_screenshot is False for shot in plan.screenshot_placeholders)
    assert all("PLACEHOLDER" in shot.placeholder_path for shot in plan.screenshot_placeholders)
    assert plan.findings_shape[0].metadata["browser_enabled"] is False
    assert plan.scoring.status == "planned"
    assert plan.wowpp_metadata.provider_calls_enabled is False


def test_ui_harness_run_dry_run_writes_plan_and_report_without_raw_secrets(tmp_path: Path) -> None:
    out = tmp_path / "run"
    report, json_path, markdown_path = write_ui_harness_report(FIXTURE, out, dry_run=True)

    assert json_path.name == "ui-harness-report.json"
    assert markdown_path.name == "ui-harness-report.md"
    assert (out / "ui-harness-plan.json").exists()
    assert (out / "ui-harness-plan.md").exists()
    assert report.schema_version == "malleus.ui_harness.report.v1"
    assert report.provider_calls_enabled is False
    assert report.browser_enabled is False
    assert report.summary.screenshots_captured == 0
    assert report.findings[0].finding_id == "uih-dry-run-no-browser"
    assert report.extracted_context

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["screenshot_placeholders"][0]["real_screenshot"] is False
    assert payload["screenshot_placeholders"][0]["note"].startswith("Placeholder only")
    public_text = _artifact_text(out)
    assert scan_public_artifact_text(public_text).passed
    assert "redacted_preview" in public_text
    assert "sha256" in public_text
    assert "length" in public_text
    assert "real_screenshot" in public_text
    assert "/home/" not in public_text
    assert "https://example.com" not in public_text
    for raw in RAW_SECRET_STRINGS:
        assert raw not in public_text


def test_ui_harness_cli_plan_and_run_dry_run(tmp_path: Path) -> None:
    runner = CliRunner()
    plan_out = tmp_path / "cli-plan"
    plan_result = runner.invoke(app, ["ui-harness", "plan", "--config", str(FIXTURE), "--out-dir", str(plan_out), "--dry-run"])

    assert plan_result.exit_code == 0, plan_result.output
    assert "UI harness plan written" in plan_result.output
    assert "Provider calls enabled: false" in plan_result.output
    assert "Browser enabled: false" in plan_result.output
    assert (plan_out / "ui-harness-plan.json").exists()
    assert (plan_out / "ui-harness-plan.md").exists()

    run_out = tmp_path / "cli-run"
    run_result = runner.invoke(app, ["ui-harness", "run", "--config", str(FIXTURE), "--out-dir", str(run_out), "--dry-run"])

    assert run_result.exit_code == 0, run_result.output
    assert "UI harness dry-run report written" in run_result.output
    assert "Browser enabled: false" in run_result.output
    assert (run_out / "ui-harness-report.json").exists()
    assert (run_out / "ui-harness-report.md").exists()


def test_ui_harness_live_ui_fails_closed_without_allowlist(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, ["ui-harness", "plan", "--config", str(FIXTURE), "--out-dir", str(tmp_path / "blocked"), "--dry-run", "--live-ui"])

    assert result.exit_code != 0
    assert "fail-closed" in result.output
    assert "--allowed-url" in result.output
    assert not (tmp_path / "blocked" / "ui-harness-plan.json").exists()


def test_ui_harness_live_ui_allowlist_is_still_scaffold_only(tmp_path: Path) -> None:
    out = tmp_path / "allowed"
    result = CliRunner().invoke(
        app,
        [
            "ui-harness",
            "run",
            "--config",
            str(FIXTURE),
            "--out-dir",
            str(out),
            "--dry-run",
            "--live-ui",
            "--allowed-url",
            "http://localhost:8080",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads((out / "ui-harness-report.json").read_text(encoding="utf-8"))
    assert payload["mode"] == "scaffold"
    assert payload["live_ui_requested"] is True
    assert payload["browser_enabled"] is False
    assert payload["provider_calls_enabled"] is False
    assert payload["summary"]["screenshots_captured"] == 0


def test_ui_harness_rejects_third_party_url_even_in_dry_run(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, ["ui-harness", "plan", "--config", str(EXTERNAL_FIXTURE), "--out-dir", str(tmp_path / "external"), "--dry-run"])

    assert result.exit_code != 0
    assert "fail-closed" in result.output
    assert "third-party" in result.output
    assert not (tmp_path / "external" / "ui-harness-plan.json").exists()
