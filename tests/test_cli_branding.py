from __future__ import annotations

import re

from typer.testing import CliRunner

from malleus.cli import app
from malleus.cli_branding import MALLEUS_ASCII, render_command_summary, render_success

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _help_has_option(output: str, option: str) -> bool:
    plain = _ANSI_RE.sub("", output)
    return option in plain or option.replace("--", "-", 1) in plain


def test_cli_info_renders_branded_splash() -> None:
    runner = CliRunner()

    result = runner.invoke(app, ["info"])

    assert result.exit_code == 0
    assert "MALLEUS" in result.output
    assert "Audit" in result.output
    assert "agent security" in result.output.lower()
    assert "benchmark soft" in result.output
    assert "Dry-run and provider-free outputs are planning" in result.output


def test_cli_version_stays_script_friendly() -> None:
    runner = CliRunner()

    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert result.output.strip().startswith("malleus-evals ")
    assert "MALLEUS" not in result.output


def test_public_root_help_hides_internal_lab_commands() -> None:
    result = CliRunner().invoke(app, ["--help"], env={"COLUMNS": "200"})

    assert result.exit_code == 0
    for command in ("quickstart", "init", "doctor", "target", "bundle", "agent", "benchmark", "findings", "audit", "run", "dashboard", "evidence-bundle", "compare"):
        assert command in result.output
    for command in ("agent-lab", "visual-lab", "safety-tune", "ui-harness", "studio", "workspace", "threat-model", "mutate-run", "mutations", "campaign", "challenge", "rag"):
        assert command not in result.output


def test_public_benchmark_help_hides_internal_planning_commands() -> None:
    result = CliRunner().invoke(app, ["benchmark", "--help"], env={"COLUMNS": "200"})

    assert result.exit_code == 0
    for command in ("soft", "exterminatus", "live-rag", "live-agentic", "live-workflow", "live-code-agent", "live-memory-agent", "live-multi-agent", "live-browser-agent"):
        assert command in result.output
    for command in ("plan", "summarize", "validate-matrix", "suite", "live-full", "live-self-modification"):
        assert command not in result.output


def test_public_run_and_benchmark_help_hide_advanced_flags() -> None:
    run_help = CliRunner().invoke(app, ["run", "--help"], env={"COLUMNS": "200"}).output
    soft_help = CliRunner().invoke(app, ["benchmark", "soft", "--help"], env={"COLUMNS": "200"}).output

    assert _help_has_option(run_help, "--target")
    assert _help_has_option(run_help, "--out-dir")
    assert _help_has_option(run_help, "--dry-run")
    assert not _help_has_option(run_help, "--repeats")
    assert not _help_has_option(run_help, "--temperature-schedule")
    assert not _help_has_option(run_help, "--config-dir")
    assert _help_has_option(soft_help, "--target")
    assert _help_has_option(soft_help, "--out-dir")
    assert not _help_has_option(soft_help, "--yes")
    assert _help_has_option(soft_help, "--trace-log")
    for flag in ("--matrix", "--mutation-profile", "--concurrency", "--request-timeout", "--max-retries", "--config-dir"):
        assert not _help_has_option(soft_help, flag)


def test_public_target_and_agent_help_hide_advanced_flags() -> None:
    target_init_help = CliRunner().invoke(app, ["target", "init", "--help"], env={"COLUMNS": "200"}).output
    doctor_help = CliRunner().invoke(app, ["target", "doctor", "--help"], env={"COLUMNS": "200"}).output
    serve_help = CliRunner().invoke(app, ["agent", "serve", "--help"], env={"COLUMNS": "200"}).output

    assert _help_has_option(target_init_help, "--provider")
    assert _help_has_option(target_init_help, "--model")
    assert _help_has_option(target_init_help, "--save-api-key")
    for flag in ("--timeout", "--max-tokens", "--temperature", "--top-p", "--env-file", "--non-interactive"):
        assert not _help_has_option(target_init_help, flag)
    assert _help_has_option(doctor_help, "--live-check")
    assert not _help_has_option(doctor_help, "--probe-endpoint")
    assert not _help_has_option(doctor_help, "--surface")
    assert _help_has_option(serve_help, "--target-type")
    assert _help_has_option(serve_help, "--framework")
    assert _help_has_option(serve_help, "--isolated")
    for flag in ("--host", "--port", "--route", "--cwd", "--network-mode", "--tool-policy"):
        assert not _help_has_option(serve_help, flag)


def test_branding_helpers_render_plain_text_without_ansi_when_disabled() -> None:
    summary = render_command_summary("Assessment complete", {"Mode": "dry_run", "Artifacts": "out"}, color=False)
    success = render_success("Evidence written", color=False)

    assert "Assessment complete" in summary
    assert "Mode" in summary
    assert "dry_run" in summary
    assert "✓ Evidence written" in success
    assert "\x1b[" not in summary
    assert "\x1b[" not in success
    assert "MALLEUS" in MALLEUS_ASCII
