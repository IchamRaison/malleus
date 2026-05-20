from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import typer

from malleus.cli_doctor import build_project_doctor_report, render_project_doctor, write_project_doctor
from malleus.cli_quickstart import render_quickstart


TargetInitCallable = Callable[..., Any]


def register_onboarding_commands(app: typer.Typer, *, target_init: TargetInitCallable, provider_choices_label: Callable[[], str]) -> None:
    @app.command("quickstart")
    def quickstart_command(
        target: str | None = typer.Option(None, "--target", help="Managed target name or target YAML path to show concrete next commands"),
        out_dir: Path = typer.Option(Path("reports/malleus-quickstart"), "--out-dir", file_okay=False, help="Suggested report directory"),
    ) -> None:
        """Show the shortest path from a model key to a useful Malleus report."""

        typer.echo(render_quickstart(target=target, out_dir=out_dir))

    @app.command("init")
    def init_command(
        provider: str | None = typer.Option(None, "--provider", help=f"Provider preset: {provider_choices_label()}"),
        model: str | None = typer.Option(None, "--model", help="Model id; for presets this can also be a suggested model number"),
        name: str | None = typer.Option(None, "--name", help="Target name; defaults to provider-model"),
        base_url: str | None = typer.Option(None, "--base-url", help="OpenAI-compatible API base URL; required for custom providers"),
        api_key_env: str | None = typer.Option(None, "--api-key-env", help="Environment variable name containing the API key"),
        out: Path | None = typer.Option(None, "--out", dir_okay=False, help="Write a target YAML at this exact path instead of the managed target store"),
        config_dir: Path | None = typer.Option(None, "--config-dir", file_okay=False, help="Managed target directory when --out is not used"),
        save_api_key: bool | None = typer.Option(None, "--save-api-key/--no-save-api-key", help="Prompt for the API key and write it to --env-file"),
        env_file: Path = typer.Option(Path(".env"), "--env-file", dir_okay=False, help="Local env file used with --save-api-key"),
        overwrite: bool = typer.Option(False, "--overwrite", help="Replace an existing target YAML"),
        non_interactive: bool = typer.Option(False, "--non-interactive", help="Use preset defaults and fail instead of prompting for missing custom fields"),
        live_check: bool = typer.Option(False, "--live-check", help="Run a live provider preflight after writing the target"),
    ) -> None:
        """Guided first-run setup: create a target, then show the next benchmark path."""

        target_init(
            provider=provider,
            model=model,
            name=name,
            base_url=base_url,
            api_key_env=api_key_env,
            timeout=180.0,
            max_tokens=None,
            temperature=0.0,
            top_p=None,
            out=out,
            config_dir=config_dir,
            save_api_key=save_api_key,
            env_file=env_file,
            overwrite_env=False,
            overwrite=overwrite,
            non_interactive=non_interactive,
            probe_provider=live_check,
        )
        typer.echo("")
        typer.echo("Next benchmark path:")
        target_reference = str(out) if out is not None else (name or "<target-name>")
        typer.echo(render_quickstart(target=target_reference))

    @app.command("doctor")
    def project_doctor_command(
        config_dir: Path | None = typer.Option(None, "--config-dir", file_okay=False, help="Managed target directory to inspect"),
        out_dir: Path | None = typer.Option(None, "--out-dir", file_okay=False, help="Write project-doctor.json"),
        json_output: bool = typer.Option(False, "--json", help="Print machine-readable JSON"),
    ) -> None:
        """Check local install, packaged assets, optional integrations, sandbox tools, and managed targets."""

        report = build_project_doctor_report(config_dir=config_dir)
        if out_dir is not None:
            path = write_project_doctor(report, out_dir)
            report["output_path"] = str(path)
        if json_output:
            typer.echo(json.dumps(report, indent=2, sort_keys=True))
        else:
            typer.echo(render_project_doctor(report))
