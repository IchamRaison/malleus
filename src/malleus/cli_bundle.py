from __future__ import annotations

import json
from pathlib import Path

import typer
from pydantic import ValidationError

from malleus.cli_apps import bundle_app
from malleus.cli_errors import format_cli_error
from malleus.target_bundle import (
    doctor_target_bundle,
    load_target_bundle,
    make_reference_bundle,
    managed_bundle_path,
    resolve_bundle,
    write_target_bundle,
)
from malleus.target_store import TargetStoreError


@bundle_app.command("init")
def bundle_init_command(
    model_target: str = typer.Option(
        ..., "--model-target", help="Managed target name or YAML path for the backing chat/vision model"
    ),
    name: str | None = typer.Option(
        None, "--name", help="Bundle name; defaults to <model-target>-reference"
    ),
    out: Path | None = typer.Option(
        None,
        "--out",
        dir_okay=False,
        help="Write bundle YAML here; defaults to the managed bundle directory",
    ),
    overwrite: bool = typer.Option(False, "--overwrite", help="Replace an existing bundle file"),
) -> None:
    """Create a portable target bundle skeleton for full trace-backed runs."""
    bundle_name = name or f"{Path(str(model_target)).stem}-reference"
    bundle = make_reference_bundle(bundle_name, model_target)
    destination = out if out is not None else managed_bundle_path(bundle.name)
    try:
        path = write_target_bundle(bundle, destination, overwrite=overwrite)
    except TargetStoreError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Target bundle written: {path}")
    typer.echo(f"Model target: {bundle.model_target}")
    typer.echo("Surfaces:")
    for surface, config in bundle.surfaces.items():
        typer.echo(f"  - {surface}: {config.target} ({config.required_target_type})")
    typer.echo(f"Next: malleus bundle doctor {path}")


@bundle_app.command("doctor")
def bundle_doctor_command(
    reference: str = typer.Argument(..., help="Managed bundle name or bundle YAML path"),
    config_dir: Path | None = typer.Option(
        None, "--config-dir", file_okay=False, help="Managed target directory", hidden=True
    ),
    bundle_dir: Path | None = typer.Option(
        None, "--bundle-dir", file_okay=False, help="Managed bundle directory", hidden=True
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Emit machine-readable bundle doctor result"
    ),
) -> None:
    """Validate that a target bundle can exercise every declared surface."""
    try:
        bundle_path = resolve_bundle(reference, bundle_dir)
        report = doctor_target_bundle(bundle_path, target_dir=config_dir)
    except (TargetStoreError, ValueError, ValidationError, OSError) as exc:
        detail = format_cli_error(exc) if isinstance(exc, (ValueError, ValidationError)) else str(exc)
        typer.echo(f"bundle_doctor: failed - {detail}", err=True)
        raise typer.Exit(code=1) from exc
    if json_output:
        typer.echo(json.dumps(report.to_dict(), indent=2))
    else:
        typer.echo(f"bundle_doctor: {'ok' if report.ok else 'failed'}")
        typer.echo(f"bundle: {report.bundle.name}")
        typer.echo(
            f"model: {report.model_status} - {report.bundle.model_target} "
            f"({report.model_target_type or 'unresolved'})"
        )
        typer.echo("surfaces:")
        for check in report.surface_checks:
            symbol = "✓" if check.status == "passed" else "✗"
            typer.echo(
                f"  {symbol} {check.surface}: {check.status} - {check.target_reference} "
                f"(required={check.required_target_type}, actual={check.target_type or 'unresolved'})"
            )
            if check.status != "passed":
                typer.echo(f"      {check.message}")
    if not report.ok:
        raise typer.Exit(code=1)


@bundle_app.command("show")
def bundle_show_command(
    reference: str = typer.Argument(..., help="Managed bundle name or bundle YAML path"),
    bundle_dir: Path | None = typer.Option(
        None, "--bundle-dir", file_okay=False, help="Managed bundle directory", hidden=True
    ),
) -> None:
    try:
        bundle_path = resolve_bundle(reference, bundle_dir)
        bundle = load_target_bundle(bundle_path)
    except (TargetStoreError, ValueError, ValidationError, OSError) as exc:
        detail = format_cli_error(exc) if isinstance(exc, (ValueError, ValidationError)) else str(exc)
        typer.echo(f"bundle_show: failed - {detail}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"bundle: {bundle.name}")
    typer.echo(f"schema_version: {bundle.schema_version}")
    typer.echo(f"mode: {bundle.mode}")
    typer.echo(f"model_target: {bundle.model_target}")
    typer.echo("surfaces:")
    for surface, config in bundle.surfaces.items():
        typer.echo(f"  - {surface}: {config.target} ({config.required_target_type})")
