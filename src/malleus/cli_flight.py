from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Literal

import typer

from malleus.attack_graph import (
    PublicBenchmarkReport,
    build_public_leaderboard,
    build_adaptive_attack_graph,
    load_public_benchmark,
    score_public_benchmark,
)
from malleus.cli_apps import flight_app
from malleus.flight_recorder import (
    FlightEvent,
    FlightRecording,
    InvariantSet,
    build_replay_bundle,
    evaluate_invariants,
    ingest_trace,
    load_invariant_set,
    sign_evidence_directory,
    verify_evidence_directory,
    write_recording,
)
from malleus.organization import OrganizationEvidenceStore
from malleus.integration_clients import submit_issue
from malleus.resources import resource_path
from malleus.remediation import (
    RemediationGatePolicy,
    ReviewRecord,
    calibrate_verdicts,
    compare_remediation,
    evaluate_remediation_gate,
    generate_regression_pack,
    integration_issue_payload,
    load_calibration_items,
    load_recording,
    write_json_model,
    write_regression_pack,
)


@flight_app.command("capture")
def capture_command(
    trace: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    invariants: Path = typer.Option(
        resource_path("configs/invariants-default.yaml"),
        "--invariants",
        exists=True,
        dir_okay=False,
        readable=True,
    ),
    source_format: str = typer.Option("auto", "--format"),
    out: Path = typer.Option(Path("flight-recording.json"), "--out", dir_okay=False),
) -> None:
    """Import a trace, reconstruct causality, and evaluate authorization invariants."""
    recording = evaluate_invariants(
        ingest_trace(trace, source_format=source_format), load_invariant_set(invariants)
    )
    write_recording(recording, out)
    typer.echo(f"Recording: {out}")
    typer.echo(f"Events: {len(recording.events)}")
    typer.echo(f"Violations: {len(recording.violations)}")


@flight_app.command("investigate")
def investigate_command(
    recording_path: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    out: Path = typer.Option(Path("attack-graph.json"), "--out", dir_okay=False),
) -> None:
    """Build a causal attack graph and recommend the next security probes."""
    graph = build_adaptive_attack_graph(load_recording(recording_path))
    write_json_model(graph, out)
    typer.echo(f"Attack graph: {out}")
    typer.echo(f"Recommended scenarios: {', '.join(graph.recommended_scenarios) or 'none'}")


@flight_app.command("replay")
def replay_command(
    recording_path: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    violation: str = typer.Option(..., "--violation"),
    invariants: Path = typer.Option(
        resource_path("configs/invariants-default.yaml"),
        "--invariants",
        exists=True,
        dir_okay=False,
        readable=True,
    ),
    out: Path = typer.Option(Path("causal-replay.json"), "--out", dir_okay=False),
) -> None:
    payload = build_replay_bundle(
        load_recording(recording_path), load_invariant_set(invariants), violation
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    typer.echo(f"Replay: {out}")


@flight_app.command("sign")
def sign_command(
    directory: Path = typer.Argument(..., exists=True, file_okay=False, readable=True),
    key_id: str = typer.Option(..., "--key-id"),
    key_env: str = typer.Option("MALLEUS_SIGNING_KEY", "--key-env"),
) -> None:
    key = os.environ.get(key_env)
    if not key:
        raise typer.BadParameter(f"missing signing key environment variable: {key_env}")
    manifest = sign_evidence_directory(directory, key=key, key_id=key_id)
    typer.echo(f"Signed {len(manifest.entries)} artifacts: {directory / 'signed-manifest.json'}")


@flight_app.command("verify")
def verify_command(
    directory: Path = typer.Argument(..., exists=True, file_okay=False, readable=True),
    manifest: Path = typer.Option(..., "--manifest", exists=True, dir_okay=False),
    key_env: str = typer.Option("MALLEUS_SIGNING_KEY", "--key-env"),
) -> None:
    key = os.environ.get(key_env)
    if not key:
        raise typer.BadParameter(f"missing signing key environment variable: {key_env}")
    valid, errors = verify_evidence_directory(directory, manifest, key=key)
    typer.echo(json.dumps({"valid": valid, "errors": errors}, indent=2))
    if not valid:
        raise typer.Exit(code=1)


@flight_app.command("regression-generate")
def regression_generate_command(
    recording_path: Path = typer.Argument(..., exists=True, dir_okay=False),
    out: Path = typer.Option(Path("security-regressions.yaml"), "--out", dir_okay=False),
) -> None:
    pack = generate_regression_pack(load_recording(recording_path))
    write_regression_pack(pack, out)
    typer.echo(f"Regression pack: {out} ({len(pack.scenarios)} scenarios)")


@flight_app.command("compare")
def compare_command(
    baseline: Path = typer.Option(..., "--baseline", exists=True, dir_okay=False),
    candidate: Path = typer.Option(..., "--candidate", exists=True, dir_okay=False),
    out: Path = typer.Option(Path("remediation-comparison.json"), "--out", dir_okay=False),
) -> None:
    comparison = compare_remediation(load_recording(baseline), load_recording(candidate))
    write_json_model(comparison, out)
    typer.echo(f"Fixed: {len(comparison.fixed)}")
    typer.echo(f"Remaining: {len(comparison.remaining)}")
    typer.echo(f"Introduced: {len(comparison.introduced)}")


@flight_app.command("gate")
def gate_command(
    baseline: Path = typer.Option(..., "--baseline", exists=True, dir_okay=False),
    candidate: Path = typer.Option(..., "--candidate", exists=True, dir_okay=False),
    max_violations: int | None = typer.Option(None, "--max-violations", min=0),
    out: Path = typer.Option(Path("remediation-gate.json"), "--out", dir_okay=False),
) -> None:
    baseline_recording = load_recording(baseline)
    candidate_recording = load_recording(candidate)
    result = evaluate_remediation_gate(
        compare_remediation(baseline_recording, candidate_recording),
        candidate_recording,
        RemediationGatePolicy(max_candidate_violations=max_violations),
    )
    write_json_model(result, out)
    typer.echo(json.dumps(result.model_dump(mode="json"), indent=2))
    if result.status == "fail":
        raise typer.Exit(code=1)


@flight_app.command("calibrate")
def calibrate_command(
    labels: Path = typer.Argument(..., exists=True, dir_okay=False),
    out: Path = typer.Option(Path("verdict-calibration.json"), "--out", dir_okay=False),
) -> None:
    report = calibrate_verdicts(load_calibration_items(labels))
    write_json_model(report, out)
    typer.echo(f"Precision: {report.precision:.3f}")
    typer.echo(f"Recall: {report.recall:.3f}")
    typer.echo(f"False-positive rate: {report.false_positive_rate:.3f}")


@flight_app.command("review")
def review_command(
    violation: str = typer.Option(..., "--violation"),
    status: Literal["confirmed", "false_positive", "accepted_risk", "needs_evidence"] = typer.Option(..., "--status"),
    reviewer: str = typer.Option(..., "--reviewer"),
    rationale: str = typer.Option(..., "--rationale"),
    out: Path = typer.Option(Path("finding-review.json"), "--out", dir_okay=False),
) -> None:
    write_json_model(
        ReviewRecord(
            violation_id=violation,
            status=status,
            reviewer=reviewer,
            rationale=rationale,
        ),
        out,
    )
    typer.echo(f"Review: {out}")


@flight_app.command("export-issue")
def export_issue_command(
    recording_path: Path = typer.Argument(..., exists=True, dir_okay=False),
    violation: str = typer.Option(..., "--violation"),
    platform: Literal["github", "gitlab", "jira"] = typer.Option(..., "--platform"),
    project: str | None = typer.Option(None, "--project"),
    submit: bool = typer.Option(False, "--submit", help="Create the issue through the remote API"),
    base_url: str | None = typer.Option(None, "--base-url"),
    token_env: str = typer.Option("MALLEUS_ISSUE_TOKEN", "--token-env"),
    out: Path = typer.Option(Path("issue-payload.json"), "--out", dir_okay=False),
) -> None:
    recording = load_recording(recording_path)
    item = next((entry for entry in recording.violations if entry.violation_id == violation), None)
    if item is None:
        raise typer.BadParameter(f"unknown violation: {violation}")
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = integration_issue_payload(item, platform=platform, project=project)
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    typer.echo(f"{platform} issue payload: {out}")
    if submit:
        if not base_url or not project:
            raise typer.BadParameter("--submit requires --base-url and --project")
        token = os.environ.get(token_env)
        if not token:
            raise typer.BadParameter(f"missing issue token environment variable: {token_env}")
        result = submit_issue(
            platform=platform,
            base_url=base_url,
            project=project,
            token=token,
            payload=payload,
        )
        typer.echo(json.dumps({"submitted": True, "result": result}, indent=2))


@flight_app.command("organization-add")
def organization_add_command(
    recording_path: Path = typer.Argument(..., exists=True, dir_okay=False),
    organization: str = typer.Option(..., "--organization"),
    project: str = typer.Option(..., "--project"),
    store: Path = typer.Option(Path(".malleus/organization.db"), "--store"),
) -> None:
    run = OrganizationEvidenceStore(store).add_recording(
        organization, project, load_recording(recording_path)
    )
    typer.echo(run.model_dump_json(indent=2))


@flight_app.command("organization-trend")
def organization_trend_command(
    organization: str = typer.Option(..., "--organization"),
    project: str | None = typer.Option(None, "--project"),
    store: Path = typer.Option(Path(".malleus/organization.db"), "--store"),
) -> None:
    typer.echo(
        OrganizationEvidenceStore(store)
        .trend(organization, project=project)
        .model_dump_json(indent=2)
    )


@flight_app.command("benchmark-info")
def benchmark_info_command(
    benchmark: Path = typer.Option(
        resource_path("datasets/public_benchmark/agent-security-v1.yaml"),
        "--benchmark",
        exists=True,
        dir_okay=False,
    ),
) -> None:
    loaded = load_public_benchmark(benchmark)
    typer.echo(loaded.model_dump_json(indent=2))


@flight_app.command("benchmark-score")
def benchmark_score_command(
    recording_path: Path = typer.Argument(..., exists=True, dir_okay=False),
    benchmark: Path = typer.Option(
        resource_path("datasets/public_benchmark/agent-security-v1.yaml"),
        "--benchmark",
        exists=True,
        dir_okay=False,
    ),
    out: Path = typer.Option(Path("agent-security-benchmark-report.json"), "--out"),
) -> None:
    report = score_public_benchmark(
        load_recording(recording_path), load_public_benchmark(benchmark)
    )
    write_json_model(report, out)
    typer.echo(f"Invariant preservation: {report.invariant_preservation_rate:.1%}")
    typer.echo(f"Trace coverage: {report.trace_coverage_rate:.1%}")
    typer.echo(f"Operational completion: {report.operational_completion_rate:.1%}")


@flight_app.command("schema")
def schema_command(
    out_dir: Path = typer.Option(Path("schemas/flight-recorder"), "--out-dir", file_okay=False),
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    schemas = {
        "flight-event.schema.json": FlightEvent.model_json_schema(),
        "flight-recording.schema.json": FlightRecording.model_json_schema(),
        "security-invariants.schema.json": InvariantSet.model_json_schema(),
    }
    for name, schema in schemas.items():
        (out_dir / name).write_text(json.dumps(schema, indent=2), encoding="utf-8")
    typer.echo(f"Schemas: {out_dir} ({len(schemas)} files)")


@flight_app.command("leaderboard")
def leaderboard_command(
    report: list[Path] = typer.Option(..., "--report", exists=True, dir_okay=False),
    target: list[str] = typer.Option(..., "--target"),
    out: Path = typer.Option(Path("agent-security-leaderboard.json"), "--out"),
) -> None:
    if len(report) != len(target):
        raise typer.BadParameter("repeat --target once for every --report")
    loaded = [
        (
            target_name,
            report_path,
            PublicBenchmarkReport.model_validate_json(report_path.read_text(encoding="utf-8")),
        )
        for target_name, report_path in zip(target, report, strict=True)
    ]
    leaderboard = build_public_leaderboard(loaded)
    write_json_model(leaderboard, out)
    typer.echo(f"Leaderboard: {out} ({len(leaderboard.entries)} targets)")
