from __future__ import annotations

import json
import os
import socket
import sys
import textwrap
from datetime import datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import httpx
import typer
from pydantic import ValidationError
from malleus.adjudication import AdjudicationStatus, adjudicate_finding
from malleus.agent_adapter import AgentAdapterError, load_agent_adapter, serve_agent_adapter, serve_agent_adapter_isolated
from malleus.agent_frameworks.generic import load_generic_agent_adapter, serve_generic_agent_adapter
from malleus.agent_frameworks.langgraph import load_langgraph_adapter, serve_langgraph_adapter
from malleus.agent_frameworks.openai_agents import load_openai_agents_adapter, serve_openai_agents_adapter
from malleus.agent_frameworks.rag import load_langchain_rag_adapter, load_llamaindex_rag_adapter, serve_langchain_rag_adapter, serve_llamaindex_rag_adapter
from malleus.agent_target_contracts import AGENT_FRAMEWORKS, L2_TARGET_TYPES, doctor_agent_target, scaffold_agent_target, validate_agent_target
from malleus.assessment import run_assessment
from malleus.assessment_catalog import load_assessment_catalog
from malleus.assessment_schemas import AssessmentMode
from malleus.agent_lab import run_agent_lab
from malleus.agent_trace import load_agent_trace_collection, render_agent_trace_summary
from malleus.anomaly import inspect_output, report_from_file, write_anomaly_report
from malleus.artifact_firewall import inspect_artifact, write_artifact_firewall_report
from malleus.benchmark_suite import run_benchmark_suite
from malleus.benchmark_workflow import summarize_benchmark_reports, write_benchmark_plan
from malleus.challenge_runner import run_challenge
from malleus.cli_branding import render_splash
from malleus.cli_onboarding import register_onboarding_commands
from malleus.code_agent import inspect_code_agent_trace
from malleus.compound_risk import build_compound_risk_report, write_compound_risk_report
from malleus.coverage import build_coverage_report, write_coverage_report
from malleus.dashboard import write_dashboard
from malleus.datasets import load_mutation_profile, load_release_matrix, load_target_config, validate_mutation_profile_pair
from malleus.diff_runs import diff_run_reports, write_diff_report
from malleus.evidence_bundle import build_evidence_bundle, write_evidence_bundle
from malleus.campaign_runner import run_campaign
from malleus.findings import find_finding, load_or_collect_findings, write_finding_artifacts
from malleus.gates import evaluate_report_file
from malleus.hidden_channels import inspect_text, write_hidden_channel_report
from malleus.interop import export_findings, import_external_results, supported_export_formats, supported_import_sources
from malleus.issue_export import export_issues_from_findings
from malleus.live_full import DEFAULT_DEEP_MUTATION_PROFILE_PATH, DEFAULT_RELEASE_MATRIX_PATH, DEFAULT_SELECTED_MUTATION_PROFILE_PATH, run_exterminatus_benchmark, run_live_full_matrix, run_live_surface_pack, run_soft_benchmark
from malleus.live_preflight import DEFAULT_PREFLIGHT_MAX_RETRIES, DEFAULT_PREFLIGHT_TIMEOUT, run_target_preflight, safe_endpoint_from_url
from malleus.model_universe import infer_provider_id, model_universe_metadata, provider_catalog, provider_compatibility_matrix, provider_ids, provider_presets_for_cli
from malleus.patches import suggest_patch_for_finding
from malleus.plugin_scanner import scan_plugin_manifest
from malleus.prod_readiness import build_prod_readiness_report, render_prod_readiness, write_prod_readiness_report
from malleus.provider_protocol import provider_protocol_report
from malleus.refusal_classifier import classify_refusal
from malleus.regression import validate_regression_pack, write_regression_pack, write_regression_validation
from malleus.resources import resource_path
from malleus.mutate_run import run_mutation_benchmark
from malleus.mutations import get_mutation, mutate_prompt, mutation_names, mutation_specs
from malleus.rag_harness import run_rag_fixture
from malleus.rescore import rescore_provider_free
from malleus.runner import compare_models, enumerate_items, run_benchmark
from malleus.safety_tuner import DEFAULT_SCORING_PATH, parse_number_grid, run_safety_tuning
from malleus.scenario_generator import REVIEW_STATUS_DRAFT, generate_defensive_scenario
from malleus.self_modification import inspect_self_modification
from malleus.studio import export_studio
from malleus.target_store import (
    TargetStoreError,
    add_managed_target,
    derive_api_key_env,
    list_managed_targets,
    remove_managed_target,
    resolve_target,
    sanitize_target_name,
    show_managed_target,
    write_target_file,
)
from malleus.target_bundle import (
    SURFACE_PACK_IDS,
    doctor_target_bundle,
    is_target_bundle_file,
    load_target_bundle,
    make_reference_bundle,
    managed_bundle_path,
    resolve_bundle,
    write_target_bundle,
)
from malleus.taxonomy_garden import write_taxonomy_diff, write_taxonomy_snapshot
from malleus.threat_model import SUPPORTED_PROFILES, init_threat_model, load_threat_model, threat_model_coverage_status, threat_model_status, write_threat_model
from malleus.tool_gateway import default_tool_policy, load_tool_policy
from malleus.trace_diff import diff_traces, write_trace_diff_report
from malleus.triage import deterministic_triage_summary
from malleus.ui_harness import write_ui_harness_plan, write_ui_harness_report
from malleus.replay import replay_finding
from malleus.validation import validate_input_path
from malleus.v1_readiness import build_v1_readiness_report, render_v1_readiness, write_v1_readiness_report
from malleus.visual_lab import generate_visual_lab_fixtures, inspect_visual_lab, run_vision_fixture
from malleus.workspace import init_workspace, inspect_workspace, render_workspace_next, render_workspace_status
from malleus.utils.redact import redact_public_text

app = typer.Typer(help="Malleus defensive LLM evaluation harness")
mutations_app = typer.Typer(help="Inspect available prompt mutation transforms")
findings_app = typer.Typer(help="List, show, and export reportable security findings")
issues_app = typer.Typer(help="Export local remediation issues from Malleus findings")
patch_app = typer.Typer(help="Generate defensive patch suggestion artifacts")
campaign_app = typer.Typer(help="Run deterministic multi-step defensive campaigns")
challenge_app = typer.Typer(help="Run local deterministic artifact challenges")
rag_app = typer.Typer(help="Run local fixture RAG security harness checks")
coverage_app = typer.Typer(help="Build attack-surface coverage artifacts")
threat_model_app = typer.Typer(help="Initialize and inspect offline threat models")
workspace_app = typer.Typer(help="Manage local artifact-backed workspaces")
benchmark_app = typer.Typer(help="Run live benchmarks")
visual_lab_app = typer.Typer(help="Generate provider-free visual and artifact fixtures")
safety_tune_app = typer.Typer(help="Explore provider-free safety risk surfaces across decoding parameters")
code_agent_app = typer.Typer(help="Inspect local code-agent VCS and lifecycle traces")
scenario_app = typer.Typer(help="Generate defensive draft scenario artifacts")
regression_app = typer.Typer(help="Generate and validate provider-free regression packs")
self_mod_app = typer.Typer(help="Inspect proposed self-modification diffs and traces")
studio_app = typer.Typer(help="Export a static sanitized studio narrative")
taxonomy_app = typer.Typer(help="Write taxonomy garden snapshots and diffs")
ui_harness_app = typer.Typer(help="Plan provider-free local/staging UI harness scaffolds")
target_app = typer.Typer(help="Manage reusable target model configurations")
bundle_app = typer.Typer(help="Manage target bundles for full trace-backed agent runs")
agent_app = typer.Typer(help="Serve and inspect real external-agent adapters")
audit_app = typer.Typer(help="Audit generated reports for suspected false positives and weak evidence")


def _parse_temperature_schedule(value: str | None) -> list[float] | None:
    if value is None or not value.strip():
        return None
    schedule: list[float] = []
    for part in value.split(","):
        stripped = part.strip()
        if not stripped:
            continue
        try:
            temperature = float(stripped)
        except ValueError as exc:
            raise typer.BadParameter("temperature schedule must be comma-separated numbers") from exc
        if temperature < 0:
            raise typer.BadParameter("temperature schedule values must be non-negative")
        schedule.append(temperature)
    return schedule or None


def _default_report_dir(target: str, mode: str) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return Path("reports") / f"{sanitize_target_name(target)}-{sanitize_target_name(mode)}-{stamp}"


def _print_report_next_steps(out_dir: Path, *, json_path: Path | None = None, markdown_path: Path | None = None, html_path: Path | None = None) -> None:
    typer.echo("")
    typer.echo("Report artifacts:")
    if markdown_path is not None:
        typer.echo(f"  Markdown: {markdown_path}")
    if html_path is not None:
        typer.echo(f"  HTML: {html_path}")
    if json_path is not None:
        typer.echo(f"  JSON: {json_path}")
    typer.echo(f"  Directory: {out_dir}")


def _parse_assessment_packs(value: str) -> list[str]:
    packs = [part.strip() for part in value.split(",") if part.strip()]
    return packs or ["default"]


def _package_version() -> str:
    try:
        return version("malleus-evals")
    except PackageNotFoundError:
        return "unknown"

app.add_typer(mutations_app, name="mutations", hidden=True)
app.add_typer(findings_app, name="findings")
app.add_typer(issues_app, name="issues", hidden=True)
app.add_typer(patch_app, name="patch", hidden=True)
app.add_typer(campaign_app, name="campaign", hidden=True)
app.add_typer(challenge_app, name="challenge", hidden=True)
app.add_typer(rag_app, name="rag", hidden=True)
app.add_typer(coverage_app, name="coverage", hidden=True)
app.add_typer(threat_model_app, name="threat-model", hidden=True)
app.add_typer(workspace_app, name="workspace", hidden=True)
app.add_typer(benchmark_app, name="benchmark")
app.add_typer(visual_lab_app, name="visual-lab", hidden=True)
app.add_typer(safety_tune_app, name="safety-tune", hidden=True)
app.add_typer(code_agent_app, name="code-agent", hidden=True)
app.add_typer(scenario_app, name="scenario", hidden=True)
app.add_typer(regression_app, name="regression", hidden=True)
app.add_typer(self_mod_app, name="self-mod", hidden=True)
app.add_typer(studio_app, name="studio", hidden=True)
app.add_typer(taxonomy_app, name="taxonomy", hidden=True)
app.add_typer(ui_harness_app, name="ui-harness", hidden=True)
app.add_typer(target_app, name="target")
app.add_typer(bundle_app, name="bundle")
app.add_typer(agent_app, name="agent")
app.add_typer(audit_app, name="audit")

CORE_MUTATION_INPUT_PATH = resource_path("datasets/benchmark_packs/core-v1.yaml")
DEFAULT_RUN_INPUT_PATH = resource_path("datasets/benchmark_packs/smoke-v1.yaml")
DEEP_MUTATION_PROFILE_PATH = resource_path("datasets/mutation_profiles/deep-v1.yaml")


OPENAI_COMPATIBLE_PROVIDER_PRESETS: dict[str, dict[str, object]] = provider_presets_for_cli()


def _provider_choices_label() -> str:
    return ", ".join([*OPENAI_COMPATIBLE_PROVIDER_PRESETS, "custom"])


def _provider_menu_options() -> list[str]:
    return provider_ids(include_custom=True)


def _prompt_choice(label: str, options: list[str], *, default_index: int = 1) -> str:
    typer.echo(f"{label}:")
    for index, option in enumerate(options, start=1):
        preset = _provider_preset(option)
        suffix = f" - {preset['label']}" if preset and preset.get("label") else ""
        typer.echo(f"  {index}. {option}{suffix}")
    selected = typer.prompt("Choice number or name", default=str(default_index)).strip()
    return _resolve_numbered_choice(selected, options)


def _resolve_numbered_choice(value: str, options: list[str]) -> str:
    raw = value.strip()
    if raw.isdigit():
        index = int(raw) - 1
        if 0 <= index < len(options):
            return options[index]
    lowered = raw.lower()
    for option in options:
        if lowered == option.lower():
            return option
    raise typer.BadParameter(f"unknown choice: {value}. Expected one of: {', '.join(options)}")


def _request_options(timeout: float | None, max_tokens: int | None, temperature: float | None, top_p: float | None) -> dict[str, object]:
    request: dict[str, object] = {}
    if timeout is not None:
        request["timeout"] = timeout
    if max_tokens is not None:
        request["max_tokens"] = max_tokens
    if temperature is not None:
        request["temperature"] = temperature
    if top_p is not None:
        request["top_p"] = top_p
    return request


def _provider_preset(provider: str) -> dict[str, object] | None:
    return OPENAI_COMPATIBLE_PROVIDER_PRESETS.get(provider.strip().lower())


def _default_target_name(provider: str, model: str) -> str:
    base = f"{provider.strip().lower()}-{model.strip()}".replace("/", "-").replace(":", "-")
    return sanitize_target_name(base)


def _resolve_prompted_model(provider: str, model_input: str | None, preset: dict[str, object] | None, *, interactive: bool) -> str:
    models = [str(item) for item in (preset or {}).get("models", []) if item]
    return _resolve_prompted_model_from_options(provider, model_input, models, interactive=interactive)


def _resolve_prompted_model_from_options(provider: str, model_input: str | None, models: list[str], *, interactive: bool) -> str:
    if model_input:
        raw = model_input.strip()
        if raw.isdigit() and models:
            index = int(raw) - 1
            if 0 <= index < len(models):
                return models[index]
        return raw
    if not models:
        if interactive:
            return typer.prompt("Model id")
        raise typer.BadParameter("--model is required for custom providers")
    if interactive:
        typer.echo("Available models:" if models else "Suggested models:")
        for index, suggested in enumerate(models, start=1):
            typer.echo(f"  {index}. {suggested}")
        selected = typer.prompt("Model id or number", default="1")
        if selected.strip().isdigit():
            index = int(selected.strip()) - 1
            if 0 <= index < len(models):
                return models[index]
        return selected.strip()
    return models[0]


def _env_file_has_key(path: Path, env_name: str) -> bool:
    if not path.exists():
        return False
    prefix = f"{env_name}="
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip().startswith(prefix):
            return True
    return False


def _read_env_file_value(path: Path, env_name: str) -> str | None:
    if not path.exists():
        return None
    prefix = f"{env_name}="
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped.startswith(prefix):
            continue
        value = stripped[len(prefix) :].strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            return value[1:-1]
        return value
    return None


def _shell_quote_env_value(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _write_env_key(path: Path, env_name: str, api_key: str, *, overwrite: bool = False) -> bool:
    path = path.expanduser()
    existing_lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    prefix = f"{env_name}="
    new_line = f"{env_name}={_shell_quote_env_value(api_key)}"
    replaced = False
    output: list[str] = []
    for line in existing_lines:
        if line.strip().startswith(prefix):
            if overwrite:
                output.append(new_line)
                replaced = True
            else:
                output.append(line)
                replaced = True
            continue
        output.append(line)
    if not replaced:
        output.append(new_line)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(output).rstrip() + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return not replaced or overwrite


def _credential_value(env_name: str, env_file: Path, *, fallback: str | None = None) -> str | None:
    return fallback or os.environ.get(env_name) or _read_env_file_value(env_file, env_name)


def _discover_provider_models(base_url: str, api_key: str | None, *, timeout: float) -> tuple[list[str], str | None]:
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    url = f"{_base_url_no_query(base_url).rstrip('/')}/models"
    try:
        response = httpx.get(url, headers=headers, timeout=timeout)
        if response.status_code >= 400:
            return [], f"models endpoint returned HTTP {response.status_code}"
        payload = response.json()
    except Exception as exc:  # pragma: no cover - defensive CLI boundary for network/provider failures
        return [], f"models endpoint check failed: {type(exc).__name__}"
    models = _extract_openai_compatible_model_ids(payload)
    return models, None if models else "models endpoint returned no model ids"


def _extract_openai_compatible_model_ids(payload: object) -> list[str]:
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if not isinstance(data, list):
        data = payload.get("models")
    ids: list[str] = []
    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            model_id = item.get("id") or item.get("name") or item.get("model")
            if isinstance(model_id, str) and model_id:
                ids.append(model_id)
    return sorted(dict.fromkeys(ids))


def _base_url_no_query(base_url: str) -> str:
    parsed = urlsplit(base_url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def _target_doctor_next_command(reference: str, *, config_dir: Path | None = None) -> str:
    command = f"malleus target doctor {reference}"
    if config_dir is not None:
        command += f" --config-dir {config_dir}"
    return f"{command} --live-check"


def _benchmark_smoke_command(reference: str | Path, target_name: str, *, config_dir: Path | None = None) -> str:
    command = f"malleus run --target {reference}"
    if config_dir is not None:
        command += f" --config-dir {config_dir}"
    return (
        f"{command} --input datasets/benchmark_packs/smoke-v1.yaml "
        f"--scoring configs/scoring-default.yaml --out-dir reports/{sanitize_target_name(target_name)}-smoke"
    )


def _model_target_doctor_report(
    target_path: Path,
    *,
    probe_endpoint: bool,
    timeout: float,
    command_reference: str | Path | None = None,
    config_dir: Path | None = None,
) -> dict[str, object]:
    target_config = load_target_config(target_path)
    metadata = target_config.metadata if isinstance(target_config.metadata, dict) else {}
    existing_universe = metadata.get("model_universe") if isinstance(metadata.get("model_universe"), dict) else {}
    provider_hint = str(existing_universe.get("provider_id") or metadata.get("provider_preset") or infer_provider_id(target_config.base_url or ""))
    universe = model_universe_metadata(
        provider_id=provider_hint,
        model=str(target_config.model or ""),
        base_url=str(target_config.base_url or ""),
        api_key_env=target_config.api_key_env,
    )
    checks: list[dict[str, object]] = [
        {"name": "config", "status": "passed", "message": "target YAML loaded and validated", "evidence": {"path": str(target_path)}},
        {
            "name": "model_universe",
            "status": "passed",
            "message": f"{universe['provider_label']} via {universe['endpoint_family']} ({universe['model_source']} model)",
            "evidence": universe,
        },
        {
            "name": "endpoint",
            "status": "passed" if target_config.base_url else "failed",
            "message": "OpenAI-compatible base URL configured" if target_config.base_url else "missing base_url",
            "evidence": {"base_url": _safe_base_url_label(target_config.base_url or "") if target_config.base_url else ""},
        },
    ]
    auth_env = target_config.api_key_env or ""
    if not auth_env:
        auth_status = "warning" if str(target_config.adapter) == "ollama" else "failed"
        auth_message = "no API key env configured"
    elif auth_env in os.environ or _env_file_has_key(Path(".env"), auth_env):
        auth_status = "passed"
        auth_message = f"credential env reference configured and present ({auth_env})"
    else:
        auth_status = "failed"
        auth_message = f"credential env reference configured but not present ({auth_env})"
    checks.append({"name": "auth", "status": auth_status, "message": auth_message, "evidence": {"api_key_env": auth_env}})

    if probe_endpoint:
        try:
            preflight = run_target_preflight(target_config, timeout=timeout, max_retries=0)
            checks.append(
                {
                    "name": "provider_preflight",
                    "status": "passed" if preflight.ok else "failed",
                    "message": f"text probe status: {preflight.text_status}",
                    "evidence": {"text_ready": preflight.text_ready, "provider_ok": preflight.ok},
                }
            )
            if not preflight.ok:
                for probe in getattr(preflight, "probes", []):
                    if getattr(probe, "status", None) != "passed":
                        checks.append(_preflight_probe_doctor_check(probe))
            models_probe = next((probe for probe in getattr(preflight, "probes", []) if getattr(probe, "name", None) == "models"), None)
            if models_probe is not None and models_probe.ok:
                model_ids = [str(item) for item in models_probe.metadata.get("model_ids", []) if item]
                if models_probe.metadata.get("target_model_found") is False and model_ids:
                    checks.append(
                        {
                            "name": "model_catalog",
                            "status": "warning",
                            "message": f"configured model was not listed by provider; choose one of: {', '.join(model_ids[:10])}",
                            "evidence": {"available_model_count": len(model_ids), "available_models": model_ids[:25]},
                        }
                    )
        except Exception as exc:  # pragma: no cover - defensive CLI boundary for provider failures
            checks.append({"name": "provider_preflight", "status": "failed", "message": f"provider probe failed: {type(exc).__name__}", "evidence": {}})
    else:
        checks.append({"name": "provider_preflight", "status": "skipped", "message": "live provider check skipped; pass --live-check to call the endpoint", "evidence": {}})

    coverage_matrix = [
        {"area": "target", "field": "adapter", "required": True, "status": "present" if target_config.adapter else "missing"},
        {"area": "target", "field": "model", "required": True, "status": "present" if target_config.model else "missing"},
        {"area": "target", "field": "base_url", "required": True, "status": "present" if target_config.base_url else "missing"},
        {"area": "target", "field": "api_key_env", "required": str(target_config.adapter) != "ollama", "status": "present" if auth_env else "missing"},
        {"area": "request", "field": "timeout", "required": False, "status": "present" if target_config.request.timeout is not None else "default"},
        {"area": "request", "field": "max_tokens", "required": False, "status": "present" if target_config.request.max_tokens is not None else "default"},
    ]
    valid = not any(check["status"] == "failed" for check in checks)
    return {
        "schema_version": "malleus.model_target_doctor.v1",
        "target_name": target_config.name,
        "target_type": str(target_config.target_type),
        "framework": "chat_completion",
        "adapter": str(target_config.adapter or ""),
        "model": str(target_config.model or ""),
        "provider": str(universe["provider_label"]),
        "model_universe": universe,
        "base_url": _safe_base_url_label(target_config.base_url or "") if target_config.base_url else "",
        "api_key_env": auth_env,
        "valid": valid,
        "checks": checks,
        "coverage_matrix": coverage_matrix,
        "live_command": _benchmark_smoke_command(command_reference or target_path, target_config.name, config_dir=config_dir),
    }


def _preflight_probe_doctor_check(probe: object) -> dict[str, object]:
    name = str(getattr(probe, "name", "probe"))
    status = str(getattr(probe, "status", "failed"))
    status_code = getattr(probe, "status_code", None)
    reason = getattr(probe, "reason", None)
    summary = getattr(probe, "response_summary", None)
    excerpt = getattr(summary, "redacted_excerpt", None) if summary is not None else None
    details = [f"{name} probe status: {status}"]
    if status_code:
        details.append(f"HTTP {status_code}")
    if reason:
        details.append(str(reason))
    if excerpt:
        details.append(str(excerpt))
    return {
        "name": f"provider_probe_{name}",
        "status": "failed" if name == "text" else "warning",
        "message": " - ".join(details),
        "evidence": {"status": status, "status_code": status_code, "reason": reason, "redacted_excerpt": excerpt},
    }


def _safe_base_url_label(base_url: str) -> str:
    endpoint = safe_endpoint_from_url(base_url)
    return f"{endpoint.label}{endpoint.path_hint or ''}"


def _system_endpoint_label(target_config: object) -> str | None:
    target_type = getattr(target_config, "target_type", "chat_completion")
    system_config = getattr(target_config, str(target_type), None)
    endpoint_url = getattr(system_config, "endpoint_url", None)
    if isinstance(endpoint_url, str) and endpoint_url:
        return _safe_base_url_label(endpoint_url)
    workspace_path = getattr(system_config, "workspace_path", None)
    if isinstance(workspace_path, str) and workspace_path:
        return workspace_path
    return None


def _system_auth_envs(target_config: object) -> list[str]:
    target_type = getattr(target_config, "target_type", "chat_completion")
    system_config = getattr(target_config, str(target_type), None)
    auth = getattr(system_config, "auth", None)
    envs: list[str] = []
    for attr in ("api_key_env", "bearer_token_env"):
        value = getattr(auth, attr, "")
        if isinstance(value, str) and value:
            envs.append(value)
    headers_env = getattr(auth, "headers_env", {})
    if isinstance(headers_env, dict):
        envs.extend(str(value) for value in headers_env.values() if value)
    command_env = getattr(system_config, "command_env", {})
    if isinstance(command_env, dict):
        envs.extend(str(value) for value in command_env.values() if value)
    return envs


def _echo_target_data(data: dict[str, object]) -> None:
    typer.echo(f"name: {data.get('name', '')}")
    typer.echo(f"adapter: {data.get('adapter', '')}")
    typer.echo(f"model: {data.get('model', '')}")
    typer.echo(f"base_url: {_safe_base_url_label(str(data.get('base_url', '')))}")
    typer.echo(f"api_key_env: {data.get('api_key_env', '')}")
    request = data.get("request")
    typer.echo("request:")
    if isinstance(request, dict):
        for key in ("timeout", "max_tokens", "temperature", "top_p"):
            if key in request:
                typer.echo(f"  {key}: {request[key]}")


def _resolve_cli_target(reference: str | Path, config_dir: Path | None) -> Path:
    try:
        target_path = resolve_target(reference, config_dir)
    except TargetStoreError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    if not target_path.is_file():
        typer.echo(f"target path is not a file: {target_path}", err=True)
        raise typer.Exit(code=1)
    if not os.access(target_path, os.R_OK):
        typer.echo(f"target path is not readable: {target_path}", err=True)
        raise typer.Exit(code=1)
    return target_path


def _format_cli_error(exc: ValueError) -> str:
    errors = getattr(exc, "errors", None)
    if callable(errors):
        try:
            entries = errors(include_input=False)
        except TypeError:
            entries = errors()
        messages: list[str] = []
        if isinstance(entries, list):
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                location = ".".join(str(part) for part in entry.get("loc", ()) if part != "__root__")
                message = str(entry.get("msg", "invalid value"))
                messages.append(f"{location}: {message}" if location else message)
        if messages:
            return "; ".join(messages)
    return str(exc)


def _render_target_doctor_markdown(report: dict[str, object]) -> str:
    universe = report.get("model_universe") if isinstance(report.get("model_universe"), dict) else {}
    lines = [
        "# Malleus target doctor",
        "",
        f"- Target: `{report.get('target_name', '')}`",
        f"- Target type: `{report.get('target_type', '')}`",
        f"- Framework: `{report.get('framework', 'unspecified')}`",
        f"- Provider: `{report.get('provider', universe.get('provider_label', 'unknown'))}`",
        f"- Valid: `{str(report.get('valid', False)).lower()}`",
        "",
        "## Checks",
        "",
        "| Check | Status | Message |",
        "|---|---:|---|",
    ]
    checks = report.get("checks", [])
    if isinstance(checks, list):
        for check in checks:
            if not isinstance(check, dict):
                continue
            lines.append(f"| `{check.get('name', '')}` | {check.get('status', '')} | {check.get('message', '')} |")
    lines.extend(["", "## Coverage Matrix", "", "| Area | Field | Required | Status |", "|---|---|---:|---|"])
    matrix = report.get("coverage_matrix", [])
    if isinstance(matrix, list):
        for row in matrix:
            if not isinstance(row, dict):
                continue
            lines.append(f"| `{row.get('area', '')}` | `{row.get('field', '')}` | {str(row.get('required', False)).lower()} | {row.get('status', '')} |")
    if universe:
        lines.extend(
            [
                "",
                "## Model Universe",
                "",
                f"- Provider id: `{universe.get('provider_id', '')}`",
                f"- Endpoint family: `{universe.get('endpoint_family', '')}`",
                f"- Configured model: `{universe.get('configured_model', '')}`",
                f"- Model source: `{universe.get('model_source', '')}`",
                f"- Operational error policy: {universe.get('operational_error_policy', '')}",
            ]
        )
    lines.extend(["", "This doctor checks exposed contracts and reachable local/staging wiring. It cannot prove that unreported side effects did not happen."])
    return "\n".join(lines).rstrip() + "\n"


def _render_target_doctor_console(report: dict[str, object], *, doctor_command: str | None = None) -> str:
    valid = bool(report.get("valid", False))
    checks = [check for check in report.get("checks", []) if isinstance(check, dict)]
    coverage = [row for row in report.get("coverage_matrix", []) if isinstance(row, dict)]
    failed = [check for check in checks if check.get("status") == "failed"]
    warnings = [check for check in checks if check.get("status") == "warning"]
    status = "ready" if valid else "needs attention"
    lines = [
        "Malleus target doctor",
        f"Status: {status}",
        f"Target: {report.get('target_name', '')}",
        f"Type: {report.get('target_type', '')}",
        f"Mode: {_doctor_mode_label(report)}",
    ]
    details = _doctor_detail_lines(report)
    if details:
        lines.extend(["", "Target details:", *details])
    lines.extend(["", "Checks:"])
    for check in checks:
        lines.append(f"  [{_doctor_status_label(str(check.get('status', '')))}] {check.get('name', '')}: {check.get('message', '')}")
    if coverage:
        lines.extend(["", "Coverage:"])
        for row in coverage:
            required = "required" if row.get("required") else "optional"
            lines.append(f"  - {row.get('area', '')}.{row.get('field', '')}: {row.get('status', '')} ({required})")
    lines.extend(["", "Meaning:"])
    if valid:
        lines.append("  The target config is usable. If the live check ran, Malleus confirmed provider auth, endpoint reachability, and response parsing.")
    else:
        lines.append("  Malleus could load the target, but at least one required check failed. Fix the failed lines above before a real benchmark.")
    if warnings:
        lines.append(f"  Warnings are non-blocking but worth reviewing: {', '.join(str(check.get('name', '')) for check in warnings)}.")
    if failed:
        lines.append(f"  Failed checks: {', '.join(str(check.get('name', '')) for check in failed)}.")
    universe = report.get("model_universe") if isinstance(report.get("model_universe"), dict) else {}
    if universe:
        lines.extend(
            [
                "",
                "Model universe:",
                f"  Provider id: {universe.get('provider_id', '')}",
                f"  Endpoint family: {universe.get('endpoint_family', '')}",
                f"  Error policy: {universe.get('operational_error_policy', '')}",
            ]
        )
    live_command = str(report.get("live_command") or "")
    lines.extend(["", "Next:"])
    if not valid and doctor_command:
        lines.append(f"  Re-run doctor: {doctor_command}")
    if live_command:
        lines.append(f"  Smoke benchmark: {live_command}")
    return "\n".join(lines).rstrip()


def _doctor_status_label(status: str) -> str:
    return {
        "passed": "ok",
        "failed": "fail",
        "warning": "warn",
        "skipped": "skip",
    }.get(status, status or "unknown")


def _doctor_detail_lines(report: dict[str, object]) -> list[str]:
    details: list[str] = []
    if report.get("adapter"):
        details.append(f"  - Adapter: {report.get('adapter')}")
    if report.get("provider"):
        details.append(f"  - Provider: {report.get('provider')}")
    if report.get("model"):
        details.append(f"  - Model: {report.get('model')}")
    if report.get("base_url"):
        details.append(f"  - Endpoint: {report.get('base_url')}")
    if report.get("api_key_env"):
        details.append(f"  - Credential env: {report.get('api_key_env')}")
    return details


def _doctor_mode_label(report: dict[str, object]) -> str:
    target_type = str(report.get("target_type", ""))
    framework = str(report.get("framework", "unspecified"))
    if target_type in {"chat_completion", "vision_model"}:
        return "model endpoint"
    return f"agent framework: {framework}"


def _render_run_error(exc: Exception, *, target: str, out_dir: Path) -> str:
    message = redact_public_text(str(exc), limit=240).text or type(exc).__name__
    lines = [
        "Malleus run failed",
        f"Reason: {type(exc).__name__}: {message}",
        "",
        "What happened:",
        "  The benchmark did not complete. This is a provider/runtime problem, not a model safety result.",
    ]
    if _looks_like_dns_failure(exc):
        lines.extend(
            [
                "",
                "Sandbox/network diagnosis:",
                "  DNS resolution failed in this process. If `target doctor` works outside a sandbox but `run` fails here, the current execution sandbox or network namespace probably cannot reach the configured resolver.",
            ]
        )
    lines.extend(
        [
            "",
            "Next:",
            f"  Check the target: malleus target doctor {target} --live-check",
            f"  Check this process network: malleus network-doctor --target {target}",
            f"  Inspect partial artifacts, if any: {out_dir}",
        ]
    )
    return "\n".join(lines)


def _looks_like_dns_failure(exc: Exception) -> bool:
    text = f"{type(exc).__name__}: {exc}".lower()
    return any(marker in text for marker in ("temporary failure in name resolution", "name or service not known", "nodename nor servname", "gaierror"))


def _network_doctor_report(*, target: str | None, host: str | None, port: int, config_dir: Path | None) -> dict[str, object]:
    target_name = None
    target_path = None
    endpoint = ""
    if target:
        resolved = _resolve_cli_target(target, config_dir)
        target_config = load_target_config(resolved)
        target_name = target_config.name
        target_path = str(resolved)
        endpoint = _safe_base_url_label(target_config.base_url or "") if target_config.base_url else ""
        parsed = urlsplit(target_config.base_url or "")
        host = host or parsed.hostname
        port = parsed.port or port or (443 if parsed.scheme == "https" else 80)
    if not host:
        raise typer.BadParameter("provide --target or --host")
    dns = _resolve_host(str(host), port)
    resolver = _read_resolver_config()
    sandbox_hints = _sandbox_hints(resolver=resolver, dns_ok=bool(dns["ok"]))
    status = "ready" if dns["ok"] else "blocked"
    return {
        "schema_version": "malleus.network_doctor.v1",
        "status": status,
        "target": target_name,
        "target_path": target_path,
        "endpoint": endpoint,
        "host": host,
        "port": port,
        "dns": dns,
        "resolver": resolver,
        "sandbox_hints": sandbox_hints,
    }


def _resolve_host(host: str, port: int) -> dict[str, object]:
    try:
        infos = socket.getaddrinfo(host, port)
    except OSError as exc:
        return {"ok": False, "error_type": type(exc).__name__, "message": redact_public_text(str(exc), limit=240).text, "addresses": []}
    addresses = sorted({str(info[4][0]) for info in infos if info and len(info) >= 5 and info[4]})
    return {"ok": True, "error_type": None, "message": "", "addresses": addresses[:12], "address_count": len(addresses)}


def _read_resolver_config(path: Path = Path("/etc/resolv.conf")) -> dict[str, object]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return {"path": str(path), "readable": False, "error": type(exc).__name__, "nameservers": [], "search": []}
    nameservers: list[str] = []
    search: list[str] = []
    for line in text.splitlines():
        parts = line.strip().split()
        if not parts:
            continue
        if parts[0] == "nameserver" and len(parts) > 1:
            nameservers.append(parts[1])
        elif parts[0] == "search":
            search.extend(parts[1:])
    return {"path": str(path), "readable": True, "nameservers": nameservers, "search": search}


def _sandbox_hints(*, resolver: dict[str, object], dns_ok: bool) -> list[str]:
    hints: list[str] = []
    if Path("/.dockerenv").exists():
        hints.append("container_marker: /.dockerenv exists")
    if Path("/run/.containerenv").exists():
        hints.append("container_marker: /run/.containerenv exists")
    for env_name in ("CODESPACES", "KUBERNETES_SERVICE_HOST", "container"):
        if os.environ.get(env_name):
            hints.append(f"env_marker: {env_name} is set")
    nameservers = [str(item) for item in resolver.get("nameservers", [])] if isinstance(resolver.get("nameservers"), list) else []
    if not dns_ok and any(item.startswith("100.100.100.100") or item.startswith("fd7a:115c:a1e0") for item in nameservers):
        hints.append("tailscale_dns_unreachable: resolver points at Tailscale DNS but this process could not resolve the host")
    if not dns_ok and not hints:
        hints.append("dns_failed_in_current_process")
    return hints


def _render_network_doctor_console(report: dict[str, object]) -> str:
    status = str(report.get("status", "blocked"))
    dns = report.get("dns") if isinstance(report.get("dns"), dict) else {}
    resolver = report.get("resolver") if isinstance(report.get("resolver"), dict) else {}
    hints = report.get("sandbox_hints") if isinstance(report.get("sandbox_hints"), list) else []
    lines = [
        "Malleus network doctor",
        f"Status: {'ready' if status == 'ready' else 'blocked'}",
        f"Host: {report.get('host', '')}:{report.get('port', '')}",
    ]
    if report.get("target"):
        lines.append(f"Target: {report.get('target')}")
    if report.get("endpoint"):
        lines.append(f"Endpoint: {report.get('endpoint')}")
    lines.extend(["", "DNS:"])
    if dns.get("ok"):
        addresses = dns.get("addresses") if isinstance(dns.get("addresses"), list) else []
        lines.append(f"  [ok] resolved {dns.get('address_count', len(addresses))} address(es): {', '.join(str(item) for item in addresses[:4])}")
    else:
        lines.append(f"  [fail] {dns.get('error_type', 'DNS error')}: {dns.get('message', '')}")
    lines.extend(["", "Resolver:"])
    nameservers = resolver.get("nameservers") if isinstance(resolver.get("nameservers"), list) else []
    search = resolver.get("search") if isinstance(resolver.get("search"), list) else []
    lines.append(f"  - config: {resolver.get('path', '/etc/resolv.conf')}")
    lines.append(f"  - nameservers: {', '.join(str(item) for item in nameservers) if nameservers else 'none detected'}")
    if search:
        lines.append(f"  - search: {', '.join(str(item) for item in search)}")
    if hints:
        lines.extend(["", "Sandbox hints:"])
        for hint in hints:
            lines.append(f"  - {hint}")
    lines.extend(["", "Meaning:"])
    if status == "ready":
        lines.append("  This Malleus process can resolve the provider host. Provider errors after this point are likely HTTP/auth/quota/model issues, not local DNS.")
    else:
        lines.append("  This Malleus process cannot resolve the provider host. Run outside the sandbox, allow DNS/network egress, or fix the resolver before benchmarking.")
    return "\n".join(lines).rstrip()


def _live_benchmark_progress_printer(*, quiet: bool = False, trace_log: Path | None = None):
    log_path = trace_log.resolve() if trace_log is not None else None
    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("", encoding="utf-8")
    if quiet and log_path is None:
        return None

    def emit(event: dict[str, object]) -> None:
        if log_path is not None:
            with log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
        if quiet:
            return
        kind = str(event.get("event") or "")
        if kind == "preflight_start":
            typer.echo(f"[preflight] Checking target {event.get('target')} ({event.get('model')})")
        elif kind == "preflight_end":
            typer.echo(
                "[preflight] "
                f"text={event.get('text_status')} ready={str(event.get('text_ready')).lower()} | "
                f"visual={event.get('visual_status')} ready={str(event.get('visual_ready')).lower()}"
            )
        elif kind == "run_start":
            typer.echo(f"[run] {event.get('benchmark_mode')} started: {event.get('total_rows')} surfaces/rows -> {event.get('out_dir')}")
        elif kind == "row_start":
            typer.echo(f"[{event.get('index')}/{event.get('total_rows')}] START {event.get('surface_name')} ({event.get('surface_id')})")
        elif kind == "case_start":
            prompt = _progress_excerpt(str(event.get("prompt") or ""), limit=220)
            typer.echo(f"    -> {event.get('kind')} {event.get('dataset')}::{event.get('case_id')} [{event.get('severity')}]")
            typer.echo(f"       objective: {_progress_excerpt(str(event.get('objective') or ''), limit=180)}")
            if prompt:
                typer.echo(f"       prompt: {prompt}")
        elif kind == "case_end":
            status = "PASS" if event.get("passed") is True else "FAIL"
            score = f"{event.get('score')}/{event.get('max_score')}"
            latency = event.get("latency_seconds")
            latency_text = f" | {float(latency):.2f}s" if isinstance(latency, (int, float)) else ""
            typer.echo(f"    <- {status} {event.get('dataset')}::{event.get('case_id')} | score={score}{latency_text}")
            checks = event.get("failure_checks")
            if isinstance(checks, list) and checks:
                typer.echo(f"       check: {_progress_excerpt(str(checks[0]), limit=220)}")
            response = _progress_excerpt(str(event.get("response") or ""), limit=260)
            if response:
                typer.echo(f"       response: {response}")
        elif kind == "system_case_end":
            status = str(event.get("status") or "unknown").upper()
            fidelity = str(event.get("evidence_fidelity") or "")
            if fidelity == "auto_wrapper_trace" and status == "PASSED":
                status = "PASSED [auto-wrapper low fidelity]"
            latency = event.get("latency_seconds")
            latency_text = f" | {float(latency):.2f}s" if isinstance(latency, (int, float)) else ""
            codes = event.get("reason_codes")
            code_text = ""
            if isinstance(codes, list) and codes:
                code_text = " | codes=" + ", ".join(str(code) for code in codes[:5])
            fidelity_text = f" | fidelity={fidelity}" if fidelity else ""
            typer.echo(f"    <- {status} {event.get('dataset')}::{event.get('case_id')}{latency_text}{fidelity_text}{code_text}")
            reason = _progress_excerpt(str(event.get("reason") or ""), limit=220)
            if reason:
                typer.echo(f"       reason: {reason}")
            trace_summary = event.get("trace_summary")
            if isinstance(trace_summary, dict):
                compact = ", ".join(f"{key}={value}" for key, value in trace_summary.items() if value not in (None, 0, [], {}, ""))
                if compact:
                    typer.echo(f"       trace: {_progress_excerpt(compact, limit=240)}")
            response = _progress_excerpt(str(event.get("response") or ""), limit=260)
            if response:
                typer.echo(f"       response: {response}")
        elif kind == "row_end":
            status = str(event.get("status") or "unknown")
            fidelity = str(event.get("evidence_fidelity") or "")
            label = status.upper()
            if fidelity == "auto_wrapper_trace" and status == "passed":
                label = "PASSED [auto-wrapper low fidelity]"
            calls = int(event.get("live_model_calls") or 0)
            backing_calls = int(event.get("backing_model_calls") or 0)
            target_calls = int(event.get("target_call_count") or 0)
            target_traces = int(event.get("target_trace_count") or 0)
            codes = event.get("reason_codes")
            code_text = ""
            if isinstance(codes, list) and codes:
                code_text = " | codes=" + ", ".join(str(code) for code in codes[:5])
            report = str(event.get("report_json") or "")
            report_text = f" | report={report}" if report else ""
            reason = str(event.get("reason") or "")
            reason_text = f" | {reason[:140]}" if reason else ""
            call_text = f"direct_calls={calls} backing_calls={backing_calls}"
            if target_calls or target_traces:
                call_text += f" target_calls={target_calls} target_traces={target_traces}"
            fidelity_text = f" | fidelity={fidelity}" if fidelity else ""
            typer.echo(f"[{event.get('index')}/{event.get('total_rows')}] {label} {event.get('surface_name')} | {call_text}{fidelity_text}{code_text}{report_text}{reason_text}")
        elif kind == "checkpoint":
            typer.echo(f"[checkpoint] {event.get('completed_rows')}/{event.get('total_rows')} rows written -> {event.get('path')}")
        elif kind == "run_end":
            typer.echo(f"[run] complete: {event.get('total_rows')} rows -> {event.get('out_dir')}")

    return emit


def _progress_excerpt(text: str, *, limit: int) -> str:
    redacted = redact_public_text(" ".join(text.split()), limit=limit).text
    if len(redacted) > limit:
        redacted = redacted[: limit - 1].rstrip() + "…"
    return textwrap.shorten(redacted, width=limit, placeholder="…")


@bundle_app.command("init")
def bundle_init_command(
    model_target: str = typer.Option(..., "--model-target", help="Managed target name or YAML path for the backing chat/vision model"),
    name: str | None = typer.Option(None, "--name", help="Bundle name; defaults to <model-target>-reference"),
    out: Path | None = typer.Option(None, "--out", dir_okay=False, help="Write bundle YAML here; defaults to the managed bundle directory"),
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
    config_dir: Path | None = typer.Option(None, "--config-dir", file_okay=False, help="Managed target directory", hidden=True),
    bundle_dir: Path | None = typer.Option(None, "--bundle-dir", file_okay=False, help="Managed bundle directory", hidden=True),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable bundle doctor result"),
) -> None:
    """Validate that a target bundle can exercise every declared surface."""
    try:
        bundle_path = resolve_bundle(reference, bundle_dir)
        report = doctor_target_bundle(bundle_path, target_dir=config_dir)
    except (TargetStoreError, ValueError, ValidationError, OSError) as exc:
        typer.echo(f"bundle_doctor: failed - {_format_cli_error(exc) if isinstance(exc, (ValueError, ValidationError)) else exc}", err=True)
        raise typer.Exit(code=1) from exc
    if json_output:
        typer.echo(json.dumps(report.to_dict(), indent=2))
    else:
        typer.echo(f"bundle_doctor: {'ok' if report.ok else 'failed'}")
        typer.echo(f"bundle: {report.bundle.name}")
        typer.echo(f"model: {report.model_status} - {report.bundle.model_target} ({report.model_target_type or 'unresolved'})")
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
    bundle_dir: Path | None = typer.Option(None, "--bundle-dir", file_okay=False, help="Managed bundle directory", hidden=True),
) -> None:
    try:
        bundle_path = resolve_bundle(reference, bundle_dir)
        bundle = load_target_bundle(bundle_path)
    except (TargetStoreError, ValueError, ValidationError, OSError) as exc:
        typer.echo(f"bundle_show: failed - {_format_cli_error(exc) if isinstance(exc, (ValueError, ValidationError)) else exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"bundle: {bundle.name}")
    typer.echo(f"schema_version: {bundle.schema_version}")
    typer.echo(f"mode: {bundle.mode}")
    typer.echo(f"model_target: {bundle.model_target}")
    typer.echo("surfaces:")
    for surface, config in bundle.surfaces.items():
        typer.echo(f"  - {surface}: {config.target} ({config.required_target_type})")



@target_app.command("init")
def target_init_command(
    provider: str | None = typer.Option(None, "--provider", help=f"Provider preset: {_provider_choices_label()}"),
    model: str | None = typer.Option(None, "--model", help="Model id; for presets this can also be a suggested model number"),
    name: str | None = typer.Option(None, "--name", help="Target name; defaults to provider-model"),
    base_url: str | None = typer.Option(None, "--base-url", help="OpenAI-compatible API base URL; required for custom providers"),
    api_key_env: str | None = typer.Option(None, "--api-key-env", help="Environment variable name containing the API key"),
    timeout: float = typer.Option(180.0, "--timeout", min=0.1, help="Request timeout in seconds", hidden=True),
    max_tokens: int | None = typer.Option(None, "--max-tokens", min=1, help="Maximum response tokens; defaults to the provider preset", hidden=True),
    temperature: float | None = typer.Option(0.0, "--temperature", min=0.0, help="Default request temperature", hidden=True),
    top_p: float | None = typer.Option(None, "--top-p", min=0.0, max=1.0, help="Default request top_p", hidden=True),
    out: Path | None = typer.Option(None, "--out", dir_okay=False, help="Write a target YAML at this exact path instead of the managed target store", hidden=True),
    config_dir: Path | None = typer.Option(None, "--config-dir", file_okay=False, help="Managed target directory when --out is not used", hidden=True),
    save_api_key: bool | None = typer.Option(None, "--save-api-key/--no-save-api-key", help="Prompt for the API key and store it locally"),
    env_file: Path = typer.Option(Path(".env"), "--env-file", dir_okay=False, help="Local env file used with --save-api-key", hidden=True),
    overwrite_env: bool = typer.Option(False, "--overwrite-env", help="Replace an existing key line in --env-file", hidden=True),
    overwrite: bool = typer.Option(False, "--overwrite", help="Replace an existing target YAML", hidden=True),
    non_interactive: bool = typer.Option(False, "--non-interactive", help="Use preset defaults and fail instead of prompting for missing custom fields", hidden=True),
    probe_provider: bool = typer.Option(False, "--probe-provider", help="Run a live provider preflight after writing the target", hidden=True),
) -> None:
    """Create a reusable OpenAI-compatible target with provider presets and optional .env setup."""
    interactive = not non_interactive
    provider_options = _provider_menu_options()
    provider_value = provider.strip().lower() if provider else ""
    if not provider_value:
        provider_value = _prompt_choice("Provider", provider_options)
    else:
        try:
            provider_value = _resolve_numbered_choice(provider_value, provider_options)
        except typer.BadParameter as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=1) from exc
    preset = _provider_preset(provider_value)

    if provider_value == "custom":
        resolved_base_url = base_url or (typer.prompt("OpenAI-compatible base URL") if interactive else None)
        if not resolved_base_url:
            typer.echo("--base-url is required for custom providers", err=True)
            raise typer.Exit(code=1)
    else:
        resolved_base_url = base_url or str(preset["base_url"])

    default_api_key_env = str((preset or {}).get("api_key_env") or derive_api_key_env(provider_value))
    if api_key_env:
        resolved_api_key_env = api_key_env
    elif provider_value == "custom" and interactive:
        resolved_api_key_env = typer.prompt("API key environment variable", default=default_api_key_env)
    else:
        resolved_api_key_env = default_api_key_env

    api_key_value: str | None = None
    if save_api_key is None and interactive and not _credential_value(resolved_api_key_env, env_file):
        save_api_key = typer.confirm(f"Store {resolved_api_key_env} in {env_file}?", default=False)
    if save_api_key:
        if _env_file_has_key(env_file, resolved_api_key_env) and not overwrite_env:
            typer.echo(f"API key env already present in {env_file}: {resolved_api_key_env}")
            api_key_value = _credential_value(resolved_api_key_env, env_file)
        else:
            api_key = typer.prompt(f"API key for {resolved_api_key_env}", hide_input=True, confirmation_prompt=False)
            if not api_key.strip():
                typer.echo("empty API key refused", err=True)
                raise typer.Exit(code=1)
            api_key_value = api_key.strip()
            _write_env_key(env_file, resolved_api_key_env, api_key_value, overwrite=overwrite_env)
            typer.echo(f"API key saved to {env_file}: {resolved_api_key_env}")
    elif not _credential_value(resolved_api_key_env, env_file):
        typer.echo(f"Credential not found yet. Add {resolved_api_key_env} to your environment or {env_file}.")

    model_options = [str(item) for item in (preset or {}).get("models", []) if item]
    if model is None and interactive:
        credential = _credential_value(resolved_api_key_env, env_file, fallback=api_key_value)
        if credential:
            typer.echo("Checking provider model list...")
            discovered_models, discovery_error = _discover_provider_models(resolved_base_url, credential, timeout=min(timeout, 20.0))
            if discovered_models:
                model_options = discovered_models
                typer.echo(f"Discovered {len(discovered_models)} models from provider.")
            elif discovery_error:
                typer.echo(f"Model discovery skipped: {discovery_error}")
                if model_options:
                    typer.echo("Falling back to built-in model suggestions.")
    resolved_model = _resolve_prompted_model_from_options(provider_value, model, model_options, interactive=interactive and model is None)
    resolved_name = name or _default_target_name(provider_value, resolved_model)
    resolved_max_tokens = max_tokens if max_tokens is not None else int((preset or {}).get("default_max_tokens") or 2048)
    request = _request_options(timeout, resolved_max_tokens, temperature, top_p)
    universe_metadata = model_universe_metadata(
        provider_id=provider_value,
        model=resolved_model,
        base_url=resolved_base_url,
        api_key_env=resolved_api_key_env,
    )
    payload: dict[str, object] = {
        "name": resolved_name,
        "adapter": "openai_compatible",
        "model": resolved_model,
        "base_url": resolved_base_url,
        "api_key_env": resolved_api_key_env,
        "request": request,
        "metadata": {"provider_preset": provider_value, "model_universe": universe_metadata},
    }

    try:
        if out is not None:
            path = write_target_file(payload, out, overwrite=overwrite)
        else:
            path = add_managed_target(payload, config_dir, overwrite=overwrite)
    except TargetStoreError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    except (ValueError, ValidationError) as exc:
        typer.echo(_format_cli_error(exc), err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(f"Target saved: {resolved_name}")
    typer.echo(f"Path: {path}")
    next_reference = str(path) if out is not None else resolved_name
    typer.echo(f"Next: {_target_doctor_next_command(next_reference, config_dir=config_dir if out is None else None)}")

    if probe_provider:
        typer.echo("provider_preflight: enabled")
        try:
            report = run_target_preflight(load_target_config(path), timeout=timeout, max_retries=0)
        except Exception as exc:  # pragma: no cover - defensive CLI boundary for network/provider failures
            typer.echo(f"provider: error - {exc}", err=True)
            raise typer.Exit(code=1) from exc
        typer.echo(f"provider: {report.text_status}")
        typer.echo(f"provider_ok: {str(report.ok).lower()}")
        if not report.ok:
            raise typer.Exit(code=1)


@target_app.command("add")
def target_add_command(
    name: str = typer.Option(..., "--name", help="Managed target name"),
    model: str = typer.Option(..., "--model", help="Provider model id"),
    base_url: str = typer.Option("https://api.openai.com/v1", "--base-url", help="Provider API base URL"),
    adapter: str = typer.Option("openai_compatible", "--adapter", help="Adapter name: openai_compatible, nvidia, or ollama"),
    api_key_env: str | None = typer.Option(None, "--api-key-env", help="Environment variable name containing the API key; raw keys are never stored"),
    timeout: float | None = typer.Option(None, "--timeout", min=0.1, help="Request timeout in seconds"),
    max_tokens: int | None = typer.Option(None, "--max-tokens", min=1, help="Maximum response tokens"),
    temperature: float | None = typer.Option(None, "--temperature", min=0.0, help="Default request temperature"),
    top_p: float | None = typer.Option(None, "--top-p", min=0.0, max=1.0, help="Default request top_p"),
    config_dir: Path | None = typer.Option(None, "--config-dir", file_okay=False, help="Managed target directory", hidden=True),
    overwrite: bool = typer.Option(False, "--overwrite", help="Replace an existing managed target"),
) -> None:
    payload: dict[str, object] = {
        "name": name,
        "adapter": adapter,
        "model": model,
        "base_url": base_url,
    }
    if api_key_env:
        payload["api_key_env"] = api_key_env
    request = _request_options(timeout, max_tokens, temperature, top_p)
    if request:
        payload["request"] = request
    try:
        path = add_managed_target(payload, config_dir, overwrite=overwrite)
    except TargetStoreError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    except (ValueError, ValidationError) as exc:
        typer.echo(_format_cli_error(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Managed target saved: {name}")
    typer.echo(f"Path: {path}")


@target_app.command("list")
def target_list_command(
    config_dir: Path | None = typer.Option(None, "--config-dir", file_okay=False, help="Managed target directory", hidden=True),
) -> None:
    try:
        targets = list_managed_targets(config_dir)
    except (OSError, ValueError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    if not targets:
        typer.echo("No managed targets found")
        return
    for target in targets:
        typer.echo(target.name)


@target_app.command("show")
def target_show_command(
    name: str = typer.Argument(..., help="Managed target name"),
    config_dir: Path | None = typer.Option(None, "--config-dir", file_okay=False, help="Managed target directory", hidden=True),
) -> None:
    try:
        data = show_managed_target(name, config_dir)
    except (TargetStoreError, ValueError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    _echo_target_data(data)


@target_app.command("remove")
def target_remove_command(
    name: str = typer.Argument(..., help="Managed target name"),
    config_dir: Path | None = typer.Option(None, "--config-dir", file_okay=False, help="Managed target directory", hidden=True),
    yes: bool = typer.Option(False, "--yes", help="Confirm deletion of the managed target"),
) -> None:
    if not yes:
        typer.echo("Refusing to remove managed target without --yes", err=True)
        raise typer.Exit(code=1)
    try:
        remove_managed_target(name, config_dir)
    except TargetStoreError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Managed target removed: {name}")


@target_app.command("test")
def target_test_command(
    reference: str = typer.Argument(..., help="Managed target name or target YAML path"),
    config_dir: Path | None = typer.Option(None, "--config-dir", file_okay=False, help="Managed target directory", hidden=True),
    allow_provider_call: bool = typer.Option(False, "--allow-provider-call", help="Allow live network/provider preflight calls"),
    timeout: float = typer.Option(DEFAULT_PREFLIGHT_TIMEOUT, "--timeout", min=0.1, help="Provider preflight timeout in seconds"),
    max_retries: int = typer.Option(DEFAULT_PREFLIGHT_MAX_RETRIES, "--max-retries", min=0, help="Provider preflight retry count"),
) -> None:
    try:
        target_path = resolve_target(reference, config_dir)
        target_config = load_target_config(target_path)
    except (TargetStoreError, ValueError, ValidationError, OSError) as exc:
        typer.echo(f"config: failed - {_format_cli_error(exc) if isinstance(exc, (ValueError, ValidationError)) else exc}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo("config: ok")
    typer.echo(f"target: {target_config.name}")
    typer.echo(f"target_type: {target_config.target_type}")
    if target_config.target_type in {"chat_completion", "vision_model"}:
        typer.echo(f"adapter: {target_config.adapter}")
        typer.echo(f"model: {target_config.model}")
        typer.echo(f"base_url: {_safe_base_url_label(target_config.base_url or '')}")
        auth_envs = [target_config.api_key_env] if target_config.api_key_env else []
    else:
        endpoint_label = _system_endpoint_label(target_config)
        if endpoint_label:
            endpoint_name = "workspace" if target_config.target_type == "code_agent" else "endpoint"
            typer.echo(f"{endpoint_name}: {endpoint_label}")
        auth_envs = _system_auth_envs(target_config)
    if auth_envs:
        typer.echo(f"auth: env var configured ({', '.join(auth_envs)})")
        typer.echo(f"auth_present: {str(all(env in os.environ for env in auth_envs)).lower()}")
    else:
        typer.echo("auth: no env auth configured")

    if not allow_provider_call:
        typer.echo("network: skipped")
        if target_config.target_type in {"chat_completion", "vision_model"}:
            typer.echo("provider: skipped - pass --allow-provider-call to run live preflight probes")
        else:
            typer.echo("target_preflight: skipped - use the matching live benchmark command with for real target execution")
        return

    if target_config.target_type not in {"chat_completion", "vision_model"}:
        typer.echo("network: skipped")
        typer.echo("target_preflight: skipped - system targets are exercised by matching live benchmark commands, not target test")
        return

    typer.echo("network: provider preflight enabled")
    try:
        report = run_target_preflight(target_config, timeout=timeout, max_retries=max_retries)
    except Exception as exc:  # pragma: no cover - defensive CLI boundary for network/provider failures
        typer.echo(f"provider: error - {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"provider: {report.text_status}")
    typer.echo(f"provider_text_ready: {str(report.text_ready).lower()}")
    typer.echo(f"provider_ok: {str(report.ok).lower()}")


@target_app.command("validate-agent")
def target_validate_agent_command(
    reference: str = typer.Argument(..., help="Managed target name or target YAML path"),
    config_dir: Path | None = typer.Option(None, "--config-dir", file_okay=False, help="Managed target directory", hidden=True),
    surface: str | None = typer.Option(None, "--surface", help=f"Expected L2 surface: {', '.join(L2_TARGET_TYPES)}", hidden=True),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable validation result"),
) -> None:
    """Validate that a target YAML is wired as a real external-agent L2 target."""
    try:
        target_path = _resolve_cli_target(reference, config_dir)
        result = validate_agent_target(target_path, surface=surface)
    except (TargetStoreError, ValueError, ValidationError, OSError) as exc:
        typer.echo(f"agent_contract: failed - {_format_cli_error(exc) if isinstance(exc, (ValueError, ValidationError)) else exc}", err=True)
        raise typer.Exit(code=1) from exc

    if json_output:
        typer.echo(result.model_dump_json(indent=2))
    else:
        typer.echo(f"agent_contract: {'ok' if result.valid else 'failed'}")
        typer.echo(f"target: {result.target_name}")
        typer.echo(f"target_type: {result.target_type}")
        typer.echo(f"framework: {result.framework}")
        if result.required_endpoint_path:
            typer.echo(f"endpoint_path: {result.required_endpoint_path}")
        typer.echo(f"request_fields: {', '.join(result.request_fields)}")
        typer.echo(f"response_fields: {', '.join(result.response_fields)}")
        typer.echo(f"trace_fields: {', '.join(result.trace_fields)}")
        if result.live_command:
            typer.echo(f"benchmark: {result.live_command}")
        for warning in result.warnings:
            typer.echo(f"warning: {warning}")
        for error in result.errors:
            typer.echo(f"error: {error}", err=True)
    if not result.valid:
        raise typer.Exit(code=1)


@target_app.command("doctor")
def target_doctor_command(
    reference: str = typer.Argument(..., help="Managed target name or target YAML path"),
    config_dir: Path | None = typer.Option(None, "--config-dir", file_okay=False, help="Managed target directory", hidden=True),
    surface: str | None = typer.Option(None, "--surface", help=f"Expected L2 surface: {', '.join(L2_TARGET_TYPES)}", hidden=True),
    probe_endpoint: bool = typer.Option(False, "--live-check", help="Call the configured provider or local/staging endpoint for a small live health check"),
    timeout: float = typer.Option(3.0, "--timeout", min=0.1, help="Live check timeout in seconds", hidden=True),
    out_dir: Path | None = typer.Option(None, "--out-dir", file_okay=False, help="Write target-doctor.json and target-doctor.md"),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable doctor result"),
) -> None:
    """Inspect L2 endpoint/auth/trace/safety coverage before a live run."""
    try:
        target_path = _resolve_cli_target(reference, config_dir)
        target_config = load_target_config(target_path)
        model_target = target_config.target_type in {"chat_completion", "vision_model"} and surface is None
        if model_target:
            model_report = _model_target_doctor_report(target_path, probe_endpoint=probe_endpoint, timeout=timeout, command_reference=reference, config_dir=config_dir)
            result = None
        else:
            result = doctor_agent_target(target_path, surface=surface, probe_endpoint=probe_endpoint, timeout=timeout)
            model_report = None
    except (TargetStoreError, ValueError, ValidationError, OSError) as exc:
        typer.echo(f"target_doctor: failed - {_format_cli_error(exc) if isinstance(exc, (ValueError, ValidationError)) else exc}", err=True)
        raise typer.Exit(code=1) from exc

    if model_report is not None:
        if out_dir is not None:
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "target-doctor.json").write_text(json.dumps(model_report, indent=2), encoding="utf-8")
            (out_dir / "target-doctor.md").write_text(_render_target_doctor_markdown(model_report), encoding="utf-8")

        if json_output:
            typer.echo(json.dumps(model_report, indent=2))
        else:
            typer.echo(_render_target_doctor_console(model_report, doctor_command=_target_doctor_next_command(reference, config_dir=config_dir)))
        if not model_report["valid"]:
            raise typer.Exit(code=1)
        return

    assert result is not None
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "target-doctor.json").write_text(result.model_dump_json(indent=2), encoding="utf-8")
        (out_dir / "target-doctor.md").write_text(_render_target_doctor_markdown(result.model_dump(mode="json")), encoding="utf-8")

    if json_output:
        typer.echo(result.model_dump_json(indent=2))
    else:
        typer.echo(_render_target_doctor_console(result.model_dump(mode="json"), doctor_command=_target_doctor_next_command(reference, config_dir=config_dir)))

    if not result.valid:
        raise typer.Exit(code=1)


@target_app.command("scaffold-agent")
def target_scaffold_agent_command(
    name: str = typer.Option(..., "--name", help="Target display name"),
    target_type: str = typer.Option("tool_agent", "--target-type", help=f"L2 target type: {', '.join(L2_TARGET_TYPES)}"),
    framework: str = typer.Option("generic", "--framework", help=f"Framework label: {', '.join(AGENT_FRAMEWORKS)}"),
    out_dir: Path = typer.Option(Path("examples/agent_adapters"), "--out-dir", file_okay=False, help="Directory for generated adapter files"),
    endpoint_url: str | None = typer.Option(None, "--endpoint-url", help="Adapter endpoint URL; defaults to a local stdlib server route"),
    auth_env: str = typer.Option("MALLEUS_AGENT_TOKEN", "--auth-env", help="Environment variable name used for adapter auth"),
    force: bool = typer.Option(False, "--force", help="Overwrite existing scaffold files"),
) -> None:
    """Create a provider-free L2 adapter scaffold for a real external agent."""
    try:
        result = scaffold_agent_target(
            name=name,
            target_type=target_type,
            framework=framework,
            out_dir=out_dir,
            endpoint_url=endpoint_url,
            auth_env=auth_env,
            force=force,
        )
    except (FileExistsError, ValueError, OSError, ValidationError) as exc:
        typer.echo(f"agent_scaffold: failed - {_format_cli_error(exc) if isinstance(exc, (ValueError, ValidationError)) else exc}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo("agent_scaffold: ok")
    typer.echo(f"target_type: {result.target_type}")
    typer.echo(f"framework: {result.framework}")
    typer.echo(f"target: {result.target_path}")
    typer.echo(f"adapter: {result.adapter_path}")
    typer.echo(f"readme: {result.readme_path}")
    typer.echo(f"benchmark: {result.live_command}")


@agent_app.command("inspect")
def agent_inspect_command(
    import_path: str = typer.Argument(..., help="Adapter import path in module:object format"),
    target_type: str | None = typer.Option(None, "--target-type", help=f"Override adapter target type: {', '.join(L2_TARGET_TYPES)}"),
    framework: str | None = typer.Option(None, "--framework", help=f"Framework label: {', '.join(AGENT_FRAMEWORKS)}"),
    route: str | None = typer.Option(None, "--route", help="Override HTTP route for the adapter"),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable adapter info"),
) -> None:
    """Load an adapter without serving it and print its normalized L2 contract."""
    try:
        loaded = load_agent_adapter(import_path, target_type=target_type, framework=framework, route=route)
    except AgentAdapterError as exc:
        typer.echo(f"agent_adapter: failed - {exc}", err=True)
        raise typer.Exit(code=1) from exc
    payload = {
        "schema_version": "malleus.agent_adapter.inspect.v1",
        "import_path": loaded.import_path,
        "target_type": loaded.target_type,
        "framework": loaded.framework,
        "route": loaded.route,
        "health": loaded.adapter.health(),
    }
    if json_output:
        typer.echo(json.dumps(payload, indent=2))
        return
    typer.echo("agent_adapter: ok")
    typer.echo(f"import_path: {loaded.import_path}")
    typer.echo(f"target_type: {loaded.target_type}")
    typer.echo(f"framework: {loaded.framework}")
    typer.echo(f"route: {loaded.route}")


@agent_app.command("serve")
def agent_serve_command(
    import_path: str = typer.Argument(..., help="Adapter import path in module:object format"),
    target_type: str | None = typer.Option(None, "--target-type", help=f"Override adapter target type: {', '.join(L2_TARGET_TYPES)}"),
    framework: str | None = typer.Option(None, "--framework", help=f"Framework label: {', '.join(AGENT_FRAMEWORKS)}"),
    host: str = typer.Option("127.0.0.1", "--host", help="Bind host", hidden=True),
    port: int = typer.Option(8787, "--port", min=0, max=65535, help="Bind port; use 0 to choose a free local port", hidden=True),
    route: str | None = typer.Option(None, "--route", help="Override HTTP route for the adapter", hidden=True),
    isolated: bool = typer.Option(False, "--isolated", help="Run the adapter in a child Python process with explicit env/PYTHONPATH allowlists"),
    cwd: Path | None = typer.Option(None, "--cwd", file_okay=False, help="Working directory for --isolated child process", hidden=True),
    env_allowlist: list[str] | None = typer.Option(None, "--env", help="Environment variable to pass to --isolated child; repeatable", hidden=True),
    pythonpath: list[Path] | None = typer.Option(None, "--pythonpath", exists=True, help="PYTHONPATH entry for --isolated child; repeatable", hidden=True),
    startup_timeout: float = typer.Option(10.0, "--startup-timeout", min=0.1, help="Seconds to wait for --isolated child to bind its port", hidden=True),
    sandbox: str = typer.Option("none", "--sandbox", help="Sandbox backend for --isolated: none or bwrap"),
    network_allowlist: list[str] | None = typer.Option(None, "--network-allowlist", help="Explicit shared-network listener allowlist for --sandbox bwrap, e.g. tcp://127.0.0.1:8787", hidden=True),
    network_mode: str = typer.Option("shared", "--network-mode", help="Network mode for --isolated: shared or blocked. blocked requires --sandbox bwrap and uses a stdio proxy.", hidden=True),
    tool_policy: Path | None = typer.Option(None, "--tool-policy", exists=True, dir_okay=False, readable=True, help="YAML/JSON Tool Gateway policy for --network-mode blocked", hidden=True),
) -> None:
    """Serve a Python adapter as a Malleus L2 HTTP target."""
    try:
        if sandbox != "none" and not isolated:
            raise AgentAdapterError("--sandbox requires --isolated")
        if isolated:
            serve_agent_adapter_isolated(
                import_path,
                host=host,
                port=port,
                target_type=target_type,
                framework=framework,
                route=route,
                cwd=cwd,
                env_allowlist=list(env_allowlist or []),
                pythonpath=list(pythonpath or []),
                startup_timeout=startup_timeout,
                sandbox=sandbox,
                network_allowlist=list(network_allowlist or []),
                network_mode=network_mode,
                tool_policy=tool_policy,
            )
        else:
            serve_agent_adapter(import_path, host=host, port=port, target_type=target_type, framework=framework, route=route)
    except AgentAdapterError as exc:
        typer.echo(f"agent_adapter: failed - {exc}", err=True)
        raise typer.Exit(code=1) from exc


@agent_app.command("inspect-tool-policy", hidden=True)
def agent_inspect_tool_policy_command(
    policy: Path | None = typer.Option(None, "--policy", exists=True, dir_okay=False, readable=True, help="YAML/JSON tool gateway policy; omit for the built-in default"),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable policy info"),
) -> None:
    """Inspect a Tool Gateway policy and its public hash."""
    try:
        loaded_policy = load_tool_policy(policy) if policy is not None else default_tool_policy()
    except Exception as exc:
        typer.echo(f"tool_gateway_policy: failed - {exc}", err=True)
        raise typer.Exit(code=1) from exc
    payload = {
        "schema_version": "malleus.tool_gateway_policy.inspect.v1",
        "policy_schema_version": loaded_policy.schema_version,
        "policy_hash": loaded_policy.policy_hash(),
        "tool_count": len(loaded_policy.tools),
        "tools": {
            name: {
                "allowed": spec.allowed,
                "requires_approval": spec.requires_approval,
                "source": spec.source,
                "sink": spec.sink,
                "has_fixture_result": bool(spec.result),
            }
            for name, spec in sorted(loaded_policy.tools.items())
        },
        "trusted_approval_sources": list(loaded_policy.trusted_approval_sources),
        "canary_count": len(loaded_policy.canaries),
    }
    if json_output:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    typer.echo("tool_gateway_policy: ok")
    typer.echo(f"policy_schema_version: {payload['policy_schema_version']}")
    typer.echo(f"policy_hash: {payload['policy_hash']}")
    typer.echo(f"tool_count: {payload['tool_count']}")
    for name, spec in payload["tools"].items():
        typer.echo(
            f"- {name}: allowed={str(spec['allowed']).lower()} "
            f"requires_approval={str(spec['requires_approval']).lower()} "
            f"source={spec['source']} sink={spec['sink']}"
        )


@agent_app.command("inspect-langgraph")
def agent_inspect_langgraph_command(
    import_path: str = typer.Argument(..., help="LangGraph graph import path in module:object format"),
    target_type: str = typer.Option("tool_agent", "--target-type", help=f"L2 target type: {', '.join(L2_TARGET_TYPES)}"),
    input_mode: str = typer.Option("hybrid", "--input-mode", help="Input mapping: hybrid, payload, or messages"),
    run_mode: str = typer.Option("auto", "--run-mode", help="Execution mode: auto, invoke, or stream"),
    route: str | None = typer.Option(None, "--route", help="Override HTTP route for the adapter"),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable adapter info"),
) -> None:
    """Inspect a LangGraph graph as a native Malleus L2 adapter."""
    try:
        loaded = load_langgraph_adapter(import_path, target_type=target_type, input_mode=input_mode, run_mode=run_mode, route=route)  # type: ignore[arg-type]
    except AgentAdapterError as exc:
        typer.echo(f"langgraph_adapter: failed - {exc}", err=True)
        raise typer.Exit(code=1) from exc
    payload = {
        "schema_version": "malleus.langgraph_adapter.inspect.v1",
        "import_path": loaded.import_path,
        "target_type": loaded.target_type,
        "framework": loaded.framework,
        "route": loaded.route,
        "health": loaded.adapter.health(),
    }
    if json_output:
        typer.echo(json.dumps(payload, indent=2))
        return
    typer.echo("langgraph_adapter: ok")
    typer.echo(f"import_path: {loaded.import_path}")
    typer.echo(f"target_type: {loaded.target_type}")
    typer.echo(f"framework: {loaded.framework}")
    typer.echo(f"route: {loaded.route}")
    typer.echo(f"input_mode: {input_mode}")
    typer.echo(f"run_mode: {run_mode}")


@agent_app.command("serve-langgraph")
def agent_serve_langgraph_command(
    import_path: str = typer.Argument(..., help="LangGraph graph import path in module:object format"),
    target_type: str = typer.Option("tool_agent", "--target-type", help=f"L2 target type: {', '.join(L2_TARGET_TYPES)}"),
    input_mode: str = typer.Option("hybrid", "--input-mode", help="Input mapping: hybrid, payload, or messages"),
    run_mode: str = typer.Option("auto", "--run-mode", help="Execution mode: auto, invoke, or stream"),
    host: str = typer.Option("127.0.0.1", "--host", help="Bind host"),
    port: int = typer.Option(8787, "--port", min=0, max=65535, help="Bind port; use 0 to choose a free local port"),
    route: str | None = typer.Option(None, "--route", help="Override HTTP route for the adapter"),
) -> None:
    """Serve a LangGraph graph as a native Malleus L2 HTTP target."""
    try:
        serve_langgraph_adapter(import_path, target_type=target_type, input_mode=input_mode, run_mode=run_mode, host=host, port=port, route=route)  # type: ignore[arg-type]
    except AgentAdapterError as exc:
        typer.echo(f"langgraph_adapter: failed - {exc}", err=True)
        raise typer.Exit(code=1) from exc


@agent_app.command("inspect-openai-agents")
def agent_inspect_openai_agents_command(
    import_path: str = typer.Argument(..., help="OpenAI Agents SDK agent import path in module:object format"),
    runner_import_path: str | None = typer.Option(None, "--runner", help="Optional Runner import path in module:object format"),
    target_type: str = typer.Option("tool_agent", "--target-type", help=f"L2 target type: {', '.join(L2_TARGET_TYPES)}"),
    input_mode: str = typer.Option("text", "--input-mode", help="Input mapping: text, payload, or messages"),
    run_mode: str = typer.Option("auto", "--run-mode", help="Execution mode: auto, run_sync, run, invoke, or call"),
    route: str | None = typer.Option(None, "--route", help="Override HTTP route for the adapter"),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable adapter info"),
) -> None:
    """Inspect an OpenAI Agents SDK agent as a native Malleus L2 adapter."""
    try:
        loaded = load_openai_agents_adapter(import_path, runner_import_path=runner_import_path, target_type=target_type, input_mode=input_mode, run_mode=run_mode, route=route)  # type: ignore[arg-type]
    except AgentAdapterError as exc:
        typer.echo(f"openai_agents_adapter: failed - {exc}", err=True)
        raise typer.Exit(code=1) from exc
    payload = {
        "schema_version": "malleus.openai_agents_adapter.inspect.v1",
        "import_path": loaded.import_path,
        "target_type": loaded.target_type,
        "framework": loaded.framework,
        "route": loaded.route,
        "health": loaded.adapter.health(),
    }
    if json_output:
        typer.echo(json.dumps(payload, indent=2))
        return
    typer.echo("openai_agents_adapter: ok")
    typer.echo(f"import_path: {loaded.import_path}")
    typer.echo(f"target_type: {loaded.target_type}")
    typer.echo(f"framework: {loaded.framework}")
    typer.echo(f"route: {loaded.route}")
    typer.echo(f"input_mode: {input_mode}")
    typer.echo(f"run_mode: {run_mode}")


@agent_app.command("serve-openai-agents")
def agent_serve_openai_agents_command(
    import_path: str = typer.Argument(..., help="OpenAI Agents SDK agent import path in module:object format"),
    runner_import_path: str | None = typer.Option(None, "--runner", help="Optional Runner import path in module:object format"),
    target_type: str = typer.Option("tool_agent", "--target-type", help=f"L2 target type: {', '.join(L2_TARGET_TYPES)}"),
    input_mode: str = typer.Option("text", "--input-mode", help="Input mapping: text, payload, or messages"),
    run_mode: str = typer.Option("auto", "--run-mode", help="Execution mode: auto, run_sync, run, invoke, or call"),
    host: str = typer.Option("127.0.0.1", "--host", help="Bind host"),
    port: int = typer.Option(8787, "--port", min=0, max=65535, help="Bind port; use 0 to choose a free local port"),
    route: str | None = typer.Option(None, "--route", help="Override HTTP route for the adapter"),
) -> None:
    """Serve an OpenAI Agents SDK agent as a native Malleus L2 HTTP target."""
    try:
        serve_openai_agents_adapter(
            import_path,
            runner_import_path=runner_import_path,
            target_type=target_type,
            input_mode=input_mode,
            run_mode=run_mode,
            host=host,
            port=port,
            route=route,
        )  # type: ignore[arg-type]
    except AgentAdapterError as exc:
        typer.echo(f"openai_agents_adapter: failed - {exc}", err=True)
        raise typer.Exit(code=1) from exc


@agent_app.command("inspect-callable")
def agent_inspect_callable_command(
    import_path: str = typer.Argument(..., help="Plain Python agent object/callable import path in module:object format"),
    target_type: str = typer.Option("tool_agent", "--target-type", help=f"L2 target type: {', '.join(L2_TARGET_TYPES)}"),
    input_mode: str = typer.Option("payload", "--input-mode", help="Input mapping: payload, text, or messages"),
    run_mode: str = typer.Option("auto", "--run-mode", help="Execution mode: auto, run, invoke, call, kickoff, or initiate_chat"),
    route: str | None = typer.Option(None, "--route", help="Override HTTP route for the adapter"),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable adapter info"),
) -> None:
    """Inspect a dependency-free Python callable/object as a native Malleus L2 adapter."""
    try:
        loaded = load_generic_agent_adapter(import_path, target_type=target_type, input_mode=input_mode, run_mode=run_mode, route=route)  # type: ignore[arg-type]
    except AgentAdapterError as exc:
        typer.echo(f"callable_adapter: failed - {exc}", err=True)
        raise typer.Exit(code=1) from exc
    _echo_loaded_agent("callable_adapter", "malleus.callable_adapter.inspect.v1", loaded, json_output=json_output, extra={"input_mode": input_mode, "run_mode": run_mode})


@agent_app.command("serve-callable")
def agent_serve_callable_command(
    import_path: str = typer.Argument(..., help="Plain Python agent object/callable import path in module:object format"),
    target_type: str = typer.Option("tool_agent", "--target-type", help=f"L2 target type: {', '.join(L2_TARGET_TYPES)}"),
    input_mode: str = typer.Option("payload", "--input-mode", help="Input mapping: payload, text, or messages"),
    run_mode: str = typer.Option("auto", "--run-mode", help="Execution mode: auto, run, invoke, call, kickoff, or initiate_chat"),
    host: str = typer.Option("127.0.0.1", "--host", help="Bind host"),
    port: int = typer.Option(8787, "--port", min=0, max=65535, help="Bind port; use 0 to choose a free local port"),
    route: str | None = typer.Option(None, "--route", help="Override HTTP route for the adapter"),
) -> None:
    """Serve a dependency-free Python callable/object as a native Malleus L2 HTTP target."""
    try:
        serve_generic_agent_adapter(import_path, target_type=target_type, input_mode=input_mode, run_mode=run_mode, host=host, port=port, route=route)  # type: ignore[arg-type]
    except AgentAdapterError as exc:
        typer.echo(f"callable_adapter: failed - {exc}", err=True)
        raise typer.Exit(code=1) from exc


@agent_app.command("inspect-langchain-rag")
def agent_inspect_langchain_rag_command(
    import_path: str = typer.Argument(..., help="LangChain chain or retriever import path in module:object format"),
    input_mode: str = typer.Option("mapping", "--input-mode", help="Input mapping: query, payload, or mapping"),
    run_mode: str = typer.Option("auto", "--run-mode", help="Execution mode: auto, invoke, query, retrieve, or call"),
    route: str | None = typer.Option(None, "--route", help="Override HTTP route for the adapter"),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable adapter info"),
) -> None:
    """Inspect a LangChain RAG object as a native Malleus rag_service target."""
    try:
        loaded = load_langchain_rag_adapter(import_path, input_mode=input_mode, run_mode=run_mode, route=route)  # type: ignore[arg-type]
    except AgentAdapterError as exc:
        typer.echo(f"langchain_rag_adapter: failed - {exc}", err=True)
        raise typer.Exit(code=1) from exc
    _echo_loaded_agent("langchain_rag_adapter", "malleus.langchain_rag_adapter.inspect.v1", loaded, json_output=json_output, extra={"input_mode": input_mode, "run_mode": run_mode})


@agent_app.command("serve-langchain-rag")
def agent_serve_langchain_rag_command(
    import_path: str = typer.Argument(..., help="LangChain chain or retriever import path in module:object format"),
    input_mode: str = typer.Option("mapping", "--input-mode", help="Input mapping: query, payload, or mapping"),
    run_mode: str = typer.Option("auto", "--run-mode", help="Execution mode: auto, invoke, query, retrieve, or call"),
    host: str = typer.Option("127.0.0.1", "--host", help="Bind host"),
    port: int = typer.Option(8787, "--port", min=0, max=65535, help="Bind port; use 0 to choose a free local port"),
    route: str | None = typer.Option(None, "--route", help="Override HTTP route for the adapter"),
) -> None:
    """Serve a LangChain chain or retriever as a native Malleus rag_service target."""
    try:
        serve_langchain_rag_adapter(import_path, input_mode=input_mode, run_mode=run_mode, host=host, port=port, route=route)  # type: ignore[arg-type]
    except AgentAdapterError as exc:
        typer.echo(f"langchain_rag_adapter: failed - {exc}", err=True)
        raise typer.Exit(code=1) from exc


@agent_app.command("inspect-llamaindex-rag")
def agent_inspect_llamaindex_rag_command(
    import_path: str = typer.Argument(..., help="LlamaIndex query engine/retriever/index import path in module:object format"),
    input_mode: str = typer.Option("query", "--input-mode", help="Input mapping: query, payload, or mapping"),
    run_mode: str = typer.Option("auto", "--run-mode", help="Execution mode: auto, invoke, query, retrieve, or call"),
    route: str | None = typer.Option(None, "--route", help="Override HTTP route for the adapter"),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable adapter info"),
) -> None:
    """Inspect a LlamaIndex RAG object as a native Malleus rag_service target."""
    try:
        loaded = load_llamaindex_rag_adapter(import_path, input_mode=input_mode, run_mode=run_mode, route=route)  # type: ignore[arg-type]
    except AgentAdapterError as exc:
        typer.echo(f"llamaindex_rag_adapter: failed - {exc}", err=True)
        raise typer.Exit(code=1) from exc
    _echo_loaded_agent("llamaindex_rag_adapter", "malleus.llamaindex_rag_adapter.inspect.v1", loaded, json_output=json_output, extra={"input_mode": input_mode, "run_mode": run_mode})


@agent_app.command("serve-llamaindex-rag")
def agent_serve_llamaindex_rag_command(
    import_path: str = typer.Argument(..., help="LlamaIndex query engine/retriever/index import path in module:object format"),
    input_mode: str = typer.Option("query", "--input-mode", help="Input mapping: query, payload, or mapping"),
    run_mode: str = typer.Option("auto", "--run-mode", help="Execution mode: auto, invoke, query, retrieve, or call"),
    host: str = typer.Option("127.0.0.1", "--host", help="Bind host"),
    port: int = typer.Option(8787, "--port", min=0, max=65535, help="Bind port; use 0 to choose a free local port"),
    route: str | None = typer.Option(None, "--route", help="Override HTTP route for the adapter"),
) -> None:
    """Serve a LlamaIndex query engine/retriever/index as a native Malleus rag_service target."""
    try:
        serve_llamaindex_rag_adapter(import_path, input_mode=input_mode, run_mode=run_mode, host=host, port=port, route=route)  # type: ignore[arg-type]
    except AgentAdapterError as exc:
        typer.echo(f"llamaindex_rag_adapter: failed - {exc}", err=True)
        raise typer.Exit(code=1) from exc


def _echo_loaded_agent(label: str, schema_version: str, loaded: object, *, json_output: bool, extra: dict[str, object] | None = None) -> None:
    payload = {
        "schema_version": schema_version,
        "import_path": getattr(loaded, "import_path"),
        "target_type": getattr(loaded, "target_type"),
        "framework": getattr(loaded, "framework"),
        "route": getattr(loaded, "route"),
        "health": getattr(loaded, "adapter").health(),
        **dict(extra or {}),
    }
    if json_output:
        typer.echo(json.dumps(payload, indent=2))
        return
    typer.echo(f"{label}: ok")
    typer.echo(f"import_path: {payload['import_path']}")
    typer.echo(f"target_type: {payload['target_type']}")
    typer.echo(f"framework: {payload['framework']}")
    typer.echo(f"route: {payload['route']}")
    for key, value in dict(extra or {}).items():
        typer.echo(f"{key}: {value}")




@ui_harness_app.command("plan")
def ui_harness_plan_command(
    config: Path = typer.Option(..., "--config", exists=True, dir_okay=False, readable=True, help="Local/staging UI harness YAML config"),
    out_dir: Path = typer.Option(..., "--out-dir", file_okay=False, help="Output directory for ui-harness-plan.json/md"),
    dry_run: bool = typer.Option(True, "--dry-run/--no-dry-run", help="Write scaffold artifacts only; browser and provider calls stay disabled"),
    live_ui: bool = typer.Option(False, "--live-ui", help="Request gated live UI scaffold mode; requires matching --allowed-url and still captures no screenshots"),
    allowed_url: list[str] | None = typer.Option(None, "--allowed-url", help="Explicit local/staging URL allowlist entry; repeatable"),
) -> None:
    try:
        plan, json_path, markdown_path = write_ui_harness_plan(config, out_dir, dry_run=dry_run, live_ui=live_ui, allowed_urls=list(allowed_url or []))
    except (ValueError, ValidationError) as exc:
        typer.echo(_format_cli_error(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("UI harness plan written")
    typer.echo(f"Mode: {plan.mode}")
    typer.echo(f"Provider calls enabled: {str(plan.provider_calls_enabled).lower()}")
    typer.echo(f"Browser enabled: {str(plan.browser_enabled).lower()}")
    typer.echo(f"Planned submissions: {len(plan.planned_prompt_submissions)}")
    typer.echo(f"JSON: {json_path}")
    typer.echo(f"Markdown: {markdown_path}")


@ui_harness_app.command("run")
def ui_harness_run_command(
    config: Path = typer.Option(..., "--config", exists=True, dir_okay=False, readable=True, help="Local/staging UI harness YAML config"),
    out_dir: Path = typer.Option(..., "--out-dir", file_okay=False, help="Output directory for ui-harness plan/report artifacts"),
    dry_run: bool = typer.Option(True, "--dry-run/--no-dry-run", help="Write scaffold artifacts only; browser and provider calls stay disabled"),
    live_ui: bool = typer.Option(False, "--live-ui", help="Request gated live UI scaffold mode; requires matching --allowed-url and still captures no screenshots"),
    allowed_url: list[str] | None = typer.Option(None, "--allowed-url", help="Explicit local/staging URL allowlist entry; repeatable"),
) -> None:
    try:
        report, json_path, markdown_path = write_ui_harness_report(config, out_dir, dry_run=dry_run, live_ui=live_ui, allowed_urls=list(allowed_url or []))
    except (ValueError, ValidationError) as exc:
        typer.echo(_format_cli_error(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("UI harness dry-run report written")
    typer.echo(f"Mode: {report.mode}")
    typer.echo(f"Provider calls enabled: {str(report.provider_calls_enabled).lower()}")
    typer.echo(f"Browser enabled: {str(report.browser_enabled).lower()}")
    typer.echo(f"Findings: {len(report.findings)}")
    typer.echo(f"JSON: {json_path}")
    typer.echo(f"Markdown: {markdown_path}")


@taxonomy_app.command("snapshot")
def taxonomy_snapshot_command(
    input_path: list[Path] = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True, help="Dataset or benchmark pack YAML; repeatable"),
    out_dir: Path = typer.Option(..., "--out-dir", file_okay=False, help="Output directory for taxonomy-snapshot.json/md and companion snapshots"),
    coverage: list[Path] | None = typer.Option(None, "--coverage", exists=True, dir_okay=False, readable=True, help="Optional existing coverage.json to merge; repeatable"),
    scenario_coverage: list[Path] | None = typer.Option(None, "--scenario-coverage", exists=True, dir_okay=False, readable=True, help="Optional scenario coverage-preview.json; repeatable"),
) -> None:
    try:
        snapshot, paths = write_taxonomy_snapshot(list(input_path), out_dir, coverage_paths=list(coverage or []), scenario_coverage_paths=list(scenario_coverage or []))
    except (ValueError, ValidationError) as exc:
        typer.echo(_format_cli_error(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("Taxonomy snapshot written")
    typer.echo("Provider calls enabled: false")
    typer.echo(f"Dataset items: {snapshot.summary.dataset_items}")
    typer.echo(f"Coverage cells: {snapshot.summary.coverage_cells}")
    typer.echo(f"Scenario cells: {snapshot.summary.scenario_cells}")
    typer.echo(f"JSON: {paths['taxonomy_json']}")
    typer.echo(f"Markdown: {paths['taxonomy_markdown']}")
    typer.echo(f"Dataset snapshot: {paths['dataset_json']}")
    typer.echo(f"Coverage snapshot: {paths['coverage_json']}")


@taxonomy_app.command("diff")
def taxonomy_diff_command(
    old: Path = typer.Option(..., "--old", exists=True, dir_okay=False, readable=True, help="Old taxonomy-snapshot.json"),
    new: Path = typer.Option(..., "--new", exists=True, dir_okay=False, readable=True, help="New taxonomy-snapshot.json"),
    out_dir: Path = typer.Option(..., "--out-dir", file_okay=False, help="Output directory for taxonomy-diff.json/md"),
) -> None:
    try:
        report, json_path, markdown_path = write_taxonomy_diff(old, new, out_dir)
    except (ValueError, ValidationError) as exc:
        typer.echo(_format_cli_error(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("Taxonomy diff written")
    typer.echo(f"Added cells: {report.summary.added_cells}")
    typer.echo(f"Removed cells: {report.summary.removed_cells}")
    typer.echo(f"Changed cells: {report.summary.changed_cells}")
    typer.echo(f"JSON: {json_path}")
    typer.echo(f"Markdown: {markdown_path}")


@studio_app.command("export")
def studio_export_command(
    report_dir: Path = typer.Option(..., "--report-dir", exists=True, file_okay=False, readable=True, help="Local WOW++ report directory to summarize"),
    out_dir: Path = typer.Option(..., "--out-dir", file_okay=False, help="Output root; studio/index.html and studio/artifact-index.json are written below it"),
) -> None:
    try:
        export = export_studio(report_dir, out_dir)
    except (ValueError, ValidationError) as exc:
        typer.echo(_format_cli_error(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("Studio export written")
    typer.echo(f"HTML: {export.index_html}")
    typer.echo(f"Artifact index: {export.artifact_index}")
    typer.echo(f"Artifacts: {len(export.artifacts)}")


@benchmark_app.command("plan", hidden=True)
def benchmark_plan_command(
    models: Path = typer.Option(..., "--models", exists=True, dir_okay=False, readable=True, help="Benchmark panel YAML with 5 to 8 model entries"),
    out_dir: Path = typer.Option(..., "--out-dir", file_okay=False, help="Output directory for benchmark-plan.json/md"),
    dry_run: bool = typer.Option(True, "--dry-run/--no-dry-run", help="Write command plans only; provider calls stay disabled"),
) -> None:
    if not dry_run:
        typer.echo("benchmark plan only supports provider-free dry-run planning.", err=True)
        raise typer.Exit(code=1)
    plan, json_path, markdown_path = write_benchmark_plan(models, out_dir, dry_run=True)
    typer.echo("Benchmark plan written")
    typer.echo(f"Provider calls enabled: {str(plan.provider_calls_enabled).lower()}")
    typer.echo(f"Models: {len(plan.models)}")
    typer.echo(f"Planned commands: {len(plan.steps)}")
    typer.echo(f"JSON: {json_path}")
    typer.echo(f"Markdown: {markdown_path}")


@benchmark_app.command("summarize", hidden=True)
def benchmark_summarize_command(
    reports: Path = typer.Option(..., "--reports", exists=True, readable=True, help="Local fixture report directory or report.json"),
    out_dir: Path = typer.Option(..., "--out-dir", file_okay=False, help="Output directory for leaderboard and case studies"),
    write_readme: Path | None = typer.Option(None, "--write-readme", dir_okay=False, help="Explicit README or docs path to update with a bounded benchmark block"),
) -> None:
    summary, json_path, markdown_path = summarize_benchmark_reports(reports, out_dir, write_readme=write_readme)
    typer.echo("Benchmark summary written")
    typer.echo(f"Models: {len(summary.leaderboard)}")
    typer.echo(f"Case studies: {len(summary.case_studies)}")
    typer.echo(f"JSON: {json_path}")
    typer.echo(f"Markdown: {markdown_path}")
    if summary.readme_written:
        typer.echo(f"README block written: {summary.readme_written}")


@benchmark_app.command("validate-matrix", hidden=True)
def benchmark_validate_matrix_command(
    matrix_path: Path = typer.Option(..., "--matrix", exists=True, dir_okay=False, readable=True, help="Release matrix YAML to validate"),
) -> None:
    try:
        matrix = load_release_matrix(matrix_path)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("Release matrix valid")
    typer.echo("Provider calls enabled: false")
    typer.echo("Judge required: false")
    typer.echo(f"Matrix: {matrix.id} {matrix.version}")
    typer.echo(f"Mode boundaries: {len(matrix.mode_boundaries)}")
    pack_entries = len(matrix.packs)
    selected_profile_entries = len(matrix.selected_mutation_profiles)
    deep_profile_entries = len(matrix.deep_mutation_profiles)
    typer.echo(f"Pack entries: {pack_entries}")
    typer.echo(f"Selected mutation profiles: {selected_profile_entries}")
    typer.echo(f"Deep mutation profiles: {deep_profile_entries}")
    typer.echo(f"Total scoped entries: {pack_entries + selected_profile_entries + deep_profile_entries}")
    typer.echo(f"Gates: {len(matrix.gates)}")


@benchmark_app.command("suite", hidden=True)
def benchmark_suite_command(
    target: Path = typer.Option(..., "--target", exists=True, readable=True, dir_okay=False, help="Target YAML to benchmark"),
    matrix: Path = typer.Option(DEFAULT_RELEASE_MATRIX_PATH, "--matrix", exists=True, readable=True, dir_okay=False, help="Release matrix with packs"),
    out_dir: Path = typer.Option(..., "--out-dir", file_okay=False, help="Output directory for benchmark-suite-report artifacts"),
    pack: list[str] | None = typer.Option(None, "--pack", help="Restrict to a compatible pack id; repeatable"),
    include_scaffold: bool = typer.Option(False, "--include-scaffold", help="Include scaffold/planned compatible packs"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Write the suite plan without executing packs"),
    yes: bool = typer.Option(True, "--yes", help="Deprecated; benchmark suite runs directly", hidden=True),
) -> None:
    """Run all release-matrix packs compatible with a target type."""
    try:
        report = run_benchmark_suite(
            target,
            matrix,
            out_dir,
            pack_ids=list(pack or []),
            include_scaffold=include_scaffold,
            dry_run=dry_run,
            yes=yes,
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Benchmark suite written: {out_dir / 'benchmark-suite-report.json'}")
    typer.echo(f"Target: {report.target_name} ({report.target_type})")
    typer.echo(f"Packs: {len(report.packs)}")
    typer.echo(f"Dry run: {str(report.dry_run).lower()}")
    if report.status_counts:
        typer.echo("Statuses: " + ", ".join(f"{key}={value}" for key, value in sorted(report.status_counts.items())))


@benchmark_app.command("live-full", hidden=True)
def benchmark_live_full_command(
    target: str = typer.Option(..., "--target", help="Target model YAML config or managed target name"),
    matrix: Path = typer.Option(..., "--matrix", exists=True, dir_okay=False, readable=True, help="Release matrix YAML"),
    mutation_profile: Path = typer.Option(..., "--mutation-profile", exists=True, dir_okay=False, readable=True, help="Selected mutation profile YAML"),
    out_dir: Path = typer.Option(..., "--out-dir", file_okay=False, help="Output directory for live-full evidence artifacts"),
    dry_run: bool = typer.Option(True, "--dry-run/--no-dry-run", help="Must be disabled explicitly; dry-run cannot be full-live evidence"),
    include_deep_mutations: bool = typer.Option(False, "--include-deep-mutations", help="Include optional deep mutation profile rows"),
    deep_mutation_profile: Path | None = typer.Option(None, "--deep-mutation-profile", exists=True, dir_okay=False, readable=True, help="Optional deep mutation profile YAML"),
    yes: bool = typer.Option(True, "--yes", help="Deprecated; live benchmark commands run directly", hidden=True),
    concurrency: int = typer.Option(1, "--concurrency", min=1, help="Record requested concurrency in run metadata; live-full execution is currently sequential", hidden=True),
    request_timeout: float = typer.Option(120.0, "--request-timeout", min=0.000001, help="Provider request timeout in seconds", hidden=True),
    max_retries: int = typer.Option(1, "--max-retries", min=0, help="Maximum provider retry attempts", hidden=True),
    quiet: bool = typer.Option(False, "--quiet", help="Suppress live progress output and print only the final summary", hidden=True),
    trace_log: Path | None = typer.Option(None, "--trace-log", dir_okay=False, help="Write full live progress/scenario trace events as JSONL for post-run audit"),
    config_dir: Path | None = typer.Option(None, "--config-dir", file_okay=False, help="Managed target directory", hidden=True),
) -> None:
    target_path = _resolve_cli_target(target, config_dir)
    try:
        evidence, json_path, markdown_path = run_live_full_matrix(
            target_path=target_path,
            matrix_path=matrix,
            mutation_profile_path=mutation_profile,
            out_dir=out_dir,
            dry_run=dry_run,
            include_deep_mutations=include_deep_mutations,
            deep_mutation_profile_path=deep_mutation_profile,
            yes=yes,
            concurrency=concurrency,
            request_timeout=request_timeout,
            max_retries=max_retries,
            progress_callback=_live_benchmark_progress_printer(quiet=quiet, trace_log=trace_log),
        )
    except (ValueError, ValidationError) as exc:
        typer.echo(_format_cli_error(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("Live-full evidence matrix written")
    typer.echo("Mode: live_provider")
    typer.echo("Dry run: false")
    typer.echo("Provider calls enabled: true")
    typer.echo(f"Rows: {len(evidence.rows)}")
    typer.echo(f"JSON: {json_path}")
    typer.echo(f"Markdown: {markdown_path}")
    if trace_log is not None:
        typer.echo(f"Trace log: {trace_log}")


def _benchmark_live_surface_command(
    *,
    surface: str,
    target: str,
    out_dir: Path,
    yes: bool,
    matrix: Path,
    request_timeout: float,
    max_retries: int,
    config_dir: Path | None,
    quiet: bool = False,
    trace_log: Path | None = None,
    mutation_profile: Path | None = None,
    mutation_limit: int | None = None,
) -> None:
    target_path = _resolve_cli_target(target, config_dir)
    try:
        evidence, json_path, markdown_path = run_live_surface_pack(
            target_path=target_path,
            pack_id=surface,
            out_dir=out_dir,
            matrix_path=matrix,
            yes=yes,
            request_timeout=request_timeout,
            max_retries=max_retries,
            progress_callback=_live_benchmark_progress_printer(quiet=quiet, trace_log=trace_log),
            mutation_profile_path=mutation_profile,
            mutation_limit=mutation_limit,
        )
    except (ValueError, ValidationError) as exc:
        typer.echo(_format_cli_error(exc), err=True)
        raise typer.Exit(code=1) from exc
    row = evidence.rows[0]
    typer.echo("Live surface evidence written")
    typer.echo(f"Surface: {surface}")
    typer.echo(f"Rows: {len(evidence.rows)}")
    typer.echo(f"Status: {row.status}" if len(evidence.rows) == 1 else f"Statuses: {', '.join(f'{item.row_id}={item.status}' for item in evidence.rows)}")
    typer.echo(f"Evidence level: {row.evidence_level}")
    typer.echo(f"Evidence fidelity: {row.evidence_fidelity}")
    typer.echo("Dry run: false")
    typer.echo("Provider calls enabled: true")
    typer.echo(f"JSON: {json_path}")
    typer.echo(f"Markdown: {markdown_path}")
    if trace_log is not None:
        typer.echo(f"Trace log: {trace_log}")


def _maybe_resolve_bundle(reference: str, bundle_dir: Path | None = None) -> Path | None:
    candidate = Path(reference).expanduser()
    if candidate.exists():
        return candidate.resolve() if is_target_bundle_file(candidate) else None
    try:
        return resolve_bundle(reference, bundle_dir)
    except TargetStoreError:
        return None


def _run_bundle_exterminatus_command(
    *,
    bundle_path: Path,
    out_dir: Path,
    yes: bool,
    matrix: Path,
    mutation_profile: Path,
    deep_mutation_profile: Path,
    concurrency: int,
    request_timeout: float,
    max_retries: int,
    quiet: bool,
    trace_log: Path | None,
    config_dir: Path | None,
) -> None:
    doctor = doctor_target_bundle(bundle_path, target_dir=config_dir)
    if not doctor.ok:
        typer.echo("target bundle is not ready for exterminatus:", err=True)
        typer.echo(json.dumps(doctor.to_dict(), indent=2), err=True)
        raise typer.Exit(code=1)
    assert doctor.model_target_path is not None
    out_dir.mkdir(parents=True, exist_ok=True)
    model_out = out_dir / "model"
    model_trace_log = trace_log
    if trace_log is not None:
        model_trace_log = trace_log.with_name(f"{trace_log.stem}-model{trace_log.suffix}")
    evidence, model_json, model_md = run_exterminatus_benchmark(
        target_path=doctor.model_target_path,
        out_dir=model_out,
        yes=yes,
        matrix_path=matrix,
        mutation_profile_path=mutation_profile,
        deep_mutation_profile_path=deep_mutation_profile,
        concurrency=concurrency,
        request_timeout=request_timeout,
        max_retries=max_retries,
        progress_callback=_live_benchmark_progress_printer(quiet=quiet, trace_log=model_trace_log),
    )
    surface_results: list[dict[str, object]] = []
    bundle = doctor.bundle
    for surface, pack_id in SURFACE_PACK_IDS.items():
        surface_config = bundle.surfaces.get(surface)  # type: ignore[arg-type]
        if surface_config is None:
            continue
        surface_target = _resolve_cli_target(surface_config.target, config_dir)
        surface_out = out_dir / "surfaces" / surface
        surface_trace_log = None
        if trace_log is not None:
            surface_trace_log = trace_log.with_name(f"{trace_log.stem}-{surface}{trace_log.suffix}")
        surface_evidence, surface_json, surface_md = run_live_surface_pack(
            target_path=surface_target,
            pack_id=pack_id,
            out_dir=surface_out,
            matrix_path=matrix,
            yes=yes,
            request_timeout=request_timeout,
            max_retries=max_retries,
            progress_callback=_live_benchmark_progress_printer(quiet=quiet, trace_log=surface_trace_log),
        )
        row = surface_evidence.rows[0]
        surface_results.append(
            {
                "surface": surface,
                "pack_id": pack_id,
                "target": surface_config.target,
                "status": row.status,
                "evidence_fidelity": row.evidence_fidelity,
                "evidence_level": row.evidence_level,
                "target_call_count": row.metadata.get("target_call_count", 0),
                "target_trace_count": row.metadata.get("target_trace_count", 0),
                "backing_model_calls": row.metadata.get("backing_model_calls", 0),
                "report_json": str(surface_json),
                "report_markdown": str(surface_md),
            }
        )
    summary = {
        "schema_version": "malleus.bundle_exterminatus.v1",
        "bundle": bundle.name,
        "bundle_path": str(bundle_path),
        "mode": "exterminatus",
        "dry_run": False,
        "provider_calls_enabled": True,
        "model_report_json": str(model_json),
        "model_report_markdown": str(model_md),
        "model_rows": len(evidence.rows),
        "surface_results": surface_results,
        "run_quality": {
            "surface_count": len(surface_results),
            "high_fidelity_surfaces": sum(1 for item in surface_results if str(item.get("evidence_fidelity", "")).startswith(("live_", "controlled_"))),
            "surface_gaps": [item for item in surface_results if item.get("status") == "target_capability_gap"],
            "surface_target_errors": [item for item in surface_results if item.get("status") in {"target_error", "target_config_error", "infra_error"}],
        },
    }
    summary_path = out_dir / "bundle-exterminatus-summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    typer.echo("Bundle exterminatus evidence written")
    typer.echo(f"Bundle: {bundle.name}")
    typer.echo(f"Model rows: {len(evidence.rows)}")
    typer.echo(f"High-fidelity surfaces: {summary['run_quality']['high_fidelity_surfaces']}/{len(surface_results)}")
    typer.echo(f"Summary: {summary_path}")
    typer.echo(f"Model JSON: {model_json}")
    for item in surface_results:
        typer.echo(
            f"  - {item['surface']}: {item['status']} | {item['evidence_fidelity']} | "
            f"traces={item['target_trace_count']} calls={item['target_call_count']} | {item['report_json']}"
        )


@benchmark_app.command("live-rag")
def benchmark_live_rag_command(
    target: str = typer.Option(..., "--target", help="RAG service target YAML config or managed target name"),
    out_dir: Path | None = typer.Option(None, "--out-dir", file_okay=False, help="Output directory; defaults to reports/<target>-live-rag-<timestamp>"),
    yes: bool = typer.Option(True, "--yes", help="Deprecated; live benchmark commands run directly", hidden=True),
    matrix: Path = typer.Option(DEFAULT_RELEASE_MATRIX_PATH, "--matrix", exists=True, dir_okay=False, readable=True, help="Release matrix YAML; defaults to canonical malleus-v0.1", hidden=True),
    request_timeout: float = typer.Option(120.0, "--request-timeout", min=0.000001, help="Target request timeout in seconds", hidden=True),
    max_retries: int = typer.Option(1, "--max-retries", min=0, help="Maximum target retry attempts", hidden=True),
    quiet: bool = typer.Option(False, "--quiet", help="Suppress live progress output and print only the final summary", hidden=True),
    trace_log: Path | None = typer.Option(None, "--trace-log", dir_okay=False, help="Write full live progress/scenario trace events as JSONL for post-run audit"),
    mutation_profile: Path | None = typer.Option(None, "--mutation-profile", exists=True, dir_okay=False, readable=True, help="Also run mutated variants of the lab fixture with this mutation profile"),
    mutation_limit: int | None = typer.Option(None, "--mutation-limit", min=1, help="Maximum number of fixture mutations to run for this surface"),
    config_dir: Path | None = typer.Option(None, "--config-dir", file_okay=False, help="Managed target directory", hidden=True),
) -> None:
    """Run canonical rag-v1 against a real rag_service target."""
    out_dir = out_dir or _default_report_dir(target, "live-rag")
    _benchmark_live_surface_command(surface="rag-v1", target=target, out_dir=out_dir, yes=yes, matrix=matrix, request_timeout=request_timeout, max_retries=max_retries, config_dir=config_dir, quiet=quiet, trace_log=trace_log, mutation_profile=mutation_profile, mutation_limit=mutation_limit)


@benchmark_app.command("live-agentic")
def benchmark_live_agentic_command(
    target: str = typer.Option(..., "--target", help="Tool-agent target YAML config or managed target name"),
    out_dir: Path | None = typer.Option(None, "--out-dir", file_okay=False, help="Output directory; defaults to reports/<target>-live-agentic-<timestamp>"),
    yes: bool = typer.Option(True, "--yes", help="Deprecated; live benchmark commands run directly", hidden=True),
    matrix: Path = typer.Option(DEFAULT_RELEASE_MATRIX_PATH, "--matrix", exists=True, dir_okay=False, readable=True, help="Release matrix YAML; defaults to canonical malleus-v0.1", hidden=True),
    request_timeout: float = typer.Option(120.0, "--request-timeout", min=0.000001, help="Target request timeout in seconds", hidden=True),
    max_retries: int = typer.Option(1, "--max-retries", min=0, help="Maximum target retry attempts", hidden=True),
    quiet: bool = typer.Option(False, "--quiet", help="Suppress live progress output and print only the final summary", hidden=True),
    trace_log: Path | None = typer.Option(None, "--trace-log", dir_okay=False, help="Write full live progress/scenario trace events as JSONL for post-run audit"),
    mutation_profile: Path | None = typer.Option(None, "--mutation-profile", exists=True, dir_okay=False, readable=True, help="Also run mutated variants of the lab fixture with this mutation profile"),
    mutation_limit: int | None = typer.Option(None, "--mutation-limit", min=1, help="Maximum number of fixture mutations to run for this surface"),
    config_dir: Path | None = typer.Option(None, "--config-dir", file_okay=False, help="Managed target directory", hidden=True),
) -> None:
    """Run canonical agentic-injection-v1 against a real tool_agent target."""
    out_dir = out_dir or _default_report_dir(target, "live-agentic")
    _benchmark_live_surface_command(surface="agentic-injection-v1", target=target, out_dir=out_dir, yes=yes, matrix=matrix, request_timeout=request_timeout, max_retries=max_retries, config_dir=config_dir, quiet=quiet, trace_log=trace_log, mutation_profile=mutation_profile, mutation_limit=mutation_limit)


@benchmark_app.command("live-workflow")
def benchmark_live_workflow_command(
    target: str = typer.Option(..., "--target", help="Workflow harness target YAML config or managed target name"),
    out_dir: Path | None = typer.Option(None, "--out-dir", file_okay=False, help="Output directory; defaults to reports/<target>-live-workflow-<timestamp>"),
    yes: bool = typer.Option(True, "--yes", help="Deprecated; live benchmark commands run directly", hidden=True),
    matrix: Path = typer.Option(DEFAULT_RELEASE_MATRIX_PATH, "--matrix", exists=True, dir_okay=False, readable=True, help="Release matrix YAML; defaults to canonical malleus-v0.1", hidden=True),
    request_timeout: float = typer.Option(120.0, "--request-timeout", min=0.000001, help="Target request timeout in seconds", hidden=True),
    max_retries: int = typer.Option(1, "--max-retries", min=0, help="Maximum target retry attempts", hidden=True),
    quiet: bool = typer.Option(False, "--quiet", help="Suppress live progress output and print only the final summary", hidden=True),
    trace_log: Path | None = typer.Option(None, "--trace-log", dir_okay=False, help="Write full live progress/scenario trace events as JSONL for post-run audit"),
    mutation_profile: Path | None = typer.Option(None, "--mutation-profile", exists=True, dir_okay=False, readable=True, help="Also run mutated variants of the lab fixture with this mutation profile"),
    mutation_limit: int | None = typer.Option(None, "--mutation-limit", min=1, help="Maximum number of fixture mutations to run for this surface"),
    config_dir: Path | None = typer.Option(None, "--config-dir", file_okay=False, help="Managed target directory", hidden=True),
) -> None:
    """Run canonical plugin-workflow-v1 against a real workflow_harness target."""
    out_dir = out_dir or _default_report_dir(target, "live-workflow")
    _benchmark_live_surface_command(surface="plugin-workflow-v1", target=target, out_dir=out_dir, yes=yes, matrix=matrix, request_timeout=request_timeout, max_retries=max_retries, config_dir=config_dir, quiet=quiet, trace_log=trace_log, mutation_profile=mutation_profile, mutation_limit=mutation_limit)


@benchmark_app.command("live-code-agent")
def benchmark_live_code_agent_command(
    target: str = typer.Option(..., "--target", help="Code-agent target YAML config or managed target name"),
    out_dir: Path | None = typer.Option(None, "--out-dir", file_okay=False, help="Output directory; defaults to reports/<target>-live-code-agent-<timestamp>"),
    yes: bool = typer.Option(True, "--yes", help="Deprecated; live benchmark commands run directly", hidden=True),
    matrix: Path = typer.Option(DEFAULT_RELEASE_MATRIX_PATH, "--matrix", exists=True, dir_okay=False, readable=True, help="Release matrix YAML; defaults to canonical malleus-v0.1", hidden=True),
    request_timeout: float = typer.Option(120.0, "--request-timeout", min=0.000001, help="Target request timeout in seconds", hidden=True),
    max_retries: int = typer.Option(1, "--max-retries", min=0, help="Maximum target retry attempts", hidden=True),
    quiet: bool = typer.Option(False, "--quiet", help="Suppress live progress output and print only the final summary", hidden=True),
    trace_log: Path | None = typer.Option(None, "--trace-log", dir_okay=False, help="Write full live progress/scenario trace events as JSONL for post-run audit"),
    mutation_profile: Path | None = typer.Option(None, "--mutation-profile", exists=True, dir_okay=False, readable=True, help="Also run mutated variants of the lab fixture with this mutation profile"),
    mutation_limit: int | None = typer.Option(None, "--mutation-limit", min=1, help="Maximum number of fixture mutations to run for this surface"),
    config_dir: Path | None = typer.Option(None, "--config-dir", file_okay=False, help="Managed target directory", hidden=True),
) -> None:
    """Run canonical code-agent-v1 against a real code_agent target."""
    out_dir = out_dir or _default_report_dir(target, "live-code-agent")
    _benchmark_live_surface_command(surface="code-agent-v1", target=target, out_dir=out_dir, yes=yes, matrix=matrix, request_timeout=request_timeout, max_retries=max_retries, config_dir=config_dir, quiet=quiet, trace_log=trace_log, mutation_profile=mutation_profile, mutation_limit=mutation_limit)


@benchmark_app.command("live-memory-agent")
def benchmark_live_memory_agent_command(
    target: str = typer.Option(..., "--target", help="Memory-agent target YAML config or managed target name"),
    out_dir: Path | None = typer.Option(None, "--out-dir", file_okay=False, help="Output directory; defaults to reports/<target>-live-memory-agent-<timestamp>"),
    yes: bool = typer.Option(True, "--yes", help="Deprecated; live benchmark commands run directly", hidden=True),
    matrix: Path = typer.Option(DEFAULT_RELEASE_MATRIX_PATH, "--matrix", exists=True, dir_okay=False, readable=True, help="Release matrix YAML; defaults to canonical malleus-v0.1", hidden=True),
    request_timeout: float = typer.Option(120.0, "--request-timeout", min=0.000001, help="Target request timeout in seconds", hidden=True),
    max_retries: int = typer.Option(1, "--max-retries", min=0, help="Maximum target retry attempts", hidden=True),
    quiet: bool = typer.Option(False, "--quiet", help="Suppress live progress output and print only the final summary", hidden=True),
    trace_log: Path | None = typer.Option(None, "--trace-log", dir_okay=False, help="Write full live progress/scenario trace events as JSONL for post-run audit"),
    mutation_profile: Path | None = typer.Option(None, "--mutation-profile", exists=True, dir_okay=False, readable=True, help="Also run mutated variants of the lab fixture with this mutation profile"),
    mutation_limit: int | None = typer.Option(None, "--mutation-limit", min=1, help="Maximum number of fixture mutations to run for this surface"),
    config_dir: Path | None = typer.Option(None, "--config-dir", file_okay=False, help="Managed target directory", hidden=True),
) -> None:
    """Run canonical memory-agent-v1 against a real memory_agent target."""
    out_dir = out_dir or _default_report_dir(target, "live-memory-agent")
    _benchmark_live_surface_command(surface="memory-agent-v1", target=target, out_dir=out_dir, yes=yes, matrix=matrix, request_timeout=request_timeout, max_retries=max_retries, config_dir=config_dir, quiet=quiet, trace_log=trace_log, mutation_profile=mutation_profile, mutation_limit=mutation_limit)


@benchmark_app.command("live-multi-agent")
def benchmark_live_multi_agent_command(
    target: str = typer.Option(..., "--target", help="Multi-agent target YAML config or managed target name"),
    out_dir: Path | None = typer.Option(None, "--out-dir", file_okay=False, help="Output directory; defaults to reports/<target>-live-multi-agent-<timestamp>"),
    yes: bool = typer.Option(True, "--yes", help="Deprecated; live benchmark commands run directly", hidden=True),
    matrix: Path = typer.Option(DEFAULT_RELEASE_MATRIX_PATH, "--matrix", exists=True, dir_okay=False, readable=True, help="Release matrix YAML; defaults to canonical malleus-v0.1", hidden=True),
    request_timeout: float = typer.Option(120.0, "--request-timeout", min=0.000001, help="Target request timeout in seconds", hidden=True),
    max_retries: int = typer.Option(1, "--max-retries", min=0, help="Maximum target retry attempts", hidden=True),
    quiet: bool = typer.Option(False, "--quiet", help="Suppress live progress output and print only the final summary", hidden=True),
    trace_log: Path | None = typer.Option(None, "--trace-log", dir_okay=False, help="Write full live progress/scenario trace events as JSONL for post-run audit"),
    mutation_profile: Path | None = typer.Option(None, "--mutation-profile", exists=True, dir_okay=False, readable=True, help="Also run mutated variants of the lab fixture with this mutation profile"),
    mutation_limit: int | None = typer.Option(None, "--mutation-limit", min=1, help="Maximum number of fixture mutations to run for this surface"),
    config_dir: Path | None = typer.Option(None, "--config-dir", file_okay=False, help="Managed target directory", hidden=True),
) -> None:
    """Run canonical multi-agent-v1 against a real multi_agent target."""
    out_dir = out_dir or _default_report_dir(target, "live-multi-agent")
    _benchmark_live_surface_command(surface="multi-agent-v1", target=target, out_dir=out_dir, yes=yes, matrix=matrix, request_timeout=request_timeout, max_retries=max_retries, config_dir=config_dir, quiet=quiet, trace_log=trace_log, mutation_profile=mutation_profile, mutation_limit=mutation_limit)


@benchmark_app.command("live-browser-agent")
def benchmark_live_browser_agent_command(
    target: str = typer.Option(..., "--target", help="Browser-agent target YAML config or managed target name"),
    out_dir: Path | None = typer.Option(None, "--out-dir", file_okay=False, help="Output directory; defaults to reports/<target>-live-browser-agent-<timestamp>"),
    yes: bool = typer.Option(True, "--yes", help="Deprecated; live benchmark commands run directly", hidden=True),
    matrix: Path = typer.Option(DEFAULT_RELEASE_MATRIX_PATH, "--matrix", exists=True, dir_okay=False, readable=True, help="Release matrix YAML; defaults to canonical malleus-v0.1", hidden=True),
    request_timeout: float = typer.Option(120.0, "--request-timeout", min=0.000001, help="Target request timeout in seconds", hidden=True),
    max_retries: int = typer.Option(1, "--max-retries", min=0, help="Maximum target retry attempts", hidden=True),
    quiet: bool = typer.Option(False, "--quiet", help="Suppress live progress output and print only the final summary", hidden=True),
    trace_log: Path | None = typer.Option(None, "--trace-log", dir_okay=False, help="Write full live progress/scenario trace events as JSONL for post-run audit"),
    mutation_profile: Path | None = typer.Option(None, "--mutation-profile", exists=True, dir_okay=False, readable=True, help="Also run mutated variants of the lab fixture with this mutation profile"),
    mutation_limit: int | None = typer.Option(None, "--mutation-limit", min=1, help="Maximum number of fixture mutations to run for this surface"),
    config_dir: Path | None = typer.Option(None, "--config-dir", file_okay=False, help="Managed target directory", hidden=True),
) -> None:
    """Run canonical ui-browser-v1 against a real browser_agent target."""
    out_dir = out_dir or _default_report_dir(target, "live-browser-agent")
    _benchmark_live_surface_command(surface="ui-browser-v1", target=target, out_dir=out_dir, yes=yes, matrix=matrix, request_timeout=request_timeout, max_retries=max_retries, config_dir=config_dir, quiet=quiet, trace_log=trace_log, mutation_profile=mutation_profile, mutation_limit=mutation_limit)


@benchmark_app.command("live-self-modification", hidden=True)
def benchmark_live_self_modification_command(
    target: str = typer.Option(..., "--target", help="Target YAML config or managed target name"),
    out_dir: Path = typer.Option(..., "--out-dir", file_okay=False, help="Output directory for live self-modification evidence or target_capability_gap coverage"),
    yes: bool = typer.Option(True, "--yes", help="Deprecated; live benchmark commands run directly", hidden=True),
    matrix: Path = typer.Option(DEFAULT_RELEASE_MATRIX_PATH, "--matrix", exists=True, dir_okay=False, readable=True, help="Release matrix YAML; defaults to canonical malleus-v0.1", hidden=True),
    request_timeout: float = typer.Option(120.0, "--request-timeout", min=0.000001, help="Target request timeout in seconds", hidden=True),
    max_retries: int = typer.Option(1, "--max-retries", min=0, help="Maximum target retry attempts", hidden=True),
    quiet: bool = typer.Option(False, "--quiet", help="Suppress live progress output and print only the final summary", hidden=True),
    trace_log: Path | None = typer.Option(None, "--trace-log", dir_okay=False, help="Write full live progress/scenario trace events as JSONL for post-run audit"),
    config_dir: Path | None = typer.Option(None, "--config-dir", file_okay=False, help="Managed target directory", hidden=True),
) -> None:
    """Route self-modification through compatible live harnesses or record target_capability_gap."""
    _benchmark_live_surface_command(surface="self-modification-v1", target=target, out_dir=out_dir, yes=yes, matrix=matrix, request_timeout=request_timeout, max_retries=max_retries, config_dir=config_dir, quiet=quiet, trace_log=trace_log)


@benchmark_app.command("soft")
def benchmark_soft_command(
    target: str = typer.Option(..., "--target", help="Target model YAML config or managed target name for intentional live provider calls"),
    out_dir: Path | None = typer.Option(None, "--out-dir", file_okay=False, help="Output directory; defaults to reports/<target>-soft-<timestamp>"),
    yes: bool = typer.Option(True, "--yes", help="Deprecated; live benchmark commands run directly", hidden=True),
    matrix: Path = typer.Option(DEFAULT_RELEASE_MATRIX_PATH, "--matrix", exists=True, dir_okay=False, readable=True, help="Release matrix YAML; defaults to canonical malleus-v0.1", hidden=True),
    mutation_profile: Path = typer.Option(DEFAULT_SELECTED_MUTATION_PROFILE_PATH, "--mutation-profile", exists=True, dir_okay=False, readable=True, help="Selected mutation profile YAML; deep mutations are not run by default", hidden=True),
    concurrency: int = typer.Option(1, "--concurrency", min=1, help="Record requested concurrency in run metadata; soft execution is currently sequential", hidden=True),
    request_timeout: float = typer.Option(120.0, "--request-timeout", min=0.000001, help="Provider request timeout in seconds", hidden=True),
    max_retries: int = typer.Option(1, "--max-retries", min=0, help="Maximum provider retry attempts", hidden=True),
    quiet: bool = typer.Option(False, "--quiet", help="Suppress live progress output and print only the final summary", hidden=True),
    trace_log: Path | None = typer.Option(None, "--trace-log", dir_okay=False, help="Write full live progress/scenario trace events as JSONL for post-run audit"),
    config_dir: Path | None = typer.Option(None, "--config-dir", file_okay=False, help="Managed target directory", hidden=True),
) -> None:
    """Run the serious/default live soft benchmark with explicit confirmation."""

    out_dir = out_dir or _default_report_dir(target, "soft")
    target_path = _resolve_cli_target(target, config_dir)
    try:
        evidence, json_path, markdown_path = run_soft_benchmark(
            target_path=target_path,
            out_dir=out_dir,
            yes=yes,
            matrix_path=matrix,
            mutation_profile_path=mutation_profile,
            concurrency=concurrency,
            request_timeout=request_timeout,
            max_retries=max_retries,
            progress_callback=_live_benchmark_progress_printer(quiet=quiet, trace_log=trace_log),
        )
    except (ValueError, ValidationError) as exc:
        typer.echo(_format_cli_error(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("Soft benchmark live evidence written")
    typer.echo("Mode: soft")
    typer.echo("Dry run: false")
    typer.echo("Provider calls enabled: true")
    typer.echo("Deep mutations included: false")
    typer.echo(f"Rows: {len(evidence.rows)}")
    typer.echo(f"JSON: {json_path}")
    typer.echo(f"Markdown: {markdown_path}")
    typer.echo(f"Mode marker: {out_dir / 'SOFT_BENCHMARK_MODE.json'}")
    _print_report_next_steps(out_dir, json_path=json_path, markdown_path=markdown_path, html_path=out_dir / "live-full-summary.html")
    if trace_log is not None:
        typer.echo(f"Trace log: {trace_log}")


@benchmark_app.command("exterminatus")
def benchmark_exterminatus_command(
    target: str = typer.Option(..., "--target", help="Target model YAML config or managed target name for expanded live provider calls"),
    out_dir: Path | None = typer.Option(None, "--out-dir", file_okay=False, help="Output directory; defaults to reports/<target>-exterminatus-<timestamp>"),
    yes: bool = typer.Option(True, "--yes", help="Deprecated; live benchmark commands run directly", hidden=True),
    matrix: Path = typer.Option(DEFAULT_RELEASE_MATRIX_PATH, "--matrix", exists=True, dir_okay=False, readable=True, help="Release matrix YAML; defaults to canonical malleus-v0.1", hidden=True),
    mutation_profile: Path = typer.Option(DEFAULT_SELECTED_MUTATION_PROFILE_PATH, "--mutation-profile", exists=True, dir_okay=False, readable=True, help="Selected mutation profile YAML; defaults to selected-v1", hidden=True),
    deep_mutation_profile: Path = typer.Option(DEFAULT_DEEP_MUTATION_PROFILE_PATH, "--deep-mutation-profile", exists=True, dir_okay=False, readable=True, help="Deep mutation profile YAML; defaults to deep-v1 and is included", hidden=True),
    concurrency: int = typer.Option(1, "--concurrency", min=1, help="Record requested concurrency in run metadata; exterminatus execution is currently sequential", hidden=True),
    request_timeout: float = typer.Option(120.0, "--request-timeout", min=0.000001, help="Provider request timeout in seconds", hidden=True),
    max_retries: int = typer.Option(1, "--max-retries", min=0, help="Maximum provider retry attempts", hidden=True),
    quiet: bool = typer.Option(False, "--quiet", help="Suppress live progress output and print only the final summary", hidden=True),
    trace_log: Path | None = typer.Option(None, "--trace-log", dir_okay=False, help="Write full live progress/scenario trace events as JSONL for post-run audit"),
    config_dir: Path | None = typer.Option(None, "--config-dir", file_okay=False, help="Managed target directory", hidden=True),
) -> None:
    """Run exhaustive/full live benchmark mode with explicit confirmation."""

    out_dir = out_dir or _default_report_dir(target, "exterminatus")
    bundle_path = _maybe_resolve_bundle(target)
    if bundle_path is not None:
        try:
            _run_bundle_exterminatus_command(
                bundle_path=bundle_path,
                out_dir=out_dir,
                yes=yes,
                matrix=matrix,
                mutation_profile=mutation_profile,
                deep_mutation_profile=deep_mutation_profile,
                concurrency=concurrency,
                request_timeout=request_timeout,
                max_retries=max_retries,
                quiet=quiet,
                trace_log=trace_log,
                config_dir=config_dir,
            )
        except (ValueError, ValidationError, TargetStoreError) as exc:
            typer.echo(_format_cli_error(exc) if isinstance(exc, (ValueError, ValidationError)) else str(exc), err=True)
            raise typer.Exit(code=1) from exc
        return

    target_path = _resolve_cli_target(target, config_dir)
    try:
        evidence, json_path, markdown_path = run_exterminatus_benchmark(
            target_path=target_path,
            out_dir=out_dir,
            yes=yes,
            matrix_path=matrix,
            mutation_profile_path=mutation_profile,
            deep_mutation_profile_path=deep_mutation_profile,
            concurrency=concurrency,
            request_timeout=request_timeout,
            max_retries=max_retries,
            progress_callback=_live_benchmark_progress_printer(quiet=quiet, trace_log=trace_log),
        )
    except (ValueError, ValidationError) as exc:
        typer.echo(_format_cli_error(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("Exhaustive benchmark live evidence written")
    typer.echo("Mode: exterminatus")
    typer.echo("Exhaustive: true")
    typer.echo("Dry run: false")
    typer.echo("Provider calls enabled: true")
    typer.echo("Deep mutations included: true")
    typer.echo("Unsupported/deferred surfaces explicit: true")
    typer.echo(f"Rows: {len(evidence.rows)}")
    typer.echo(f"JSON: {json_path}")
    typer.echo(f"Markdown: {markdown_path}")
    typer.echo(f"Mode marker: {out_dir / 'EXTERMINATUS_BENCHMARK_MODE.json'}")
    _print_report_next_steps(out_dir, json_path=json_path, markdown_path=markdown_path, html_path=out_dir / "live-full-summary.html")
    if trace_log is not None:
        typer.echo(f"Trace log: {trace_log}")


@audit_app.command("false-positives")
def audit_false_positives(
    report_dir: Path = typer.Argument(..., exists=True, help="Report directory or JSON report to audit"),
    out: Path | None = typer.Option(None, "--out", dir_okay=False, help="Optional Markdown output path"),
) -> None:
    """List likely false positives, weak evidence, and harness-only failures."""
    rows = _collect_false_positive_candidates(report_dir)
    lines = [
        "# Malleus False-positive Audit",
        "",
        f"- Source: `{report_dir}`",
        f"- Candidates: {len(rows)}",
        "",
        "| Case | Status | Reason codes | Signal | Report |",
        "| --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        lines.append(f"| {_md(row['case'])} | {_md(row['status'])} | {_md(', '.join(row['reason_codes']) or 'none')} | {_md(row['signal'])} | {_md(row['report'])} |")
    if not rows:
        lines.append("| none | - | - | No suspected false positives or weak-evidence rows found. | - |")
    text = "\n".join(lines).rstrip() + "\n"
    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        typer.echo(f"False-positive audit written: {out}")
    else:
        typer.echo(text)


def _collect_false_positive_candidates(report_dir: Path) -> list[dict[str, object]]:
    paths = [report_dir] if report_dir.is_file() else sorted(report_dir.rglob("*.json"))
    candidates: list[dict[str, object]] = []
    for path in paths:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        candidates.extend(_false_positive_rows_from_json(data, report_path=path))
    return candidates


def _false_positive_rows_from_json(data: object, *, report_path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    if not isinstance(data, dict):
        return rows
    for result in data.get("results", []) if isinstance(data.get("results"), list) else []:
        if not isinstance(result, dict):
            continue
        metadata = result.get("metadata") if isinstance(result.get("metadata"), dict) else {}
        harness_result = result.get("harness_result") if isinstance(result.get("harness_result"), dict) else {}
        harness_metadata = harness_result.get("metadata") if isinstance(harness_result.get("metadata"), dict) else {}
        reason_codes = [str(item) for item in result.get("reason_codes", []) if isinstance(item, str)] if isinstance(result.get("reason_codes"), list) else []
        signal = _false_positive_signal(result, metadata={**metadata, **harness_metadata}, reason_codes=reason_codes)
        if signal:
            rows.append(
                {
                    "case": str(result.get("scenario_id") or result.get("prompt_id") or result.get("workflow_id") or result.get("query_id") or result.get("id") or "unknown"),
                    "status": str(result.get("status") or "unknown"),
                    "reason_codes": reason_codes,
                    "signal": signal,
                    "report": str(report_path),
                }
            )
    for row in data.get("rows", []) if isinstance(data.get("rows"), list) else []:
        if not isinstance(row, dict):
            continue
        metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
        reason_codes = [str(item) for item in metadata.get("reason_codes", []) if isinstance(item, str)] if isinstance(metadata.get("reason_codes"), list) else []
        signal = _false_positive_signal(row, metadata=metadata, reason_codes=reason_codes)
        if signal:
            rows.append({"case": str(row.get("case_id") or row.get("row_id") or "unknown"), "status": str(row.get("status") or "unknown"), "reason_codes": reason_codes, "signal": signal, "report": str(report_path)})
    return rows


def _false_positive_signal(result: dict[str, object], *, metadata: dict[str, object], reason_codes: list[str]) -> str | None:
    status = str(result.get("status") or "")
    if metadata.get("suspected_false_positive") is True:
        return "marked suspected_false_positive"
    if metadata.get("low_fidelity") is True or metadata.get("evidence_fidelity") == "auto_wrapper_trace":
        return "low-fidelity auto-wrapper verdict"
    if metadata.get("evidence_strength") == "weak":
        return "weak code-agent evidence"
    if status in {"target_error", "infra_error"}:
        return "harness/provider error, not model behavior"
    if "output_contract_violation" in reason_codes:
        return "structured output contract failure; inspect before treating as attack success"
    if "browser_page_mismatch" in reason_codes:
        return "browser fixture mismatch; no model verdict"
    if "missing_backing_model_call_proof" in reason_codes:
        return "missing live model proof"
    return None


def _md(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").strip()


@app.command()
def info() -> None:
    typer.echo(render_splash(version=_package_version(), color=True))


@app.command("version")
def version_command() -> None:
    typer.echo(f"malleus-evals {_package_version()}")


register_onboarding_commands(app, target_init=target_init_command, provider_choices_label=_provider_choices_label)


@app.command("v1-readiness", hidden=True)
def v1_readiness_command(
    out_dir: Path | None = typer.Option(None, "--out-dir", file_okay=False, help="Write v1-readiness.json"),
    json_output: bool = typer.Option(False, "--json", help="Print machine-readable JSON"),
) -> None:
    """Report what remains before Malleus can honestly claim v1 stable."""

    report = build_v1_readiness_report()
    if out_dir is not None:
        path = write_v1_readiness_report(report, out_dir)
        report["output_path"] = str(path)
    if json_output:
        typer.echo(json.dumps(report, indent=2, sort_keys=True))
    else:
        typer.echo(render_v1_readiness(report))


@app.command("prod-readiness", hidden=True)
def prod_readiness_command(
    out_dir: Path | None = typer.Option(None, "--out-dir", file_okay=False, help="Write prod-readiness.json"),
    json_output: bool = typer.Option(False, "--json", help="Print machine-readable JSON"),
) -> None:
    """Audit the ten production-readiness axes for a public release."""

    report = build_prod_readiness_report()
    if out_dir is not None:
        path = write_prod_readiness_report(report, out_dir)
        report["output_path"] = str(path)
    if json_output:
        typer.echo(json.dumps(report, indent=2, sort_keys=True))
    else:
        typer.echo(render_prod_readiness(report))


@app.command("assess", hidden=True)
def assess_command(
    target_path: Path = typer.Option(..., "--target", exists=True, dir_okay=False, readable=True, help="Target model YAML config"),
    profile: str = typer.Option(..., "--profile", help="Assessment profile id"),
    packs_expression: str = typer.Option("default", "--packs", help="Comma-separated assessment pack ids, or default/all"),
    mode: str = typer.Option("dry_run", "--mode", help="Assessment mode"),
    out_dir: Path = typer.Option(..., "--out-dir", file_okay=False, help="Assessment output directory"),
    compare_targets: list[Path] | None = typer.Option(None, "--compare-target", exists=True, dir_okay=False, readable=True, help="Comparison target YAML config; repeatable"),
    regression_pack: Path | None = typer.Option(None, "--regression-pack", exists=True, dir_okay=False, readable=True, help="Optional regression pack YAML"),
    policy_path: Path | None = typer.Option(None, "--policy", exists=True, dir_okay=False, readable=True, help="Optional policy YAML"),
    baseline_path: Path | None = typer.Option(None, "--baseline", exists=True, dir_okay=False, readable=True, help="Optional baseline JSON/report"),
    include_experimental: bool = typer.Option(False, "--include-experimental", help="Include experimental assessment packs"),
    limit: int | None = typer.Option(None, "--limit", min=1, help="Limit selected assessment cases"),
    case_ids: list[str] | None = typer.Option(None, "--case-id", help="Assessment case id filter; repeatable"),
    allow_live_provider: bool = typer.Option(False, "--allow-live-provider", help="Permit live_provider mode when the environment gate is also set"),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON instead of human text"),
) -> None:
    catalog = load_assessment_catalog()
    packs = _parse_assessment_packs(packs_expression)

    if profile not in catalog.profiles:
        typer.echo(f"unknown profile: {profile}", err=True)
        raise typer.Exit(code=1)

    known_modes = {assessment_mode.value for assessment_mode in AssessmentMode}
    if mode not in known_modes:
        typer.echo(f"unknown mode: {mode}", err=True)
        raise typer.Exit(code=1)

    pack_ids = {pack.id for pack in catalog.packs}
    for pack in packs:
        if pack not in {"default", "all"} and pack not in pack_ids:
            typer.echo(f"unknown pack: {pack}", err=True)
            raise typer.Exit(code=1)

    provider_calls_enabled = False

    try:
        result = run_assessment(
            target_path=target_path,
            profile=profile,
            packs=packs,
            mode=mode,
            out_dir=out_dir,
            compare_targets=list(compare_targets or []),
            regression_pack=regression_pack,
            policy_path=policy_path,
            baseline_path=baseline_path,
            include_experimental=include_experimental,
            limit=limit,
            case_ids=list(case_ids or []),
            allow_live_provider=allow_live_provider,
            provider_calls_enabled=provider_calls_enabled,
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    if json_output:
        typer.echo(json.dumps(result, indent=2, sort_keys=True))
        if mode == AssessmentMode.LIVE_PROVIDER.value:
            typer.echo("live_provider assessment is fail-closed: provider and network calls are disabled.", err=True)
            raise typer.Exit(code=1)
        return

    if mode == AssessmentMode.LIVE_PROVIDER.value:
        typer.echo("Assessment fail-closed")
        typer.echo(f"Mode: {result.get('mode', mode)}")
        typer.echo("Provider calls enabled: false")
        typer.echo("Network enabled: false")
        typer.echo(f"Manifest: {result.get('manifest_path')}")
        typer.echo("live_provider assessment is fail-closed: provider and network calls are disabled.", err=True)
        raise typer.Exit(code=1)

    typer.echo("Assessment complete")
    typer.echo(f"Mode: {result.get('mode', mode)}")
    typer.echo(f"Provider calls enabled: {str(provider_calls_enabled).lower()}")
    typer.echo(f"Manifest: {result.get('manifest_path')}")


@app.command("inspect-refusal", hidden=True)
def inspect_refusal_command(
    text: str = typer.Argument(..., help="Response text to classify"),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON instead of human text"),
) -> None:
    result = classify_refusal(text)
    if json_output:
        typer.echo(result.model_dump_json(indent=2))
        return
    typer.echo(f"Label: {result.label}")
    typer.echo(f"Refused: {result.refused}")
    typer.echo(f"Confidence: {result.confidence:.2f}")
    typer.echo(f"Rationale: {result.rationale}")
    typer.echo("Evidence:")
    for span in result.evidence_spans:
        typer.echo(f"- {span.kind} [{span.start}:{span.end}] {span.pattern}: {span.text}")


@app.command("inspect-output", hidden=True)
def inspect_output_command(
    text: str | None = typer.Argument(None, help="Output text to inspect. Omit when using --file."),
    file_path: Path | None = typer.Option(None, "--file", exists=True, dir_okay=False, readable=True, help="Output file to inspect"),
    out_dir: Path | None = typer.Option(None, "--out-dir", file_okay=False, help="Write anomaly-report.json/md"),
    json_output: bool = typer.Option(False, "--json", help="Emit sanitized JSON instead of human text"),
) -> None:
    if file_path is None and text is None:
        typer.echo("Provide text or --file.", err=True)
        raise typer.Exit(code=1)
    if file_path is not None and text is not None:
        typer.echo("Use either text or --file, not both.", err=True)
        raise typer.Exit(code=1)

    report = report_from_file(file_path) if file_path is not None else inspect_output(text or "", source="inline")
    if out_dir is not None:
        json_path, markdown_path = write_anomaly_report(report, out_dir)
        typer.echo("Anomaly inspection complete")
        typer.echo(f"Findings: {report.summary.total_findings}")
        typer.echo(f"Highest severity: {report.summary.highest_severity}")
        typer.echo(f"Gate recommendation: {report.gate_recommendation}")
        typer.echo(f"JSON: {json_path}")
        typer.echo(f"Markdown: {markdown_path}")
        return
    if json_output:
        typer.echo(report.model_dump_json(indent=2))
        return
    typer.echo(f"Findings: {report.summary.total_findings}")
    typer.echo(f"Highest severity: {report.summary.highest_severity}")
    typer.echo(f"Gate recommendation: {report.gate_recommendation}")
    typer.echo(f"Rationale: {report.summary.rationale}")
    for finding in report.findings:
        typer.echo(f"- {finding.code} line={finding.line} severity={finding.severity}: {finding.rationale}")


@app.command("inspect-text", hidden=True)
def inspect_text_command(
    text: str | None = typer.Argument(None, help="Text to inspect. Omit when using --file."),
    file_path: Path | None = typer.Option(None, "--file", exists=True, dir_okay=False, readable=True, help="Text/Markdown file to inspect"),
    out_dir: Path | None = typer.Option(None, "--out-dir", file_okay=False, help="Write hidden-channel-report.json/md"),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON instead of human text"),
) -> None:
    if file_path is None and text is None:
        typer.echo("Provide text or --file.", err=True)
        raise typer.Exit(code=1)
    if file_path is not None and text is not None:
        typer.echo("Use either text or --file, not both.", err=True)
        raise typer.Exit(code=1)

    if file_path is not None:
        inspected_text = file_path.read_text(encoding="utf-8")
        source = str(file_path)
    else:
        inspected_text = text or ""
        source = "inline"

    report = inspect_text(inspected_text, source=source)
    if out_dir is not None:
        json_path, markdown_path = write_hidden_channel_report(report, out_dir)
        typer.echo("Hidden-channel inspection complete")
        typer.echo(f"Findings: {report.summary.total_findings}")
        typer.echo(f"Highest severity: {report.summary.highest_severity}")
        typer.echo(f"Gate recommendation: {report.gate_recommendation or 'n/a'}")
        typer.echo(f"JSON: {json_path}")
        typer.echo(f"Markdown: {markdown_path}")
        return
    if json_output:
        typer.echo(report.model_dump_json(indent=2))
        return
    typer.echo(f"Findings: {report.summary.total_findings}")
    typer.echo(f"Highest severity: {report.summary.highest_severity}")
    typer.echo(f"Gate recommendation: {report.gate_recommendation or 'n/a'}")
    for finding in report.findings:
        typer.echo(f"- {finding.kind} [{finding.start}:{finding.end}] {finding.severity}: {finding.description}")


def _artifact_firewall_command(file_path: Path, out_dir: Path | None, json_output: bool) -> None:
    report = inspect_artifact(file_path)
    if out_dir is not None:
        json_path, markdown_path = write_artifact_firewall_report(report, out_dir)
        typer.echo("Artifact firewall inspection complete")
        typer.echo(f"Format: {report.manifest.format}")
        typer.echo(f"Findings: {len(report.findings)}")
        typer.echo(f"Recommendation: {report.recommendation}")
        typer.echo(f"JSON: {json_path}")
        typer.echo(f"Markdown: {markdown_path}")
        return
    if json_output:
        typer.echo(report.model_dump_json(indent=2))
        return
    typer.echo(f"Format: {report.manifest.format}")
    typer.echo(f"Findings: {len(report.findings)}")
    typer.echo(f"Recommendation: {report.recommendation}")
    for finding in report.findings:
        typer.echo(f"- {finding.kind}: {finding.severity}: {finding.description}")


@app.command("inspect-artifact", hidden=True)
def inspect_artifact_command(
    file_path: Path = typer.Option(..., "--file", exists=True, dir_okay=False, readable=True, help="Artifact file to inspect safely"),
    out_dir: Path | None = typer.Option(None, "--out-dir", file_okay=False, help="Write artifact-firewall-report.json/md"),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON instead of human text"),
) -> None:
    _artifact_firewall_command(file_path, out_dir, json_output)


@app.command("artifact-firewall", hidden=True)
def artifact_firewall_command(
    file_path: Path = typer.Option(..., "--file", exists=True, dir_okay=False, readable=True, help="Artifact file to inspect safely"),
    out_dir: Path | None = typer.Option(None, "--out-dir", file_okay=False, help="Write artifact-firewall-report.json/md"),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON instead of human text"),
) -> None:
    _artifact_firewall_command(file_path, out_dir, json_output)


@app.command("plugin-scan", hidden=True)
def plugin_scan_command(
    input_path: Path = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True, help="Local plugin manifest, OpenAPI file, or tool registry YAML/JSON"),
    out_dir: Path = typer.Option(..., "--out-dir", file_okay=False, help="Output directory for plugin-risk-report.json/md"),
) -> None:
    report = scan_plugin_manifest(input_path, out_dir)
    typer.echo("Plugin risk scan complete")
    typer.echo("Mode: local_fixture")
    typer.echo("Provider calls enabled: false")
    typer.echo(f"Findings: {report.summary.total_findings}")
    typer.echo(f"Highest severity: {report.summary.highest_severity or 'none'}")
    typer.echo(f"Gate recommendation: {report.summary.gate_recommendation}")
    typer.echo(f"JSON: {out_dir / 'plugin-risk-report.json'}")
    typer.echo(f"Markdown: {out_dir / 'plugin-risk-report.md'}")


@code_agent_app.command("inspect")
def code_agent_inspect_command(
    trace: Path = typer.Option(..., "--trace", exists=True, dir_okay=False, readable=True, help="Local code-agent VCS/lifecycle trace YAML/JSON"),
    out_dir: Path = typer.Option(..., "--out-dir", file_okay=False, help="Output directory for code-agent reports"),
) -> None:
    try:
        inspection = inspect_code_agent_trace(trace, out_dir)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("Code-agent inspection complete")
    typer.echo("Mode: local_fixture")
    typer.echo("Provider calls enabled: false")
    typer.echo(f"VCS findings: {inspection.vcs_report.summary.total_findings}")
    typer.echo(f"Lifecycle findings: {inspection.lifecycle_report.summary.total_findings}")
    typer.echo(f"Lifecycle gates satisfied: {str(inspection.lifecycle_report.gates.all_required_satisfied).lower()}")
    typer.echo(f"VCS gate recommendation: {inspection.vcs_report.summary.gate_recommendation}")
    typer.echo(f"Lifecycle gate recommendation: {inspection.lifecycle_report.summary.gate_recommendation}")
    typer.echo(f"VCS JSON: {out_dir / 'vcs-workflow-report.json'}")
    typer.echo(f"VCS Markdown: {out_dir / 'vcs-workflow-report.md'}")
    typer.echo(f"Lifecycle JSON: {out_dir / 'code-agent-lifecycle-report.json'}")
    typer.echo(f"Lifecycle Markdown: {out_dir / 'code-agent-lifecycle-report.md'}")


@self_mod_app.command("inspect")
def self_mod_inspect_command(
    diff: list[Path] | None = typer.Option(None, "--diff", exists=True, dir_okay=False, readable=True, help="Local proposed unified diff fixture; repeatable"),
    trace: list[Path] | None = typer.Option(None, "--trace", exists=True, dir_okay=False, readable=True, help="Local proposed self-modification trace YAML/JSON; repeatable"),
    out_dir: Path = typer.Option(..., "--out-dir", file_okay=False, help="Output directory for self-modification-report.json/md"),
) -> None:
    try:
        report = inspect_self_modification(list(diff or []), list(trace or []), out_dir)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("Self-modification inspection complete")
    typer.echo("Mode: local_fixture")
    typer.echo("Provider calls enabled: false")
    typer.echo(f"Inputs: {len(report.inputs)}")
    typer.echo(f"Findings: {report.summary.total_findings}")
    typer.echo(f"Highest severity: {report.summary.highest_severity or 'none'}")
    typer.echo(f"Gate recommendation: {report.summary.gate_recommendation}")
    typer.echo(f"JSON: {out_dir / 'self-modification-report.json'}")
    typer.echo(f"Markdown: {out_dir / 'self-modification-report.md'}")


@app.command("list-cases", hidden=True)
def list_cases_command(
    input_path: Path = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True, help="Dataset or benchmark pack YAML"),
) -> None:
    for item in enumerate_items(input_path):
        typer.echo(item)


@app.command("import", hidden=True)
def import_command(
    source: str = typer.Argument(..., help=f"External source: {', '.join(supported_import_sources())}"),
    path: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True, help="External result JSON to normalize"),
    out_dir: Path = typer.Option(..., "--out-dir", file_okay=False, help="Output directory for findings.json and interop-report.json"),
) -> None:
    try:
        report = import_external_results(source, path, out_dir)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Interop import complete: {report.source}")
    typer.echo(f"Findings: {report.normalized_finding_count}")
    typer.echo(f"Warnings: {len(report.warnings) + len(report.unsupported_field_warnings)}")
    for kind, artifact_path in sorted(report.output_artifacts.items()):
        typer.echo(f"{kind}: {artifact_path}")


@app.command("export", hidden=True)
def export_command(
    format_name: str = typer.Argument(..., metavar="FORMAT", help=f"Export format: {', '.join(supported_export_formats())}"),
    findings: Path = typer.Option(..., "--findings", exists=True, readable=True, help="findings.json or report directory"),
    out: Path = typer.Option(..., "--out", dir_okay=False, help="Output artifact path"),
) -> None:
    try:
        report = export_findings(format_name, findings, out)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Interop export complete: {report.format}")
    typer.echo(f"Findings: {report.exported_finding_count}")
    typer.echo(f"Warnings: {len(report.warnings) + len(report.unsupported_field_warnings)}")
    typer.echo(f"Artifact: {report.output_artifact}")


@findings_app.command("list")
def findings_list_command(
    report: Path = typer.Option(..., "--report", exists=True, readable=True, help="Report directory, report.json, agent-lab-report.json, or findings.json"),
) -> None:
    bundle = load_or_collect_findings(report)
    for finding in bundle.findings:
        typer.echo(f"{finding.finding_id}\t{finding.severity}\t{finding.source_type}\t{finding.title}")
    if not bundle.findings:
        typer.echo("No findings.")


@findings_app.command("show")
def findings_show_command(
    finding_id: str = typer.Argument(...),
    report: Path = typer.Option(..., "--report", exists=True, readable=True, help="Report directory, report.json, agent-lab-report.json, or findings.json"),
) -> None:
    bundle = load_or_collect_findings(report)
    finding = find_finding(bundle, finding_id)
    if finding is None:
        typer.echo(f"Finding not found: {finding_id}", err=True)
        raise typer.Exit(code=1)
    typer.echo(finding.model_dump_json(indent=2))


@findings_app.command("export")
def findings_export_command(
    report: Path = typer.Option(..., "--report", exists=True, readable=True, help="Report directory, report.json, agent-lab-report.json, or findings.json"),
    out_dir: Path = typer.Option(..., "--out-dir", file_okay=False, help="Output directory for findings.json/md"),
) -> None:
    bundle = load_or_collect_findings(report)
    json_path, markdown_path = write_finding_artifacts(bundle, out_dir)
    typer.echo(f"Findings exported: {bundle.summary.total_findings}")
    typer.echo(f"JSON: {json_path}")
    typer.echo(f"Markdown: {markdown_path}")


@issues_app.command("export")
def issues_export_command(
    findings: Path = typer.Option(..., "--findings", "--report", exists=True, readable=True, help="Findings JSON or report directory to convert into local issue artifacts"),
    out_dir: Path = typer.Option(..., "--out-dir", file_okay=False, help="Output directory for issues/, issue-export.json, and remediation-board.md"),
    github_scaffold: bool = typer.Option(False, "--github-scaffold", help="Write explicit GitHub creation scaffold metadata only; does not invoke gh"),
    create_github: bool = typer.Option(False, "--create-github", help="Fail closed. GitHub issue creation is not performed by this local export command"),
) -> None:
    try:
        artifact, paths = export_issues_from_findings(findings, out_dir, github_scaffold=github_scaffold, create_github=create_github)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("Issue export written")
    typer.echo("GitHub creation enabled: false")
    typer.echo(f"GitHub creation status: {artifact.github_creation_status}")
    typer.echo(f"Issues: {artifact.summary.total_issues}")
    typer.echo(f"JSON: {paths['json']}")
    typer.echo(f"Board: {paths['board']}")
    typer.echo(f"Issues dir: {paths['issues_dir']}")


@patch_app.command("suggest")
def patch_suggest_command(
    finding_id: str = typer.Option(..., "--finding", help="Finding ID to use as sanitized context"),
    report: Path = typer.Option(..., "--report", exists=True, readable=True, help="Report directory, report JSON, or findings.json"),
    out: Path = typer.Option(..., "--out", file_okay=False, help="Output directory for defensive suggestions"),
) -> None:
    try:
        manifest = suggest_patch_for_finding(finding_id, report, out)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Patch suggestions written: {manifest.finding_id}")
    typer.echo("Suggestions are defensive starting points and are not guaranteed remediation.")
    for name in sorted(manifest.artifacts):
        typer.echo(f"- {name}: {manifest.artifacts[name]}")


def _adjudicate_command(
    finding_id: str,
    report: Path,
    status: AdjudicationStatus,
    reviewer: str,
    reason_code: str,
    note: str,
    expires_at: str | None = None,
) -> None:
    try:
        bundle, json_path, markdown_path = adjudicate_finding(
            finding_id,
            report,
            status=status,
            reviewer=reviewer,
            reason_code=reason_code,
            note=note,
            expires_at=expires_at,
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Adjudication recorded: {finding_id} -> {status}")
    typer.echo(f"Records: {bundle.summary.total_records}")
    typer.echo(f"Open findings: {bundle.summary.open_findings}")
    typer.echo(f"JSON: {json_path}")
    typer.echo(f"Markdown: {markdown_path}")


@app.command("adjudicate", hidden=True)
def adjudicate_command(
    finding_id: str = typer.Option(..., "--finding", help="Finding ID to adjudicate"),
    report: Path = typer.Option(..., "--report", exists=True, readable=True, help="Report directory, report JSON, or findings.json"),
    status: AdjudicationStatus = typer.Option(..., "--status", help="confirmed, false_positive, accepted_risk, needs_review, or fixed"),
    reviewer: str = typer.Option(..., "--reviewer", help="Human reviewer identity"),
    reason_code: str = typer.Option(..., "--reason-code", help="Stable reason code for audit queries"),
    note: str = typer.Option("", "--note", help="Optional reviewer note"),
    expires_at: str | None = typer.Option(None, "--expires-at", help="Optional ISO timestamp for accepted-risk waiver expiration"),
) -> None:
    _adjudicate_command(finding_id, report, status, reviewer, reason_code, note, expires_at)


@app.command("review", hidden=True)
def review_command(
    finding_id: str = typer.Option(..., "--finding", help="Finding ID to adjudicate"),
    report: Path = typer.Option(..., "--report", exists=True, readable=True, help="Report directory, report JSON, or findings.json"),
    status: AdjudicationStatus = typer.Option(..., "--status", help="confirmed, false_positive, accepted_risk, needs_review, or fixed"),
    reviewer: str = typer.Option(..., "--reviewer", help="Human reviewer identity"),
    reason_code: str = typer.Option(..., "--reason-code", help="Stable reason code for audit queries"),
    note: str = typer.Option("", "--note", help="Optional reviewer note"),
    expires_at: str | None = typer.Option(None, "--expires-at", help="Optional ISO timestamp for accepted-risk waiver expiration"),
) -> None:
    _adjudicate_command(finding_id, report, status, reviewer, reason_code, note, expires_at)


@app.command("diff-runs")
def diff_runs_command(
    old_report: Path = typer.Option(..., "--old", exists=True, dir_okay=False, readable=True, help="Baseline report.json"),
    new_report: Path = typer.Option(..., "--new", exists=True, dir_okay=False, readable=True, help="Candidate report.json"),
    out_dir: Path = typer.Option(..., "--out-dir", file_okay=False, help="Output directory for diff-runs-report.json/md"),
) -> None:
    report = diff_run_reports(old_report, new_report)
    json_path, markdown_path = write_diff_report(report, out_dir)
    typer.echo(f"Run diff complete: {report.old_run_id} -> {report.new_run_id}")
    typer.echo(f"Score delta: {report.summary.score_delta}")
    typer.echo(f"Newly failing: {report.summary.newly_failing}")
    typer.echo(f"Newly passing: {report.summary.newly_passing}")
    typer.echo(f"Added items: {report.summary.added_items}")
    typer.echo(f"Removed items: {report.summary.removed_items}")
    typer.echo(f"JSON: {json_path}")
    typer.echo(f"Markdown: {markdown_path}")


@app.command("diff-traces")
def diff_traces_command(
    old_trace: Path = typer.Option(..., "--old", exists=True, dir_okay=False, readable=True, help="Baseline trace, agent-lab-report.json, or trace bundle"),
    new_trace: Path = typer.Option(..., "--new", exists=True, dir_okay=False, readable=True, help="Candidate trace, agent-lab-report.json, or trace bundle"),
    out_dir: Path = typer.Option(..., "--out-dir", file_okay=False, help="Output directory for trace-diff-report.json/md"),
) -> None:
    report = diff_traces(old_trace, new_trace)
    json_path, markdown_path = write_trace_diff_report(report, out_dir)
    typer.echo(f"Trace diff complete: {report.old_trace_id} -> {report.new_trace_id}")
    typer.echo(f"Deltas: {report.summary.total_deltas}")
    typer.echo(f"High/Critical regressions: {report.summary.regressions}")
    typer.echo(f"Critical: {report.summary.critical}")
    typer.echo(f"High: {report.summary.high}")
    typer.echo(f"JSON: {json_path}")
    typer.echo(f"Markdown: {markdown_path}")


@app.command("mutate", hidden=True)
def mutate_command(
    prompt: str = typer.Argument(...),
    mutation: str = typer.Option(..., "--mutation", help=f"One of: {', '.join(mutation_names())}"),
) -> None:
    typer.echo(mutate_prompt(prompt, mutation))


@mutations_app.command("list")
def mutations_list_command() -> None:
    for spec in mutation_specs():
        typer.echo(f"{spec.name}	Family: {spec.family}	Risk: {spec.risk}	Surface: {spec.surface}	{spec.description}")


@mutations_app.command("inspect")
def mutations_inspect_command(name: str = typer.Argument(..., help="Mutation name")) -> None:
    try:
        spec = get_mutation(name)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Mutation: {spec.name}")
    typer.echo(f"Category: {spec.category}")
    typer.echo(f"Family: {spec.family}")
    typer.echo(f"Risk: {spec.risk}")
    typer.echo(f"Surface: {spec.surface}")
    typer.echo(f"Deterministic: {str(spec.deterministic).lower()}")
    typer.echo(f"Reversible: {str(spec.reversible).lower()}")
    typer.echo(f"Description: {spec.description}")
    typer.echo(f"Example: {spec.example}")
    typer.echo(f"Safe example: {spec.safe_example}")
    typer.echo(f"Boundary: {spec.boundary}")
    typer.echo(f"Tags: {', '.join(spec.tags)}")


@mutations_app.command("validate-profile")
def mutations_validate_profile_command(
    profile_path: Path = typer.Option(..., "--profile", exists=True, dir_okay=False, readable=True, help="Mutation profile YAML to validate"),
    deep_profile_path: Path | None = typer.Option(None, "--deep-profile", exists=True, dir_okay=False, readable=True, help="Optional deep profile YAML to validate selected/deep alignment"),
) -> None:
    try:
        profile = load_mutation_profile(profile_path)
        deep_profile = load_mutation_profile(deep_profile_path) if deep_profile_path is not None else None
        if deep_profile is not None:
            validate_mutation_profile_pair(profile, deep_profile)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("Mutation profile valid")
    typer.echo("Provider calls enabled: false")
    typer.echo(f"Profile: {profile.id} {profile.version}")
    typer.echo(f"Mutations: {len(profile.mutations)}")
    typer.echo(f"Default: {str(profile.default).lower()}")
    typer.echo(f"Deep: {str(profile.deep).lower()}")
    if deep_profile is not None:
        typer.echo(f"Deep profile: {deep_profile.id}")

@app.command("mutate-run", hidden=True)
def mutate_run_command(
    preset: str | None = typer.Argument(None, help="Optional preset name; currently supports 'core'."),
    target: Path = typer.Option(..., exists=True, dir_okay=False, readable=True),
    input_path: Path | None = typer.Option(None, "--input", exists=True, dir_okay=False, readable=True, help="Dataset or benchmark pack YAML"),
    scoring: Path = typer.Option(..., exists=True, dir_okay=False, readable=True),
    out_dir: Path = typer.Option(..., file_okay=False),
    mutation: list[str] | None = typer.Option(None, "--mutation", help="Mutation name; repeat to run multiple. Defaults to all mutations."),
    mutation_profile: Path | None = typer.Option(None, "--mutation-profile", exists=True, dir_okay=False, readable=True, help="Mutation profile YAML whose mutations should be used."),
    limit: int | None = typer.Option(None, min=1, help="Maximum number of original cases to execute"),
    case_id: list[str] | None = typer.Option(None, "--case-id", help="Only run one or more case ids"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Write an execution plan without calling the target"),
    continue_on_provider_error: bool = typer.Option(False, "--continue-on-provider-error", help="Keep writing a partial mutation report when provider calls fail."),
    provider_min_delay: float = typer.Option(0.0, "--provider-min-delay", min=0.0, help="Minimum delay between provider calls in seconds."),
) -> None:
    resolved_input_path = input_path
    resolved_mutation_profile = mutation_profile
    if preset is not None:
        if preset != "core":
            typer.echo(f"unknown mutate-run preset: {preset}", err=True)
            raise typer.Exit(code=1)
        if input_path is not None:
            typer.echo("core preset cannot be combined with --input", err=True)
            raise typer.Exit(code=1)
        resolved_input_path = CORE_MUTATION_INPUT_PATH
        if resolved_mutation_profile is None and not mutation:
            resolved_mutation_profile = DEEP_MUTATION_PROFILE_PATH
    elif resolved_input_path is None:
        typer.echo("--input is required unless using the core preset", err=True)
        raise typer.Exit(code=1)

    selected_mutations = list(mutation or []) or None
    if resolved_mutation_profile is not None:
        if selected_mutations is not None:
            typer.echo("--mutation and --mutation-profile cannot be used together; choose explicit mutations or one profile.", err=True)
            raise typer.Exit(code=1)
        try:
            selected_mutations = list(load_mutation_profile(resolved_mutation_profile).mutations)
        except ValueError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=1) from exc

    try:
        report = run_mutation_benchmark(
            target,
            resolved_input_path,
            scoring,
            out_dir,
            mutations=selected_mutations,
            limit=limit,
            case_ids=set(case_id or []) or None,
            dry_run=dry_run,
            mutation_profile_path=resolved_mutation_profile,
            continue_on_provider_error=continue_on_provider_error,
            provider_min_delay=provider_min_delay,
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    except Exception as exc:  # pragma: no cover - defensive CLI boundary for provider/runtime failures
        typer.echo(_render_run_error(exc, target=str(target), out_dir=out_dir), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Mutation run complete: {report.run_id}")
    typer.echo(f"Mutated items: {report.summary.total_mutated_items}")
    typer.echo(f"Worst delta: {report.summary.worst_delta}")
    typer.echo(f"Worst mutation: {report.summary.worst_mutation or 'n/a'}")


@app.command("agent-lab", hidden=True)
def agent_lab_command(
    target: Path = typer.Option(..., exists=True, dir_okay=False, readable=True),
    scenarios: Path = typer.Option(..., "--scenarios", exists=True, dir_okay=False, readable=True, help="Agentic injection scenario YAML"),
    out_dir: Path = typer.Option(..., file_okay=False),
    scenario_id: list[str] | None = typer.Option(None, "--scenario-id", help="Only run one or more scenario ids"),
    limit: int | None = typer.Option(None, min=1, help="Maximum number of scenarios to execute"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Write an execution plan without calling the target"),
) -> None:
    report = run_agent_lab(
        target,
        scenarios,
        out_dir,
        scenario_ids=set(scenario_id or []) or None,
        limit=limit,
        dry_run=dry_run,
    )
    typer.echo(f"Agent lab complete: {report.run_id}")
    typer.echo(f"Violations: {report.summary.violations}/{report.summary.total_scenarios}")
    typer.echo(f"Highest risk: {report.summary.highest_risk or 'n/a'}")


@app.command("validate", hidden=True)
def validate_command(
    input_path: Path = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True, help="Dataset or benchmark pack YAML"),
    json_output: bool = typer.Option(False, "--json", help="Emit structured JSON validation report"),
) -> None:
    report = validate_input_path(input_path)
    typer.echo(report.to_json() if json_output else report.to_text())
    if not report.ok:
        raise typer.Exit(code=1)


@target_app.command("universe")
def target_universe_command(
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable provider/model universe catalog"),
) -> None:
    """List built-in provider/model presets without contacting any provider."""
    providers = [spec.to_public_dict() for spec in provider_catalog()]
    payload = {
        "schema_version": "malleus.model_universe_catalog.v1",
        "providers": providers,
        "compatibility_matrix": provider_compatibility_matrix(),
        "protocol_report": provider_protocol_report(),
        "custom_provider_supported": True,
        "operational_error_policy": "Provider/auth/quota/network/runtime errors are run conditions, not model behavior findings.",
    }
    if json_output:
        typer.echo(json.dumps(payload, indent=2))
        return
    lines = [
        "Malleus model universe",
        "Built-in OpenAI-compatible provider presets:",
    ]
    for provider in providers:
        models = provider.get("models", [])
        model_preview = ", ".join(str(item) for item in models[:3]) if isinstance(models, list) else ""
        verification = "live-verified" if provider.get("live_verified_by_maintainer") else "protocol-tested"
        lines.append(
            f"  - {provider.get('provider_id')}: {provider.get('label')} "
            f"({provider.get('api_key_env')}, {verification})"
            + (f" -> {model_preview}" if model_preview else "")
        )
    lines.extend(
        [
            "",
            "Custom providers:",
            "  Use `malleus target init --provider custom --base-url ...` for any OpenAI-compatible endpoint.",
            "",
            "Error policy:",
            f"  {payload['operational_error_policy']}",
        ]
    )
    typer.echo("\n".join(lines))


@app.command("gate", hidden=True)
def gate_command(
    report: Path = typer.Option(..., "--report", exists=True, dir_okay=False, readable=True, help="report.json or dry-run.json path"),
    policy: Path | None = typer.Option(None, "--policy", exists=True, dir_okay=False, readable=True, help="Optional gate policy YAML"),
) -> None:
    decision = evaluate_report_file(report, policy)
    typer.echo(decision.model_dump_json(indent=2))
    if decision.status in {"pass", "warn"}:
        return
    if decision.status == "fail":
        raise typer.Exit(code=1)
    raise typer.Exit(code=2)


@visual_lab_app.command("generate")
def visual_lab_generate_command(
    out_dir: Path = typer.Option(..., "--out-dir", file_okay=False, help="Output directory for visual-lab-manifest.json and safe fixtures"),
    scenario: str | None = typer.Option(None, "--scenario", help="Optional scenario id to generate a single fixture"),
) -> None:
    try:
        report = generate_visual_lab_fixtures(out_dir, scenario_id=scenario)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("Visual lab fixtures generated")
    typer.echo(f"Provider calls enabled: {str(report.provider_calls_enabled).lower()}")
    typer.echo(f"Scenarios: {report.summary.total_scenarios}")
    typer.echo(f"Visual scenarios: {report.summary.visual_scenarios}")
    typer.echo(f"Artifact scenarios: {report.summary.artifact_scenarios}")
    typer.echo(f"Artifacts: {report.summary.artifacts_written}")
    typer.echo(f"JSON: {Path(out_dir) / 'visual-lab-manifest.json'}")
    typer.echo(f"Markdown: {Path(out_dir) / 'visual-lab-report.md'}")


@visual_lab_app.command("run")
def visual_lab_run_command(
    fixture: Path = typer.Option(..., "--fixture", exists=True, dir_okay=False, readable=True, help="Visual lab fixture YAML or generated visual-lab-manifest.json"),
    out_dir: Path = typer.Option(..., "--out-dir", file_okay=False, help="Output directory for visual-lab inspection artifacts"),
) -> None:
    try:
        report = inspect_visual_lab(fixture, out_dir, source_is_fixture=fixture.suffix.lower() in {".yaml", ".yml"})
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("Visual lab inspection complete")
    typer.echo(f"Provider calls enabled: {str(report.provider_calls_enabled).lower()}")
    typer.echo(f"Gate recommendation: {report.gate_recommendation}")
    typer.echo(f"Scenarios: {report.summary.total_scenarios}")
    typer.echo(f"Findings: {report.summary.total_findings}")
    typer.echo(f"JSON: {Path(out_dir) / 'visual-lab-report.json'}")
    typer.echo(f"Markdown: {Path(out_dir) / 'visual-lab-report.md'}")
    typer.echo(f"HTML: {Path(out_dir) / 'visual-lab-report.html'}")


@visual_lab_app.command("vision-run")
def visual_lab_vision_run_command(
    prompt: str = typer.Option(..., "--prompt", help="Trusted text prompt to evaluate against the image context"),
    image: Path = typer.Option(..., "--image", exists=True, dir_okay=False, readable=True, help="Local image or visual artifact path"),
    target: Path = typer.Option(..., "--target", exists=True, dir_okay=False, readable=True, help="Target config used for scaffold metadata only"),
    out_dir: Path = typer.Option(..., "--out-dir", file_okay=False, help="Output directory for visual-run-report.json/md"),
    mode: str = typer.Option("local_fixture", "--mode", help="Run mode label: local_fixture or scaffold"),
    ocr_surface: list[str] | None = typer.Option(None, "--ocr-surface", help="Optional untrusted OCR fixture surface; repeatable"),
    metadata_surface: list[str] | None = typer.Option(None, "--metadata-surface", help="Optional untrusted metadata fixture surface; repeatable"),
    live_provider: bool = typer.Option(False, "--live-provider", help="Request future live-provider path; requires MALLEUS_ALLOW_PROVIDER_CALLS=1 and remains scaffold-only"),
) -> None:
    if mode not in {"local_fixture", "scaffold"}:
        typer.echo("vision-run --mode must be local_fixture or scaffold", err=True)
        raise typer.Exit(code=1)
    try:
        report = run_vision_fixture(
            prompt=prompt,
            image=image,
            target=target,
            output_dir=out_dir,
            ocr_surfaces=list(ocr_surface or []),
            metadata_surfaces=list(metadata_surface or []),
            mode=mode,
            live_provider=live_provider,
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("Visual lab vision run complete")
    typer.echo(f"Mode: {report.mode}")
    typer.echo(f"Provider calls enabled: {str(report.provider_calls_enabled).lower()}")
    typer.echo(f"Untrusted surfaces: {report.summary.untrusted_surface_count}")
    typer.echo(f"JSON: {Path(out_dir) / 'visual-run-report.json'}")
    typer.echo(f"Markdown: {Path(out_dir) / 'visual-run-report.md'}")


@safety_tune_app.command("run")
def safety_tune_run_command(
    target: Path = typer.Option(..., "--target", exists=True, dir_okay=False, readable=True, help="Target YAML used for metadata and recommended-target output"),
    input_path: Path = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True, help="Dataset or benchmark pack YAML"),
    out_dir: Path = typer.Option(..., "--out-dir", file_okay=False, help="Output directory for safety tuning artifacts"),
    scoring: Path = typer.Option(DEFAULT_SCORING_PATH, "--scoring", exists=True, dir_okay=False, readable=True, help="Scoring config YAML"),
    temperature: str | None = typer.Option(None, "--temperature", help="Comma-separated temperature grid; defaults to target request temperature"),
    top_p: str | None = typer.Option(None, "--top-p", help="Comma-separated top_p grid; defaults to target request top_p"),
    max_tokens: str | None = typer.Option(None, "--max-tokens", help="Comma-separated max_tokens grid; defaults to target request max_tokens"),
    repeats: int = typer.Option(3, "--repeats", min=1, help="Provider-free planned samples per item/configuration"),
    strategy: str = typer.Option("grid", "--strategy", help="Allocation strategy: grid or ucb"),
    budget: int | None = typer.Option(None, "--budget", min=1, help="UCB fixture allocation budget; defaults to full grid size"),
    seed: int = typer.Option(0, "--seed", help="Deterministic UCB tie-break seed"),
    category_pack: list[Path] | None = typer.Option(None, "--category-pack", exists=True, dir_okay=False, readable=True, help="Additional dataset or benchmark pack to include; repeatable"),
    anomaly_report: Path | None = typer.Option(None, "--anomaly-report", exists=True, dir_okay=False, readable=True, help="Optional local anomaly summary JSON to fold into anomaly rates"),
    dry_run: bool = typer.Option(True, "--dry-run/--no-dry-run", help="Write provider-free planning artifacts; provider calls stay disabled"),
    live_provider: bool = typer.Option(False, "--live-provider", help="Fail-closed future live-provider path; requires MALLEUS_ALLOW_PROVIDER_CALLS=1 and still makes no calls"),
) -> None:
    try:
        report = run_safety_tuning(
            target_path=target,
            input_paths=[input_path, *list(category_pack or [])],
            output_dir=out_dir,
            scoring_path=scoring,
            temperatures=parse_number_grid(temperature, cast_type=float, default=[]),
            top_ps=parse_number_grid(top_p, cast_type=float, default=[]),
            max_tokens_values=parse_number_grid(max_tokens, cast_type=int, default=[]),
            repeats=repeats,
            strategy=strategy,
            budget=budget,
            seed=seed,
            dry_run=dry_run,
            live_provider=live_provider,
            anomaly_report=anomaly_report,
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("Safety tuning report written")
    typer.echo(f"Mode: {report.mode}")
    typer.echo(f"Provider calls enabled: {str(report.provider_calls_enabled).lower()}")
    typer.echo(f"Strategy: {report.strategy}")
    typer.echo(f"Budget: {report.budget if report.budget is not None else 'full grid'}")
    typer.echo(f"Configurations: {len(report.configurations)}")
    typer.echo(f"Recommended: {report.recommended_config_id or 'n/a'}")
    typer.echo(f"JSON: {Path(out_dir) / 'safety-tuning-report.json'}")
    typer.echo(f"Markdown: {Path(out_dir) / 'safety-tuning-report.md'}")
    typer.echo(f"HTML: {Path(out_dir) / 'risk-surface.html'}")


@campaign_app.command("run")
def campaign_run_command(
    campaign: Path = typer.Option(..., "--campaign", exists=True, dir_okay=False, readable=True, help="Campaign YAML"),
    target: Path = typer.Option(..., "--target", exists=True, dir_okay=False, readable=True, help="Target YAML"),
    out_dir: Path = typer.Option(..., "--out-dir", file_okay=False, help="Output directory"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Write deterministic campaign artifacts without provider calls"),
) -> None:
    try:
        report = run_campaign(campaign, target, out_dir, dry_run=dry_run)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Campaign run complete: {report.run_id}")
    typer.echo(f"Steps: {report.summary.passed_steps}/{report.summary.total_steps} passed")
    typer.echo(f"Blocked steps: {report.summary.blocked_steps}")


@challenge_app.command("run")
def challenge_run_command(
    challenge: Path = typer.Option(..., "--challenge", exists=True, dir_okay=False, readable=True, help="Local challenge YAML"),
    out_dir: Path = typer.Option(..., "--out-dir", file_okay=False, help="Output directory"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Write scaffold artifacts without executing fixture semantics"),
) -> None:
    try:
        report = run_challenge(challenge, out_dir, dry_run=dry_run)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Challenge run complete: {report.run_id}")
    typer.echo(f"Status: {report.summary.status}")
    typer.echo(f"Score: {report.summary.score}")
    typer.echo("Provider calls enabled: false")
    typer.echo(f"JSON: {Path(out_dir) / 'challenge-report.json'}")
    typer.echo(f"Agent Protocol: {Path(out_dir) / 'agent-protocol.json'}")


@rag_app.command("run")
def rag_run_command(
    fixture: Path = typer.Option(..., "--fixture", exists=True, dir_okay=False, readable=True, help="Local RAG fixture YAML"),
    out_dir: Path = typer.Option(..., "--out-dir", file_okay=False, help="Output directory"),
) -> None:
    report = run_rag_fixture(fixture, out_dir)
    typer.echo(f"RAG harness complete: {report.run_id}")
    typer.echo(f"Detections: {report.summary.detections}")
    typer.echo(f"Failing queries: {report.summary.failing_queries}/{report.summary.total_queries}")


@coverage_app.command("build")
def coverage_build_command(
    input_path: Path = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True, help="Dataset or benchmark pack YAML"),
    out_dir: Path = typer.Option(..., "--out-dir", file_okay=False, help="Output directory for coverage.json/md/html"),
    report: list[Path] | None = typer.Option(None, "--report", exists=True, readable=True, help="Optional report directory, report JSON, or findings.json; repeatable"),
    campaign: list[Path] | None = typer.Option(None, "--campaign", exists=True, dir_okay=False, readable=True, help="Optional campaign YAML; repeatable"),
    agent_scenarios: list[Path] | None = typer.Option(None, "--agent-scenarios", exists=True, dir_okay=False, readable=True, help="Optional agent scenario YAML; repeatable"),
    mutation_report: list[Path] | None = typer.Option(None, "--mutation-report", dir_okay=False, help="Optional mutation-report.json or mutation-dry-run.json; repeatable"),
    hidden_report: list[Path] | None = typer.Option(None, "--hidden-report", dir_okay=False, help="Optional hidden-channel-report.json; repeatable"),
    artifact_report: list[Path] | None = typer.Option(None, "--artifact-report", dir_okay=False, help="Optional artifact-firewall-report.json; repeatable"),
    rag_report: list[Path] | None = typer.Option(None, "--rag-report", dir_okay=False, help="Optional rag-report.json; repeatable"),
    campaign_report: list[Path] | None = typer.Option(None, "--campaign-report", dir_okay=False, help="Optional campaign-report.json; repeatable"),
    visual_report: list[Path] | None = typer.Option(None, "--visual-report", dir_okay=False, help="Optional visual-lab-report.json or visual-run-report.json; repeatable"),
    safety_report: list[Path] | None = typer.Option(None, "--safety-report", dir_okay=False, help="Optional safety-tuning-report.json; repeatable"),
    anomaly_report: list[Path] | None = typer.Option(None, "--anomaly-report", dir_okay=False, help="Optional anomaly-report.json; repeatable"),
) -> None:
    try:
        coverage = build_coverage_report(
            input_path,
            report_paths=list(report or []),
            campaign_paths=list(campaign or []),
            agent_scenario_paths=list(agent_scenarios or []),
            mutation_reports=list(mutation_report or []),
            hidden_reports=list(hidden_report or []),
            artifact_reports=list(artifact_report or []),
            rag_reports=list(rag_report or []),
            campaign_reports=list(campaign_report or []),
            visual_reports=list(visual_report or []),
            safety_reports=list(safety_report or []),
            anomaly_reports=list(anomaly_report or []),
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    json_path, markdown_path, html_path = write_coverage_report(coverage, out_dir)
    typer.echo("Coverage build complete")
    typer.echo(f"Covered cells: {coverage.summary.covered_cells}/{coverage.summary.total_cells}")
    typer.echo(f"Missing cells: {coverage.summary.missing_cells}")
    typer.echo(f"JSON: {json_path}")
    typer.echo(f"Markdown: {markdown_path}")
    typer.echo(f"HTML: {html_path}")


@threat_model_app.command("init")
def threat_model_init_command(
    profile: str = typer.Option(..., "--profile", help=f"One of: {', '.join(SUPPORTED_PROFILES)}"),
    out: Path = typer.Option(..., "--out", dir_okay=False, help="Output YAML path"),
) -> None:
    try:
        model = init_threat_model(profile)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    path = write_threat_model(model, out)
    typer.echo(f"Threat model written: {path}")
    typer.echo(f"Profile: {model.profile}")
    typer.echo(f"Required cells: {len(model.required_cells)}")


@threat_model_app.command("status")
def threat_model_status_command(
    model: Path = typer.Option(..., "--model", exists=True, dir_okay=False, readable=True, help="Threat model YAML"),
) -> None:
    try:
        loaded = load_threat_model(model)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(threat_model_status(loaded), nl=False)


@threat_model_app.command("coverage")
def threat_model_coverage_command(
    model: Path = typer.Option(..., "--model", exists=True, dir_okay=False, readable=True, help="Threat model YAML"),
    coverage: Path = typer.Option(..., "--coverage", exists=True, dir_okay=False, readable=True, help="coverage.json"),
) -> None:
    result, text = threat_model_coverage_status(model, coverage)
    typer.echo(text, nl=False)
    if result.status != "covered":
        raise typer.Exit(code=1)


@workspace_app.command("init")
def workspace_init_command(
    path: Path = typer.Option(..., "--path", file_okay=False, help="Workspace directory to create"),
    profile: str = typer.Option(..., "--profile", help=f"One of: {', '.join(SUPPORTED_PROFILES)}"),
) -> None:
    try:
        root = init_workspace(path, profile)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Workspace initialized: {root}")
    typer.echo(f"Profile: {profile}")
    typer.echo("Provider calls enabled: false")


@workspace_app.command("status")
def workspace_status_command(
    path: Path = typer.Option(..., "--path", exists=True, file_okay=False, readable=True, help="Workspace directory"),
) -> None:
    typer.echo(render_workspace_status(inspect_workspace(path)), nl=False)


@workspace_app.command("next")
def workspace_next_command(
    path: Path = typer.Option(..., "--path", exists=True, file_okay=False, readable=True, help="Workspace directory"),
) -> None:
    typer.echo(render_workspace_next(inspect_workspace(path)), nl=False)


@scenario_app.command("generate")
def scenario_generate_command(
    profile: str = typer.Option(..., "--profile", help=f"One of: {', '.join(SUPPORTED_PROFILES)}"),
    surface: str = typer.Option(..., "--surface", help="Attack surface label, for example rag_context"),
    technique: str = typer.Option(..., "--technique", help="Technique label, for example tool_output_instruction"),
    boundary: str = typer.Option(..., "--boundary", help="Expected boundary label, for example agent_policy_boundary"),
    out_dir: Path = typer.Option(..., "--out-dir", file_okay=False, help="Output directory for draft artifacts"),
    severity: str = typer.Option("high", "--severity", help="Draft severity: low, medium, high, or critical"),
    tag: list[str] | None = typer.Option(None, "--tag", help="Optional sanitized draft tag; repeatable"),
) -> None:
    try:
        result = generate_defensive_scenario(
            profile=profile,
            surface=surface,
            technique=technique,
            boundary=boundary,
            out_dir=out_dir,
            severity=severity,
            tags=list(tag or []),
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("Scenario draft generated")
    typer.echo(f"Review status: {REVIEW_STATUS_DRAFT}")
    typer.echo("Provider calls enabled: false")
    typer.echo("Auto-add to benchmark packs: false")
    typer.echo(f"Scenario ID: {result.draft.scenario_id}")
    typer.echo(f"YAML draft: {result.paths['draft_yaml']}")
    typer.echo(f"Reviewer checklist: {result.paths['reviewer_checklist']}")
    typer.echo(f"Validation report: {result.paths['validation_json']}")
    typer.echo(f"Coverage preview: {result.paths['coverage_json']}")


@regression_app.command("generate")
def regression_generate_command(
    report: Path = typer.Option(..., "--report", exists=True, readable=True, help="Report directory, report JSON, or findings.json"),
    out_dir: Path = typer.Option(..., "--out-dir", file_okay=False, help="Output directory for regression-pack.yaml and replay-commands.md"),
) -> None:
    try:
        pack, paths = write_regression_pack(report, out_dir)
    except (OSError, ValueError, ValidationError) as exc:
        typer.echo(_format_cli_error(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("Regression pack generated")
    typer.echo("Provider calls enabled: false")
    typer.echo("Network enabled: false")
    typer.echo(f"Cases: {len(pack.cases)}")
    typer.echo(f"Pack: {paths['pack']}")
    typer.echo(f"Replay commands: {paths['commands']}")
    typer.echo(f"Manifest: {paths['manifest']}")


@regression_app.command("validate")
def regression_validate_command(
    pack: Path = typer.Option(..., "--pack", exists=True, dir_okay=False, readable=True, help="Regression pack YAML"),
    out_dir: Path | None = typer.Option(None, "--out-dir", file_okay=False, help="Optional directory for validation JSON/Markdown"),
    source_findings: Path | None = typer.Option(None, "--source-findings", exists=True, dir_okay=False, readable=True, help="Optional findings.json used to verify source hash"),
) -> None:
    report = validate_regression_pack(pack, source_findings=source_findings)
    if out_dir is not None:
        json_path, markdown_path = write_regression_validation(report, out_dir)
    else:
        json_path = markdown_path = None
    typer.echo(f"Regression validation: {report.status}")
    typer.echo("Provider calls enabled: false")
    typer.echo("Network enabled: false")
    typer.echo(f"Cases: {report.total_cases}")
    if report.errors:
        typer.echo(f"Errors: {len(report.errors)}")
    if report.warnings:
        typer.echo(f"Warnings: {len(report.warnings)}")
    if json_path is not None and markdown_path is not None:
        typer.echo(f"JSON: {json_path}")
        typer.echo(f"Markdown: {markdown_path}")
    if report.status != "pass":
        raise typer.Exit(code=1)


@app.command("replay")
def replay_command(
    finding_id: str = typer.Argument(..., help="Finding ID to replay as a dry-run/mock plan"),
    report: Path = typer.Option(..., "--report", exists=True, readable=True, help="Report directory, report.json, agent-lab-report.json, or findings.json"),
    dry_run: bool = typer.Option(True, "--dry-run/--no-dry-run", help="Only dry-run replay is supported"),
) -> None:
    try:
        json_path, markdown_path = replay_finding(finding_id, report, dry_run=dry_run)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Replay dry-run written: {finding_id}")
    typer.echo(f"JSON: {json_path}")
    typer.echo(f"Markdown: {markdown_path}")


@app.command("rescore")
def rescore_command(
    source: Path = typer.Option(..., "--source", exists=True, dir_okay=False, readable=True, help="Stored report, assessment report, or triage records JSON"),
    cache: Path = typer.Option(..., "--cache", dir_okay=False, help="Output rescore-cache.json path"),
) -> None:
    try:
        result = rescore_provider_free(source, cache_path=cache)
    except (OSError, ValueError, TypeError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("Rescore cache written")
    typer.echo(f"Provider calls enabled: {str(result.metadata.provider_calls_enabled).lower()}")
    typer.echo(f"Source kind: {result.metadata.source_kind}")
    typer.echo(f"Observations: {len(result.observations)}")
    typer.echo(f"Posture: {result.triage_summary.get('posture', 'REVIEW')}")
    typer.echo(f"Cache: {cache}")


@app.command("triage")
def triage_command(
    source: Path = typer.Option(..., "--source", exists=True, dir_okay=False, readable=True, help="Stored report, assessment report, or triage records JSON"),
    out: Path | None = typer.Option(None, "--out", dir_okay=False, help="Optional deterministic triage summary JSON path"),
) -> None:
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
        summary = deterministic_triage_summary(payload)
        if out is not None:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("Deterministic triage complete")
    typer.echo("Provider calls enabled: false")
    typer.echo(f"Posture: {summary.get('posture', 'REVIEW')}")
    typer.echo(f"Total cases: {summary.get('total_cases', 0)}")
    typer.echo(f"Pass: {summary.get('pass_count', 0)}")
    typer.echo(f"Fail: {summary.get('fail_count', 0)}")
    typer.echo(f"Errors: {summary.get('error_count', 0)}")
    typer.echo(f"Review: {summary.get('review_count', 0)}")
    typer.echo(f"Model security failures: {summary.get('model_security_failure_count', 0)}")
    typer.echo(f"Provider operational errors: {summary.get('provider_operational_error_count', 0)}")
    if out is not None:
        typer.echo(f"JSON: {out}")


@app.command("trace-summary")
def trace_summary_command(
    report: list[Path] = typer.Option(..., "--report", exists=True, dir_okay=False, readable=True, help="Report JSON containing agent_traces or embedded agent_trace_summary blocks"),
    out: Path | None = typer.Option(None, "--out", dir_okay=False, help="Optional AgentTrace collection JSON path"),
    json_output: bool = typer.Option(False, "--json", help="Print the collection JSON instead of text"),
) -> None:
    try:
        collection = load_agent_trace_collection(report)
        payload = collection.model_dump(mode="json")
        if out is not None:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    if json_output:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    else:
        typer.echo(render_agent_trace_summary(collection))
        if out is not None:
            typer.echo(f"JSON: {out}")


@app.command("network-doctor", hidden=True)
def network_doctor_command(
    target: str | None = typer.Option(None, "--target", help="Managed target name or target YAML path to diagnose"),
    host: str | None = typer.Option(None, "--host", help="Host to resolve when no target is supplied"),
    port: int = typer.Option(443, "--port", min=1, max=65535, help="Port used for DNS address lookup context"),
    config_dir: Path | None = typer.Option(None, "--config-dir", file_okay=False, help="Managed target directory", hidden=True),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable network doctor result"),
) -> None:
    """Diagnose DNS/resolver/sandbox reachability from the current Malleus process."""
    try:
        report = _network_doctor_report(target=target, host=host, port=port, config_dir=config_dir)
    except (TargetStoreError, ValueError, ValidationError, OSError) as exc:
        typer.echo(f"network_doctor: failed - {_format_cli_error(exc) if isinstance(exc, (ValueError, ValidationError)) else exc}", err=True)
        raise typer.Exit(code=1) from exc
    if json_output:
        typer.echo(json.dumps(report, indent=2))
    else:
        typer.echo(_render_network_doctor_console(report))
    if report["status"] != "ready":
        raise typer.Exit(code=1)


@app.command("run")
def run_command(
    target: str | None = typer.Argument(None, metavar="[TARGET]", help="Target model YAML config or managed target name"),
    target_option: str | None = typer.Option(None, "--target", help="Target model YAML config or managed target name"),
    input_path: Path = typer.Option(DEFAULT_RUN_INPUT_PATH, "--input", exists=True, dir_okay=False, readable=True, help="Dataset or benchmark pack YAML"),
    scoring: Path = typer.Option(DEFAULT_SCORING_PATH, "--scoring", exists=True, dir_okay=False, readable=True, help="Scoring config YAML"),
    out_dir: Path | None = typer.Option(None, "--out-dir", file_okay=False, help="Output directory; defaults to reports/<target>-run-<timestamp>"),
    limit: int | None = typer.Option(None, min=1, help="Maximum number of cases/groups to execute", hidden=True),
    case_id: list[str] | None = typer.Option(None, "--case-id", help="Only run one or more case/group ids", hidden=True),
    dry_run: bool = typer.Option(False, "--dry-run", help="Write an execution plan without calling the target"),
    repeats: int = typer.Option(1, "--repeats", min=1, help="Number of samples per case; defaults to one provider call", hidden=True),
    temperature_schedule: str | None = typer.Option(None, "--temperature-schedule", help="Comma-separated temperatures applied per repeated sample", hidden=True),
    config_dir: Path | None = typer.Option(None, "--config-dir", file_okay=False, help="Managed target directory", hidden=True),
) -> None:
    target_ref = target_option or target
    if target_ref is None:
        raise typer.BadParameter("provide a target as an argument or with --target")
    out_dir = out_dir or _default_report_dir(target_ref, "run")
    target_path = _resolve_cli_target(target_ref, config_dir)
    try:
        report = run_benchmark(
            target_path,
            input_path,
            scoring,
            out_dir,
            limit=limit,
            case_ids=set(case_id or []) or None,
            dry_run=dry_run,
            repeats=repeats,
            temperature_schedule=_parse_temperature_schedule(temperature_schedule),
            cli_argv=sys.argv,
        )
    except (ValueError, ValidationError) as exc:
        typer.echo(_format_cli_error(exc), err=True)
        raise typer.Exit(code=1) from exc
    except Exception as exc:  # pragma: no cover - defensive CLI boundary for provider/runtime failures
        typer.echo(_render_run_error(exc, target=target_ref, out_dir=out_dir), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Run complete: {report.run_id}")
    typer.echo(f"Score: {report.summary.score_total}/{report.summary.max_score_total}")
    if dry_run:
        _print_report_next_steps(out_dir, json_path=out_dir / "dry-run.json", markdown_path=out_dir / "dry-run.md")
    else:
        _print_report_next_steps(out_dir, json_path=out_dir / "report.json", markdown_path=out_dir / "report.md", html_path=out_dir / "report.html")


@app.command("dashboard")
def dashboard_command(
    report: list[Path] = typer.Option(..., "--report", exists=True, dir_okay=False, readable=True, help="report.json or live-full-evidence.json path; repeat for multiple targets"),
    out_dir: Path = typer.Option(..., file_okay=False),
) -> None:
    output = write_dashboard(list(report), out_dir)
    typer.echo(f"Dashboard written to: {output / 'index.html'}")


@app.command("evidence-bundle")
def evidence_bundle_command(
    out_dir: Path = typer.Option(..., "--out-dir", file_okay=False, help="Output directory for index.html"),
    title: str = typer.Option("Malleus Evidence Bundle", "--title", help="Dashboard title"),
    run_report: list[Path] | None = typer.Option(None, "--run-report", exists=True, dir_okay=False, readable=True, help="Malleus report.json; repeatable"),
    mutation_report: list[Path] | None = typer.Option(None, "--mutation-report", exists=True, dir_okay=False, readable=True, help="mutation-report.json; repeatable", hidden=True),
    agent_report: list[Path] | None = typer.Option(None, "--agent-report", exists=True, dir_okay=False, readable=True, help="agent-lab-report.json; repeatable", hidden=True),
    hidden_report: list[Path] | None = typer.Option(None, "--hidden-report", exists=True, dir_okay=False, readable=True, help="hidden-channel-report.json; repeatable", hidden=True),
    diff_report: list[Path] | None = typer.Option(None, "--diff-report", exists=True, dir_okay=False, readable=True, help="diff-runs-report.json; repeatable"),
    artifact_report: list[Path] | None = typer.Option(None, "--artifact-report", exists=True, dir_okay=False, readable=True, help="artifact-firewall-report.json; repeatable", hidden=True),
    visual_report: list[Path] | None = typer.Option(None, "--visual-report", exists=True, dir_okay=False, readable=True, help="visual-lab-report.json or visual-run-report.json; repeatable", hidden=True),
    rag_report: list[Path] | None = typer.Option(None, "--rag-report", exists=True, dir_okay=False, readable=True, help="rag-report.json; repeatable", hidden=True),
    campaign_report: list[Path] | None = typer.Option(None, "--campaign-report", exists=True, dir_okay=False, readable=True, help="campaign-report.json; repeatable", hidden=True),
    coverage_report: list[Path] | None = typer.Option(None, "--coverage-report", exists=True, dir_okay=False, readable=True, help="coverage.json; repeatable", hidden=True),
    threat_model: list[Path] | None = typer.Option(None, "--threat-model", exists=True, dir_okay=False, readable=True, help="threat-model YAML; repeatable", hidden=True),
    safety_report: list[Path] | None = typer.Option(None, "--safety-report", exists=True, dir_okay=False, readable=True, help="safety-tuning-report.json; repeatable", hidden=True),
    anomaly_report: list[Path] | None = typer.Option(None, "--anomaly-report", exists=True, dir_okay=False, readable=True, help="anomaly-report.json; repeatable", hidden=True),
    benchmark_report: list[Path] | None = typer.Option(None, "--benchmark-report", exists=True, dir_okay=False, readable=True, help="benchmark-plan.json or leaderboard.json; repeatable"),
    benchmark_panel: list[Path] | None = typer.Option(None, "--benchmark-panel", exists=True, dir_okay=False, readable=True, help="benchmark panel YAML; repeatable", hidden=True),
    patch_report: list[Path] | None = typer.Option(None, "--patch-report", exists=True, dir_okay=False, readable=True, help="patch-suggestions-*.json; repeatable", hidden=True),
    replay_report: list[Path] | None = typer.Option(None, "--replay-report", exists=True, dir_okay=False, readable=True, help="replay artifact JSON; repeatable", hidden=True),
    compound_report: list[Path] | None = typer.Option(None, "--compound-report", exists=True, dir_okay=False, readable=True, help="compound-risk-report.json; repeatable", hidden=True),
    issue_report: list[Path] | None = typer.Option(None, "--issue-report", exists=True, dir_okay=False, readable=True, help="issue-export.json; repeatable", hidden=True),
    remediation_board: list[Path] | None = typer.Option(None, "--remediation-board", exists=True, dir_okay=False, readable=True, help="remediation-board.md; repeatable", hidden=True),
    audit_mode: bool = typer.Option(False, "--audit-mode", help="Write auditor-mode summary, risk, remediation, and artifact hash files"),
) -> None:
    artifact_paths = [
        *list(run_report or []),
        *list(mutation_report or []),
        *list(agent_report or []),
        *list(hidden_report or []),
        *list(diff_report or []),
        *list(artifact_report or []),
        *list(visual_report or []),
        *list(rag_report or []),
        *list(campaign_report or []),
        *list(coverage_report or []),
        *list(threat_model or []),
        *list(safety_report or []),
        *list(anomaly_report or []),
        *list(benchmark_report or []),
        *list(benchmark_panel or []),
        *list(patch_report or []),
        *list(replay_report or []),
        *list(compound_report or []),
        *list(issue_report or []),
        *list(remediation_board or []),
    ]
    bundle = build_evidence_bundle(
        title=title,
        run_reports=list(run_report or []),
        mutation_reports=list(mutation_report or []),
        agent_reports=list(agent_report or []),
        hidden_reports=list(hidden_report or []),
        diff_reports=list(diff_report or []),
        artifact_reports=list(artifact_report or []),
        visual_reports=list(visual_report or []),
        rag_reports=list(rag_report or []),
        campaign_reports=list(campaign_report or []),
        coverage_reports=list(coverage_report or []),
        threat_models=list(threat_model or []),
        safety_reports=list(safety_report or []),
        anomaly_reports=list(anomaly_report or []),
        benchmark_reports=list(benchmark_report or []),
        benchmark_panels=list(benchmark_panel or []),
        patch_reports=list(patch_report or []),
        replay_reports=list(replay_report or []),
        compound_reports=list(compound_report or []),
        issue_reports=list(issue_report or []),
        remediation_boards=list(remediation_board or []),
    )
    if audit_mode:
        output = write_evidence_bundle(bundle, out_dir, audit_mode=True, artifact_paths=artifact_paths)
    else:
        output = write_evidence_bundle(bundle, out_dir)
    typer.echo(f"Evidence bundle written: {output}")
    if audit_mode:
        typer.echo(f"Audit summary: {out_dir / 'audit-summary.md'}")
        typer.echo(f"Risk register: {out_dir / 'risk-register.json'}")
        typer.echo(f"Remediation table: {out_dir / 'remediation-table.json'}")
        typer.echo(f"Artifact index: {out_dir / 'artifact-index.json'}")
    typer.echo(f"Run reports: {bundle.summary.run_reports}")
    typer.echo(f"Failed eval items: {bundle.summary.failed_eval_items}")
    typer.echo(f"Agent violations: {bundle.summary.agent_violations}")
    typer.echo(f"Hidden findings: {bundle.summary.hidden_findings}")
    typer.echo(f"New regressions: {bundle.summary.diff_newly_failing}")
    typer.echo(f"Artifact findings: {getattr(bundle.summary, 'artifact_findings', 0)}")
    typer.echo(f"RAG detections: {getattr(bundle.summary, 'rag_detections', 0)}")
    typer.echo(f"Safety unsafe regions: {getattr(bundle.summary, 'safety_unsafe_regions', 0)}")
    typer.echo(f"Anomaly findings: {getattr(bundle.summary, 'anomaly_findings', 0)}")
    typer.echo(f"Compound scenarios: {getattr(bundle.summary, 'compound_scenarios', 0)}")
    typer.echo(f"Exported issues: {getattr(bundle.summary, 'exported_issues', 0)}")


@app.command("compound-risk", hidden=True)
def compound_risk_command(
    input_path: list[Path] = typer.Option(..., "--input", exists=True, readable=True, help="Local findings/report JSON or report directory; repeatable"),
    out_dir: Path = typer.Option(..., "--out-dir", file_okay=False, help="Output directory for compound-risk-report.json/md/html"),
) -> None:
    try:
        report = build_compound_risk_report(list(input_path))
        json_path, markdown_path, html_path = write_compound_risk_report(report, out_dir)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("Compound risk report written")
    typer.echo("Provider calls enabled: false")
    typer.echo(f"Findings: {report.summary.total_findings}")
    typer.echo(f"Scenarios: {report.summary.total_scenarios}")
    typer.echo(f"Highest risk: {report.summary.highest_risk or 'n/a'}")
    typer.echo(f"JSON: {json_path}")
    typer.echo(f"Markdown: {markdown_path}")
    typer.echo(f"HTML: {html_path}")


@app.command("compare")
def compare_command(
    target: str = typer.Option(..., help="Target model YAML config or managed target name"),
    input_path: Path = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True, help="Dataset or benchmark pack YAML"),
    scoring: Path = typer.Option(..., exists=True, dir_okay=False, readable=True),
    out_dir: Path = typer.Option(..., file_okay=False),
    model: list[str] = typer.Option(..., "--model", help="Model id to evaluate; repeat for multiple models"),
    limit: int | None = typer.Option(None, min=1, help="Maximum number of cases/groups per model"),
    dry_run: bool = typer.Option(True, "--dry-run/--live-provider", help="Use --live-provider for real comparison evidence; --dry-run writes CI/dev planning artifacts only."),
    config_dir: Path | None = typer.Option(None, "--config-dir", file_okay=False, help="Managed target directory", hidden=True),
) -> None:
    target_path = _resolve_cli_target(target, config_dir)
    try:
        output = compare_models(target_path, input_path, scoring, out_dir, list(model), limit=limit, dry_run=dry_run)
    except (ValueError, ValidationError) as exc:
        typer.echo(_format_cli_error(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Comparison written to: {output}")
    typer.echo(f"Mode: {'dry_run' if dry_run else 'live_provider'}")
    typer.echo(f"Provider calls enabled: {str(not dry_run).lower()}")


if __name__ == "__main__":
    app()
