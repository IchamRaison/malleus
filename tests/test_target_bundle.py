from __future__ import annotations

import json
from pathlib import Path

import yaml
from typer.testing import CliRunner

from malleus.cli import app
from malleus.target_bundle import doctor_target_bundle, load_target_bundle, make_reference_bundle, write_target_bundle


def test_bundle_init_writes_reference_bundle(tmp_path: Path) -> None:
    out = tmp_path / "bundle.yaml"
    result = CliRunner().invoke(app, ["bundle", "init", "--model-target", "deepseek-v4-flash-official", "--name", "demo", "--out", str(out)])

    assert result.exit_code == 0
    bundle = load_target_bundle(out)
    assert bundle.name == "demo"
    assert bundle.model_target == "deepseek-v4-flash-official"
    assert set(bundle.surfaces) == {"rag", "tool_agent", "workflow", "memory", "multi_agent", "browser", "code_agent"}
    assert bundle.surfaces["rag"].required_target_type == "rag_service"


def test_bundle_doctor_reports_missing_surface_targets(tmp_path: Path) -> None:
    model = tmp_path / "model.yaml"
    _write_model_target(model)
    bundle = make_reference_bundle("demo", str(model))
    bundle_path = write_target_bundle(bundle, tmp_path / "bundle.yaml")

    report = doctor_target_bundle(bundle_path)

    assert report.model_status == "passed"
    assert not report.ok
    assert all(check.status == "missing" for check in report.surface_checks)


def test_bundle_doctor_cli_json_is_machine_readable(tmp_path: Path) -> None:
    model = tmp_path / "model.yaml"
    _write_model_target(model)
    bundle = make_reference_bundle("demo", str(model))
    bundle_path = write_target_bundle(bundle, tmp_path / "bundle.yaml")

    result = CliRunner().invoke(app, ["bundle", "doctor", str(bundle_path), "--json"])

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["bundle"] == "demo"
    assert payload["model"]["status"] == "passed"
    assert payload["surfaces"][0]["status"] == "missing"


def test_bundle_doctor_passes_when_surface_targets_match(tmp_path: Path) -> None:
    model = tmp_path / "model.yaml"
    _write_model_target(model)
    targets = tmp_path / "targets"
    targets.mkdir()
    bundle = make_reference_bundle("demo", str(model))
    for surface, config in bundle.surfaces.items():
        target_path = targets / f"{config.target}.yaml"
        _write_system_target(target_path, config.target, str(config.required_target_type))
        config.target = str(target_path)
    bundle_path = write_target_bundle(bundle, tmp_path / "bundle.yaml")

    report = doctor_target_bundle(bundle_path)

    assert report.ok
    assert {check.surface for check in report.surface_checks} == set(bundle.surfaces)
    assert all(check.status == "passed" for check in report.surface_checks)


def _write_model_target(path: Path) -> None:
    path.write_text(
        yaml.safe_dump(
            {
                "name": "model",
                "target_type": "chat_completion",
                "adapter": "openai_compatible",
                "model": "fixture-model",
                "base_url": "http://127.0.0.1:9999/v1",
                "api_key_env": "MALLEUS_TEST_API_KEY",
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )


def _write_system_target(path: Path, name: str, target_type: str) -> None:
    payload: dict[str, object] = {"name": name, "target_type": target_type}
    if target_type == "code_agent":
        payload["code_agent"] = {"workspace_path": str(path.parent), "command_env": {}}
    else:
        field = target_type
        payload[field] = {"endpoint_url": "http://127.0.0.1:9999/run"}
        if target_type == "workflow_harness":
            payload[field]["workflow_id"] = "fixture-workflow"  # type: ignore[index]
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
