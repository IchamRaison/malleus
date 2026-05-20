from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from malleus.agent_lab import load_agent_scenarios
from malleus.artifact_firewall import inspect_artifact
from malleus.campaign_runner import run_campaign
from malleus.challenge_runner import run_challenge
from malleus.code_agent import inspect_code_agent_trace
from malleus.hidden_channels import inspect_text_deep
from malleus.plugin_scanner import scan_plugin_manifest
from malleus.rag_harness import run_rag_fixture
from malleus.self_modification import inspect_self_modification
from malleus.ui_harness import build_ui_harness_plan
from malleus.visual_lab import scenario_matrix


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "examples/targets/openai.yaml"


@dataclass(frozen=True)
class SurfaceInventory:
    surface: str
    current_count: int
    target_count: int
    stable_ids: tuple[str, ...]
    paths: tuple[Path, ...]
    counting_rule: str
    documented_exception: str | None = None


def _read_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict), path
    return data


def _yaml_files(directory: Path) -> tuple[Path, ...]:
    return tuple(sorted(directory.glob("*.yaml")))


def _durable_artifact_hidden_paths() -> tuple[Path, ...]:
    return (
        ROOT / "tests/fixtures/artifacts/suspicious.html",
        ROOT / "tests/fixtures/artifacts/suspicious.svg",
        ROOT / "tests/fixtures/hidden_channels/nested-encoded-canary.md",
    )


def _artifact_hidden_catalog_path() -> Path:
    return ROOT / "tests/fixtures/hidden_channels/artifact-hidden-catalog.yaml"


def _artifact_hidden_catalog_cases() -> tuple[dict[str, Any], ...]:
    catalog = _read_yaml(_artifact_hidden_catalog_path())
    assert catalog["schema"] == "malleus.artifact_hidden_catalog.v1"
    cases = catalog["cases"]
    assert isinstance(cases, list)
    return tuple(cases)


def _assert_unique(values: Iterable[str], label: str) -> None:
    items = list(values)
    duplicates = sorted({item for item in items if items.count(item) > 1})
    assert not duplicates, f"duplicate {label}: {duplicates}"


def _rag_inventory() -> SurfaceInventory:
    path = ROOT / "tests/fixtures/rag/security-fixture.yaml"
    data = _read_yaml(path)
    query_ids = tuple(query["id"] for query in data["queries"])
    doc_ids = {document["id"] for document in data["documents"]}
    for query in data["queries"]:
        assert set(query["retrieved_ids"]) <= doc_ids
        assert set(query["citations"]) - doc_ids <= {"missing-doc"}
    return SurfaceInventory("rag", len(query_ids), 20, query_ids, (path,), "queries[] entry")


def _agent_tool_inventory() -> SurfaceInventory:
    path = ROOT / "datasets/agentic/agentic_injection_v1.yaml"
    pack = load_agent_scenarios(path)
    ids = tuple(scenario.id for scenario in pack.scenarios)
    for scenario in pack.scenarios:
        assert scenario.forbidden_tools
        assert set(scenario.allowed_tools).isdisjoint(scenario.forbidden_tools)
    return SurfaceInventory("agent/tool", len(ids), 20, ids, (path,), "scenarios[] entry")


def _artifact_hidden_inventory() -> SurfaceInventory:
    fixture_paths = _durable_artifact_hidden_paths()
    catalog_path = _artifact_hidden_catalog_path()
    catalog_cases = _artifact_hidden_catalog_cases()
    ids = tuple(case["id"] for case in catalog_cases)
    carriers = tuple(case["carrier"] for case in catalog_cases)
    _assert_unique(carriers, "artifact/hidden-channel carrier")
    assert {case["family"] for case in catalog_cases} <= {"artifact", "hidden-channel"}
    assert all(case["safe_sample"] for case in catalog_cases)
    assert all("MALLEUS-CANARY-AHC-" in case["safe_sample"] for case in catalog_cases)
    return SurfaceInventory(
        "artifact/hidden-channel",
        len(catalog_cases),
        20,
        ids,
        (*fixture_paths, catalog_path),
        "durable fixture file or committed catalog row",
        "temporary artifact tests do not count as durable inventory",
    )


def _visual_inventory() -> SurfaceInventory:
    scenarios = scenario_matrix()
    ids = tuple(scenario.scenario_id for scenario in scenarios)
    visual_non_scaffold = [scenario for scenario in scenarios if scenario.family == "visual" and not scenario.scaffold_future]
    visual_scaffold = [scenario for scenario in scenarios if scenario.family == "visual" and scenario.scaffold_future]
    artifact_family = [scenario for scenario in scenarios if scenario.family == "artifact"]
    assert len(visual_non_scaffold) == 23
    assert len(visual_scaffold) == 9
    assert len(artifact_family) == 29
    return SurfaceInventory(
        "visual/ocr",
        len(scenarios),
        20,
        ids,
        (ROOT / "src/malleus/visual_lab.py", ROOT / "tests/fixtures/visual/support-ticket.yaml"),
        "scenario_matrix() case by broad visual/OCR rule",
        "broad matrix count passes; non-scaffold visual/OCR count is documented separately",
    )


def _code_agent_inventory() -> SurfaceInventory:
    paths = _yaml_files(ROOT / "tests/fixtures/code_agent")
    ids = tuple(path.stem for path in paths)
    return SurfaceInventory("code-agent", len(paths), 20, ids, paths, "YAML trace fixture")


def _plugin_inventory() -> SurfaceInventory:
    paths = _yaml_files(ROOT / "tests/fixtures/plugins")
    ids = tuple(path.stem for path in paths)
    return SurfaceInventory("plugin/workflow", len(paths), 20, ids, paths, "plugin/OpenAPI/workflow manifest fixture")


def _ui_inventory() -> SurfaceInventory:
    local = ROOT / "tests/fixtures/ui_harness/local-product.yaml"
    external = ROOT / "tests/fixtures/ui_harness/external-product.yaml"
    data = _read_yaml(local)
    prompts = data["prompts"]
    ids = tuple(prompt.get("id", f"local-product:{index}") for index, prompt in enumerate(prompts, start=1))
    external_data = _read_yaml(external)
    assert external_data["target_url"].startswith("https://example.com")
    return SurfaceInventory(
        "ui/browser",
        len(prompts),
        20,
        ids,
        (local,),
        "local scaffold prompt/workflow unit",
        "external-product.yaml is fail-closed third-party negative coverage and is not counted",
    )


def _campaign_inventory() -> SurfaceInventory:
    path = ROOT / "tests/fixtures/campaigns/agentic-extreme.yaml"
    data = _read_yaml(path)
    ids = tuple(step["id"] for step in data["steps"])
    step_ids = set(ids)
    for step in data["steps"]:
        assert step["tactic"]
        assert set(step.get("depends_on", [])) <= step_ids
    return SurfaceInventory("campaign", len(ids), 20, ids, (path,), "campaign step with unique tactic/oracle")


def _self_modification_inventory() -> SurfaceInventory:
    paths = tuple(sorted((ROOT / "tests/fixtures/self_modification").glob("*")))
    durable = tuple(path for path in paths if path.suffix in {".diff", ".yaml"})
    ids = tuple(path.name for path in durable)
    trace = _read_yaml(ROOT / "tests/fixtures/self_modification/loop-trace.yaml")
    assert trace["events"]
    assert not all("id" in event for event in trace["events"])
    return SurfaceInventory(
        "self-modification",
        len(durable),
        20,
        ids,
        durable,
        "durable diff or trace fixture",
        "loop-trace events need stable event IDs before event-level counting",
    )


def _challenge_inventory() -> SurfaceInventory:
    paths = _yaml_files(ROOT / "tests/fixtures/challenges")
    ids = tuple(_read_yaml(path)["id"] for path in paths)
    return SurfaceInventory("challenge", len(paths), 20, ids, paths, "challenge YAML fixture")


def _inventories() -> tuple[SurfaceInventory, ...]:
    return (
        _rag_inventory(),
        _agent_tool_inventory(),
        _artifact_hidden_inventory(),
        _visual_inventory(),
        _code_agent_inventory(),
        _plugin_inventory(),
        _ui_inventory(),
        _campaign_inventory(),
        _self_modification_inventory(),
        _challenge_inventory(),
    )


def test_all_locked_surfaces_are_represented_with_stable_unique_ids() -> None:
    inventories = _inventories()

    assert {inventory.surface for inventory in inventories} == {
        "rag",
        "agent/tool",
        "artifact/hidden-channel",
        "visual/ocr",
        "code-agent",
        "plugin/workflow",
        "ui/browser",
        "campaign",
        "self-modification",
        "challenge",
    }
    for inventory in inventories:
        assert inventory.counting_rule
        assert inventory.current_count == len(inventory.stable_ids)
        assert all(identifier and identifier == identifier.strip() for identifier in inventory.stable_ids)
        _assert_unique(inventory.stable_ids, inventory.surface)
        assert all(path.exists() for path in inventory.paths)


def test_surface_counts_meet_locked_targets_or_documented_visual_rule() -> None:
    shortfalls = {
        inventory.surface: {
            "current": inventory.current_count,
            "target": inventory.target_count,
            "rule": inventory.counting_rule,
            "exception": inventory.documented_exception,
        }
        for inventory in _inventories()
        if inventory.current_count < inventory.target_count
    }

    assert not shortfalls


def test_current_fixtures_load_or_parse_without_provider_browser_plugin_git_or_diff_execution(tmp_path: Path) -> None:
    rag_report = run_rag_fixture(ROOT / "tests/fixtures/rag/security-fixture.yaml", tmp_path / "rag")
    campaign_report = run_campaign(ROOT / "tests/fixtures/campaigns/agentic-extreme.yaml", TARGET, tmp_path / "campaign", dry_run=True)
    ui_plan = build_ui_harness_plan(ROOT / "tests/fixtures/ui_harness/local-product.yaml", tmp_path / "ui", dry_run=True)

    assert rag_report.provider_calls_enabled is False
    assert campaign_report.provider_calls_enabled is False
    assert all(attempt.provider_call is False for step in campaign_report.steps for attempt in step.attempts)
    assert ui_plan.provider_calls_enabled is False
    assert ui_plan.browser_enabled is False

    for path in _yaml_files(ROOT / "tests/fixtures/code_agent"):
        inspection = inspect_code_agent_trace(path)
        assert inspection.vcs_report.metadata["git_mutation_enabled"] is False
        assert inspection.vcs_report.metadata["trace_execution_enabled"] is False

    for path in _yaml_files(ROOT / "tests/fixtures/plugins"):
        report = scan_plugin_manifest(path)
        assert report.provider_calls_enabled is False
        assert report.metadata["remote_schema_fetch_enabled"] is False
        assert report.metadata["plugin_code_execution_enabled"] is False

    self_mod = inspect_self_modification(
        sorted((ROOT / "tests/fixtures/self_modification").glob("*.diff")),
        [ROOT / "tests/fixtures/self_modification/loop-trace.yaml"],
    )
    assert self_mod.provider_calls_enabled is False
    assert self_mod.metadata["diff_application_enabled"] is False
    assert self_mod.metadata["trace_execution_enabled"] is False
    assert self_mod.metadata["autonomous_self_editing_enabled"] is False


def test_artifact_hidden_and_challenge_fixtures_are_static_local_inventory(tmp_path: Path) -> None:
    for artifact in (ROOT / "tests/fixtures/artifacts").glob("*.*"):
        report = inspect_artifact(artifact)
        assert report.manifest.format in {"html", "svg"}
        assert report.manifest.sha256

    hidden = ROOT / "tests/fixtures/hidden_channels/nested-encoded-canary.md"
    hidden_report = inspect_text_deep(hidden.read_text(encoding="utf-8"), source=str(hidden))
    assert hidden_report.deep is not None
    assert hidden_report.gate_recommendation in {"quarantine", "block"}

    for challenge in _yaml_files(ROOT / "tests/fixtures/challenges"):
        report = run_challenge(challenge, tmp_path / challenge.stem)
        assert report.provider_calls_enabled is False
        assert report.mode == "local_fixture"
        assert not (tmp_path / "escaped.txt").exists()


def test_synthetic_canary_and_secret_hygiene_for_expansion_inventory() -> None:
    inventory_paths = sorted(
        {
            path
            for inventory in _inventories()
            for path in inventory.paths
            if path.is_file() and path.suffix in {".diff", ".html", ".md", ".svg", ".yaml"}
        }
    )
    texts = {path: path.read_text(encoding="utf-8", errors="ignore") for path in inventory_paths}

    secret_patterns = {
        "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,}\b"),
        "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
        "openai_key": re.compile(r"\bsk-(?!WOWPP|UIHARNESS|MALLEUS|SYNTHETIC)[A-Za-z0-9_-]{32,}\b"),
        "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    }
    for path, text in texts.items():
        for label, pattern in secret_patterns.items():
            assert not pattern.search(text), f"{label} matched in {path.relative_to(ROOT)}"

    forbidden_research_markers = ("Elder " + "Plinius", "ST" + "3GG", "P4RS3" + "LT0NGV3", "G0D" + "M0D3", "LEAK" + "HUB")
    legacy_encoded_fixture = ROOT / "tests/fixtures/hidden_channels/nested-encoded-canary.md"
    for path, text in texts.items():
        assert not any(marker in text for marker in forbidden_research_markers), path.relative_to(ROOT)
        if path == legacy_encoded_fixture:
            continue
        assert "```" not in text, f"raw fenced block in {path.relative_to(ROOT)}"
        encoded_blobs = re.findall(r"[A-Za-z0-9+/]{120,}={0,2}", text)
        assert not encoded_blobs, f"long encoded-looking blob in {path.relative_to(ROOT)}"

    canary_text = "\n".join(texts.values())
    assert "MALLEUS" in canary_text
    assert "CANARY" in canary_text
