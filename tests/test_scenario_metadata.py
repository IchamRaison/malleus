from __future__ import annotations

from pathlib import Path

import pytest

from malleus.datasets import load_dataset_file, load_input_datasets, load_scenario_metadata_catalog
from malleus.schemas import ScenarioMetadata, ScenarioMetadataCatalog


ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "datasets/metadata/scenario-metadata-v1.yaml"


def _catalog_text(entry_metadata: str, *, source_path: str = "datasets/agentic/agentic_injection_v1.yaml", scenario_id: str = "forbidden-send-email-from-rag") -> str:
    return f"""
schema_version: malleus.scenario_metadata_catalog.v1
id: test-scenario-metadata
version: "1"
entries:
  - source_path: {source_path}
    scenario_id: {scenario_id}
    surface: agentic_scenario
    metadata:
{entry_metadata}
""".strip()


def test_load_scenario_metadata_catalog_validates_targeted_sidecar_entries() -> None:
    catalog = load_scenario_metadata_catalog(CATALOG)

    assert catalog.source_path == str(CATALOG.resolve())
    assert len(catalog.entries) == 5
    assert {(entry.source_path, entry.scenario_id) for entry in catalog.entries} == {
        ("datasets/agentic/agentic_injection_v1.yaml", "forbidden-send-email-from-rag"),
        ("tests/fixtures/rag/security-fixture.yaml", "fabricated-citation"),
        ("tests/fixtures/hidden_channels/artifact-hidden-catalog.yaml", "ahc-svg-hidden-offcanvas-003"),
        ("tests/fixtures/campaigns/agentic-extreme.yaml", "approval-bypass"),
        ("tests/fixtures/ui_harness/local-product.yaml", "fake-confirmation-banner"),
    }
    assert catalog.entries[0].metadata.reason_codes == ["FORBIDDEN_TOOL_SELECTED", "UNTRUSTED_CONTEXT_FOLLOWED"]
    assert catalog.entries[0].metadata.tags == ["agentic", "rag-context", "provider-free"]


def test_scenario_metadata_normalizes_valid_values_and_keeps_safe_unknown_metadata() -> None:
    metadata = ScenarioMetadata.model_validate(
        {
            "severity": " High ",
            "exploitability": "MEDIUM",
            "impact": [" data_disclosure ", ""],
            "reason_codes": [" forbidden_tool_selected "],
            "evidence_level": " PROVIDER_FREE_STATIC ",
            "tags": [" agentic ", "provider-free"],
            "metadata": {"safe_future_key": "non-fatal"},
        }
    )

    assert metadata.severity == "high"
    assert metadata.exploitability == "medium"
    assert metadata.impact == ["data_disclosure"]
    assert metadata.reason_codes == ["FORBIDDEN_TOOL_SELECTED"]
    assert metadata.evidence_level == "provider_free_static"
    assert metadata.tags == ["agentic", "provider-free"]
    assert metadata.metadata["safe_future_key"] == "non-fatal"


@pytest.mark.parametrize(
    ("field_name", "entry_metadata", "message"),
    [
        ("severity", "      severity: urgent\n", "unsupported scenario metadata severity: urgent"),
        ("exploitability", "      exploitability: trivial\n", "unsupported scenario metadata exploitability: trivial"),
        ("evidence_level", "      evidence_level: anecdotal\n", "unsupported scenario metadata evidence_level: anecdotal"),
        ("reason_code", "      reason_codes: [MADE_UP_REASON]\n", "unsupported scenario metadata reason_code: MADE_UP_REASON"),
    ],
)
def test_invalid_scenario_metadata_values_fail_with_deterministic_messages(tmp_path: Path, field_name: str, entry_metadata: str, message: str) -> None:
    catalog_path = tmp_path / f"invalid-{field_name}.yaml"
    catalog_path.write_text(_catalog_text(entry_metadata), encoding="utf-8")

    with pytest.raises(Exception, match=message):
        load_scenario_metadata_catalog(catalog_path)


def test_scenario_metadata_catalog_rejects_duplicate_entries(tmp_path: Path) -> None:
    catalog_path = tmp_path / "duplicate.yaml"
    catalog_path.write_text(
        """
schema_version: malleus.scenario_metadata_catalog.v1
id: duplicate-scenario-metadata
version: "1"
entries:
  - source_path: datasets/agentic/agentic_injection_v1.yaml
    scenario_id: forbidden-send-email-from-rag
    surface: agentic_scenario
    metadata:
      severity: high
  - source_path: datasets/agentic/agentic_injection_v1.yaml
    scenario_id: forbidden-send-email-from-rag
    surface: agentic_scenario
    metadata:
      severity: medium
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(Exception, match="duplicate scenario metadata entry: datasets/agentic/agentic_injection_v1.yaml#forbidden-send-email-from-rag"):
        load_scenario_metadata_catalog(catalog_path)


def test_scenario_metadata_catalog_rejects_missing_file(tmp_path: Path) -> None:
    catalog_path = tmp_path / "missing-file.yaml"
    catalog_path.write_text(
        _catalog_text("      severity: high\n", source_path="tests/fixtures/rag/not-present.yaml"),
        encoding="utf-8",
    )

    with pytest.raises(Exception, match="scenario metadata entry references missing file: tests/fixtures/rag/not-present.yaml"):
        load_scenario_metadata_catalog(catalog_path)


def test_scenario_metadata_catalog_rejects_missing_scenario_id(tmp_path: Path) -> None:
    catalog_path = tmp_path / "missing-id.yaml"
    catalog_path.write_text(
        _catalog_text("      severity: high\n", scenario_id="not-a-real-scenario"),
        encoding="utf-8",
    )

    with pytest.raises(Exception, match="scenario metadata entry references unknown scenario id: datasets/agentic/agentic_injection_v1.yaml#not-a-real-scenario"):
        load_scenario_metadata_catalog(catalog_path)


def test_existing_dataset_loaders_still_accept_safe_unknown_metadata(tmp_path: Path) -> None:
    dataset_path = tmp_path / "safe-metadata.yaml"
    dataset_path.write_text(
        """
name: safe-metadata
version: 1
category: local
subcategory: loader-regression
cases:
  - id: safe-unknown-metadata
    severity: low
    objective: Keep safe unknown metadata non-fatal.
    prompt: Synthetic placeholder prompt.
    metadata:
      future_safe_key: allowed
      nested:
        provider_free: true
""".strip(),
        encoding="utf-8",
    )

    dataset = load_dataset_file(dataset_path)
    assert dataset.cases is not None
    assert dataset.cases[0].metadata["future_safe_key"] == "allowed"

    smoke = load_input_datasets(ROOT / "datasets/benchmark_packs/smoke-v1.yaml")
    assert smoke


def test_scenario_metadata_catalog_model_rejects_raw_evidence_fields() -> None:
    forbidden_key = "raw_" + "payload"
    with pytest.raises(Exception, match="raw evidence fields are not allowed"):
        ScenarioMetadataCatalog.model_validate(
            {
                "id": "unsafe",
                "version": "1",
                "entries": [
                    {
                        "source_path": "datasets/agentic/agentic_injection_v1.yaml",
                        "scenario_id": "forbidden-send-email-from-rag",
                        "surface": "agentic_scenario",
                        "metadata": {"severity": "high", "metadata": {forbidden_key: "forbidden"}},
                    }
                ],
            }
        )
