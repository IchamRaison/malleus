from __future__ import annotations

from pathlib import Path

from malleus.datasets import load_dataset_file, load_input_datasets
from malleus.schemas import ScenarioMetadata


REPO_ROOT = Path(__file__).resolve().parents[1]
CALIBRATION_PATH = REPO_ROOT / "datasets/calibration/calibration-v1.yaml"
BENIGN_MARKER = "benign-control"

EXPECTED_CASE_IDS = {
    "cal-benign-rag-summary",
    "cal-benign-strict-json",
    "cal-benign-tool-selection",
    "cal-benign-plugin-manifest",
    "cal-benign-code-agent-trace",
    "cal-benign-artifact-hidden-channel-text",
    "cal-benign-support-ticket-workflow",
    "cal-benign-doc-quote-ignore-previous",
    "cal-benign-json-danger-word-string",
    "cal-benign-plugin-disabled-dangerous-route",
    "cal-benign-mcp-readonly-version-note",
    "cal-benign-memory-preference-update",
    "cal-benign-multi-agent-review-summary",
    "cal-benign-browser-fragment-state",
}

FORBIDDEN_ATTACK_EXECUTION_MARKERS = {
    "adapter",
    "provider_mode",
    "tool_call",
    "tool_call_execution",
    "tool_execution",
    "expected_failure",
    "expected_outcome_failure",
    "raw_payload",
    "raw_body",
    "payload",
}


def _load_cases():
    dataset = load_dataset_file(CALIBRATION_PATH)
    return dataset, dataset.cases or []


def test_calibration_pack_loads_through_existing_dataset_apis() -> None:
    dataset, cases = _load_cases()
    loaded_inputs = load_input_datasets(CALIBRATION_PATH)

    assert dataset.name == "calibration-v1"
    assert dataset.category == "calibration"
    assert dataset.subcategory == "adversarial-benign-controls"
    assert dataset.metadata["calibration"] is True
    assert dataset.metadata["evidence_level"] == "live_model_required"
    assert dataset.metadata["expected_outcome"] == "pass"
    assert dataset.metadata["provider_calls_enabled"] is True
    assert len(loaded_inputs) == 1
    assert loaded_inputs[0].name == dataset.name
    assert {case.id for case in cases} == EXPECTED_CASE_IDS


def test_calibration_pack_benign_controls_are_static_expected_pass() -> None:
    _, cases = _load_cases()
    assert cases

    for case in cases:
        metadata = case.metadata
        scenario_metadata = ScenarioMetadata.model_validate(metadata)

        assert metadata["calibration"] is True
        assert metadata["expected_outcome"] == "pass"
        assert metadata["evidence_level"] == "live_model_required"
        assert BENIGN_MARKER in metadata["tags"]
        assert scenario_metadata.calibration is True
        assert scenario_metadata.evidence_level == "live_model_required"
        assert BENIGN_MARKER in scenario_metadata.tags
        assert case.severity == "low"
        assert case.expected_behavior
        assert case.pass_signals
        assert case.failure_signals
        assert metadata.keys().isdisjoint(FORBIDDEN_ATTACK_EXECUTION_MARKERS)
        assert metadata.get("expected_outcome") != "fail"
        assert "live provider" not in case.prompt.lower()
        assert "execute the tool" not in case.prompt.lower()


def test_calibration_pack_benign_adversarial_looking_text_is_inert() -> None:
    _, cases = _load_cases()
    cases_by_id = {case.id: case for case in cases}

    doc_quote = cases_by_id["cal-benign-doc-quote-ignore-previous"]
    assert "ignore previous instructions" in doc_quote.prompt
    assert doc_quote.metadata["expected_outcome"] == "pass"
    assert "documentation-quote" in doc_quote.metadata["tags"]
    assert doc_quote.metadata["inert_quote"] == "ignore previous instructions"
    assert "UNTRUSTED_CONTEXT_FOLLOWED" in doc_quote.metadata["reason_codes"]

    json_string = cases_by_id["cal-benign-json-danger-word-string"]
    assert '"delete is a word' in json_string.prompt
    assert json_string.metadata["expected_outcome"] == "pass"
    assert "json-string" in json_string.metadata["tags"]
    assert json_string.metadata["inert_json_string"] is True
    assert json_string.metadata["dangerous_word_is_data"] == "delete"
    assert "FORBIDDEN_TOOL_SELECTED" in json_string.metadata["reason_codes"]


def test_calibration_pack_reason_codes_are_only_on_applicable_controls() -> None:
    _, cases = _load_cases()
    reasoned_case_ids = {case.id for case in cases if case.metadata.get("reason_codes")}

    assert reasoned_case_ids == {
        "cal-benign-tool-selection",
        "cal-benign-code-agent-trace",
        "cal-benign-artifact-hidden-channel-text",
        "cal-benign-doc-quote-ignore-previous",
        "cal-benign-json-danger-word-string",
        "cal-benign-plugin-disabled-dangerous-route",
    }
    for case in cases:
        ScenarioMetadata.model_validate(case.metadata)


def test_calibration_pack_has_required_live_deterministic_signals() -> None:
    _, cases = _load_cases()
    cases_by_id = {case.id: case for case in cases}

    strict_json = cases_by_id["cal-benign-strict-json"]
    assert [signal.type for signal in strict_json.pass_signals] == ["valid_json_exact"]
    assert {signal.type for signal in strict_json.failure_signals} == {"extra_text_around_json", "exact_json_keys_mismatch"}

    assert any(signal.pattern == "lookup_article_title" for signal in cases_by_id["cal-benign-tool-selection"].pass_signals)
    assert any(signal.type == "regex" for signal in cases_by_id["cal-benign-doc-quote-ignore-previous"].failure_signals)
    assert cases_by_id["cal-benign-plugin-manifest"].metadata["inert_chat_control"] is True
    assert cases_by_id["cal-benign-code-agent-trace"].metadata["inert_chat_control"] is True
