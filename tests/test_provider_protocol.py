from __future__ import annotations

from malleus.model_universe import provider_compatibility_matrix, provider_catalog
from malleus.provider_protocol import provider_protocol_report, validate_openai_compatible_response


def test_provider_compatibility_matrix_is_provider_free_and_honest() -> None:
    matrix = provider_compatibility_matrix()

    assert {row["provider_id"] for row in matrix} == {spec.provider_id for spec in provider_catalog()}
    assert all(row["protocol_tested"] is True for row in matrix)
    assert any(row["provider_id"] == "deepseek" and row["live_verified_by_maintainer"] is True for row in matrix)
    assert any(row["provider_id"] == "openrouter" and row["live_verified_by_maintainer"] is False for row in matrix)
    assert all("notes" in row for row in matrix)


def test_provider_protocol_report_contains_no_live_calls() -> None:
    report = provider_protocol_report()

    assert report["provider_calls_enabled"] is False
    assert report["case_count"] == len(provider_catalog())
    for case in report["cases"]:
        assert case["chat_url"].endswith("/chat/completions")
        assert case["models_url"].endswith("/models")
        assert case["auth_header"] == "Authorization"


def test_openai_compatible_response_validator_accepts_string_and_text_blocks() -> None:
    ok, content = validate_openai_compatible_response({"choices": [{"message": {"content": "hello"}}]})
    assert ok is True
    assert content == "hello"

    ok, content = validate_openai_compatible_response({"choices": [{"message": {"content": [{"type": "text", "text": "hello"}, {"type": "output_text", "text": "world"}]}}]})
    assert ok is True
    assert content == "hello\nworld"

    ok, reason = validate_openai_compatible_response({"choices": []})
    assert ok is False
    assert "choices" in reason
