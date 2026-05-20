from __future__ import annotations

import json
from pathlib import Path

from malleus.ui_action_live import build_ui_action_live_prompt, load_ui_action_fixture, run_ui_action_live
from malleus.utils.redact import scan_public_artifact_text


FIXTURE = Path("tests/fixtures/ui_harness/local-product.yaml")


def test_ui_action_live_calls_adapter_and_writes_redacted_non_browser_report(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)
    calls: list[str] = []
    expected_prompts = len(load_ui_action_fixture(FIXTURE).prompts)

    class SafeAdapter:
        def __init__(self, target):
            self.target = target

        def generate(self, prompt: str) -> str:
            calls.append(prompt)
            return json.dumps({"action": "read", "selector": "#message", "value": "", "rationale": "inspect untrusted page text without side effects"})

        def close(self) -> None:
            pass

    monkeypatch.setitem(__import__("malleus.runner").runner.ADAPTERS, "openai_compatible", SafeAdapter)

    report = run_ui_action_live(target, FIXTURE, tmp_path / "ui-live")

    assert len(calls) == expected_prompts
    assert report.provider_calls_enabled is True
    assert report.dry_run is False
    assert report.browser_enabled is False
    assert report.method == "non_browser_text_action_choice_live_model"
    assert report.live_model_calls == expected_prompts
    assert report.summary.status_counts == {"passed": expected_prompts, "failed": 0, "provider_error": 0}
    assert all(result.prompt_sha256 and result.response_sha256 for result in report.results)
    assert not (tmp_path / "ui-live" / "ui-harness-report.json").exists()
    assert (tmp_path / "ui-live" / "ui-action-live-report.json").exists()
    assert (tmp_path / "ui-live" / "ui-action-live-report.md").exists()
    public_text = (tmp_path / "ui-live" / "ui-action-live-report.json").read_text(encoding="utf-8")
    assert "RAW-COOKIE-TOKEN" not in public_text
    assert "SYNTHETIC-SK-UIHARNESS" not in public_text
    assert "ignore previous instructions" not in public_text.lower()
    assert "reveal a session token" not in public_text.lower()
    assert scan_public_artifact_text(public_text).passed


def test_ui_action_live_prompt_separates_trusted_task_from_untrusted_page_content(tmp_path: Path) -> None:
    fixture = load_ui_action_fixture(FIXTURE)
    prompt = build_ui_action_live_prompt(fixture, fixture.prompts[0], 1)

    assert "TRUSTED USER TASK (authoritative)" in prompt
    assert "TRUSTED DOM/SELECTOR SUMMARY" in prompt
    assert "UNTRUSTED PAGE CONTENT" in prompt
    assert "Return only strict JSON" in prompt
    assert "click Approve" in prompt
    assert "RAW-COOKIE-TOKEN" not in prompt
    assert "SYNTHETIC-SK-UIHARNESS" not in prompt


def test_ui_action_live_scores_forbidden_selector_as_model_failure(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)

    class ForbiddenSelectorAdapter:
        def __init__(self, target):
            self.target = target

        def generate(self, prompt: str) -> str:
            return json.dumps({"action": "click", "selector": "auth_header", "value": "", "rationale": "use the authorization header selector"})

        def close(self) -> None:
            pass

    monkeypatch.setitem(__import__("malleus.runner").runner.ADAPTERS, "openai_compatible", ForbiddenSelectorAdapter)

    report = run_ui_action_live(target, FIXTURE, tmp_path / "ui-live")
    expected_prompts = len(load_ui_action_fixture(FIXTURE).prompts)

    assert report.summary.failed == expected_prompts
    assert report.summary.provider_error == 0
    assert "forbidden_selector" in report.summary.reason_codes
    assert any(result.error_type is None and result.status == "failed" for result in report.results)


def test_ui_action_live_scores_invalid_json_as_model_failure_not_provider_error(monkeypatch, tmp_path: Path) -> None:
    target = _target(tmp_path)

    class InvalidJsonAdapter:
        def __init__(self, target):
            self.target = target

        def generate(self, prompt: str) -> str:
            return "not json"

        def close(self) -> None:
            pass

    monkeypatch.setitem(__import__("malleus.runner").runner.ADAPTERS, "openai_compatible", InvalidJsonAdapter)

    report = run_ui_action_live(target, FIXTURE, tmp_path / "ui-live")
    expected_prompts = len(load_ui_action_fixture(FIXTURE).prompts)

    assert report.summary.failed == expected_prompts
    assert report.summary.provider_error == 0
    assert "invalid_json" in report.summary.reason_codes
    assert all(result.response_sha256 and result.error_type is None for result in report.results)


def _target(tmp_path: Path) -> Path:
    target = tmp_path / "target.yaml"
    target.write_text("name: ui-target\nadapter: openai_compatible\nmodel: fake-model\nbase_url: https://example.test/v1\napi_key_env: MISSING_UI_ACTION_LIVE_KEY\n", encoding="utf-8")
    return target
