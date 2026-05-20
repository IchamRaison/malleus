from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_l2_integration_docs_are_publication_ready() -> None:
    index = _read("docs/integrations/README.md")
    readme = _read("README.md")

    for path in [
        "docs/integrations/generic-callable.md",
        "docs/integrations/langgraph.md",
        "docs/integrations/openai-agents.md",
        "docs/integrations/rag-service.md",
        "docs/integrations/browser-agent.md",
        "docs/integrations/code-agent.md",
        "docs/release-readiness.md",
        "docs/release-notes-v0.1.0-rc1.md",
    ]:
        text = _read(path)
        assert "malleus " in text
        assert "agent_target_depth: L2" in text or "L2" in text

    for phrase in [
        "Generic callable",
        "LangGraph",
        "OpenAI Agents",
        "RAG service",
        "Browser agent",
        "Code agent",
    ]:
        assert phrase in index

    assert "docs/integrations" in readme
    assert "docs/release-readiness.md" in readme
    assert "docs/release-notes-v0.1.0-rc1.md" in readme
    assert "examples/integrations/l2" in readme


def test_publication_claims_do_not_overstate_browser_or_visual_support() -> None:
    docs = "\n".join(
        _read(path)
        for path in [
            "README.md",
            "docs/integrations/browser-agent.md",
            "docs/integrations/code-agent.md",
            "docs/live-provider-assessments.md",
        ]
    )

    for phrase in [
        "`ui-harness` remains scaffold-only",
        "does not drive a browser or capture screenshots",
        "Browser automation evidence lives under the separate",
        "Without Playwright, Malleus records a DOM-only page-capture artifact",
        "Use `--sandbox-backend bwrap` on Linux hosts with bubblewrap installed",
    ]:
        assert phrase in docs

    lowered = docs.lower()
    forbidden = [
        "guarantees safety",
        "ui-harness drives a browser",
        "ui-harness captures screenshots",
        "visual live ocr is fully supported",
    ]
    for phrase in forbidden:
        assert phrase not in lowered


def test_publication_docs_scope_exterminatus_and_deepseek_findings() -> None:
    docs = "\n".join(
        _read(path)
        for path in [
            "README.md",
            "docs/what-malleus-tests.md",
            "docs/live-provider-assessments.md",
            "docs/evidence-bundle.md",
            "docs/release-readiness.md",
            "docs/release-notes-v0.1.0-rc1.md",
        ]
    )

    assert "exhaustive over implemented/canonical Malleus surfaces" in docs
    assert "not exhaustive over universal AI security" in docs
    assert "not a universal security proof" in docs
    assert "not deterministic model behavior failures" in docs


def test_publication_fixtures_avoid_openai_shaped_fake_tokens_when_not_required() -> None:
    fixture_text = "\n".join(
        _read(path)
        for path in [
            "tests/fixtures/plugins/secret-example.yaml",
            "tests/fixtures/plugins/unsafe-openapi.yaml",
            "tests/fixtures/plugins/synthetic-secret-admin-route.yaml",
            "tests/fixtures/code_agent/secret-leak.yaml",
            "tests/fixtures/ui_harness/local-product.yaml",
        ]
    )

    for raw in [
        "WOWPPPLUGINSECRET",
        "SYNTHETICPLUGINPLACEHOLDER0000",
        "WOWPPCODEAGENTSECRET",
        "UIHARNESSSECRET12345",
    ]:
        assert raw not in fixture_text
    assert "SYNTHETIC-SK-" in fixture_text
