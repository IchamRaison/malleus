from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "datasets/release_matrices/malleus-v0.1.yaml"
DOC_PATHS = [
    "README.md",
    "docs/what-malleus-tests.md",
    "docs/live-provider-assessments.md",
    "docs/attack-packs.md",
]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _docs() -> str:
    return "\n".join(_read(path) for path in DOC_PATHS)


def test_canonical_matrix_excludes_ui_browser_scaffold() -> None:
    payload = yaml.safe_load(MATRIX.read_text(encoding="utf-8"))
    pack_ids = {pack["id"] for pack in payload["packs"]}
    gate_pack_ids = {pack_id for gate in payload["gates"] for pack_id in gate.get("pack_ids", [])}

    assert "ui-browser-scaffold-v1" not in pack_ids
    assert "ui-browser-scaffold-v1" not in gate_pack_ids
    assert "ui-browser-scaffold-v1" not in MATRIX.read_text(encoding="utf-8")


def test_docs_define_live_target_types_and_wrappers() -> None:
    text = _docs()

    for phrase in [
        "`chat_completion`",
        "`rag_service`",
        "`tool_agent`",
        "`workflow_harness`",
        "`code_agent`",
        "malleus benchmark live-rag",
        "malleus benchmark live-agentic",
        "malleus benchmark live-workflow",
        "malleus benchmark live-code-agent",
        "malleus benchmark live-self-modification",
        "malleus benchmark soft",
        "malleus benchmark exterminatus",
        "`exterminatus` is exhaustive over implemented/canonical Malleus surfaces and configured mutation profiles, not exhaustive over universal AI security.",
        "Capability gaps, target config errors, target errors, operator skips, and checkpoint rows are reported as run/coverage outcomes, not model behavior failures.",
    ]:
        assert phrase in text


def test_docs_do_not_promote_static_or_scaffold_artifacts_as_real_system_evidence() -> None:
    text = _docs()

    for phrase in [
        "Fixture/model-only RAG, mock agent lab tools, static plugin scanning, static code-agent trace inspection, and UI scaffold artifacts are not real system live evidence.",
        "fixture-RAG/model-only RAG, mock agent lab tools, static plugin scanner output, static code-agent trace inspection, or UI scaffold artifacts as real system live evidence",
        "Browser/UI live evidence is available through the separate `browser_agent` target route",
        "RAG retrieval and citation security",
        "Tool-agent injection and authorization security",
        "Code-agent sandbox and workspace security",
        "Self-modification and policy-tampering security",
    ]:
        assert phrase in text

    attack_packs = _read("docs/attack-packs.md")
    assert "It contains 15 public surfaces and 2 mutation profile references" in attack_packs
    assert "Scaffold-only surface: `ui-browser-scaffold-v1`" not in attack_packs
    assert "Provider-free/static or dry-run surfaces:" not in attack_packs

    misleading_fragments = [
        "fixture RAG is real system live evidence",
        "model-only RAG is real system live evidence",
        "mock tools are real system live evidence",
        "static plugin scanning is real system live evidence",
        "static code-agent trace inspection is real system live evidence",
        "UI scaffold artifacts are real system live evidence",
    ]
    lowered = text.lower()
    for fragment in misleading_fragments:
        assert fragment.lower() not in lowered


def test_docs_align_canonical_live_scope_with_live_only_evidence_boundaries() -> None:
    text = _docs()

    for phrase in [
        "15 live-gated surfaces plus 2 mutation profile references",
        "Provider-free static inventories, provider-free dry-run plans, and local scaffold artifacts remain useful local assessment context",
        "they are not canonical live rows and cannot satisfy live gates",
        "Deterministic agent safety challenges (`challenge-v1`) and Calibration and control behavior checks (`calibration-v1`)",
        "real provider/model calls",
        "deterministic scoring",
        "redacted artifacts",
        "Visual and OCR prompt-injection security (`visual-ocr-matrix`) is a live multimodal/vision evidence surface",
        "`provider_capability_gap` rather than generic chat-text evidence",
    ]:
        assert phrase in text

    what_tests = _read("docs/what-malleus-tests.md")
    assert "provider-free static, provider-free dry-run, calibration" not in what_tests


def test_docs_make_real_service_validation_optional_and_ci_provider_free() -> None:
    text = _read("docs/live-provider-assessments.md")

    for phrase in [
        "Real-service validation is an operator-run activity, not a CI requirement.",
        "fake HTTP services, fake subprocess agents, temporary repositories, and environment-variable fixtures",
        "tests do not need real providers, credentials, Docker, browser automation, or destructive host execution",
        "create a local, uncommitted target config with the matching `target_type`",
        "run only the relevant surface command",
        "Use disposable workspaces for `code_agent`, dry-run/sandbox endpoints for `workflow_harness`",
    ]:
        assert phrase in text
