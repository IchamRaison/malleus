from __future__ import annotations

import json
import re
from pathlib import Path

from malleus.assessment import run_assessment


FORBIDDEN_PUBLIC_PATTERNS = [
    r"Bearer\s+",
    r"/home/",
    r"raw_prompt",
    r"raw_response",
    r"<\s*script",
    r"javascript\s*:",
    r"\$\(",
    r"rm\s+-rf",
]


def _write_target(tmp_path: Path) -> Path:
    target = tmp_path / "target.yaml"
    target.write_text(
        "name: t\nadapter: openai_compatible\nmodel: m\nbase_url: https://example.test/v1\napi_key_env: OPENAI_API_KEY\n",
        encoding="utf-8",
    )
    return target


def _run_assessment(tmp_path: Path, *, packs: list[str], mode: str, profile: str = "rag-agent") -> Path:
    out_dir = tmp_path / f"assessment-{mode}-{'-'.join(packs)}"
    run_assessment(
        target_path=_write_target(tmp_path),
        profile=profile,
        packs=packs,
        mode=mode,
        out_dir=out_dir,
        compare_targets=[],
        regression_pack=None,
        policy_path=None,
        baseline_path=None,
        include_experimental=False,
        limit=None,
        case_ids=[],
        allow_live_provider=False,
        provider_calls_enabled=False,
    )
    return out_dir


def _artifact_texts(out_dir: Path) -> dict[str, str]:
    paths = [
        "findings/findings.json",
        "findings/findings.md",
        "remediation/remediation-board.md",
        "remediation/issue-export.json",
        "regression/regression-pack.yaml",
        "regression/replay-commands.md",
        "risk-report.json",
    ]
    return {path: (out_dir / path).read_text(encoding="utf-8") for path in paths}


def test_assessment_gap_findings_generate_remediation_issue_and_regression_artifacts(tmp_path: Path) -> None:
    first = _run_assessment(tmp_path, packs=["rag"], mode="dry_run")
    second = _run_assessment(tmp_path, packs=["rag"], mode="dry_run")

    findings_report = json.loads((first / "findings" / "findings.json").read_text(encoding="utf-8"))
    second_findings = json.loads((second / "findings" / "findings.json").read_text(encoding="utf-8"))
    issue_export = json.loads((first / "remediation" / "issue-export.json").read_text(encoding="utf-8"))
    regression_pack = (first / "regression" / "regression-pack.yaml").read_text(encoding="utf-8")
    replay_commands = (first / "regression" / "replay-commands.md").read_text(encoding="utf-8")

    assert findings_report["schema_version"] == "malleus.assessment_findings.v1"
    assert findings_report["status"] == "active_findings"
    assert len(findings_report["findings"]) == 1
    finding = findings_report["findings"][0]
    assert finding["finding_id"] == second_findings["findings"][0]["finding_id"]
    assert finding["finding_id"].startswith("finding-rag-agent-rag-requires-fixture-")
    assert finding["severity"] == "info"
    assert finding["category"] == "coverage_gap"
    assert finding["pack_id"] == "rag"
    assert finding["technique"] == "RAG Injection"
    assert finding["surface"] == "retrieval_context"
    assert finding["profile"] == "rag-agent"
    assert finding["status"] == "coverage_gap"
    assert finding["owner"] == "unassigned"
    assert finding["likelihood"] == "unknown"
    assert finding["confidence"] == "medium"
    assert finding["remediation"]
    assert finding["regression"]["replay_command_ref"] == "regression/replay-commands.md"
    assert finding["redacted_preview"].startswith("[REDACTED")
    assert finding["evidence_refs"] == ["ev-rag-planning"]

    assert issue_export["schema_version"] == "malleus.assessment_issue_export.v1"
    assert issue_export["remote_creation"] == "disabled"
    assert issue_export["issues"][0]["finding_id"] == finding["finding_id"]
    assert "Owner" in (first / "remediation" / "remediation-board.md").read_text(encoding="utf-8")
    assert finding["finding_id"] in regression_pack
    assert "expected_fixed_behavior" in regression_pack
    assert "replay_mode: 'provider_free_required'" in regression_pack
    assert "malleus assess" in replay_commands
    assert "--packs rag" in replay_commands
    assert "$(" not in replay_commands


def test_empty_findings_still_emit_valid_no_active_findings_artifacts(tmp_path: Path) -> None:
    out_dir = _run_assessment(tmp_path, packs=["core"], mode="dry_run", profile="chatbot")

    findings_report = json.loads((out_dir / "findings" / "findings.json").read_text(encoding="utf-8"))
    issue_export = json.loads((out_dir / "remediation" / "issue-export.json").read_text(encoding="utf-8"))
    remediation = (out_dir / "remediation" / "remediation-board.md").read_text(encoding="utf-8")
    regression_pack = (out_dir / "regression" / "regression-pack.yaml").read_text(encoding="utf-8")
    replay_commands = (out_dir / "regression" / "replay-commands.md").read_text(encoding="utf-8")

    assert findings_report["status"] == "no_active_findings"
    assert findings_report["findings"] == []
    assert "No active findings" in findings_report["note"]
    assert "No active findings recorded." in (out_dir / "findings" / "findings.md").read_text(encoding="utf-8")
    assert issue_export["issues"] == []
    assert "No remediation required" in remediation
    assert "[]" in regression_pack
    assert "No replay commands generated" in replay_commands


def test_findings_public_artifacts_redact_unsafe_previews_and_commands(tmp_path: Path) -> None:
    out_dir = _run_assessment(tmp_path, packs=["rag"], mode="dry_run")
    texts = _artifact_texts(out_dir)

    for relative_path, text in texts.items():
        lowered = text.lower()
        for pattern in FORBIDDEN_PUBLIC_PATTERNS:
            assert re.search(pattern, lowered, flags=re.IGNORECASE) is None, f"{relative_path} leaked {pattern}"

    replay_commands = texts["regression/replay-commands.md"]
    assert "<assessment-output>" in replay_commands
    assert "/tmp/" not in replay_commands
