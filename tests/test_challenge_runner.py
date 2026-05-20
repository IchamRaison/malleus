from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from malleus.challenge_runner import import_agent_protocol, run_challenge
from malleus.cli import app
from malleus.utils.redact import scan_public_artifact_text

FIXTURES = Path("tests/fixtures/challenges")


def _public_text(out: Path) -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in sorted(out.iterdir()) if path.suffix in {".json", ".md"})


def test_safe_artifact_challenge_passes_and_writes_public_artifacts(tmp_path: Path) -> None:
    out = tmp_path / "safe"
    result = CliRunner().invoke(app, ["challenge", "run", "--challenge", str(FIXTURES / "safe-summary.yaml"), "--out-dir", str(out)])

    assert result.exit_code == 0, result.output
    assert "Challenge run complete" in result.output
    assert {"challenge-report.json", "challenge-report.md", "challenge-diff.json", "challenge-findings.json", "agent-protocol.json"}.issubset({path.name for path in out.iterdir()})
    payload = json.loads((out / "challenge-report.json").read_text(encoding="utf-8"))
    assert payload["schema_version"] == "malleus.challenge_report.v1"
    assert payload["mode"] == "local_fixture"
    assert payload["provider_calls_enabled"] is False
    assert payload["summary"]["status"] == "pass"
    assert payload["summary"]["score"] == 1.0
    assert payload["expected_artifacts"][0]["path"] == "summary.md"
    assert len(payload["expected_artifacts"][0]["sha256"]) == 64
    assert payload["agent_protocol"]["task_id"] == "task-safe-summary"
    assert payload["agent_protocol"]["step_id"] == "step-summarize"
    assert payload["agent_protocol"]["status"] == "passed"
    text = _public_text(out)
    assert "/home/" not in text
    assert "WOWPPSECRET" not in text
    assert scan_public_artifact_text(text).passed


def test_workspace_escape_is_blocked_fail_closed(tmp_path: Path) -> None:
    out = tmp_path / "escape"
    report = run_challenge(FIXTURES / "workspace-escape.yaml", out)

    payload = json.loads((out / "challenge-report.json").read_text(encoding="utf-8"))
    assert report.summary.status == "fail"
    assert payload["summary"]["status"] == "fail"
    assert any(finding["code"] == "workspace_escape" for finding in payload["findings"])
    assert not (out / "escaped.txt").exists()
    assert not (tmp_path / "escaped.txt").exists()
    assert payload["forbidden_artifacts"][0]["path"] == "../escaped.txt"
    assert "/home/" not in _public_text(out)


def test_agent_protocol_round_trip_and_process_supervision_fixture(tmp_path: Path) -> None:
    out = tmp_path / "agent"
    report = run_challenge(FIXTURES / "agent-protocol.yaml", out)
    protocol = import_agent_protocol(out / "agent-protocol.json")

    assert report.process.timeout is True
    assert report.process.process_tree_killed is True
    assert report.process.stdout_length == len("Agent protocol fixture completed.")
    assert report.process.stderr_length == len("Synthetic timeout marker captured.")
    assert protocol.schema_version == "malleus.agent_protocol.v1"
    assert protocol.task_id == "task-agent-protocol"
    assert protocol.step_id == "step-roundtrip"
    assert protocol.status == "failed"
    assert protocol.result["imported"] is True
    assert protocol.result["challenge_id"] == "agent-protocol-roundtrip"
    assert "process_supervision" in protocol.result["findings"]
    roundtrip = json.loads(protocol.model_dump_json(indent=2))
    assert roundtrip["task_id"] == "task-agent-protocol"
    assert roundtrip["step_id"] == "step-roundtrip"
    assert roundtrip["status"] == "failed"
    assert "artifacts" in roundtrip
    assert "logs" in roundtrip
    assert "result" in roundtrip
    assert "score" in roundtrip
