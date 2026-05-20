from __future__ import annotations

import json

from typer.testing import CliRunner

from malleus.cli import app
from malleus.v1_readiness import build_v1_readiness_report


def test_v1_readiness_report_tracks_done_and_blocking_items() -> None:
    report = build_v1_readiness_report()

    assert report["schema_version"] == "malleus.v1_readiness.v1"
    assert report["summary"]["done"] >= 1
    assert report["blocking_count"] == 0
    assert any(item["requirement"] == "live_full.py reduced to v1 compatibility-orchestrator size budget" and item["status"] == "done" for item in report["items"])


def test_v1_readiness_cli_writes_json(tmp_path) -> None:
    out_dir = tmp_path / "readiness"
    result = CliRunner().invoke(app, ["v1-readiness", "--out-dir", str(out_dir)])

    assert result.exit_code == 0, result.output
    assert "Malleus v1 readiness" in result.output
    payload = json.loads((out_dir / "v1-readiness.json").read_text(encoding="utf-8"))
    assert payload["status"] == "ready_for_v1"
    assert payload["blocking_count"] == 0
