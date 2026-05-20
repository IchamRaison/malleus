from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from malleus.cli import app
from malleus.studio import export_studio, render_studio_html


FIXTURE = Path("tests/fixtures/studio/wowpp")


def _combined_public_text(out: Path) -> str:
    return "\n".join((out / name).read_text(encoding="utf-8") for name in ["index.html", "artifact-index.json"])


def test_studio_export_writes_narrative_html_and_artifact_index(tmp_path: Path) -> None:
    export = export_studio(FIXTURE, tmp_path)

    assert export.index_html == tmp_path / "studio" / "index.html"
    assert export.artifact_index == tmp_path / "studio" / "artifact-index.json"
    assert export.index_html.exists()
    assert export.artifact_index.exists()

    html = export.index_html.read_text(encoding="utf-8")
    for heading in [
        "Run overview",
        "Timeline/events",
        "Selected case/finding",
        "Redacted prompt / transformed prompt preview",
        "Hidden/artifact/visual findings",
        "Hidden findings",
        "Artifact findings",
        "Visual findings",
        "Response summary",
        "Refusal/anomaly classification",
        "Policy decision",
        "Coverage cell",
        "Replay command",
        "Patches",
        "Risk card",
        "Evidence refs",
        "Artifact index",
    ]:
        assert heading in html
    assert "malleus run --target examples/targets/openai.yaml" in html

    index = json.loads(export.artifact_index.read_text(encoding="utf-8"))
    assert index["schema_version"] == "malleus.studio.v1"
    artifact_paths = {item["path"] for item in index["artifacts"]}
    assert {
        "report.json",
        "events.jsonl",
        "findings.json",
        "mutation-report.json",
        "hidden-channel-report.json",
        "artifact-firewall-report.json",
        "visual-lab-report.json",
        "anomaly-report.json",
        "risk-summary.json",
        "coverage.json",
        "model-risk-card.md",
        "patch-suggestions-mf-studio-1.json",
        "replay-mf-studio-1.json",
    } <= artifact_paths
    assert all(len(item["sha256"]) == 64 for item in index["artifacts"])
    assert all(item["size_bytes"] > 0 for item in index["artifacts"])
    assert all(not item["path"].startswith("/") for item in index["artifacts"])


def test_studio_export_escapes_untrusted_content_and_has_no_external_dependencies(tmp_path: Path) -> None:
    export_studio(FIXTURE, tmp_path)
    combined = _combined_public_text(tmp_path / "studio")
    lowered = combined.lower()

    assert "<script>" not in combined
    assert "</script>" not in combined
    assert "MALLEUS-CANARY-STUDIO" not in combined
    assert "DO_NOT_DUMP_RAW_STUDIO" not in combined
    assert "/home/" not in combined
    assert "C:\\Users" not in combined
    assert "http://" not in lowered
    assert "https://" not in lowered
    assert "fonts.googleapis" not in lowered
    assert "fonts.gstatic" not in lowered
    assert "cdn" not in lowered
    assert "[REDACTED]" in combined


def test_studio_export_cli_writes_under_studio_subdirectory(tmp_path: Path) -> None:
    out = tmp_path / "malleus-studio"

    result = CliRunner().invoke(app, ["studio", "export", "--report-dir", str(FIXTURE), "--out-dir", str(out)])

    assert result.exit_code == 0, result.output
    assert "Studio export written" in result.output
    assert (out / "studio" / "index.html").exists()
    assert (out / "studio" / "artifact-index.json").exists()


def test_render_studio_html_can_be_parsed_from_existing_fixture_artifacts() -> None:
    html = render_studio_html(FIXTURE, [])

    assert html.startswith("<!doctype html>")
    assert "Security incident dossier" not in html
    assert "Malleus Studio" in html
    assert "Static HTML with no external JavaScript" in html
