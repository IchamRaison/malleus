from __future__ import annotations

import json

from typer.testing import CliRunner

from malleus.cli import app
from malleus.prod_readiness import build_prod_readiness_report


def test_prod_readiness_report_maps_ten_release_axes() -> None:
    report = build_prod_readiness_report()

    assert report["schema_version"] == "malleus.prod_readiness.v1"
    assert report["status"] == "prod_ready"
    assert report["blocking_count"] == 0
    assert len(report["items"]) == 10
    assert {item["axis"] for item in report["items"]} == {
        "architecture",
        "ci_cd",
        "cli_ux",
        "docs",
        "observability",
        "packaging_public",
        "plugins",
        "providers",
        "release_hygiene",
        "sandboxing",
    }


def test_prod_readiness_cli_writes_json(tmp_path) -> None:
    out_dir = tmp_path / "prod"
    result = CliRunner().invoke(app, ["prod-readiness", "--out-dir", str(out_dir)])

    assert result.exit_code == 0, result.output
    assert "Malleus production readiness" in result.output
    payload = json.loads((out_dir / "prod-readiness.json").read_text(encoding="utf-8"))
    assert payload["status"] == "prod_ready"
    assert payload["blocking_count"] == 0
