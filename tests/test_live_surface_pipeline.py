import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel

from malleus.live_surfaces.pipeline import (
    MissingSystemHarnessReport,
    SystemHarnessSpec,
    execute_system_harness,
)


class _Report(BaseModel):
    status: str


def test_execute_system_harness_applies_spec_and_loads_report(tmp_path: Path) -> None:
    calls: list[dict[str, Any]] = []

    def runner(target: str | Path, fixture: Path, output: Path, **kwargs: Any) -> None:
        calls.append({"target": target, "fixture": fixture, "output": output, **kwargs})
        output.mkdir(parents=True)
        (output / "report.json").write_text(json.dumps({"status": "passed"}), encoding="utf-8")

    spec = SystemHarnessSpec(
        "code_agent",
        "code-agent",
        runner,
        _Report,
        "report.json",
        supports_limit=True,
        sandbox_backend="bwrap",
    )
    output = tmp_path / "output"

    report = execute_system_harness(
        spec,
        target_path="target.yaml",
        fixture_path=tmp_path / "fixture.yaml",
        output_dir=output,
        limit=3,
    )

    assert report == _Report(status="passed")
    assert calls == [
        {
            "target": "target.yaml",
            "fixture": tmp_path / "fixture.yaml",
            "output": output,
            "limit": 3,
            "sandbox_backend": "bwrap",
        }
    ]


def test_execute_system_harness_requires_report_artifact(tmp_path: Path) -> None:
    spec = SystemHarnessSpec("tool_agent", "tool-agent", lambda *args, **kwargs: None, _Report, "report.json")

    with pytest.raises(MissingSystemHarnessReport, match="report.json"):
        execute_system_harness(
            spec,
            target_path="target.yaml",
            fixture_path=tmp_path / "fixture.yaml",
            output_dir=tmp_path,
            limit=None,
        )
