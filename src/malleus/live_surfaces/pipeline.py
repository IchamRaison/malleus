from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


HarnessRunner = Callable[..., Any]


class MissingSystemHarnessReport(RuntimeError):
    pass


@dataclass(frozen=True)
class SystemHarnessSpec:
    target_type: str
    output_name: str
    runner: HarnessRunner
    report_type: Any
    report_name: str
    supports_limit: bool = False
    sandbox_backend: str | None = None


def execute_system_harness(
    spec: SystemHarnessSpec,
    *,
    target_path: str | Path,
    fixture_path: Path,
    output_dir: Path,
    limit: int | None,
) -> Any:
    kwargs: dict[str, Any] = {}
    if limit is not None and spec.supports_limit:
        kwargs["limit"] = limit
    if spec.sandbox_backend is not None:
        kwargs["sandbox_backend"] = spec.sandbox_backend
    spec.runner(target_path, fixture_path, output_dir, **kwargs)

    report_path = output_dir / spec.report_name
    if not report_path.exists():
        raise MissingSystemHarnessReport(spec.report_name)
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    return spec.report_type.model_validate(payload)
