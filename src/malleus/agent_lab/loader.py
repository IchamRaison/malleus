from __future__ import annotations

from pathlib import Path
from typing import cast

import yaml

from malleus.agent_lab.schemas import AgentScenarioPack


def load_agent_scenarios(path: str | Path) -> AgentScenarioPack:
    resolved = Path(path).resolve()
    data = yaml.safe_load(resolved.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"agent scenario file must contain a mapping: {resolved}")
    return AgentScenarioPack.model_validate(cast(dict[str, object], data))
