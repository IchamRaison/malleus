from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from malleus.utils.time import now_iso


EVENT_SCHEMA_VERSION = "malleus.events.v1"


class EventRecord(BaseModel):
    schema_version: str = EVENT_SCHEMA_VERSION
    event_type: str
    run_id: str
    timestamp: str = Field(default_factory=now_iso)
    payload: dict[str, Any] = Field(default_factory=dict)


class EventLogger:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("", encoding="utf-8")

    def emit(self, event_type: str, run_id: str, **payload: Any) -> EventRecord:
        record = EventRecord(event_type=event_type, run_id=run_id, payload=payload)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record.model_dump(), sort_keys=True) + "\n")
        return record
