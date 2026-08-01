from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from malleus.flight_recorder import FlightRecording
from malleus.utils.time import now_iso


class OrganizationRun(BaseModel):
    organization: str
    project: str
    recording_id: str
    created_at: str
    source: str
    event_count: int
    violation_count: int
    critical_count: int
    metadata: dict[str, Any] = Field(default_factory=dict)


class OrganizationTrend(BaseModel):
    schema_version: str = "malleus.organization_trend.v1"
    organization: str
    project: str | None = None
    run_count: int
    total_violations: int
    latest_violations: int
    previous_violations: int | None = None
    direction: str


class OrganizationEvidenceStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def add_recording(
        self, organization: str, project: str, recording: FlightRecording
    ) -> OrganizationRun:
        run = OrganizationRun(
            organization=organization,
            project=project,
            recording_id=recording.recording_id,
            created_at=recording.created_at or now_iso(),
            source=recording.source,
            event_count=len(recording.events),
            violation_count=len(recording.violations),
            critical_count=sum(item.severity == "critical" for item in recording.violations),
            metadata=recording.metadata,
        )
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO recordings
                (organization, project, recording_id, created_at, source, event_count,
                 violation_count, critical_count, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run.organization,
                    run.project,
                    run.recording_id,
                    run.created_at,
                    run.source,
                    run.event_count,
                    run.violation_count,
                    run.critical_count,
                    recording.model_dump_json(),
                ),
            )
        return run

    def list_runs(
        self, organization: str, *, project: str | None = None, limit: int = 100
    ) -> list[OrganizationRun]:
        query = "SELECT * FROM recordings WHERE organization = ?"
        parameters: list[Any] = [organization]
        if project is not None:
            query += " AND project = ?"
            parameters.append(project)
        query += " ORDER BY created_at DESC LIMIT ?"
        parameters.append(max(1, min(limit, 1000)))
        with closing(self._connect()) as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [self._row_to_run(row) for row in rows]

    def get_recording(self, recording_id: str) -> FlightRecording:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT payload FROM recordings WHERE recording_id = ?", (recording_id,)
            ).fetchone()
        if row is None:
            raise KeyError(recording_id)
        return FlightRecording.model_validate_json(row["payload"])

    def trend(self, organization: str, *, project: str | None = None) -> OrganizationTrend:
        runs = self.list_runs(organization, project=project, limit=1000)
        latest = runs[0].violation_count if runs else 0
        previous = runs[1].violation_count if len(runs) > 1 else None
        direction = "new" if previous is None else "improving" if latest < previous else "regressing" if latest > previous else "stable"
        return OrganizationTrend(
            organization=organization,
            project=project,
            run_count=len(runs),
            total_violations=sum(run.violation_count for run in runs),
            latest_violations=latest,
            previous_violations=previous,
            direction=direction,
        )

    def _initialize(self) -> None:
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS recordings (
                    organization TEXT NOT NULL,
                    project TEXT NOT NULL,
                    recording_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    source TEXT NOT NULL,
                    event_count INTEGER NOT NULL,
                    violation_count INTEGER NOT NULL,
                    critical_count INTEGER NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_recordings_org_project ON recordings (organization, project, created_at)"
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    @staticmethod
    def _row_to_run(row: sqlite3.Row) -> OrganizationRun:
        payload = json.loads(row["payload"])
        return OrganizationRun(
            organization=row["organization"],
            project=row["project"],
            recording_id=row["recording_id"],
            created_at=row["created_at"],
            source=row["source"],
            event_count=row["event_count"],
            violation_count=row["violation_count"],
            critical_count=row["critical_count"],
            metadata=payload.get("metadata", {}),
        )
