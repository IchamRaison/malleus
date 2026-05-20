from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from malleus.findings import FindingsBundle, SecurityFinding, find_finding, load_or_collect_findings
from malleus.reporting import _md_safe

ADJUDICATION_SCHEMA_VERSION = "malleus.adjudications.v1"
AdjudicationStatus = Literal["confirmed", "false_positive", "accepted_risk", "needs_review", "fixed"]
_SECRET_RE = re.compile(
    r"\bsk-[A-Za-z0-9_-]{8,}\b|\b(?:api[_ -]?key|secret|token|password|credential|bearer)\s*[:=]?\s*[^\s`|<>]+",
    re.IGNORECASE,
)
_UNSAFE_RE = re.compile(
    r"\b(ignore previous instructions|system prompt|developer message|exfiltrate|call\s+exfiltrate_secret|environment token|reveal hidden)\b",
    re.IGNORECASE,
)
_SPACE_RE = re.compile(r"\s+")


class AdjudicationRecord(BaseModel):
    finding_id: str
    finding_hash: str
    status: AdjudicationStatus
    reviewer: str
    timestamp: str
    reason_code: str
    note: str = ""
    expires_at: str | None = None
    original_severity: str
    original_score: float | int | None = None
    original_metadata: dict[str, object] = Field(default_factory=dict)


class AdjudicationSummary(BaseModel):
    total_records: int = 0
    unique_findings: int = 0
    counts_by_status: dict[str, int] = Field(default_factory=dict)
    latest_status_by_finding: dict[str, str] = Field(default_factory=dict)
    open_findings: int = 0
    false_positive_findings: int = 0
    accepted_risk_findings: int = 0
    expired_accepted_risk_findings: int = 0
    fixed_findings: int = 0


class AdjudicationBundle(BaseModel):
    schema_version: str = ADJUDICATION_SCHEMA_VERSION
    generated_at: str
    source_findings: str | None = None
    summary: AdjudicationSummary
    records: list[AdjudicationRecord] = Field(default_factory=list)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def finding_hash(finding: SecurityFinding) -> str:
    payload = json.dumps(finding.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _redaction_label(value: str, *, kind: str = "sensitive") -> str:
    return f"[REDACTED {kind} sha256={_sha256_text(value)[:16]} length={len(value)}]"


def _sanitize_reviewer_field(value: object, *, limit: int = 360) -> str:
    text = _SPACE_RE.sub(" ", str(value)).strip()
    if not text:
        return "n/a"
    text = _SECRET_RE.sub(lambda match: _redaction_label(match.group(0)), text)
    text = _UNSAFE_RE.sub(lambda match: _redaction_label(match.group(0), kind="unsafe-instruction-like"), text)
    return text[:limit] + ("..." if len(text) > limit else "")


def _sanitize_record(record: AdjudicationRecord) -> AdjudicationRecord:
    return record.model_copy(
        update={
            "reviewer": _sanitize_reviewer_field(record.reviewer, limit=160),
            "reason_code": _sanitize_reviewer_field(record.reason_code, limit=160),
            "note": _sanitize_reviewer_field(record.note, limit=600) if record.note else "",
        }
    )


def _artifact_dir(report: str | Path) -> Path:
    path = Path(report).resolve()
    return path.parent if path.is_file() else path


def adjudication_path_for(report: str | Path) -> Path:
    return _artifact_dir(report) / "adjudications.json"


def _summary(records: list[AdjudicationRecord], findings: FindingsBundle | None = None) -> AdjudicationSummary:
    counts: dict[str, int] = {}
    latest: dict[str, str] = {}
    for record in records:
        counts[record.status] = counts.get(record.status, 0) + 1
        latest[record.finding_id] = record.status
    now = datetime.now(UTC)
    expired_accepted = {
        record.finding_id
        for record in records
        if record.status == "accepted_risk" and record.expires_at and _is_expired(record.expires_at, now=now)
    }
    open_statuses = {"confirmed", "needs_review"}
    if findings is not None:
        relevant_ids = {finding.finding_id for finding in findings.findings}
    else:
        relevant_ids = set(latest)
    return AdjudicationSummary(
        total_records=len(records),
        unique_findings=len(set(latest)),
        counts_by_status=dict(sorted(counts.items())),
        latest_status_by_finding=dict(sorted(latest.items())),
        open_findings=sum(1 for finding_id in relevant_ids if latest.get(finding_id, "needs_review") in open_statuses or finding_id in expired_accepted),
        false_positive_findings=sum(1 for status in latest.values() if status == "false_positive"),
        accepted_risk_findings=sum(1 for status in latest.values() if status == "accepted_risk"),
        expired_accepted_risk_findings=len(expired_accepted),
        fixed_findings=sum(1 for status in latest.values() if status == "fixed"),
    )


def _is_expired(value: str, *, now: datetime) -> bool:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return True
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed <= now


def load_adjudications(path: str | Path) -> AdjudicationBundle | None:
    artifact = Path(path)
    if artifact.is_dir():
        artifact = artifact / "adjudications.json"
    if not artifact.exists():
        return None
    return AdjudicationBundle.model_validate_json(artifact.read_text(encoding="utf-8"))


def load_adjudications_for_report(report: str | Path) -> AdjudicationBundle | None:
    return load_adjudications(adjudication_path_for(report))


def _record_for(
    finding: SecurityFinding,
    *,
    status: AdjudicationStatus,
    reviewer: str,
    reason_code: str,
    note: str = "",
    expires_at: str | None = None,
    timestamp: str | None = None,
) -> AdjudicationRecord:
    original_metadata: dict[str, object] = {
        "source_type": finding.source_type,
        "attack_surface": finding.attack_surface,
        "technique": finding.technique,
        "violated_boundary": finding.violated_boundary,
        "affected_model": finding.affected_model,
    }
    score = finding.metadata.get("score") if isinstance(finding.metadata, dict) else None
    if "penalty" in finding.metadata:
        original_metadata["penalty"] = finding.metadata["penalty"]
    return _sanitize_record(AdjudicationRecord(
        finding_id=finding.finding_id,
        finding_hash=finding_hash(finding),
        status=status,
        reviewer=reviewer,
        timestamp=timestamp or _now(),
        reason_code=reason_code,
        note=note,
        expires_at=expires_at,
        original_severity=finding.severity,
        original_score=score if isinstance(score, int | float) else None,
        original_metadata=original_metadata,
    ))


def render_adjudications_markdown(bundle: AdjudicationBundle) -> str:
    lines = [
        "# Malleus Finding Adjudications",
        "",
        f"- Records: {bundle.summary.total_records}",
        f"- Unique findings: {bundle.summary.unique_findings}",
        f"- Open findings: {bundle.summary.open_findings}",
        f"- False positives: {bundle.summary.false_positive_findings}",
        f"- Accepted risk: {bundle.summary.accepted_risk_findings}",
        f"- Expired accepted risk: {bundle.summary.expired_accepted_risk_findings}",
        f"- Fixed: {bundle.summary.fixed_findings}",
        "",
        "Adjudications are append-only. Original findings and evidence remain unchanged.",
        "",
    ]
    if not bundle.records:
        lines.append("No adjudication records.")
        return "\n".join(lines).rstrip() + "\n"
    lines.extend(["| Finding | Status | Reviewer | Reason | Timestamp |", "| --- | --- | --- | --- | --- |"])
    for record in bundle.records:
        lines.append(
            f"| {_md_safe(record.finding_id)} | {_md_safe(record.status)} | {_md_safe(record.reviewer)} | "
            f"{_md_safe(record.reason_code)} | {_md_safe(record.timestamp)} |"
        )
    lines.extend(["", "## Notes", ""])
    for record in bundle.records:
        lines.append(f"- {_md_safe(record.finding_id)} {_md_safe(record.status)}: {_md_safe(record.note or 'n/a')}")
    return "\n".join(lines).rstrip() + "\n"


def write_adjudications(bundle: AdjudicationBundle, output_dir: str | Path) -> tuple[Path, Path]:
    destination = Path(output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    bundle = bundle.model_copy(update={"records": [_sanitize_record(record) for record in bundle.records]})
    json_path = destination / "adjudications.json"
    markdown_path = destination / "adjudications.md"
    json_path.write_text(bundle.model_dump_json(indent=2), encoding="utf-8")
    markdown_path.write_text(render_adjudications_markdown(bundle), encoding="utf-8")
    return json_path, markdown_path


def adjudicate_finding(
    finding_id: str,
    report: str | Path,
    *,
    status: AdjudicationStatus,
    reviewer: str,
    reason_code: str,
    note: str = "",
    expires_at: str | None = None,
    timestamp: str | None = None,
) -> tuple[AdjudicationBundle, Path, Path]:
    findings = load_or_collect_findings(report)
    finding = find_finding(findings, finding_id)
    if finding is None:
        raise ValueError(f"finding not found: {finding_id}")
    destination = _artifact_dir(report)
    existing = load_adjudications(destination)
    records = list(existing.records if existing is not None else [])
    records.append(_record_for(finding, status=status, reviewer=reviewer, reason_code=reason_code, note=note, expires_at=expires_at, timestamp=timestamp))
    bundle = AdjudicationBundle(generated_at=timestamp or _now(), source_findings=str(Path(report).resolve()), summary=_summary(records, findings), records=records)
    json_path, markdown_path = write_adjudications(bundle, destination)
    return bundle, json_path, markdown_path


def adjudication_summary_text(bundle: AdjudicationBundle | None) -> str:
    if bundle is None:
        return "No adjudication artifact found."
    summary = bundle.summary
    return (
        f"records={summary.total_records}, open={summary.open_findings}, false_positive={summary.false_positive_findings}, "
        f"accepted_risk={summary.accepted_risk_findings}, expired_accepted_risk={summary.expired_accepted_risk_findings}, fixed={summary.fixed_findings}"
    )
