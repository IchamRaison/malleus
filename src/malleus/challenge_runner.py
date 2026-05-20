from __future__ import annotations

import hashlib
import json
import re
import shutil
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

from malleus.reporting import _md_safe
from malleus.schemas import REPORT_MODE_LOCAL_FIXTURE, REPORT_MODE_SCAFFOLD, RedactionMetadata, WowppReportMetadata
from malleus.utils.ids import new_run_id
from malleus.utils.redact import redact_public_text, redacted_preview, sha256_text

CHALLENGE_SCHEMA_VERSION = "malleus.challenge.v1"
CHALLENGE_REPORT_SCHEMA_VERSION = "malleus.challenge_report.v1"
AGENT_PROTOCOL_SCHEMA_VERSION = "malleus.agent_protocol.v1"
_REDACTED = "[REDACTED_CHALLENGE_TEXT]"
_MAX_PREVIEW = 160


class ChallengeArtifactSpec(BaseModel):
    path: str
    contains: str | None = None
    forbidden_contains: list[str] = Field(default_factory=list)


class ChallengeInputArtifact(BaseModel):
    path: str
    text: str = ""


class ChallengeProcessSpec(BaseModel):
    mode: Literal["safe_fixture", "scaffold"] = "safe_fixture"
    action: Literal["write_summary", "attempt_escape", "agent_protocol_roundtrip", "timeout", "scaffold_only"] = "write_summary"
    stdout: str = ""
    stderr: str = ""
    return_code: int = 0
    timeout: bool = False
    process_tree_killed: bool = False
    writes: list[ChallengeInputArtifact] = Field(default_factory=list)


class AgentProtocolArtifact(BaseModel):
    path: str
    sha256: str | None = None
    length: int | None = None
    redacted_preview: str | None = None


class AgentProtocolLog(BaseModel):
    stream: Literal["stdout", "stderr", "system"] = "system"
    sha256: str
    length: int
    redacted_preview: str


class AgentProtocolMessage(BaseModel):
    schema_version: str = AGENT_PROTOCOL_SCHEMA_VERSION
    task_id: str
    step_id: str
    status: Literal["pending", "running", "passed", "failed", "blocked", "scaffold"] = "pending"
    artifacts: list[AgentProtocolArtifact] = Field(default_factory=list)
    logs: list[AgentProtocolLog] = Field(default_factory=list)
    result: dict[str, Any] = Field(default_factory=dict)
    score: float = 0.0


class ChallengeCheckSpec(BaseModel):
    expected_artifacts: list[ChallengeArtifactSpec] = Field(default_factory=list)
    forbidden_artifacts: list[str] = Field(default_factory=list)
    forbidden_output: list[str] = Field(default_factory=list)


class ChallengeSpec(BaseModel):
    schema_version: str = CHALLENGE_SCHEMA_VERSION
    id: str
    task_id: str
    step_id: str
    title: str
    task_input: str = ""
    workspace: str = "workspace"
    artifacts_in: list[ChallengeInputArtifact] = Field(default_factory=list)
    process: ChallengeProcessSpec = Field(default_factory=ChallengeProcessSpec)
    checks: ChallengeCheckSpec = Field(default_factory=ChallengeCheckSpec)
    agent_protocol: AgentProtocolMessage | None = None


class ChallengeArtifactRecord(BaseModel):
    path: str
    exists: bool
    sha256: str | None = None
    length: int | None = None
    redacted_preview: str | None = None


class ChallengeProcessRecord(BaseModel):
    mode: str
    command_scaffolded: bool = True
    stdout_sha256: str
    stdout_length: int
    stdout_preview: str
    stderr_sha256: str
    stderr_length: int
    stderr_preview: str
    return_code: int
    timeout: bool = False
    process_tree_killed: bool = False


class ChallengeFinding(BaseModel):
    code: str
    status: Literal["fail", "warn"] = "fail"
    reason: str
    artifact_path: str | None = None


class ChallengeSummary(BaseModel):
    status: Literal["pass", "fail", "scaffold"]
    score: float
    total_checks: int
    passed_checks: int
    failed_checks: int


class ChallengeReport(BaseModel):
    schema_version: str = CHALLENGE_REPORT_SCHEMA_VERSION
    run_id: str
    started_at: str
    finished_at: str
    challenge_id: str
    task_id: str
    step_id: str
    title: str
    mode: str
    provider_calls_enabled: bool = False
    executor: str = "safe_local_fixture"
    workspace_root: str
    challenge_path: str
    artifacts_in: list[ChallengeArtifactRecord] = Field(default_factory=list)
    artifacts_out: list[ChallengeArtifactRecord] = Field(default_factory=list)
    expected_artifacts: list[ChallengeArtifactRecord] = Field(default_factory=list)
    forbidden_artifacts: list[ChallengeArtifactRecord] = Field(default_factory=list)
    findings: list[ChallengeFinding] = Field(default_factory=list)
    process: ChallengeProcessRecord
    workspace_snapshot: list[ChallengeArtifactRecord] = Field(default_factory=list)
    agent_protocol: AgentProtocolMessage
    summary: ChallengeSummary
    wowpp_metadata: WowppReportMetadata | None = None
    redaction_metadata: RedactionMetadata = Field(default_factory=lambda: RedactionMetadata(status="redacted", marker=_REDACTED))


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _safe_rel(path: str) -> str:
    value = path.replace("\\", "/").strip()
    if not value:
        raise ValueError("artifact path must not be empty")
    posix = PurePosixPath(value)
    if posix.is_absolute() or ".." in posix.parts:
        raise ValueError(f"artifact path escapes workspace: {value}")
    return posix.as_posix()


def _display_path(path: str | Path) -> str:
    resolved = Path(path).resolve()
    try:
        return resolved.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        text = resolved.as_posix()
        return redact_public_text(text).text if "/home/" in text else resolved.name


def _preview(value: str) -> str:
    redacted = redact_public_text(value, limit=_MAX_PREVIEW)
    if redacted.redacted:
        return redacted.text
    suspicious = re.search(r"\b(secret|token|password|api[_ -]?key|canary)\b", value, re.IGNORECASE)
    if suspicious:
        return f"{_REDACTED} sha256={sha256_text(value)[:16]} length={len(value)}"
    return redacted_preview(value, limit=_MAX_PREVIEW)


def _hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _artifact_record(root: Path, rel_path: str) -> ChallengeArtifactRecord:
    safe = _safe_rel(rel_path)
    path = root / safe
    if not path.exists() or not path.is_file():
        return ChallengeArtifactRecord(path=safe, exists=False)
    text = path.read_text(encoding="utf-8", errors="replace")
    return ChallengeArtifactRecord(path=safe, exists=True, sha256=_hash_file(path), length=len(path.read_bytes()), redacted_preview=_preview(text))


def load_challenge(path: str | Path) -> ChallengeSpec:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError("challenge YAML must contain a mapping")
    return ChallengeSpec.model_validate(data)


def export_agent_protocol(message: AgentProtocolMessage, path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(message.model_dump_json(indent=2), encoding="utf-8")
    return destination


def import_agent_protocol(path: str | Path) -> AgentProtocolMessage:
    return AgentProtocolMessage.model_validate_json(Path(path).read_text(encoding="utf-8"))


def _write_workspace_inputs(spec: ChallengeSpec, workspace: Path) -> list[ChallengeArtifactRecord]:
    records: list[ChallengeArtifactRecord] = []
    for artifact in spec.artifacts_in:
        rel_path = _safe_rel(artifact.path)
        destination = workspace / rel_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(artifact.text, encoding="utf-8")
        records.append(_artifact_record(workspace, rel_path))
    return records


def _safe_fixture_process(spec: ChallengeSpec, workspace: Path) -> tuple[ChallengeProcessRecord, list[str], list[ChallengeFinding]]:
    process = spec.process
    findings: list[ChallengeFinding] = []
    written: list[str] = []
    if process.mode != "safe_fixture":
        stdout = process.stdout or "scaffold only; no command executed"
        record = _process_record(process, stdout=stdout, stderr=process.stderr, return_code=0, scaffold=True)
        return record, written, findings

    for artifact in process.writes:
        try:
            rel_path = _safe_rel(artifact.path)
        except ValueError as exc:
            findings.append(ChallengeFinding(code="workspace_escape", reason=str(exc), artifact_path=artifact.path))
            continue
        destination = workspace / rel_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(artifact.text, encoding="utf-8")
        written.append(rel_path)
    if process.action == "write_summary" and not written:
        source = workspace / "input.txt"
        body = source.read_text(encoding="utf-8", errors="replace") if source.exists() else spec.task_input
        summary = " ".join(body.split())[:120]
        (workspace / "summary.md").write_text(f"# Summary\n\n{summary}\n", encoding="utf-8")
        written.append("summary.md")
    if process.action == "attempt_escape":
        findings.append(ChallengeFinding(code="workspace_escape", reason="safe fixture blocked attempted write outside virtual workspace", artifact_path="../escape.txt"))
    stdout = process.stdout or f"safe fixture completed challenge {spec.id}"
    record = _process_record(process, stdout=stdout, stderr=process.stderr, return_code=process.return_code, scaffold=False)
    return record, sorted(set(written)), findings


def _process_record(process: ChallengeProcessSpec, *, stdout: str, stderr: str, return_code: int, scaffold: bool) -> ChallengeProcessRecord:
    return ChallengeProcessRecord(
        mode=REPORT_MODE_SCAFFOLD if process.mode == "scaffold" else REPORT_MODE_LOCAL_FIXTURE,
        command_scaffolded=scaffold,
        stdout_sha256=sha256_text(stdout),
        stdout_length=len(stdout),
        stdout_preview=_preview(stdout),
        stderr_sha256=sha256_text(stderr),
        stderr_length=len(stderr),
        stderr_preview=_preview(stderr),
        return_code=return_code,
        timeout=process.timeout,
        process_tree_killed=process.process_tree_killed,
    )


def _snapshot(workspace: Path) -> list[ChallengeArtifactRecord]:
    records = []
    for path in sorted(item for item in workspace.rglob("*") if item.is_file()):
        rel_path = path.relative_to(workspace).as_posix()
        records.append(_artifact_record(workspace, rel_path))
    return records


def _evaluate_checks(spec: ChallengeSpec, workspace: Path, process: ChallengeProcessRecord, seed_findings: list[ChallengeFinding]) -> tuple[list[ChallengeArtifactRecord], list[ChallengeArtifactRecord], list[ChallengeFinding], ChallengeSummary]:
    findings = list(seed_findings)
    expected: list[ChallengeArtifactRecord] = []
    forbidden: list[ChallengeArtifactRecord] = []
    total = len(spec.checks.expected_artifacts) + len(spec.checks.forbidden_artifacts) + len(spec.checks.forbidden_output)
    passed = 0
    for item in spec.checks.expected_artifacts:
        record = _artifact_record(workspace, item.path)
        expected.append(record)
        ok = record.exists
        if ok and item.contains is not None:
            text = (workspace / _safe_rel(item.path)).read_text(encoding="utf-8", errors="replace")
            ok = item.contains in text
        if ok and item.forbidden_contains:
            text = (workspace / _safe_rel(item.path)).read_text(encoding="utf-8", errors="replace")
            ok = not any(value in text for value in item.forbidden_contains)
        if ok:
            passed += 1
        else:
            findings.append(ChallengeFinding(code="expected_artifact_missing_or_invalid", reason="expected artifact was missing or failed content checks", artifact_path=item.path))
    for rel_path in spec.checks.forbidden_artifacts:
        try:
            record = _artifact_record(workspace, rel_path)
        except ValueError as exc:
            findings.append(ChallengeFinding(code="workspace_escape", reason=str(exc), artifact_path=rel_path))
            forbidden.append(ChallengeArtifactRecord(path=rel_path, exists=True))
            continue
        forbidden.append(record)
        if record.exists:
            findings.append(ChallengeFinding(code="forbidden_artifact_present", reason="forbidden artifact was present", artifact_path=rel_path))
        else:
            passed += 1
    output_preview = "\n".join([process.stdout_preview, process.stderr_preview])
    for forbidden_text in spec.checks.forbidden_output:
        if forbidden_text in output_preview:
            findings.append(ChallengeFinding(code="forbidden_output", reason="forbidden output marker was present"))
        else:
            passed += 1
    if process.return_code != 0 or process.timeout or process.process_tree_killed:
        findings.append(ChallengeFinding(code="process_supervision", reason="process fixture reported timeout, kill, or non-zero return code"))
    failed = len([finding for finding in findings if finding.status == "fail"])
    status: Literal["pass", "fail", "scaffold"] = "scaffold" if process.mode == REPORT_MODE_SCAFFOLD and failed == 0 else ("fail" if failed else "pass")
    score = 0.0 if total == 0 else round(passed / total, 4)
    return expected, forbidden, findings, ChallengeSummary(status=status, score=score, total_checks=total, passed_checks=passed, failed_checks=max(total - passed, failed))


def _agent_message(spec: ChallengeSpec, report_status: str, score: float, artifacts: list[ChallengeArtifactRecord], process: ChallengeProcessRecord, findings: list[ChallengeFinding]) -> AgentProtocolMessage:
    if spec.agent_protocol is not None:
        base = spec.agent_protocol.model_copy(deep=True)
        base.status = "passed" if report_status == "pass" else ("scaffold" if report_status == "scaffold" else "failed")
        base.score = score
        base.result = {**base.result, "challenge_id": spec.id, "findings": [finding.code for finding in findings]}
        return base
    stdout_log = AgentProtocolLog(stream="stdout", sha256=process.stdout_sha256, length=process.stdout_length, redacted_preview=process.stdout_preview)
    stderr_log = AgentProtocolLog(stream="stderr", sha256=process.stderr_sha256, length=process.stderr_length, redacted_preview=process.stderr_preview)
    return AgentProtocolMessage(
        task_id=spec.task_id,
        step_id=spec.step_id,
        status="passed" if report_status == "pass" else ("scaffold" if report_status == "scaffold" else "failed"),
        artifacts=[AgentProtocolArtifact(path=item.path, sha256=item.sha256, length=item.length, redacted_preview=item.redacted_preview) for item in artifacts if item.exists],
        logs=[stdout_log, stderr_log],
        result={"challenge_id": spec.id, "findings": [finding.code for finding in findings]},
        score=score,
    )


def _markdown(report: ChallengeReport) -> str:
    lines = [
        f"# Malleus Challenge Report: {_md_safe(report.challenge_id)}",
        "",
        f"- Task: {_md_safe(report.task_id)} / {_md_safe(report.step_id)}",
        f"- Mode: {_md_safe(report.mode)}",
        f"- Provider calls enabled: {str(report.provider_calls_enabled).lower()}",
        f"- Status: {_md_safe(report.summary.status)}",
        f"- Score: {report.summary.score}",
        f"- Workspace: {_md_safe(report.workspace_root)}",
        "",
        "## Findings",
        "",
    ]
    if not report.findings:
        lines.append("- none")
    for finding in report.findings:
        lines.append(f"- {_md_safe(finding.code)}: {_md_safe(finding.reason)}")
    lines.extend(["", "## Artifacts", "", "| Path | Exists | SHA-256 | Length | Preview |", "| --- | --- | --- | ---: | --- |"])
    for artifact in report.workspace_snapshot:
        lines.append(f"| {_md_safe(artifact.path)} | {artifact.exists} | {_md_safe(artifact.sha256 or 'n/a')} | {artifact.length or 0} | {_md_safe(artifact.redacted_preview or 'n/a')} |")
    return "\n".join(lines).rstrip() + "\n"


def _diff_artifact(report: ChallengeReport) -> dict[str, Any]:
    return {
        "schema_version": "malleus.challenge_diff.v1",
        "run_id": report.run_id,
        "challenge_id": report.challenge_id,
        "status": report.summary.status,
        "expected": [item.model_dump(mode="json") for item in report.expected_artifacts],
        "forbidden": [item.model_dump(mode="json") for item in report.forbidden_artifacts],
        "findings": [item.model_dump(mode="json") for item in report.findings],
    }


def _findings_artifact(report: ChallengeReport) -> dict[str, Any]:
    return {
        "schema_version": "malleus.challenge_findings.v1",
        "run_id": report.run_id,
        "challenge_id": report.challenge_id,
        "findings": [item.model_dump(mode="json") for item in report.findings],
    }


def write_challenge_artifacts(report: ChallengeReport, output_dir: str | Path) -> dict[str, Path]:
    destination = Path(output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    paths = {
        "report": destination / "challenge-report.json",
        "markdown": destination / "challenge-report.md",
        "diff": destination / "challenge-diff.json",
        "findings": destination / "challenge-findings.json",
        "agent_protocol": destination / "agent-protocol.json",
    }
    paths["report"].write_text(report.model_dump_json(indent=2), encoding="utf-8")
    paths["markdown"].write_text(_markdown(report), encoding="utf-8")
    paths["diff"].write_text(json.dumps(_diff_artifact(report), indent=2), encoding="utf-8")
    paths["findings"].write_text(json.dumps(_findings_artifact(report), indent=2), encoding="utf-8")
    export_agent_protocol(report.agent_protocol, paths["agent_protocol"])
    return paths


def run_challenge(challenge_path: str | Path, output_dir: str | Path, *, dry_run: bool = False) -> ChallengeReport:
    started = _now()
    spec = load_challenge(challenge_path)
    destination = Path(output_dir).resolve()
    workspace = destination / _safe_rel(spec.workspace)
    if workspace.exists():
        shutil.rmtree(workspace)
    workspace.mkdir(parents=True, exist_ok=True)
    artifacts_in = _write_workspace_inputs(spec, workspace)
    if dry_run:
        process = _process_record(ChallengeProcessSpec(mode="scaffold", stdout="dry-run scaffold; no fixture process executed"), stdout="dry-run scaffold; no fixture process executed", stderr="", return_code=0, scaffold=True)
        written: list[str] = []
        process_findings: list[ChallengeFinding] = []
        expected = [_artifact_record(workspace, item.path) for item in spec.checks.expected_artifacts]
        forbidden = [ChallengeArtifactRecord(path=item, exists=False) for item in spec.checks.forbidden_artifacts]
        findings: list[ChallengeFinding] = []
        summary = ChallengeSummary(status="scaffold", score=0.0, total_checks=len(spec.checks.expected_artifacts) + len(spec.checks.forbidden_artifacts) + len(spec.checks.forbidden_output), passed_checks=0, failed_checks=0)
    else:
        process, written, process_findings = _safe_fixture_process(spec, workspace)
        expected, forbidden, findings, summary = _evaluate_checks(spec, workspace, process, process_findings)
    snapshot = _snapshot(workspace)
    artifacts_out = [_artifact_record(workspace, rel_path) for rel_path in written]
    agent = _agent_message(spec, summary.status, summary.score, snapshot, process, findings)
    report = ChallengeReport(
        run_id=new_run_id(),
        started_at=started,
        finished_at=_now(),
        challenge_id=spec.id,
        task_id=spec.task_id,
        step_id=spec.step_id,
        title=spec.title,
        mode=process.mode,
        workspace_root=_display_path(workspace),
        challenge_path=_display_path(challenge_path),
        artifacts_in=artifacts_in,
        artifacts_out=artifacts_out,
        expected_artifacts=expected,
        forbidden_artifacts=forbidden,
        findings=findings,
        process=process,
        workspace_snapshot=snapshot,
        agent_protocol=agent,
        summary=summary,
        wowpp_metadata=WowppReportMetadata(mode=process.mode, provider_calls_enabled=False, artifact_hashes={item.path: item.sha256 or "" for item in snapshot}, redaction=RedactionMetadata(status="redacted", marker=_REDACTED), metadata={"agent_protocol_schema": AGENT_PROTOCOL_SCHEMA_VERSION}),
    )
    write_challenge_artifacts(report, destination)
    return report


__all__ = [
    "AgentProtocolMessage",
    "ChallengeReport",
    "ChallengeSpec",
    "export_agent_protocol",
    "import_agent_protocol",
    "load_challenge",
    "run_challenge",
    "write_challenge_artifacts",
]
