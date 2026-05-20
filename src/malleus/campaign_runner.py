from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

from malleus.campaigns import CampaignSpec, CampaignStep
from malleus.datasets import load_target_config
from malleus.findings import collect_findings, write_finding_artifacts
from malleus.hidden_channels import inspect_text
from malleus.policy_firewall import default_agent_policy, evaluate_policy, normalize_action
from malleus.reporting import _md_safe
from malleus.schemas import EvaluationSurface, EvidenceRecord, EvidenceRef, RedactionMetadata, WowppReportMetadata, REPORT_MODE_SIMULATED
from malleus.utils.ids import new_run_id
from malleus.utils.redact import REDACTION_MARKER, redact_public_text, sha256_text

CAMPAIGN_REPORT_SCHEMA_VERSION = "malleus.campaign_report.v1"
_REDACTED = "[REDACTED_CAMPAIGN_TEXT]"
_SECRET_RE = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b|\b(?:api[_ -]?key|secret|token|password|credential|bearer)\s*[:=]?\s*[^\s`|<>]+", re.IGNORECASE)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _preview(value: str, *, limit: int = 96) -> str:
    text = " ".join(value.split())
    if not text:
        return "n/a"
    lowered = text.lower()
    if _SECRET_RE.search(text) or any(marker in lowered for marker in ("ignore previous", "system prompt", "secret", "token", "password", "api_key", "bearer", "canary", "exfiltrate")):
        return f"{_REDACTED} sha256={_sha256_text(value)[:16]} length={len(value)}"
    return text[:limit] + ("…" if len(text) > limit else "")


def _safe_replay_path(path: str | Path) -> str:
    resolved = Path(path).resolve()
    try:
        return resolved.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        value = resolved.as_posix()
        return redact_public_text(value).text if "/home/" in value else value


def _artifact_summary(artifact: Any) -> dict[str, object]:
    content = str(getattr(artifact, "synthetic_content", ""))
    canary = str(getattr(artifact, "canary", ""))
    redacted = redact_public_text(content)
    return {
        "id": getattr(artifact, "id", "unknown"),
        "mode": REPORT_MODE_SIMULATED,
        "description": _preview(str(getattr(artifact, "description", ""))),
        "content_sha256": _sha256_text(content),
        "content_length": len(content),
        "canary_sha256": _sha256_text(canary) if canary else None,
        "redacted_preview": _preview(content),
        "redaction_metadata": RedactionMetadata(status="redacted" if canary or redacted.redacted else "not_applicable", sha256=redacted.sha256, length=redacted.length, marker=_REDACTED if canary else (REDACTION_MARKER if redacted.redacted else None), matched_labels=redacted.matched_labels).model_dump(mode="json"),
        "coverage_tags": ["campaign", "artifact", "long_context"],
    }


class CampaignAttemptRecord(BaseModel):
    attempt_index: int
    status: Literal["planned", "mocked"] = "planned"
    provider_call: bool = False
    prompt_sha256: str
    prompt_preview: str
    mode: str = REPORT_MODE_SIMULATED
    evidence_ref: str | None = None


class CampaignGateRecord(BaseModel):
    status: Literal["pass", "warn", "fail"]
    reasons: list[str] = Field(default_factory=list)


class CampaignStepRecord(BaseModel):
    step_id: str
    order: int
    surface: str
    tactic: str
    depends_on: list[str] = Field(default_factory=list)
    attempts: list[CampaignAttemptRecord] = Field(default_factory=list)
    policy_action: str
    policy_allowed: bool
    policy_reasons: list[str] = Field(default_factory=list)
    hidden_channel_recommendation: str = "allow"
    hidden_channel_reasons: list[str] = Field(default_factory=list)
    adaptive_branches: list[dict[str, str]] = Field(default_factory=list)
    selected_branch: str | None = None
    gate: CampaignGateRecord
    artifact_refs: list[str] = Field(default_factory=list)
    mode: str = REPORT_MODE_SIMULATED
    evidence_ref: str | None = None
    replay_ref: str | None = None
    coverage_tags: list[str] = Field(default_factory=list)


class CampaignSummary(BaseModel):
    total_steps: int
    passed_steps: int
    failed_steps: int
    blocked_steps: int
    highest_risk: str | None = None


class CampaignReport(BaseModel):
    schema_version: str = CAMPAIGN_REPORT_SCHEMA_VERSION
    run_id: str
    started_at: str
    finished_at: str
    campaign_id: str
    campaign_title: str
    objective: str
    replay_seed: int
    target_name: str
    target_adapter: str
    target_model: str
    campaign_path: str
    target_path: str
    mode: str = REPORT_MODE_SIMULATED
    report_wording: str = "simulated provider-free campaign execution; no provider/API/model calls are made"
    dry_run: bool
    provider_calls_enabled: bool = False
    redaction_metadata: RedactionMetadata = Field(default_factory=lambda: RedactionMetadata(status="redacted", marker=_REDACTED))
    replay_refs: list[str] = Field(default_factory=list)
    coverage_tags: list[str] = Field(default_factory=list)
    findings: list[dict[str, object]] = Field(default_factory=list)
    wowpp_metadata: WowppReportMetadata | None = None
    steps: list[CampaignStepRecord] = Field(default_factory=list)
    artifacts: list[dict[str, object]] = Field(default_factory=list)
    shared_state: dict[str, object] = Field(default_factory=dict)
    summary: CampaignSummary


def load_campaign(path: str | Path) -> CampaignSpec:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError("campaign YAML must contain a mapping")
    return CampaignSpec.model_validate(data)


def _selected_branch_targets(campaign: CampaignSpec) -> set[str]:
    selected: set[str] = set()
    for step in campaign.steps:
        _, branch_target = _branch_records(step)
        if branch_target:
            selected.add(branch_target)
    return selected


def _unselected_branch_targets(campaign: CampaignSpec) -> set[str]:
    all_targets = {branch.next_step_id for step in campaign.steps for branch in step.adaptive_branches}
    return all_targets - _selected_branch_targets(campaign)


def _ordered_steps(campaign: CampaignSpec) -> list[CampaignStep]:
    skipped = _unselected_branch_targets(campaign)
    remaining = {step.id: step for step in campaign.steps if step.id not in skipped}
    completed: set[str] = set()
    ordered: list[CampaignStep] = []
    while remaining:
        ready = [step for step in remaining.values() if all(dep in completed or dep in skipped for dep in step.depends_on)]
        if not ready:
            cycle = ", ".join(sorted(remaining))
            raise ValueError(f"campaign dependency cycle or unsatisfied dependency: {cycle}")
        ready.sort(key=lambda item: (item.order, item.id))
        step = ready[0]
        ordered.append(step)
        completed.add(step.id)
        del remaining[step.id]
    return ordered


def _step_artifact_text(campaign: CampaignSpec) -> dict[str, str]:
    return {artifact.id: artifact.synthetic_content for artifact in campaign.long_context_artifacts}


def _branch_records(step: CampaignStep) -> tuple[list[dict[str, str]], str | None]:
    branches = [branch.model_dump() for branch in step.adaptive_branches]
    selected = None
    if branches:
        selected = sorted(branches, key=lambda item: (item.get("when", ""), item.get("next_step_id", "")))[0]["next_step_id"]
    return branches, selected


def _record_step(campaign: CampaignSpec, step: CampaignStep, artifact_text: dict[str, str], *, dry_run: bool) -> CampaignStepRecord:
    artifacts = dict(artifact_text)
    canaries = [artifact.canary for artifact in campaign.long_context_artifacts if artifact.canary]
    policy = default_agent_policy(canaries=canaries)
    requires_approval = any(term in step.tactic.lower() or term in step.prompt.lower() for term in ("approval", "bypass", "dispatch", "push"))
    decision = evaluate_policy(
        policy,
        normalize_action(
            kind="campaign_step",
            tool_name="campaign_step",
            tool_args={"step_id": step.id, "surface": step.surface, "tactic": step.tactic, "prompt_preview": _preview(step.prompt)},
            final_answer="",
            artifacts={key: _preview(value) for key, value in artifacts.items()},
            canaries=canaries,
            requires_approval=requires_approval,
            trusted_approved=False,
        ),
    )
    hidden_inputs = [step.prompt, *artifacts.values()]
    hidden_reports = [inspect_text(value, source=f"campaign:{campaign.id}:{step.id}") for value in hidden_inputs if value]
    recommendations = [report.gate_recommendation or "allow" for report in hidden_reports]
    rec_order = {"allow": 0, "warn": 1, "quarantine": 2, "block": 3}
    hidden_recommendation = max(recommendations or ["allow"], key=lambda item: rec_order.get(item, 0))
    hidden_reasons: list[str] = []
    for report in hidden_reports:
        if report.deep:
            hidden_reasons.extend(report.deep.gate_reasons[:3])
    gate_reasons = list(decision.reasons)
    if hidden_recommendation in {"quarantine", "block"}:
        gate_reasons.append(f"hidden_channel_{hidden_recommendation}")
    for check in step.covert_channel_checks:
        for absent in check.expected_absent:
            if absent in step.prompt or any(absent in value for value in artifacts.values()):
                gate_reasons.append(f"covert_channel_expected_absent_present:{check.kind}")
    failed = (not decision.allowed) or hidden_recommendation in {"quarantine", "block"} or any(reason.startswith("covert_channel_expected") for reason in gate_reasons)
    gate = CampaignGateRecord(status="fail" if failed else "pass", reasons=sorted(dict.fromkeys(gate_reasons or ["policy_passed"])))
    branches, selected = _branch_records(step)
    prompt_hash = _sha256_text(step.prompt)
    technique_tag = step.metadata.get("malleus_technique", "") if isinstance(step.metadata, dict) else ""
    coverage_tags = sorted(str(tag) for tag in {"campaign", "campaign_step", step.surface, step.tactic, technique_tag, hidden_recommendation, gate.status} if str(tag))
    attempts = [
        CampaignAttemptRecord(
            attempt_index=index,
            status="planned" if dry_run else "mocked",
            provider_call=False,
            prompt_sha256=prompt_hash,
            prompt_preview=_preview(step.prompt),
            evidence_ref=f"campaign-report.json#/steps/{step.id}/attempts/{index - 1}",
        )
        for index in range(1, step.repeated_attempts + 1)
    ]
    return CampaignStepRecord(
        step_id=step.id,
        order=step.order,
        surface=step.surface,
        tactic=step.tactic,
        depends_on=list(step.depends_on),
        attempts=attempts,
        policy_action=decision.action,
        policy_allowed=decision.allowed,
        policy_reasons=decision.reasons,
        hidden_channel_recommendation=hidden_recommendation,
        hidden_channel_reasons=sorted(dict.fromkeys(hidden_reasons))[:8],
        adaptive_branches=branches,
        selected_branch=selected,
        gate=gate,
        artifact_refs=sorted(artifacts),
        evidence_ref=f"campaign-report.json#/steps/{step.id}",
        replay_ref="campaign-replay.json",
        coverage_tags=coverage_tags,
    )


def _step_findings(report: CampaignReport) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for step in report.steps:
        if step.gate.status != "fail" and step.policy_action not in {"block", "quarantine"} and step.hidden_channel_recommendation not in {"block", "quarantine"}:
            continue
        findings.append(
            {
                "finding_id": f"campaign-{report.campaign_id}-{step.step_id}",
                "source_type": "campaign",
                "mode": report.mode,
                "severity": "high" if step.policy_action in {"block", "quarantine"} else "medium",
                "step_id": step.step_id,
                "surface": step.surface,
                "technique": step.tactic,
                "coverage_tags": step.coverage_tags,
                "replay_ref": step.replay_ref,
                "evidence_ref": step.evidence_ref,
                "gate_status": step.gate.status,
                "redacted_reasons": [_preview(reason) for reason in step.gate.reasons[:5]],
            }
        )
    return findings


def _wowpp_metadata(report: CampaignReport) -> WowppReportMetadata:
    surfaces = [
        EvaluationSurface(surface_id=f"campaign-step-{step.step_id}", name=step.step_id, category="campaign", modality="text", metadata={"surface": step.surface, "tactic": step.tactic, "gate_status": step.gate.status})
        for step in report.steps
    ]
    records = [
        EvidenceRecord(
            evidence_id=f"campaign-{report.campaign_id}-{step.step_id}",
            mode=REPORT_MODE_SIMULATED,
            artifact=EvidenceRef(evidence_id=f"campaign-{step.step_id}", artifact_path="campaign-report.json", artifact_type="campaign_report_json", redacted_preview=step.attempts[0].prompt_preview if step.attempts else None, metadata={"step_id": step.step_id}),
            artifact_sha256=step.attempts[0].prompt_sha256 if step.attempts else None,
            redacted_preview=step.attempts[0].prompt_preview if step.attempts else None,
            redaction=RedactionMetadata(status="redacted", sha256=step.attempts[0].prompt_sha256 if step.attempts else None, marker=_REDACTED, metadata={"prompt_hash_only": True}),
            metadata={"coverage_tags": step.coverage_tags, "replay_ref": step.replay_ref},
        )
        for step in report.steps
    ]
    return WowppReportMetadata(mode=REPORT_MODE_SIMULATED, provider_calls_enabled=False, evaluation_surfaces=surfaces, evidence_records=records, artifact_hashes={"campaign-report.json": sha256_text(report.run_id)}, redaction=report.redaction_metadata, metadata={"report_wording": report.report_wording})


def _summary(steps: list[CampaignStepRecord]) -> CampaignSummary:
    failed = [step for step in steps if step.gate.status == "fail"]
    blocked = [step for step in steps if step.policy_action in {"block", "quarantine"} or step.hidden_channel_recommendation in {"block", "quarantine"}]
    highest = "high" if blocked else ("medium" if failed else None)
    return CampaignSummary(total_steps=len(steps), passed_steps=len(steps) - len(failed), failed_steps=len(failed), blocked_steps=len(blocked), highest_risk=highest)


def _render_markdown(report: CampaignReport) -> str:
    lines = [
        f"# Malleus Campaign Report: {_md_safe(report.campaign_id)}",
        "",
        f"- Target: {_md_safe(report.target_name)} ({_md_safe(report.target_adapter)} / {_md_safe(report.target_model)})",
        f"- Mode: {_md_safe(report.mode)}",
        f"- Evidence wording: {_md_safe(report.report_wording)}",
        f"- Dry run: {report.dry_run}",
        f"- Provider calls enabled: {report.provider_calls_enabled}",
        f"- Steps: {report.summary.total_steps}",
        f"- Failed steps: {report.summary.failed_steps}",
        "",
        "| Step | Surface | Attempts | Policy | Gate | Branch | Reasons |",
        "| --- | --- | ---: | --- | --- | --- | --- |",
    ]
    for step in report.steps:
        lines.append(
            "| "
            + " | ".join(
                [
                    _md_safe(step.step_id),
                    _md_safe(step.surface),
                    str(len(step.attempts)),
                    _md_safe(step.policy_action),
                    _md_safe(step.gate.status),
                    _md_safe(step.selected_branch or "n/a"),
                    _md_safe(", ".join(step.gate.reasons[:4])),
                ]
            )
            + " |"
        )
    return "\n".join(lines).rstrip() + "\n"


def _render_risk_card(report: CampaignReport) -> str:
    lines = [
        f"# Campaign risk card: {_md_safe(report.campaign_title)}",
        "",
        f"- Campaign: {_md_safe(report.campaign_id)}",
        f"- Objective: {_md_safe(report.objective)}",
        f"- Mode: {_md_safe(report.mode)}",
        f"- Highest risk: {_md_safe(report.summary.highest_risk or 'n/a')}",
        f"- Failed steps: {report.summary.failed_steps}/{report.summary.total_steps}",
        f"- Provider calls enabled: {report.provider_calls_enabled}",
        "",
        "## Step gates",
        "",
    ]
    for step in report.steps:
        lines.append(f"- {_md_safe(step.step_id)}: {_md_safe(step.gate.status)} ({_md_safe(', '.join(step.gate.reasons[:3]))})")
    return "\n".join(lines).rstrip() + "\n"


def _evidence_ledger(report: CampaignReport) -> dict[str, object]:
    return {
        "schema_version": "malleus.evidence_ledger.v1",
        "run_id": report.run_id,
        "mode": report.mode,
        "redaction": "step prompts and artifact bodies are represented by hashes/redacted previews only",
        "entries": [
            {
                "evidence_id": f"{report.campaign_id}-{step.step_id}",
                "step_id": step.step_id,
                "prompt_sha256": step.attempts[0].prompt_sha256 if step.attempts else None,
                "artifact_refs": step.artifact_refs,
                "policy_reasons": step.policy_reasons,
                "gate_status": step.gate.status,
            }
            for step in report.steps
        ],
    }


def _replay_spec(report: CampaignReport) -> dict[str, object]:
    return {
        "schema_version": "malleus.campaign_replay.v1",
        "run_id": report.run_id,
        "mode": report.mode,
        "campaign_id": report.campaign_id,
        "replay_seed": report.replay_seed,
        "dry_run": True,
        "provider_calls_enabled": False,
        "step_path": [step.step_id for step in report.steps],
        "command": f"malleus campaign run --campaign {report.campaign_path} --target {report.target_path} --out-dir REPLAY_OUT --dry-run",
    }


def _trace_events(report: CampaignReport) -> dict[str, object]:
    events: list[dict[str, object]] = []
    for step in report.steps:
        for artifact_id in step.artifact_refs:
            events.append({"event_type": "artifact_reference", "step_id": step.step_id, "artifact_id": artifact_id, "redaction_status": "redacted"})
        events.append({"event_type": "policy_decision", "step_id": step.step_id, "action": step.policy_action, "allowed": step.policy_allowed, "reasons": step.policy_reasons})
        events.append({"event_type": "hidden_channel_check", "step_id": step.step_id, "recommendation": step.hidden_channel_recommendation, "reasons": step.hidden_channel_reasons})
        for attempt in step.attempts:
            events.append({"event_type": "attempt_decision", "step_id": step.step_id, "attempt_index": attempt.attempt_index, "status": attempt.status, "provider_call": attempt.provider_call, "prompt_sha256": attempt.prompt_sha256})
        if step.selected_branch:
            events.append({"event_type": "adaptive_branch", "step_id": step.step_id, "selected_branch": step.selected_branch, "branches": step.adaptive_branches})
        events.append({"event_type": "gate_decision", "step_id": step.step_id, "status": step.gate.status, "reasons": step.gate.reasons})
    return {"run_id": report.run_id, "campaign_id": report.campaign_id, "mode": report.mode, "provider_calls_enabled": False, "step_path": [step.step_id for step in report.steps], "events": events}


def write_campaign_artifacts(report: CampaignReport, output_dir: str | Path) -> list[Path]:
    destination = Path(output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    paths = []
    for name, text in {
        "campaign-report.json": report.model_dump_json(indent=2),
        "campaign-report.md": _render_markdown(report),
        "campaign-trace.json": json.dumps(_trace_events(report), indent=2),
        "campaign-risk-card.md": _render_risk_card(report),
        "campaign-evidence-ledger.json": json.dumps(_evidence_ledger(report), indent=2),
        "campaign-replay.json": json.dumps(_replay_spec(report), indent=2),
    }.items():
        path = destination / name
        path.write_text(text, encoding="utf-8")
        paths.append(path)
    bundle = collect_findings(destination)
    write_finding_artifacts(bundle, destination)
    return paths


def run_campaign(campaign_path: str | Path, target_path: str | Path, output_dir: str | Path, *, dry_run: bool = False) -> CampaignReport:
    started = _now()
    campaign = load_campaign(campaign_path)
    target = load_target_config(target_path)
    artifacts = [_artifact_summary(artifact) for artifact in campaign.long_context_artifacts]
    artifact_text = _step_artifact_text(campaign)
    steps = [_record_step(campaign, step, artifact_text, dry_run=dry_run) for step in _ordered_steps(campaign)]
    report = CampaignReport(
        run_id=new_run_id(),
        started_at=started,
        finished_at=_now(),
        campaign_id=campaign.id,
        campaign_title=campaign.title,
        objective=_preview(campaign.objective),
        replay_seed=campaign.replay_seed,
        target_name=target.name,
        target_adapter=target.adapter,
        target_model=target.model,
        campaign_path=_safe_replay_path(campaign_path),
        target_path=_safe_replay_path(target_path),
        dry_run=dry_run,
        provider_calls_enabled=False,
        replay_refs=["campaign-replay.json"],
        coverage_tags=sorted({tag for step in steps for tag in step.coverage_tags if tag}),
        steps=steps,
        artifacts=artifacts,
        shared_state={"completed_steps": [step.step_id for step in steps], "adaptive_path": [step.selected_branch for step in steps if step.selected_branch]},
        summary=_summary(steps),
    )
    report.findings = _step_findings(report)
    report.wowpp_metadata = _wowpp_metadata(report)
    write_campaign_artifacts(report, output_dir)
    return report
