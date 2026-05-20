from __future__ import annotations

import json
import re
from html import escape
from pathlib import Path
from typing import Any

from malleus.ir import ReportManifest
from malleus.registry import reporter_registry
from malleus.schemas import RunReport
from malleus.utils.redact import redact_public_text

_RISK_CARD_SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_SECRET_PATTERNS = (
    re.compile(r"(?<!SYNTHETIC-)(?<!FAKE-)\bsk-[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\b(?:api[_-]?key|secret|token)\s*=\s*[^\s`|<>]+", re.IGNORECASE),
    re.compile(r"\bMALLEUS-CANARY-[A-Za-z0-9_-]+\b", re.IGNORECASE),
    re.compile(r"\bcanary\s*[:=]\s*[^\s`|<>]+", re.IGNORECASE),
)


def _redact_display(value: object, *, limit: int | None = None) -> str:
    text = redact_public_text(str(value)).text
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    if limit is not None:
        text = text[:limit]
    return text


def _md_safe(value: object) -> str:
    text = _redact_display(value)
    text = text.replace("&", "&amp;").replace("<", "&lt;")
    return text.replace("\r", " ").replace("\n", " ").replace("|", r"\|").replace("`", r"\`").replace("#", r"\#")


def _md_fence(value: object, *, limit: int | None = None) -> list[str]:
    text = _redact_display(value, limit=limit).replace("&", "&amp;").replace("<", "&lt;")
    longest = max((len(match.group(0)) for match in re.finditer(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return [f"{fence}text", text, fence]


def _html_safe(value: object, *, limit: int | None = None) -> str:
    return escape(_redact_display(value, limit=limit))


def _write_json_report(report: RunReport, output_dir: str | Path) -> Path:
    destination = Path(output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    report_path = destination / "report.json"
    report_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return report_path


def write_json_report(report: RunReport, output_dir: str | Path) -> Path:
    return reporter_registry.get("json")(report, output_dir)


def render_markdown_report(report: RunReport) -> str:
    lines = [
        f"# Malleus Report: {_md_safe(report.run_id)}",
        "",
        f"- Target: {_md_safe(report.target_name)} ({_md_safe(report.target_adapter)} / {_md_safe(report.target_model)})",
        f"- Started: {_md_safe(report.started_at)}",
        f"- Finished: {_md_safe(report.finished_at)}",
        f"- Score: {report.summary.score_total}/{report.summary.max_score_total}",
        f"- Passed: {report.summary.passed_items}/{report.summary.total_items}",
        "",
        "## Datasets",
        "",
    ]
    for dataset in report.datasets:
        lines.extend(
            [
                f"### {_md_safe(dataset.dataset_name)}",
                "",
                f"- Category: {_md_safe(dataset.category)}/{_md_safe(dataset.subcategory)}",
                f"- Source: {_md_safe(dataset.source_path or 'n/a')}",
                f"- Score: {dataset.summary.score_total}/{dataset.summary.max_score_total}",
                f"- Passed: {dataset.summary.passed_items}/{dataset.summary.total_items}",
                "",
            ]
        )
        for case in dataset.case_results:
            lines.extend(
                [
                    f"#### Case {_md_safe(case.case_id)}: {'PASS' if case.passed else 'FAIL'} ({case.score})",
                    "",
                    f"- Severity: {_md_safe(case.severity)}",
                    f"- Objective: {_md_safe(case.objective)}",
                    f"- Penalty: {case.penalty}",
                    f"- Latency: {case.latency_seconds if case.latency_seconds is not None else 'n/a'}",
                    "- Failure checks:",
                ]
            )
            if case.warnings:
                lines.append("- Warnings:")
                for warning in case.warnings:
                    lines.append(f"  - {_md_safe(warning)}")
            for check in case.failure_checks:
                lines.append(f"  - {'OK' if check.passed else 'FAIL'} {_md_safe(check.type)}: {_md_safe(check.detail)}")
            lines.append("- Pass checks:")
            for check in case.pass_checks:
                lines.append(f"  - {'OK' if check.passed else 'FAIL'} {_md_safe(check.type)}: {_md_safe(check.detail)}")
            lines.extend(["", "Response excerpt:", "", *_md_fence(case.response_text, limit=1200), ""])
        for group in dataset.group_results:
            lines.extend(
                [
                    f"#### Group {_md_safe(group.group_id)}: {'PASS' if group.passed else 'FAIL'} ({group.score})",
                    "",
                    f"- Severity: {_md_safe(group.severity)}",
                    f"- Objective: {_md_safe(group.objective)}",
                    f"- Penalty: {group.penalty}",
                    f"- Warnings: {_md_safe(', '.join(group.warnings) if group.warnings else 'none')}",
                    "- Variants:",
                ]
            )
            for index, variant in enumerate(group.variants, start=1):
                lines.append(
                    f"  - {index}: refusal_detected={variant.refusal_detected}, latency={_md_safe(variant.latency_seconds if variant.latency_seconds is not None else 'n/a')}"
                )
            lines.append("")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _write_markdown_report(report: RunReport, output_dir: str | Path) -> Path:
    destination = Path(output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    report_path = destination / "report.md"
    report_path.write_text(render_markdown_report(report), encoding="utf-8")
    return report_path


def write_markdown_report(report: RunReport, output_dir: str | Path) -> Path:
    return reporter_registry.get("markdown")(report, output_dir)


def render_html_report(report: RunReport) -> str:
    rows: list[str] = []
    for dataset in report.datasets:
        for case in dataset.case_results:
            status = "pass" if case.passed else "fail"
            latency_cell = f"<td>{case.latency_seconds:.3f}s</td>" if case.latency_seconds is not None else "<td>n/a</td>"
            rows.append(
                "<tr>"
                f"<td>{_html_safe(dataset.dataset_name)}</td>"
                f"<td>{_html_safe(case.case_id)}</td>"
                f"<td class='{status}'>{status.upper()}</td>"
                f"<td>{case.score}</td>"
                f"<td>{_html_safe(case.severity)}</td>"
                f"{latency_cell}"
                f"<td><pre>{_html_safe(case.response_text, limit=600)}</pre></td>"
                "</tr>"
            )
        for group in dataset.group_results:
            status = "pass" if group.passed else "fail"
            rows.append(
                "<tr>"
                f"<td>{_html_safe(dataset.dataset_name)}</td>"
                f"<td>{_html_safe(group.group_id)}</td>"
                f"<td class='{status}'>{status.upper()}</td>"
                f"<td>{group.score}</td>"
                f"<td>{_html_safe(group.severity)}</td>"
                "<td>group</td>"
                f"<td><pre>{_html_safe(str([variant.refusal_detected for variant in group.variants]))}</pre></td>"
                "</tr>"
            )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Malleus Report {_html_safe(report.run_id)}</title>
<style>
body {{ font-family: Inter, ui-sans-serif, system-ui, sans-serif; margin: 2rem; background: #0b1020; color: #e5e7eb; }}
.card {{ background: #111827; border: 1px solid #374151; border-radius: 12px; padding: 1rem; margin-bottom: 1rem; }}
table {{ border-collapse: collapse; width: 100%; background: #111827; }}
th, td {{ border: 1px solid #374151; padding: .6rem; vertical-align: top; }}
th {{ background: #1f2937; }}
.pass {{ color: #22c55e; font-weight: 700; }}
.fail {{ color: #ef4444; font-weight: 700; }}
pre {{ white-space: pre-wrap; max-width: 48rem; }}
</style>
</head>
<body>
<h1>Malleus Report</h1>
<div class="card">
<p><strong>Run:</strong> {_html_safe(report.run_id)}</p>
<p><strong>Target:</strong> {_html_safe(report.target_name)} / {_html_safe(report.target_model)}</p>
<p><strong>Score:</strong> {report.summary.score_total}/{report.summary.max_score_total}</p>
<p><strong>Passed:</strong> {report.summary.passed_items}/{report.summary.total_items}</p>
</div>
<table>
<thead><tr><th>Dataset</th><th>Item</th><th>Status</th><th>Score</th><th>Severity</th><th>Latency</th><th>Excerpt</th></tr></thead>
<tbody>{''.join(rows)}</tbody>
</table>
</body>
</html>
"""


def _write_html_report(report: RunReport, output_dir: str | Path) -> Path:
    destination = Path(output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    report_path = destination / "report.html"
    report_path.write_text(render_html_report(report), encoding="utf-8")
    return report_path


def write_html_report(report: RunReport, output_dir: str | Path) -> Path:
    return reporter_registry.get("html")(report, output_dir)


def _artifact_link(destination: Path, name: str) -> str:
    return f"- [{name}]({name})" if (destination / name).exists() else f"- {name}: not present"


def _load_json_artifact(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _as_list(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def _campaign_detail_lines(report: RunReport) -> list[str]:
    lines: list[str] = []
    for dataset in report.datasets:
        if dataset.category != "defensive-campaign":
            continue
        lines.append(f"- {_md_safe(dataset.dataset_name)}: {dataset.summary.total_items} campaign items")
        campaign_cases = sorted(dataset.case_results, key=lambda case: (case.metadata.get("order", 0), case.case_id))
        if not campaign_cases:
            continue
        replay_seeds = sorted({str(case.metadata.get("replay_seed")) for case in campaign_cases if case.metadata.get("replay_seed") is not None})
        if replay_seeds:
            lines.append(f"  - Replay seed: {_md_safe(', '.join(replay_seeds))}")
        kill_chain = []
        failed_steps = []
        tactics: dict[str, int] = {}
        for case in campaign_cases:
            metadata = case.metadata
            step_id = str(metadata.get("step_id") or case.case_id)
            order = metadata.get("order", "?")
            tactic = str(metadata.get("tactic") or "unspecified")
            tactics[tactic] = tactics.get(tactic, 0) + 1
            dependencies = ",".join(str(item) for item in _as_list(metadata.get("depends_on"))) or "root"
            kill_chain.append(f"{order}:{step_id}({dependencies})")
            if not case.passed or case.penalty:
                failed_steps.append(f"{order}:{step_id} penalty={case.penalty}")
            for branch in _as_list(metadata.get("adaptive_branches")):
                if isinstance(branch, dict):
                    lines.append(
                        "  - Adapted branch: "
                        f"{_md_safe(step_id)} when={_md_safe(branch.get('when', 'n/a'))} "
                        f"next={_md_safe(branch.get('next_step_id', 'n/a'))}"
                    )
            checks = _as_list(metadata.get("covert_channel_checks"))
            if checks:
                kinds = [str(check.get("kind", "unknown")) for check in checks if isinstance(check, dict)]
                lines.append(f"  - Covert-channel checks: {_md_safe(', '.join(kinds) or 'present')}")
            attempts = metadata.get("repeated_attempts")
            if isinstance(attempts, int) and attempts > 1:
                lines.append(f"  - Repeated attempts: {_md_safe(step_id)} x{attempts}")
        lines.append(f"  - Kill-chain order: {_md_safe(' -> '.join(kill_chain))}")
        lines.append(f"  - Tactic coverage: {_md_safe(', '.join(f'{name}={count}' for name, count in sorted(tactics.items())))}")
        lines.append(f"  - Failed step: {_md_safe('; '.join(failed_steps) if failed_steps else 'none')}")
    return lines


def _agent_detail_lines(destination: Path) -> list[str]:
    report = _load_json_artifact(destination / "agent-lab-report.json")
    if report is None:
        return []
    summary = report.get("summary", {}) if isinstance(report.get("summary"), dict) else {}
    lines = [
        f"- Agent report: scenarios={_md_safe(summary.get('total_scenarios', 0))}, violations={_md_safe(summary.get('violations', 0))}, highest_risk={_md_safe(summary.get('highest_risk') or 'n/a')}",
    ]
    for result in _as_list(report.get("results")):
        if not isinstance(result, dict):
            continue
        trace = result.get("trace") if isinstance(result.get("trace"), dict) else {}
        scenario_id = str(result.get("scenario_id") or "unknown")
        approval = trace.get("approval_state") if isinstance(trace.get("approval_state"), dict) else {}
        if approval:
            lines.append(
                f"  - Approval timeline: {_md_safe(scenario_id)} required={_md_safe(approval.get('required', False))} "
                f"granted={_md_safe(approval.get('granted', False))} source={_md_safe(approval.get('source', 'n/a'))}"
            )
        decisions = _as_list(trace.get("observed_tool_decisions"))
        for decision in decisions:
            if isinstance(decision, dict):
                lines.append(
                    f"  - Tool audit: {_md_safe(scenario_id)} tool={_md_safe(decision.get('tool') or 'n/a')} "
                    f"allowed={_md_safe(decision.get('allowed_by_policy', False))} reason={_md_safe(decision.get('reason', 'n/a'))}"
                )
        memory_items = _as_list(trace.get("memory_writes")) + _as_list(trace.get("session_writes"))
        canaries = _as_list(trace.get("canary_violations"))
        if memory_items or canaries:
            lines.append(
                f"  - Memory/canary ledger: {_md_safe(scenario_id)} "
                f"writes={len(memory_items)} violations={_md_safe(', '.join(str(item) for item in canaries) or 'none')}"
            )
    return lines


def _adjudication_detail_lines(destination: Path) -> list[str]:
    data = _load_json_artifact(destination / "adjudications.json")
    if data is None:
        return ["- No adjudication artifact found."]
    summary = data.get("summary", {}) if isinstance(data.get("summary"), dict) else {}
    lines = [
        "- Adjudications: "
        f"records={_md_safe(summary.get('total_records', 0))}, "
        f"open={_md_safe(summary.get('open_findings', 0))}, "
        f"false_positive={_md_safe(summary.get('false_positive_findings', 0))}, "
        f"accepted_risk={_md_safe(summary.get('accepted_risk_findings', 0))}, "
        f"fixed={_md_safe(summary.get('fixed_findings', 0))}",
    ]
    latest = summary.get("latest_status_by_finding") if isinstance(summary.get("latest_status_by_finding"), dict) else {}
    for finding_id, status in sorted(latest.items())[:8]:
        lines.append(f"  - {_md_safe(finding_id)}: {_md_safe(status)}")
    return lines


def _risk_card_gate_status(destination: Path) -> tuple[str, list[str]]:
    risk_path = destination / "risk-summary.json"
    if not risk_path.exists():
        return "unknown", ["risk-summary.json not present"]
    import json

    data = json.loads(risk_path.read_text(encoding="utf-8"))
    return str(data.get("status", "unknown")), [str(reason) for reason in data.get("reasons", [])]


def _risk_card_gate_data(destination: Path) -> dict[str, Any]:
    return _load_json_artifact(destination / "risk-summary.json") or {}


def _risk_card_triage_data(destination: Path) -> dict[str, Any]:
    data = _load_json_artifact(destination / "deterministic-triage.json")
    if data is not None:
        return data
    cache = _load_json_artifact(destination / "rescore-cache.json")
    summary = cache.get("triage_summary") if isinstance(cache, dict) else None
    return summary if isinstance(summary, dict) else {}


def _run_metadata(report: RunReport) -> dict[str, Any]:
    metadata = report.metadata if isinstance(report.metadata, dict) else {}
    run_metadata = metadata.get("run") if isinstance(metadata.get("run"), dict) else {}
    return run_metadata


def _release_matrix_metadata(report: RunReport, gate_data: dict[str, Any]) -> dict[str, Any]:
    run_matrix = _run_metadata(report).get("release_matrix")
    if isinstance(run_matrix, dict):
        return run_matrix
    metadata = gate_data.get("metadata") if isinstance(gate_data.get("metadata"), dict) else {}
    gate_matrix = metadata.get("release_matrix") if isinstance(metadata.get("release_matrix"), dict) else {}
    return gate_matrix


def _risk_card_count(mapping: dict[str, Any], key: str) -> int:
    return int(mapping.get(key) or 0)


def _risk_card_percent(value: object) -> str:
    if not isinstance(value, (float, int)):
        return "n/a"
    return f"{float(value) * 100:.1f}%"


def _risk_card_reliability_lines(gate_data: dict[str, Any]) -> list[str]:
    summary = gate_data.get("summary") if isinstance(gate_data.get("summary"), dict) else {}
    provider_error_rate = summary.get("deterministic_provider_error_rate")
    parse_rate = summary.get("deterministic_json_parse_rate")
    provider_reliability = 1 - float(provider_error_rate) if isinstance(provider_error_rate, (float, int)) else None
    lines = [
        f"- Provider reliability: {_md_safe(_risk_card_percent(provider_reliability))} (from gate summary deterministic_provider_error_rate)",
        f"- Parse reliability: {_md_safe(_risk_card_percent(parse_rate))} (from gate summary deterministic_json_parse_rate)",
    ]
    flaky = _risk_card_count(summary, "repeated_flaky_high_severity_count")
    deterministic_flaky = _risk_card_count(summary, "repeated_deterministic_flaky_count")
    fingerprint_mismatch = _risk_card_count(summary, "repeated_fingerprint_mismatch_count")
    repeated = _risk_card_count(summary, "repeated_case_count")
    if flaky or deterministic_flaky or fingerprint_mismatch or repeated:
        lines.append(
            f"- Flakiness: {flaky} high-severity flaky cases, "
            f"{deterministic_flaky} deterministic flaky cases, "
            f"{fingerprint_mismatch} fingerprint mismatches across {repeated} repeated cases"
        )
    else:
        lines.append("- Flakiness: not available")
    return lines


def _risk_card_evidence_lines(triage: dict[str, Any], gate_data: dict[str, Any]) -> list[str]:
    summary = gate_data.get("summary") if isinstance(gate_data.get("summary"), dict) else {}
    live = _risk_card_count(summary, "deterministic_live_evidence_count")
    non_live = _risk_card_count(summary, "deterministic_non_live_evidence_count")
    live_required = _risk_card_count(summary, "deterministic_live_required_gate_count")
    if not triage:
        return ["- Deterministic triage: not present", f"- Evidence levels: live={live}, non_live={non_live}, live_required_gates={live_required}"]
    pass_rate = triage.get("pass_rate")
    pass_rate_text = _risk_card_percent(pass_rate) if isinstance(pass_rate, (float, int)) else "n/a"
    return [
        f"- Deterministic triage posture: {_md_safe(triage.get('posture') or 'unknown')}",
        "- Evidence-level summary: "
        f"live={live}, non_live={non_live}, live_required_gates={live_required}, "
        f"pass_rate={_md_safe(pass_rate_text)} over {_risk_card_count(triage, 'pass_rate_denominator')} applicable cases",
        "- Deterministic outcome counts: "
        f"pass={_risk_card_count(triage, 'pass_count')}, fail={_risk_card_count(triage, 'fail_count')}, "
        f"error={_risk_card_count(triage, 'error_count')}, review={_risk_card_count(triage, 'review_count')}, "
        f"scaffold_only={_risk_card_count(triage, 'scaffold_only_count')}, not_tested={_risk_card_count(triage, 'not_tested_count')}",
    ]


def _deterministic_finding_counts(triage: dict[str, Any]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0}
    for finding in _as_list(triage.get("top_findings")):
        if not isinstance(finding, dict):
            continue
        severity = str(finding.get("severity") or "").lower()
        if severity in counts:
            counts[severity] += 1
    explicit = triage.get("deterministic_fail_counts_by_severity")
    if isinstance(explicit, dict):
        for severity in counts:
            counts[severity] = int(explicit.get(severity) or counts[severity])
    return counts


def _risk_card_deterministic_finding_lines(triage: dict[str, Any]) -> list[str]:
    if not triage:
        return ["- Critical deterministic fails: 0", "- High deterministic fails: 0", "- Medium deterministic fails: 0"]
    counts = _deterministic_finding_counts(triage)
    lines = [
        f"- Critical deterministic fails: {counts['critical']}",
        f"- High deterministic fails: {counts['high']}",
        f"- Medium deterministic fails: {counts['medium']}",
    ]
    for finding in _as_list(triage.get("top_findings"))[:5]:
        if isinstance(finding, dict):
            reasons = finding.get("reason_codes") if isinstance(finding.get("reason_codes"), list) else []
            lines.append(
                f"  - {_md_safe(finding.get('severity') or 'unknown')} {_md_safe(finding.get('case_id') or finding.get('finding_id') or 'unknown')} "
                f"surface={_md_safe(finding.get('surface') or 'unknown')} reasons={_md_safe(', '.join(str(reason) for reason in reasons) or 'none')}: "
                f"{_md_safe(finding.get('title') or 'deterministic finding')}"
            )
    return lines


def _risk_card_surface_lines(triage: dict[str, Any]) -> list[str]:
    counts = triage.get("counts_by_surface") if isinstance(triage.get("counts_by_surface"), dict) else {}
    if not counts:
        return ["- Strongest surfaces by deterministic counts: n/a", "- Weakest surfaces by deterministic counts: n/a"]
    ordered = sorted(((str(surface), int(count)) for surface, count in counts.items()), key=lambda item: (item[1], item[0]))
    strongest = ", ".join(f"{surface}={count}" for surface, count in ordered[:3])
    weakest = ", ".join(f"{surface}={count}" for surface, count in reversed(ordered[-3:]))
    return [
        f"- Strongest surfaces by deterministic counts: {_md_safe(strongest)}",
        f"- Weakest surfaces by deterministic counts: {_md_safe(weakest)}",
    ]


def _risk_card_recommendation(triage: dict[str, Any]) -> str:
    counts = _deterministic_finding_counts(triage)
    if counts["critical"] or counts["high"]:
        return "not recommended for high-risk use"
    if counts["medium"] or _risk_card_count(triage, "fail_count"):
        return "use only after remediation and scoped validation"
    return "no deterministic blocker in scoped evidence; not proof of general safety"


def _deterministic_risk_card_lines(triage: dict[str, Any], gate_data: dict[str, Any]) -> list[str]:
    lines = ["", "## Deterministic triage summary", ""]
    lines.extend(_risk_card_evidence_lines(triage, gate_data))
    lines.extend(["", "## Deterministic findings", ""])
    lines.extend(_risk_card_deterministic_finding_lines(triage))
    lines.extend(["", "## Provider and parse reliability", ""])
    lines.extend(_risk_card_reliability_lines(gate_data))
    lines.extend(["", "## Deterministic surface summary", ""])
    lines.extend(_risk_card_surface_lines(triage))
    lines.extend(["", "## Conservative recommendation", "", f"- Recommendation: {_md_safe(_risk_card_recommendation(triage))}"])
    return lines


def render_model_risk_card(report: RunReport, output_dir: str | Path, *, regression_summary: str | None = None, agent_summary: str | None = None) -> str:
    destination = Path(output_dir)
    gate_data = _risk_card_gate_data(destination)
    triage = _risk_card_triage_data(destination)
    gate_status, gate_reasons = _risk_card_gate_status(destination)
    failed_cases = []
    for dataset in report.datasets:
        for case in dataset.case_results:
            if not case.passed or case.penalty:
                failed_cases.append((case.severity, case.case_id, case.objective, case.penalty))
        for group in dataset.group_results:
            if not group.passed or group.penalty:
                failed_cases.append((group.severity, group.group_id, group.objective, group.penalty))
    failed_cases.sort(key=lambda item: (_RISK_CARD_SEVERITY_ORDER.get(item[0], 0), item[3]), reverse=True)
    top_risks = failed_cases[:5]
    lines = [
        f"# Malleus model risk card: {_md_safe(report.target_model)}",
        "",
        "## Deployment gate",
        "",
        f"- Status: {_md_safe(gate_status)}",
        f"- Reasons: {', '.join(_md_safe(reason) for reason in gate_reasons) if gate_reasons else 'none'}",
        f"- Score: {report.summary.score_total}/{report.summary.max_score_total}",
        f"- Passed: {report.summary.passed_items}/{report.summary.total_items}",
        "",
        "## Top risks",
        "",
    ]
    if top_risks:
        for severity, item_id, objective, penalty in top_risks:
            lines.append(f"- {_md_safe(severity)} {_md_safe(item_id)} penalty={penalty}: {_md_safe(objective)}")
    else:
        lines.append("- No failed atomic items in this report.")
    lines.extend([
        "",
        "## Regression summary",
        "",
        f"- {_md_safe(regression_summary or 'No regression diff artifact supplied.')}",
        "",
        "## Complex campaign summary",
        "",
    ])
    campaign_lines = _campaign_detail_lines(report)
    if campaign_lines:
        lines.extend(campaign_lines)
    else:
        lines.append("- No defensive campaign datasets in this report.")
    lines.extend([
        "",
        "## Agent summary",
        "",
    ])
    if agent_summary:
        lines.append(f"- {_md_safe(agent_summary)}")
    agent_lines = _agent_detail_lines(destination)
    if agent_lines:
        lines.extend(agent_lines)
    elif not agent_summary:
        lines.append("- No agent-lab artifact supplied.")
    lines.extend([
        "",
        "## Human adjudication summary",
        "",
        *_adjudication_detail_lines(destination),
    ])
    lines.extend([
        "",
        "## Model/config metadata",
        "",
        f"- Run ID: {_md_safe(report.run_id)}",
        f"- Target: {_md_safe(report.target_name)}",
        f"- Adapter: {_md_safe(report.target_adapter)}",
        f"- Provider: {_md_safe(_run_metadata(report).get('provider') or report.target_adapter)}",
        f"- Model: {_md_safe(_run_metadata(report).get('model_id') or report.target_model)}",
        f"- Matrix ID: {_md_safe(_release_matrix_metadata(report, gate_data).get('id') or 'n/a')}",
        f"- Matrix version: {_md_safe(_release_matrix_metadata(report, gate_data).get('version') or 'n/a')}",
        f"- Input: {_md_safe(report.input_path)}",
        f"- Scoring: {_md_safe(report.scoring_path)}",
        *_deterministic_risk_card_lines(triage, gate_data),
        "",
        "## Evidence links",
        "",
        _artifact_link(destination, "manifest.json"),
        _artifact_link(destination, "events.jsonl"),
        _artifact_link(destination, "risk-summary.json"),
    ])
    return "\n".join(lines).rstrip() + "\n"


def write_model_risk_card(report: RunReport, output_dir: str | Path, *, regression_summary: str | None = None, agent_summary: str | None = None) -> Path:
    destination = Path(output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / "model-risk-card.md"
    path.write_text(render_model_risk_card(report, destination, regression_summary=regression_summary, agent_summary=agent_summary), encoding="utf-8")
    return path


def write_report_manifest(manifest: ReportManifest, output_dir: str | Path) -> Path:
    destination = Path(output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / "report-manifest.json"
    path.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")
    return path


def register_builtin_reporters() -> None:
    reporter_registry.register("json", _write_json_report)
    reporter_registry.register("markdown", _write_markdown_report)
    reporter_registry.register("html", _write_html_report)


register_builtin_reporters()
