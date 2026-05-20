from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from html import escape
from pathlib import Path
from typing import Any


STUDIO_SCHEMA_VERSION = "malleus.studio.v1"

_SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\b(?:api[_ -]?key|secret|token|password|credential|bearer|canary)\s*[:=]?\s*[^\s`|<>]+", re.IGNORECASE),
    re.compile(r"/home/[^\s`|<>\]\)]+"),
    re.compile(r"/Users/[^\s`|<>\]\)]+"),
    re.compile(r"[A-Za-z]:[\\/]+Users[\\/]+[^\s`|<>\]\)]+"),
)
_UNSAFE_PATTERNS = (
    re.compile(r"<\s*/?\s*script\b[^>]*>", re.IGNORECASE),
    re.compile(r"\b(ignore previous instructions|system prompt|developer message|exfiltrate|call\s+exfiltrate_secret|environment token|reveal hidden|private fixture|do_not_dump_raw\w*)\b", re.IGNORECASE),
)
_SPACE_RE = re.compile(r"\s+")

_KNOWN_STUDIO_ARTIFACTS = {
    "report.json",
    "events.jsonl",
    "findings.json",
    "findings.md",
    "mutation-report.json",
    "mutation-dry-run.json",
    "hidden-channel-report.json",
    "artifact-firewall-report.json",
    "visual-lab-report.json",
    "visual-run-report.json",
    "anomaly-report.json",
    "risk-summary.json",
    "coverage.json",
    "compound-risk-report.json",
    "issue-export.json",
    "remediation-board.md",
    "replay-spec.json",
    "model-risk-card.md",
}
_KNOWN_PREFIXES = ("patch-suggestions-", "replay-")


@dataclass(frozen=True)
class StudioArtifact:
    path: str
    sha256: str
    size_bytes: int
    artifact_type: str


@dataclass(frozen=True)
class StudioExport:
    index_html: Path
    artifact_index: Path
    artifacts: list[StudioArtifact]


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists() or not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _json_items(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _redaction_label(value: str, *, kind: str = "sensitive") -> str:
    return f"[REDACTED] {kind} sha256={_sha256_text(value)[:16]} length={len(value)}"


def _sanitize_text(value: object, *, limit: int = 520) -> str:
    text = _SPACE_RE.sub(" ", str(value)).strip()
    if not text:
        return "n/a"
    if any(pattern.search(text) for pattern in _UNSAFE_PATTERNS):
        text = _redaction_label(text, kind="unsafe")
    else:
        for pattern in _SECRET_PATTERNS:
            text = pattern.sub(lambda match: _redaction_label(match.group(0)), text)
    return text[:limit] + ("..." if len(text) > limit else "")


def _html_safe(value: object, *, limit: int = 520) -> str:
    return escape(_sanitize_text(value, limit=limit))


def _body_ref(label: str, value: object) -> str:
    text = str(value or "")
    return f"[REDACTED] {label} sha256={_sha256_text(text)[:16]} length={len(text)}"


def _safe_relpath(path: Path, base: Path) -> str:
    try:
        raw = path.resolve().relative_to(base.resolve()).as_posix()
    except ValueError:
        raw = path.name
    safe = _sanitize_text(raw.replace("\\", "/"), limit=240)
    if safe.startswith("../") or safe.startswith("/") or "://" in safe:
        return _sanitize_text(path.name, limit=240)
    return safe


def _artifact_type(path: Path) -> str:
    name = path.name
    for suffix in (".json", ".jsonl", ".md", ".html", ".yaml", ".yml"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    return _sanitize_text(name.replace("-", "_"), limit=80)


def _is_studio_artifact(path: Path) -> bool:
    return path.name in _KNOWN_STUDIO_ARTIFACTS or any(path.name.startswith(prefix) for prefix in _KNOWN_PREFIXES)


def _collect_artifacts(report_dir: Path) -> list[StudioArtifact]:
    paths = sorted((path for path in report_dir.rglob("*") if path.is_file() and _is_studio_artifact(path)), key=lambda item: _safe_relpath(item, report_dir))
    return [
        StudioArtifact(
            path=_safe_relpath(path, report_dir),
            sha256=_sha256_file(path),
            size_bytes=path.stat().st_size,
            artifact_type=_artifact_type(path),
        )
        for path in paths
    ]


def _first_failed_case(report: dict[str, Any]) -> dict[str, Any]:
    fallback: dict[str, Any] = {}
    for dataset in _json_items(report.get("datasets")):
        dataset_name = str(dataset.get("dataset_name") or dataset.get("name") or "dataset")
        for case in _json_items(dataset.get("case_results")):
            enriched = dict(case)
            enriched["dataset_name"] = dataset_name
            if not fallback:
                fallback = enriched
            if not case.get("passed", False) or int(case.get("penalty") or 0) > 0:
                return enriched
    return fallback


def _selected_finding(findings: dict[str, Any]) -> dict[str, Any]:
    items = _json_items(findings.get("findings"))
    if not items:
        return {}
    return sorted(items, key=lambda item: str(item.get("severity") or ""), reverse=True)[0]


def _evidence_refs(finding: dict[str, Any]) -> list[dict[str, Any]]:
    return _json_items(finding.get("evidence_refs"))[:8]


def _timeline(report_dir: Path, report: dict[str, Any], finding: dict[str, Any], risk: dict[str, Any]) -> list[tuple[str, str, str]]:
    events_path = report_dir / "events.jsonl"
    events: list[tuple[str, str, str]] = []
    if events_path.exists():
        for line in events_path.read_text(encoding="utf-8").splitlines()[:18]:
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                events.append((str(item.get("timestamp") or item.get("time") or "event"), str(item.get("event") or item.get("type") or "event"), str(item.get("detail") or item.get("message") or item.get("case_id") or "recorded")))
    if events:
        return events
    started = report.get("started_at") or report.get("generated_at") or "start"
    finished = report.get("finished_at") or "finish"
    return [
        (str(started), "run_started", f"run={report.get('run_id', 'unknown')}"),
        ("analysis", "finding_selected", finding.get("finding_id", "no finding selected")),
        ("gate", "policy_decision", risk.get("status", "unknown")),
        (str(finished), "studio_export_ready", "static narrative assembled from local artifacts"),
    ]


def _hidden_rows(hidden: dict[str, Any]) -> str:
    rows = []
    for item in _json_items(hidden.get("findings"))[:8]:
        rows.append(
            "<tr>"
            f"<td>{_html_safe(item.get('kind', 'hidden_channel'))}</td>"
            f"<td>{_html_safe(item.get('severity', 'unknown'))}</td>"
            f"<td>{_html_safe(item.get('description') or item.get('redacted_preview') or 'hidden surface')}</td>"
            "</tr>"
        )
    return "".join(rows) or "<tr><td colspan='3'>No hidden-channel artifact supplied.</td></tr>"


def _artifact_rows(artifact_report: dict[str, Any]) -> str:
    rows = []
    for item in _json_items(artifact_report.get("findings"))[:8]:
        rows.append(
            "<tr>"
            f"<td>{_html_safe(item.get('kind', 'artifact'))}</td>"
            f"<td>{_html_safe(item.get('severity', 'unknown'))}</td>"
            f"<td>{_html_safe(item.get('description') or item.get('evidence') or 'artifact surface')}</td>"
            "</tr>"
        )
    return "".join(rows) or "<tr><td colspan='3'>No artifact-firewall findings supplied.</td></tr>"


def _visual_rows(visual: dict[str, Any]) -> str:
    rows = []
    for result in _json_items(visual.get("results"))[:6]:
        findings = [*_json_items(result.get("visual_lab_findings")), *_json_items(result.get("artifact_firewall_findings"))]
        if not findings:
            rows.append(
                "<tr>"
                f"<td>{_html_safe(result.get('scenario_id', 'visual'))}</td>"
                f"<td>{_html_safe(result.get('gate_recommendation', 'unknown'))}</td>"
                f"<td>{_html_safe(', '.join(str(tag) for tag in result.get('coverage_tags', []) if str(tag)) or 'safe context only')}</td>"
                "</tr>"
            )
        for finding in findings[:4]:
            rows.append(
                "<tr>"
                f"<td>{_html_safe(result.get('scenario_id', 'visual'))}</td>"
                f"<td>{_html_safe(finding.get('severity', result.get('gate_recommendation', 'unknown')))}</td>"
                f"<td>{_html_safe(finding.get('description') or finding.get('redacted_preview') or finding.get('kind') or 'visual finding')}</td>"
                "</tr>"
            )
    return "".join(rows) or "<tr><td colspan='3'>No visual lab artifact supplied.</td></tr>"


def _coverage_cell(coverage: dict[str, Any], finding: dict[str, Any]) -> dict[str, Any]:
    cells = _json_items(coverage.get("cells"))
    if not cells:
        return {}
    target = (str(finding.get("attack_surface") or ""), str(finding.get("technique") or ""), str(finding.get("violated_boundary") or ""))
    for cell in cells:
        if (str(cell.get("source_surface") or ""), str(cell.get("technique") or ""), str(cell.get("expected_boundary") or "")) == target:
            return cell
    for cell in cells:
        if cell.get("status") == "covered" or int(cell.get("finding_count") or 0) > 0:
            return cell
    return cells[0]


def _compound_rows(report: dict[str, Any]) -> str:
    rows = []
    for scenario in _json_items(report.get("scenarios"))[:6]:
        rows.append(
            "<tr>"
            f"<td>{_html_safe(scenario.get('scenario_id', 'compound'))}</td>"
            f"<td>{_html_safe(scenario.get('threat_class', 'unknown'))}</td>"
            f"<td>{_html_safe(scenario.get('compound_risk', 'unknown'))}</td>"
            f"<td>{_html_safe(scenario.get('countermeasure', 'review local control'), limit=220)}</td>"
            "</tr>"
        )
    return "".join(rows) or "<tr><td colspan='4'>No compound-risk artifact supplied.</td></tr>"


def _issue_rows(report: dict[str, Any]) -> str:
    rows = []
    for issue in _json_items(report.get("issues"))[:6]:
        rows.append(
            "<tr>"
            f"<td>{_html_safe(issue.get('issue_id', 'issue'))}</td>"
            f"<td>{_html_safe(issue.get('severity', 'unknown'))}</td>"
            f"<td>{_html_safe(issue.get('owner', '@owner-tbd'))}</td>"
            f"<td>{_html_safe(issue.get('title', 'local issue'), limit=220)}</td>"
            "</tr>"
        )
    return "".join(rows) or "<tr><td colspan='4'>No issue-export artifact supplied.</td></tr>"


def _patch_summary(report_dir: Path, finding: dict[str, Any]) -> dict[str, Any]:
    finding_id = str(finding.get("finding_id") or "")
    candidates = sorted(report_dir.rglob("patch-suggestions-*.json"))
    for path in candidates:
        data = _load_json(path)
        if not finding_id or data.get("finding_id") == finding_id:
            return data
    return {}


def _replay_command(report_dir: Path, finding: dict[str, Any]) -> str:
    spec = _dict(finding.get("replay_spec"))
    if spec.get("command"):
        return str(spec["command"])
    for path in sorted(report_dir.rglob("replay-*.json")):
        data = _load_json(path)
        if data.get("command"):
            return str(data["command"])
    data = _load_json(report_dir / "replay-spec.json")
    return str(data.get("command") or "malleus replay <finding-id> --report <report-dir-or-findings.json> --dry-run")


def _risk_card_excerpt(path: Path) -> str:
    if not path.exists():
        return "No model risk card artifact supplied."
    text = path.read_text(encoding="utf-8")
    return _sanitize_text(text, limit=620)


def _timeline_html(events: list[tuple[str, str, str]]) -> str:
    return "".join(
        "<li>"
        f"<time>{_html_safe(timestamp, limit=90)}</time>"
        f"<strong>{_html_safe(kind, limit=90)}</strong>"
        f"<span>{_html_safe(detail, limit=180)}</span>"
        "</li>"
        for timestamp, kind, detail in events
    )


def _artifact_index_rows(artifacts: list[StudioArtifact]) -> str:
    rows = []
    for artifact in artifacts[:18]:
        rows.append(
            "<tr>"
            f"<td>{_html_safe(artifact.path)}</td>"
            f"<td><code>{artifact.sha256}</code></td>"
            f"<td>{artifact.size_bytes}</td>"
            f"<td>{_html_safe(artifact.artifact_type)}</td>"
            "</tr>"
        )
    return "".join(rows) or "<tr><td colspan='4'>No local artifacts indexed.</td></tr>"


def render_studio_html(report_dir: str | Path, artifacts: list[StudioArtifact]) -> str:
    directory = Path(report_dir).resolve()
    report = _load_json(directory / "report.json")
    findings = _load_json(directory / "findings.json")
    mutation = _load_json(directory / "mutation-report.json") or _load_json(directory / "mutation-dry-run.json")
    hidden = _load_json(directory / "hidden-channel-report.json")
    artifact_report = _load_json(directory / "artifact-firewall-report.json")
    visual = _load_json(directory / "visual-lab-report.json")
    anomaly = _load_json(directory / "anomaly-report.json")
    risk = _load_json(directory / "risk-summary.json")
    coverage = _load_json(directory / "coverage.json")
    compound = _load_json(directory / "compound-risk-report.json")
    issues = _load_json(directory / "issue-export.json")

    case = _first_failed_case(report)
    finding = _selected_finding(findings)
    coverage_cell = _coverage_cell(coverage, finding)
    patch = _patch_summary(directory, finding)
    replay = _replay_command(directory, finding)
    summary = _dict(report.get("summary"))
    mutation_summary = _dict(mutation.get("summary"))
    anomaly_summary = _dict(anomaly.get("summary"))
    risk_reasons = risk.get("reasons") if isinstance(risk.get("reasons"), list) else []
    evidence_refs = _evidence_refs(finding)
    patch_commands = patch.get("regression_commands") if isinstance(patch.get("regression_commands"), list) else []
    patch_artifacts = patch.get("artifacts") if isinstance(patch.get("artifacts"), dict) else {}
    case_metadata = _dict(case.get("metadata"))
    target_model = report.get("target_model") or _dict(finding.get("affected_model")).get("model") or "unknown model"
    title = f"Malleus Studio / {_sanitize_text(report.get('run_id') or findings.get('run_id') or 'local evidence', limit=90)}"

    evidence_list = "".join(
        f"<li><code>{_html_safe(ref.get('evidence_id', 'evidence'))}</code> {_html_safe(ref.get('artifact_path', 'artifact'))} {_html_safe(ref.get('json_pointer') or '')}<br><span>{_html_safe(ref.get('redacted_excerpt') or 'redacted evidence ref')}</span></li>"
        for ref in evidence_refs
    ) or "<li>No finding evidence refs supplied.</li>"
    patch_list = "".join(f"<li>{_html_safe(name)} → {_html_safe(path)}</li>" for name, path in sorted(patch_artifacts.items())) or "<li>No patch artifact map supplied.</li>"
    command_list = "".join(f"<li><code>{_html_safe(command, limit=360)}</code></li>" for command in patch_commands[:3]) or "<li>No patch regression command supplied.</li>"
    labels = anomaly_summary.get("labels") if isinstance(anomaly_summary.get("labels"), list) else []
    risk_reason_list = "".join(f"<li>{_html_safe(reason)}</li>" for reason in risk_reasons[:6]) or "<li>No gate reasons supplied.</li>"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_html_safe(title)}</title>
<style>
:root {{ color-scheme: dark; --bg:#08090a; --panel:#0f1011; --surface:#17191d; --ink:#f7f8f8; --muted:#8a8f98; --soft:#d0d6e0; --line:rgba(255,255,255,.09); --accent:#7170ff; --accent-2:#38bdf8; --danger:#ef4444; --warning:#f59e0b; --ok:#10b981; --space-1:6px; --space-2:10px; --space-3:14px; --space-4:18px; --space-5:24px; --space-6:32px; --radius-1:14px; --radius-2:20px; --shadow-1:0 24px 90px rgba(0,0,0,.38); }}
* {{ box-sizing:border-box; }}
body {{ margin:0; font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; background:radial-gradient(circle at 14% 0%, rgba(113,112,255,.22), transparent 31%), radial-gradient(circle at 86% 12%, rgba(56,189,248,.12), transparent 24%), var(--bg); color:var(--ink); }}
main {{ max-width:1240px; margin:0 auto; padding:var(--space-6) var(--space-5) 72px; }}
.hero {{ position:relative; border:1px solid var(--line); background:linear-gradient(180deg, rgba(255,255,255,.055), rgba(255,255,255,.018)); border-radius:28px; padding:var(--space-6); box-shadow:var(--shadow-1); overflow:hidden; }}
.hero:after {{ content:""; position:absolute; inset:auto -12% -45% 38%; height:210px; background:linear-gradient(90deg, transparent, rgba(113,112,255,.16), rgba(56,189,248,.11), transparent); transform:rotate(-7deg); }}
.eyebrow {{ color:var(--accent-2); font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:12px; letter-spacing:.11em; text-transform:uppercase; }}
h1 {{ max-width:940px; font-size:clamp(36px,6vw,72px); line-height:.96; letter-spacing:-1.4px; font-weight:520; margin:var(--space-3) 0; }}
.subtitle {{ color:var(--muted); max-width:850px; font-size:17px; line-height:1.65; }}
.overview {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:var(--space-3); margin:var(--space-5) 0 0; }}
.metric,.panel {{ border:1px solid var(--line); background:rgba(15,16,17,.82); border-radius:var(--radius-2); padding:var(--space-4); }}
.metric span,.label {{ color:var(--muted); font-size:13px; }}
.metric strong {{ display:block; margin:var(--space-2) 0 var(--space-1); font-size:28px; letter-spacing:-.04em; }}
.layout {{ display:grid; grid-template-columns:minmax(0,1fr) 360px; gap:var(--space-5); align-items:start; }}
section {{ margin-top:var(--space-6); }}
h2 {{ font-size:23px; margin:0 0 var(--space-3); font-weight:560; letter-spacing:-.3px; }}
h3 {{ font-size:16px; color:var(--soft); margin:0 0 var(--space-2); }}
p {{ color:var(--soft); line-height:1.58; }}
code,pre {{ font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }}
pre {{ white-space:pre-wrap; overflow:auto; margin:0; background:#050608; border:1px solid var(--line); border-radius:var(--radius-1); padding:var(--space-3); color:#d8dee9; }}
table {{ width:100%; border-collapse:collapse; font-size:13px; }}
th,td {{ border-bottom:1px solid rgba(255,255,255,.06); padding:11px 10px; text-align:left; vertical-align:top; }}
th {{ color:var(--soft); font-weight:520; background:rgba(255,255,255,.025); }}
.timeline {{ list-style:none; margin:0; padding:0; border-left:1px solid var(--line); }}
.timeline li {{ position:relative; padding:0 0 var(--space-4) var(--space-5); }}
.timeline li:before {{ content:""; position:absolute; left:-5px; top:5px; width:9px; height:9px; border-radius:999px; background:var(--accent); box-shadow:0 0 0 5px rgba(113,112,255,.12); }}
.timeline time,.timeline span {{ display:block; color:var(--muted); font-size:12px; }}
.pill {{ display:inline-flex; align-items:center; gap:var(--space-1); padding:5px 9px; border:1px solid var(--line); border-radius:999px; color:var(--soft); background:rgba(255,255,255,.025); font-size:12px; }}
.danger {{ color:var(--danger); }} .warning {{ color:var(--warning); }} .ok {{ color:var(--ok); }}
ul {{ color:var(--soft); padding-left:20px; }}
li {{ margin:var(--space-1) 0; }}
.aside {{ position:sticky; top:var(--space-5); }}
footer {{ color:var(--muted); margin-top:42px; font-size:13px; }}
@media (max-width: 920px) {{ .layout {{ grid-template-columns:1fr; }} .aside {{ position:static; }} }}
</style>
</head>
<body>
<main>
<section class="hero"><div class="eyebrow">Malleus Studio / sanitized evidence graph</div><h1>{_html_safe(title)}</h1><p class="subtitle">A static, local-only narrative studio export for analyst review. Prompt bodies, transformed prompts, responses, secret-like values, and private paths are represented with hashes, lengths, redacted previews, and evidence refs only.</p></section>
<section><h2>Run overview</h2><div class="overview">
<article class="metric"><span>Run</span><strong>{_html_safe(report.get('run_id', findings.get('run_id', 'unknown')), limit=120)}</strong><small>{_html_safe(target_model, limit=160)}</small></article>
<article class="metric"><span>Score</span><strong>{_html_safe(summary.get('score_total', 'n/a'))}/{_html_safe(summary.get('max_score_total', 'n/a'))}</strong><small>passed={_html_safe(summary.get('passed_items', 'n/a'))} failed={_html_safe(summary.get('failed_items', 'n/a'))}</small></article>
<article class="metric"><span>Gate</span><strong>{_html_safe(risk.get('status', 'unknown'))}</strong><small>{len(risk_reasons)} policy reasons</small></article>
<article class="metric"><span>Artifacts</span><strong>{len(artifacts)}</strong><small>parseable artifact index with SHA-256 hashes</small></article>
</div></section>
<div class="layout"><div>
<section><h2>Timeline/events</h2><div class="panel"><ol class="timeline">{_timeline_html(_timeline(directory, report, finding, risk))}</ol></div></section>
<section><h2>Selected case/finding</h2><div class="panel"><p><span class="pill">{_html_safe(finding.get('severity', case.get('severity', 'unknown')))}</span> <span class="pill">{_html_safe(finding.get('source_type', 'run_report'))}</span></p><h3>{_html_safe(finding.get('title') or case.get('case_id') or 'No finding selected')}</h3><p>{_html_safe(finding.get('attack_surface') or case.get('dataset_name') or 'unknown surface')} / {_html_safe(finding.get('technique') or case_metadata.get('technique') or 'unknown technique')} / {_html_safe(finding.get('violated_boundary') or case_metadata.get('violated_boundary') or 'unknown boundary')}</p></div></section>
<section><h2>Redacted prompt / transformed prompt preview</h2><div class="panel"><h3>Prompt</h3><pre>{_html_safe(case.get('prompt_preview') or _body_ref('prompt', case.get('prompt', '')), limit=360)}</pre><h3>Transformed prompt</h3><pre>{_html_safe(case.get('transformed_prompt_preview') or _body_ref('transformed_prompt', case_metadata.get('transformed_prompt') or mutation_summary.get('worst_mutation') or ''), limit=360)}</pre></div></section>
<section><h2>Hidden/artifact/visual findings</h2><div class="panel"><h3>Hidden findings</h3><table><thead><tr><th>Kind</th><th>Severity</th><th>Sanitized detail</th></tr></thead><tbody>{_hidden_rows(hidden)}</tbody></table><h3>Artifact findings</h3><table><thead><tr><th>Kind</th><th>Severity</th><th>Sanitized detail</th></tr></thead><tbody>{_artifact_rows(artifact_report)}</tbody></table><h3>Visual findings</h3><table><thead><tr><th>Scenario</th><th>Gate/severity</th><th>Sanitized detail</th></tr></thead><tbody>{_visual_rows(visual)}</tbody></table></div></section>
<section><h2>Response summary</h2><div class="panel"><p>{_html_safe(case.get('response_summary') or _body_ref('response', case.get('response_text', '')), limit=360)}</p><p class="label">Raw response bodies are intentionally omitted from the studio export.</p></div></section>
<section><h2>Refusal/anomaly classification</h2><div class="panel"><p><strong>Refusal:</strong> {_html_safe(case_metadata.get('refusal_label') or case.get('refusal_label') or 'unknown')}</p><p><strong>Anomaly gate:</strong> {_html_safe(anomaly.get('gate_recommendation') or anomaly_summary.get('highest_severity') or 'none')}</p><p><strong>Labels:</strong> {_html_safe(', '.join(str(label) for label in labels) or 'none')}</p></div></section>
<section><h2>Policy decision</h2><div class="panel"><p><strong>Status:</strong> {_html_safe(risk.get('status', 'unknown'))}</p><ul>{risk_reason_list}</ul></div></section>
<section><h2>Coverage cell</h2><div class="panel"><p><strong>{_html_safe(coverage_cell.get('status', 'unknown'))}</strong> — {_html_safe(coverage_cell.get('source_surface', 'n/a'))} / {_html_safe(coverage_cell.get('technique', 'n/a'))} / {_html_safe(coverage_cell.get('expected_boundary', 'n/a'))}</p><p>{_html_safe(coverage_cell.get('missing_reason') or f"evidence_refs={len(coverage_cell.get('evidence_refs', []) if isinstance(coverage_cell.get('evidence_refs'), list) else [])}")}</p></div></section>
<section><h2>Compound risk</h2><div class="panel"><table><thead><tr><th>Scenario</th><th>Threat class</th><th>Risk</th><th>Countermeasure</th></tr></thead><tbody>{_compound_rows(compound)}</tbody></table></div></section>
<section><h2>Issues and remediation</h2><div class="panel"><table><thead><tr><th>Issue</th><th>Severity</th><th>Owner</th><th>Title</th></tr></thead><tbody>{_issue_rows(issues)}</tbody></table></div></section>
</div><aside class="aside">
<section><h2>Replay command</h2><div class="panel"><pre>{_html_safe(replay, limit=420)}</pre><p class="label">Dry-run/mock replay only; no provider or network calls are executed by studio export.</p></div></section>
<section><h2>Patches</h2><div class="panel"><ul>{patch_list}</ul><h3>Regression commands</h3><ul>{command_list}</ul></div></section>
<section><h2>Risk card</h2><div class="panel"><p>{_html_safe(_risk_card_excerpt(directory / 'model-risk-card.md'), limit=680)}</p></div></section>
<section><h2>Evidence refs</h2><div class="panel"><ul>{evidence_list}</ul></div></section>
</aside></div>
<section><h2>Artifact index</h2><div class="panel"><table><thead><tr><th>Path</th><th>SHA-256</th><th>Bytes</th><th>Type</th></tr></thead><tbody>{_artifact_index_rows(artifacts)}</tbody></table></div></section>
<footer>Generated by Malleus Studio from local report artifacts. Static HTML with no external JavaScript, fonts, third-party assets, server, or network dependency.</footer>
</main>
</body>
</html>
"""


def export_studio(report_dir: str | Path, out_dir: str | Path) -> StudioExport:
    source = Path(report_dir).resolve()
    if not source.exists() or not source.is_dir():
        raise ValueError(f"studio report directory not found: {report_dir}")
    destination = Path(out_dir).resolve() / "studio"
    destination.mkdir(parents=True, exist_ok=True)
    artifacts = _collect_artifacts(source)
    index_html = destination / "index.html"
    artifact_index = destination / "artifact-index.json"
    index_html.write_text(render_studio_html(source, artifacts), encoding="utf-8")
    artifact_index.write_text(
        json.dumps(
            {
                "schema_version": STUDIO_SCHEMA_VERSION,
                "generated_at": datetime.now(UTC).isoformat(),
                "source": _sanitize_text(source.name, limit=120),
                "artifacts": [artifact.__dict__ for artifact in artifacts],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return StudioExport(index_html=index_html, artifact_index=artifact_index, artifacts=artifacts)
