from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from html import escape
from pathlib import Path
from typing import Any

from malleus.surface_names import public_surface_name


_SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\b(?:api[_-]?key|secret|token)\s*=\s*[^\s`|<>]+", re.IGNORECASE),
)


def _load(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _html_safe(value: object, *, limit: int | None = None) -> str:
    text = str(value)
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    if limit is not None:
        text = text[:limit]
    return escape(text)


def _pct(score: int, max_score: int) -> float:
    return 0.0 if max_score == 0 else (score / max_score) * 100


@dataclass
class SurfaceSummary:
    name: str
    total: int = 0
    passed: int = 0
    failed: int = 0
    evidence: Counter[str] = field(default_factory=Counter)
    reasons: Counter[str] = field(default_factory=Counter)
    target_types: Counter[str] = field(default_factory=Counter)


@dataclass
class GatewaySummary:
    calls: int = 0
    blocked: int = 0
    policy_hashes: Counter[str] = field(default_factory=Counter)
    reason_codes: Counter[str] = field(default_factory=Counter)


@dataclass
class DashboardReport:
    model: str
    source: str
    score: int
    max_score: int
    passed_items: int
    total_items: int
    evidence_level: str
    surfaces: dict[str, SurfaceSummary]
    failures: list[dict[str, object]]
    gateway: GatewaySummary = field(default_factory=GatewaySummary)

    @property
    def rate(self) -> float:
        return _pct(self.score, self.max_score)


def render_dashboard(report_paths: list[str | Path]) -> str:
    reports = [_normalize_report(_load(path), Path(path)) for path in report_paths]
    reports.sort(key=lambda report: report.rate, reverse=True)
    total_items = sum(report.total_items for report in reports)
    passed_items = sum(report.passed_items for report in reports)
    failed_items = max(0, total_items - passed_items)
    live_traces = sum(1 for report in reports for surface in report.surfaces.values() if surface.evidence.get("live_system_trace"))
    gateway_calls = sum(report.gateway.calls for report in reports)
    gateway_blocked = sum(report.gateway.blocked for report in reports)
    executive_rate = _pct(passed_items, total_items)
    cards: list[str] = []
    rows: list[str] = []
    failures: list[str] = []
    surface_cards = _surface_cards(reports)
    gateway_panel = _gateway_panel(reports)
    for rank, report in enumerate(reports, start=1):
        cards.append(
            f"<article class='card'><div class='rank'>#{rank}</div><h2>{_html_safe(report.model)}</h2>"
            f"<div class='score'>{report.score}/{report.max_score}</div><div class='bar'><span style='width:{report.rate:.1f}%'></span></div>"
            f"<p>{report.rate:.1f}% · {report.passed_items}/{report.total_items} passed · {_html_safe(report.evidence_level)}</p></article>"
        )
        rows.append(
            f"<tr><td>{rank}</td><td>{_html_safe(report.model)}</td><td>{report.score}/{report.max_score}</td><td>{report.rate:.1f}%</td>"
            f"<td>{report.passed_items}/{report.total_items}</td><td>{_html_safe(report.evidence_level)}</td><td>{_html_safe(report.source)}</td></tr>"
        )
        for failure in report.failures:
            failures.append(_failure_card(report.model, failure))
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Malleus Benchmark Dashboard</title>
<style>
:root {{ color-scheme: dark; --bg:#070b14; --panel:#111827; --muted:#9ca3af; --text:#e5e7eb; --green:#22c55e; --amber:#f59e0b; --red:#ef4444; --blue:#38bdf8; --line:#273449; }}
body {{ margin:0; font-family: Inter, ui-sans-serif, system-ui, sans-serif; background:#070b14; color:var(--text); }}
main {{ max-width:1180px; margin:0 auto; padding:40px 24px; }}
.hero {{ border:1px solid var(--line); background:linear-gradient(135deg,#111827,#0f172a); border-radius:8px; padding:32px; box-shadow: 0 20px 80px rgba(0,0,0,.35); }}
h1 {{ font-size:44px; margin:0 0 8px; letter-spacing:0; }}
.subtitle {{ color:var(--muted); font-size:18px; max-width:820px; }}
.summary {{ display:grid; grid-template-columns: repeat(auto-fit,minmax(180px,1fr)); gap:12px; margin-top:24px; }}
.metric {{ border:1px solid var(--line); background:#0b1220; border-radius:8px; padding:14px; }}
.metric strong {{ display:block; font-size:28px; }}
.metric span {{ color:var(--muted); font-size:13px; text-transform:uppercase; }}
.grid {{ display:grid; grid-template-columns: repeat(auto-fit,minmax(240px,1fr)); gap:16px; margin:28px 0; }}
.card {{ background:linear-gradient(180deg,#111827,#0f172a); border:1px solid var(--line); border-radius:8px; padding:18px; }}
.rank {{ color:var(--green); font-weight:800; }}
.card h2 {{ font-size:16px; min-height:42px; }}
.score {{ font-size:32px; font-weight:900; }}
.bar {{ height:10px; background:#1f2937; border-radius:999px; overflow:hidden; }}
.bar span {{ display:block; height:100%; background:linear-gradient(90deg,var(--green),#a3e635); }}
.risk {{ border-top:3px solid var(--blue); }}
.risk.high {{ border-top-color:var(--red); }}
.risk.medium {{ border-top-color:var(--amber); }}
.risk.low {{ border-top-color:var(--green); }}
.chips {{ display:flex; flex-wrap:wrap; gap:6px; margin-top:10px; }}
.chip {{ background:#1f2937; border:1px solid #334155; border-radius:999px; color:#cbd5e1; font-size:12px; padding:4px 8px; }}
table {{ width:100%; border-collapse:collapse; background:rgba(17,24,39,.9); border:1px solid var(--line); border-radius:8px; overflow:hidden; }}
th,td {{ padding:12px; border-bottom:1px solid var(--line); text-align:left; }}
th {{ color:#cbd5e1; background:#111827; }}
.failure {{ margin:16px 0; padding:18px; border:1px solid #7f1d1d; border-radius:8px; background:rgba(127,29,29,.18); }}
.failure h3 {{ margin-top:0; color:#fecaca; }}
pre {{ white-space:pre-wrap; color:#d1d5db; background:#020617; padding:12px; border-radius:8px; overflow:auto; }}
footer {{ color:var(--muted); margin-top:36px; }}
</style>
</head>
<body>
<main>
<section class="hero">
<h1>Malleus Benchmark Dashboard</h1>
<p class="subtitle">Executive security summary for model and agent benchmark evidence. Scores remain deterministic where applicable; live evidence rows distinguish observed system behavior from planning or capability gaps.</p>
<div class="summary">
<div class="metric"><strong>{len(reports)}</strong><span>runs compared</span></div>
<div class="metric"><strong>{passed_items}/{total_items}</strong><span>items passed</span></div>
<div class="metric"><strong>{executive_rate:.1f}%</strong><span>aggregate pass rate</span></div>
<div class="metric"><strong>{failed_items}</strong><span>review items</span></div>
<div class="metric"><strong>{live_traces}</strong><span>live surface traces</span></div>
<div class="metric"><strong>{gateway_blocked}/{gateway_calls}</strong><span>gateway blocked</span></div>
</div>
</section>
<section class="grid">{''.join(cards)}</section>
<h2>Leaderboard</h2>
<table><thead><tr><th>#</th><th>Target</th><th>Score</th><th>Rate</th><th>Passed</th><th>Evidence</th><th>Source</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
<h2>Risk cards by surface</h2>
<section class="grid">{surface_cards or '<p>No surface metadata found in these reports.</p>'}</section>
{gateway_panel}
<h2>Failure replay cards</h2>
{''.join(failures) if failures else '<p>No failed cases in this benchmark.</p>'}
<footer>Generated by Malleus from report.json and live-full-evidence.json artifacts. Public output redacts common secret patterns.</footer>
</main>
</body>
</html>
"""


def _normalize_report(raw: dict[str, Any], path: Path) -> DashboardReport:
    if raw.get("schema_version") == "malleus.live_evidence_matrix.v1":
        return _normalize_live_evidence(raw, path)
    if raw.get("schema_version") == "malleus.tool_agent_report.v1":
        return _normalize_tool_agent_report(raw, path)
    return _normalize_classic_report(raw, path)


def _normalize_classic_report(raw: dict[str, Any], path: Path) -> DashboardReport:
    summary = raw.get("summary", {})
    score = int(summary.get("score_total", 0) or 0)
    max_score = int(summary.get("max_score_total", 0) or 0)
    passed = int(summary.get("passed_items", 0) or 0)
    total = int(summary.get("total_items", 0) or 0)
    surfaces: dict[str, SurfaceSummary] = {}
    failures: list[dict[str, object]] = []
    for dataset in raw.get("datasets", []):
        surface_name = str(dataset.get("dataset_name") or dataset.get("name") or "benchmark")
        surface = surfaces.setdefault(surface_name, SurfaceSummary(name=surface_name))
        for case in dataset.get("case_results", []):
            surface.total += 1
            case_passed = bool(case.get("passed") and not case.get("penalty"))
            if case_passed:
                surface.passed += 1
            else:
                surface.failed += 1
                failures.append(
                    {
                        "id": case.get("case_id", "unknown"),
                        "surface": surface_name,
                        "score": case.get("score", ""),
                        "penalty": case.get("penalty", ""),
                        "reason": case.get("objective", ""),
                        "excerpt": case.get("response_text", ""),
                    }
                )
            if case.get("severity"):
                surface.reasons.update([str(case["severity"])])
            surface.evidence.update(["deterministic_score"])
    return DashboardReport(
        model=str(raw.get("target_model") or raw.get("target", {}).get("model") or path.parent.name),
        source=path.name,
        score=score,
        max_score=max_score,
        passed_items=passed,
        total_items=total,
        evidence_level="deterministic_score",
        surfaces=surfaces,
        failures=failures,
    )


def _normalize_live_evidence(raw: dict[str, Any], path: Path) -> DashboardReport:
    rows = [row for row in raw.get("rows", []) if isinstance(row, dict)]
    report_metadata = raw.get("metadata", {}) if isinstance(raw.get("metadata"), dict) else {}
    passed = sum(1 for row in rows if row.get("status") == "passed")
    total = len(rows)
    surfaces: dict[str, SurfaceSummary] = {}
    failures: list[dict[str, object]] = []
    evidence_counter: Counter[str] = Counter()
    for row in rows:
        row_metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
        surface_name = str(
            row.get("surface_name")
            or row_metadata.get("surface_name")
            or row_metadata.get("profile_name")
            or public_surface_name(str(row.get("surface_id") or row.get("case_id") or "live_surface"))
        )
        surface = surfaces.setdefault(surface_name, SurfaceSummary(name=surface_name))
        surface.total += 1
        status = str(row.get("status") or "unknown")
        if status == "passed":
            surface.passed += 1
        else:
            surface.failed += 1
            failures.append(
                {
                    "id": row.get("case_id") or row.get("surface_id") or "unknown",
                    "surface": surface_name,
                    "score": "live",
                    "penalty": status,
                    "reason": row.get("reason") or row.get("finding_summary") or "",
                    "excerpt": row.get("public_log") or row.get("summary") or row.get("reason") or "",
                }
            )
        evidence = str(row.get("evidence_level") or "unknown")
        surface.evidence.update([evidence])
        evidence_counter.update([evidence])
        target_type = row.get("target_type") or row_metadata.get("target_type")
        if target_type:
            surface.target_types.update([str(target_type)])
        reason_codes = row.get("reason_codes") or row_metadata.get("reason_codes") or []
        if isinstance(reason_codes, list):
            surface.reasons.update(str(reason) for reason in reason_codes)
    evidence_level = evidence_counter.most_common(1)[0][0] if evidence_counter else "live_evidence"
    return DashboardReport(
        model=str(report_metadata.get("target_name") or report_metadata.get("target_model") or raw.get("target_name") or path.parent.name),
        source=path.name,
        score=passed * 100,
        max_score=max(total, 1) * 100,
        passed_items=passed,
        total_items=total,
        evidence_level=evidence_level,
        surfaces=surfaces,
        failures=failures,
    )


def _normalize_tool_agent_report(raw: dict[str, Any], path: Path) -> DashboardReport:
    summary = raw.get("summary", {}) if isinstance(raw.get("summary"), dict) else {}
    total = int(summary.get("total_scenarios", 0) or 0)
    passed = int(summary.get("passed", 0) or 0)
    gateway = GatewaySummary(
        calls=int(summary.get("tool_gateway_calls", 0) or 0),
        blocked=int(summary.get("tool_gateway_blocked", 0) or 0),
    )
    surfaces: dict[str, SurfaceSummary] = {}
    failures: list[dict[str, object]] = []
    for result in raw.get("results", []):
        if not isinstance(result, dict):
            continue
        surface_name = str(result.get("attack_surface") or "tool_agent")
        surface = surfaces.setdefault(surface_name, SurfaceSummary(name=surface_name))
        surface.total += 1
        status = str(result.get("status") or "unknown")
        if status == "passed":
            surface.passed += 1
        else:
            surface.failed += 1
            failures.append(
                {
                    "id": result.get("scenario_id", "unknown"),
                    "surface": surface_name,
                    "score": "live",
                    "penalty": status,
                    "reason": result.get("reason") or "",
                    "excerpt": ", ".join(str(code) for code in result.get("reason_codes", []) if code),
                }
            )
        surface.evidence.update(["tool_gateway_trace" if _has_gateway_call(result) else "tool_trace"])
        surface.target_types.update(["tool_agent"])
        reason_codes = result.get("reason_codes") if isinstance(result.get("reason_codes"), list) else []
        surface.reasons.update(str(code) for code in reason_codes)
        for call in result.get("tool_calls", []):
            if not isinstance(call, dict):
                continue
            metadata = call.get("metadata") if isinstance(call.get("metadata"), dict) else {}
            decision = metadata.get("gateway_decision") or call.get("gateway_decision")
            if decision:
                gateway.calls += 1 if not int(summary.get("tool_gateway_calls", 0) or 0) else 0
                if decision == "blocked" and not int(summary.get("tool_gateway_blocked", 0) or 0):
                    gateway.blocked += 1
            policy_hash = metadata.get("gateway_policy_hash") or call.get("gateway_policy_hash")
            if isinstance(policy_hash, str) and policy_hash:
                gateway.policy_hashes.update([policy_hash[:12]])
            gateway_codes = metadata.get("gateway_reason_codes") or call.get("gateway_reason_codes") or []
            if isinstance(gateway_codes, list):
                gateway.reason_codes.update(str(code) for code in gateway_codes)
    report_metadata = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}
    report_gateway = report_metadata.get("tool_gateway") if isinstance(report_metadata.get("tool_gateway"), dict) else {}
    policy_hash = report_gateway.get("policy_hash") if isinstance(report_gateway, dict) else None
    if isinstance(policy_hash, str) and policy_hash:
        gateway.policy_hashes.update([policy_hash[:12]])
    if gateway.calls == 0 and gateway.blocked == 0:
        gateway.calls = int(summary.get("tool_gateway_calls", 0) or 0)
        gateway.blocked = int(summary.get("tool_gateway_blocked", 0) or 0)
    return DashboardReport(
        model=str(raw.get("target_name") or path.parent.name),
        source=path.name,
        score=passed * 100,
        max_score=max(total, 1) * 100,
        passed_items=passed,
        total_items=total,
        evidence_level="tool_gateway_trace" if gateway.calls else "tool_trace",
        surfaces=surfaces,
        failures=failures,
        gateway=gateway,
    )


def _has_gateway_call(result: dict[str, Any]) -> bool:
    for call in result.get("tool_calls", []):
        if not isinstance(call, dict):
            continue
        metadata = call.get("metadata") if isinstance(call.get("metadata"), dict) else {}
        if metadata.get("gateway_decision") or call.get("gateway_decision"):
            return True
    return False


def _surface_cards(reports: list[DashboardReport]) -> str:
    merged: dict[str, SurfaceSummary] = {}
    for report in reports:
        for name, surface in report.surfaces.items():
            target = merged.setdefault(name, SurfaceSummary(name=name))
            target.total += surface.total
            target.passed += surface.passed
            target.failed += surface.failed
            target.evidence.update(surface.evidence)
            target.reasons.update(surface.reasons)
            target.target_types.update(surface.target_types)
    cards: list[str] = []
    for surface in sorted(merged.values(), key=lambda item: (item.failed == 0, -item.failed, item.name)):
        rate = _pct(surface.passed, surface.total)
        risk = "low" if surface.failed == 0 else "high" if rate < 70 else "medium"
        reasons = surface.reasons.most_common(4) or [("no_reason_codes", 1)]
        evidence = surface.evidence.most_common(3) or [("unknown", 1)]
        target_types = surface.target_types.most_common(2)
        chips = "".join(f"<span class='chip'>{_html_safe(label)} ×{count}</span>" for label, count in [*evidence, *reasons, *target_types])
        cards.append(
            f"<article class='card risk {risk}'><div class='rank'>{risk.upper()}</div><h2>{_html_safe(surface.name)}</h2>"
            f"<div class='score'>{surface.passed}/{surface.total}</div><p>{rate:.1f}% pass · {surface.failed} review items</p>"
            f"<div class='chips'>{chips}</div></article>"
        )
    return "".join(cards)


def _gateway_panel(reports: list[DashboardReport]) -> str:
    summary = GatewaySummary()
    for report in reports:
        summary.calls += report.gateway.calls
        summary.blocked += report.gateway.blocked
        summary.policy_hashes.update(report.gateway.policy_hashes)
        summary.reason_codes.update(report.gateway.reason_codes)
    if summary.calls == 0 and summary.blocked == 0 and not summary.reason_codes:
        return ""
    allowed = max(0, summary.calls - summary.blocked)
    block_rate = _pct(summary.blocked, summary.calls)
    reasons = summary.reason_codes.most_common(6) or [("none", 0)]
    policies = summary.policy_hashes.most_common(3) or [("unknown", 0)]
    reason_chips = "".join(f"<span class='chip'>{_html_safe(label)} ×{count}</span>" for label, count in reasons)
    policy_chips = "".join(f"<span class='chip'>policy {_html_safe(label)} ×{count}</span>" for label, count in policies)
    return (
        "<h2>Tool Gateway evidence</h2>"
        "<section class='grid'>"
        f"<article class='card risk {'high' if summary.blocked else 'low'}'><div class='rank'>GATEWAY</div><h2>Tool decisions</h2>"
        f"<div class='score'>{summary.blocked}/{summary.calls}</div><p>{block_rate:.1f}% blocked · {allowed} allowed</p>"
        f"<div class='chips'>{reason_chips}</div></article>"
        f"<article class='card'><div class='rank'>POLICY</div><h2>Gateway policy hash</h2>"
        f"<div class='chips'>{policy_chips}</div></article>"
        "</section>"
    )


def _failure_card(model: str, failure: dict[str, object]) -> str:
    title = failure.get("surface") or failure.get("id", "unknown")
    technical_id = failure.get("id")
    id_line = ""
    if technical_id and str(technical_id) != str(title):
        id_line = f"<p><strong>Technical ID:</strong> <code>{_html_safe(technical_id)}</code></p>"
    return (
        "<section class='failure'>"
        f"<h3>{_html_safe(model)} · {_html_safe(title)}</h3>"
        f"{id_line}"
        f"<p><strong>Surface:</strong> {_html_safe(failure.get('surface', 'unknown'))} · "
        f"<strong>Score:</strong> {_html_safe(failure.get('score', ''))} · "
        f"<strong>Status/Penalty:</strong> {_html_safe(failure.get('penalty', ''))}</p>"
        f"<p><strong>Reason:</strong> {_html_safe(str(failure.get('reason', '')))}</p>"
        f"<pre>{_html_safe(str(failure.get('excerpt', '')), limit=800)}</pre>"
        "</section>"
    )


def write_dashboard(report_paths: list[str | Path], output_dir: str | Path) -> Path:
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "index.html").write_text(render_dashboard(report_paths), encoding="utf-8")
    return destination
