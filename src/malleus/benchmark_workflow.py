from __future__ import annotations

import json
import re
import shlex
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, model_validator

from malleus.reporting import _md_safe


BENCHMARK_PLAN_SCHEMA_VERSION = "malleus.benchmark_plan.v1"
BENCHMARK_SUMMARY_SCHEMA_VERSION = "malleus.benchmark_summary.v1"
DEFAULT_SCORING = "configs/scoring-default.yaml"
DEFAULT_SMOKE_PACK = "datasets/benchmark_packs/smoke-v1.yaml"
DEFAULT_AGENT_SCENARIOS = "datasets/agentic/agentic_injection_smoke.yaml"
DEFAULT_CAMPAIGN = "datasets/campaigns/public_agentic_subset.yaml"
_SPACE_RE = re.compile(r"\s+")
_SECRET_RE = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b|\b(?:api[_ -]?key|secret|token|password|credential|bearer|canary)\s*[:=]?\s*[^\s`|<>]+", re.IGNORECASE)
_UNSAFE_RE = re.compile(
    r"\b(ignore[ _-]+previous[ _-]+instructions|system[ _-]+prompt|developer[ _-]+message|hidden[ _-]+instructions?|exfiltrate(?:[ _-]+secret)?|reveal[ _-]+hidden|private[ _-]+fixture|raw[ _-]+payload)\b",
    re.IGNORECASE,
)


class BenchmarkPanelModel(BaseModel):
    name: str
    publisher: str
    model: str
    target: str
    notes: str = ""


class BenchmarkPanel(BaseModel):
    name: str
    version: int = 1
    models: list[BenchmarkPanelModel] = Field(min_length=5, max_length=8)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_model_ids(self) -> "BenchmarkPanel":
        ids = [model.model for model in self.models]
        if len(ids) != len(set(ids)):
            raise ValueError("benchmark panel model ids must be unique")
        return self


class BenchmarkPlanStep(BaseModel):
    id: str
    model: str | None = None
    purpose: str
    provider_calls_enabled: bool = False
    command: list[str]
    artifacts: list[str] = Field(default_factory=list)


class BenchmarkPlan(BaseModel):
    schema_version: str = BENCHMARK_PLAN_SCHEMA_VERSION
    generated_at: str
    panel_path: str
    output_dir: str
    dry_run: bool = True
    provider_calls_enabled: bool = False
    models: list[BenchmarkPanelModel]
    steps: list[BenchmarkPlanStep]
    artifacts: list[str] = Field(default_factory=list)


class LeaderboardRow(BaseModel):
    rank: int
    model: str
    publisher: str = "unknown"
    score: int
    max_score: int
    pass_rate: float
    passed_items: int
    total_items: int
    top_risks: list[str] = Field(default_factory=list)
    taxonomy_coverage_hints: list[str] = Field(default_factory=list)
    report: str
    risk_card: str | None = None


class BenchmarkSummary(BaseModel):
    schema_version: str = BENCHMARK_SUMMARY_SCHEMA_VERSION
    generated_at: str
    reports_path: str
    output_dir: str
    leaderboard: list[LeaderboardRow]
    case_studies: list[str] = Field(default_factory=list)
    readme_written: str | None = None


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip("-.").lower()
    return slug or "model"


def _safe_text(value: object, *, limit: int = 240) -> str:
    text = _SPACE_RE.sub(" ", str(value)).strip()
    text = _SECRET_RE.sub("[REDACTED]", text)
    text = _UNSAFE_RE.sub("[REDACTED]", text)
    return text[:limit] + ("..." if len(text) > limit else "")


def _safe_relpath(path: Path, base: Path) -> str:
    try:
        rel = path.resolve().relative_to(base.resolve())
        raw = str(rel).replace("\\", "/")
    except ValueError:
        raw = path.name
    return _safe_text(raw, limit=240)


def load_benchmark_panel(path: str | Path) -> BenchmarkPanel:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError("benchmark panel YAML must contain a mapping")
    return BenchmarkPanel.model_validate(data)


def _command(*parts: object) -> list[str]:
    return [str(part) for part in parts]


def _load_target_template(path: str | Path) -> dict[str, Any]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"target YAML must contain a mapping: {path}")
    return data


def _write_panel_target(model: BenchmarkPanelModel, target_path: Path) -> Path:
    target = dict(_load_target_template(model.target))
    target["name"] = f"benchmark-{_slug(model.model)}"
    target["model"] = model.model
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(yaml.safe_dump(target, sort_keys=False), encoding="utf-8")
    return target_path


def build_benchmark_plan(panel_path: str | Path, out_dir: str | Path, *, dry_run: bool = True) -> BenchmarkPlan:
    panel = load_benchmark_panel(panel_path)
    destination = Path(out_dir)
    steps: list[BenchmarkPlanStep] = []
    artifacts: list[str] = []
    for model in panel.models:
        slug = _slug(model.model)
        target_path = destination / "targets" / f"{slug}.yaml"
        _write_panel_target(model, target_path)
        model_root = destination / "models" / slug
        smoke_dir = model_root / "smoke"
        mutation_dir = model_root / "mutations"
        agent_dir = model_root / "agent-lab"
        campaign_dir = model_root / "campaign"
        steps.extend(
            [
                BenchmarkPlanStep(
                    id=f"{slug}-smoke",
                    model=model.model,
                    purpose="Smoke benchmark dry-run plan for the public panel model.",
                    command=_command("malleus", "run", "--target", target_path, "--input", DEFAULT_SMOKE_PACK, "--scoring", DEFAULT_SCORING, "--out-dir", smoke_dir, "--dry-run"),
                    artifacts=[str(target_path), str(smoke_dir / "dry-run.json"), str(smoke_dir / "dry-run.md"), str(smoke_dir / "model-risk-card.md")],
                ),
                BenchmarkPlanStep(
                    id=f"{slug}-mutations",
                    model=model.model,
                    purpose="Mutation robustness dry-run plan for selected smoke cases.",
                    command=_command("malleus", "mutate-run", "--target", target_path, "--input", DEFAULT_SMOKE_PACK, "--scoring", DEFAULT_SCORING, "--out-dir", mutation_dir, "--limit", 2, "--dry-run"),
                    artifacts=[str(mutation_dir / "mutation-dry-run.json"), str(mutation_dir / "mutation-dry-run.md")],
                ),
                BenchmarkPlanStep(
                    id=f"{slug}-agent-lab",
                    model=model.model,
                    purpose="Agentic injection lab dry-run plan using local scenarios.",
                    command=_command("malleus", "agent-lab", "--target", target_path, "--scenarios", DEFAULT_AGENT_SCENARIOS, "--out-dir", agent_dir, "--limit", 2, "--dry-run"),
                    artifacts=[str(agent_dir / "agent-lab-dry-run.json"), str(agent_dir / "agent-lab-dry-run.md")],
                ),
                BenchmarkPlanStep(
                    id=f"{slug}-campaign",
                    model=model.model,
                    purpose="Campaign subset dry-run plan using synthetic local campaign metadata.",
                    command=_command("malleus", "campaign", "run", "--campaign", DEFAULT_CAMPAIGN, "--target", target_path, "--out-dir", campaign_dir, "--dry-run"),
                    artifacts=[str(campaign_dir / "campaign-report.json"), str(campaign_dir / "campaign-report.md")],
                ),
            ]
        )
        artifacts.extend(steps[-4].artifacts + steps[-3].artifacts + steps[-2].artifacts + steps[-1].artifacts)
    coverage_dir = destination / "coverage"
    bundle_dir = destination / "evidence-bundle"
    steps.extend(
        [
            BenchmarkPlanStep(
                id="coverage-build",
                purpose="Build taxonomy coverage matrix from local packs, campaign, and agent scenarios.",
                command=_command("malleus", "coverage", "build", "--input", DEFAULT_SMOKE_PACK, "--campaign", DEFAULT_CAMPAIGN, "--agent-scenarios", DEFAULT_AGENT_SCENARIOS, "--out-dir", coverage_dir),
                artifacts=[str(coverage_dir / "coverage.json"), str(coverage_dir / "coverage.md"), str(coverage_dir / "coverage.html")],
            ),
            BenchmarkPlanStep(
                id="evidence-bundle-audit",
                purpose="Prepare local audit-mode evidence bundle from generated artifacts.",
                command=_command(
                    "malleus",
                    "evidence-bundle",
                    "--audit-mode",
                    "--title",
                    "Malleus Public WOW Benchmark Evidence",
                    "--out-dir",
                    bundle_dir,
                    *[part for step in steps if step.model for artifact in step.artifacts for part in ("--run-report", artifact) if artifact.endswith("dry-run.json")],
                    *[part for step in steps if step.model for artifact in step.artifacts for part in ("--mutation-report", artifact) if artifact.endswith("mutation-dry-run.json")],
                    *[part for step in steps if step.model for artifact in step.artifacts for part in ("--agent-report", artifact) if artifact.endswith("agent-lab-dry-run.json")],
                ),
                artifacts=[str(bundle_dir / "index.html"), str(bundle_dir / "audit-summary.md"), str(bundle_dir / "artifact-index.json")],
            ),
        ]
    )
    artifacts.extend(steps[-2].artifacts + steps[-1].artifacts)
    return BenchmarkPlan(generated_at=_now(), panel_path=str(panel_path), output_dir=str(destination), dry_run=dry_run, provider_calls_enabled=False, models=panel.models, steps=steps, artifacts=artifacts)


def render_benchmark_plan_markdown(plan: BenchmarkPlan) -> str:
    lines = [
        "# Malleus public benchmark evidence plan",
        "",
        f"- Panel: {_md_safe(plan.panel_path)}",
        f"- Output directory: {_md_safe(plan.output_dir)}",
        f"- Provider calls enabled: {str(plan.provider_calls_enabled).lower()}",
        f"- Models: {len(plan.models)}",
        "",
        "## Planned commands",
        "",
    ]
    for step in plan.steps:
        command = _md_safe(shlex.join(step.command))
        lines.extend([f"### {_md_safe(step.id)}", "", f"- Purpose: {_md_safe(step.purpose)}", f"- Provider calls enabled: {str(step.provider_calls_enabled).lower()}", "", "```bash", command, "```", ""])
        if step.artifacts:
            lines.append("Artifacts:")
            for artifact in step.artifacts:
                lines.append(f"- `{_md_safe(artifact)}`")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def write_benchmark_plan(panel_path: str | Path, out_dir: str | Path, *, dry_run: bool = True) -> tuple[BenchmarkPlan, Path, Path]:
    destination = Path(out_dir)
    destination.mkdir(parents=True, exist_ok=True)
    plan = build_benchmark_plan(panel_path, destination, dry_run=dry_run)
    json_path = destination / "benchmark-plan.json"
    markdown_path = destination / "benchmark-plan.md"
    json_path.write_text(plan.model_dump_json(indent=2), encoding="utf-8")
    markdown_path.write_text(render_benchmark_plan_markdown(plan), encoding="utf-8")
    return plan, json_path, markdown_path


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    return data if isinstance(data, dict) else None


def _report_paths(reports: str | Path) -> list[Path]:
    root = Path(reports)
    if root.is_file():
        return [root]
    return sorted(root.glob("**/report.json"), key=lambda path: str(path))


def _metadata_hints(result: dict[str, Any]) -> list[str]:
    metadata = result.get("metadata") if isinstance(result.get("metadata"), dict) else {}
    hints: list[str] = []
    for key in ("owasp", "nist", "malleus_surface", "malleus_technique", "malleus_boundary", "avid_effect", "maps_to"):
        value = metadata.get(key)
        if isinstance(value, list):
            hints.extend(_safe_text(item, limit=80) for item in value[:3])
        elif value:
            hints.append(_safe_text(value, limit=80))
    return sorted(dict.fromkeys(hint for hint in hints if hint))[:6]


def _collect_risks(report: dict[str, Any]) -> tuple[list[str], list[str], list[dict[str, Any]]]:
    risks: list[str] = []
    hints: list[str] = []
    failures: list[dict[str, Any]] = []
    for dataset in report.get("datasets", []) if isinstance(report.get("datasets"), list) else []:
        if not isinstance(dataset, dict):
            continue
        for result in list(dataset.get("case_results") or []) + list(dataset.get("group_results") or []):
            if not isinstance(result, dict):
                continue
            hints.extend(_metadata_hints(result))
            if result.get("passed") is False:
                case_id = result.get("case_id") or result.get("group_id") or "unknown"
                severity = result.get("severity") or "unknown"
                objective = _safe_text(result.get("objective") or case_id, limit=120)
                safe_case_id = _safe_text(case_id, limit=120)
                safe_severity = _safe_text(severity, limit=40)
                risks.append(f"{safe_severity}:{safe_case_id}")
                failures.append({"id": safe_case_id, "severity": safe_severity, "objective": objective, "taxonomy": _metadata_hints(result)})
    return sorted(dict.fromkeys(risks))[:5], sorted(dict.fromkeys(hints))[:8], failures


def _publisher(report: dict[str, Any]) -> str:
    metadata = report.get("metadata") if isinstance(report.get("metadata"), dict) else {}
    return _safe_text(metadata.get("publisher") or "unknown", limit=80)


def _risk_card_for(report_path: Path, base: Path) -> str | None:
    risk_card = report_path.parent / "model-risk-card.md"
    if risk_card.exists():
        return _safe_relpath(risk_card, base)
    return None


def _leaderboard_rows(reports: Path) -> tuple[list[LeaderboardRow], list[dict[str, Any]]]:
    rows: list[LeaderboardRow] = []
    failures: list[dict[str, Any]] = []
    for path in _report_paths(reports):
        report = _load_json(path)
        if not report:
            continue
        summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
        score = int(summary.get("score_total") or 0)
        max_score = int(summary.get("max_score_total") or 0)
        passed = int(summary.get("passed_items") or 0)
        total = int(summary.get("total_items") or 0)
        risks, hints, report_failures = _collect_risks(report)
        model = _safe_text(report.get("target_model") or path.parent.name, limit=120)
        for failure in report_failures:
            failure["model"] = model
            failure["report"] = _safe_relpath(path, reports)
        failures.extend(report_failures)
        rows.append(
            LeaderboardRow(
                rank=0,
                model=model,
                publisher=_publisher(report),
                score=score,
                max_score=max_score,
                pass_rate=0.0 if total == 0 else (passed / total) * 100,
                passed_items=passed,
                total_items=total,
                top_risks=risks or ["none"],
                taxonomy_coverage_hints=hints or ["none"],
                report=_safe_relpath(path, reports),
                risk_card=_risk_card_for(path, reports),
            )
        )
    rows.sort(key=lambda row: (row.pass_rate, row.score), reverse=True)
    for index, row in enumerate(rows, start=1):
        row.rank = index
    return rows, failures


def render_leaderboard_markdown(summary: BenchmarkSummary) -> str:
    lines = [
        "# Malleus public benchmark leaderboard",
        "",
        "Local fixture summary only. It does not run models or edit source docs by default.",
        "",
        "| Rank | Model | Publisher | Score | Pass rate | Top risks | Taxonomy hints | Risk card |",
        "|---:|---|---|---:|---:|---|---|---|",
    ]
    for row in summary.leaderboard:
        risk_card = row.risk_card or "n/a"
        lines.append(f"| {row.rank} | {_md_safe(row.model)} | {_md_safe(row.publisher)} | {row.score}/{row.max_score} | {row.pass_rate:.1f}% | {_md_safe(', '.join(row.top_risks))} | {_md_safe(', '.join(row.taxonomy_coverage_hints))} | {_md_safe(risk_card)} |")
    lines.extend(["", "## Case-study skeletons", ""])
    for path in summary.case_studies:
        lines.append(f"- `{_md_safe(path)}`")
    return "\n".join(lines).rstrip() + "\n"


def _case_study_markdown(index: int, failure: dict[str, Any]) -> str:
    taxonomy = failure.get("taxonomy") if isinstance(failure.get("taxonomy"), list) else []
    lines = [
        f"# Case study skeleton {index}: {_md_safe(failure.get('id', 'unknown'))}",
        "",
        "This template is sanitized. It intentionally omits raw prompts, raw model output, unsafe instruction text, and secret-like values.",
        "",
        "## Evidence summary",
        "",
        f"- Model: {_md_safe(failure.get('model', 'unknown'))}",
        f"- Case: {_md_safe(failure.get('id', 'unknown'))}",
        f"- Severity: {_md_safe(failure.get('severity', 'unknown'))}",
        f"- Objective: {_md_safe(failure.get('objective', 'n/a'))}",
        f"- Report: `{_md_safe(failure.get('report', 'n/a'))}`",
        f"- Taxonomy hints: {_md_safe(', '.join(str(item) for item in taxonomy) or 'none')}",
        "",
        "## Analyst notes",
        "",
        "- Expected boundary:",
        "- Observed failure pattern:",
        "- Defensive recommendation:",
        "- Follow-up regression command:",
        "",
    ]
    return "\n".join(lines)


def _write_case_studies(failures: list[dict[str, Any]], out_dir: Path, reports_base: Path) -> list[str]:
    case_dir = out_dir / "case-studies"
    case_dir.mkdir(parents=True, exist_ok=True)
    selected = failures[:3] or [
        {"id": "no-failures-summary", "model": "n/a", "severity": "n/a", "objective": "No failing fixture cases were present.", "report": "n/a", "taxonomy": []},
        {"id": "analyst-review-template", "model": "n/a", "severity": "n/a", "objective": "Use this template for qualitative analyst notes when fixture reports have no failures.", "report": "n/a", "taxonomy": []},
    ]
    paths: list[str] = []
    for index, failure in enumerate(selected, start=1):
        path = case_dir / f"case-study-{index}-{_slug(_safe_text(failure.get('id', 'case'), limit=80))}.md"
        path.write_text(_case_study_markdown(index, failure), encoding="utf-8")
        paths.append(_safe_relpath(path, out_dir))
    return paths


def _readme_block(summary: BenchmarkSummary) -> str:
    return "\n".join(["<!-- malleus-benchmark:start -->", render_leaderboard_markdown(summary).rstrip(), "<!-- malleus-benchmark:end -->", ""])


def _write_readme_block(path: Path, summary: BenchmarkSummary) -> None:
    block = _readme_block(summary)
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    pattern = re.compile(r"<!-- malleus-benchmark:start -->.*?<!-- malleus-benchmark:end -->\n?", re.DOTALL)
    if pattern.search(existing):
        updated = pattern.sub(block, existing)
    else:
        updated = existing.rstrip() + "\n\n" + block
    path.write_text(updated, encoding="utf-8")


def summarize_benchmark_reports(reports: str | Path, out_dir: str | Path, *, write_readme: str | Path | None = None) -> tuple[BenchmarkSummary, Path, Path]:
    reports_base = Path(reports)
    destination = Path(out_dir)
    destination.mkdir(parents=True, exist_ok=True)
    rows, failures = _leaderboard_rows(reports_base)
    case_studies = _write_case_studies(failures, destination, reports_base)
    summary = BenchmarkSummary(generated_at=_now(), reports_path=_safe_text(reports_base, limit=240), output_dir=_safe_text(destination, limit=240), leaderboard=rows, case_studies=case_studies)
    if write_readme is not None:
        readme_path = Path(write_readme)
        _write_readme_block(readme_path, summary)
        summary.readme_written = str(readme_path)
    json_path = destination / "leaderboard.json"
    markdown_path = destination / "leaderboard.md"
    json_path.write_text(summary.model_dump_json(indent=2), encoding="utf-8")
    markdown_path.write_text(render_leaderboard_markdown(summary), encoding="utf-8")
    return summary, json_path, markdown_path
