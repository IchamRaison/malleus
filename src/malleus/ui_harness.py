from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, Field, model_validator

from malleus.schemas import (
    EvaluationSurface,
    EvidenceRecord,
    EvidenceRef,
    RedactionMetadata,
    WowppReportMetadata,
    REPORT_MODE_DRY_RUN,
    REPORT_MODE_SCAFFOLD,
)
from malleus.utils.ids import new_run_id
from malleus.utils.redact import REDACTION_MARKER, redact_public_text, redaction_label, scan_public_artifact_text, sha256_text

UI_HARNESS_PLAN_SCHEMA_VERSION = "malleus.ui_harness.plan.v1"
UI_HARNESS_REPORT_SCHEMA_VERSION = "malleus.ui_harness.report.v1"
_SENSITIVE_KEY_RE = re.compile(r"(cookie|token|authorization|auth|session|secret|password|credential|api[_-]?key)", re.IGNORECASE)
_UNSAFE_PROMPT_RE = re.compile(
    r"\b(ignore[ _-]+previous|system[ _-]+prompt|developer[ _-]+message|reveal[ _-]+secret|exfiltrate|token|cookie|authorization|session)\b",
    re.IGNORECASE,
)


class UIHarnessConfig(BaseModel):
    product: str
    environment: Literal["local", "staging"] = "local"
    target_url: str
    selectors: dict[str, Any] = Field(default_factory=dict)
    prompts: list[dict[str, Any]] = Field(default_factory=list, min_length=1)
    redaction_rules: list[str] = Field(default_factory=lambda: ["cookie", "token", "authorization", "session", "secret", "password"])
    expected_extraction: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_environment_url(self) -> "UIHarnessConfig":
        validate_ui_url(self.target_url, live_ui=False, allowed_urls=[])
        return self


class UIHarnessSelectorSummary(BaseModel):
    name: str
    value_sha256: str
    value_length: int
    redacted_preview: str


class UIHarnessPromptSummary(BaseModel):
    prompt_id: str
    sha256: str
    length: int
    redacted_preview: str
    submit_selector: str | None = None
    expected_extraction: dict[str, Any] = Field(default_factory=dict)


class UIHarnessScreenshotPlaceholder(BaseModel):
    label: str
    placeholder_path: str
    real_screenshot: bool = False
    note: str = "Placeholder only; no browser was launched and no screenshot was captured."


class UIHarnessFinding(BaseModel):
    finding_id: str
    title: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    status: Literal["pass", "warn", "fail", "error"] = "warn"
    description: str
    evidence_ref: str
    redacted_preview: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class UIHarnessScore(BaseModel):
    max_score: int = 100
    score: int = 100
    status: Literal["planned", "pass", "warn", "fail"] = "planned"
    rationale: str = "Dry-run scaffold only; no browser, provider, or product interaction occurred."


class UIHarnessSummary(BaseModel):
    product: str
    environment: str
    planned_submissions: int
    selectors: int
    findings: int
    provider_calls_enabled: bool = False
    browser_enabled: bool = False
    screenshots_captured: int = 0


class UIHarnessPlan(BaseModel):
    schema_version: str = UI_HARNESS_PLAN_SCHEMA_VERSION
    run_id: str
    generated_at: str
    mode: str = REPORT_MODE_DRY_RUN
    dry_run: bool = True
    provider_calls_enabled: bool = False
    browser_enabled: bool = False
    live_ui_requested: bool = False
    config_ref: str
    target: dict[str, Any]
    selectors: list[UIHarnessSelectorSummary] = Field(default_factory=list)
    planned_prompt_submissions: list[UIHarnessPromptSummary] = Field(default_factory=list)
    expected_extraction: dict[str, Any] = Field(default_factory=dict)
    screenshot_placeholders: list[UIHarnessScreenshotPlaceholder] = Field(default_factory=list)
    redaction_rules: list[str] = Field(default_factory=list)
    findings_shape: list[UIHarnessFinding] = Field(default_factory=list)
    scoring: UIHarnessScore = Field(default_factory=UIHarnessScore)
    summary: UIHarnessSummary
    wowpp_metadata: WowppReportMetadata


class UIHarnessReport(BaseModel):
    schema_version: str = UI_HARNESS_REPORT_SCHEMA_VERSION
    run_id: str
    generated_at: str
    mode: str = REPORT_MODE_DRY_RUN
    dry_run: bool = True
    provider_calls_enabled: bool = False
    browser_enabled: bool = False
    live_ui_requested: bool = False
    source_plan: str
    target: dict[str, Any]
    submissions: list[UIHarnessPromptSummary] = Field(default_factory=list)
    extracted_context: list[dict[str, Any]] = Field(default_factory=list)
    screenshot_placeholders: list[UIHarnessScreenshotPlaceholder] = Field(default_factory=list)
    findings: list[UIHarnessFinding] = Field(default_factory=list)
    scoring: UIHarnessScore = Field(default_factory=UIHarnessScore)
    summary: UIHarnessSummary
    wowpp_metadata: WowppReportMetadata


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _safe_label(value: object, *, limit: int = 120) -> str:
    text = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value)).strip("-.").lower()
    return (text or "ui")[:limit]


def _safe_relpath(path: Path, base: Path | None = None) -> str:
    try:
        root = (base or Path.cwd()).resolve()
        return str(path.resolve().relative_to(root)).replace("\\", "/")
    except ValueError:
        return path.name


def _load_config(config_path: str | Path) -> UIHarnessConfig:
    data = yaml.safe_load(Path(config_path).read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError("ui harness config YAML must contain a mapping")
    return UIHarnessConfig.model_validate(data)


def _is_local_or_staging_url(value: str) -> bool:
    parsed = urlparse(value)
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"http", "https"} or not host:
        return False
    if host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".local"):
        return True
    if host.startswith("staging.") or ".staging." in host or host.endswith(".staging"):
        return True
    return False


def _url_matches_allowlist(value: str, allowed_urls: list[str]) -> bool:
    parsed = urlparse(value)
    origin = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    host = (parsed.hostname or "").lower()
    for allowed in allowed_urls:
        allowed_parsed = urlparse(allowed if "://" in allowed else f"https://{allowed}")
        allowed_origin = f"{allowed_parsed.scheme}://{allowed_parsed.netloc}".rstrip("/")
        allowed_host = (allowed_parsed.hostname or allowed).lower().strip("/")
        if origin == allowed_origin or host == allowed_host:
            return True
    return False


def validate_ui_url(target_url: str, *, live_ui: bool, allowed_urls: list[str]) -> None:
    if not _is_local_or_staging_url(target_url):
        raise ValueError("ui harness fail-closed: target URL must be local or staging; third-party UI automation is not allowed")
    if live_ui and (not allowed_urls or not _url_matches_allowlist(target_url, allowed_urls)):
        raise ValueError("ui harness fail-closed: --live-ui requires an explicit --allowed-url matching the local/staging target")


def _redact_config_value(key: str, value: Any) -> Any:
    if isinstance(value, dict):
        return {str(child_key): _redact_config_value(str(child_key), child_value) for child_key, child_value in sorted(value.items())}
    if isinstance(value, list):
        return [_redact_config_value(key, item) for item in value]
    text = str(value)
    if _SENSITIVE_KEY_RE.search(key) or _SENSITIVE_KEY_RE.search(text):
        return redaction_label(text, kind="ui_config")
    redacted = redact_public_text(text, limit=180)
    return redacted.text


def _selector_summaries(selectors: dict[str, Any]) -> list[UIHarnessSelectorSummary]:
    rows: list[UIHarnessSelectorSummary] = []
    for key, value in sorted(selectors.items()):
        raw = json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else str(value)
        rows.append(
            UIHarnessSelectorSummary(
                name=str(key),
                value_sha256=sha256_text(raw),
                value_length=len(raw),
                redacted_preview=str(_redact_config_value(str(key), value)),
            )
        )
    return rows


def _prompt_preview(text: str) -> str:
    redacted = redact_public_text(text, limit=160)
    preview = redacted.text
    if _UNSAFE_PROMPT_RE.search(text) and REDACTION_MARKER not in preview:
        preview = redaction_label(text, kind="prompt")
    return preview


def _prompt_summaries(config: UIHarnessConfig) -> list[UIHarnessPromptSummary]:
    rows: list[UIHarnessPromptSummary] = []
    for index, prompt in enumerate(config.prompts, start=1):
        raw = str(prompt.get("body") or prompt.get("prompt") or prompt.get("text") or "")
        prompt_id = str(prompt.get("id") or f"prompt-{index}")
        expected = prompt.get("expected_extraction") if isinstance(prompt.get("expected_extraction"), dict) else config.expected_extraction
        rows.append(
            UIHarnessPromptSummary(
                prompt_id=_safe_label(prompt_id),
                sha256=sha256_text(raw),
                length=len(raw),
                redacted_preview=_prompt_preview(raw),
                submit_selector=str(prompt.get("submit_selector")) if prompt.get("submit_selector") else None,
                expected_extraction=_redact_config_value("expected_extraction", expected),
            )
        )
    return rows


def _target_summary(config: UIHarnessConfig) -> dict[str, Any]:
    parsed = urlparse(config.target_url)
    host = parsed.hostname or ""
    local_url = host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".local")
    return {
        "product": redact_public_text(config.product, limit=120).text,
        "environment": config.environment,
        "url_class": "local" if local_url else "staging",
        "target_url_ref": "local-ui-target" if local_url else "staging-ui-target-redacted",
        "host_sha256": sha256_text(host) if host else None,
        "url_length": len(config.target_url),
    }


def _placeholder_rows(prompts: list[UIHarnessPromptSummary]) -> list[UIHarnessScreenshotPlaceholder]:
    return [
        UIHarnessScreenshotPlaceholder(
            label=f"placeholder-before-after-{prompt.prompt_id}",
            placeholder_path=f"screenshots/PLACEHOLDER-{prompt.prompt_id}.png",
        )
        for prompt in prompts
    ]


def _finding_shape(prompts: list[UIHarnessPromptSummary]) -> list[UIHarnessFinding]:
    return [
        UIHarnessFinding(
            finding_id="uih-scaffold-finding-shape",
            title="UI harness finding shape placeholder",
            severity="info",
            status="warn",
            description="Downstream live/local UI harness reports should populate findings with sanitized evidence refs, severity, status, and redacted previews.",
            evidence_ref="ui-harness-report.json#/findings/0",
            redacted_preview=redaction_label("ui harness dry-run finding shape", kind="finding_shape"),
            metadata={"planned_prompt_count": len(prompts), "browser_enabled": False},
        )
    ]


def _wowpp_metadata(config_ref: str, prompts: list[UIHarnessPromptSummary], screenshots: list[UIHarnessScreenshotPlaceholder]) -> WowppReportMetadata:
    surfaces = [
        EvaluationSurface(
            surface_id=f"ui_prompt_{prompt.prompt_id}",
            name=f"UI prompt submission {prompt.prompt_id}",
            category="ui_harness",
            modality="browser_form",
            metadata={"mode": REPORT_MODE_DRY_RUN, "trust_label": "untrusted"},
        )
        for prompt in prompts
    ]
    records: list[EvidenceRecord] = []
    hashes: dict[str, str] = {}
    for prompt in prompts:
        evidence_id = f"uih-prompt-{prompt.prompt_id}"
        records.append(
            EvidenceRecord(
                evidence_id=evidence_id,
                mode=REPORT_MODE_DRY_RUN,
                artifact=EvidenceRef(
                    evidence_id=evidence_id,
                    artifact_path=f"ui-harness-plan.json#/planned_prompt_submissions/{prompt.prompt_id}",
                    artifact_type="ui_prompt_plan",
                    sha256=prompt.sha256,
                    redacted_preview=prompt.redacted_preview,
                ),
                artifact_sha256=prompt.sha256,
                artifact_length=prompt.length,
                redacted_preview=prompt.redacted_preview,
                redaction=RedactionMetadata(status="redacted", sha256=prompt.sha256, length=prompt.length, marker=REDACTION_MARKER),
                metadata={"config_ref": config_ref, "browser_enabled": False},
            )
        )
    for screenshot in screenshots:
        hashes[screenshot.placeholder_path] = sha256_text(screenshot.placeholder_path)
    return WowppReportMetadata(
        mode=REPORT_MODE_DRY_RUN,
        provider_calls_enabled=False,
        evaluation_surfaces=surfaces,
        evidence_records=records,
        artifact_hashes=hashes,
        metadata={"generator": "ui_harness", "browser_enabled": False, "screenshots_are_placeholders": True},
    )


def build_ui_harness_plan(
    config_path: str | Path,
    out_dir: str | Path,
    *,
    dry_run: bool = True,
    live_ui: bool = False,
    allowed_urls: list[str] | None = None,
) -> UIHarnessPlan:
    if not dry_run:
        raise ValueError("ui harness currently supports dry-run scaffold artifacts only; use --dry-run")
    config = _load_config(config_path)
    validate_ui_url(config.target_url, live_ui=live_ui, allowed_urls=list(allowed_urls or []))
    prompts = _prompt_summaries(config)
    screenshots = _placeholder_rows(prompts)
    findings = _finding_shape(prompts)
    summary = UIHarnessSummary(
        product=redact_public_text(config.product, limit=120).text,
        environment=config.environment,
        planned_submissions=len(prompts),
        selectors=len(config.selectors),
        findings=len(findings),
    )
    config_ref = _safe_relpath(Path(config_path))
    return UIHarnessPlan(
        run_id=new_run_id(),
        generated_at=_now(),
        mode=REPORT_MODE_SCAFFOLD if live_ui else REPORT_MODE_DRY_RUN,
        dry_run=True,
        provider_calls_enabled=False,
        browser_enabled=False,
        live_ui_requested=live_ui,
        config_ref=config_ref,
        target=_target_summary(config),
        selectors=_selector_summaries(config.selectors),
        planned_prompt_submissions=prompts,
        expected_extraction=_redact_config_value("expected_extraction", config.expected_extraction),
        screenshot_placeholders=screenshots,
        redaction_rules=list(config.redaction_rules),
        findings_shape=findings,
        scoring=UIHarnessScore(),
        summary=summary,
        wowpp_metadata=_wowpp_metadata(config_ref, prompts, screenshots),
    )


def render_ui_harness_plan_markdown(plan: UIHarnessPlan) -> str:
    lines = [
        "# Malleus UI harness dry-run plan",
        "",
        f"- Run: {plan.run_id}",
        f"- Product: {plan.summary.product}",
        f"- Environment: {plan.summary.environment}",
        f"- Provider calls enabled: {str(plan.provider_calls_enabled).lower()}",
        f"- Browser enabled: {str(plan.browser_enabled).lower()}",
        f"- Live UI requested: {str(plan.live_ui_requested).lower()}",
        f"- Target URL ref: {plan.target['target_url_ref']}",
        "- Screenshot handling: placeholders only; no browser was launched and no screenshot was captured.",
        "",
        "## Selectors",
        "",
        "| Name | SHA-256 | Length | Redacted preview |",
        "| --- | --- | ---: | --- |",
    ]
    lines.extend(f"| {row.name} | `{row.value_sha256}` | {row.value_length} | `{row.redacted_preview}` |" for row in plan.selectors)
    lines.extend(["", "## Planned prompt submissions", "", "| Prompt | SHA-256 | Length | Expected extraction |", "| --- | --- | ---: | --- |"])
    for prompt in plan.planned_prompt_submissions:
        expected = json.dumps(prompt.expected_extraction, sort_keys=True)
        lines.append(f"| {prompt.prompt_id} | `{prompt.sha256}` | {prompt.length} | `{expected}` |")
    lines.extend(["", "## Screenshot placeholders", ""])
    lines.extend(f"- `{shot.placeholder_path}` — {shot.note}" for shot in plan.screenshot_placeholders)
    lines.extend(["", "## Finding shape", ""])
    lines.extend(f"- {finding.finding_id}: {finding.severity}/{finding.status} — {finding.description}" for finding in plan.findings_shape)
    lines.extend(["", "## Scoring shape", "", f"- Status: {plan.scoring.status}", f"- Score: {plan.scoring.score}/{plan.scoring.max_score}", f"- Rationale: {plan.scoring.rationale}"])
    return "\n".join(lines).rstrip() + "\n"


def write_ui_harness_plan(config_path: str | Path, out_dir: str | Path, *, dry_run: bool = True, live_ui: bool = False, allowed_urls: list[str] | None = None) -> tuple[UIHarnessPlan, Path, Path]:
    destination = Path(out_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    plan = build_ui_harness_plan(config_path, destination, dry_run=dry_run, live_ui=live_ui, allowed_urls=allowed_urls)
    json_path = destination / "ui-harness-plan.json"
    markdown_path = destination / "ui-harness-plan.md"
    json_path.write_text(plan.model_dump_json(indent=2), encoding="utf-8")
    markdown_path.write_text(render_ui_harness_plan_markdown(plan), encoding="utf-8")
    _assert_public_safe(json_path, markdown_path)
    return plan, json_path, markdown_path


def build_ui_harness_report(plan: UIHarnessPlan) -> UIHarnessReport:
    extracted = [
        {
            "extraction_id": f"expected-{prompt.prompt_id}",
            "mode": REPORT_MODE_DRY_RUN,
            "source_prompt_id": prompt.prompt_id,
            "expected_extraction": prompt.expected_extraction,
            "redacted_preview": redaction_label(json.dumps(prompt.expected_extraction, sort_keys=True), kind="expected_extraction"),
            "sha256": sha256_text(json.dumps(prompt.expected_extraction, sort_keys=True)),
        }
        for prompt in plan.planned_prompt_submissions
    ]
    findings = [finding.model_copy(update={"finding_id": "uih-dry-run-no-browser", "title": "Dry-run scaffold produced no live UI findings"}) for finding in plan.findings_shape]
    return UIHarnessReport(
        run_id=plan.run_id,
        generated_at=_now(),
        mode=plan.mode,
        dry_run=True,
        provider_calls_enabled=False,
        browser_enabled=False,
        live_ui_requested=plan.live_ui_requested,
        source_plan="ui-harness-plan.json",
        target=plan.target,
        submissions=plan.planned_prompt_submissions,
        extracted_context=extracted,
        screenshot_placeholders=plan.screenshot_placeholders,
        findings=findings,
        scoring=plan.scoring,
        summary=plan.summary.model_copy(update={"findings": len(findings)}),
        wowpp_metadata=plan.wowpp_metadata,
    )


def render_ui_harness_report_markdown(report: UIHarnessReport) -> str:
    lines = [
        "# Malleus UI harness dry-run report",
        "",
        f"- Run: {report.run_id}",
        f"- Mode: {report.mode}",
        f"- Provider calls enabled: {str(report.provider_calls_enabled).lower()}",
        f"- Browser enabled: {str(report.browser_enabled).lower()}",
        f"- Planned submissions: {report.summary.planned_submissions}",
        f"- Screenshots captured: {report.summary.screenshots_captured}",
        "- Screenshot paths below are placeholders, not real screenshots.",
        "",
        "## Submissions",
        "",
    ]
    for prompt in report.submissions:
        lines.extend([f"### {prompt.prompt_id}", "", f"- SHA-256: `{prompt.sha256}`", f"- Length: {prompt.length}", f"- Redacted preview: `{prompt.redacted_preview}`", ""])
    lines.extend(["## Findings", ""])
    lines.extend(f"- {finding.finding_id}: {finding.severity}/{finding.status} — {finding.description}" for finding in report.findings)
    lines.extend(["", "## Screenshot placeholders", ""])
    lines.extend(f"- `{shot.placeholder_path}` — placeholder only; real_screenshot={str(shot.real_screenshot).lower()}" for shot in report.screenshot_placeholders)
    return "\n".join(lines).rstrip() + "\n"


def write_ui_harness_report(config_path: str | Path, out_dir: str | Path, *, dry_run: bool = True, live_ui: bool = False, allowed_urls: list[str] | None = None) -> tuple[UIHarnessReport, Path, Path]:
    destination = Path(out_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    plan, plan_json, plan_md = write_ui_harness_plan(config_path, destination, dry_run=dry_run, live_ui=live_ui, allowed_urls=allowed_urls)
    report = build_ui_harness_report(plan)
    json_path = destination / "ui-harness-report.json"
    markdown_path = destination / "ui-harness-report.md"
    json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    markdown_path.write_text(render_ui_harness_report_markdown(report), encoding="utf-8")
    _assert_public_safe(plan_json, plan_md, json_path, markdown_path)
    return report, json_path, markdown_path


def _assert_public_safe(*paths: Path) -> None:
    combined = "\n".join(path.read_text(encoding="utf-8") for path in paths if path.exists())
    scan = scan_public_artifact_text(combined)
    if not scan.passed:
        raise ValueError(f"ui harness public artifact scan failed: {', '.join(scan.findings)}")
    forbidden = ["/home/", "https://example.com", "http://example.com"]
    leaked = [item for item in forbidden if item in combined]
    if leaked:
        raise ValueError(f"ui harness public artifact contains forbidden value: {', '.join(leaked)}")
