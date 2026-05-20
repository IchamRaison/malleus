from __future__ import annotations

import json
import re
from html import escape as html_escape
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from malleus.utils.redact import redact_public_text

ItemKind = Literal["case", "group"]
Transition = Literal["unchanged", "regressed", "improved", "changed", "provider_error", "added", "removed", "incompatible"]
ComparisonStatus = Literal["PASS", "REVIEW", "ERROR"]

_COMPATIBLE_SCHEMA_VERSIONS = {None, "malleus.run_report.v1", "malleus.dry_run_report.v1"}
_FAILURE_VERDICTS = {"SECURITY_FAIL", "FORMAT_FAIL", "SCHEMA_FAIL", "TOOL_FAIL", "GROUNDING_FAIL", "PARSE_ERROR", "TIMEOUT", "CONFIG_ERROR", "REVIEW"}
_PROVIDER_ERROR_VERDICTS = {"PROVIDER_ERROR"}
_NON_FAILURE_VERDICTS = {"PASS", "NOT_APPLICABLE", "SCAFFOLD_ONLY", "NOT_TESTED"}
_OPERATIONAL_REASON_CODES = {"PROVIDER_ERROR", "TIMEOUT", "PARSE_ERROR", "CONFIG_ERROR"}
_SEVERITY_WEIGHTS = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_SECRET_KEY_RE = re.compile(r"(?:api[_ -]?key|secret|token|password|credential|bearer|authorization)", re.IGNORECASE)
_BEARER_VALUE_RE = re.compile(r"\bBearer\s+[^\s`|<>]+", re.IGNORECASE)


class RunItemSnapshot(BaseModel):
    item_id: str
    normalized_key: str
    kind: ItemKind
    category: str
    dataset_name: str
    raw_id: str
    severity: str
    objective: str
    passed: bool
    score: int
    max_score: int = 100
    deterministic_verdict: str | None = None
    reason_codes: list[str] = Field(default_factory=list)
    evidence_level: str | None = None
    evidence_strength: str | None = None
    provider_error: bool = False
    provider_error_summary: str | None = None
    weighted_score: int = 0


class RunItemDelta(BaseModel):
    item_id: str
    normalized_key: str
    kind: ItemKind
    category: str
    dataset_name: str
    raw_id: str
    severity: str
    objective: str
    transition: Transition
    old_passed: bool | None = None
    new_passed: bool | None = None
    old_score: int | None = None
    new_score: int | None = None
    score_delta: int
    old_weighted_score: int | None = None
    new_weighted_score: int | None = None
    weighted_score_delta: int = 0
    old_deterministic_verdict: str | None = None
    new_deterministic_verdict: str | None = None
    old_reason_codes: list[str] = Field(default_factory=list)
    new_reason_codes: list[str] = Field(default_factory=list)
    old_evidence_level: str | None = None
    new_evidence_level: str | None = None
    old_evidence_strength: str | None = None
    new_evidence_strength: str | None = None
    old_provider_error: bool = False
    new_provider_error: bool = False
    provider_error_summary: str | None = None
    change_reasons: list[str] = Field(default_factory=list)


class CategoryDelta(BaseModel):
    category: str
    old_items: int
    new_items: int
    old_passed: int
    new_passed: int
    old_score: int
    new_score: int
    old_max_score: int
    new_max_score: int
    score_delta: int
    old_weighted_score: int = 0
    new_weighted_score: int = 0
    weighted_score_delta: int = 0
    pass_rate_delta: float


class RunDiffSummary(BaseModel):
    old_total_items: int
    new_total_items: int
    old_passed_items: int
    new_passed_items: int
    old_score_total: int
    new_score_total: int
    old_max_score_total: int
    new_max_score_total: int
    score_delta: int
    pass_rate_delta: float
    newly_failing: int
    newly_passing: int
    added_items: int
    removed_items: int
    unchanged_items: int
    comparison_status: ComparisonStatus = "PASS"
    reasons: list[str] = Field(default_factory=list)
    new_failures: int = 0
    resolved_failures: int = 0
    changed_verdicts: int = 0
    new_provider_errors: int = 0
    old_provider_errors: int = 0
    new_provider_error_total: int = 0
    baseline_incompatible: bool = False
    old_weighted_score_total: int = 0
    new_weighted_score_total: int = 0
    weighted_score_delta: int = 0
    deterministic_items: int = 0
    legacy_items: int = 0


class RunDiffReport(BaseModel):
    old_run_id: str
    new_run_id: str
    old_target_model: str
    new_target_model: str
    old_report_path: str
    new_report_path: str
    summary: RunDiffSummary
    category_deltas: dict[str, CategoryDelta] = Field(default_factory=dict)
    item_deltas: list[RunItemDelta] = Field(default_factory=list)
    newly_failing: list[RunItemDelta] = Field(default_factory=list)
    newly_passing: list[RunItemDelta] = Field(default_factory=list)
    new_failures: list[RunItemDelta] = Field(default_factory=list)
    resolved_failures: list[RunItemDelta] = Field(default_factory=list)
    changed_verdicts: list[RunItemDelta] = Field(default_factory=list)
    new_provider_errors: list[RunItemDelta] = Field(default_factory=list)
    added: list[RunItemDelta] = Field(default_factory=list)
    removed: list[RunItemDelta] = Field(default_factory=list)
    incompatible: list[RunItemDelta] = Field(default_factory=list)


def _load_report(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _pass_rate(passed: int, total: int) -> float:
    return 0.0 if total == 0 else round((passed / total) * 100, 4)


def _safe_text(value: object) -> str:
    redacted = redact_public_text(str(value)).text
    return _BEARER_VALUE_RE.sub("[REDACTED]", redacted)


def _safe_object(value: Any) -> Any:
    if isinstance(value, dict):
        safe: dict[str, Any] = {}
        for key, child in sorted(value.items(), key=lambda item: str(item[0])):
            key_text = _safe_text(key)
            safe[key_text] = "[REDACTED]" if _SECRET_KEY_RE.search(str(key)) else _safe_object(child)
        return safe
    if isinstance(value, list):
        return [_safe_object(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return _safe_text(value) if isinstance(value, str) else value
    return _safe_text(value)


def _normalize_token(value: object) -> str:
    text = str(value or "unknown").strip().lower()
    text = re.sub(r"\s+", "_", text)
    text = re.sub(r"[^a-z0-9_.:/-]+", "_", text)
    return text.strip("_") or "unknown"


def _item_id(kind: ItemKind, category: str, raw_id: str) -> str:
    return f"{kind}:{category}:{raw_id}"


def _normalized_key(kind: ItemKind, category: str, raw_id: str, item: dict[str, Any]) -> str:
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    scenario = metadata.get("scenario_key") or metadata.get("scenario_id") or item.get("scenario_id") or raw_id
    return _item_id(kind, _normalize_token(category), _normalize_token(scenario))


def _as_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return sorted({_safe_text(item).strip().upper() for item in value if str(item).strip()})
    text = str(value).strip()
    return [_safe_text(text).upper()] if text else []


def _metadata(item: dict[str, Any]) -> dict[str, Any]:
    value = item.get("metadata")
    return value if isinstance(value, dict) else {}


def _deterministic_verdict(item: dict[str, Any], reason_codes: list[str]) -> str | None:
    metadata = _metadata(item)
    value = metadata.get("deterministic_verdict") or metadata.get("verdict") or metadata.get("outcome")
    if value is not None:
        return _safe_text(value).strip().upper()
    if reason_codes:
        if any(reason in _OPERATIONAL_REASON_CODES for reason in reason_codes):
            return reason_codes[0]
        return "REVIEW"
    return None


def _evidence_level(item: dict[str, Any]) -> str | None:
    metadata = _metadata(item)
    value = metadata.get("evidence_level") or metadata.get("evidence")
    return _safe_text(value).strip() if value is not None else None


def _evidence_strength(item: dict[str, Any]) -> str | None:
    metadata = _metadata(item)
    value = metadata.get("evidence_strength") or metadata.get("evidence_level")
    return _safe_text(value).strip() if value is not None else None


def _provider_error_summary(item: dict[str, Any], reason_codes: list[str], verdict: str | None) -> str | None:
    metadata = _metadata(item)
    if verdict in _PROVIDER_ERROR_VERDICTS or "PROVIDER_ERROR" in reason_codes:
        source = metadata.get("provider_error") or metadata.get("provider_error_message") or metadata.get("error") or metadata.get("error_type") or "PROVIDER_ERROR"
        return _safe_text(source)
    return None


def _severity_weight(severity: str) -> int:
    return _SEVERITY_WEIGHTS.get(str(severity).lower(), 1)


def _snapshot(kind: ItemKind, category: str, dataset_name: str, raw_id: str, item: dict[str, Any]) -> RunItemSnapshot:
    reason_codes = _as_string_list(_metadata(item).get("reason_codes") or _metadata(item).get("reason_code"))
    verdict = _deterministic_verdict(item, reason_codes)
    provider_summary = _provider_error_summary(item, reason_codes, verdict)
    severity = _safe_text(item.get("severity", "unknown"))
    score = int(item.get("score", 0))
    return RunItemSnapshot(
        item_id=_item_id(kind, category, raw_id),
        normalized_key=_normalized_key(kind, category, raw_id, item),
        kind=kind,
        category=_safe_text(category),
        dataset_name=_safe_text(dataset_name),
        raw_id=_safe_text(raw_id),
        severity=severity,
        objective=_safe_text(item.get("objective", "")),
        passed=bool(item.get("passed", False)),
        score=score,
        deterministic_verdict=verdict,
        reason_codes=reason_codes,
        evidence_level=_evidence_level(item),
        evidence_strength=_evidence_strength(item),
        provider_error=provider_summary is not None,
        provider_error_summary=provider_summary,
        weighted_score=score * _severity_weight(severity),
    )


def _index_items(report: dict[str, Any]) -> dict[str, RunItemSnapshot]:
    indexed: dict[str, RunItemSnapshot] = {}
    for dataset in report.get("datasets", []):
        if not isinstance(dataset, dict):
            continue
        category = _safe_text(dataset.get("category", "uncategorized"))
        dataset_name = _safe_text(dataset.get("dataset_name", "unknown"))
        for case in dataset.get("case_results", []):
            if not isinstance(case, dict):
                continue
            raw_id = _safe_text(case.get("case_id", "unknown"))
            snapshot = _snapshot("case", category, dataset_name, raw_id, case)
            indexed[snapshot.normalized_key] = snapshot
        for group in dataset.get("group_results", []):
            if not isinstance(group, dict):
                continue
            raw_id = _safe_text(group.get("group_id", "unknown"))
            snapshot = _snapshot("group", category, dataset_name, raw_id, group)
            indexed[snapshot.normalized_key] = snapshot
    return indexed


def _is_failure(item: RunItemSnapshot | None) -> bool:
    if item is None:
        return False
    if item.provider_error:
        return False
    if item.deterministic_verdict:
        if item.deterministic_verdict in _PROVIDER_ERROR_VERDICTS | _NON_FAILURE_VERDICTS:
            return False
        if item.deterministic_verdict in _FAILURE_VERDICTS:
            return True
    return not item.passed


def _is_provider_error(item: RunItemSnapshot | None) -> bool:
    return bool(item and item.provider_error)


def _delta_for(normalized_key: str, old: RunItemSnapshot | None, new: RunItemSnapshot | None) -> RunItemDelta:
    source = new or old
    assert source is not None
    change_reasons: list[str] = []
    if old is None:
        transition: Transition = "added"
        score_delta = source.score
        weighted_score_delta = source.weighted_score
        if _is_failure(new):
            change_reasons.append("added_failure")
        if _is_provider_error(new):
            change_reasons.append("added_provider_error")
    elif new is None:
        transition = "removed"
        score_delta = -old.score
        weighted_score_delta = -old.weighted_score
        if _is_failure(old):
            change_reasons.append("removed_failure")
        if _is_provider_error(old):
            change_reasons.append("removed_provider_error")
    else:
        score_delta = new.score - old.score
        weighted_score_delta = new.weighted_score - old.weighted_score
        old_failure = _is_failure(old)
        new_failure = _is_failure(new)
        if not old.provider_error and new.provider_error:
            transition = "provider_error"
            change_reasons.append("new_provider_error")
        elif not old_failure and new_failure:
            transition = "regressed"
            change_reasons.append("new_failure")
        elif old_failure and not new_failure:
            transition = "improved"
            change_reasons.append("resolved_failure")
        elif old.deterministic_verdict != new.deterministic_verdict and (old.deterministic_verdict or new.deterministic_verdict):
            transition = "changed"
            change_reasons.append("changed_verdict")
        elif old.reason_codes != new.reason_codes:
            transition = "changed"
            change_reasons.append("changed_reason_codes")
        elif old.evidence_level != new.evidence_level or old.evidence_strength != new.evidence_strength:
            transition = "changed"
            change_reasons.append("changed_evidence")
        else:
            transition = "unchanged"
    return RunItemDelta(
        item_id=source.item_id,
        normalized_key=normalized_key,
        kind=source.kind,
        category=source.category,
        dataset_name=source.dataset_name,
        raw_id=source.raw_id,
        severity=source.severity,
        objective=source.objective,
        transition=transition,
        old_passed=old.passed if old else None,
        new_passed=new.passed if new else None,
        old_score=old.score if old else None,
        new_score=new.score if new else None,
        score_delta=score_delta,
        old_weighted_score=old.weighted_score if old else None,
        new_weighted_score=new.weighted_score if new else None,
        weighted_score_delta=weighted_score_delta,
        old_deterministic_verdict=old.deterministic_verdict if old else None,
        new_deterministic_verdict=new.deterministic_verdict if new else None,
        old_reason_codes=old.reason_codes if old else [],
        new_reason_codes=new.reason_codes if new else [],
        old_evidence_level=old.evidence_level if old else None,
        new_evidence_level=new.evidence_level if new else None,
        old_evidence_strength=old.evidence_strength if old else None,
        new_evidence_strength=new.evidence_strength if new else None,
        old_provider_error=old.provider_error if old else False,
        new_provider_error=new.provider_error if new else False,
        provider_error_summary=(new.provider_error_summary if new and new.provider_error_summary else old.provider_error_summary if old else None),
        change_reasons=sorted(change_reasons),
    )


def _category_deltas(old_items: dict[str, RunItemSnapshot], new_items: dict[str, RunItemSnapshot]) -> dict[str, CategoryDelta]:
    categories = sorted({item.category for item in old_items.values()} | {item.category for item in new_items.values()})
    result: dict[str, CategoryDelta] = {}
    for category in categories:
        old_cat = [item for item in old_items.values() if item.category == category]
        new_cat = [item for item in new_items.values() if item.category == category]
        old_score = sum(item.score for item in old_cat)
        new_score = sum(item.score for item in new_cat)
        old_weighted = sum(item.weighted_score for item in old_cat)
        new_weighted = sum(item.weighted_score for item in new_cat)
        old_passed = sum(1 for item in old_cat if item.passed)
        new_passed = sum(1 for item in new_cat if item.passed)
        old_max = sum(item.max_score for item in old_cat)
        new_max = sum(item.max_score for item in new_cat)
        result[category] = CategoryDelta(
            category=category,
            old_items=len(old_cat),
            new_items=len(new_cat),
            old_passed=old_passed,
            new_passed=new_passed,
            old_score=old_score,
            new_score=new_score,
            old_max_score=old_max,
            new_max_score=new_max,
            score_delta=new_score - old_score,
            old_weighted_score=old_weighted,
            new_weighted_score=new_weighted,
            weighted_score_delta=new_weighted - old_weighted,
            pass_rate_delta=round(_pass_rate(new_passed, len(new_cat)) - _pass_rate(old_passed, len(old_cat)), 4),
        )
    return result


def _schema_error(report: dict[str, Any]) -> str | None:
    schema_version = report.get("schema_version")
    if schema_version not in _COMPATIBLE_SCHEMA_VERSIONS:
        return "stale_or_incompatible_baseline_schema"
    if not isinstance(report.get("datasets", []), list):
        return "invalid_run_report_datasets"
    if not isinstance(report.get("summary", {}), dict):
        return "invalid_run_report_summary"
    return None


def _incompatible_delta(reason: str) -> RunItemDelta:
    return RunItemDelta(
        item_id="baseline:incompatible",
        normalized_key="baseline:incompatible",
        kind="case",
        category="baseline",
        dataset_name="baseline",
        raw_id="incompatible",
        severity="critical",
        objective=_safe_text(reason),
        transition="incompatible",
        score_delta=0,
        change_reasons=[reason],
        old_deterministic_verdict="CONFIG_ERROR",
        new_deterministic_verdict="CONFIG_ERROR",
        old_reason_codes=["CONFIG_ERROR"],
        new_reason_codes=["CONFIG_ERROR"],
    )


def _top_level_provider_error_count(report: dict[str, Any]) -> int:
    errors = report.get("provider_errors")
    if isinstance(errors, list):
        return len(errors)
    manifest = report.get("manifest") if isinstance(report.get("manifest"), dict) else {}
    manifest_errors = manifest.get("provider_errors")
    return len(manifest_errors) if isinstance(manifest_errors, list) else 0


def diff_run_reports(old_report_path: str | Path, new_report_path: str | Path) -> RunDiffReport:
    old_report = _safe_object(_load_report(old_report_path))
    new_report = _safe_object(_load_report(new_report_path))
    old_schema_error = _schema_error(old_report)
    new_schema_error = _schema_error(new_report)
    if old_schema_error or new_schema_error:
        reason = old_schema_error or new_schema_error or "incompatible_baseline"
        incompatible = [_incompatible_delta(reason)]
        return RunDiffReport(
            old_run_id=str(old_report.get("run_id", "unknown-old")),
            new_run_id=str(new_report.get("run_id", "unknown-new")),
            old_target_model=str(old_report.get("target_model", "unknown")),
            new_target_model=str(new_report.get("target_model", "unknown")),
            old_report_path=str(Path(old_report_path)),
            new_report_path=str(Path(new_report_path)),
            summary=RunDiffSummary(
                old_total_items=0,
                new_total_items=0,
                old_passed_items=0,
                new_passed_items=0,
                old_score_total=0,
                new_score_total=0,
                old_max_score_total=0,
                new_max_score_total=0,
                score_delta=0,
                pass_rate_delta=0.0,
                newly_failing=0,
                newly_passing=0,
                added_items=0,
                removed_items=0,
                unchanged_items=0,
                comparison_status="ERROR",
                reasons=[reason],
                baseline_incompatible=True,
            ),
            item_deltas=incompatible,
            incompatible=incompatible,
        )

    old_items = _index_items(old_report)
    new_items = _index_items(new_report)
    item_deltas = [_delta_for(item_key, old_items.get(item_key), new_items.get(item_key)) for item_key in sorted(set(old_items) | set(new_items))]

    newly_failing = [item for item in item_deltas if item.transition == "regressed"]
    newly_passing = [item for item in item_deltas if item.transition == "improved"]
    changed_verdicts = [item for item in item_deltas if item.transition == "changed" and "changed_verdict" in item.change_reasons]
    new_provider_errors = [item for item in item_deltas if item.transition == "provider_error" or "added_provider_error" in item.change_reasons]
    added = [item for item in item_deltas if item.transition == "added"]
    removed = [item for item in item_deltas if item.transition == "removed"]
    unchanged = [item for item in item_deltas if item.transition == "unchanged"]

    old_summary = old_report.get("summary", {})
    new_summary = new_report.get("summary", {})
    old_total = int(old_summary.get("total_items", len(old_items)))
    new_total = int(new_summary.get("total_items", len(new_items)))
    old_passed = int(old_summary.get("passed_items", sum(1 for item in old_items.values() if item.passed)))
    new_passed = int(new_summary.get("passed_items", sum(1 for item in new_items.values() if item.passed)))
    old_score = int(old_summary.get("score_total", sum(item.score for item in old_items.values())))
    new_score = int(new_summary.get("score_total", sum(item.score for item in new_items.values())))
    old_max = int(old_summary.get("max_score_total", sum(item.max_score for item in old_items.values())))
    new_max = int(new_summary.get("max_score_total", sum(item.max_score for item in new_items.values())))
    old_weighted = sum(item.weighted_score for item in old_items.values())
    new_weighted = sum(item.weighted_score for item in new_items.values())
    old_provider_errors = sum(1 for item in old_items.values() if item.provider_error) + _top_level_provider_error_count(old_report)
    new_provider_error_total = sum(1 for item in new_items.values() if item.provider_error) + _top_level_provider_error_count(new_report)
    deterministic_items = sum(1 for item in [*old_items.values(), *new_items.values()] if item.deterministic_verdict or item.reason_codes or item.evidence_level or item.evidence_strength or item.provider_error)
    legacy_items = len(old_items) + len(new_items) - deterministic_items
    reasons: list[str] = []
    if newly_failing:
        reasons.append("new_failures_detected")
    if new_provider_errors:
        reasons.append("new_provider_errors_detected")
    if changed_verdicts:
        reasons.append("changed_deterministic_verdicts_detected")
    if not reasons:
        reasons.append("no_regression_categories_detected")

    return RunDiffReport(
        old_run_id=str(old_report.get("run_id", "unknown-old")),
        new_run_id=str(new_report.get("run_id", "unknown-new")),
        old_target_model=str(old_report.get("target_model", "unknown")),
        new_target_model=str(new_report.get("target_model", "unknown")),
        old_report_path=str(Path(old_report_path)),
        new_report_path=str(Path(new_report_path)),
        summary=RunDiffSummary(
            old_total_items=old_total,
            new_total_items=new_total,
            old_passed_items=old_passed,
            new_passed_items=new_passed,
            old_score_total=old_score,
            new_score_total=new_score,
            old_max_score_total=old_max,
            new_max_score_total=new_max,
            score_delta=new_score - old_score,
            pass_rate_delta=round(_pass_rate(new_passed, new_total) - _pass_rate(old_passed, old_total), 4),
            newly_failing=len(newly_failing),
            newly_passing=len(newly_passing),
            added_items=len(added),
            removed_items=len(removed),
            unchanged_items=len(unchanged),
            comparison_status="REVIEW" if newly_failing or new_provider_errors or changed_verdicts else "PASS",
            reasons=reasons,
            new_failures=len(newly_failing),
            resolved_failures=len(newly_passing),
            changed_verdicts=len(changed_verdicts),
            new_provider_errors=len(new_provider_errors),
            old_provider_errors=old_provider_errors,
            new_provider_error_total=new_provider_error_total,
            old_weighted_score_total=old_weighted,
            new_weighted_score_total=new_weighted,
            weighted_score_delta=new_weighted - old_weighted,
            deterministic_items=deterministic_items,
            legacy_items=legacy_items,
        ),
        category_deltas=_category_deltas(old_items, new_items),
        item_deltas=item_deltas,
        newly_failing=newly_failing,
        newly_passing=newly_passing,
        new_failures=newly_failing,
        resolved_failures=newly_passing,
        changed_verdicts=changed_verdicts,
        new_provider_errors=new_provider_errors,
        added=added,
        removed=removed,
    )


def _md_text(value: object) -> str:
    text = html_escape(_safe_text(value), quote=False).replace("\r", " ").replace("\n", " ")
    return text.replace("|", r"\|").replace("`", r"\`").replace("#", r"\#")


def _transition_table(title: str, items: list[RunItemDelta]) -> list[str]:
    lines = [f"## {title}", ""]
    if not items:
        lines.extend(["None.", ""])
        return lines
    lines.extend(["| Item | Category | Verdict | Reasons | Old | New | Delta | Weighted delta |", "|---|---|---|---|---:|---:|---:|---:|"])
    for item in items:
        verdict = item.new_deterministic_verdict or item.old_deterministic_verdict or "legacy"
        reasons = ", ".join(item.new_reason_codes or item.old_reason_codes) or ", ".join(item.change_reasons) or "n/a"
        lines.append(
            f"| {_md_text(item.item_id)} | {_md_text(item.category)} | {_md_text(verdict)} | {_md_text(reasons)} | "
            f"{item.old_score if item.old_score is not None else 'n/a'} | {item.new_score if item.new_score is not None else 'n/a'} | "
            f"{item.score_delta:+d} | {item.weighted_score_delta:+d} |"
        )
    lines.append("")
    return lines


def render_diff_markdown(report: RunDiffReport) -> str:
    lines = [
        "# Malleus run diff",
        "",
        f"- Old run: {_md_text(report.old_run_id)} ({_md_text(report.old_target_model)})",
        f"- New run: {_md_text(report.new_run_id)} ({_md_text(report.new_target_model)})",
        f"- Status: {_md_text(report.summary.comparison_status)}",
        f"- Reasons: {_md_text(', '.join(report.summary.reasons) or 'none')}",
        f"- Score delta: {report.summary.score_delta}",
        f"- Severity-weighted score delta: {report.summary.weighted_score_delta}",
        f"- Pass-rate delta: {report.summary.pass_rate_delta:+.1f}%",
        f"- Newly failing: {report.summary.newly_failing}",
        f"- Newly passing: {report.summary.newly_passing}",
        f"- Changed verdicts: {report.summary.changed_verdicts}",
        f"- New provider errors: {report.summary.new_provider_errors}",
        f"- Added items: {report.summary.added_items}",
        f"- Removed items: {report.summary.removed_items}",
        f"- Baseline incompatible: {report.summary.baseline_incompatible}",
        "",
        "## Category deltas",
        "",
        "| Category | Old score | New score | Delta | Weighted delta | Old pass rate | New pass rate |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for delta in report.category_deltas.values():
        old_rate = _pass_rate(delta.old_passed, delta.old_items)
        new_rate = _pass_rate(delta.new_passed, delta.new_items)
        lines.append(
            f"| {_md_text(delta.category)} | {delta.old_score}/{delta.old_max_score} | {delta.new_score}/{delta.new_max_score} | "
            f"{delta.score_delta:+d} | {delta.weighted_score_delta:+d} | {old_rate:.1f}% | {new_rate:.1f}% |"
        )
    lines.append("")
    if not report.newly_failing and not report.newly_passing and not report.changed_verdicts and not report.new_provider_errors and not report.added and not report.removed and not report.incompatible:
        lines.extend(["No pass/fail transitions detected.", ""])
    lines.extend(_transition_table("New failures", report.new_failures))
    lines.extend(_transition_table("Resolved failures", report.resolved_failures))
    lines.extend(_transition_table("Changed verdicts", report.changed_verdicts))
    lines.extend(_transition_table("New provider errors", report.new_provider_errors))
    lines.extend(_transition_table("Added items", report.added))
    lines.extend(_transition_table("Removed items", report.removed))
    lines.extend(_transition_table("Baseline incompatibility", report.incompatible))
    return "\n".join(lines).rstrip() + "\n"

def write_diff_report(report: RunDiffReport, output_dir: str | Path) -> tuple[Path, Path]:
    destination = Path(output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    json_path = destination / "diff-runs-report.json"
    markdown_path = destination / "diff-runs-report.md"
    json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    markdown_path.write_text(render_diff_markdown(report), encoding="utf-8")
    return json_path, markdown_path
