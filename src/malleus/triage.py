from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from pydantic import BaseModel, Field

from malleus.schemas import REQUIRED_DETERMINISTIC_VERDICTS, REQUIRED_REASON_CODES, RunReport, verdict_for_reason


TRIAGE_SCHEMA_VERSION = "malleus.deterministic_triage.v1"

_FAIL_VERDICTS = {"SECURITY_FAIL", "FORMAT_FAIL", "SCHEMA_FAIL", "TOOL_FAIL", "GROUNDING_FAIL"}
_OPERATIONAL_VERDICTS = {"PROVIDER_ERROR", "PARSE_ERROR", "TIMEOUT", "CONFIG_ERROR"}
_UNTESTED_VERDICTS = {"SCAFFOLD_ONLY", "NOT_TESTED", "NOT_APPLICABLE"}
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}


class TriageRecord(BaseModel):
    case_id: str
    verdict: str = "REVIEW"
    reason_codes: list[str] = Field(default_factory=list)
    severity: str = "unknown"
    surface: str = "unknown"
    attack_family: str | None = None
    finding_id: str | None = None
    title: str = ""
    source: str = "unknown"


def triage_deterministically(source: Any) -> dict[str, Any]:
    """Summarize canonical deterministic outcomes from reports or finding records.

    Accepted inputs are existing ``RunReport`` objects, assessment risk-report style
    dictionaries, dictionaries containing ``findings``/``records``/``cases``, or
    iterables of simplified finding/case dictionaries. Unknown verdicts fail closed
    to ``REVIEW`` and scaffold/not-tested records never contribute to pass rate.
    """

    repeated_projection = _repeated_summary_projection(source)
    records = sorted(_records_from_source(source), key=_record_sort_key)
    counts_by_verdict = {verdict: 0 for verdict in REQUIRED_DETERMINISTIC_VERDICTS}
    counts_by_severity: dict[str, int] = {}
    counts_by_surface: dict[str, int] = {}
    counts_by_reason_code = {reason: 0 for reason in REQUIRED_REASON_CODES}
    clusters: dict[str, dict[str, Any]] = {}
    top_candidates: list[TriageRecord] = []

    pass_count = 0
    fail_count = 0
    error_count = 0
    review_count = 0
    scaffold_only_count = 0
    not_tested_count = 0
    not_applicable_count = 0
    model_security_failure_count = 0
    provider_operational_error_count = 0

    for record in records:
        verdict = _canonical_verdict(record.verdict)
        counts_by_verdict[verdict] = counts_by_verdict.get(verdict, 0) + 1
        counts_by_severity[record.severity] = counts_by_severity.get(record.severity, 0) + 1
        counts_by_surface[record.surface] = counts_by_surface.get(record.surface, 0) + 1

        if verdict == "PASS":
            pass_count += 1
        elif verdict in _FAIL_VERDICTS:
            fail_count += 1
            model_security_failure_count += 1
        elif verdict in _OPERATIONAL_VERDICTS:
            error_count += 1
            provider_operational_error_count += 1
        elif verdict == "SCAFFOLD_ONLY":
            scaffold_only_count += 1
        elif verdict == "NOT_TESTED":
            not_tested_count += 1
        elif verdict == "NOT_APPLICABLE":
            not_applicable_count += 1
        else:
            review_count += 1

        for reason_code in record.reason_codes or [_default_reason_for_verdict(verdict)]:
            reason = _canonical_reason(reason_code)
            if reason is None:
                continue
            counts_by_reason_code[reason] = counts_by_reason_code.get(reason, 0) + 1
            cluster_key = _cluster_key(record, reason)
            cluster = clusters.setdefault(
                cluster_key,
                {"key": cluster_key, "surface": record.surface, "attack_family": record.attack_family, "reason_code": reason, "count": 0, "case_ids": []},
            )
            cluster["count"] += 1
            cluster["case_ids"].append(record.case_id)

        if verdict in _FAIL_VERDICTS and record.severity in {"critical", "high"}:
            top_candidates.append(record)

    tested_denominator = len(records) - scaffold_only_count - not_tested_count - not_applicable_count
    posture = _posture(
        tested_denominator=tested_denominator,
        pass_count=pass_count,
        fail_count=fail_count,
        error_count=error_count,
        review_count=review_count,
    )
    return {
        "schema_version": TRIAGE_SCHEMA_VERSION,
        "posture": posture,
        "total_cases": len(records),
        "pass_count": pass_count,
        "fail_count": fail_count,
        "error_count": error_count,
        "review_count": review_count,
        "scaffold_only_count": scaffold_only_count,
        "not_tested_count": not_tested_count,
        "not_applicable_count": not_applicable_count,
        "pass_rate": round(pass_count / tested_denominator, 6) if tested_denominator else None,
        "pass_rate_denominator": tested_denominator,
        "provider_operational_error_count": provider_operational_error_count,
        "model_security_failure_count": model_security_failure_count,
        "counts_by_verdict": _nonzero_sorted(counts_by_verdict),
        "counts_by_severity": _nonzero_sorted(counts_by_severity),
        "counts_by_surface": _nonzero_sorted(counts_by_surface),
        "counts_by_reason_code": _nonzero_sorted(counts_by_reason_code),
        "top_findings": [_finding_projection(record) for record in sorted(top_candidates, key=_top_finding_sort_key)[:10]],
        "clusters": [
            {**cluster, "case_ids": sorted(cluster["case_ids"])}
            for _, cluster in sorted(clusters.items(), key=lambda item: (-item[1]["count"], item[0]))
        ],
        **repeated_projection,
    }


def deterministic_triage_summary(source: Any) -> dict[str, Any]:
    return triage_deterministically(source)


def _repeated_summary_projection(source: Any) -> dict[str, Any]:
    if isinstance(source, BaseModel):
        source = source.model_dump(mode="json")
    if not isinstance(source, Mapping):
        return {}
    repeated = source
    if str(source.get("schema_version") or "") != "malleus.repeated_summary.v1":
        repeated = source.get("repeated_summary") or source.get("repeated-summary") or {}
    if isinstance(repeated, BaseModel):
        repeated = repeated.model_dump(mode="json")
    if not isinstance(repeated, Mapping):
        return {}
    cases = repeated.get("cases") if isinstance(repeated.get("cases"), list) else []
    flaky_cases = [case for case in cases if isinstance(case, Mapping) and bool(case.get("flaky"))]
    deterministic_flaky_cases = [case for case in cases if isinstance(case, Mapping) and bool(case.get("deterministic_flaky"))]
    fingerprint_mismatch_cases = [case for case in cases if isinstance(case, Mapping) and bool(case.get("fingerprint_mismatch"))]
    if not cases and str(repeated.get("schema_version") or "") != "malleus.repeated_summary.v1":
        return {}
    return {
        "repeated_case_count": len([case for case in cases if isinstance(case, Mapping)]),
        "repeated_flaky_case_count": len(flaky_cases),
        "repeated_deterministic_flaky_count": len(deterministic_flaky_cases),
        "repeated_fingerprint_mismatch_count": len(fingerprint_mismatch_cases),
        "repeated_config_error_count": len([
            case for case in cases
            if isinstance(case, Mapping)
            and (str(case.get("aggregation_status") or "").upper() == "CONFIG_ERROR" or str(case.get("fail_closed_verdict") or "").upper() == "CONFIG_ERROR")
        ]),
        "repeated_flaky_case_ids": sorted(str(case.get("case_id") or "") for case in flaky_cases),
    }


def _records_from_source(source: Any) -> list[TriageRecord]:
    if isinstance(source, RunReport):
        return _records_from_run_report(source)
    if isinstance(source, BaseModel):
        source = source.model_dump(mode="json")
    if isinstance(source, Mapping):
        if str(source.get("schema_version") or "") == "malleus.repeated_summary.v1":
            return []
        return _records_from_mapping(source)
    if isinstance(source, Iterable) and not isinstance(source, (str, bytes)):
        return [_record_from_mapping(item) for item in source if isinstance(item, Mapping)]
    return []


def _records_from_run_report(report: RunReport) -> list[TriageRecord]:
    records: list[TriageRecord] = []
    for dataset in report.datasets:
        for case in dataset.case_results:
            metadata = case.metadata if isinstance(case.metadata, dict) else {}
            records.append(
                TriageRecord(
                    case_id=f"{dataset.dataset_name}:{case.case_id}",
                    verdict=_verdict_from_metadata(metadata, passed=case.passed),
                    reason_codes=_reason_codes(metadata),
                    severity=_severity(case.severity),
                    surface=_surface(metadata, dataset.subcategory),
                    attack_family=_optional_text(metadata.get("attack_family") or metadata.get("malleus_technique") or dataset.category),
                    finding_id=_optional_text(metadata.get("finding_id")),
                    title=str(metadata.get("title") or case.objective or ""),
                    source="run_report",
                )
            )
        for group in dataset.group_results:
            records.append(
                TriageRecord(
                    case_id=f"{dataset.dataset_name}:{group.group_id}",
                    verdict="PASS" if group.passed else "SECURITY_FAIL",
                    severity=_severity(group.severity),
                    surface=dataset.subcategory or dataset.category or "unknown",
                    attack_family=dataset.category or None,
                    title=group.objective,
                    source="run_report",
                )
            )
    return records


def _records_from_mapping(data: Mapping[str, Any]) -> list[TriageRecord]:
    if not data:
        return []
    if isinstance(data.get("datasets"), list):
        try:
            return _records_from_run_report(RunReport.model_validate(data))
        except Exception:
            pass
    records: list[TriageRecord] = []
    for key in ("findings", "records", "cases", "case_results"):
        value = data.get(key)
        if isinstance(value, list):
            records.extend(_record_from_mapping(item) for item in value if isinstance(item, Mapping))
    for pack in data.get("packs", []) if isinstance(data.get("packs"), list) else []:
        if isinstance(pack, Mapping) and _pack_is_untested(pack):
            records.append(_record_from_pack(pack))
    return records or [_record_from_mapping(data)]


def _posture(*, tested_denominator: int, pass_count: int, fail_count: int, error_count: int, review_count: int) -> str:
    if error_count:
        return "PROVIDER_ERROR"
    if fail_count:
        return "SECURITY_FAIL"
    if review_count:
        return "REVIEW"
    if tested_denominator <= 0:
        return "NOT_TESTED"
    if pass_count == tested_denominator:
        return "PASS"
    return "REVIEW"


def _record_from_mapping(data: Mapping[str, Any]) -> TriageRecord:
    metadata = data.get("metadata") if isinstance(data.get("metadata"), Mapping) else {}
    return TriageRecord(
        case_id=_first_text(data, metadata, "case_id", "scenario_id", "pack_id", "id", "finding_id", fallback="unknown"),
        verdict=_verdict_from_mapping(data, metadata),
        reason_codes=_reason_codes(data) or _reason_codes(metadata),
        severity=_severity(data.get("severity") or metadata.get("severity")),
        surface=_surface({**dict(metadata), **dict(data)}, "unknown"),
        attack_family=_optional_text(data.get("attack_family") or metadata.get("attack_family")),
        finding_id=_optional_text(data.get("finding_id") or data.get("id")),
        title=str(data.get("title") or metadata.get("title") or ""),
        source=str(data.get("source") or data.get("source_type") or "record"),
    )


def _record_from_pack(pack: Mapping[str, Any]) -> TriageRecord:
    status = str(pack.get("applicability") or pack.get("score_use") or "not_tested").upper()
    verdict = "SCAFFOLD_ONLY" if "SCAFFOLD" in status else "NOT_TESTED"
    return TriageRecord(
        case_id=str(pack.get("id") or "unknown"),
        verdict=verdict,
        reason_codes=[verdict],
        severity="unknown",
        surface=str(pack.get("category") or pack.get("title") or "unknown"),
        title=str(pack.get("title") or pack.get("id") or ""),
        source="assessment_pack",
    )


def _pack_is_untested(pack: Mapping[str, Any]) -> bool:
    values = {str(pack.get(key) or "").lower() for key in ("applicability", "score_use", "status", "mode")}
    strengths = {str(value).lower() for value in pack.get("evidence_strengths", []) if value is not None} if isinstance(pack.get("evidence_strengths"), list) else set()
    return bool(values & {"not_tested", "scaffold_only", "scaffold"} or strengths & {"scaffold_only", "planning_only"})


def _verdict_from_mapping(data: Mapping[str, Any], metadata: Mapping[str, Any]) -> str:
    for key in ("verdict", "deterministic_verdict", "outcome"):
        value = data.get(key) or metadata.get(key)
        if value:
            return _canonical_verdict(str(value))
    for key in ("reason_code", "reason_codes"):
        value = data.get(key) or metadata.get(key)
        reason = _first_reason(value)
        if reason:
            return verdict_for_reason(reason)
    status = str(data.get("status") or metadata.get("status") or "").lower()
    if status in {"pass", "passed", "ok"}:
        return "PASS"
    if status in {"fail", "failed"}:
        return "SECURITY_FAIL"
    if status in {"error", "provider_error"}:
        return "PROVIDER_ERROR"
    if status in {"not_tested", "untested"}:
        return "NOT_TESTED"
    if status in {"scaffold", "scaffold_only"}:
        return "SCAFFOLD_ONLY"
    passed = data.get("passed")
    if isinstance(passed, bool):
        return "PASS" if passed else "SECURITY_FAIL"
    return "REVIEW"


def _verdict_from_metadata(metadata: Mapping[str, Any], *, passed: bool) -> str:
    verdict = metadata.get("deterministic_verdict") or metadata.get("verdict")
    if verdict:
        return _canonical_verdict(str(verdict))
    reason = _first_reason(metadata.get("reason_codes") or metadata.get("reason_code"))
    if reason:
        return verdict_for_reason(reason)
    return "PASS" if passed else "SECURITY_FAIL"


def _canonical_verdict(value: str) -> str:
    normalized = value.strip().upper().replace("-", "_").replace(" ", "_")
    if normalized in REQUIRED_DETERMINISTIC_VERDICTS:
        return normalized
    return "REVIEW"


def _reason_codes(data: Mapping[str, Any]) -> list[str]:
    value = data.get("reason_codes") or data.get("reason_code")
    values = value if isinstance(value, list) else [value] if value else []
    return [reason for reason in (_canonical_reason(item) for item in values) if reason is not None]


def _canonical_reason(value: Any) -> str | None:
    normalized = str(value).strip().upper().replace("-", "_").replace(" ", "_")
    return normalized if normalized in REQUIRED_REASON_CODES else None


def _default_reason_for_verdict(verdict: str) -> str | None:
    return verdict if verdict in REQUIRED_REASON_CODES else None


def _first_reason(value: Any) -> str | None:
    values = value if isinstance(value, list) else [value] if value else []
    for item in values:
        reason = _canonical_reason(item)
        if reason:
            return reason
    return None


def _severity(value: Any) -> str:
    normalized = str(value or "unknown").strip().lower()
    return normalized if normalized in {"critical", "high", "medium", "low"} else "unknown"


def _surface(data: Mapping[str, Any], fallback: str) -> str:
    for key in ("surface", "attack_surface", "malleus_surface", "source_surface"):
        value = data.get(key)
        if value:
            return str(value).strip() or fallback or "unknown"
    return str(fallback or "unknown")


def _optional_text(value: Any) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text or None


def _first_text(data: Mapping[str, Any], metadata: Mapping[str, Any], *keys: str, fallback: str) -> str:
    for key in keys:
        value = data.get(key) or metadata.get(key)
        if value:
            return str(value)
    return fallback


def _cluster_key(record: TriageRecord, reason: str) -> str:
    left = record.surface or record.attack_family or "unknown"
    if record.attack_family and not record.surface:
        left = record.attack_family
    return f"{left}|{reason}"


def _record_sort_key(record: TriageRecord) -> tuple[str, str, str, str]:
    return (record.case_id, record.finding_id or "", record.verdict, ",".join(record.reason_codes))


def _top_finding_sort_key(record: TriageRecord) -> tuple[int, str, str, str]:
    return (_SEVERITY_RANK.get(record.severity, 4), record.case_id, record.finding_id or "", record.title)


def _finding_projection(record: TriageRecord) -> dict[str, Any]:
    return {
        "case_id": record.case_id,
        "finding_id": record.finding_id or record.case_id,
        "severity": record.severity,
        "surface": record.surface,
        "reason_codes": list(record.reason_codes),
        "title": record.title,
    }


def _nonzero_sorted(counts: Mapping[str, int]) -> dict[str, int]:
    return {key: counts[key] for key in sorted(counts) if counts[key]}
