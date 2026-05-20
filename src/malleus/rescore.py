from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from malleus.schemas import (
    KNOWN_EVIDENCE_LEVELS,
    ObservationRecord,
    REQUIRED_DETERMINISTIC_VERDICTS,
    REQUIRED_REASON_CODES,
    RunFingerprint,
    RunReport,
    verdict_for_reason,
)
from malleus.triage import triage_deterministically
from malleus.utils.redact import redaction_label, redact_public_text, sha256_text

RESCORE_SCHEMA_VERSION = "malleus.rescore.v1"
RESCORE_SCORER_VERSION = "malleus.rescore.deterministic.v1"
_CACHE_HASH_KEYS = ("scorer_version", "scoring_config", "input", "release_matrix", "mutation_profile")


class RescoreCacheMetadata(BaseModel):
    schema_version: str = RESCORE_SCHEMA_VERSION
    generated_at: str
    provider_calls_enabled: bool = False
    scorer_version: str = RESCORE_SCORER_VERSION
    source_kind: str
    source_sha256: str
    input_hashes: dict[str, str | None] = Field(default_factory=dict)
    stale_reasons: list[str] = Field(default_factory=list)
    derived_summaries_stale: bool = False


class RescoreCache(BaseModel):
    schema_version: str = RESCORE_SCHEMA_VERSION
    metadata: RescoreCacheMetadata
    fingerprint: RunFingerprint
    observations: list[ObservationRecord] = Field(default_factory=list)
    triage_summary: dict[str, Any] = Field(default_factory=dict)


def rescore_provider_free(
    source: str | Path | RunReport | dict[str, Any] | list[dict[str, Any]],
    *,
    cache_path: str | Path | None = None,
    scoring_config_sha256: str | None = None,
    input_sha256: str | None = None,
    release_matrix_sha256: str | None = None,
    mutation_profile_sha256: str | None = None,
    scorer_version: str = RESCORE_SCORER_VERSION,
) -> RescoreCache:
    """Recompute deterministic triage summaries from stored artifacts only.

    The rescore path is intentionally provider-free: it accepts already written
    reports or records, builds sanitized observations, and calls the deterministic
    triage contract. It does not import or instantiate benchmark adapters.
    """

    loaded = _load_source(source)
    hashes = _input_hashes(
        loaded,
        scorer_version=scorer_version,
        scoring_config_sha256=scoring_config_sha256,
        input_sha256=input_sha256,
        release_matrix_sha256=release_matrix_sha256,
        mutation_profile_sha256=mutation_profile_sha256,
    )
    stale_reasons = _stale_reasons(cache_path, hashes)
    observations = _observations_from_loaded(loaded)
    triage_source = [observation.model_dump(mode="json") for observation in observations]
    summary = triage_deterministically(triage_source)
    fingerprint = _fingerprint(loaded, hashes, observations)
    cache = RescoreCache(
        metadata=RescoreCacheMetadata(
            generated_at=datetime.now(UTC).isoformat(),
            provider_calls_enabled=False,
            scorer_version=scorer_version,
            source_kind=loaded["kind"],
            source_sha256=loaded["source_sha256"],
            input_hashes=hashes,
            stale_reasons=stale_reasons,
            derived_summaries_stale=bool(stale_reasons),
        ),
        fingerprint=fingerprint,
        observations=observations,
        triage_summary=summary,
    )
    if cache_path is not None:
        destination = Path(cache_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(cache.model_dump_json(indent=2), encoding="utf-8")
    return cache


def load_rescore_cache(path: str | Path) -> RescoreCache:
    return RescoreCache.model_validate_json(Path(path).read_text(encoding="utf-8"))


def _load_source(source: str | Path | RunReport | dict[str, Any] | list[dict[str, Any]]) -> dict[str, Any]:
    if isinstance(source, RunReport):
        payload = source.model_dump(mode="json")
        return {"kind": "run_report", "payload": payload, "report": source, "source_sha256": _canonical_hash(payload)}
    if isinstance(source, (str, Path)):
        path = Path(source)
        data = json.loads(path.read_text(encoding="utf-8"))
        loaded = _load_source(data)
        loaded["source_path"] = str(path)
        loaded["source_sha256"] = sha256_text(path.read_text(encoding="utf-8"))
        return loaded
    if isinstance(source, list):
        records = [dict(item) for item in source if isinstance(item, dict)]
        return {"kind": "triage_records", "payload": records, "source_sha256": _canonical_hash(records)}
    if isinstance(source, dict):
        if isinstance(source.get("datasets"), list):
            try:
                report = RunReport.model_validate(source)
            except Exception:
                report = None
            if report is not None:
                return {"kind": "run_report", "payload": report.model_dump(mode="json"), "report": report, "source_sha256": _canonical_hash(source)}
        kind = "assessment_report" if any(key in source for key in ("packs", "findings", "gate", "profile")) else "triage_records"
        return {"kind": kind, "payload": dict(source), "source_sha256": _canonical_hash(source)}
    raise TypeError(f"unsupported rescore source: {type(source).__name__}")


def _input_hashes(
    loaded: dict[str, Any],
    *,
    scorer_version: str,
    scoring_config_sha256: str | None,
    input_sha256: str | None,
    release_matrix_sha256: str | None,
    mutation_profile_sha256: str | None,
) -> dict[str, str | None]:
    payload = loaded["payload"]
    run_metadata = _run_metadata(payload)
    return {
        "scorer_version": scorer_version,
        "scoring_config": scoring_config_sha256 or _nested_sha(run_metadata, "scoring_config") or _path_sha(payload.get("scoring_path") if isinstance(payload, dict) else None),
        "input": input_sha256 or _nested_sha(run_metadata, "scenario_input") or _path_sha(payload.get("input_path") if isinstance(payload, dict) else None),
        "release_matrix": release_matrix_sha256 or _nested_sha(run_metadata, "release_matrix"),
        "mutation_profile": mutation_profile_sha256 or _nested_sha(run_metadata, "mutation_profile") or _profile_hash(payload),
    }


def _stale_reasons(cache_path: str | Path | None, current_hashes: dict[str, str | None]) -> list[str]:
    if cache_path is None:
        return []
    path = Path(cache_path)
    if not path.exists():
        return []
    try:
        previous = load_rescore_cache(path)
    except Exception:
        return ["previous_cache_unreadable"]
    previous_hashes = previous.metadata.input_hashes
    reasons: list[str] = []
    for key in _CACHE_HASH_KEYS:
        if previous_hashes.get(key) != current_hashes.get(key):
            reasons.append(f"{key}_hash_changed")
    return reasons


def _observations_from_loaded(loaded: dict[str, Any]) -> list[ObservationRecord]:
    if loaded.get("report") is not None:
        return _observations_from_run_report(loaded["report"])
    payload = loaded["payload"]
    if isinstance(payload, dict):
        records = _record_mappings_from_dict(payload)
    elif isinstance(payload, list):
        records = payload
    else:
        records = []
    return [_observation_from_mapping(record, index) for index, record in enumerate(records, start=1) if isinstance(record, dict)]


def _observations_from_run_report(report: RunReport) -> list[ObservationRecord]:
    observations: list[ObservationRecord] = []
    for dataset in report.datasets:
        for case in dataset.case_results:
            metadata = case.metadata if isinstance(case.metadata, dict) else {}
            verdict, reasons = _deterministic_outcome({"metadata": metadata})
            digest_payload = {
                "dataset_name": dataset.dataset_name,
                "case_id": case.case_id,
                "prompt": case.prompt,
                "response_text": case.response_text,
                "metadata": metadata,
            }
            observation_hash = _canonical_hash(digest_payload)
            observations.append(
                ObservationRecord(
                    observation_id=f"obs-{observation_hash[:16]}",
                    verdict=verdict,
                    reason_codes=reasons,
                    reason=_reason_text(verdict, reasons),
                    case_id=_safe_identifier(case.case_id),
                    dataset_name=_safe_identifier(dataset.dataset_name),
                    evidence_level=_safe_evidence_level({}, metadata),
                    redacted_preview=_observation_preview(observation_hash, _canonical_length(digest_payload), case.case_id),
                    metadata={
                        "source": "run_report",
                        "dataset_category": _safe_identifier(dataset.category),
                        "dataset_subcategory": _safe_identifier(dataset.subcategory),
                        "prompt_sha256": sha256_text(case.prompt),
                        "prompt_length": len(case.prompt),
                        "response_sha256": sha256_text(case.response_text),
                        "response_length": len(case.response_text),
                    },
                )
            )
        for group in dataset.group_results:
            digest_payload = {"dataset_name": dataset.dataset_name, "group_id": group.group_id, "variants": [variant.model_dump(mode="json") for variant in group.variants]}
            observation_hash = _canonical_hash(digest_payload)
            observations.append(
                ObservationRecord(
                    observation_id=f"obs-{observation_hash[:16]}",
                    verdict="REVIEW",
                    reason_codes=[],
                    reason="insufficient deterministic verdict/reason evidence",
                    case_id=_safe_identifier(group.group_id),
                    dataset_name=_safe_identifier(dataset.dataset_name),
                    evidence_level="provider_free_static",
                    redacted_preview=_observation_preview(observation_hash, _canonical_length(digest_payload), group.group_id),
                    metadata={"source": "run_report", "variant_count": len(group.variants)},
                )
            )
    return observations


def _record_mappings_from_dict(payload: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for key in ("findings", "records", "cases", "case_results"):
        value = payload.get(key)
        if isinstance(value, list):
            records.extend(dict(item) for item in value if isinstance(item, dict))
    packs = payload.get("packs")
    if isinstance(packs, list):
        records.extend(dict(item) for item in packs if isinstance(item, dict))
    if not records and payload:
        records.append(payload)
    return records


def _observation_from_mapping(record: dict[str, Any], index: int) -> ObservationRecord:
    verdict, reasons = _deterministic_outcome(record)
    observation_hash = _canonical_hash(record)
    case_id = _first_text(record, "case_id", "scenario_id", "pack_id", "id", "finding_id", fallback=f"record-{index}")
    metadata = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
    return ObservationRecord(
        observation_id=f"obs-{observation_hash[:16]}",
        verdict=verdict,
        reason_codes=reasons,
        reason=_reason_text(verdict, reasons),
        case_id=_safe_identifier(case_id),
        dataset_name=_safe_identifier(_first_text(record, "dataset_name", "source", fallback="rescore")),
        evidence_level=_safe_evidence_level(record, metadata),
        redacted_preview=_observation_preview(observation_hash, _canonical_length(record), case_id),
        metadata={
            "source": "assessment_report" if "finding_id" in record or "pack_id" in record else "triage_record",
            "record_sha256": observation_hash,
            "record_length": _canonical_length(record),
        },
    )


def _deterministic_outcome(record: dict[str, Any]) -> tuple[str, list[str]]:
    metadata = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
    verdict_value = record.get("verdict") or record.get("deterministic_verdict") or record.get("outcome") or metadata.get("verdict") or metadata.get("deterministic_verdict")
    reasons = _reason_codes(record) or _reason_codes(metadata)
    if reasons and not verdict_value:
        return verdict_for_reason(reasons[0]), reasons
    verdict = _canonical_verdict(verdict_value) if verdict_value else "REVIEW"
    if verdict in {"SECURITY_FAIL", "FORMAT_FAIL", "SCHEMA_FAIL", "TOOL_FAIL", "GROUNDING_FAIL"} and not reasons:
        return "REVIEW", []
    return verdict, reasons


def _reason_codes(data: dict[str, Any]) -> list[str]:
    value = data.get("reason_codes") or data.get("reason_code")
    values = value if isinstance(value, list) else [value] if value else []
    return [normalized for item in values if (normalized := _canonical_reason(item)) is not None]


def _canonical_reason(value: Any) -> str | None:
    normalized = str(value).strip().upper().replace("-", "_").replace(" ", "_")
    return normalized if normalized in REQUIRED_REASON_CODES else None


def _canonical_verdict(value: Any) -> str:
    normalized = str(value).strip().upper().replace("-", "_").replace(" ", "_")
    return normalized if normalized in REQUIRED_DETERMINISTIC_VERDICTS else "REVIEW"


def _fingerprint(loaded: dict[str, Any], hashes: dict[str, str | None], observations: list[ObservationRecord]) -> RunFingerprint:
    payload = loaded["payload"] if isinstance(loaded.get("payload"), dict) else {}
    run_id = str(payload.get("run_id") or payload.get("assessment_id") or "rescore")
    return RunFingerprint(
        fingerprint_id=f"rescore-{sha256_text(loaded['source_sha256'] + json.dumps(hashes, sort_keys=True))[:16]}",
        run_id=run_id,
        target_name=_safe_identifier(str(payload.get("target_name") or (payload.get("target", {}) if isinstance(payload.get("target"), dict) else {}).get("name") or "unknown")),
        target_model=_safe_identifier(str(payload.get("target_model") or (payload.get("target", {}) if isinstance(payload.get("target"), dict) else {}).get("model") or "unknown")),
        input_sha256=hashes.get("input"),
        scoring_sha256=hashes.get("scoring_config"),
        dataset_sha256=loaded["source_sha256"],
        config_sha256=hashes.get("release_matrix"),
        case_ids=[observation.case_id for observation in observations if observation.case_id],
        metadata={
            "source_kind": loaded["kind"],
            "observation_count": len(observations),
            "mutation_profile_sha256": hashes.get("mutation_profile"),
            "provider_calls_enabled": False,
        },
    )


def _run_metadata(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    run_metadata = metadata.get("run") if isinstance(metadata.get("run"), dict) else {}
    return dict(run_metadata)


def _nested_sha(metadata: dict[str, Any], key: str) -> str | None:
    value = metadata.get(key)
    if isinstance(value, dict) and isinstance(value.get("sha256"), str):
        return value["sha256"]
    return None


def _path_sha(value: Any) -> str | None:
    if not value:
        return None
    path = Path(str(value))
    if path.exists() and path.is_file():
        return sha256_text(path.read_text(encoding="utf-8", errors="replace"))
    return None


def _profile_hash(payload: Any) -> str | None:
    if isinstance(payload, dict) and payload.get("profile"):
        return sha256_text(str(payload["profile"]))
    return None


def _safe_identifier(value: Any) -> str:
    return redact_public_text(str(value), limit=160).text


def _safe_evidence_level(record: dict[str, Any], metadata: dict[str, Any]) -> str | None:
    value = record.get("evidence_level") or metadata.get("evidence_level") or record.get("evidence_strength")
    if isinstance(value, str) and value.strip() in KNOWN_EVIDENCE_LEVELS:
        return value.strip()
    return "provider_free_static"


def _observation_preview(observation_hash: str, length: int, label: Any) -> str:
    safe_label = redact_public_text(str(label), limit=80).text
    return f"{redaction_label(observation_hash, kind='observation')} source={safe_label} canonical_length={length}"


def _reason_text(verdict: str, reasons: list[str]) -> str:
    if reasons:
        return ",".join(reasons)
    if verdict == "REVIEW":
        return "insufficient deterministic verdict/reason evidence"
    return verdict


def _first_text(data: dict[str, Any], *keys: str, fallback: str) -> str:
    metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    for key in keys:
        value = data.get(key) or metadata.get(key)
        if value:
            return str(value)
    return fallback


def _canonical_hash(value: Any) -> str:
    return sha256_text(_canonical_json(value))


def _canonical_length(value: Any) -> int:
    return len(_canonical_json(value))


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
