from __future__ import annotations

import json
from pathlib import Path

from malleus.rescore import load_rescore_cache, rescore_provider_free
from malleus.schemas import CaseResult, DatasetReport, DatasetSummary, RunReport, RunSummary


def _case(case_id: str, *, prompt: str, response: str, passed: bool = False, metadata: dict | None = None) -> CaseResult:
    return CaseResult(
        dataset_name="core",
        case_id=case_id,
        severity="high",
        objective=f"objective {case_id}",
        prompt=prompt,
        response_text=response,
        passed=passed,
        score=100 if passed else 0,
        penalty=0 if passed else 100,
        metadata=metadata or {},
        failure_checks=[],
        pass_checks=[],
    )


def _run_report(tmp_path: Path) -> RunReport:
    scoring = tmp_path / "scoring.yaml"
    scoring.write_text("version: 1\n", encoding="utf-8")
    dataset = tmp_path / "dataset.yaml"
    dataset.write_text("name: d\n", encoding="utf-8")
    cases = [
        _case(
            "leak-case",
            prompt="DO NOT STORE RAW PROMPT SYNTHETIC-SK-OPENAI-SECRET",
            response="response includes MALLEUS-CANARY-RAWSECRET",
            metadata={"reason_codes": ["CANARY_LEAK"], "surface": "chat", "evidence_level": "provider_free_static"},
        ),
        _case("ambiguous", prompt="missing verdict prompt", response="missing verdict response", passed=True, metadata={"surface": "chat"}),
    ]
    dataset_report = DatasetReport(
        dataset_name="core",
        category="core-boundary",
        subcategory="instruction",
        case_results=cases,
        summary=DatasetSummary(total_items=2, passed_items=1, failed_items=1, score_total=100, max_score_total=200),
    )
    return RunReport(
        run_id="run-rescore",
        started_at="2026-04-26T00:00:00Z",
        finished_at="2026-04-26T00:00:01Z",
        target_name="target",
        target_adapter="openai_compatible",
        target_model="model",
        input_path=str(dataset),
        scoring_path=str(scoring),
        datasets=[dataset_report],
        summary=RunSummary(total_items=2, passed_items=1, failed_items=1, score_total=100, max_score_total=200),
        metadata={
            "run": {
                "scoring_config": {"sha256": "score-a"},
                "scenario_input": {"sha256": "input-a"},
                "release_matrix": {"sha256": "matrix-a"},
                "mutation_profile": {"sha256": "profile-a"},
            }
        },
    )


def test_provider_free_rescore_run_report_does_not_instantiate_adapters(monkeypatch, tmp_path: Path) -> None:
    class ExplodingAdapter:
        def __init__(self, target):
            raise AssertionError("rescore must not instantiate adapters")

    monkeypatch.setitem(__import__("malleus.runner").runner.ADAPTERS, "openai_compatible", ExplodingAdapter)

    cache_path = tmp_path / "rescore-cache.json"
    cache = rescore_provider_free(_run_report(tmp_path), cache_path=cache_path)

    assert cache.metadata.provider_calls_enabled is False
    assert cache.metadata.derived_summaries_stale is False
    assert cache.triage_summary["posture"] == "SECURITY_FAIL"
    assert cache.triage_summary["fail_count"] == 1
    assert cache.triage_summary["review_count"] == 1
    assert [observation.verdict for observation in cache.observations] == ["SECURITY_FAIL", "REVIEW"]
    assert cache.observations[1].reason == "insufficient deterministic verdict/reason evidence"
    assert load_rescore_cache(cache_path).triage_summary == cache.triage_summary


def test_provider_free_cache_artifact_excludes_raw_prompt_response_and_secret_values(tmp_path: Path) -> None:
    cache_path = tmp_path / "rescore-cache.json"
    rescore_provider_free(_run_report(tmp_path), cache_path=cache_path)

    serialized = cache_path.read_text(encoding="utf-8")

    assert "prompt_sha256" in serialized
    assert "response_sha256" in serialized
    assert "redacted_preview" in serialized
    assert "DO NOT STORE RAW PROMPT" not in serialized
    assert "missing verdict response" not in serialized
    assert "SYNTHETIC-SK-OPENAI-SECRET" not in serialized
    assert "MALLEUS-CANARY-RAWSECRET" not in serialized
    assert "raw_payload" not in serialized
    assert "response_text" not in serialized
    assert '"prompt"' not in serialized


def test_provider_free_rescore_accepts_assessment_style_records_without_provider(tmp_path: Path) -> None:
    assessment = {
        "assessment_id": "assess-1",
        "profile": "rag-agent",
        "findings": [
            {"finding_id": "F-1", "case_id": "core:leak", "severity": "high", "surface": "rag", "reason_codes": ["UNTRUSTED_CONTEXT_FOLLOWED"]},
            {"finding_id": "F-2", "case_id": "core:unknown", "severity": "medium", "surface": "rag", "title": "needs review"},
        ],
        "packs": [{"id": "ui", "applicability": "scaffold_only", "evidence_strength": "scaffold_only", "reason_code": "SCAFFOLD_ONLY"}],
    }

    cache = rescore_provider_free(assessment, cache_path=tmp_path / "assessment-cache.json")

    assert cache.metadata.source_kind == "assessment_report"
    assert cache.triage_summary["fail_count"] == 1
    assert cache.triage_summary["review_count"] == 1
    assert cache.triage_summary["scaffold_only_count"] == 1
    assert {observation.verdict for observation in cache.observations} == {"GROUNDING_FAIL", "REVIEW", "SCAFFOLD_ONLY"}


def test_explicit_pass_verdict_without_reason_codes_remains_pass(tmp_path: Path) -> None:
    cache = rescore_provider_free(
        [
            {
                "case_id": "pass-explicit",
                "verdict": "PASS",
                "evidence_level": "provider_free_static",
            }
        ],
        cache_path=tmp_path / "pass-cache.json",
    )

    assert cache.observations[0].verdict == "PASS"
    assert cache.observations[0].reason == "PASS"
    assert cache.triage_summary["posture"] == "PASS"
    assert cache.triage_summary["pass_count"] == 1
    assert cache.triage_summary["review_count"] == 0


def test_invalidate_marks_cached_derived_summaries_stale_when_input_hashes_change(tmp_path: Path) -> None:
    report = _run_report(tmp_path)
    cache_path = tmp_path / "rescore-cache.json"
    first = rescore_provider_free(
        report,
        cache_path=cache_path,
        scoring_config_sha256="score-a",
        input_sha256="input-a",
        release_matrix_sha256="matrix-a",
        mutation_profile_sha256="profile-a",
    )
    second = rescore_provider_free(
        report,
        cache_path=cache_path,
        scoring_config_sha256="score-b",
        input_sha256="input-b",
        release_matrix_sha256="matrix-b",
        mutation_profile_sha256="profile-b",
    )

    assert first.metadata.derived_summaries_stale is False
    assert second.metadata.derived_summaries_stale is True
    assert second.metadata.stale_reasons == [
        "scoring_config_hash_changed",
        "input_hash_changed",
        "release_matrix_hash_changed",
        "mutation_profile_hash_changed",
    ]
    assert second.triage_summary["posture"] == "SECURITY_FAIL"


def test_invalidate_marks_scorer_version_change_stale(tmp_path: Path) -> None:
    report = _run_report(tmp_path)
    cache_path = tmp_path / "rescore-cache.json"
    rescore_provider_free(report, cache_path=cache_path, scorer_version="scorer-v1")
    cache = rescore_provider_free(report, cache_path=cache_path, scorer_version="scorer-v2")

    assert cache.metadata.derived_summaries_stale is True
    assert cache.metadata.stale_reasons == ["scorer_version_hash_changed"]
    payload = json.loads(cache_path.read_text(encoding="utf-8"))
    assert payload["metadata"]["input_hashes"]["scorer_version"] == "scorer-v2"
