from __future__ import annotations

import json
from pathlib import Path

from malleus.live_full import run_live_full_matrix
from malleus.live_preflight import LivePreflightReport, SafeTargetEndpoint
from malleus.utils.redact import REDACTION_MARKER, scan_public_artifact_text


REPORTS = (
    "FULL_BENCHMARK_SUMMARY.md",
    "FULL_BENCHMARK_MATRIX.json",
    "FULL_BENCHMARK_MATRIX.md",
    "COMMAND_LOG.md",
    "PROVIDER_ERRORS.md",
    "MODEL_FAILURES.md",
    "SERVER_DIAGNOSTICS.md",
)


def test_full_reports_redact_secret_like_values(monkeypatch, tmp_path: Path) -> None:
    raw_path = "/home/alice/private/api_key=secret-live-full-token/core.yaml"
    raw_secret = "token=secret-live-full-token"
    raw_bearer = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secretlivefulltoken"
    target = _target(tmp_path, metadata={"notes": "redaction regression", "path_label": "private-core", "auth_header_env": "MISSING_LIVE_FULL_KEY"})
    matrix = _matrix(tmp_path, _dataset(tmp_path, "smoke-pack", ["s1"]), core_path=raw_path)
    profile = _profile(tmp_path)

    def provider_error(target_path, input_path, scoring_path, output_dir, **kwargs):
        raise RuntimeError(f"provider failed near {raw_path} with {raw_secret} and {raw_bearer}")

    def mutation_error(*args, **kwargs):
        raise RuntimeError(f"mutation provider failed with {raw_secret} and {raw_bearer} at {raw_path}")

    monkeypatch.setattr("malleus.live_full.run_target_preflight", lambda target, **kwargs: _preflight())
    monkeypatch.setattr("malleus.live_full.run_benchmark", provider_error)
    monkeypatch.setattr("malleus.live_full.run_mutation_benchmark", mutation_error)

    out = tmp_path / "out"
    run_live_full_matrix(target_path=target, matrix_path=matrix, mutation_profile_path=profile, out_dir=out, dry_run=False, yes=True)

    combined = "\n".join((out / name).read_text(encoding="utf-8") for name in REPORTS)
    assert raw_path not in combined
    assert raw_secret not in combined
    assert raw_bearer not in combined
    assert "/home/alice" not in combined
    assert "secret-live-full-token" not in combined
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secretlivefulltoken" not in combined
    assert REDACTION_MARKER in combined
    scan = scan_public_artifact_text(combined)
    assert scan.passed, scan.findings

    payload = json.loads((out / "FULL_BENCHMARK_MATRIX.json").read_text(encoding="utf-8"))
    assert payload["dry_run"] is False
    assert payload["status_counts"]["provider_error"] >= 1
    for row in payload["rows"]:
        assert row["dry_run"] is False
        assert raw_path not in json.dumps(row)
        assert raw_secret not in json.dumps(row)
        assert raw_bearer not in json.dumps(row)


def _target(tmp_path: Path, *, metadata: dict[str, object]) -> Path:
    target = tmp_path / "target.yaml"
    metadata_lines = "\n".join(f"  {key}: {json.dumps(value)}" for key, value in metadata.items())
    target.write_text(
        "name: t\nadapter: openai_compatible\nmodel: m\nbase_url: http://example.test:8080/v1\napi_key_env: MISSING_LIVE_FULL_KEY\nmetadata:\n"
        + metadata_lines
        + "\n",
        encoding="utf-8",
    )
    return target


def _dataset(tmp_path: Path, name: str, case_ids: list[str]) -> Path:
    dataset = tmp_path / f"{name}.yaml"
    cases = "".join(
        f"  - id: {case_id}\n    severity: low\n    objective: refuse unsafe request\n    prompt: unsafe request {case_id}\n    pass_signals:\n      - type: refusal_marker\n"
        for case_id in case_ids
    )
    dataset.write_text(f"name: {name}\nversion: 1\ncategory: c\nsubcategory: s\ncases:\n{cases}", encoding="utf-8")
    return dataset


def _matrix(tmp_path: Path, smoke: Path, *, core_path: str) -> Path:
    matrix = tmp_path / "matrix.yaml"
    matrix.write_text(
        f"""schema_version: malleus.release_matrix.v1
id: test-matrix
version: 1.0.0
mode_boundaries:
  - mode: live_provider
    evidence_level: live_model_required
    provider_calls_enabled: true
packs:
  - id: smoke-v1
    path: {smoke}
    evidence_level: live_model_required
    status: available
    live_model_evidence: true
    scaffold_only: false
  - id: core-v1
    path: {core_path}
    evidence_level: live_model_required
    status: available
    live_model_evidence: true
    scaffold_only: false
selected_mutation_profiles:
  - id: selected-v1
    path: {_profile(tmp_path)}
    status: available
    default: true
    mutation_count: 1
    evidence_level: live_model_required
deep_mutation_profiles: []
gates: []
""",
        encoding="utf-8",
    )
    return matrix


def _profile(tmp_path: Path) -> Path:
    profile = tmp_path / "selected.yaml"
    if not profile.exists():
        profile.write_text("schema_version: malleus.mutation_profile.v1\nid: selected-v1\nname: Selected\nversion: 1.0.0\nmutations:\n  - unicode_wrap\n", encoding="utf-8")
    return profile


def _preflight() -> LivePreflightReport:
    return LivePreflightReport(
        target_name="t",
        adapter="openai_compatible",
        model="m",
        endpoint=SafeTargetEndpoint(scheme="http", host="example.test", port=8080, path_hint="/v1"),
        text_status="passed",
        text_ready=True,
        visual_status="not_supported",
        ok=True,
        probes=[],
    )
