from __future__ import annotations

import json
import hashlib
from pathlib import Path

from malleus.ir import RunManifest
from malleus.runner import run_benchmark
from malleus.schemas import RunReport


def _write_common_files(tmp_path: Path) -> tuple[Path, Path, Path]:
    target = tmp_path / "target.yaml"
    target.write_text(
        "\n".join(
            [
                "name: metadata-target",
                "adapter: openai_compatible",
                "model: model-with-metadata",
                "base_url: 'https://api.example.test/v1/chat/completions'",
                "api_key_env: OPENAI_API_KEY",
                "request:",
                "  temperature: 0.2",
                "  top_p: 0.9",
                "  max_tokens: 64",
                "metadata:",
                "  seed: 1234",
                "",
            ]
        ),
        encoding="utf-8",
    )
    scoring = tmp_path / "scoring.yaml"
    scoring.write_text(
        "version: 1\nmax_score: 100\nseverity_weights:\n  low: 10\n  medium: 20\n  high: 35\n  critical: 50\n",
        encoding="utf-8",
    )
    dataset = tmp_path / "dataset.yaml"
    dataset.write_text(
        """name: d
version: 1
category: c
subcategory: s
cases:
  - id: c1
    severity: low
    objective: first
    prompt: first prompt
    pass_signals:
      - type: refusal_marker
""",
        encoding="utf-8",
    )
    return target, scoring, dataset


def test_dry_run_metadata_captures_model_hashes_and_optional_matrix(tmp_path: Path) -> None:
    target, scoring, dataset = _write_common_files(tmp_path)
    mutation_profile = tmp_path / "mutation-profile.yaml"
    mutation_profile.write_text("id: selected-v1\nversion: 1\n", encoding="utf-8")
    release_matrix = tmp_path / "release-matrix.yaml"
    release_matrix.write_text("id: matrix-v1\nversion: '2026.04'\n", encoding="utf-8")

    report = run_benchmark(
        target,
        dataset,
        scoring,
        tmp_path / "out",
        dry_run=True,
        cli_argv=["malleus", "run", "--api-key", "SYNTHETIC-SK-OPENAI-SECRET", "--token=MALLEUS-CANARY-AWS-KEY"],
        mutation_profile_path=mutation_profile,
        release_matrix_path=release_matrix,
    )

    payload = json.loads((tmp_path / "out" / "dry-run.json").read_text(encoding="utf-8"))
    manifest = json.loads((tmp_path / "out" / "manifest.json").read_text(encoding="utf-8"))
    report_metadata = payload["metadata"]["run"]
    manifest_metadata = manifest["metadata"]["run"]

    assert report.run_id == payload["run_id"]
    assert report_metadata == manifest_metadata
    assert report_metadata["model_id"] == "model-with-metadata"
    assert report_metadata["adapter"] == "openai_compatible"
    assert report_metadata["provider"] == "openai_compatible"
    assert report_metadata["base_url"]["host"] == "api.example.test"
    assert report_metadata["request"] == {"temperature": 0.2, "top_p": 0.9, "max_tokens": 64, "seed": 1234}
    assert report_metadata["scoring_config"]["sha256"] == hashlib.sha256(scoring.read_bytes()).hexdigest()
    assert report_metadata["scenario_input"]["sha256"] == hashlib.sha256(dataset.read_bytes()).hexdigest()
    assert report_metadata["mutation_profile"]["sha256"] == hashlib.sha256(mutation_profile.read_bytes()).hexdigest()
    assert report_metadata["release_matrix"]["id"] == "matrix-v1"
    assert report_metadata["release_matrix"]["version"] == "2026.04"
    assert report_metadata["release_matrix"]["sha256"] == hashlib.sha256(release_matrix.read_bytes()).hexdigest()
    assert report_metadata["git_commit"]
    assert report_metadata["timestamp"]


def test_redact_sanitized_argv_and_base_url_secrets_from_artifacts(tmp_path: Path) -> None:
    target, scoring, dataset = _write_common_files(tmp_path)
    out = tmp_path / "out-redact"

    run_benchmark(
        target,
        dataset,
        scoring,
        out,
        dry_run=True,
        cli_argv=[
            "malleus",
            "run",
            "--password",
            "p@ssword-secret",
            "--canary=MALLEUS-CANARY-ABC123",
            "--access-key=MALLEUS-CANARY-AWS-KEY",
            "--literal",
            "token=SYNTHETIC-SK-OPENAI-SECRET",
        ],
    )

    serialized = "\n".join(
        [
            (out / "dry-run.json").read_text(encoding="utf-8"),
            (out / "manifest.json").read_text(encoding="utf-8"),
            (out / "dry-run.md").read_text(encoding="utf-8"),
        ]
    )

    assert "api.example.test" in serialized
    assert "/v1/chat/completions" not in serialized
    assert "api_key=" not in serialized
    assert "SYNTHETIC-SK-OPENAI-SECRET" not in serialized
    assert "SYNTHETIC-SK-OPENAI-SECRET" not in serialized
    assert "MALLEUS-CANARY-AWS-KEY" not in serialized
    assert "MALLEUS-CANARY-ABC123" not in serialized
    assert "p@ssword-secret" not in serialized
    assert "token=SYNTHETIC-SK-OPENAI-SECRET" not in serialized
    assert "[REDACTED]" in serialized


def test_target_config_rejects_base_url_secrets_before_metadata_artifacts(tmp_path: Path) -> None:
    target, scoring, dataset = _write_common_files(tmp_path)
    target.write_text(
        target.read_text(encoding="utf-8").replace(
            "https://api.example.test/v1/chat/completions",
            "https://api.example.test/v1/chat/completions?api_key=SYNTHETIC-SK-OPENAI-SECRET",
        ),
        encoding="utf-8",
    )

    try:
        run_benchmark(target, dataset, scoring, tmp_path / "out", dry_run=True)
    except ValueError as exc:
        assert "base_url must not include secret-like query parameters" in str(exc)
    else:
        raise AssertionError("run_benchmark should reject secret-bearing target base_url")


def test_old_report_and_manifest_without_metadata_still_validate() -> None:
    report = RunReport.model_validate(
        {
            "run_id": "run-old",
            "started_at": "2026-04-26T00:00:00Z",
            "finished_at": "2026-04-26T00:00:01Z",
            "target_name": "t",
            "target_adapter": "openai_compatible",
            "target_model": "m",
            "input_path": "dataset.yaml",
            "scoring_path": "scoring.yaml",
            "datasets": [],
            "summary": {"total_items": 0, "passed_items": 0, "failed_items": 0, "score_total": 0, "max_score_total": 0},
        }
    )
    manifest = RunManifest.model_validate(
        {
            "run_id": "run-old",
            "target_name": "t",
            "target_adapter": "openai_compatible",
            "target_model": "m",
            "input_path": "dataset.yaml",
            "scoring_path": "scoring.yaml",
            "output_dir": "out",
            "dry_run": True,
        }
    )

    assert report.metadata == {}
    assert manifest.metadata == {}
