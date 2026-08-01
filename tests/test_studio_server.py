from __future__ import annotations

import json
import time
from pathlib import Path

from fastapi.testclient import TestClient

from malleus.studio_server import create_studio_app


def test_studio_api_exposes_health_targets_and_attacks(tmp_path) -> None:
    app = create_studio_app(
        runs_root=tmp_path / "runs",
        session_target_dir=tmp_path / "session-targets",
        provider_keys_path=tmp_path / "provider-keys.json",
    )
    client = TestClient(app)

    health = client.get("/api/health")
    attacks = client.get("/api/attacks")
    scan_profiles = client.get("/api/scan-profiles")
    targets = client.get("/api/targets")
    providers = client.get("/api/providers")

    assert health.status_code == 200
    assert health.json()["ok"] is True
    assert attacks.status_code == 200
    assert {"smoke-v1", "core-v1", "soft", "exterminatus", "rag-v1", "agentic-injection-v1"} <= {item["id"] for item in attacks.json()["attacks"]}
    assert scan_profiles.status_code == 200
    assert "standard-vulnerability-scan" in {item["id"] for item in scan_profiles.json()["profiles"]}
    assert targets.status_code == 200
    assert isinstance(targets.json()["targets"], list)
    assert providers.status_code == 200
    assert "nvidia" in {item["id"] for item in providers.json()["providers"]}


def test_studio_api_allows_configured_cors_origin(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("MALLEUS_STUDIO_CORS_ORIGINS", "https://malleus-studio-demo.vercel.app")
    app = create_studio_app(
        runs_root=tmp_path / "runs",
        session_target_dir=tmp_path / "session-targets",
        provider_keys_path=tmp_path / "provider-keys.json",
    )
    client = TestClient(app)

    response = client.options(
        "/api/health",
        headers={
            "Origin": "https://malleus-studio-demo.vercel.app",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://malleus-studio-demo.vercel.app"


def test_studio_api_manages_provider_keys_without_returning_secret(tmp_path) -> None:
    app = create_studio_app(
        runs_root=tmp_path / "runs",
        session_target_dir=tmp_path / "session-targets",
        provider_keys_path=tmp_path / "provider-keys.json",
    )
    client = TestClient(app)

    saved = client.put("/api/provider-keys/deepseek", json={"api_key": "sk-secret-value-1234"})
    assert saved.status_code == 200
    assert saved.json()["provider_key"]["present"] is True
    assert "sk-secret-value-1234" not in saved.text

    listed = client.get("/api/provider-keys")
    assert listed.status_code == 200
    by_provider = {item["provider_id"]: item for item in listed.json()["provider_keys"]}
    assert by_provider["deepseek"]["source"] == "vault"
    assert "sk-secret-value-1234" not in listed.text

    deleted = client.delete("/api/provider-keys/deepseek")
    assert deleted.status_code == 200
    assert deleted.json()["provider_key"]["present"] is False


def test_studio_api_exposes_run_history_and_safe_artifacts(tmp_path) -> None:
    run_dir = tmp_path / "runs" / "studio-example-run"
    run_dir.mkdir(parents=True)
    (run_dir / "studio-events.jsonl").write_text('{"event":"queued"}\n', encoding="utf-8")
    (run_dir / "studio-run-summary.json").write_text(
        json.dumps(
            {
                "run_id": "studio-example-run",
                "target": "target-a",
                "attack_id": "smoke-v1",
                "status": "completed",
                "out_dir": str(run_dir),
                "report_json": str(run_dir / "report.json"),
                "evidence_json": None,
                "score": "1/1",
                "passed_items": 1,
                "total_items": 1,
                "failed_cases": [],
                "error": None,
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "report.json").write_text('{"ok": true}', encoding="utf-8")
    app = create_studio_app(
        runs_root=tmp_path / "runs",
        session_target_dir=tmp_path / "session-targets",
        provider_keys_path=tmp_path / "provider-keys.json",
    )
    client = TestClient(app)

    history = client.get("/api/run-history")
    assert history.status_code == 200
    assert history.json()["runs"][0]["run"]["run_id"] == "studio-example-run"
    assert history.json()["runs"][0]["event_count"] == 1

    detail = client.get("/api/runs/studio-example-run")
    assert detail.status_code == 200
    assert detail.json()["run"]["score"] == "1/1"

    events = client.get("/api/runs/studio-example-run/events.json")
    assert events.status_code == 200
    assert events.json()["events"][0]["event"] == "queued"

    artifact = client.get("/api/runs/studio-example-run/artifact", params={"path": "report.json"})
    assert artifact.status_code == 200
    assert artifact.json() == {"ok": True}

    export_json = client.get("/api/runs/studio-example-run/export.json")
    assert export_json.status_code == 200
    assert export_json.json()["schema_version"] == "malleus.studio_run_export.v1"
    assert export_json.json()["run"]["run_id"] == "studio-example-run"

    export_html = client.get("/api/runs/studio-example-run/export.html")
    assert export_html.status_code == 200
    assert "Malleus Studio export" in export_html.text
    assert "studio-example-run" in export_html.text

    timeline = client.get("/api/runs/studio-example-run/timeline")
    assert timeline.status_code == 200
    assert timeline.json()["recording"]["events"][0]["event_type"] == "queued"

    escape = client.get("/api/runs/studio-example-run/artifact", params={"path": "../secret.txt"})
    assert escape.status_code == 404


def test_studio_api_stores_organization_recordings(tmp_path) -> None:
    app = create_studio_app(
        runs_root=tmp_path / "runs",
        session_target_dir=tmp_path / "session-targets",
        provider_keys_path=tmp_path / "provider-keys.json",
        organization_store_path=tmp_path / "organization.db",
    )
    client = TestClient(app)
    recording = {
        "recording_id": "recording-1",
        "source": "ci",
        "events": [],
        "violations": [],
    }

    added = client.post(
        "/api/organizations/acme/projects/assistant/recordings", json=recording
    )
    runs = client.get("/api/organizations/acme/runs", params={"project": "assistant"})
    trend = client.get("/api/organizations/acme/trend", params={"project": "assistant"})

    assert added.status_code == 200
    assert runs.json()["runs"][0]["recording_id"] == "recording-1"
    assert trend.json()["trend"]["direction"] == "new"


def test_studio_api_builds_scan_plan(tmp_path) -> None:
    session_dir = tmp_path / "session-targets"
    session_dir.mkdir(parents=True)
    (session_dir / "studio-target.yaml").write_text(
        "\n".join(
            [
                "name: studio-target",
                "target_type: chat_completion",
                "adapter: openai_compatible",
                "model: studio/model",
                "base_url: https://example.test/v1",
                "api_key_env: STUDIO_API_KEY",
                "",
            ]
        ),
        encoding="utf-8",
    )
    app = create_studio_app(
        runs_root=tmp_path / "runs",
        session_target_dir=session_dir,
        provider_keys_path=tmp_path / "provider-keys.json",
    )
    client = TestClient(app)

    response = client.post(
        "/api/scan-plan",
        json={
            "target": "studio-target",
            "description": "Support agent",
            "languages": ["en"],
            "profile_id": "standard-vulnerability-scan",
            "max_attacks": 2,
            "seed": 11,
        },
    )

    assert response.status_code == 200
    plan = response.json()["plan"]
    assert plan["schema_version"] == "malleus.studio_scan_plan.v1"
    assert plan["target"]["name"] == "studio-target"
    assert len(plan["steps"]) == 2


def test_studio_api_starts_scan_run(monkeypatch, tmp_path) -> None:
    session_dir = tmp_path / "session-targets"
    session_dir.mkdir(parents=True)
    (session_dir / "studio-target.yaml").write_text(
        "\n".join(
            [
                "name: studio-target",
                "target_type: chat_completion",
                "adapter: openai_compatible",
                "model: studio/model",
                "base_url: https://example.test/v1",
                "api_key_env: STUDIO_API_KEY",
                "",
            ]
        ),
        encoding="utf-8",
    )

    class Summary:
        score_total = 5
        max_score_total = 5
        passed_items = 1
        total_items = 1

    class Report:
        summary = Summary()
        datasets = []

    def fake_run_benchmark(*args, **kwargs):
        kwargs["progress_callback"]({"event": "case_start", "case_id": Path(args[1]).stem})
        kwargs["progress_callback"]({"event": "case_end", "case_id": Path(args[1]).stem, "passed": True})
        return Report()

    monkeypatch.setattr("malleus.studio_runtime.run_benchmark", fake_run_benchmark)
    app = create_studio_app(
        runs_root=tmp_path / "runs",
        session_target_dir=session_dir,
        provider_keys_path=tmp_path / "provider-keys.json",
    )
    client = TestClient(app)

    response = client.post(
        "/api/scan-runs",
        json={
            "target": "studio-target",
            "profile_id": "standard-vulnerability-scan",
            "max_attacks": 2,
            "seed": 15,
            "request_timeout": 30,
            "max_retries": 0,
        },
    )

    assert response.status_code == 200
    run_id = response.json()["run"]["run_id"]
    for _ in range(50):
        detail = client.get(f"/api/runs/{run_id}").json()["run"]
        if detail["status"] in {"completed", "failed", "cancelled"}:
            break
        time.sleep(0.02)

    assert detail["status"] == "completed", detail.get("error")
    assert detail["attack_id"] == "scan:standard-vulnerability-scan"
    assert detail["score"] == "2/2 items"
