from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx

from malleus.live_preflight import minimal_image_data_url
from malleus.utils.redact import scan_public_artifact_text
from malleus.visual_live import build_visual_live_payload, run_visual_live


def test_visual_live_payload_uses_minimal_text_and_image(tmp_path: Path) -> None:
    target = _target(tmp_path)
    payload = build_visual_live_payload(_load_target(target))

    assert payload["max_tokens"] == 64
    assert payload["temperature"] == 0
    content = payload["messages"][0]["content"]
    assert content[0]["type"] == "text"
    assert "TRUSTED TASK" in content[0]["text"]
    assert content[1] == {"type": "image_url", "image_url": {"url": minimal_image_data_url()}}
    assert len(content[1]["image_url"]["url"]) < 200


def test_visual_live_success_writes_sanitized_report(tmp_path: Path) -> None:
    target = _target(tmp_path)
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/v1/chat/completions":
            body = json.loads(request.read().decode("utf-8"))
            assert body["messages"][0]["content"][1]["image_url"]["url"].startswith("data:image/png;base64,")
            return httpx.Response(200, json={"choices": [{"message": {"content": "A tiny synthetic image was provided."}}]})
        if request.url.path.endswith("/health"):
            return httpx.Response(200, json={"status": "ok"})
        return httpx.Response(500, json={"error": "unexpected"})

    report = run_visual_live(target, tmp_path / "out", client=_client(handler), timeout=0.1)

    assert report.live_model_calls == 1
    assert report.summary.status_counts == {"passed": 1, "provider_error": 0}
    assert report.results[0].response_sha256 is not None
    assert report.results[0].post_image_health_status == "passed"
    assert [request.url.path for request in requests] == ["/v1/chat/completions", "/v1/health"]
    public_text = (tmp_path / "out" / "visual-live-report.json").read_text(encoding="utf-8") + (tmp_path / "out" / "visual-live-report.md").read_text(encoding="utf-8")
    assert scan_public_artifact_text(public_text).passed
    assert "TRUSTED TASK" not in public_text
    assert "data:image/png" not in public_text


def test_visual_live_empty_or_unhealthy_is_provider_error(tmp_path: Path) -> None:
    target = _target(tmp_path)
    health_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal health_calls
        if request.url.path == "/v1/chat/completions":
            return httpx.Response(200, json={"choices": [{"message": {"content": ""}}]})
        if request.url.path.endswith("/health"):
            health_calls += 1
            return httpx.Response(503, json={"error": "unhealthy"})
        return httpx.Response(500, json={"error": "unexpected"})

    report = run_visual_live(target, tmp_path / "out", client=_client(handler), timeout=0.1)

    assert report.live_model_calls == 0
    assert report.summary.provider_error == 1
    assert report.results[0].status == "provider_error"
    assert report.results[0].reason_codes == ["empty_visual_response"]
    assert report.results[0].post_image_health_status == "provider_error"
    assert health_calls == 2


def test_visual_live_timeout_records_provider_error_without_completion(tmp_path: Path) -> None:
    target = _target(tmp_path)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/chat/completions":
            raise httpx.ReadTimeout("vision timeout", request=request)
        if request.url.path.endswith("/health"):
            return httpx.Response(200, json={"status": "ok"})
        return httpx.Response(500, json={"error": "unexpected"})

    report = run_visual_live(target, tmp_path / "out", client=_client(handler), timeout=0.1)

    assert report.live_model_calls == 0
    assert report.attempted_provider_calls == 1
    assert report.results[0].status == "provider_error"
    assert report.results[0].reason_codes == ["timeout"]
    assert report.results[0].error_type == "ReadTimeout"


def _target(tmp_path: Path) -> Path:
    target = tmp_path / "target.yaml"
    target.write_text("name: visual-target\nadapter: openai_compatible\nmodel: fake-vision\nbase_url: https://example.test/v1\napi_key_env: MISSING_VISUAL_LIVE_KEY\n", encoding="utf-8")
    return target


def _load_target(path: Path) -> Any:
    from malleus.datasets import load_target_config

    return load_target_config(path)


def _client(handler: Any) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))
