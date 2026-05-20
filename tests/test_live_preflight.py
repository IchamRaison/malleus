from __future__ import annotations

import json
import subprocess
from typing import Any

import httpx

from malleus.live_preflight import (
    PREFLIGHT_TEXT,
    _auth_headers,
    collect_ssh_diagnostics,
    minimal_image_data_url,
    run_target_preflight,
)
from malleus.schemas import TargetConfig
from malleus.utils.redact import scan_public_artifact_text


def _target(base_url: str = "http://secret-token.example.test:8080/v1") -> TargetConfig:
    return TargetConfig(
        name="local-qwen",
        adapter="openai_compatible",
        model="qwen-local",
        base_url=base_url,
        api_key_env="",
    )


def _client(handler: Any) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def _chat_response(text: str) -> httpx.Response:
    return httpx.Response(200, json={"choices": [{"message": {"content": text}}]})


def test_text_and_model_preflight_success_records_sanitized_endpoint() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/v1/health":
            return httpx.Response(404, json={"error": "missing"})
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/v1/models":
            return httpx.Response(
                200,
                json={"data": [{"id": "qwen-local", "capabilities": {"text": True}, "modalities": ["text"]}]},
            )
        if request.url.path == "/v1/chat/completions":
            return _chat_response(PREFLIGHT_TEXT)
        return httpx.Response(500, json={"error": "unexpected"})

    report = run_target_preflight(_target(), client=_client(handler), timeout=0.1, max_retries=0)

    assert report.ok is True
    assert report.text_status == "passed"
    assert report.text_ready is True
    assert report.endpoint.host == "secret-token.example.test"
    assert report.endpoint.port == 8080
    assert report.endpoint.path_hint == "/v1"
    assert all("secret-token.example.test:8080/v1" not in probe.model_dump_json() for probe in report.probes)
    assert [request.url.path for request in requests][:2] == ["/v1/health", "/health"]
    models_probe = next(probe for probe in report.probes if probe.name == "models")
    assert models_probe.metadata["target_model_found"] is True
    assert models_probe.metadata["capabilities"]["qwen-local"]["capabilities"]["text"] is True


def test_preflight_auth_headers_load_local_dotenv(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("LOCAL_PREFLIGHT_KEY='SYNTHETIC-TOKEN'\n", encoding="utf-8")
    target = _target().model_copy(update={"api_key_env": "LOCAL_PREFLIGHT_KEY"})

    assert _auth_headers(target) == {"Authorization": "Bearer SYNTHETIC-TOKEN"}


def test_dead_text_endpoint_is_infra_error_without_unredacted_exception() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/health"):
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/v1/models":
            return httpx.Response(200, json={"data": [{"id": "qwen-local"}]})
        raise httpx.ConnectError("connection failed token=supersecret123 /home/alice/.env", request=request)

    report = run_target_preflight(_target("http://127.0.0.1:8080/v1"), client=_client(handler), timeout=0.1, max_retries=1)
    text = next(probe for probe in report.probes if probe.name == "text")

    assert report.ok is False
    assert report.text_status == "infra_error"
    assert report.text_ready is False
    assert text.status == "infra_error"
    assert text.error_class == "infra"
    assert text.attempts == 2
    payload = report.model_dump_json()
    assert "supersecret123" not in payload
    assert "/home/alice" not in payload
    assert scan_public_artifact_text(payload).passed


def test_text_probe_mismatch_is_preflight_failed_with_safe_summary() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/health"):
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/v1/models":
            return httpx.Response(200, json={"data": [{"id": "qwen-local"}]})
        return _chat_response("wrong answer with token: SYNTHETIC-SK-OPENAI-SECRET")

    report = run_target_preflight(_target(), client=_client(handler), timeout=0.1, max_retries=0)
    text = next(probe for probe in report.probes if probe.name == "text")

    assert report.text_status == "preflight_failed"
    assert report.text_ready is False
    assert text.status == "preflight_failed"
    assert text.response_summary is not None
    assert "SYNTHETIC-SK-OPENAI-SECRET" not in text.response_summary.redacted_excerpt
    assert "response_sha256" in text.metadata


def test_text_probe_request_is_portable_by_default_and_reasoning_controls_are_opt_in() -> None:
    payloads: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/health"):
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/v1/models":
            return httpx.Response(200, json={"data": [{"id": "qwen-local"}]})
        payloads.append(json.loads(request.read().decode("utf-8")))
        return _chat_response(PREFLIGHT_TEXT)

    report = run_target_preflight(_target(), client=_client(handler), timeout=0.1, max_retries=0)
    target_with_opt_in = _target().model_copy(update={"metadata": {"preflight_reasoning_controls": True}})
    opt_in_report = run_target_preflight(target_with_opt_in, client=_client(handler), timeout=0.1, max_retries=0)

    assert report.text_status == "passed"
    assert opt_in_report.text_status == "passed"
    assert payloads[0]["max_tokens"] == 256
    assert "reasoning_effort" not in payloads[0]
    assert "chat_template_kwargs" not in payloads[0]
    assert payloads[1]["reasoning_effort"] == "none"
    assert payloads[1]["chat_template_kwargs"]["enable_thinking"] is False


def test_text_probe_rejects_sentinel_from_reasoning_content_when_content_is_empty() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/health"):
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/v1/models":
            return httpx.Response(200, json={"data": [{"id": "qwen-local"}]})
        return httpx.Response(200, json={"choices": [{"message": {"content": "", "reasoning_content": PREFLIGHT_TEXT}}]})

    report = run_target_preflight(_target(), client=_client(handler), timeout=0.1, max_retries=0)

    assert report.text_status == "preflight_failed"
    assert report.text_ready is False


def test_text_probe_rejects_sentinel_from_structured_reasoning_blocks() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/health"):
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/v1/models":
            return httpx.Response(200, json={"data": [{"id": "qwen-local"}]})
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": None, "reasoning": [{"type": "text", "text": PREFLIGHT_TEXT}]}}]},
        )

    report = run_target_preflight(_target(), client=_client(handler), timeout=0.1, max_retries=0)

    assert report.text_status == "preflight_failed"
    assert report.text_ready is False


def test_text_probe_rejects_wrong_alternate_reasoning_text() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/health"):
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/v1/models":
            return httpx.Response(200, json={"data": [{"id": "qwen-local"}]})
        return httpx.Response(200, json={"choices": [{"message": {"content": "", "reasoning": "almost MALLEUS_LOCAL_OK"}}]})

    report = run_target_preflight(_target(), client=_client(handler), timeout=0.1, max_retries=0)
    text = next(probe for probe in report.probes if probe.name == "text")

    assert report.text_status == "preflight_failed"
    assert report.text_ready is False
    assert text.status == "preflight_failed"
    assert text.error_class == "preflight"


def test_visual_probe_supported_and_post_image_health_passes() -> None:
    chat_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal chat_calls
        if request.url.path.endswith("/health"):
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/v1/models":
            return httpx.Response(200, json={"data": [{"id": "qwen-local", "modalities": ["text", "image"]}]})
        chat_calls += 1
        body = request.read().decode("utf-8")
        if chat_calls == 2:
            assert "data:image/png;base64," in body
            return _chat_response("MALLEUS_IMAGE_OK")
        return _chat_response(PREFLIGHT_TEXT)

    report = run_target_preflight(_target(), client=_client(handler), include_image_probe=True, timeout=0.1, max_retries=0)

    assert report.ok is True
    assert report.text_ready is True
    assert report.visual_status == "passed"
    assert report.visual_destabilized_endpoint is False
    assert next(probe for probe in report.probes if probe.name == "image").status == "passed"
    assert next(probe for probe in report.probes if probe.name == "post_image_health").status == "passed"
    assert minimal_image_data_url().startswith("data:image/png;base64,")


def test_visual_probe_unsupported_continues_text_preflight() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/health"):
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/v1/models":
            return httpx.Response(200, json={"data": [{"id": "qwen-local"}]})
        if "image_url" in request.read().decode("utf-8"):
            return httpx.Response(400, json={"error": "image unsupported"})
        return _chat_response(PREFLIGHT_TEXT)

    report = run_target_preflight(_target(), client=_client(handler), include_image_probe=True, timeout=0.1, max_retries=0)

    assert report.text_status == "passed"
    assert report.text_ready is True
    assert report.visual_status == "provider_capability_gap"
    assert report.visual_destabilized_endpoint is False
    assert report.ok is True
    assert "post_image_health" not in {probe.name for probe in report.probes}


def test_visual_probe_failure_does_not_abort_text_surface() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/health"):
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/v1/models":
            return httpx.Response(200, json={"data": [{"id": "qwen-local"}]})
        if "image_url" in request.read().decode("utf-8"):
            return httpx.Response(503, json={"error": "vision crashed"})
        return _chat_response(PREFLIGHT_TEXT)

    report = run_target_preflight(_target(), client=_client(handler), include_image_probe=True, timeout=0.1, max_retries=0)

    assert report.text_status == "passed"
    assert report.text_ready is True
    assert report.visual_status == "provider_error"
    assert report.visual_destabilized_endpoint is False
    assert report.ok is False


def test_post_image_unhealthy_marks_visual_provider_error_with_redacted_reason() -> None:
    health_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal health_calls
        if request.url.path.endswith("/health"):
            health_calls += 1
            if health_calls >= 2:
                return httpx.Response(503, json={"error": "crashed token: SYNTHETIC-SK-OPENAI-SECRET"})
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/v1/models":
            return httpx.Response(200, json={"data": [{"id": "qwen-local"}]})
        if "image_url" in request.read().decode("utf-8"):
            return _chat_response("MALLEUS_IMAGE_OK")
        return _chat_response(PREFLIGHT_TEXT)

    report = run_target_preflight(_target(), client=_client(handler), include_image_probe=True, timeout=0.1, max_retries=0)
    image = next(probe for probe in report.probes if probe.name == "image")

    assert report.text_status == "passed"
    assert report.text_ready is True
    assert report.visual_status == "provider_error"
    assert report.visual_destabilized_endpoint is True
    assert image.status == "provider_error"
    assert image.reason is not None
    assert "SYNTHETIC-SK-OPENAI-SECRET" not in report.model_dump_json()
    assert scan_public_artifact_text(report.model_dump_json()).passed


def test_redaction_removes_diagnostic_outputs() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/health"):
            return httpx.Response(200, json={"status": "ok", "token": "SYNTHETIC-SK-OPENAI-SECRET"})
        if request.url.path == "/v1/models":
            return httpx.Response(200, json={"data": [{"id": "qwen-local", "owned_by": "token: SYNTHETIC-SK-OPENAI-SECRET"}]})
        return _chat_response(PREFLIGHT_TEXT)

    report = run_target_preflight(
        _target("http://127.0.0.1:8080/v1"),
        client=_client(handler),
        timeout=0.1,
        max_retries=0,
    )
    payload = report.model_dump_json()

    assert report.text_ready is True
    assert report.endpoint.host == "127.0.0.1"
    assert "SYNTHETIC-SK-OPENAI-SECRET" not in payload
    assert "SYNTHETIC-SK-OPENAI-SECRET" not in payload
    assert scan_public_artifact_text(payload).passed


def test_ssh_unavailable_is_nonblocking_and_redacted() -> None:
    def runner(*_: Any, **__: Any) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError("/home/alice/bin/ssh missing token=supersecret123")

    result = collect_ssh_diagnostics(runner=runner)
    payload = result.model_dump_json()

    assert result.status == "unavailable"
    assert result.commands[0].status == "unavailable"
    assert "mouhfid@100.124.213.2" not in payload
    assert "m***@100.124.213.2" in payload
    assert "/home/alice" not in payload
    assert "supersecret123" not in payload
    assert scan_public_artifact_text(payload).passed


def test_ssh_custom_target_is_redacted_in_recorded_commands() -> None:
    def runner(*_: Any, **__: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="ok", stderr="")

    result = collect_ssh_diagnostics(target="alice@example.internal", runner=runner)
    payload = result.model_dump_json()

    assert result.status == "completed"
    assert "alice@example.internal" not in payload
    assert "a***@example.internal" in payload
    assert all("alice@example.internal" not in command.command for command in result.commands)
    assert scan_public_artifact_text(payload).passed


def test_ssh_diagnostics_outputs_are_redacted() -> None:
    def runner(*_: Any, **__: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="ok token: SYNTHETIC-SK-OPENAI-SECRET /home/alice/app", stderr="")

    result = collect_ssh_diagnostics(runner=runner)
    payload = result.model_dump_json()

    assert result.status == "completed"
    assert len(result.commands) == 3
    assert "SYNTHETIC-SK-OPENAI-SECRET" not in payload
    assert "/home/alice" not in payload
    assert scan_public_artifact_text(payload).passed
