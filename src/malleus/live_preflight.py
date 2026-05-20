from __future__ import annotations

import base64
import os
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit

import httpx
from pydantic import BaseModel, Field, model_validator

from malleus.live_evidence import LiveEvidenceStatus, RedactedResponseSummary, summarize_response
from malleus.schemas import TargetConfig, _reject_raw_evidence_fields
from malleus.utils.redact import redact_public_text, redacted_preview, sha256_text

PREFLIGHT_TEXT = "MALLEUS_LOCAL_OK"
DEFAULT_PREFLIGHT_TIMEOUT = 5.0
DEFAULT_PREFLIGHT_MAX_RETRIES = 1
DEFAULT_SSH_TARGET = "mouhfid@100.124.213.2"
_MINIMAL_PNG_BASE64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII="

ProbeName = Literal["health", "models", "text", "image", "post_image_health", "ssh_diagnostics"]
PreflightErrorClass = Literal["preflight", "provider", "infra", "none"]


class VersionedLivePreflightModel(BaseModel):
    schema_version: str = "malleus.live_preflight.v1"

    @model_validator(mode="before")
    @classmethod
    def validate_no_raw_payload_fields(cls, data: Any) -> Any:
        return _reject_raw_evidence_fields(data)


class SafeTargetEndpoint(VersionedLivePreflightModel):
    scheme: str
    host: str
    port: int | None = None
    path_hint: str | None = None

    @property
    def label(self) -> str:
        port = f":{self.port}" if self.port is not None else ""
        return f"{self.scheme}://{self.host}{port}"


class PreflightProbeResult(VersionedLivePreflightModel):
    name: ProbeName
    status: LiveEvidenceStatus
    error_class: PreflightErrorClass = "none"
    ok: bool = False
    attempts: int = 0
    status_code: int | None = None
    reason: str | None = None
    response_summary: RedactedResponseSummary | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class LivePreflightReport(VersionedLivePreflightModel):
    target_name: str
    adapter: str
    model: str
    endpoint: SafeTargetEndpoint
    text_status: LiveEvidenceStatus
    text_ready: bool = False
    visual_status: LiveEvidenceStatus | None = None
    visual_destabilized_endpoint: bool = False
    ok: bool = False
    probes: list[PreflightProbeResult] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SshDiagnosticCommand(VersionedLivePreflightModel):
    command: str
    status: Literal["completed", "unavailable", "skipped", "timeout", "error"]
    returncode: int | None = None
    output_summary: RedactedResponseSummary | None = None
    reason: str | None = None


class SshDiagnosticsResult(VersionedLivePreflightModel):
    target: str
    status: Literal["completed", "unavailable", "skipped", "partial"]
    commands: list[SshDiagnosticCommand] = Field(default_factory=list)
    reason: str | None = None


def safe_endpoint_from_url(base_url: str) -> SafeTargetEndpoint:
    parsed = urlsplit(base_url)
    host = parsed.hostname or "unknown"
    return SafeTargetEndpoint(
        scheme=parsed.scheme or "http",
        host=host,
        port=parsed.port,
        path_hint=_safe_path_hint(parsed.path),
    )


def run_target_preflight(
    target: TargetConfig,
    *,
    client: httpx.Client | None = None,
    include_image_probe: bool = False,
    timeout: float = DEFAULT_PREFLIGHT_TIMEOUT,
    max_retries: int = DEFAULT_PREFLIGHT_MAX_RETRIES,
) -> LivePreflightReport:
    owns_client = client is None
    active_client = client or httpx.Client(timeout=timeout, headers=_auth_headers(target))
    try:
        probes: list[PreflightProbeResult] = []
        health = probe_health(target, active_client, timeout=timeout, max_retries=max_retries)
        probes.append(health)
        models = probe_models(target, active_client, timeout=timeout, max_retries=max_retries)
        probes.append(models)
        text = probe_text(target, active_client, timeout=timeout, max_retries=max_retries)
        probes.append(text)

        visual_status: LiveEvidenceStatus | None = None
        visual_destabilized_endpoint = False
        if include_image_probe:
            image = probe_image(target, active_client, timeout=timeout, max_retries=max_retries)
            probes.append(image)
            visual_status = image.status
            if image.status in {"passed", "provider_error", "timeout"}:
                post = probe_health(
                    target,
                    active_client,
                    timeout=timeout,
                    max_retries=max_retries,
                    name="post_image_health",
                )
                probes.append(post)
                if not post.ok and image.status == "passed":
                    image.status = "provider_error"
                    image.ok = False
                    image.error_class = "provider"
                    image.reason = _safe_reason(f"endpoint unhealthy after image probe: {post.reason or post.status}")
                    image.metadata["post_image_health"] = post.status
                    visual_status = image.status
                    visual_destabilized_endpoint = True

        text_status = _combine_text_status(health, models, text)
        text_ready = text_status == "passed"
        return LivePreflightReport(
            target_name=target.name,
            adapter=target.adapter,
            model=target.model,
            endpoint=safe_endpoint_from_url(target.base_url),
            text_status=text_status,
            text_ready=text_ready,
            visual_status=visual_status,
            visual_destabilized_endpoint=visual_destabilized_endpoint,
            ok=text_ready and (visual_status in (None, "passed", "provider_capability_gap")),
            probes=probes,
            metadata={"timeout_seconds": timeout, "max_retries": max_retries},
        )
    finally:
        if owns_client:
            active_client.close()


def probe_health(
    target: TargetConfig,
    client: httpx.Client,
    *,
    timeout: float = DEFAULT_PREFLIGHT_TIMEOUT,
    max_retries: int = DEFAULT_PREFLIGHT_MAX_RETRIES,
    name: ProbeName = "health",
) -> PreflightProbeResult:
    attempts = 0
    last: PreflightProbeResult | None = None
    for url in _health_urls(target.base_url):
        result = _request_with_retries(client, "GET", url, timeout=timeout, max_retries=max_retries, probe_name=name)
        attempts += result.attempts
        if result.status_code == 404:
            last = result
            continue
        if result.ok:
            result.attempts = attempts
            return result
        last = result
    if last is None:
        return _failure(name, "infra_error", "infra", "no health URL candidates", attempts=0)
    last.attempts = attempts
    last.ok = False
    if last.status_code and last.status_code >= 500:
        last.status = "provider_error"
        last.error_class = "provider"
    elif last.status == "failed":
        last.status = "preflight_failed"
        last.error_class = "preflight"
    return last


def probe_models(
    target: TargetConfig,
    client: httpx.Client,
    *,
    timeout: float = DEFAULT_PREFLIGHT_TIMEOUT,
    max_retries: int = DEFAULT_PREFLIGHT_MAX_RETRIES,
) -> PreflightProbeResult:
    url = f"{_base_url_no_query(target.base_url).rstrip('/')}/models"
    result, models_payload = _request_with_json(client, "GET", url, timeout=timeout, max_retries=max_retries, probe_name="models")
    if not result.ok:
        return result
    ids, capabilities = _extract_model_metadata(models_payload)
    result.metadata.update(
        {
            "target_model_found": target.model in ids,
            "model_ids": ids[:25],
            "capabilities": capabilities,
        }
    )
    return result


def probe_text(
    target: TargetConfig,
    client: httpx.Client,
    *,
    timeout: float = DEFAULT_PREFLIGHT_TIMEOUT,
    max_retries: int = DEFAULT_PREFLIGHT_MAX_RETRIES,
) -> PreflightProbeResult:
    payload = {
        "model": target.model,
        "messages": [{"role": "user", "content": f"Reply with exactly {PREFLIGHT_TEXT} and no other text."}],
        "temperature": 0,
        "max_tokens": max(256, min(int(target.request.max_tokens or 256), 512)),
    }
    metadata = getattr(target, "metadata", None) or {}
    if isinstance(metadata, dict) and metadata.get("preflight_reasoning_controls") is True:
        payload["reasoning_effort"] = "none"
        payload["chat_template_kwargs"] = {"enable_thinking": False}
    result, response_payload = _request_with_json(
        client,
        "POST",
        _chat_url(target),
        timeout=timeout,
        max_retries=max_retries,
        probe_name="text",
        json_payload=payload,
    )
    if not result.ok:
        return result
    text = _extract_chat_text(response_payload)
    result.response_summary = summarize_response(text, excerpt_limit=120)
    result.metadata["response_sha256"] = sha256_text(text)
    if text.strip() != PREFLIGHT_TEXT:
        result.status = "preflight_failed"
        result.error_class = "preflight"
        result.ok = False
        result.reason = _safe_reason("text probe mismatch; response did not match expected sentinel")
    return result


def probe_image(
    target: TargetConfig,
    client: httpx.Client,
    *,
    timeout: float = DEFAULT_PREFLIGHT_TIMEOUT,
    max_retries: int = DEFAULT_PREFLIGHT_MAX_RETRIES,
) -> PreflightProbeResult:
    payload = {
        "model": target.model,
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Reply with exactly MALLEUS_IMAGE_OK if you can inspect this image."},
                    {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{_MINIMAL_PNG_BASE64}"}},
                ],
            }
        ],
        "temperature": 0,
        "max_tokens": 16,
    }
    result, response_payload = _request_with_json(
        client,
        "POST",
        _chat_url(target),
        timeout=timeout,
        max_retries=max_retries,
        probe_name="image",
        json_payload=payload,
    )
    if result.status in {"preflight_failed", "provider_error"} and result.status_code in {400, 404, 415, 422}:
        result.status = "provider_capability_gap"
        result.error_class = "preflight"
        result.reason = _safe_reason("image input not supported by target endpoint")
        return result
    if not result.ok:
        return result
    text = _extract_chat_text(response_payload)
    result.response_summary = summarize_response(text, excerpt_limit=120)
    result.metadata["response_sha256"] = sha256_text(text)
    return result


def collect_ssh_diagnostics(
    *,
    target: str = DEFAULT_SSH_TARGET,
    timeout: float = 5.0,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> SshDiagnosticsResult:
    if not target.strip():
        return SshDiagnosticsResult(target="", status="skipped", reason="empty SSH target")
    run = runner or subprocess.run
    commands = [
        "systemctl --no-pager --lines=40 status llama-server || true",
        "journalctl --no-pager -n 80 -u llama-server || true",
        "ss -ltnp || true",
    ]
    records: list[SshDiagnosticCommand] = []
    for remote in commands:
        argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=3", target, remote]
        command_text = _redact_command(argv, target=target)
        try:
            completed = run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        except FileNotFoundError as exc:
            records.append(SshDiagnosticCommand(command=command_text, status="unavailable", reason=_safe_reason(str(exc))))
            return SshDiagnosticsResult(target=_redact_ssh_target(target), status="unavailable", commands=records, reason="ssh executable unavailable")
        except subprocess.TimeoutExpired as exc:
            records.append(SshDiagnosticCommand(command=command_text, status="timeout", reason=_safe_reason(str(exc))))
            return SshDiagnosticsResult(target=_redact_ssh_target(target), status="partial", commands=records, reason="ssh diagnostics timed out")
        except OSError as exc:
            records.append(SshDiagnosticCommand(command=command_text, status="unavailable", reason=_safe_reason(str(exc))))
            return SshDiagnosticsResult(target=_redact_ssh_target(target), status="unavailable", commands=records, reason="ssh diagnostics unavailable")
        output = "\n".join(part for part in (completed.stdout, completed.stderr) if part)
        records.append(
            SshDiagnosticCommand(
                command=command_text,
                status="completed" if completed.returncode == 0 else "error",
                returncode=completed.returncode,
                output_summary=summarize_response(output, excerpt_limit=240),
                reason=None if completed.returncode == 0 else _safe_reason(f"ssh command exited {completed.returncode}"),
            )
        )
    overall = "completed" if all(record.status == "completed" for record in records) else "partial"
    return SshDiagnosticsResult(target=_redact_ssh_target(target), status=overall, commands=records)


def _request_with_retries(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    timeout: float,
    max_retries: int,
    probe_name: ProbeName,
    json_payload: dict[str, Any] | None = None,
) -> PreflightProbeResult:
    result, _ = _request_with_json(
        client,
        method,
        url,
        timeout=timeout,
        max_retries=max_retries,
        probe_name=probe_name,
        json_payload=json_payload,
    )
    return result


def _request_with_json(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    timeout: float,
    max_retries: int,
    probe_name: ProbeName,
    json_payload: dict[str, Any] | None = None,
) -> tuple[PreflightProbeResult, Any | None]:
    attempts = 0
    last_result: PreflightProbeResult | None = None
    for _ in range(max(0, max_retries) + 1):
        attempts += 1
        try:
            response = client.request(method, url, json=json_payload, timeout=timeout)
        except httpx.TimeoutException as exc:
            last_result = _failure(probe_name, "timeout", "infra", str(exc), attempts=attempts)
            continue
        except httpx.TransportError as exc:
            last_result = _failure(probe_name, "infra_error", "infra", str(exc), attempts=attempts)
            continue
        except Exception as exc:  # defensive boundary for preflight reporting
            last_result = _failure(probe_name, "infra_error", "infra", str(exc), attempts=attempts)
            continue

        body_text = response.text
        summary = summarize_response(body_text, excerpt_limit=160) if body_text else None
        if 200 <= response.status_code < 300:
            metadata: dict[str, Any] = {}
            parsed_json: Any | None = None
            if body_text:
                try:
                    parsed_json = response.json()
                except ValueError:
                    metadata["body_sha256"] = sha256_text(body_text)
            return (
                PreflightProbeResult(
                    name=probe_name,
                    status="passed",
                    error_class="none",
                    ok=True,
                    attempts=attempts,
                    status_code=response.status_code,
                    response_summary=summary,
                    metadata=metadata,
                ),
                parsed_json,
            )
        status = "provider_error" if response.status_code >= 500 else "preflight_failed"
        error_class: PreflightErrorClass = "provider" if response.status_code >= 500 else "preflight"
        last_result = PreflightProbeResult(
            name=probe_name,
            status=status,
            error_class=error_class,
            ok=False,
            attempts=attempts,
            status_code=response.status_code,
            reason=_safe_reason(f"HTTP {response.status_code} from target"),
            response_summary=summary,
        )
        if response.status_code < 500:
            break
    return (last_result or _failure(probe_name, "infra_error", "infra", "request did not execute", attempts=attempts), None)


def _failure(
    name: ProbeName,
    status: LiveEvidenceStatus,
    error_class: PreflightErrorClass,
    reason: str,
    *,
    attempts: int,
) -> PreflightProbeResult:
    return PreflightProbeResult(name=name, status=status, error_class=error_class, ok=False, attempts=attempts, reason=_safe_reason(reason))


def _combine_text_status(health: PreflightProbeResult, models: PreflightProbeResult, text: PreflightProbeResult) -> LiveEvidenceStatus:
    if text.status == "passed":
        return "passed"
    for result in (health, models, text):
        if result.status in {"timeout", "infra_error"}:
            return result.status
    for result in (health, models, text):
        if result.status == "provider_error":
            return "provider_error"
    return "preflight_failed"


def _auth_headers(target: TargetConfig) -> dict[str, str]:
    env_name = getattr(target, "api_key_env", None)
    if not env_name:
        return {}
    token = os.getenv(str(env_name)) or _load_env_var_from_dotenv(str(env_name))
    if not token:
        return {}
    return {"Authorization": f"Bearer {token}"}


def _load_env_var_from_dotenv(name: str) -> str | None:
    for env_file in _candidate_env_files():
        if not env_file.exists():
            continue
        for line in env_file.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            if key.strip() == name:
                return value.strip().strip('"').strip("'")
    return None


def _candidate_env_files() -> list[Path]:
    return [Path.cwd() / ".env", Path(__file__).resolve().parents[2] / ".env"]


def _chat_url(target: TargetConfig) -> str:
    return f"{_base_url_no_query(target.base_url).rstrip('/')}/chat/completions"


def _health_urls(base_url: str) -> list[str]:
    trimmed = _base_url_no_query(base_url).rstrip("/")
    parsed = urlsplit(trimmed)
    origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    candidates = [f"{trimmed}/health"]
    if origin and origin != trimmed:
        candidates.append(f"{origin}/health")
    return list(dict.fromkeys(candidates))


def _base_url_no_query(base_url: str) -> str:
    parsed = urlsplit(base_url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def _safe_path_hint(path: str) -> str | None:
    parts = [part for part in path.split("/") if part]
    if not parts:
        return None
    if parts[-1] in {"v1", "api"}:
        return f"/{parts[-1]}"
    return "/..."


def _extract_model_metadata(payload: Any) -> tuple[list[str], dict[str, Any]]:
    if not isinstance(payload, dict):
        return [], {}
    data = payload.get("data")
    if not isinstance(data, list):
        data = payload.get("models")
    ids: list[str] = []
    capabilities: dict[str, Any] = {}
    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            model_id = item.get("id") or item.get("name") or item.get("model")
            if isinstance(model_id, str):
                safe_model_id = redacted_preview(model_id, limit=120)
                ids.append(safe_model_id)
                model_metadata: dict[str, Any] = {}
                for key in ("owned_by", "capabilities", "modalities", "context_length"):
                    if key in item:
                        model_metadata[key] = _safe_metadata_value(item.get(key))
                if model_metadata:
                    capabilities[safe_model_id] = model_metadata
    return ids, capabilities


def _extract_chat_text(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""
    choices = payload.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        choice = choices[0]
        message = choice.get("message")
        if isinstance(message, dict):
            text = _extract_text_value(message.get("content"))
            if text:
                return text
        text = _extract_text_value(choice.get("text"))
        if text:
            return text
    message = payload.get("message")
    if isinstance(message, dict):
        text = _extract_text_value(message.get("content"))
        if text:
            return text
    return ""


def _extract_text_value(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts = [_extract_text_value(item) for item in value]
        return "".join(parts)
    if isinstance(value, dict):
        for key in ("text", "content"):
            text = _extract_text_value(value.get(key))
            if text:
                return text
    return ""


def _safe_metadata_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_public_text(value, limit=200).text
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        return [_safe_metadata_value(item) for item in value[:20]]
    if isinstance(value, dict):
        return {redact_public_text(str(key), limit=80).text: _safe_metadata_value(item) for key, item in list(value.items())[:20]}
    return redact_public_text(str(value), limit=200).text


def _safe_reason(reason: str) -> str:
    return redact_public_text(str(reason), limit=240).text


def _redact_command(argv: Sequence[str], *, target: str) -> str:
    redacted_args = [_redact_ssh_target(arg) if _looks_like_ssh_target(arg) else arg for arg in argv]
    display = " ".join(redacted_args)
    safe = redact_public_text(display, limit=260).text
    if target:
        safe = safe.replace(target, _redact_ssh_target(target))
    return safe


def _looks_like_ssh_target(value: str) -> bool:
    return "@" in value and not value.startswith("-") and " " not in value


def _redact_ssh_target(target: str) -> str:
    if "@" not in target:
        return redact_public_text(target, limit=80).text
    user, host = target.split("@", 1)
    return f"{user[:1]}***@{host}"


def minimal_image_data_url() -> str:
    decoded = base64.b64decode(_MINIMAL_PNG_BASE64)
    return "data:image/png;base64," + base64.b64encode(decoded).decode("ascii")
