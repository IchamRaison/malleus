from __future__ import annotations

from contextlib import contextmanager
import os
import signal
import threading
import time
from pathlib import Path
from types import FrameType
from typing import Any, Iterator, TypeAlias, cast

import httpx

from malleus.schemas import TargetConfig

JSONScalar: TypeAlias = str | int | float | bool | None
JSONValue: TypeAlias = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]

OPENAI_COMPATIBLE_RETRY_MIN_TOKENS = 8192
OPENAI_COMPATIBLE_RETRY_MAX_TOKENS = 32768
TRANSIENT_HTTP_STATUS_CODES = {408, 409, 425, 429, 500, 502, 503, 504}
TRANSIENT_HTTP_RETRY_DELAYS = (1.0, 3.0, 10.0, 30.0)


class AdapterError(RuntimeError):
    pass


class BaseAdapter:
    def __init__(self, target: TargetConfig, client: httpx.Client | None = None) -> None:
        self.target: TargetConfig = target
        self._api_key: str = self._load_api_key()
        self._owns_client: bool = client is None
        self.client: httpx.Client = client or httpx.Client(timeout=target.request.timeout)

    def _candidate_env_files(self) -> list[Path]:
        return [Path.cwd() / ".env", Path(__file__).resolve().parents[3] / ".env"]

    def _load_env_var_from_dotenv(self, name: str) -> str | None:
        for env_file in self._candidate_env_files():
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

    def _load_api_key(self) -> str:
        if not self.target.api_key_env:
            return ""
        value = os.environ.get(self.target.api_key_env) or self._load_env_var_from_dotenv(self.target.api_key_env)
        if not value:
            raise AdapterError(
                f"missing API key in environment variable '{self.target.api_key_env}' or local .env"
            )
        return value

    def endpoint(self) -> str:
        return f"{self.target.base_url.rstrip('/')}/chat/completions"

    def headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    def build_messages(self, prompt: str) -> list[dict[str, str]]:
        messages: list[dict[str, str]] = []
        if self.target.system_prompt:
            messages.append({"role": "system", "content": self.target.system_prompt})
        messages.append({"role": "user", "content": prompt})
        return messages

    def build_payload(self, prompt: str) -> dict[str, JSONValue]:
        return cast(
            dict[str, JSONValue],
            {
                "model": self.target.model,
                "messages": self.build_messages(prompt),
                "temperature": self.target.request.temperature,
                "top_p": self.target.request.top_p,
                "max_tokens": self.target.request.max_tokens,
            },
        )

    def extract_text(self, payload: dict[str, JSONValue]) -> str:
        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices:
            raise AdapterError("adapter response choices payload was missing or malformed")

        choice = choices[0]
        if not isinstance(choice, dict):
            raise AdapterError("adapter response choice payload was malformed")

        message = choice.get("message")
        if not isinstance(message, dict):
            raise AdapterError("adapter response message payload was malformed")

        content = message.get("content")
        if isinstance(content, str) and content:
            return content
        if isinstance(content, list):
            text_parts: list[str] = []
            for item in content:
                if not isinstance(item, dict):
                    continue
                item_type = item.get("type")
                item_text = item.get("text") or item.get("content")
                if item_type in {"text", "output_text"} and isinstance(item_text, str):
                    text_parts.append(item_text)
            if text_parts:
                return "".join(text_parts)

        refusal = message.get("refusal")
        if isinstance(refusal, str) and refusal:
            return refusal

        # Some NVIDIA Build partner endpoints expose reasoning-only partial
        # responses when token caps are too small. Capture that text instead
        # of failing the whole benchmark run; reports make the behavior visible.
        reasoning_content = message.get("reasoning_content") or message.get("reasoning")
        if isinstance(reasoning_content, str) and reasoning_content:
            return reasoning_content

        finish_reason = choice.get("finish_reason")
        if isinstance(finish_reason, str) and finish_reason:
            raise AdapterError(f"adapter response content was empty or unsupported; finish_reason={finish_reason}")
        raise AdapterError("adapter response content was empty or not a supported text shape")

    def generate(self, prompt: str) -> str:
        with self._total_request_timeout():
            return self._generate_with_retries(prompt)

    def _generate_with_retries(self, prompt: str) -> str:
        payload = self.build_payload(prompt)
        response = self._post_json_with_transient_retries(payload)
        response_payload = response.json()
        try:
            return self.extract_text(response_payload)
        except AdapterError as exc:
            retry_tokens = self._retry_token_budget(response_payload, payload)
            if retry_tokens is None:
                raise
            retry_payload = dict(payload)
            retry_payload["max_tokens"] = retry_tokens
            retry_response = self._post_json_with_transient_retries(retry_payload)
            try:
                return self.extract_text(retry_response.json())
            except AdapterError as retry_exc:
                raise AdapterError(
                    f"{retry_exc}; retried after empty length-limited response with max_tokens={retry_tokens}"
                ) from exc

    def _post_json_with_transient_retries(self, payload: dict[str, JSONValue]) -> httpx.Response:
        response: httpx.Response | None = None
        for attempt in range(len(TRANSIENT_HTTP_RETRY_DELAYS) + 1):
            response = self.client.post(self.endpoint(), headers=self.headers(), json=payload)
            if response.status_code not in TRANSIENT_HTTP_STATUS_CODES or attempt >= len(TRANSIENT_HTTP_RETRY_DELAYS):
                response.raise_for_status()
                return response
            time.sleep(self._retry_delay(response, attempt))
        assert response is not None
        response.raise_for_status()
        return response

    def _retry_delay(self, response: httpx.Response, attempt: int) -> float:
        header = response.headers.get("Retry-After")
        if header:
            try:
                return min(max(float(header), 0.0), 60.0)
            except ValueError:
                pass
        return TRANSIENT_HTTP_RETRY_DELAYS[min(attempt, len(TRANSIENT_HTTP_RETRY_DELAYS) - 1)]

    @contextmanager
    def _total_request_timeout(self) -> Iterator[None]:
        timeout = float(self.target.request.timeout)
        if timeout <= 0 or threading.current_thread() is not threading.main_thread() or not hasattr(signal, "setitimer"):
            yield
            return

        previous_handler = signal.getsignal(signal.SIGALRM)
        previous_timer = signal.setitimer(signal.ITIMER_REAL, timeout)

        def _raise_timeout(_signum: int, _frame: FrameType | None) -> None:
            raise AdapterError(f"adapter request exceeded total timeout {timeout:.1f}s")

        signal.signal(signal.SIGALRM, _raise_timeout)
        try:
            yield
        finally:
            signal.setitimer(signal.ITIMER_REAL, previous_timer[0], previous_timer[1])
            signal.signal(signal.SIGALRM, previous_handler)

    def _retry_token_budget(self, response_payload: Any, request_payload: dict[str, JSONValue]) -> int | None:
        if not self._is_empty_length_limited_response(response_payload):
            return None
        current = request_payload.get("max_tokens")
        if not isinstance(current, int) or current <= 0:
            current = int(self.target.request.max_tokens)
        retry_tokens = min(max(current * 4, OPENAI_COMPATIBLE_RETRY_MIN_TOKENS), OPENAI_COMPATIBLE_RETRY_MAX_TOKENS)
        if retry_tokens <= current:
            return None
        return retry_tokens

    def _is_empty_length_limited_response(self, payload: Any) -> bool:
        if not isinstance(payload, dict):
            return False
        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            return False
        choice = choices[0]
        if choice.get("finish_reason") != "length":
            return False
        message = choice.get("message")
        if not isinstance(message, dict):
            return False
        content = message.get("content")
        reasoning = message.get("reasoning_content") or message.get("reasoning")
        refusal = message.get("refusal")
        return not bool(content) and not bool(reasoning) and not bool(refusal)

    def close(self) -> None:
        if self._owns_client:
            self.client.close()
