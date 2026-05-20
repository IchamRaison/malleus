from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import parse_qsl, urlsplit

import yaml

from malleus.datasets import load_target_config
from malleus.schemas import TargetConfig


TARGET_FIELDS: tuple[str, ...] = (
    "name",
    "adapter",
    "model",
    "base_url",
    "api_key_env",
    "system_prompt",
    "request",
    "metadata",
)
_RAW_KEY_FIELDS = {"api_key", "api_key_value", "api_key_secret", "token", "password", "secret"}
_ENV_VAR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SECRET_QUERY_KEY_ALIASES = {"apikey", "xapikey", "key"}
_RAW_API_KEY_ENV_PREFIX_RE = re.compile(r"^(?:sk|pk)_(?:live|test|prod|secret)(?:_|$)", re.IGNORECASE)
_OPAQUE_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{32,}$")


class TargetStoreError(ValueError):
    """Base error for managed target storage operations."""


class TargetExistsError(TargetStoreError):
    """Raised when a managed target already exists and overwrite is disabled."""


class TargetNotFoundError(TargetStoreError):
    """Raised when a managed target or target reference cannot be resolved."""


@dataclass(frozen=True)
class ManagedTarget:
    name: str
    path: Path
    config: TargetConfig


def default_target_dir() -> Path:
    return Path.home() / ".config" / "malleus" / "targets"


def sanitize_target_name(name: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9_.-]+", "-", name.strip().lower())
    sanitized = re.sub(r"-+", "-", sanitized).strip("-_.")
    return sanitized or "target"


def derive_api_key_env(name: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9]+", "_", name.strip().upper())
    sanitized = re.sub(r"_+", "_", sanitized).strip("_")
    return f"MALLEUS_TARGET_{sanitized or 'TARGET'}_API_KEY"


def managed_target_path(name: str, target_dir: str | Path | None = None) -> Path:
    root = Path(target_dir).expanduser() if target_dir is not None else default_target_dir()
    return root / f"{sanitize_target_name(name)}.yaml"


def confirm_yes(value: str | bool) -> bool:
    if isinstance(value, bool):
        return value
    return value.strip().lower() in {"y", "yes", "true", "1"}


def add_managed_target(data: Mapping[str, Any] | TargetConfig, target_dir: str | Path | None = None, *, overwrite: bool = False) -> Path:
    target = validate_target_payload(data)
    path = managed_target_path(target.name, target_dir)
    if path.exists() and not overwrite:
        raise TargetExistsError(f"managed target already exists: {target.name}. Re-run with overwrite enabled to replace it.")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(serialize_target_config(target), encoding="utf-8")
    return path


def write_target_file(data: Mapping[str, Any] | TargetConfig, path: str | Path, *, overwrite: bool = False) -> Path:
    target = validate_target_payload(data)
    target_path = Path(path).expanduser()
    if target_path.exists() and not overwrite:
        raise TargetExistsError(f"target file already exists: {target_path}. Re-run with overwrite enabled to replace it.")
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(serialize_target_config(target), encoding="utf-8")
    return target_path


def validate_target_payload(data: Mapping[str, Any] | TargetConfig) -> TargetConfig:
    payload = _target_payload(data)
    _reject_raw_secret_fields(payload)
    _reject_secret_bearing_base_url(payload)
    if not payload.get("api_key_env"):
        name = payload.get("name")
        if not isinstance(name, str):
            raise TargetStoreError("target name is required before deriving api_key_env")
        payload["api_key_env"] = derive_api_key_env(name)
    _validate_api_key_env(payload.get("api_key_env"))
    return TargetConfig.model_validate(payload)


def serialize_target_config(target: TargetConfig) -> str:
    data = target.model_dump(mode="json")
    serialized = {field: data[field] for field in TARGET_FIELDS}
    return yaml.safe_dump(serialized, sort_keys=False)


def list_managed_targets(target_dir: str | Path | None = None) -> list[ManagedTarget]:
    root = Path(target_dir).expanduser() if target_dir is not None else default_target_dir()
    if not root.exists():
        return []
    targets: list[ManagedTarget] = []
    for path in sorted(root.glob("*.yaml")):
        config = load_target_config(path)
        targets.append(ManagedTarget(name=config.name, path=path, config=config))
    return targets


def show_managed_target(name: str, target_dir: str | Path | None = None) -> dict[str, Any]:
    config = load_managed_target(name, target_dir)
    return redacted_target_data(config)


def load_managed_target(name: str, target_dir: str | Path | None = None) -> TargetConfig:
    path = managed_target_path(name, target_dir)
    if not path.exists():
        raise TargetNotFoundError(f"managed target not found: {name}")
    return load_target_config(path)


def remove_managed_target(name: str, target_dir: str | Path | None = None, *, missing_ok: bool = False) -> bool:
    path = managed_target_path(name, target_dir)
    if not path.exists():
        if missing_ok:
            return False
        raise TargetNotFoundError(f"managed target not found: {name}")
    path.unlink()
    return True


def resolve_target(reference: str | Path, target_dir: str | Path | None = None) -> Path:
    candidate = Path(reference).expanduser()
    if candidate.exists():
        return candidate.resolve()

    managed = managed_target_path(str(reference), target_dir)
    if managed.exists():
        return managed.resolve()

    example = _example_target_path(str(reference))
    if example is not None:
        return example.resolve()

    raise TargetNotFoundError(
        f"target not found: {reference}. Provide an existing target YAML path, use an example target name from "
        f"`examples/targets/`, or add a managed target with `malleus target add {reference}`."
    )


def _example_target_path(reference: str) -> Path | None:
    raw = reference.strip()
    if not raw or any(separator in raw for separator in ("/", "\\")):
        return None
    filename = raw if raw.endswith((".yaml", ".yml")) else f"{raw}.yaml"
    candidate = Path(__file__).resolve().parents[2] / "examples" / "targets" / filename
    return candidate if candidate.exists() else None


def redacted_target_data(config: TargetConfig | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(config, TargetConfig):
        data = config.model_dump(mode="json")
        return {field: data.get(field) for field in TARGET_FIELDS if field in data}
    else:
        data = dict(config)
    for field in _RAW_KEY_FIELDS:
        if field in data:
            data[field] = "[REDACTED]"
    return data


def _target_payload(data: Mapping[str, Any] | TargetConfig) -> dict[str, Any]:
    if isinstance(data, TargetConfig):
        return data.model_dump(mode="json")
    return dict(data)


def _reject_raw_secret_fields(payload: Mapping[str, Any]) -> None:
    present = sorted(field for field in _RAW_KEY_FIELDS if field in payload and payload[field])
    if present:
        raise TargetStoreError(
            "managed targets store API key environment variable names only; remove raw secret fields: " + ", ".join(present)
        )


def _reject_secret_bearing_base_url(payload: Mapping[str, Any]) -> None:
    base_url = payload.get("base_url")
    if not isinstance(base_url, str):
        return
    parsed = urlsplit(base_url)
    if parsed.username or parsed.password:
        raise TargetStoreError("base_url must not include username or password credentials")
    secret_query_keys = [key for key, value in parse_qsl(parsed.query, keep_blank_values=True) if value and _is_secret_query_key(key)]
    if secret_query_keys:
        raise TargetStoreError("base_url must not include secret-like query parameters: " + ", ".join(sorted(secret_query_keys)))


def _is_secret_query_key(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "", key.lower())
    if normalized in _SECRET_QUERY_KEY_ALIASES:
        return True
    return any(re.sub(r"[^a-z0-9]+", "", token) in normalized for token in _RAW_KEY_FIELDS)


def _validate_api_key_env(value: object) -> None:
    if value in (None, ""):
        return
    if not isinstance(value, str) or not _ENV_VAR_RE.fullmatch(value):
        raise TargetStoreError("api_key_env must be an environment variable name, not a raw key value")
    if _looks_like_raw_api_key_env(value):
        raise TargetStoreError("api_key_env must be an environment variable name, not a raw key value")


def _looks_like_raw_api_key_env(value: str) -> bool:
    if _RAW_API_KEY_ENV_PREFIX_RE.match(value):
        return True
    if _OPAQUE_KEY_RE.fullmatch(value) and not ("_" in value or value.isupper()):
        return True
    return False
