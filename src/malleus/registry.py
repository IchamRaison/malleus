from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, Generic, Protocol, TypeVar

import yaml
from pydantic import BaseModel, Field

from malleus.adapters.base import BaseAdapter
from malleus.adapters.nvidia import NvidiaAdapter
from malleus.adapters.ollama import OllamaAdapter
from malleus.adapters.openai_compatible import OpenAICompatibleAdapter


T = TypeVar("T")


class Registry(Generic[T]):
    """Small explicit name registry for built-in extension points only."""

    def __init__(self, kind: str) -> None:
        self.kind = kind
        self._items: dict[str, T] = {}

    def register(self, name: str, item: T) -> None:
        if not name or any(separator in name for separator in (".", ":", "/", "\\")):
            raise ValueError(f"invalid {self.kind} name '{name}'")
        self._items[name] = item

    def get(self, name: str) -> T:
        try:
            return self._items[name]
        except KeyError as exc:
            available = ", ".join(sorted(self._items)) or "none"
            raise ValueError(f"unknown {self.kind} '{name}'. Available {self.kind}s: {available}") from exc

    def names(self) -> list[str]:
        return sorted(self._items)

    def values(self) -> list[T]:
        return [self._items[name] for name in self.names()]

    def items(self) -> dict[str, T]:
        return self._items


class SignalScorer(Protocol):
    def __call__(self, signal: Any, text: str, case: Any) -> tuple[bool, str]: ...


class Mutator(Protocol):
    name: str
    description: str
    category: str
    risk: str
    transform: Callable[[str], str]
    example: str


class Reporter(Protocol):
    def __call__(self, report: Any, output_dir: str | Path) -> Path: ...


class CorpusImporter(Protocol):
    def __call__(self, source: str | Path) -> Any: ...


class AgentHarness(Protocol):
    def __call__(self, *args: Any, **kwargs: Any) -> Any: ...


class ExtensionContribution(BaseModel):
    id: str
    kind: str
    path: str
    description: str = ""
    evidence_level: str = "static_analysis"
    target_types: list[str] = Field(default_factory=list)


class ExtensionManifest(BaseModel):
    schema_version: str = "malleus.extension_manifest.v1"
    name: str
    version: str = "0.1.0"
    provider_calls_enabled: bool = False
    network_enabled: bool = False
    contributions: list[ExtensionContribution] = Field(default_factory=list)


adapter_registry: Registry[type[BaseAdapter]] = Registry("adapter")
scorer_registry: Registry[SignalScorer] = Registry("scorer")
mutator_registry: Registry[Mutator] = Registry("mutator")
reporter_registry: Registry[Reporter] = Registry("reporter")
corpus_importer_registry: Registry[CorpusImporter] = Registry("corpus importer")
agent_harness_registry: Registry[AgentHarness] = Registry("agent harness")
extension_pack_registry: Registry[ExtensionContribution] = Registry("extension contribution")


def load_extension_manifest(path: str | Path) -> ExtensionManifest:
    manifest_path = Path(path)
    data = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError("extension manifest must be a YAML mapping")
    manifest = ExtensionManifest.model_validate(data)
    if manifest.provider_calls_enabled:
        raise ValueError("extension manifests must not enable provider calls")
    if manifest.network_enabled:
        raise ValueError("extension manifests must not enable network access")
    base = manifest_path.parent.resolve()
    for contribution in manifest.contributions:
        if contribution.kind not in {"pack", "scorer", "harness", "reporter"}:
            raise ValueError(f"unsupported extension contribution kind: {contribution.kind}")
        resolved = (base / contribution.path).resolve()
        if not str(resolved).startswith(str(base)):
            raise ValueError(f"extension contribution path escapes manifest directory: {contribution.id}")
    return manifest


def register_extension_manifest(path: str | Path) -> ExtensionManifest:
    manifest = load_extension_manifest(path)
    for contribution in manifest.contributions:
        extension_pack_registry.register(contribution.id, contribution)
    return manifest


def register_builtin_adapters() -> None:
    adapter_registry.register("openai_compatible", OpenAICompatibleAdapter)
    adapter_registry.register("nvidia", NvidiaAdapter)
    adapter_registry.register("ollama", OllamaAdapter)


register_builtin_adapters()
