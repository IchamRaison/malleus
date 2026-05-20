from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from malleus.mutations import MutationSpec, get_mutation


@dataclass(frozen=True)
class MutatedFixture:
    mutation: str
    path: Path
    mutated_fields: tuple[str, ...]


PACK_FIELD_PATHS: dict[str, tuple[tuple[Any, ...], ...]] = {
    "rag-v1": (("documents", "*", "body"), ("documents", "*", "title")),
    "agentic-injection-v1": (("scenarios", "*", "untrusted_context"), ("scenarios", "*", "untrusted_artifacts", "*")),
    "plugin-workflow-v1": (("workflows", "*", "input", "**"),),
    "memory-agent-v1": (("scenarios", "*", "untrusted_context"),),
    "multi-agent-v1": (("scenarios", "*", "untrusted_context"),),
    "ui-browser-v1": (("prompts", "*", "body"),),
    "code-agent-v1": (("metadata", "intent"), ("actions", "*", "message")),
}


def build_mutated_surface_fixtures(
    *,
    pack_id: str,
    fixture_path: str | Path,
    output_dir: str | Path,
    mutations: list[str],
    limit: int | None = None,
) -> list[MutatedFixture]:
    """Write mutated fixture copies for lab system surfaces.

    Only attacker-controlled/untrusted textual fields are mutated. Oracle fields,
    expected denied tools, approvals, allowed actions, paths, and canaries remain
    unchanged so deterministic harness scoring stays meaningful.
    """

    source = Path(fixture_path).resolve()
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    selected = mutations[:limit] if limit is not None else mutations
    results: list[MutatedFixture] = []
    for mutation_name in selected:
        spec = get_mutation(mutation_name)
        mutated_path, fields = _write_mutated_fixture(pack_id=pack_id, source=source, destination=destination, spec=spec)
        if fields:
            results.append(MutatedFixture(mutation=mutation_name, path=mutated_path, mutated_fields=tuple(fields)))
    return results


def _write_mutated_fixture(*, pack_id: str, source: Path, destination: Path, spec: MutationSpec) -> tuple[Path, list[str]]:
    if source.is_dir():
        target_dir = destination / spec.name
        target_dir.mkdir(parents=True, exist_ok=True)
        changed: list[str] = []
        for child in sorted(source.glob("*.yaml")):
            data = _load_yaml(child)
            fields = _mutate_data(pack_id, data, spec)
            out = target_dir / child.name
            out.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
            changed.extend(f"{child.name}:{field}" for field in fields)
        return target_dir, changed

    data = _load_yaml(source)
    fields = _mutate_data(pack_id, data, spec)
    out = destination / f"{source.stem}--{spec.name}{source.suffix or '.yaml'}"
    out.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return out, fields


def _load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _mutate_data(pack_id: str, data: Any, spec: MutationSpec) -> list[str]:
    changed: list[str] = []
    for path in PACK_FIELD_PATHS.get(pack_id, ()):
        changed.extend(_mutate_path(data, path, spec.transform))
    return changed


def _mutate_path(node: Any, path: tuple[Any, ...], transform: Any, prefix: str = "") -> list[str]:
    if not path:
        return []
    head, *tail = path
    changed: list[str] = []
    if head == "*":
        if not isinstance(node, list):
            return []
        for index, item in enumerate(node):
            changed.extend(_mutate_path(item, tuple(tail), transform, f"{prefix}[{index}]"))
        return changed
    if head == "**":
        changed.extend(_mutate_all_strings(node, transform, prefix))
        return changed
    if not isinstance(node, dict) or head not in node:
        return []
    key_prefix = f"{prefix}.{head}" if prefix else str(head)
    if not tail:
        value = node[head]
        if isinstance(value, str) and _should_mutate_text(value):
            mutated = transform(value)
            if mutated != value:
                node[head] = mutated
                changed.append(key_prefix)
        return changed
    changed.extend(_mutate_path(node[head], tuple(tail), transform, key_prefix))
    return changed


def _mutate_all_strings(node: Any, transform: Any, prefix: str) -> list[str]:
    changed: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            child_prefix = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, str) and _should_mutate_text(value):
                mutated = transform(value)
                if mutated != value:
                    node[key] = mutated
                    changed.append(child_prefix)
            else:
                changed.extend(_mutate_all_strings(value, transform, child_prefix))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            child_prefix = f"{prefix}[{index}]"
            if isinstance(value, str) and _should_mutate_text(value):
                mutated = transform(value)
                if mutated != value:
                    node[index] = mutated
                    changed.append(child_prefix)
            else:
                changed.extend(_mutate_all_strings(value, transform, child_prefix))
    return changed


def _should_mutate_text(value: str) -> bool:
    stripped = value.strip()
    if not stripped:
        return False
    if stripped.startswith("MALLEUS_SYNTHETIC_"):
        return False
    return True
