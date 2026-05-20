from __future__ import annotations

from pathlib import Path
from typing import cast

import yaml

from malleus.mutations import mutation_names
from malleus.resources import resource_path
from malleus.schemas import BenchmarkPack, DatasetFile, MutationProfile, ReleaseMatrix, ScenarioMetadataCatalog, ScoringConfig, TargetConfig


def dataset_root() -> Path:
    return resource_path("datasets")


def _read_yaml(path: str | Path) -> dict[str, object]:
    resolved = resource_path(path)
    with resolved.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError(f"YAML file must contain a mapping: {resolved}")
    return cast(dict[str, object], data)


def load_target_config(path: str | Path) -> TargetConfig:
    return TargetConfig.model_validate(_read_yaml(path))


def load_scoring_config(path: str | Path) -> ScoringConfig:
    return ScoringConfig.model_validate(_read_yaml(path))


def load_dataset_file(path: str | Path) -> DatasetFile:
    dataset = DatasetFile.model_validate(_read_yaml(path))
    dataset.source_path = str(resource_path(path))
    return dataset


def load_benchmark_pack(path: str | Path) -> BenchmarkPack:
    pack = BenchmarkPack.model_validate(_read_yaml(path))
    pack.source_path = str(resource_path(path))
    return pack


def load_release_matrix(path: str | Path) -> ReleaseMatrix:
    matrix = ReleaseMatrix.model_validate(_read_yaml(path))
    matrix.source_path = str(resource_path(path))
    return matrix


def validate_release_matrix_references(matrix_or_path: ReleaseMatrix | str | Path) -> ReleaseMatrix:
    if isinstance(matrix_or_path, ReleaseMatrix):
        matrix = matrix_or_path
        if matrix.source_path is None:
            raise ValueError("release matrix source_path is required for reference validation")
        matrix_path = Path(matrix.source_path).resolve()
    else:
        matrix_path = resource_path(matrix_or_path)
        matrix = load_release_matrix(matrix_path)

    selected_profiles: list[MutationProfile] = []
    deep_profiles: list[MutationProfile] = []
    for pack in matrix.packs:
        _validate_release_matrix_local_path(_release_matrix_reference_path(pack.path, matrix_path), pack.path)
    for profile_ref in matrix.selected_mutation_profiles:
        profile_path = _release_matrix_reference_path(profile_ref.path, matrix_path)
        _validate_release_matrix_local_path(profile_path, profile_ref.path)
        profile = load_mutation_profile(profile_path)
        selected_profiles.append(profile)
    for profile_ref in matrix.deep_mutation_profiles:
        profile_path = _release_matrix_reference_path(profile_ref.path, matrix_path)
        _validate_release_matrix_local_path(profile_path, profile_ref.path)
        profile = load_mutation_profile(profile_path)
        deep_profiles.append(profile)
    for selected in selected_profiles:
        for deep in deep_profiles:
            validate_mutation_profile_pair(selected, deep)
    return matrix


def load_mutation_profile(path: str | Path) -> MutationProfile:
    profile = MutationProfile.model_validate(_read_yaml(path))
    registry_names = set(mutation_names())
    unknown = [name for name in profile.mutations if name not in registry_names]
    if unknown:
        raise ValueError(f"mutation profile {profile.id} references unknown mutations: {', '.join(unknown)}")
    profile.source_path = str(resource_path(path))
    return profile


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _release_matrix_reference_path(source_path: str, matrix_path: Path) -> Path:
    candidate = Path(source_path)
    if candidate.is_absolute():
        return candidate.resolve()
    matrix_relative = (matrix_path.parent / candidate).resolve()
    if matrix_relative.exists():
        return matrix_relative
    return resource_path(candidate)


def _validate_release_matrix_local_path(path: Path, source_path: str) -> None:
    if not path.exists():
        raise ValueError(f"release matrix path does not exist: {source_path}")
    if path.is_dir() and not any(item.is_file() and not item.name.startswith(".") for item in path.rglob("*")):
        raise ValueError(f"release matrix directory has no non-hidden files: {source_path}")


def _scenario_reference_path(source_path: str) -> Path:
    candidate = Path(source_path)
    if candidate.is_absolute():
        return candidate.resolve()
    return resource_path(candidate)


def _scenario_ids_from_yaml(data: dict[str, object], source_path: str) -> set[str]:
    ids: set[str] = set()
    for collection_name in ("scenarios", "queries", "cases", "steps", "prompts"):
        values = data.get(collection_name)
        if values is None:
            continue
        if not isinstance(values, list):
            continue
        for item in values:
            if isinstance(item, dict) and isinstance(item.get("id"), str):
                ids.add(item["id"])
    if not ids:
        raise ValueError(f"scenario metadata source has no addressable scenario IDs: {source_path}")
    return ids


def load_scenario_metadata_catalog(path: str | Path) -> ScenarioMetadataCatalog:
    catalog = ScenarioMetadataCatalog.model_validate(_read_yaml(path))
    catalog.source_path = str(resource_path(path))

    ids_by_source: dict[str, set[str]] = {}
    for entry in catalog.entries:
        if entry.source_path not in ids_by_source:
            reference_path = _scenario_reference_path(entry.source_path)
            if not reference_path.exists():
                raise ValueError(f"scenario metadata entry references missing file: {entry.source_path}")
            ids_by_source[entry.source_path] = _scenario_ids_from_yaml(_read_yaml(reference_path), entry.source_path)
        if entry.scenario_id not in ids_by_source[entry.source_path]:
            raise ValueError(f"scenario metadata entry references unknown scenario id: {entry.source_path}#{entry.scenario_id}")
    return catalog


def validate_mutation_profile_pair(selected: MutationProfile, deep: MutationProfile) -> None:
    missing_from_deep = [name for name in selected.mutations if name not in set(deep.mutations)]
    if missing_from_deep:
        raise ValueError(f"selected mutation profile {selected.id} is not a subset of {deep.id}: {', '.join(missing_from_deep)}")
    if deep.default:
        raise ValueError(f"deep mutation profile {deep.id} cannot be default")


def is_benchmark_pack(path: str | Path) -> bool:
    data = _read_yaml(path)
    return "includes" in data


def _resolve_include(parent: Path, include: str) -> Path:
    """Resolve a benchmark-pack include.

    Includes are normally relative to the pack file. For convenience in small
    benchmark packs, a bare filename may also resolve under a sibling
    ``datasets/`` directory if it is not found next to the pack.
    """
    candidate = (parent / include).resolve()
    if candidate.exists():
        return candidate
    fallback = (parent / "datasets" / include).resolve()
    if fallback.exists():
        return fallback
    return candidate


def expand_benchmark_pack(path: str | Path) -> list[Path]:
    ordered: list[Path] = []
    seen_paths: set[Path] = set()

    def visit(current: Path, stack: tuple[Path, ...]) -> None:
        resolved = current.resolve()
        if resolved in stack:
            cycle = " -> ".join(str(item) for item in (*stack, resolved))
            raise ValueError(f"benchmark pack include cycle detected: {cycle}")
        if is_benchmark_pack(resolved):
            pack = load_benchmark_pack(resolved)
            for include in pack.includes:
                visit(_resolve_include(resolved.parent, include), (*stack, resolved))
            return
        if resolved not in seen_paths:
            seen_paths.add(resolved)
            ordered.append(resolved)

    visit(resource_path(path), tuple())
    return ordered


def load_input_datasets(path: str | Path) -> list[DatasetFile]:
    resolved = resource_path(path)
    if is_benchmark_pack(resolved):
        return [load_dataset_file(item) for item in expand_benchmark_pack(resolved)]
    return [load_dataset_file(resolved)]
