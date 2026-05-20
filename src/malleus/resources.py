from __future__ import annotations

from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parent
ASSET_ROOT = PACKAGE_ROOT / "assets"
REPO_ROOT = PACKAGE_ROOT.parents[1]


def resource_path(path: str | Path) -> Path:
    """Resolve Malleus repo/package resources for editable and wheel installs."""

    candidate = Path(path)
    if candidate.is_absolute():
        return candidate.resolve()
    cwd_candidate = (Path.cwd() / candidate).resolve()
    if cwd_candidate.exists():
        return cwd_candidate
    repo_candidate = (REPO_ROOT / candidate).resolve()
    if repo_candidate.exists():
        return repo_candidate
    asset_candidate = _asset_candidate(candidate)
    if asset_candidate.exists():
        return asset_candidate.resolve()
    return asset_candidate.resolve()


def _asset_candidate(path: Path) -> Path:
    parts = path.parts
    if parts[:2] == ("src", "malleus"):
        return PACKAGE_ROOT.joinpath(*parts[2:])
    if parts[:1] == ("datasets",):
        return ASSET_ROOT / path
    if parts[:1] == ("configs",):
        return ASSET_ROOT / path
    if parts[:2] == ("tests", "fixtures"):
        return ASSET_ROOT / path
    return ASSET_ROOT / path
