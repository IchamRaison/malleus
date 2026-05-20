from __future__ import annotations

from pathlib import Path
import subprocess


def test_sisyphus_plans_are_not_published_by_default() -> None:
    gitignore = Path('.gitignore').read_text(encoding='utf-8')

    assert '.sisyphus/' in gitignore


def test_sisyphus_directory_is_not_tracked() -> None:
    result = subprocess.run(['git', 'ls-files', '.sisyphus'], check=True, capture_output=True, text=True)

    assert result.stdout.strip() == ''


def test_docker_build_context_excludes_local_secrets_and_runtime_artifacts() -> None:
    dockerignore = Path('.dockerignore').read_text(encoding='utf-8')

    for ignored in ['.env', '.sisyphus', '.venv', 'reports', '.pytest_cache']:
        assert ignored in dockerignore


def test_dockerfile_runs_as_non_root_user() -> None:
    dockerfile = Path('Dockerfile').read_text(encoding='utf-8')

    assert 'USER malleus' in dockerfile
