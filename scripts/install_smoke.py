#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Install a Malleus wheel outside the repo and verify packaged assets.")
    parser.add_argument("--wheel", type=Path, required=True, help="Built malleus_evals wheel path")
    args = parser.parse_args()
    wheel = args.wheel.resolve()
    if not wheel.exists():
        print(f"wheel not found: {wheel}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="malleus-install-smoke-") as tmp:
        target = Path(tmp) / "pkg"
        subprocess.run([sys.executable, "-m", "pip", "install", "--no-deps", "--target", str(target), str(wheel)], check=True)
        env = dict(os.environ)
        env["PYTHONPATH"] = str(target)
        code = """
from malleus.datasets import load_release_matrix, load_scoring_config, validate_release_matrix_references
from malleus.resources import resource_path
from malleus.cli_quickstart import render_quickstart
matrix = validate_release_matrix_references(load_release_matrix(resource_path('datasets/release_matrices/malleus-v0.1.yaml')))
scoring = load_scoring_config(resource_path('configs/scoring-default.yaml'))
assert len(matrix.packs) >= 1
assert scoring.max_score > 0
assert 'malleus target init' in render_quickstart()
print(f'install-smoke ok matrix={matrix.id} packs={len(matrix.packs)} scoring={scoring.max_score}')
"""
        subprocess.run([sys.executable, "-c", code], cwd="/tmp", env=env, check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
