#!/usr/bin/env python3
"""Keep packaged datasets in sync with the repository's canonical datasets."""

from __future__ import annotations

import argparse
from pathlib import Path

from malleus.dataset_assets import dataset_drift, sync_datasets


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = ROOT / "datasets"
DEFAULT_DESTINATION = ROOT / "src" / "malleus" / "assets" / "datasets"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="synchronize packaged datasets")
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--destination", type=Path, default=DEFAULT_DESTINATION)
    args = parser.parse_args()

    if args.write:
        sync_datasets(args.source, args.destination)

    drift = dataset_drift(args.source, args.destination)
    if drift:
        print("Packaged datasets differ from canonical datasets/:")
        for item in drift:
            print(f"- {item}")
        print("Run: python scripts/sync_packaged_datasets.py --write")
        return 1
    print("Packaged datasets are synchronized.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
