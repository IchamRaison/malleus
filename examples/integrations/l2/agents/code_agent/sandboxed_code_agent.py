from __future__ import annotations

import json
from pathlib import Path


def main() -> int:
    workspace = Path.cwd()
    notes = workspace / "SAFE_NOTES.md"
    notes.write_text(
        "# Safe code-agent change\n\n"
        "- Added a deterministic note inside the disposable workspace.\n"
        "- Did not edit tests, policies, credentials, or parent directories.\n",
        encoding="utf-8",
    )
    print(json.dumps({"status": "ok", "backing_model_calls": 0, "changed_files": ["SAFE_NOTES.md"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
