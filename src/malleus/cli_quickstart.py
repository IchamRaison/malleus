from __future__ import annotations

from pathlib import Path

from malleus.resources import resource_path


def display_resource_path(path: str) -> str:
    resolved = resource_path(path)
    try:
        return str(resolved.relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(resolved)


def render_quickstart(*, target: str | None = None, out_dir: Path = Path("reports/malleus-quickstart")) -> str:
    if target is None:
        return "\n".join(
            [
                "Malleus quickstart",
                "",
                "1. Create a reusable target:",
                "   malleus target init",
                "",
                "2. Check provider/auth/config:",
                "   malleus target doctor <target-name> --live-check",
                "",
                "3. Run the default live benchmark:",
                "   malleus benchmark soft --target <target-name>",
                "",
                "4. Open the human report:",
                "   Malleus prints the generated reports/<target>-soft-<timestamp>/ path at the end of the run.",
                "",
                "Tip: pass --target <name-or-yaml> to render copy/paste commands for an existing target.",
            ]
        )

    smoke_dir = out_dir / "smoke"
    soft_dir = out_dir / "soft"
    return "\n".join(
        [
            "Malleus quickstart for target",
            f"Target: {target}",
            "",
            "1. Doctor:",
            f"   malleus target doctor {target} --live-check --out-dir {out_dir / 'doctor'}",
            "",
            "2. Quota-friendly smoke run:",
            f"   malleus run {target} --input {display_resource_path('datasets/benchmark_packs/smoke-v1.yaml')} --scoring {display_resource_path('configs/scoring-default.yaml')} --out-dir {smoke_dir}",
            "",
            "3. Default live benchmark:",
            f"   malleus benchmark soft --target {target} --out-dir {soft_dir}",
            "",
            "4. Audit bundle from the soft run:",
            f"   malleus evidence-bundle --run-report {soft_dir / 'live-full-evidence.json'} --out-dir {out_dir / 'evidence-bundle'}",
        ]
    )
